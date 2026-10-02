"""工具治理框架：Pydantic 校验 → 权限状态机 → 一次性审批 → 超时恢复 → 结果脱敏 → 审计追踪。

仓库里附带一个完整的示例工具 `transfer`（转账），演示如何把一个高风险写工具接进框架。

六个接入点（搜索 `# =====` 可定位）：

    ACCOUNTS            模拟账户数据
    TransferArgs        转账参数模型
    transfer_precheck   业务预检
    transfer_handler    转账处理
    build_tools()       注册 transfer 工具
    _redact             账号脱敏

验收命令：

    python -m pytest tests/test_tool_governance.py -v -k "transfer"

框架的固定约束：

    1. PermissionEngine.decide 的优先级顺序是固定框架，一行未动。
    2. 测试不绕过 ToolRuntime.invoke，所有调用都走 runtime.invoke()。
    3. TransferArgs 的 extra="forbid" 保留（继承自 StrictArgs，是防注入的最后屏障）。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class PermissionMode(StrEnum):
    DEFAULT = "default"
    PLAN = "plan"
    BYPASS_PERMISSIONS = "bypassPermissions"
    DONT_ASK = "dontAsk"


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    SHELL = "shell"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


Permission = Literal["order:read", "refund:create", "shell:run", "transfer:execute"]


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    trace_id: str
    user_id: str
    tenant_id: str
    mode: PermissionMode
    permissions: frozenset[Permission]
    allowed_tools: frozenset[str]
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    effect: Effect
    risk: Risk
    permission: Permission
    requires_approval: bool
    timeout_seconds: float
    max_retries: int
    idempotent: bool


class StrictArgs(BaseModel):
    """模型只能提交 Schema 允许的业务候选参数。"""

    model_config = ConfigDict(extra="forbid", strict=True)


class GetOrderArgs(StrictArgs):
    order_id: str = Field(pattern=r"^ord_[0-9]{4}$")


class CreateRefundArgs(StrictArgs):
    order_id: str = Field(pattern=r"^ord_[0-9]{4}$")
    amount: float = Field(gt=0, le=10_000)
    reason: str = Field(min_length=4, max_length=200)


class RunShellArgs(StrictArgs):
    command: str = Field(min_length=1, max_length=200)


# ===== 转账参数模型 =====
# 与 CreateRefundArgs 同一套写法：Field 约束写在声明上，StrictArgs 提供
# extra="forbid" 与 strict=True —— 前者挡住模型注入的多余键，后者挡住
# "100" 这样的字符串被悄悄转成数字。
class TransferArgs(StrictArgs):
    """转账工具的业务候选参数。"""

    from_account: str = Field(pattern=r"^ACC-[A-Z]-[0-9]{6}$")
    to_account: str = Field(pattern=r"^ACC-[A-Z]-[0-9]{6}$")
    amount: float = Field(gt=0, le=100_000)


ArgsModel = GetOrderArgs | CreateRefundArgs | RunShellArgs | TransferArgs
Handler = Callable[[str, ArgsModel, ExecutionContext], Awaitable[Mapping[str, Any]]]
Precheck = Callable[[ArgsModel, ExecutionContext], Awaitable[None]]
CanonicalTarget = Callable[[ArgsModel], str]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    parameters_model: type[StrictArgs]
    policy: ToolPolicy
    handler: Handler
    canonical_target: CanonicalTarget
    precheck: Precheck | None = None

    def to_model_tool(self) -> dict[str, Any]:
        """只投影模型需要的描述和 JSON Schema，不暴露 handler 与治理策略。"""

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_model.model_json_schema(),
            },
        }


@dataclass(frozen=True, slots=True)
class PermissionRule:
    effect: Literal["allow", "deny"]
    tool_name: str
    target_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    action: DecisionAction
    code: str
    reason: str
    source: Literal[
        "rule", "mode", "whitelist", "rbac", "business", "approval", "risk", "default"
    ]


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool_call_id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_call_id: str
    tool_name: str
    ok: bool
    action: DecisionAction
    code: str
    content: Any
    retryable: bool = False

    def to_tool_message(self) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": self.tool_call_id,
            "content": json.dumps(
                {
                    "ok": self.ok,
                    "code": self.code,
                    "action": self.action,
                    "content": self.content,
                },
                ensure_ascii=False,
            ),
        }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    trace_id: str
    tool_call_id: str
    tool_name: str
    user_id: str
    tenant_id: str
    phase: Literal["decision", "execution"]
    decision: str
    code: str
    argument_keys: tuple[str, ...]
    latency_ms: int | None = None


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: str
    user_id: str
    tenant_id: str
    tool_name: str
    digest: str
    expires_at: float
    used: bool = False


class PolicyDenied(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TransientToolError(RuntimeError):
    pass


def _stable_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _stable_value(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {key: _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_value(item) for item in value]
    return value


def _approval_digest(tool_name: str, arguments: ArgsModel | Mapping[str, Any]) -> str:
    canonical = json.dumps(_stable_value(arguments), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(f"{tool_name}:{canonical}".encode()).hexdigest()


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    def approve(
        self,
        approval_id: str,
        context: ExecutionContext,
        tool_name: str,
        arguments: ArgsModel | Mapping[str, Any],
        *,
        ttl_seconds: float = 300,
    ) -> None:
        self._records[approval_id] = ApprovalRecord(
            approval_id=approval_id,
            user_id=context.user_id,
            tenant_id=context.tenant_id,
            tool_name=tool_name,
            digest=_approval_digest(tool_name, arguments),
            expires_at=time.time() + ttl_seconds,
        )

    def consume(
        self,
        approval_id: str | None,
        context: ExecutionContext,
        tool_name: str,
        arguments: ArgsModel,
    ) -> bool:
        record = self._records.get(approval_id or "")
        valid = bool(
            record
            and not record.used
            and record.expires_at >= time.time()
            and record.user_id == context.user_id
            and record.tenant_id == context.tenant_id
            and record.tool_name == tool_name
            and record.digest == _approval_digest(tool_name, arguments)
        )
        if valid and record:
            record.used = True
        return valid


class AuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        self.records.append(record)


DANGEROUS_SHELL_PATTERNS = (
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\bgit\s+push\s+--force\b", re.I),
    re.compile(r"\bgit\s+reset\s+--hard\b", re.I),
    re.compile(r"\bsudo\b", re.I),
    re.compile(r"\bmkfs\b", re.I),
    re.compile(r">\s*/dev/", re.I),
)


def _is_dangerous_shell(command: str) -> bool:
    return any(pattern.search(command) for pattern in DANGEROUS_SHELL_PATTERNS)


# 账号形如 ACC-A-123456：前缀 ACC-<租户字母>-，后面六位数字。
_ACCOUNT_PATTERN = re.compile(r"\bACC-[A-Z]-[0-9]{6}\b")


def _mask_account(match: re.Match[str]) -> str:
    """保留可辨识的前缀与末 4 位，中间换成 ****。"""

    account = match.group(0)
    return f"{account[:6]}****{account[-4:]}"


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: "***" if re.search(r"token|secret|password|authorization", key, re.I) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "***@***", value)
        # ===== 账号脱敏 =====
        # 用函数式替换而不是字符串替换：需要同时读前缀和末 4 位，
        # 字符串替换里写不出"保留末尾"这种引用（\1/\g<1> 只能引用捕获组，
        # 而末 4 位要先知道总长度）。
        return _ACCOUNT_PATTERN.sub(_mask_account, value)
    return value


class PermissionEngine:
    """固定优先级的三态权限状态机。"""

    def __init__(self, rules: Sequence[PermissionRule], approvals: ApprovalStore) -> None:
        self._rules = tuple(rules)
        self._approvals = approvals

    def _rule_matches(self, rule: PermissionRule, tool: ToolDefinition, arguments: ArgsModel) -> bool:
        if rule.tool_name != tool.name:
            return False
        if rule.target_prefix is None:
            return True
        return tool.canonical_target(arguments).startswith(rule.target_prefix)

    async def decide(
        self,
        tool: ToolDefinition,
        arguments: ArgsModel,
        context: ExecutionContext,
    ) -> PermissionDecision:
        # 1. deny-first：硬拒绝不能被 allow 或 bypass 覆盖。
        if any(
            rule.effect == "deny" and self._rule_matches(rule, tool, arguments)
            for rule in self._rules
        ):
            return PermissionDecision(DecisionAction.DENY, "DENY_RULE", "命中 deny 规则", "rule")

        # 2. plan 是执行层只读契约，而不是一句系统提示词。
        if context.mode is PermissionMode.PLAN and tool.policy.effect is not Effect.READ:
            return PermissionDecision(
                DecisionAction.DENY,
                "PLAN_MODE_DENIED",
                "plan 模式禁止写操作和 Shell",
                "mode",
            )

        # 3. 发现阶段过滤后，执行阶段仍然要重新检查白名单。
        if tool.name not in context.allowed_tools:
            return PermissionDecision(
                DecisionAction.DENY,
                "TOOL_NOT_ALLOWED",
                "工具不在本轮执行白名单",
                "whitelist",
            )

        # 4. 只相信认证层生成的 ExecutionContext。
        if tool.policy.permission not in context.permissions:
            return PermissionDecision(
                DecisionAction.DENY,
                "PERMISSION_DENIED",
                f"缺少业务权限 {tool.policy.permission}",
                "rbac",
            )

        # 5. 资源归属、状态和额度在 handler 之前验证。
        try:
            if tool.precheck:
                await tool.precheck(arguments, context)
        except PolicyDenied as error:
            return PermissionDecision(DecisionAction.DENY, error.code, str(error), "business")

        # 6. 高风险业务写操作必须使用一次性、参数绑定审批。
        if tool.policy.requires_approval or tool.policy.risk is Risk.HIGH:
            if self._approvals.consume(context.approval_id, context, tool.name, arguments):
                return PermissionDecision(
                    DecisionAction.ALLOW,
                    "APPROVED",
                    "审批与当前用户、租户、工具和参数完全匹配",
                    "approval",
                )
            if context.mode is PermissionMode.DONT_ASK:
                return PermissionDecision(
                    DecisionAction.DENY,
                    "APPROVAL_REQUIRED",
                    "非交互模式无法完成高风险确认",
                    "approval",
                )
            return PermissionDecision(
                DecisionAction.CONFIRM,
                "APPROVAL_REQUIRED",
                "需要确认本次具体动作",
                "approval",
            )

        # 7. bypass 只能跳过普通确认，不能跳过前面的硬边界。
        if context.mode is PermissionMode.BYPASS_PERMISSIONS:
            return PermissionDecision(
                DecisionAction.ALLOW,
                "BYPASS_ALLOWED",
                "跳过普通确认，但硬边界已经全部通过",
                "mode",
            )

        # 8. allow 规则只在 deny、plan、白名单、RBAC 和审批以后生效。
        if any(
            rule.effect == "allow" and self._rule_matches(rule, tool, arguments)
            for rule in self._rules
        ):
            return PermissionDecision(DecisionAction.ALLOW, "ALLOW_RULE", "命中 allow 规则", "rule")

        # 9. 正则只是教学兜底，生产中必须配合窄工具、AST 与沙箱。
        if tool.policy.effect is Effect.SHELL and _is_dangerous_shell(
            str(getattr(arguments, "command", ""))
        ):
            if context.mode is PermissionMode.DONT_ASK:
                return PermissionDecision(
                    DecisionAction.DENY,
                    "DANGEROUS_OPERATION",
                    "危险 Shell 在非交互模式下被拒绝",
                    "risk",
                )
            return PermissionDecision(
                DecisionAction.CONFIRM,
                "DANGEROUS_OPERATION",
                "危险 Shell 需要用户确认",
                "risk",
            )

        return PermissionDecision(
            DecisionAction.ALLOW,
            "DEFAULT_ALLOWED",
            "所有确定性检查均已通过",
            "default",
        )


class ToolRuntime:
    """模型、CLI、测试与未来 Provider 共用的唯一工具执行入口。"""

    def __init__(
        self,
        tools: Sequence[ToolDefinition],
        permission_engine: PermissionEngine,
        audit_sink: AuditSink,
    ) -> None:
        self._tools = {tool.name: tool for tool in tools}
        self._permission_engine = permission_engine
        self._audit = audit_sink

    def model_tools(self, context: ExecutionContext) -> list[dict[str, Any]]:
        """发现期白名单：减少模型可见能力，不把 handler 暴露给模型。"""

        return [
            tool.to_model_tool()
            for tool in self._tools.values()
            if tool.name in context.allowed_tools
        ]

    async def invoke(self, call: ToolCall, context: ExecutionContext) -> ToolResult:
        started = time.perf_counter()
        tool = self._tools.get(call.name)
        if tool is None:
            return self._rejected(call, context, "TOOL_NOT_FOUND", "工具不存在")

        # prepare-1：Pydantic 把不可信字典转换成 handler 可接收的业务对象。
        try:
            arguments = tool.parameters_model.model_validate(call.arguments)
        except ValidationError as error:
            details = [
                {"path": ".".join(map(str, item["loc"])), "message": item["msg"]}
                for item in error.errors(include_url=False)
            ]
            return self._rejected(call, context, "INVALID_ARGUMENT", details)

        # prepare-2：执行期重新授权，返回 allow / deny / confirm。
        decision = await self._permission_engine.decide(tool, arguments, context)
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="decision",
                decision=decision.action,
                code=decision.code,
                argument_keys=tuple(sorted(call.arguments)),
            )
        )
        if decision.action is not DecisionAction.ALLOW:
            return ToolResult(
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                ok=False,
                action=decision.action,
                code=decision.code,
                content=decision.reason,
            )

        # execute：只有通过全部确定性检查后，handler 才可能产生副作用。
        try:
            raw = await self._execute_with_recovery(tool, call.tool_call_id, arguments, context)
        except TimeoutError:
            code = "TIMEOUT" if tool.policy.effect is Effect.READ or tool.policy.idempotent else "TIMEOUT_UNKNOWN"
            return self._failed(call, context, started, code, "工具执行超时")
        except PolicyDenied as error:
            return self._failed(call, context, started, error.code, str(error))
        except Exception as error:  # 生产中映射异常类型，不把 traceback 交给模型。
            return self._failed(call, context, started, "TOOL_ERROR", str(error))

        # finalize：先投影与脱敏，再形成模型能看见的 ToolResult。
        safe_content = _redact(dict(raw))
        latency_ms = round((time.perf_counter() - started) * 1_000)
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="execution",
                decision="executed",
                code="OK",
                argument_keys=tuple(sorted(call.arguments)),
                latency_ms=latency_ms,
            )
        )
        return ToolResult(call.tool_call_id, call.name, True, DecisionAction.ALLOW, "OK", safe_content)

    async def _execute_with_recovery(
        self,
        tool: ToolDefinition,
        tool_call_id: str,
        arguments: ArgsModel,
        context: ExecutionContext,
    ) -> Mapping[str, Any]:
        retries = tool.policy.max_retries if tool.policy.effect is Effect.READ or tool.policy.idempotent else 0
        for attempt in range(retries + 1):
            try:
                async with asyncio.timeout(tool.policy.timeout_seconds):
                    return await tool.handler(tool_call_id, arguments, context)
            except TransientToolError:
                if attempt == retries:
                    raise
                await asyncio.sleep(min(0.05 * (2**attempt), 0.2))
        raise AssertionError("unreachable")

    def _rejected(
        self,
        call: ToolCall,
        context: ExecutionContext,
        code: str,
        content: Any,
    ) -> ToolResult:
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="decision",
                decision="deny",
                code=code,
                argument_keys=tuple(sorted(call.arguments)),
            )
        )
        return ToolResult(call.tool_call_id, call.name, False, DecisionAction.DENY, code, content)

    def _failed(
        self,
        call: ToolCall,
        context: ExecutionContext,
        started: float,
        code: str,
        content: Any,
    ) -> ToolResult:
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="execution",
                decision="failed",
                code=code,
                argument_keys=tuple(sorted(call.arguments)),
                latency_ms=round((time.perf_counter() - started) * 1_000),
            )
        )
        return ToolResult(call.tool_call_id, call.name, False, DecisionAction.DENY, code, content)


ORDERS = {
    ("tenant_a", "ord_1001"): {
        "status": "paid",
        "refundable": 399.0,
        "customer_email": "alice@example.com",
    }
}

# ===== 模拟账户数据 =====
# 模块级可变状态：测试用 isolated_accounts fixture 逐用例快照还原，
# 所以必须是普通 dict，不能写成 MappingProxy 或 frozenset 之类只读结构。
ACCOUNTS: dict[tuple[str, str], float] = {
    ("tenant_a", "ACC-A-123456"): 100_000.0,
    ("tenant_a", "ACC-A-654321"): 5_000.0,
    ("tenant_a", "ACC-A-888888"): 20_000.0,
    ("tenant_b", "ACC-B-111111"): 50_000.0,
}
SIDE_EFFECTS = {"refund_executions": 0, "shell_executions": 0}


def reset_side_effects() -> None:
    SIDE_EFFECTS.update(refund_executions=0, shell_executions=0)


async def get_order_handler(
    _tool_call_id: str,
    raw_arguments: ArgsModel,
    context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, GetOrderArgs)
    order = ORDERS.get((context.tenant_id, arguments.order_id))
    if not order:
        raise PolicyDenied("ORDER_NOT_FOUND", "当前租户下不存在该订单")
    return {**order, "access_token": "tok_demo_should_not_leak"}


async def refund_precheck(raw_arguments: ArgsModel, context: ExecutionContext) -> None:
    arguments = raw_arguments
    assert isinstance(arguments, CreateRefundArgs)
    order = ORDERS.get((context.tenant_id, arguments.order_id))
    if not order or order["status"] != "paid":
        raise PolicyDenied("BUSINESS_RULE_DENIED", "订单不存在或状态不可退款")
    if arguments.amount > float(order["refundable"]):
        raise PolicyDenied("BUSINESS_RULE_DENIED", "退款金额超过可退金额")


# ===== 业务预检 =====
# 只做判断、不改余额。顺序即优先级：先拦教学区间，再查余额 ——
# 一次调用只应因为一个原因被拒，先命中哪个就报哪个码。
async def transfer_precheck(raw_arguments: ArgsModel, context: ExecutionContext) -> None:
    arguments = raw_arguments
    assert isinstance(arguments, TransferArgs)

    # 1. 教学用的金额区间拦截。注意上界是闭区间：amount > 80_000 必须放过去，
    #    超时演示要靠它。
    if 50_000 < arguments.amount <= 80_000:
        raise PolicyDenied(
            "EXCEED_LIMIT",
            "单笔转账金额落在教学拦截区间 (50000, 80000]",
        )

    # 2. 余额充足。账户不存在时按余额 0 处理 —— 对调用方来说这与余额不足
    #    是同一件事：这笔钱转不出去。
    balance = ACCOUNTS.get((context.tenant_id, arguments.from_account), 0.0)
    if balance < arguments.amount:
        raise PolicyDenied(
            "INSUFFICIENT_BALANCE",
            f"转出账户余额不足：{balance} < {arguments.amount}",
        )


async def create_refund_handler(
    tool_call_id: str,
    raw_arguments: ArgsModel,
    context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, CreateRefundArgs)
    SIDE_EFFECTS["refund_executions"] += 1
    return {
        "refund_id": "ref_9001",
        "idempotency_key": tool_call_id,
        "tenant_id": context.tenant_id,
        "order_id": arguments.order_id,
        "amount": arguments.amount,
        "status": "accepted",
    }


# ===== 转账处理 =====
# 两个副作用之间的顺序是关键：sleep 必须在扣款之前。
# 框架用 asyncio.timeout 掐断执行，取消发生在第一个 await 点上；
# 只要扣款排在 sleep 后面，超时那一刻余额就还没动过 ——
# 这正是测试要断言的 "balances untouched"。
async def transfer_handler(
    tool_call_id: str,
    raw_arguments: ArgsModel,
    context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, TransferArgs)

    # 1. 超时模拟，必须早于任何写操作。
    if arguments.amount > 80_000:
        await asyncio.sleep(3.0)

    from_key = (context.tenant_id, arguments.from_account)
    to_key = (context.tenant_id, arguments.to_account)

    # 2. 转入账户必须存在。放在扣款之前，否则钱会凭空消失。
    if to_key not in ACCOUNTS:
        raise PolicyDenied("ACCOUNT_NOT_FOUND", "转入账户不存在")

    # 3. 改余额。到这里为止没有任何 await，所以这两步要么都发生，要么都不发生。
    ACCOUNTS[from_key] -= arguments.amount
    ACCOUNTS[to_key] += arguments.amount

    # 4. txn_id 取 tool_call_id 的后 6 位。账号不在这里脱敏 ——
    #    脱敏是 finalize 阶段的统一职责（_redact），handler 不重复实现。
    return {
        "txn_id": tool_call_id[-6:],
        "from": arguments.from_account,
        "to": arguments.to_account,
        "amount": arguments.amount,
        "status": "accepted",
    }


async def simulated_shell_handler(
    _tool_call_id: str,
    raw_arguments: ArgsModel,
    _context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, RunShellArgs)
    SIDE_EFFECTS["shell_executions"] += 1
    return {
        "simulated": True,
        "command": arguments.command,
        "stdout": "教学模拟：没有创建真实子进程",
    }


def build_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="get_order",
            description="查询当前租户订单状态和可退金额",
            parameters_model=GetOrderArgs,
            policy=ToolPolicy(Effect.READ, Risk.MEDIUM, "order:read", False, 1.0, 2, True),
            handler=get_order_handler,
            canonical_target=lambda args: str(getattr(args, "order_id")),
        ),
        ToolDefinition(
            name="create_refund",
            description="为当前租户的已支付订单创建退款",
            parameters_model=CreateRefundArgs,
            policy=ToolPolicy(Effect.WRITE, Risk.HIGH, "refund:create", True, 2.0, 0, False),
            handler=create_refund_handler,
            precheck=refund_precheck,
            canonical_target=lambda args: f"{getattr(args, 'order_id')}:{getattr(args, 'amount')}",
        ),
        ToolDefinition(
            name="run_shell",
            description="教学用模拟 Shell，不执行真实系统命令",
            parameters_model=RunShellArgs,
            policy=ToolPolicy(Effect.SHELL, Risk.MEDIUM, "shell:run", False, 1.0, 0, False),
            handler=simulated_shell_handler,
            canonical_target=lambda args: str(getattr(args, "command")),
        ),
        # ===== 注册 transfer 工具 =====
        # policy 与 create_refund 同类：WRITE + HIGH + 需要人工审批 + 非幂等 + max_retries=0。
        # timeout_seconds 取 1.0 —— 必须小于 sleep(3.0) 那个演示值，
        # 否则框架等不到超时，测试会真的睡满 3 秒然后扣款成功。
        # canonical_target 用三段拼接：金额必须进摘要，否则"改了金额再用同一张审批"
        # 就能通过，参数绑定测试会失败。
        ToolDefinition(
            name="transfer",
            description="在租户内的两个账户之间转账（高风险写操作，需要人工审批）",
            parameters_model=TransferArgs,
            policy=ToolPolicy(Effect.WRITE, Risk.HIGH, "transfer:execute", True, 1.0, 0, False),
            handler=transfer_handler,
            precheck=transfer_precheck,
            canonical_target=lambda args: (
                f"{getattr(args, 'from_account')}:"
                f"{getattr(args, 'to_account')}:"
                f"{getattr(args, 'amount')}"
            ),
        ),
    ]


DEFAULT_RULES = (
    PermissionRule("deny", "run_shell", "rm -rf"),
    PermissionRule("deny", "run_shell", "git push --force"),
    PermissionRule("allow", "run_shell", "pytest"),
)


def base_context(**overrides: Any) -> ExecutionContext:
    context = ExecutionContext(
        trace_id="trace_demo",
        user_id="u_100",
        tenant_id="tenant_a",
        mode=PermissionMode.DEFAULT,
        permissions=frozenset({"order:read", "refund:create", "shell:run"}),
        allowed_tools=frozenset({"get_order", "create_refund", "run_shell"}),
    )
    return replace(context, **overrides)


def build_runtime(
    *,
    approvals: ApprovalStore | None = None,
    audit: AuditSink | None = None,
    rules: Sequence[PermissionRule] = DEFAULT_RULES,
) -> tuple[ToolRuntime, ApprovalStore, AuditSink]:
    approval_store = approvals or ApprovalStore()
    audit_sink = audit or AuditSink()
    engine = PermissionEngine(rules, approval_store)
    return ToolRuntime(build_tools(), engine, audit_sink), approval_store, audit_sink


async def run_offline_demo() -> None:
    reset_side_effects()
    runtime, approvals, audit = build_runtime()
    context = base_context()
    refund_arguments = {"order_id": "ord_1001", "amount": 399.0, "reason": "商品存在质量问题"}

    results = [
        await runtime.invoke(ToolCall("call_01", "get_order", {"order_id": "ord_1001"}), context),
        await runtime.invoke(ToolCall("call_02", "create_refund", refund_arguments), context),
    ]
    approvals.approve("approval_01", context, "create_refund", refund_arguments)
    results.append(
        await runtime.invoke(
            ToolCall("call_03", "create_refund", refund_arguments),
            replace(context, approval_id="approval_01"),
        )
    )
    results.extend(
        [
            await runtime.invoke(
                ToolCall(
                    "call_04",
                    "create_refund",
                    {**refund_arguments, "user_id": "admin", "approved": True},
                ),
                context,
            ),
            await runtime.invoke(
                ToolCall("call_05", "run_shell", {"command": "rm -rf /tmp/demo"}),
                replace(context, mode=PermissionMode.BYPASS_PERMISSIONS),
            ),
            await runtime.invoke(
                ToolCall("call_06", "create_refund", refund_arguments),
                replace(context, mode=PermissionMode.PLAN, approval_id="approval_01"),
            ),
        ]
    )

    for result in results:
        print(json.dumps(result.__dict__ if hasattr(result, "__dict__") else {
            "tool_call_id": result.tool_call_id,
            "tool_name": result.tool_name,
            "ok": result.ok,
            "action": result.action,
            "code": result.code,
            "content": result.content,
        }, ensure_ascii=False, default=str))
    print(json.dumps({"side_effects": SIDE_EFFECTS, "audit_records": len(audit.records)}, ensure_ascii=False))


async def run_transfer_demo() -> None:
    """转账链路的手工演示：CONFIRM → 审批 → 执行 → 脱敏 + 审计。

    `run_offline_demo` 演示的是退款与 Shell；transfer 的审批绑定需要按
    具体参数生成摘要，所以单独走一遍，方便肉眼核对脱敏后的输出。
    """

    reset_side_effects()
    runtime, approvals, audit = build_runtime()
    context = replace(
        base_context(),
        permissions=frozenset({"order:read", "refund:create", "shell:run", "transfer:execute"}),
        allowed_tools=frozenset({"get_order", "create_refund", "run_shell", "transfer"}),
    )
    arguments = {"from_account": "ACC-A-123456", "to_account": "ACC-A-654321", "amount": 1200.0}

    print("== 1. 未审批：应返回 CONFIRM / APPROVAL_REQUIRED ==")
    pending = await runtime.invoke(ToolCall("call_tr_000001", "transfer", arguments), context)
    print(json.dumps(pending.to_tool_message(), ensure_ascii=False))

    print("\n== 2. 审批后：应返回 OK，且账号已脱敏 ==")
    approvals.approve("approval_demo", context, "transfer", arguments)
    executed = await runtime.invoke(
        ToolCall("call_tr_000002", "transfer", arguments),
        replace(context, approval_id="approval_demo"),
    )
    print(json.dumps(executed.to_tool_message(), ensure_ascii=False))

    print("\n== 3. 审计日志 ==")
    for record in audit.records:
        print(
            f"  {record.phase:<10} {record.code:<20} {record.tool_name:<10} "
            f"{record.latency_ms if record.latency_ms is not None else '-'} ms"
        )

    print("\n== 4. 余额 ==")
    print(json.dumps({f"{t}/{a}": b for (t, a), b in ACCOUNTS.items()}, ensure_ascii=False))


async def run_deepseek_agent(user_input: str) -> None:
    """可选真实模型闭环；所有工具调用仍经过同一个 ToolRuntime.invoke。"""

    from openai import AsyncOpenAI

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("请先设置环境变量 DEEPSEEK_API_KEY")

    runtime, _, _ = build_runtime()
    context = base_context(allowed_tools=frozenset({"get_order"}))
    client = AsyncOpenAI(api_key=api_key, base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": "你是订单助手。只根据工具结果回答，不得伪造订单事实。",
        },
        {"role": "user", "content": user_input},
    ]

    for _round in range(8):
        stream = await client.chat.completions.create(
            model=model,
            messages=messages,
            tools=runtime.model_tools(context),
            stream=True,
            extra_body={"thinking": {"type": "disabled"}},
        )
        text_parts: list[str] = []
        pending_calls: dict[int, dict[str, Any]] = {}

        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta.content:
                text_parts.append(delta.content)
                print(delta.content, end="", flush=True)
            for delta_call in delta.tool_calls or []:
                current = pending_calls.setdefault(
                    delta_call.index,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                if delta_call.id:
                    current["id"] = delta_call.id
                if delta_call.function:
                    if delta_call.function.name:
                        current["function"]["name"] += delta_call.function.name
                    if delta_call.function.arguments:
                        current["function"]["arguments"] += delta_call.function.arguments

        provider_calls = [pending_calls[index] for index in sorted(pending_calls)]
        assistant_message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
        if provider_calls:
            assistant_message["tool_calls"] = provider_calls
        messages.append(assistant_message)

        if not provider_calls:
            print()
            return

        if text_parts:
            print()
        for provider_call in provider_calls:
            try:
                raw_arguments = json.loads(provider_call["function"]["arguments"])
            except json.JSONDecodeError:
                raw_arguments = {"_invalid_json": provider_call["function"]["arguments"]}
            result = await runtime.invoke(
                ToolCall(provider_call["id"], provider_call["function"]["name"], raw_arguments),
                context,
            )
            print(f"[tool_result] {result.tool_name} {result.code}")
            messages.append(result.to_tool_message())

    raise RuntimeError("Agent Loop 超过最大轮数 8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python 工具治理与权限状态机演示")
    parser.add_argument("--agent", action="store_true", help="使用 DeepSeek 运行真实 Agent Loop")
    parser.add_argument("--input", default="请查询订单 ord_1001 的状态和可退金额")
    parser.add_argument("--transfer", action="store_true", help="运行转账链路演示")
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = parse_args()
    if cli_args.transfer:
        asyncio.run(run_transfer_demo())
    elif cli_args.agent:
        asyncio.run(run_deepseek_agent(cli_args.input))
    else:
        asyncio.run(run_offline_demo())
