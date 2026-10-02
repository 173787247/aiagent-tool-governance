# Python 工具治理框架

一套把**模型提交的不可信参数**变成**一次受控副作用**的治理框架 —— 参数校验 →
业务预检 → 权限判断 → 人工审批 → 超时处理 → 结果脱敏 → 审计追踪。

仓库里附带一个完整的示例工具 `transfer`（转账），把这条链路从头到尾跑通。

## 它解决什么

Agent 调用工具时，参数来自模型、副作用落在真实系统上。这两件事之间需要一层
确定性的检查，而且这一层不能靠提示词 —— 提示词可以被绕过，状态机不行。

框架把这条链路做成固定优先级的三态状态机：

```
deny 规则 ──→ plan 只读契约 ──→ 执行白名单 ──→ RBAC ──→ 业务预检
                                                            │
                              ┌─────────────────────────────┘
                              ↓
                     一次性参数绑定审批 ──→ bypass（只跳普通确认）
                              │
                              ↓
                     allow 规则 ──→ 危险 Shell 兜底 ──→ 默认放行
```

每一步都只可能**收紧**，不可能放宽：`bypassPermissions` 跳到的是「普通确认」，
越不过前面任何一道硬边界。`PermissionEngine.decide` 里那段编号注释就是这九步。

## 快速开始

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 离线演示：退款、Shell 模拟、注入拦截、plan 模式
python tool_governance_demo.py

# 转账链路：未审批→CONFIRM，审批后→OK，账号已脱敏，附审计日志
python tool_governance_demo.py --transfer

# 真实模型闭环（可选，需要 DEEPSEEK_API_KEY）
python tool_governance_demo.py --agent --input "查一下订单 ord_1001"

# 测试
python -m pytest tests/ -q
```

## 治理链路上的七件事

| 环节 | 实现位置 | 作用 |
|---|---|---|
| 参数校验 | `StrictArgs` + Pydantic | `extra="forbid"` 挡住模型注入的多余键，`strict=True` 挡住类型漂移 |
| 业务预检 | `ToolDefinition.precheck` | 资源归属、状态、额度在 handler **之前**验证 |
| 权限判断 | `PermissionEngine.decide` | 九步固定优先级，只收紧不放宽 |
| 人工审批 | `ApprovalStore` | 一次性、参数绑定：摘要 = `SHA-256(tool_name + 规范化参数)` |
| 超时处理 | `ToolRuntime._execute_with_recovery` | 读/幂等超时是 `TIMEOUT`，非幂等写是 `TIMEOUT_UNKNOWN` |
| 结果脱敏 | `_redact` | 键名命中 `token/secret/password/authorization` 一律 `***`；字符串走正则 |
| 审计追踪 | `AuditSink` | decision 与 execution 两阶段各记一条，含参数键名与耗时 |

## 示例工具：transfer

一个高风险写工具，覆盖了上面全部七个环节。

| # | 位置 | 做了什么 |
|---|---|---|
| 1 | `ACCOUNTS` | 四个账户的初始余额。可变 dict —— 测试的 `isolated_accounts` fixture 逐用例快照还原 |
| 2 | `TransferArgs` | 继承 `StrictArgs`，两个账号字段用同一套正则，金额 `gt=0, le=100_000` |
| 3 | `transfer_precheck` | 先拦演示区间 `(50000, 80000]`，再查余额；只判断，不动余额 |
| 4 | `transfer_handler` | `sleep(3.0)` **排在扣款之前**；转入账户不存在则拒绝；改余额；返回 `txn_id` |
| 5 | `build_tools()` | 注册 `transfer`：`WRITE` + `HIGH` + 需审批 + 非幂等 + `max_retries=0`，`timeout_seconds=1.0` |
| 6 | `_redact` | `ACC-A-123456` → `ACC-A-****3456`，函数式替换 |

## 三个不显眼但决定行为的地方

**① `sleep` 必须在扣款之前。**
框架用 `asyncio.timeout` 掐断执行，取消只发生在 `await` 点上。只要扣款排在
`sleep` 后面，超时那一刻余额就还没动过 —— 这正是
`test_transfer_timeout_...leaves_balances_untouched` 断言的东西。把 `sleep`
挪到扣款之后，测试会失败，生产里会变成「报了超时但钱已经出去了」。

**② `timeout_seconds` 必须小于 `sleep` 的 3.0 秒。**
策略里的超时若大于它，框架等不到超时，调用会真睡满 3 秒然后转账成功 ——
走到的是 `OK` 而不是 `TIMEOUT_UNKNOWN`。这里取 1.0。

**③ `canonical_target` 必须把金额算进审批摘要。**
审批是参数绑定的。如果 `canonical_target` 只拼两个账号，那么「按 1200 元申请
审批、再改成 9000 元执行」就能复用同一张审批 ——
`test_transfer_requires_approval_bound_to_arguments...` 里的 `tampered` 那一步
会从 `CONFIRM` 变成 `ALLOW`。所以三段都拼进去。

## 框架的固定约束

改动这个仓库时，下面三条是边界，不是风格偏好：

- `PermissionEngine.decide` 的九步优先级顺序是框架本身，不要重排
  （deny → plan → 白名单 → RBAC → 预检 → 审批 → bypass → allow 规则 → 危险 Shell 兜底）。
- 所有调用经 `ToolRuntime.invoke`，不要绕过它直接调 handler —— 绕过就等于跳过全部治理。
- `TransferArgs` 的 `extra="forbid"` 保留（继承自 `StrictArgs`）—— 注入测试靠它。

## 文件

```
tool_governance_demo.py          治理框架 + transfer 工具 + 三个可跑入口
tests/test_tool_governance.py    转账链路的 5 个测试
tests/conftest.py                让 pytest 从项目根导入
requirements.txt
```

## 关于这个框架的定位

它是一份教学规模的演示，不是生产库：状态都在进程内存里，审批人是一个函数调用，
危险 Shell 只做正则兜底。它的价值在于把「模型参数 → 受控副作用」这条链路上
**每一个必须做的判断**摆在一个文件里，让每一步都能被读、被测试、被替换。
