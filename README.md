# Python 工具治理框架 —— 新增「转账」工具

在给定的工具治理框架（`tool_governance_demo.py`）上接入一个 `transfer` 工具，
把 **参数校验 → 业务预检 → 权限判断 → 人工审批 → 超时处理 → 结果脱敏 → 审计追踪**
整条链路跑通。

## 验收

```sh
python -m pytest tests/test_tool_governance.py -v -k "transfer"
```

```
5 passed
```

## 运行

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python tool_governance_demo.py              # 原有离线演示（退款 / Shell）
python tool_governance_demo.py --transfer   # 转账链路演示（审批 → 脱敏 → 审计）
python -m pytest tests/ -q                  # 全部测试
```

## 六个任务对应的改动

| 任务 | 位置 | 做了什么 |
|---|---|---|
| 1 | `ACCOUNTS` | 四个账户的初始余额。必须是可变 dict —— 测试的 `isolated_accounts` fixture 逐用例快照还原 |
| 2 | `TransferArgs` | 继承 `StrictArgs`，两个账号字段用同一套正则，金额 `gt=0, le=100_000` |
| 3 | `transfer_precheck` | 先拦教学区间 `(50000, 80000]`，再查余额；只判断，不动余额 |
| 4 | `transfer_handler` | `sleep(3.0)` **排在扣款之前**；转入账户不存在则拒绝；改余额；返回 `txn_id` |
| 5 | `build_tools()` | 注册 `transfer`：`WRITE` + `HIGH` + 需审批 + 非幂等 + `max_retries=0`，`timeout_seconds=1.0` |
| 6 | `_redact` | `ACC-A-123456` → `ACC-A-****3456`，函数式替换 |

## 三个不显眼但要紧的地方

**① `sleep` 必须在扣款之前。**
框架用 `asyncio.timeout` 掐断执行，取消只会发生在 `await` 点上。
只要扣款排在 `sleep` 后面，超时那一刻余额就还没动过 —— 这正是
`test_transfer_timeout_...leaves_balances_untouched` 断言的东西。
把 `sleep` 挪到扣款之后，测试会失败，而且生产里会变成「超时了但钱已经出去了」。

**② `timeout_seconds` 必须小于 3.0。**
任务 4 的演示值就是 `sleep(3.0)`。策略里的超时若大于它，框架等不到超时，
测试会真睡满 3 秒然后转账成功 —— 走到的是 `OK` 而不是 `TIMEOUT_UNKNOWN`。
这里取 1.0。

**③ `canonical_target` 必须把金额算进审批摘要。**
审批是参数绑定的：`ApprovalStore` 用 `tool_name + 规范化参数` 的 SHA-256 做摘要。
如果 `canonical_target` 只拼两个账号，那么「先按 1200 元申请审批，再改成 9000 元执行」
就能复用同一张审批 —— `test_transfer_requires_approval_bound_to_arguments...`
里的 `tampered` 那一步就会从 `CONFIRM` 变成 `ALLOW`。所以三段都拼进去。

## 没有改动的地方

- `PermissionEngine.decide` 的优先级顺序一行未动（deny → plan → 白名单 → RBAC → 预检 → 审批 → bypass → allow 规则 → 危险 Shell 兜底）。
- 测试全部经 `ToolRuntime.invoke`，没有直接调用 handler。
- `TransferArgs` 的 `extra="forbid"` 保留（继承自 `StrictArgs`）—— 注入测试靠它。

## 文件

```
tool_governance_demo.py          治理框架 + transfer 工具
tests/test_tool_governance.py    5 个链路测试（作业给定）
tests/conftest.py                让 pytest 从项目根导入
requirements.txt
```
