# MIHOMO Rule Review Skill V1

面向 `zhangsan-nb/MIHOMO_YAMLS` 的长期审核 Skill。

目标不是让用户学习 CIDR、RuleSet、MRS 或 Mihomo Oracle，而是把审计输出转成普通人能做决定的中文审核卡，并在明确批准后生成安全执行计划。

## 用户只需要记住

- 邮件显示 **成功**：不用处理。
- 邮件显示 **需审核**：把邮件、Run URL 或 Run ID 交给本 Skill。
- 邮件显示 **安全阻断 / 运行失败**：交给本 Skill，不要手动放行。
- Skill 给出建议后，只需回答：`按建议处理`、`保持原策略` 或 `暂不处理`。

## 四种用户态

| 用户态 | 含义 | 用户动作 |
|---|---|---|
| `NO_ACTION` | 自动审核通过 | 不处理 |
| `APPROVAL_REQUIRED` | 新业务策略变化 | 看中文建议并批准/拒绝 |
| `SECURITY_BLOCKED` | 安全/完整性问题 | 不放行 |
| `SYSTEM_ERROR` | 审计/CI/Oracle 故障 | 修系统，不做业务批准 |

## 权威状态

Skill 不复制业务决策作为第二套“真相”。长期决策以当前仓库的：

- `audit/known-decisions.yaml`
- `audit/harness.yaml`
- 当前 audit report
- 当前真实生产配置

为准。

版本：`V1.0.0`
