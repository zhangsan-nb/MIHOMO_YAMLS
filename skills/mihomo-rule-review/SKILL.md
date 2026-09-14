# Skill: MIHOMO Rule Review

Version: 1.0.0

## Purpose

将 MIHOMO/OpenClash 规则供应链审计结果转化为：

1. 普通用户能理解的中文结论；
2. 最少数量的人工决策项；
3. 有证据链的建议；
4. 经明确批准后才能执行的安全变更计划；
5. 默认 fail-closed、可追踪、可回滚的发布流程。

本 Skill 不负责“让 CI 变绿”，而负责解释为什么绿、黄、红，以及下一步应该做什么。

## Activation

当用户提供以下任一内容时启用：

- GitHub Actions Run URL / Run ID
- MIHOMO 审计邮件
- `audit-report.json` / `audit-report.txt`
- `REVIEW` / `FAIL` / `需审核` / `安全阻断`
- “审核一下这个” / “按建议处理” / “这个需要处理吗”

## User Experience Contract

用户不需要理解 CIDR、RuleSet、MRS、Oracle、baseline、witness、BGP。

第一屏只允许四种状态：

- 🟢 `NO_ACTION`
- 🟡 `APPROVAL_REQUIRED`
- 🔴 `SECURITY_BLOCKED`
- 🛠️ `SYSTEM_ERROR`

如果是 `APPROVAL_REQUIRED`，必须把多个 witness 合并成最少的业务决策。

## Core Decision Model

### PASS

输出 `NO_ACTION`。不要制造假确认。

### REVIEW

输出 `APPROVAL_REQUIRED`。只呈现真正需要人决定的新策略变化。

### FAIL

输出 `SECURITY_BLOCKED`。不得用 known decision、白名单、override 或用户同意绕过技术完整性失败。

### Technical failure / missing report

输出 `SYSTEM_ERROR`。不得把系统故障伪装成业务 REVIEW。

## Review Normalization

### Domain

必须从 witness 还原到源规则。多个子域若来自同一 `DOMAIN-SUFFIX`，只能产生一个人工决策。

### IP

必须从 witness 还原到 exact upstream CIDR。永久审批对象是 CIDR，不是抽样 IP。

## Evidence Policy

### Source identity

优先确认：

1. exact semantic diff
2. added / removed side
3. OLD effective route
4. NEW effective route

### IP attribution

证据优先级：

1. RIR RDAP / WHOIS
2. exact allocation range
3. registered organization / country
4. BGP origin
5. reputable network metadata
6. geolocation

ASN 注册国家不能单独代表 IP 归属；GeoIP 不能压过 RIR allocation。

## Existing Policy First

人工审核前必须先检查：

- `audit/known-decisions.yaml`
- `audit/harness.yaml`
- Policy Contract
- Golden regression
- 当前真实生产配置 local override

已有明确长期决策的变化不得重复打扰用户。

## Approval Semantics

人工批准必须表达“期望策略”，不是“永久忽略变化”。

正确：`103.238.46.0/23 expected CHINA`。

未来如果该网段从 CHINA 变 FINAL，仍必须重新 REVIEW。

## Local Override Semantics

如果用户拒绝 upstream 路由变化：

- 不修改 upstream MRS
- 不破坏 source/MRS 一致性
- 在真实配置中添加更高优先级 local override
- audit harness 加语义等价 override

项目策略映射：

- `FINAL` ↔ `🧩 兜底流量`
- `CHINA` ↔ `🇨🇳 国内流量`
- `PROXY` ↔ `🌍 国外流量`

## Real Config Rule

真实 OpenClash 配置可能位于仓库外并包含订阅 token。

必须：

- 视为敏感本地文件
- 禁止提交公开仓库
- 禁止在报告中输出完整敏感内容
- 只验证必要规则和顺序

无法唯一定位真实配置时：`STOP: PRODUCTION_CONFIG_AMBIGUOUS`。

## Routing Oracle Rules

- 真实 Mihomo 是最终路由裁判
- `UNMATCHED != UNCHANGED`
- OLD / NEW 任一侧真正命中 changed RuleSet 即可算 exercised
- inline rule policy 相同不等于 provider 被 exercised
- fallback witness 必须有上限、确定性、透明报告
- fallback 发现新 routing change 必须重新 REVIEW

## Security Rules

永远禁止：

1. 通过 known decision 绕过 FAIL
2. 为了过 CI 加 blanket approval
3. 整体批准一个 upstream commit
4. 整体批准 provider 的未来所有变化
5. 单独批准 witness IP 而忽略 exact CIDR
6. 编辑 upstream MRS 实现本地策略
7. Feature branch 发布生产规则
8. 未部署真实配置就发布依赖 local override 的规则
9. 未确认 production branch 推进就宣称发布成功
10. 暴露订阅 token、私钥、Cookie、Authorization header

## Loop Breaker

避免“永远在测试”。

当：

- 本地 tests PASS
- Feature CI PASS
- 无新的未审核 routing change
- Feature branch 没修改生产

则停止扩展测试。

如果依赖真实配置 local override，下一步只等用户确认：`已经部署并启用`。

确认后：merge -> 一次 production CI -> PASS 则发布并收官。

没有代码变化，不重复跑完整测试。

## Required User-Facing Output

REVIEW 时首先输出：

- 状态
- 需要决定几项
- 每项“发生了什么”
- 影响范围
- 证据
- 风险
- 建议
- 三个用户选择

不要先输出长日志。

## Execution After Approval

只有用户明确“按建议处理 / 接受 / 保持原策略”等授权后才能生成执行计划。

执行计划必须：

- 使用 feature branch
- 明确 expected SHA
- 明确 STOP 条件
- Feature branch 不可发布
- 明确生产发布条件
- 明确最终验收

## Final Release Acceptance

至少确认：

- main 已含批准策略
- Production CI PASS
- Publish SUCCESS
- Purge SUCCESS（如启用）
- `openclash-rules` 已推进
- baseline 已更新
- source/MRS lockstep 成立
- real config 已部署
- 无未审核 routing change

最终输出 `PRODUCTION_RELEASE_COMPLETE` 后停止，不再“顺便再测一次”。
