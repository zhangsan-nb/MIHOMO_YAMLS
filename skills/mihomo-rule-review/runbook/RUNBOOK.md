# MIHOMO Rule Review Runbook

## 0. 目标

把一次邮件/CI 异常处理成有限状态机，避免“不断测试、始终进不了下一阶段”。

## 状态机

```text
INTAKE
  -> CLASSIFY
     -> PASS -> NO_ACTION
     -> REVIEW -> NORMALIZE -> EXISTING_POLICY -> EVIDENCE -> USER_APPROVAL
        -> ACCEPT -> FEATURE_IMPL
        -> REJECT -> LOCAL_OVERRIDE -> FEATURE_IMPL
        -> HOLD -> STOP
     -> FAIL -> SECURITY_BLOCKED
     -> ERROR -> SYSTEM_ERROR

FEATURE_IMPL
  -> FEATURE_CI
     -> PASS -> REAL_CONFIG_GATE or PRODUCTION_RELEASE
     -> REVIEW -> ONLY_NEW_CHANGE_REVIEW
     -> FAIL -> FIX_TECHNICAL_CAUSE

REAL_CONFIG_GATE
  -> user confirms deployed_and_enabled
  -> PRODUCTION_RELEASE

PRODUCTION_RELEASE
  -> ONE_PRODUCTION_CI
     -> PASS -> VERIFY_RELEASE -> PRODUCTION_RELEASE_COMPLETE
     -> REVIEW/FAIL -> STOP_AND_REPORT
```

## 1. Intake

接受邮件、Run URL、Run ID、JSON、TXT。优先结构化 JSON。

报告缺失：`SYSTEM_ERROR`，不要从日志猜 Decision。

## 2. Classify

- PASS -> `🟢 NO_ACTION`
- REVIEW -> `🟡 APPROVAL_REQUIRED`
- FAIL -> `🔴 SECURITY_BLOCKED`
- 技术错误 -> `🛠️ SYSTEM_ERROR`

## 3. Normalize REVIEW

### Domain

回到 exact source rule；一个 suffix rule 只产生一个人工决策。

### IP

回到 exact CIDR；禁止按 witness IP 持久批准。

## 4. Check Existing Policy

依次检查：

1. `audit/known-decisions.yaml`
2. `audit/harness.yaml`
3. Policy Contract
4. Golden
5. 当前真实配置 local override

已有策略不得重复问用户。

## 5. Evidence

只有真正未决项才查外部证据。

CIDR 优先：RIR -> allocation -> org/country -> BGP -> metadata -> GeoIP。

## 6. Recommendation

只允许：

- `ACCEPT_NEW_POLICY`
- `KEEP_OLD_POLICY`
- `HOLD`

建议不是批准。

## 7. User Approval

给三个选项：接受建议 / 保持原策略 / 暂不处理。

“按你的建议处理”算明确授权。

## 8. Implementation

接受 upstream：优先 known decision / Policy Contract。

拒绝 upstream：real config local override + harness 等价 override。

禁止改 upstream MRS。

## 9. Feature CI

Feature branch：可审计，不可 Publish，不可 Purge production。

PASS 后必须推进；不得无新证据继续造“Phase N+1 测试”。

## 10. Loop Breaker

若代码无新变化、本地测试已 PASS、Feature CI 已 PASS、无新 routing change，则禁止继续增加测试。

下一步必须是：

- real config 部署
或
- production release

## 11. Real Config Deployment

依赖 local override 时，等待用户明确：`已经部署并启用`。

这一步不扩展审计代码。

## 12. Production Release

1. merge approved feature -> main
2. push main
3. 只触发一次 production workflow
4. 等结果

此时 REVIEW 只处理新的 upstream 变化，不重复审核已批准变化。

## 13. Release Verification

确认：Publish SUCCESS、Purge SUCCESS（如启用）、production branch 推进、baseline 更新、source/MRS lockstep、无未审核变化。

然后输出：`PRODUCTION_RELEASE_COMPLETE`。

## 14. Post-release

不要立即删除审核分支和证据。至少等下一次真实 scheduled run 后再清理。
