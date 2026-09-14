# Agent Safety Boundaries

## A. 允许的只读动作

无需额外批准：

- 读取 Git 状态/workflow/audit report
- 下载 Actions artifact
- 查看 branch/commit
- 读取 immutable source snapshots
- 查 RIR RDAP / WHOIS / BGP
- 计算 SHA256
- 运行本地 tests
- 生成审核卡和执行计划

## B. 需要用户明确批准 REVIEW 才能做

- 写 `audit/known-decisions.yaml`
- 写 Policy Contract
- 新增业务 local override
- 修改 real config 的业务路由策略
- 合并业务 policy feature branch

批准必须对应 domain 或 exact CIDR，禁止 witness IP。

## C. 发布生产的额外条件

- Feature CI PASS
- main-only Publish/Purge guard 有效
- 如依赖 local override，用户明确确认真实配置已部署并启用
- main merge 成功
- Production CI PASS

## D. 永远禁止

1. 用业务批准绕过 FAIL
2. 修改 upstream MRS 实现本地策略
3. blanket approve upstream commit/provider
4. Feature branch 发布生产
5. 泄露订阅 URL/token、Cookie、私钥、`.env`
6. 猜真实配置
7. 隐藏/删除未审核 routing change

Feature branch 意外发布：立即 STOP，按严重安全事件处理。

找不到唯一真实配置：`PRODUCTION_CONFIG_AMBIGUOUS`。

## E. Fail-closed STOP 状态

- `APPROVAL_REQUIRED`
- `SECURITY_BLOCKED`
- `SYSTEM_ERROR`
- `PRODUCTION_CONFIG_AMBIGUOUS`
- `REAL_CONFIG_NOT_FOUND`
- `NEW_UPSTREAM_REVIEW_REQUIRED`

## F. No-Test-Loop Boundary

没有新代码、新 upstream change、新 failure evidence 时，禁止重复完整测试。

Feature CI PASS 后必须推进下一阶段。

用户确认真实配置部署后必须推进生产发布。

Production release 完成后必须停止。
