# Design Principles

1. 可读源码做差异。
2. 真实 Mihomo 做裁判。
3. Golden 做回归保险。
4. Policy Contract 定义正确性。
5. known decisions 表达长期期望策略。
6. local override 表达“拒绝 upstream 变化”。
7. upstream MRS 保持原样。
8. 只有 PASS 才发布。
9. REVIEW 是业务决策，不是故障。
10. FAIL 是安全/完整性阻断，不能靠业务批准绕过。
11. `UNMATCHED != UNCHANGED`。
12. witness 是证据，不是 policy unit。
13. 自动化应减少人工审核，而不是隐藏新变化。
14. 发现新变化才重新审核；没有新变化就推进阶段。
