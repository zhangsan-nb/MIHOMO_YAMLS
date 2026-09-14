# 🟡 MIHOMO 规则审核

状态：`APPROVAL_REQUIRED`

需要你决定：**{{decision_count}} 项**

## 决策 {{index}}：{{policy_unit}}

### 发生了什么

旧策略：`{{old_policy}}`  
新策略：`{{new_policy}}`

{{plain_language_change}}

### 影响范围

{{impact_scope}}

### 证据

- 源规则：`{{exact_source_rule}}`
- 变化方向：`{{added_or_removed}}`
- 注册/归属：{{rir_summary}}
- 路由信息：{{bgp_summary}}
- 证据一致性：`{{evidence_consistency}}`

### 风险

`{{risk_level}}`

{{risk_explanation}}

### 建议

**{{recommendation}}**

{{recommendation_reason}}

你只需要选一个：

1. **接受建议**
2. **保持原策略**
3. **暂不处理**

系统在你确认前不会发布这项变化。
