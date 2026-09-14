# Example: CIDR REVIEW

输入 witness：`103.238.46.1 FINAL -> CHINA`

源 diff：`+ 103.238.46.0/23`

正确 policy unit：`103.238.46.0/23`

错误：批准单个 `103.238.46.1`。

如果用户批准，应表达为 `103.238.46.0/23 expected CHINA`。未来反向变化仍重新 REVIEW。
