# Approval Matrix

| 动作 | 自动 | 需要业务批准 | 需要部署确认 | 禁止 |
|---|---:|---:|---:|---:|
| 读取报告 | ✅ | | | |
| 查 APNIC/RDAP | ✅ | | | |
| 生成建议 | ✅ | | | |
| 运行本地测试 | ✅ | | | |
| 写 domain known decision | | ✅ | | |
| 写 CIDR known decision | | ✅ | | |
| 新增 local override | | ✅ | | |
| 修改 audit harness 等价 override | | ✅ | | |
| 修改 upstream MRS | | | | ✅ |
| Feature branch publish | | | | ✅ |
| 合并批准后的 feature 到 main | | ✅ | 视情况 | |
| 发布依赖真实配置 override 的更新 | | ✅ | ✅ | |
| 用 known decision 绕过 FAIL | | | | ✅ |
| blanket approve provider/commit | | | | ✅ |

## 用户语言映射

明确批准：

- “按建议处理”
- “接受”
- “同意这个路由”
- “保持原策略”
- “拒绝这个 upstream 变化”

不算批准：

- “看看”
- “分析一下”
- “是不是可以”
- “你觉得呢”
- “先测试”
