# Email Triage

## 邮件：成功
输出 `🟢 NO_ACTION`

## 邮件：需审核
读取 Run / artifact，进入 REVIEW normalization，输出 `🟡 APPROVAL_REQUIRED`

## 邮件：安全阻断
读取失败原因，输出 `🔴 SECURITY_BLOCKED`

## 邮件：运行失败
先判断是否报告缺失、Oracle/CI 故障，输出 `🛠️ SYSTEM_ERROR`

不要把“运行失败”自动等价成规则危险。
