# 给 Agent 的一次性安装指令

你现在只做一个 Skill 安装任务，不做规则发布，不修改现有审计业务逻辑。

目标仓库：`zhangsan-nb/MIHOMO_YAMLS`

待安装包：`MIHOMO-Rule-Review-Skill-V1`

## 1. 找 Skill 根目录

先检查仓库是否已有统一 Skill 根，例如：

- `skills/`
- `.agents/skills/`
- `.claude/skills/`
- `.codex/skills/`

如果已有明确惯例，使用现有惯例。

如果没有，创建：`skills/mihomo-rule-review/`

不要为了 Skill 安装重构其他目录。

## 2. 复制

把整个包内容复制到 `<skill-root>/mihomo-rule-review/`。

至少包含：

- `SKILL.md`
- `policy/`
- `runbook/`
- `agent/`
- `templates/`
- `schemas/`
- `examples/`
- `references/`

## 3. 安全检查

安装前后执行 `git status --short`。

确认没有加入：

- `.env`
- token
- subscription URL
- real OpenClash production config
- private key
- Cookie
- Actions artifact
- scheduled-stability evidence dump

Skill 只包含规则、模板、文档、schema。

## 4. 可选 AGENTS.md 指针

如果仓库已使用 `AGENTS.md`，可追加：

```md
## MIHOMO Rule Review
When reviewing MIHOMO/OpenClash audit emails, GitHub Actions runs,
REVIEW/FAIL decisions, or routing-policy changes, read:
`skills/mihomo-rule-review/SKILL.md`
Do not bypass FAIL or publish from feature branches.
```

如果仓库没有使用 AGENTS.md，不要新建复杂全局 Agent 管理结构。

## 5. 验证

确认：

- Markdown 可读
- YAML 可 parse
- JSON schema 可 parse
- 没有绝对本地秘密路径被当成运行依赖
- Skill 不修改现有 CI workflow

## 6. Commit

只提交 Skill 安装文件。

建议 commit：`docs: add MIHOMO rule review skill v1`

## 7. 最终报告

```text
MIHOMO_RULE_REVIEW_SKILL_INSTALLED

Skill path:
...

SKILL.md:
OK

Review policy:
OK

Runbook:
OK

Agent boundaries:
OK

Templates:
OK

Schema:
OK

Secrets included:
NO

Existing audit logic modified:
NO
```

然后停止。不要触发 workflow，不要运行 production release，不要删除现有分支。
