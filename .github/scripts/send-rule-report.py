#!/usr/bin/env python3

import csv
import os
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path


def load_report(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def stage_summary() -> tuple[bool, list[str]]:
    stages = [
        ("下载校验", os.getenv("MIRROR_OUTCOME", "unknown")),
        ("发布分支", os.getenv("PUBLISH_OUTCOME", "unknown")),
        ("刷新 CDN", os.getenv("PURGE_OUTCOME", "unknown")),
    ]
    outcome_names = {
        "success": "成功",
        "failure": "失败",
        "skipped": "跳过",
        "cancelled": "取消",
        "unknown": "未知",
    }
    successful = all(outcome in {"success", "skipped"} for _, outcome in stages)
    return successful, [f"- {name}：{outcome_names.get(outcome, outcome)}" for name, outcome in stages]


def build_message(rows: list[dict[str, str]]) -> tuple[str, str]:
    new = [row for row in rows if row.get("status") == "NEW"]
    updated = [row for row in rows if row.get("status") == "UPDATED"]
    unchanged = [row for row in rows if row.get("status") == "UNCHANGED"]
    failed = [row for row in rows if row.get("status") == "FAILED"]
    stages_ok, stage_lines = stage_summary()
    overall_ok = stages_ok and not failed
    result = "成功" if overall_ok else "失败"
    changed = new + updated
    validated = len(new) + len(updated) + len(unchanged)

    subject = (
        f"[MIHOMO YAMLS规则] {result} | 校验成功 {validated} | "
        f"变化 {len(changed)} | 失败 {len(failed)}"
    )
    china_time = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8)))
    lines = [
        f"MIHOMO YAMLS规则镜像：{result}",
        f"北京时间：{china_time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"校验成功：{validated}",
        f"变化：{len(changed)}（新增 {len(new)}，更新 {len(updated)}）",
        f"未变化：{len(unchanged)}",
        f"失败：{len(failed)}",
        "",
        "阶段：",
        *stage_lines,
    ]

    lines.extend(["", "本次有变化："])
    if changed:
        lines.extend(f"- {row['path']}（{row['status']}）" for row in changed)
    else:
        lines.append("- 无")

    lines.extend(["", "失败："])
    if failed:
        lines.extend(f"- {row['path']}：{row.get('detail', '未知错误')}" for row in failed)
    else:
        lines.append("- 无")

    run_url = os.getenv("RUN_URL", "")
    if run_url:
        lines.extend(["", f"运行详情：{run_url}"])

    return subject, "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: send-rule-report.py REPORT_TSV [--preview]", file=sys.stderr)
        return 2

    rows = load_report(Path(sys.argv[1]))
    subject, body = build_message(rows)
    if "--preview" in sys.argv[2:]:
        print(subject)
        print(body)
        return 0

    recipient_text = os.getenv("RULE_EMAIL_TO", "").strip()
    if not recipient_text:
        print("email notification skipped: RULE_EMAIL_TO is not configured")
        return 0

    settings = {
        "RULE_EMAIL_SMTP_HOST": os.getenv("RULE_EMAIL_SMTP_HOST", "").strip(),
        "RULE_EMAIL_SMTP_USERNAME": os.getenv("RULE_EMAIL_SMTP_USERNAME", "").strip(),
        "RULE_EMAIL_SMTP_PASSWORD": os.getenv("RULE_EMAIL_SMTP_PASSWORD", ""),
    }
    missing = [name for name, value in settings.items() if not value]
    if missing:
        print(f"email notification misconfigured: missing {', '.join(missing)}", file=sys.stderr)
        return 1

    security = os.getenv("RULE_EMAIL_SMTP_SECURITY", "ssl").strip().lower()
    if security not in {"ssl", "starttls"}:
        print("RULE_EMAIL_SMTP_SECURITY must be ssl or starttls", file=sys.stderr)
        return 1

    default_port = 465 if security == "ssl" else 587
    port = int(os.getenv("RULE_EMAIL_SMTP_PORT", str(default_port)))
    sender = os.getenv("RULE_EMAIL_FROM", "").strip() or settings["RULE_EMAIL_SMTP_USERNAME"]
    recipients = [item.strip() for item in recipient_text.replace(";", ",").split(",") if item.strip()]
    if not recipients:
        print("RULE_EMAIL_TO does not contain a recipient", file=sys.stderr)
        return 1

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    context = ssl.create_default_context()
    if security == "ssl":
        with smtplib.SMTP_SSL(settings["RULE_EMAIL_SMTP_HOST"], port, timeout=30, context=context) as smtp:
            smtp.login(settings["RULE_EMAIL_SMTP_USERNAME"], settings["RULE_EMAIL_SMTP_PASSWORD"])
            smtp.send_message(message, from_addr=sender, to_addrs=recipients)
    else:
        with smtplib.SMTP(settings["RULE_EMAIL_SMTP_HOST"], port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(settings["RULE_EMAIL_SMTP_USERNAME"], settings["RULE_EMAIL_SMTP_PASSWORD"])
            smtp.send_message(message, from_addr=sender, to_addrs=recipients)

    print(f"email report sent to {len(recipients)} recipient(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
