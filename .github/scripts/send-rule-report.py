#!/usr/bin/env python3

import csv
import json
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


def load_audit_decision(path: Path | None) -> tuple[str, str, list[str]]:
    if path is None or not path.is_file():
        return "UNKNOWN", "", []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return "ERROR", f"cannot read audit report: {exc}", []

    decision = str(data.get("decision") or "").upper()

    if decision not in {"PASS", "REVIEW", "FAIL"}:
        return "ERROR", f"invalid audit decision: {decision!r}", []

    risk = str(data.get("risk") or "")
    reasons = [str(x) for x in (data.get("reasons") or [])]

    return decision, risk, reasons


def determine_overall_status(
    mirror_outcome: str,
    audit_outcome: str,
    publish_outcome: str,
    purge_outcome: str,
    decision: str,
    failed_count: int,
) -> str:
    if mirror_outcome != "success" or failed_count > 0:
        return "运行失败"

    if publish_outcome == "failure" or purge_outcome == "failure":
        return "运行失败"

    if decision == "REVIEW":
        if publish_outcome in {"skipped", "unknown", "success"} and purge_outcome in {"skipped", "unknown", "success"}:
            return "需审核"
        return "运行失败"

    if decision == "FAIL":
        if publish_outcome in {"skipped", "unknown", "success"} and purge_outcome in {"skipped", "unknown", "success"}:
            return "安全阻断"
        return "运行失败"

    if decision == "PASS":
        if audit_outcome == "success" and publish_outcome in {"success", "skipped"} and purge_outcome in {"success", "skipped"}:
            return "成功"
        return "运行失败"

    return "运行失败"


def stage_summary(
    mirror_outcome: str,
    audit_outcome: str,
    publish_outcome: str,
    purge_outcome: str,
    overall_status: str,
    decision: str,
) -> list[str]:
    outcome_names = {
        "success": "成功",
        "failure": "失败",
        "skipped": "跳过",
        "cancelled": "取消",
        "unknown": "未知",
    }

    mirror_label = outcome_names.get(mirror_outcome, mirror_outcome)

    if overall_status == "需审核" or decision == "REVIEW":
        audit_label = "需人工审核"
    elif overall_status == "安全阻断" or decision == "FAIL":
        audit_label = "安全阻断"
    elif decision == "PASS" and audit_outcome == "success":
        audit_label = "通过"
    else:
        audit_label = outcome_names.get(audit_outcome, audit_outcome)

    if overall_status in {"需审核", "安全阻断"} and publish_outcome in {"skipped", "unknown"}:
        publish_label = "已阻断"
    else:
        publish_label = outcome_names.get(publish_outcome, publish_outcome)

    if overall_status in {"需审核", "安全阻断"} and purge_outcome in {"skipped", "unknown"}:
        purge_label = "已跳过"
    else:
        purge_label = outcome_names.get(purge_outcome, purge_outcome)

    return [
        f"- 下载校验：{mirror_label}",
        f"- 供应链审计：{audit_label}",
        f"- 发布分支：{publish_label}",
        f"- 刷新 CDN：{purge_label}",
    ]


def build_message(
    rows: list[dict[str, str]],
    audit_report_path: Path | None = None,
) -> tuple[str, str]:
    if audit_report_path is None:
        env_path = os.getenv("AUDIT_REPORT", "").strip()
        if env_path:
            audit_report_path = Path(env_path)

    new = [row for row in rows if row.get("status") == "NEW"]
    updated = [row for row in rows if row.get("status") == "UPDATED"]
    unchanged = [row for row in rows if row.get("status") == "UNCHANGED"]
    failed = [row for row in rows if row.get("status") == "FAILED"]

    mirror_outcome = os.getenv("MIRROR_OUTCOME", "unknown")
    audit_outcome = os.getenv("AUDIT_OUTCOME", "unknown")
    publish_outcome = os.getenv("PUBLISH_OUTCOME", "unknown")
    purge_outcome = os.getenv("PURGE_OUTCOME", "unknown")

    decision, risk, reasons = load_audit_decision(audit_report_path)

    overall_status = determine_overall_status(
        mirror_outcome=mirror_outcome,
        audit_outcome=audit_outcome,
        publish_outcome=publish_outcome,
        purge_outcome=purge_outcome,
        decision=decision,
        failed_count=len(failed),
    )

    stage_lines = stage_summary(
        mirror_outcome=mirror_outcome,
        audit_outcome=audit_outcome,
        publish_outcome=publish_outcome,
        purge_outcome=purge_outcome,
        overall_status=overall_status,
        decision=decision,
    )

    changed = new + updated
    validated = len(new) + len(updated) + len(unchanged)

    if overall_status == "成功":
        subject = f"[MIHOMO YAMLS规则] 成功 | 校验 {validated} | 变化 {len(changed)}"
    elif overall_status == "需审核":
        subject = f"[MIHOMO YAMLS规则] 需审核 | 变化 {len(changed)} | 发布已阻断"
    elif overall_status == "安全阻断":
        subject = f"[MIHOMO YAMLS规则] 安全阻断 | 变化 {len(changed)} | 发布已阻断"
    else:
        if failed:
            subject = f"[MIHOMO YAMLS规则] 运行失败 | 校验失败 {len(failed)}"
        else:
            subject = "[MIHOMO YAMLS规则] 运行失败 | 阶段异常"

    china_time = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8)))
    lines = [
        f"MIHOMO YAMLS规则镜像：{overall_status}",
        f"北京时间：{china_time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"校验成功：{validated}",
        f"变化：{len(changed)}（新增 {len(new)}，更新 {len(updated)}）",
        f"未变化：{len(unchanged)}",
        f"失败：{len(failed)}",
        "",
        "阶段：",
        *stage_lines,
    ]

    if decision in {"REVIEW", "FAIL"}:
        lines.extend([
            "",
            "审计：",
            f"Decision: {decision}",
            f"Risk: {risk}",
            "",
            "原因：",
        ])
        if reasons:
            lines.extend(f"- {r}" for r in reasons)
        else:
            lines.append("- 无")

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

    audit_report_env = os.getenv("AUDIT_REPORT", "").strip()
    audit_report_path = Path(audit_report_env) if audit_report_env else None

    rows = load_report(Path(sys.argv[1]))
    subject, body = build_message(rows, audit_report_path)
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
