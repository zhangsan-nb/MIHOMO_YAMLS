from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditResult, RoutingChange


def render_text(result: AuditResult) -> str:
    r = result.report
    lines = [
        "=== MIHOMO ROUTING AUDIT ===",
        "",
        f"Baseline: {r.get('baseline', '')}",
        f"Candidate: {r.get('candidate', '')}",
        f"Mihomo: {result.mihomo_version or r.get('mihomo_version', '')}",
        f"Oracle: {result.oracle_kind}",
        f"Routing oracle: {r.get('routing_oracle', result.oracle_kind)}",
        f"hitCount API: {'yes' if r.get('hitcount_supported') else 'UNSUPPORTED'}",
        f"Upstream commit: {r.get('upstream_commit') or '(none)'}",
        f"Readable baseline: {r.get('readable_baseline_count', 0)} paired",
        f"Binary-only: {', '.join(r.get('binary_only') or []) or '(none)'}",
        f"DNS oracle: {r.get('dns_oracle', 'not applicable')}",
        f"ROUTING_SCOPE: {r.get('routing_scope', 'mirror-covered rulesets')}",
        f"FULL_CONFIG_EQUIVALENCE: {r.get('full_config_equivalence', False)}",
        "",
        "Changed providers:",
    ]
    changed = r.get("providers_changed") or []
    if changed:
        for name in changed:
            lines.append(f"  {name}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Unchanged:")
    unchanged = r.get("providers_unchanged") or []
    lines.append("  " + (", ".join(unchanged[:12]) or "(none)"))
    lines += [
        "",
        "Semantic diff:",
        f"  Added: {r.get('added', 0)}",
        f"  Removed: {r.get('removed', 0)}",
        f"  Unavailable providers: {r.get('semantic_unavailable', 0)}",
        "",
        "Coverage:",
        f"  { (r.get('coverage') or {}).get('providers_exercised', 0) } / "
        f"{ (r.get('coverage') or {}).get('providers_total', 0) } "
        f"({ (r.get('coverage') or {}).get('coverage_percent', 0) }%)",
        "  UNCOVERED: " + (", ".join((r.get('coverage') or {}).get('uncovered') or [])[:300] or "(none)"),
        "",
        f"Broad rules: {r.get('broad_critical', 0)}",
        f"Effective routing changes: {r.get('routing_changes', 0)}",
        "",
        "Golden regression:",
        f"  PASS: {r.get('golden_pass', 0)}",
        f"  FAIL: {r.get('golden_fail', 0)}",
        "",
        "Policy Contract:",
        f"  PASS: {r.get('policy_pass', 0)}",
        f"  FAIL: {r.get('policy_fail', 0)}",
        "",
        f"Risk: {result.risk}",
        f"Decision: {result.decision}",
        f"Publish: {'ALLOWED' if result.publish_allowed else 'BLOCKED'}",
        "",
        "Reasons:",
    ]
    if result.reasons:
        lines.extend(f"  - {x}" for x in result.reasons[:40])
    else:
        lines.append("  (none)")
    for change in (r.get("routing_change_details") or [])[:12]:
        lines += [
            "",
            f"DOMAIN: {change.get('host')}",
            f"OLD: {change.get('old_rule')} -> {change.get('old_policy')}",
            f"NEW: {change.get('new_rule')} -> {change.get('new_policy')}",
        ]
    lines.append("")
    return "\n".join(lines)


def write_reports(result: AuditResult, out_json: Path, out_text: Path | None = None) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mihomo_version": result.mihomo_version,
        "oracle": result.oracle_kind,
        "decision": result.decision,
        "publish_allowed": result.publish_allowed,
        "risk": result.risk,
        "reasons": result.reasons,
        "full_regression": result.full_regression,
        **result.report,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    text = render_text(result)
    result.text = text
    if out_text is None:
        out_text = out_json.with_suffix(".txt")
    out_text.write_text(text, encoding="utf-8")


def routing_change_dict(change: RoutingChange) -> dict:
    return {
        "host": change.host,
        "reason": change.reason,
        "old_rule": change.old.rule_text if change.old else None,
        "old_policy": change.old.policy if change.old else None,
        "new_rule": change.new.rule_text if change.new else None,
        "new_policy": change.new.policy if change.new else None,
    }
