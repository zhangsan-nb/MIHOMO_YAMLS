"""Provider coverage and changed-but-unexercised detection."""
from __future__ import annotations

import re

from .models import MatchResult, ProviderSnapshot

_RULESET = re.compile(r"(?:RuleSet|RULE-SET)[\(\s,]+([A-Za-z0-9_-]+)", re.I)


def provider_from_match(match: MatchResult) -> str | None:
    text = f"{match.rule_text} {match.payload or ''}"
    m = _RULESET.search(text)
    if m:
        return m.group(1)
    return None


def collect_exercised(matches: list[MatchResult]) -> set[str]:
    out: set[str] = set()
    for match in matches:
        name = provider_from_match(match)
        if name:
            out.add(name)
    return out


def coverage_report(
    *,
    provider_names: list[str],
    exercised: set[str],
    harness_names: set[str],
) -> dict:
    total = len(provider_names)
    exercised_in = [n for n in provider_names if n in exercised]
    uncovered = [n for n in provider_names if n not in exercised]
    harness_uncovered = [n for n in uncovered if n in harness_names]
    pct = (100.0 * len(exercised_in) / total) if total else 0.0
    return {
        "providers_total": total,
        "providers_exercised": len(exercised_in),
        "providers_uncovered": len(uncovered),
        "coverage_percent": round(pct, 1),
        "exercised": exercised_in,
        "uncovered": uncovered,
        "harness_uncovered": harness_uncovered,
    }


def changed_unexercised(changed: list[str], exercised: set[str], hosts_by_provider: dict[str, list[str]]) -> list[str]:
    """Changed providers with no golden/witness/sentinel actually run through the oracle."""
    bad = []
    for name in changed:
        if name in exercised:
            continue
        if hosts_by_provider.get(name):
            # hosts were queued but none hit this RULE-SET
            bad.append(name)
            continue
        bad.append(name)
    return bad


def propose_sentinels(rules, *, limit: int = 3) -> list[str]:
    from .analysis import blast_radius

    out: list[str] = []
    if not rules:
        return out
    for rule in rules:
        if rule.kind != "DOMAIN-SUFFIX":
            continue
        if blast_radius(rule) == "CRITICAL":
            continue
        if rule.value.count(".") < 1:
            continue
        if len(rule.value) < 6:
            continue
        host = rule.value.lower().rstrip(".")
        if host not in out:
            out.append(host)
        if len(out) >= limit:
            break
    return out
