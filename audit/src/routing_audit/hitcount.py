"""Oracle selection: hitCount PRIMARY if present, else log FALLBACK."""
from __future__ import annotations

from .models import MatchResult
from .oracle import OracleError


def hitcount_supported(rules_payload) -> bool:
    items = rules_payload.get("rules") if isinstance(rules_payload, dict) else rules_payload
    if not isinstance(items, list) or not items:
        return False
    extra = items[0].get("extra") if isinstance(items[0], dict) else None
    return isinstance(extra, dict) and "hitCount" in extra


def snapshot_hits(rules_payload) -> list[tuple[int, int, str, str, str]]:
    items = rules_payload.get("rules") if isinstance(rules_payload, dict) else rules_payload
    out = []
    if not isinstance(items, list):
        return out
    for i, item in enumerate(items):
        extra = item.get("extra") or {}
        out.append(
            (
                i,
                int(extra.get("hitCount") or 0),
                str(item.get("type") or ""),
                str(item.get("payload") or ""),
                str(item.get("proxy") or ""),
            )
        )
    return out


def match_from_hitcount(before, after, host: str) -> MatchResult | None:
    bumped = [a for b, a in zip(before, after) if a[1] > b[1]]
    if len(bumped) != 1:
        return None
    idx, _, typ, payload, proxy = bumped[0]
    return MatchResult(
        host=host,
        rule_index=idx,
        rule_text=f"{typ}({payload})" if payload else typ,
        policy=proxy,
        payload=payload,
        source="mihomo",
    )


def select_oracle_mode(rules_payload) -> str:
    return "structured_api" if hitcount_supported(rules_payload) else "log_fallback"


def cross_check(api_match: MatchResult, log_match: MatchResult) -> None:
    if api_match.policy != log_match.policy:
        raise OracleError(
            "FAIL_ORACLE_INCONSISTENT "
            f"api={api_match.policy} log={log_match.policy} host={api_match.host}"
        )


class DualOracle:
    def __init__(self, primary, secondary=None):
        self.primary = primary
        self.secondary = secondary

    def match(self, host: str, ip: str | None = None):
        a = self.primary.match(host, ip) if ip else self.primary.match(host)
        if self.secondary is None:
            return a
        b = self.secondary.match(host, ip) if ip else self.secondary.match(host)
        cross_check(a, b)
        return a

    def close(self) -> None:
        for obj in (self.primary, self.secondary):
            if obj is not None and hasattr(obj, "close"):
                obj.close()
