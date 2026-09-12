from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

TrustMode = Literal["A", "B", "C"]
Decision = Literal["PASS", "REVIEW", "FAIL"]
OracleKind = Literal["mihomo", "fixture", "unavailable"]


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    raw: str

    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)


@dataclass
class ProviderSnapshot:
    name: str
    path: str
    behavior: str
    format: str
    sha256: str
    size: int
    trust_mode: TrustMode
    semantic_diff: str  # AVAILABLE | UNAVAILABLE
    entry_count: int | None = None
    rules: tuple[Rule, ...] | None = None
    readable_sha256: str | None = None
    present: bool = True
    load_error: str | None = None


@dataclass
class MatchResult:
    host: str
    rule_index: int
    rule_text: str
    policy: str
    payload: str | None = None
    source: OracleKind = "fixture"


@dataclass
class RoutingChange:
    host: str
    old: MatchResult | None
    new: MatchResult | None
    reason: str


@dataclass
class AuditResult:
    decision: Decision
    publish_allowed: bool
    risk: str
    reasons: list[str] = field(default_factory=list)
    full_regression: bool = False
    oracle_kind: OracleKind = "unavailable"
    mihomo_version: str = ""
    report: dict = field(default_factory=dict)
    text: str = ""
