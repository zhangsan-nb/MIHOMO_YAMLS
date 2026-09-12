from __future__ import annotations

from .models import AuditResult, Decision, MatchResult, RoutingChange

_RANK = {"PASS": 0, "REVIEW": 1, "FAIL": 2}
_RISK = {"PASS": "LOW", "REVIEW": "MEDIUM", "FAIL": "CRITICAL"}


def _raise(current: Decision, incoming: Decision) -> Decision:
    return incoming if _RANK[incoming] > _RANK[current] else current


def domain_matches_protected(host: str, protected: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for item in protected:
        item = item.lower().rstrip(".")
        if host == item or host.endswith("." + item):
            return True
    return False


def contract_for(host: str, policy_doc: dict) -> dict | None:
    domains = policy_doc.get("domains") or {}
    host_l = host.lower().rstrip(".")
    if host_l in domains:
        return domains[host_l]
    # suffix fallback: api.github.com uses github.com contract if exact missing
    parts = host_l.split(".")
    for i in range(1, len(parts) - 0):
        cand = ".".join(parts[i:])
        if cand in domains:
            return domains[cand]
    return None


def evaluate_contract(host: str, policy: str, policy_doc: dict, protected_doc: dict) -> Decision | None:
    """Return FAIL if violated, None if no contract applies."""
    contract = contract_for(host, policy_doc)
    protected = list((protected_doc or {}).get("domains") or [])
    is_protected = domain_matches_protected(host, protected)
    default_forbidden = list((protected_doc or {}).get("default_forbidden") or [])
    allowed = None
    forbidden: list[str] = []
    if contract:
        allowed = list(contract.get("allowed") or [])
        forbidden = list(contract.get("forbidden") or default_forbidden)
    elif is_protected:
        forbidden = default_forbidden
    if allowed is not None and policy not in allowed:
        if is_protected or policy in forbidden or policy == "REJECT":
            return "FAIL"
        return "REVIEW"
    if policy in forbidden:
        return "FAIL" if is_protected or policy == "REJECT" else "REVIEW"
    if is_protected and policy == "REJECT":
        return "FAIL"
    return None


def known_expected(host: str, known_doc: dict) -> str | None:
    host_l = host.lower().rstrip(".")
    for item in known_doc.get("decisions") or []:
        domain = str(item.get("domain") or "").lower().rstrip(".")
        if not domain:
            continue
        if host_l == domain or host_l.endswith("." + domain):
            return str(item.get("expected") or "") or None
    return None


def decide(
    *,
    load_errors: list[str],
    broad_critical: list[str],
    size_fails: list[str],
    count_fails: list[str],
    golden_results: list[tuple[str, MatchResult, Decision | None]],
    routing_changes: list[RoutingChange],
    policy_doc: dict,
    protected_doc: dict,
    known_doc: dict,
    mode_c_changed: list[str],
    missing_baseline: bool,
    oracle_error: str | None,
    full_regression: bool,
    bootstrap_unverified: list[str] | None = None,
    source_mrs_mismatch: list[str] | None = None,
    changed_unexercised: list[str] | None = None,
    dns_fails: list[str] | None = None,
    dns_reviews: list[str] | None = None,
    commit_mismatch: list[str] | None = None,
) -> AuditResult:
    decision: Decision = "PASS"
    reasons: list[str] = []

    def fail(msg: str) -> None:
        nonlocal decision
        decision = _raise(decision, "FAIL")
        reasons.append(msg)

    def review(msg: str) -> None:
        nonlocal decision
        decision = _raise(decision, "REVIEW")
        reasons.append(msg)

    if oracle_error:
        fail(f"oracle error: {oracle_error}")
    if missing_baseline:
        fail("missing baseline (fail closed)")
    for err in load_errors:
        fail(f"load error: {err}")
    for item in commit_mismatch or []:
        fail(f"source and MRS from different upstream commits: {item}")
    for item in source_mrs_mismatch or []:
        fail(f"SOURCE_MRS_INCONSISTENT: {item}")
    for item in dns_fails or []:
        fail(f"dns contract FAIL: {item}")
    for item in broad_critical:
        fail(f"broad rule CRITICAL: {item}")
    for item in size_fails:
        fail(f"size anomaly: {item}")
    for item in count_fails:
        fail(f"count anomaly: {item}")

    golden_fail = 0
    golden_pass = 0
    policy_fail = 0
    policy_pass = 0
    for host, match, verdict in golden_results:
        if verdict == "FAIL":
            golden_fail += 1
            policy_fail += 1
            fail(f"golden/policy FAIL {host} -> {match.policy}")
        elif verdict == "REVIEW":
            review(f"golden REVIEW {host} -> {match.policy}")
        else:
            golden_pass += 1
            policy_pass += 1

    for change in routing_changes:
        host = change.host
        new_policy = change.new.policy if change.new else "UNMATCHED"
        old_policy = change.old.policy if change.old else "UNMATCHED"
        expected = known_expected(host, known_doc)
        if expected and new_policy == expected:
            reasons.append(f"known decision {host} -> {expected}")
            continue
        verdict = evaluate_contract(host, new_policy, policy_doc, protected_doc)
        if verdict == "FAIL":
            fail(f"routing {host}: {old_policy} -> {new_policy} violates contract")
            continue
        if verdict == "REVIEW":
            review(f"routing {host}: {old_policy} -> {new_policy} not in contract")
            continue
        # no contract
        review(f"unreviewed routing change {host}: {old_policy} -> {new_policy}")

    if mode_c_changed and decision != "FAIL":
        review(
            "binary/source-gap change; SEMANTIC_DIFF=UNAVAILABLE "
            f"({', '.join(mode_c_changed[:8])})"
        )
    for item in bootstrap_unverified or []:
        review(f"BOOTSTRAP_UNVERIFIED: {item}")
    for item in changed_unexercised or []:
        review(f"CHANGED_BUT_UNEXERCISED: {item}")
    for item in dns_reviews or []:
        review(f"dns behavior changed: {item}")

    if full_regression:
        reasons.append("full regression triggered")

    return AuditResult(
        decision=decision,
        publish_allowed=decision == "PASS",
        risk=_RISK[decision],
        reasons=reasons,
        full_regression=full_regression,
        report={
            "golden_pass": golden_pass,
            "golden_fail": golden_fail,
            "policy_pass": policy_pass,
            "policy_fail": policy_fail,
            "routing_changes": len(routing_changes),
        },
    )
