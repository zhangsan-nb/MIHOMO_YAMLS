from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path

from .analysis import blast_radius, generate_witnesses, semantic_diff
from .bootstrap import pair_readable
from .catalog import load_providers_catalog, load_yaml, snapshot_provider
from .correspondence import source_mrs_lockstep
from .coverage import changed_unexercised, collect_exercised, coverage_report, propose_sentinels, provider_from_match
from .decision import decide, evaluate_contract
from .mihomo_bin import download_mihomo, find_mihomo, pinned_version
from .models import AuditResult, MatchResult, ProviderSnapshot, RoutingChange
from .oracle import FixtureOracle, MihomoOracle, OracleError, _free_port, build_harness_config, probe_match_api
from .report import routing_change_dict, write_reports


def _fetch(url: str, dest: Path, timeout: int = 45) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "MIHOMO-YAMLS-audit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as handle:
        shutil.copyfileobj(resp, handle)


def collect_golden_hosts(golden: dict) -> list[str]:
    hosts: list[str] = []
    for item in golden.get("critical") or []:
        hosts.append(str(item))
    rep = golden.get("representative") or {}
    if isinstance(rep, dict):
        for values in rep.values():
            hosts.extend(str(x) for x in (values or []))
    hosts.extend(str(x) for x in (golden.get("learned") or []))
    out: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        key = host.lower().rstrip(".")
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def percent_delta(old: int, new: int) -> float:
    if old <= 0:
        return 100.0 if new else 0.0
    return abs(new - old) * 100.0 / old


def run_engine(
    *,
    baseline: dict[str, ProviderSnapshot],
    candidate: dict[str, ProviderSnapshot],
    harness: dict,
    policy_doc: dict,
    golden_doc: dict,
    protected_doc: dict,
    known_doc: dict,
    thresholds: dict,
    oracle_old,
    oracle_new,
    full_regression: bool,
    missing_baseline: bool,
    mihomo_version: str,
    oracle_kind: str,
    extra_load_errors: list[str] | None = None,
    extra_hosts: list[str] | None = None,
    bootstrap_unverified: list[str] | None = None,
    commit_mismatch: list[str] | None = None,
    dns_fails: list[str] | None = None,
    dns_reviews: list[str] | None = None,
) -> AuditResult:
    load_errors = list(extra_load_errors or [])
    broad_critical: list[str] = []
    size_fails: list[str] = []
    count_fails: list[str] = []
    mode_c_changed: list[str] = []
    added_total = 0
    removed_total = 0
    semantic_unavailable = 0
    changed: list[str] = []
    unchanged: list[str] = []
    diffs: dict[str, dict] = {}
    critical_tlds = ((thresholds.get("broad_suffix") or {}).get("critical_tlds")) or None
    fail_on_critical = bool((thresholds.get("broad_suffix") or {}).get("fail_on_critical", True))

    witness_hosts: list[str] = []
    for name, new in candidate.items():
        old = baseline.get(name)
        if new.load_error:
            load_errors.append(f"{name}: {new.load_error}")
        if not new.present:
            load_errors.append(f"{name}: missing candidate artifact")
        if old and old.present and old.sha256 == new.sha256 and old.readable_sha256 == new.readable_sha256:
            unchanged.append(name)
        else:
            changed.append(name)

        size_cfg = thresholds.get("file_size") or {}
        if old and old.size and new.size:
            pct = percent_delta(old.size, new.size)
            if pct >= float(size_cfg.get("fail_percent") or 70):
                size_fails.append(f"{name} size {old.size}->{new.size} ({pct:.1f}%)")

        count_cfg = thresholds.get("entry_count") or {}
        if old and old.entry_count and new.entry_count is not None:
            shrink = (old.entry_count - new.entry_count) * 100.0 / old.entry_count
            if shrink >= float(count_cfg.get("fail_shrink_percent") or 50):
                count_fails.append(f"{name} entries {old.entry_count}->{new.entry_count}")
            if new.entry_count < int(count_cfg.get("fail_if_below") or 8) and old.entry_count >= 8:
                count_fails.append(f"{name} collapsed to {new.entry_count} entries")

        diff = semantic_diff(old.rules if old else None, new.rules)
        diffs[name] = diff
        if old and old.present and old.sha256 != new.sha256 and not diff["available"]:
            # Cannot enumerate added/removed. Do not pretend this was audited.
            mode_c_changed.append(name)
        if not diff["available"]:
            semantic_unavailable += 1
            if new.rules:
                for rule in new.rules:
                    level = blast_radius(rule, critical_tlds)
                    if level == "CRITICAL" and fail_on_critical:
                        broad_critical.append(f"{name} {rule.raw}")
        else:
            added_total += len(diff["added"])
            removed_total += len(diff["removed"])
            for rule in list(diff["added"]) + list(diff["removed"]):
                level = blast_radius(rule, critical_tlds)
                if level == "CRITICAL" and fail_on_critical:
                    broad_critical.append(f"{name} {rule.raw}")
                witness_hosts.extend(generate_witnesses(rule))

    source_mrs_mismatch: list[str] = []
    for name, new in candidate.items():
        old = baseline.get(name)
        lock = source_mrs_lockstep(
            mrs_changed=bool(old and old.sha256 != new.sha256),
            txt_changed=bool(
                old
                and old.readable_sha256
                and new.readable_sha256
                and old.readable_sha256 != new.readable_sha256
            ),
            has_both=bool(old and old.readable_sha256 and new.readable_sha256),
        )
        if lock:
            source_mrs_mismatch.append(f"{name}")

        if name in changed and new.rules:
            witness_hosts.extend(propose_sentinels(new.rules, limit=2))

    hosts = collect_golden_hosts(golden_doc)
    for host in extra_hosts or []:
        if host not in hosts:
            hosts.append(host)
    for host in witness_hosts:
        if host not in hosts and not _looks_ip(host):
            hosts.append(host)

    oracle_error = None
    routing_changes: list[RoutingChange] = []
    golden_results: list = []
    new_matches: list = []
    try:
        golden_set = set(collect_golden_hosts(golden_doc))
        for host in hosts:
            try:
                old_m = oracle_old.match(host)
            except Exception as exc:  # noqa: BLE001
                if "no match observed" not in str(exc):
                    oracle_error = str(exc)
                    break
                old_m = MatchResult(host, -1, "UNMATCHED", "UNMATCHED")
            try:
                new_m = oracle_new.match(host)
            except Exception as exc:  # noqa: BLE001
                if "no match observed" not in str(exc):
                    oracle_error = str(exc)
                    break
                new_m = MatchResult(host, -1, "UNMATCHED", "UNMATCHED")
            new_matches.append(new_m)
            if old_m.policy != new_m.policy:
                routing_changes.append(
                    RoutingChange(host=host, old=old_m, new=new_m, reason="policy changed")
                )
            if host in golden_set:
                verdict = evaluate_contract(host, new_m.policy, policy_doc, protected_doc)
                golden_results.append((host, new_m, verdict if verdict else "PASS"))
    except Exception as exc:  # noqa: BLE001
        oracle_error = str(exc)

    exercised = collect_exercised(new_matches)
    harness_names = set()
    for line in harness.get("rules") or []:
        if str(line).upper().startswith("RULE-SET,"):
            parts = [p.strip() for p in str(line).split(",")]
            if len(parts) >= 2:
                harness_names.add(parts[1])
    cov = coverage_report(
        provider_names=list(candidate.keys()),
        exercised=exercised,
        harness_names=harness_names,
    )
    unex = changed_unexercised(changed, exercised, {})

    result = decide(
        load_errors=load_errors,
        broad_critical=broad_critical,
        size_fails=size_fails,
        count_fails=count_fails,
        golden_results=golden_results,
        routing_changes=routing_changes,
        policy_doc=policy_doc,
        protected_doc=protected_doc,
        known_doc=known_doc,
        mode_c_changed=mode_c_changed,
        missing_baseline=missing_baseline,
        oracle_error=oracle_error,
        full_regression=full_regression,
        bootstrap_unverified=bootstrap_unverified,
        source_mrs_mismatch=source_mrs_mismatch,
        changed_unexercised=unex,
        dns_fails=dns_fails,
        dns_reviews=dns_reviews,
        commit_mismatch=commit_mismatch,
    )
    result.oracle_kind = oracle_kind  # type: ignore[assignment]
    result.mihomo_version = mihomo_version
    result.report.update(
        {
            "providers_changed": changed,
            "providers_unchanged": unchanged,
            "added": added_total,
            "removed": removed_total,
            "semantic_unavailable": semantic_unavailable,
            "broad_critical": len(broad_critical),
            "routing_change_details": [routing_change_dict(c) for c in routing_changes],
            "mode_c_changed": mode_c_changed,
            "trust": {name: snap.trust_mode for name, snap in candidate.items()},
            "semantic_diff_flag": {name: snap.semantic_diff for name, snap in candidate.items()},
            "coverage": cov,
            "exercised": sorted(exercised),
            "changed_unexercised": unex,
            "routing_scope": "mirror-covered rulesets",
            "full_config_equivalence": False,
        }
    )
    return result


def _looks_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _copy_provider_files(root: Path, specs: list[dict], dest: Path) -> dict[str, dict]:
    mapping = {}
    for spec in specs:
        src = root / spec["path"]
        if not src.is_file():
            continue
        target = dest / spec["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        fmt = spec.get("format") or src.suffix.lstrip(".")
        if fmt == "list":
            fmt = "text"
        mapping[spec["name"]] = {
            "path": spec["path"].replace("\\", "/"),
            "behavior": spec.get("behavior") or "domain",
            "format": fmt,
        }
    return mapping


def _fixture_providers(snaps: dict[str, ProviderSnapshot]) -> dict:
    out = {}
    for name, snap in snaps.items():
        out[name] = (snap.behavior, list(snap.rules or ()))
    return out


def run_audit(
    *,
    audit_dir: Path,
    baseline_dir: Path | None,
    candidate_dir: Path,
    out_json: Path,
    oracle_name: str = "auto",
    fetch_sources: bool = True,
    allow_bootstrap: bool = False,
) -> AuditResult:
    audit_dir = audit_dir.resolve()
    specs = load_providers_catalog(audit_dir)
    harness = load_yaml(audit_dir / "harness.yaml")
    policy_doc = load_yaml(audit_dir / "policy.yaml")
    golden_doc = load_yaml(audit_dir / "golden-domains.yaml")
    protected_doc = load_yaml(audit_dir / "protected-domains.yaml")
    known_doc = load_yaml(audit_dir / "known-decisions.yaml")
    thresholds = load_yaml(audit_dir / "thresholds.yaml")

    missing_baseline = baseline_dir is None or not (baseline_dir / "SOURCES.tsv").is_file()
    if missing_baseline and not allow_bootstrap:
        result = AuditResult(
            decision="FAIL",
            publish_allowed=False,
            risk="CRITICAL",
            reasons=["missing baseline (fail closed)"],
        )
        result.report = {"baseline": str(baseline_dir or ""), "candidate": str(candidate_dir)}
        write_reports(result, out_json)
        return result

    if fetch_sources:
        try:
            from .materialize import attach_readable_from_audit, materialize_paired_sources

            manifest = materialize_paired_sources(
                specs=specs,
                baseline_dir=baseline_dir,
                candidate_dir=candidate_dir,
            )
        except Exception as exc:  # noqa: BLE001
            result = AuditResult(
                decision="FAIL",
                publish_allowed=False,
                risk="CRITICAL",
                reasons=[f"upstream pin failed: {exc}"],
            )
            result.report = {"baseline": str(baseline_dir or ""), "candidate": str(candidate_dir)}
            write_reports(result, out_json)
            return result
    else:
        manifest = {}
        from .materialize import attach_readable_from_audit

    extra_hosts: list[str] = []
    sentinels_doc = {}
    sentinels_path = audit_dir / "sentinels.yaml"
    if sentinels_path.is_file():
        sentinels_doc = load_yaml(sentinels_path)
        for values in (sentinels_doc.get("providers") or {}).values():
            extra_hosts.extend(str(x) for x in (values or []))

    baseline_snaps = {}
    if baseline_dir:
        for spec in specs:
            baseline_snaps[spec["name"]] = snapshot_provider(
                spec, baseline_dir, readable_text=attach_readable_from_audit(baseline_dir, spec)
            )
    candidate_snaps = {
        spec["name"]: snapshot_provider(
            spec, candidate_dir, readable_text=attach_readable_from_audit(candidate_dir, spec)
        )
        for spec in specs
    }

    harness_fp = hashlib.sha256("\n".join(harness.get("rules") or []).encode()).hexdigest()
    prev_fp = ""
    prev_mihomo = ""
    if baseline_dir and (baseline_dir / "baseline.json").is_file():
        prev = json.loads((baseline_dir / "baseline.json").read_text(encoding="utf-8"))
        prev_fp = str(prev.get("rules_section_sha256") or "")
        prev_mihomo = str(prev.get("mihomo_version") or "")
    full_regression = bool(prev_fp and prev_fp != harness_fp)
    wanted_mihomo = str((thresholds.get("mihomo_version") or pinned_version()))
    if prev_mihomo and prev_mihomo != wanted_mihomo:
        full_regression = True

    oracle_old = None
    oracle_new = None
    dummy_dns = None
    mihomo_version = wanted_mihomo
    kind = "unavailable"
    tmp: Path | None = None
    try:
        use_mihomo = oracle_name in {"auto", "mihomo"}
        require = bool((thresholds.get("oracle") or {}).get("require_real_mihomo", True))
        if oracle_name == "fixture":
            use_mihomo = False
            require = False
        if use_mihomo:
            cache = audit_dir / ".cache"
            binary = find_mihomo(cache)
            if binary is None:
                try:
                    pin = {}
                    pin_path = audit_dir / "mihomo-pin.yaml"
                    if pin_path.is_file():
                        pin = load_yaml(pin_path)
                    binary = download_mihomo(cache, wanted_mihomo, pin)
                except Exception as exc:
                    if require:
                        result = AuditResult(
                            decision="FAIL",
                            publish_allowed=False,
                            risk="CRITICAL",
                            reasons=[f"mihomo unavailable: {exc}"],
                            oracle_kind="unavailable",
                        )
                        result.report = {"baseline": str(baseline_dir), "candidate": str(candidate_dir)}
                        write_reports(result, out_json)
                        return result
                    binary = None
            if binary:
                tmp = Path(tempfile.mkdtemp(prefix="mihomo-audit-"))
                old_dir = tmp / "old"
                new_dir = tmp / "new"
                old_dir.mkdir()
                new_dir.mkdir()
                old_map = _copy_provider_files(baseline_dir or candidate_dir, specs, old_dir)
                new_map = _copy_provider_files(candidate_dir, specs, new_dir)
                secret = str((thresholds.get("oracle") or {}).get("api_secret") or "audit-local")
                old_mixed, old_api = _free_port(), _free_port()
                new_mixed, new_api = _free_port(), _free_port()
                from .dns_oracle import DummyDns

                dummy_dns = DummyDns()
                dummy_dns.start()
                dns_listen_old, dns_listen_new = _free_port(), _free_port()

                def _dns_cfg(listen: int) -> dict:
                    return {
                        "enable": True,
                        "ipv6": False,
                        "enhanced-mode": "fake-ip",
                        "fake-ip-range": "198.18.0.1/16",
                        "listen": f"127.0.0.1:{listen}",
                        "default-nameserver": [f"127.0.0.1:{dummy_dns.port}"],
                        "nameserver": [f"127.0.0.1:{dummy_dns.port}"],
                        "fake-ip-filter": [
                            "rule-set:Direct",
                            "rule-set:Private",
                            "rule-set:China",
                            "rule-set:fakeip-filter",
                        ],
                    }

                old_cfg = build_harness_config(
                    harness=harness,
                    provider_files=old_map,
                    mixed_port=old_mixed,
                    api_port=old_api,
                    secret=secret,
                    workdir=old_dir,
                    dns=_dns_cfg(dns_listen_old),
                )
                new_cfg = build_harness_config(
                    harness=harness,
                    provider_files=new_map,
                    mixed_port=new_mixed,
                    api_port=new_api,
                    secret=secret,
                    workdir=new_dir,
                    dns=_dns_cfg(dns_listen_new),
                )
                oracle_old = MihomoOracle(binary, old_dir, old_cfg, old_mixed, old_api, secret)
                oracle_new = MihomoOracle(binary, new_dir, new_cfg, new_mixed, new_api, secret)
                oracle_old.dns_listen = dns_listen_old
                oracle_new.dns_listen = dns_listen_new
                try:
                    oracle_old.start()
                    oracle_new.start()
                except Exception as exc:
                    result = AuditResult(
                        decision="FAIL",
                        publish_allowed=False,
                        risk="CRITICAL",
                        reasons=[f"oracle error: {exc}"],
                        oracle_kind="unavailable",
                    )
                    result.report = {"baseline": str(baseline_dir), "candidate": str(candidate_dir)}
                    write_reports(result, out_json)
                    return result
                mihomo_version = oracle_new.version or wanted_mihomo
                kind = "mihomo"
                api_probe = probe_match_api(oracle_new)
            elif require:
                result = AuditResult(
                    decision="FAIL",
                    publish_allowed=False,
                    risk="CRITICAL",
                    reasons=["mihomo binary not found (fail closed)"],
                    oracle_kind="unavailable",
                )
                result.report = {"baseline": str(baseline_dir), "candidate": str(candidate_dir)}
                write_reports(result, out_json)
                return result
        if oracle_old is None:
            oracle_old = FixtureOracle(list(harness.get("rules") or []), _fixture_providers(baseline_snaps or candidate_snaps))
            oracle_new = FixtureOracle(list(harness.get("rules") or []), _fixture_providers(candidate_snaps))
            kind = "fixture"

        dns_fails: list[str] = []
        dns_reviews: list[str] = []
        dns_status = "not applicable"
        if kind == "mihomo" and getattr(oracle_new, "dns_listen", None):
            dns_status = "enabled"
            dns_doc = {}
            dns_path = audit_dir / "dns-policy.yaml"
            if dns_path.is_file():
                dns_doc = load_yaml(dns_path)
            from .dns_oracle import evaluate_dns, lookup

            for host in list(dns_doc.get("must_real_ip") or []) + list(dns_doc.get("must_fake_ip") or []):
                old_d = lookup(host, "127.0.0.1", int(oracle_old.dns_listen))
                new_d = lookup(host, "127.0.0.1", int(oracle_new.dns_listen))
                verd = evaluate_dns(
                    old=old_d,
                    new=new_d,
                    must_real_ip=list(dns_doc.get("must_real_ip") or []),
                    must_fake_ip=list(dns_doc.get("must_fake_ip") or []),
                )
                if verd == "FAIL":
                    dns_fails.append(f"{host} {old_d.kind}->{new_d.kind} ({new_d.address})")
                elif verd == "REVIEW":
                    dns_reviews.append(f"{host} {old_d.kind}->{new_d.kind}")

        result = run_engine(
            baseline=baseline_snaps,
            candidate=candidate_snaps,
            harness=harness,
            policy_doc=policy_doc,
            golden_doc=golden_doc,
            protected_doc=protected_doc,
            known_doc=known_doc,
            thresholds=thresholds,
            oracle_old=oracle_old,
            oracle_new=oracle_new,
            full_regression=full_regression,
            missing_baseline=missing_baseline and not allow_bootstrap,
            mihomo_version=mihomo_version,
            oracle_kind=kind,
            extra_hosts=extra_hosts,
            bootstrap_unverified=list(manifest.get("unverified") or []),
            commit_mismatch=list(manifest.get("commit_mismatch") or []),
            dns_fails=dns_fails,
            dns_reviews=dns_reviews,
        )
        result.report["baseline"] = str(baseline_dir or "")
        result.report["candidate"] = str(candidate_dir)
        result.report["mihomo_version"] = mihomo_version
        result.report["rules_section_sha256"] = harness_fp
        if kind == "mihomo":
            result.report["match_api"] = api_probe  # type: ignore[name-defined]
            result.report["routing_oracle"] = getattr(oracle_new, "oracle_mode", "log_fallback")
            result.report["hitcount_supported"] = bool(getattr(oracle_new, "hitcount_supported", False))
        result.report["upstream_commit"] = manifest.get("upstream_commit")
        result.report["readable_paired"] = list(manifest.get("paired") or [])
        result.report["readable_baseline_count"] = len(manifest.get("paired") or [])
        result.report["bootstrap_unverified"] = list(manifest.get("unverified") or [])
        result.report["dns_oracle"] = dns_status
        binary_only = [
            name for name, snap in candidate_snaps.items() if snap.trust_mode == "C"
        ]
        result.report["binary_only"] = binary_only
        write_reports(result, out_json)
        if result.publish_allowed:
            baseline_payload = {
                "mihomo_version": mihomo_version,
                "rules_section_sha256": harness_fp,
                "providers": {
                    name: {
                        "sha256": snap.sha256,
                        "size": snap.size,
                        "entry_count": snap.entry_count,
                        "trust_mode": snap.trust_mode,
                    }
                    for name, snap in candidate_snaps.items()
                },
            }
            (candidate_dir / "baseline.json").write_text(
                json.dumps(baseline_payload, indent=2), encoding="utf-8"
            )
        return result
    finally:
        for obj in (oracle_old, oracle_new):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        if dummy_dns is not None:
            try:
                dummy_dns.close()
            except Exception:
                pass
        if tmp and tmp.is_dir() and os.environ.get("AUDIT_KEEP_TMP") != "1":
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mihomo rule supply-chain audit")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run", help="audit candidate vs baseline")
    run_p.add_argument("--audit-dir", type=Path, default=Path("audit"))
    run_p.add_argument("--baseline", type=Path, required=True)
    run_p.add_argument("--candidate", type=Path, required=True)
    run_p.add_argument("--out", type=Path, default=Path("audit/reports/audit-report.json"))
    run_p.add_argument("--oracle", choices=["auto", "mihomo", "fixture"], default="auto")
    run_p.add_argument("--no-fetch", action="store_true")
    run_p.add_argument("--allow-bootstrap", action="store_true")
    run_p.add_argument("--fail-closed", action="store_true")
    args = parser.parse_args(argv)

    result = run_audit(
        audit_dir=args.audit_dir,
        baseline_dir=args.baseline,
        candidate_dir=args.candidate,
        out_json=args.out,
        oracle_name=args.oracle,
        fetch_sources=not args.no_fetch,
        allow_bootstrap=args.allow_bootstrap,
    )
    print(result.text or result.decision)
    if args.fail_closed and not result.publish_allowed:
        return 2
    return 0
