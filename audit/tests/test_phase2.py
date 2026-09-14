from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.analysis import blast_radius
from routing_audit.bootstrap import pair_readable
from routing_audit.correspondence import compare_source_and_decoded, source_mrs_lockstep
from routing_audit.dns_oracle import DnsLookup, classify_ip, evaluate_dns
from routing_audit.hitcount import DualOracle, hitcount_supported, select_oracle_mode
from routing_audit.models import MatchResult, ProviderSnapshot, Rule
from routing_audit.oracle import FixtureOracle, OracleError, _http_probe_url
from routing_audit.run import run_engine
from routing_audit.upstream import commit_raw_url, infer_upstream

from test_attack_cases import GOLDEN, POLICY, PROTECTED, THRESH, engine, harness_github_then_direct, snap


class Phase2Bootstrap(unittest.TestCase):
    def test_1_source_mrs_different_commits_fail(self):
        r = pair_readable(
            name="Direct",
            deployed_mrs=b"mrs-a",
            upstream_mrs=b"mrs-a",
            upstream_txt=b"+.example.com\n",
            commit="aaa",
            mrs_commit="aaaaaaaaaaaa",
            txt_commit="bbbbbbbbbbbb",
        )
        self.assertEqual(r.status, "commit_mismatch")

    def test_2_bootstrap_refused_when_deployed_mrs_differs(self):
        r = pair_readable(
            name="Direct",
            deployed_mrs=b"deployed",
            upstream_mrs=b"upstream",
            upstream_txt=b"+.example.com\n",
            commit="cccccccccccccccc",
        )
        self.assertEqual(r.status, "unverified")
        self.assertIn("BOOTSTRAP_UNVERIFIED", r.reason)
        self.assertIsNone(r.txt_bytes)

    def test_10_immutable_sha_url_not_branch(self):
        url = commit_raw_url("666OS/rules", "4109a511f4386346520b9c552038d6681b318c9c", "mihomo/domain/Direct.txt")
        self.assertIn("/4109a511f4386346520b9c552038d6681b318c9c/", url)
        self.assertNotIn("/release/", url)
        with self.assertRaises(Exception):
            commit_raw_url("666OS/rules", "release", "mihomo/domain/Direct.txt")
        inferred = infer_upstream(
            "https://raw.githubusercontent.com/666OS/rules/release/mihomo/domain/Direct.mrs"
        )
        self.assertEqual(inferred["mrs_path"], "mihomo/domain/Direct.mrs")
        self.assertEqual(inferred["txt_path"], "mihomo/domain/Direct.txt")


class Phase2CoverageOracle(unittest.TestCase):
    def test_3_changed_provider_unexercised_review(self):
        h = harness_github_then_direct()
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n", format="yaml", behavior="classical"),
            "Direct": snap("Direct", "", sha256="old-direct", trust_mode="C", semantic_diff="UNAVAILABLE", rules=(), entry_count=None, format="mrs"),
        }
        new = {
            "github": old["github"],
            "Direct": snap("Direct", "", sha256="new-direct", trust_mode="C", semantic_diff="UNAVAILABLE", rules=(), entry_count=None, format="mrs"),
        }
        # MODE C empty rules: snapshot helper still parses "" as 0 rules
        new["Direct"].rules = None
        old["Direct"].rules = None
        result = engine(old, new, h)
        self.assertEqual(result.decision, "REVIEW")
        self.assertTrue(any("UNEXERCISED" in x or "UNAVAILABLE" in x for x in result.reasons))

    def test_4_oracle_api_log_inconsistent_raises(self):
        h = harness_github_then_direct()
        providers = {
            "github": ("classical", list(snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n").rules)),
            "Direct": ("domain", []),
        }
        a = FixtureOracle(h["rules"], providers)
        class Flip:
            def match(self, host, ip=None):
                return MatchResult(host, 0, "RULE-SET,Direct", "DIRECT", source="fixture")
        with self.assertRaises(OracleError) as ctx:
            DualOracle(a, Flip()).match("github.com")
        self.assertIn("FAIL_ORACLE_INCONSISTENT", str(ctx.exception))

    def test_5_hitcount_unsupported_falls_back_to_log(self):
        payload = {"rules": [{"type": "RuleSet", "payload": "github", "proxy": "GITHUB", "size": -1}]}
        self.assertFalse(hitcount_supported(payload))
        self.assertEqual(select_oracle_mode(payload), "log_fallback")
        with_extra = {"rules": [{"type": "RuleSet", "payload": "github", "proxy": "GITHUB", "extra": {"hitCount": 3}}]}
        self.assertTrue(hitcount_supported(with_extra))
        self.assertEqual(select_oracle_mode(with_extra), "structured_api")


class Phase2DnsAndLockstep(unittest.TestCase):
    def test_6_fakeip_real_to_fake_fails_contract(self):
        old = DnsLookup("printer.lan", "REAL_IP", "9.9.9.9")
        new = DnsLookup("printer.lan", "FAKE_IP", "198.18.0.10")
        self.assertEqual(
            evaluate_dns(old=old, new=new, must_real_ip=["printer.lan"], must_fake_ip=["github.com"]),
            "FAIL",
        )
        self.assertEqual(classify_ip("198.18.1.2"), "FAKE_IP")
        self.assertEqual(classify_ip("9.9.9.9"), "REAL_IP")

    def test_7_mode_c_changed_dns_same_review_no_fake_diff(self):
        h = harness_github_then_direct()
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n", format="yaml", behavior="classical"),
            "fakeip-filter": ProviderSnapshot(
                name="fakeip-filter",
                path="fakeip/fakeip-filter.mrs",
                behavior="domain",
                format="mrs",
                sha256="sha-old",
                size=1000,
                trust_mode="C",
                semantic_diff="UNAVAILABLE",
                rules=None,
                present=True,
            ),
        }
        new = dict(old)
        new["fakeip-filter"] = ProviderSnapshot(
            name="fakeip-filter",
            path="fakeip/fakeip-filter.mrs",
            behavior="domain",
            format="mrs",
            sha256="sha-new",
            size=1000,
            trust_mode="C",
            semantic_diff="UNAVAILABLE",
            rules=None,
            present=True,
        )
        result = engine(old, new, h)
        self.assertEqual(result.decision, "REVIEW")
        self.assertEqual(result.report.get("semantic_diff_flag", {}).get("fakeip-filter"), "UNAVAILABLE")
        self.assertFalse(result.report.get("added"))

    def test_8_mrs_same_txt_changed_inconsistent(self):
        self.assertEqual(
            source_mrs_lockstep(mrs_changed=False, txt_changed=True, has_both=True),
            "SOURCE_MRS_INCONSISTENT",
        )
        h = harness_github_then_direct()
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n", format="yaml", behavior="classical"),
            "Direct": snap("Direct", "+.aaa.com\n", sha256="same-mrs", readable_sha256="txt-old"),
        }
        new = {
            "github": old["github"],
            "Direct": snap("Direct", "+.bbb.com\n", sha256="same-mrs", readable_sha256="txt-new"),
        }
        # snap() doesn't take readable_sha256 - set after
        old["Direct"].readable_sha256 = "txt-old"
        new["Direct"].readable_sha256 = "txt-new"
        new["Direct"].sha256 = old["Direct"].sha256
        result = engine(old, new, h)
        self.assertEqual(result.decision, "FAIL")
        self.assertTrue(any("SOURCE_MRS_INCONSISTENT" in x for x in result.reasons))

    def test_9_mrs_changed_txt_same_inconsistent(self):
        self.assertEqual(
            source_mrs_lockstep(mrs_changed=True, txt_changed=False, has_both=True),
            "SOURCE_MRS_INCONSISTENT",
        )
        h = harness_github_then_direct()
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n", format="yaml", behavior="classical"),
            "Direct": snap("Direct", "+.aaa.com\n"),
        }
        new = {
            "github": old["github"],
            "Direct": snap("Direct", "+.aaa.com\n", sha256="mrs-new"),
        }
        old["Direct"].readable_sha256 = "txt-same"
        new["Direct"].readable_sha256 = "txt-same"
        result = engine(old, new, h)
        self.assertEqual(result.decision, "FAIL")
        self.assertTrue(any("SOURCE_MRS_INCONSISTENT" in x for x in result.reasons))

    def test_optional_decode_mismatch_is_not_equal(self):
        self.assertEqual(
            compare_source_and_decoded("+.a.com\n", "+.b.com\n", behavior="domain"),
            "mismatch",
        )
        self.assertEqual(
            compare_source_and_decoded("+.a.com\n", None, behavior="domain"),
            "decode_unavailable",
        )


class Phase2IpWitnessAndIpv6Oracle(unittest.TestCase):
    # A. IPv6 /32 不再 CRITICAL：blast_radius(IP-CIDR6 2401:fa00::/32) -> HIGH
    def test_a_ipv6_32_is_high_not_critical(self):
        r = Rule("IP-CIDR6", "2401:fa00::/32", "IP-CIDR6,2401:fa00::/32")
        self.assertEqual(blast_radius(r), "HIGH")

    # B. China /32: 2402:73e0::/32 -> HIGH
    def test_b_china_ipv6_32_is_high(self):
        r = Rule("IP-CIDR6", "2402:73e0::/32", "IP-CIDR6,2402:73e0::/32")
        self.assertEqual(blast_radius(r), "HIGH")

    # C. 真正超宽 IPv6: 2000::/16 -> CRITICAL
    def test_c_ipv6_16_is_critical(self):
        r = Rule("IP-CIDR6", "2000::/16", "IP-CIDR6,2000::/16")
        self.assertEqual(blast_radius(r), "CRITICAL")

    # D. IPv6 HTTP URL: 2401:fa00::1 -> http://[2401:fa00::1]/
    def test_d_ipv6_http_probe_url(self):
        self.assertEqual(_http_probe_url("2401:fa00::1"), "http://[2401:fa00::1]/")

    # E. IPv4 HTTP URL: 8.8.8.8 -> http://8.8.8.8/
    def test_e_ipv4_http_probe_url(self):
        self.assertEqual(_http_probe_url("8.8.8.8"), "http://8.8.8.8/")

    # F. Domain HTTP URL: example.com -> http://example.com/
    def test_f_domain_http_probe_url(self):
        self.assertEqual(_http_probe_url("example.com"), "http://example.com/")

    # G. IP witness 不再被 _looks_ip 丢弃
    def test_g_ip_witness_not_dropped(self):
        harness = {
            "policies": ["GITHUB", "GOOGLE", "FINAL"],
            "rules": [
                "RULE-SET,github,GITHUB",
                "RULE-SET,GoogleIP,GOOGLE",
                "MATCH,FINAL",
            ],
        }
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "GoogleIP": snap("GoogleIP", "", behavior="ipcidr", rules=(), sha256="old-google"),
        }
        new_rule = Rule("IP-CIDR", "8.8.8.0/24", "IP-CIDR,8.8.8.0/24")
        new = {
            "github": old["github"],
            "GoogleIP": snap("GoogleIP", "8.8.8.0/24\n", behavior="ipcidr", rules=(new_rule,), sha256="new-google"),
        }
        res = engine(old, new, harness)
        self.assertIn("GoogleIP", res.report.get("exercised", []))
        self.assertNotIn("GoogleIP", res.report.get("changed_unexercised", []))

    # H. IP witness 调用形式必须：oracle.match(ip, ip=ip)
    def test_h_ip_witness_called_with_ip_param(self):
        calls = []
        class SpyOracle:
            def match(self, host: str, ip: str | None = None):
                calls.append((host, ip))
                return MatchResult(host, 0, "MATCH,FINAL", "FINAL", source="spy")

        harness = {"rules": ["MATCH,FINAL"]}
        old = {"GoogleIP": snap("GoogleIP", "", behavior="ipcidr", rules=(), sha256="old")}
        r = Rule("IP-CIDR", "8.8.8.0/24", "IP-CIDR,8.8.8.0/24")
        new = {"GoogleIP": snap("GoogleIP", "8.8.8.0/24\n", behavior="ipcidr", rules=(r,), sha256="new")}
        run_engine(
            baseline=old,
            candidate=new,
            harness=harness,
            policy_doc=POLICY,
            golden_doc=GOLDEN,
            protected_doc=PROTECTED,
            known_doc={"decisions": []},
            thresholds=THRESH,
            oracle_old=SpyOracle(),
            oracle_new=SpyOracle(),
            full_regression=False,
            missing_baseline=False,
            mihomo_version="v1.19.15",
            oracle_kind="fixture",
        )
        ip_calls = [(h, ip) for h, ip in calls if ip is not None]
        self.assertTrue(len(ip_calls) > 0)
        for h, ip in ip_calls:
            self.assertEqual(h, ip)

    # I. 每 provider 每 side 最多 3 个 IP witness
    def test_i_ip_witness_limit_per_side(self):
        harness = {"rules": ["MATCH,FINAL"]}
        old = {"MultiIP": snap("MultiIP", "", behavior="ipcidr", rules=(), sha256="old")}
        added_rules = tuple(
            Rule("IP-CIDR", f"10.0.{i}.0/24", f"IP-CIDR,10.0.{i}.0/24") for i in range(10)
        )
        new = {"MultiIP": snap("MultiIP", "\n".join(f"10.0.{i}.0/24" for i in range(10)), behavior="ipcidr", rules=added_rules, sha256="new")}
        calls = []
        class SpyOracle:
            def match(self, host: str, ip: str | None = None):
                if ip:
                    calls.append(ip)
                return MatchResult(host, 0, "MATCH,FINAL", "FINAL", source="spy")

        run_engine(
            baseline=old,
            candidate=new,
            harness=harness,
            policy_doc=POLICY,
            golden_doc=GOLDEN,
            protected_doc=PROTECTED,
            known_doc={"decisions": []},
            thresholds=THRESH,
            oracle_old=SpyOracle(),
            oracle_new=SpyOracle(),
            full_regression=False,
            missing_baseline=False,
            mihomo_version="v1.19.15",
            oracle_kind="fixture",
        )
        unique_ips = set(calls)
        self.assertLessEqual(len(unique_ips), 3)

    # J. removed-only provider: OLD 命中 FacebookIP, NEW 不命中 FacebookIP, 仍必须算 FacebookIP exercised = YES
    def test_j_removed_only_exercised_via_old_match(self):
        harness = {
            "policies": ["GITHUB", "FACEBOOK", "FINAL"],
            "rules": [
                "RULE-SET,github,GITHUB",
                "RULE-SET,FacebookIP,FACEBOOK",
                "MATCH,FINAL",
            ],
        }
        r = Rule("IP-CIDR", "157.240.0.0/16", "IP-CIDR,157.240.0.0/16")
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "FacebookIP": snap("FacebookIP", "157.240.0.0/16\n", behavior="ipcidr", rules=(r,), sha256="old-fb"),
        }
        new = {
            "github": old["github"],
            "FacebookIP": snap("FacebookIP", "", behavior="ipcidr", rules=(), sha256="new-fb"),
        }
        res = engine(old, new, harness)
        self.assertNotIn("FacebookIP", res.report.get("changed_unexercised", []))

    # K. 如果 IP OLD/NEW policy 改变：必须进入 routing_changes，不得只增加 coverage
    def test_k_ip_routing_change_recorded(self):
        harness = {
            "policies": ["GITHUB", "PROXY", "FINAL"],
            "rules": [
                "RULE-SET,github,GITHUB",
                "RULE-SET,GoogleIP,PROXY",
                "MATCH,FINAL",
            ],
        }
        r = Rule("IP-CIDR", "8.8.8.0/24", "IP-CIDR,8.8.8.0/24")
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "GoogleIP": snap("GoogleIP", "", behavior="ipcidr", rules=(), sha256="old-g"),
        }
        new = {
            "github": old["github"],
            "GoogleIP": snap("GoogleIP", "8.8.8.0/24\n", behavior="ipcidr", rules=(r,), sha256="new-g"),
        }
        res = engine(old, new, harness)
        details = res.report.get("routing_change_details", [])
        ip_changes = [c for c in details if c.get("host", "").startswith("8.8.8.")]
        self.assertTrue(len(ip_changes) > 0)
        self.assertEqual(ip_changes[0]["old_policy"], "FINAL")
        self.assertEqual(ip_changes[0]["new_policy"], "PROXY")

    # L. 真正没有 OLD/NEW provider match: 仍然 CHANGED_BUT_UNEXERCISED, 保持 fail-closed
    def test_l_unmatched_provider_remains_unexercised_fail_closed(self):
        harness = {
            "policies": ["GITHUB", "PROXY", "FINAL"],
            "rules": [
                "RULE-SET,github,GITHUB",
                "MATCH,FINAL",
            ],
        }
        r1 = Rule("IP-CIDR", "192.0.2.0/24", "IP-CIDR,192.0.2.0/24")
        r2 = Rule("IP-CIDR", "192.0.2.0/23", "IP-CIDR,192.0.2.0/23")
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "UnreachableIP": snap("UnreachableIP", "192.0.2.0/24\n", behavior="ipcidr", rules=(r1,), sha256="old"),
        }
        new = {
            "github": old["github"],
            "UnreachableIP": snap("UnreachableIP", "192.0.2.0/23\n", behavior="ipcidr", rules=(r2,), sha256="new"),
        }
        res = engine(old, new, harness)
        self.assertIn("UnreachableIP", res.report.get("changed_unexercised", []))
        self.assertEqual(res.decision, "REVIEW")


if __name__ == "__main__":
    unittest.main()

