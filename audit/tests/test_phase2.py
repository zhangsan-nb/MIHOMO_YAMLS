from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.bootstrap import pair_readable
from routing_audit.correspondence import compare_source_and_decoded, source_mrs_lockstep
from routing_audit.dns_oracle import DnsLookup, classify_ip, evaluate_dns
from routing_audit.hitcount import DualOracle, hitcount_supported, select_oracle_mode
from routing_audit.models import MatchResult, ProviderSnapshot
from routing_audit.oracle import FixtureOracle, OracleError
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


if __name__ == "__main__":
    unittest.main()
