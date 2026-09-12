from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.analysis import blast_radius, semantic_diff
from routing_audit.decision import decide
from routing_audit.models import ProviderSnapshot, Rule
from routing_audit.oracle import FixtureOracle
from routing_audit.ruleset import parse_ruleset_text
from routing_audit.run import run_engine

AUDIT = Path(__file__).resolve().parents[1]


def snap(name: str, text: str, **kwargs) -> ProviderSnapshot:
    rules = tuple(parse_ruleset_text(text, behavior=kwargs.get("behavior", "domain")))
    return ProviderSnapshot(
        name=name,
        path=kwargs.get("path", f"{name}.txt"),
        behavior=kwargs.get("behavior", "domain"),
        format=kwargs.get("format", "text"),
        sha256=kwargs.get("sha256", name + "-sha"),
        size=kwargs.get("size", max(len(text), 32)),
        trust_mode=kwargs.get("trust_mode", "A"),
        semantic_diff=kwargs.get("semantic_diff", "AVAILABLE"),
        entry_count=kwargs.get("entry_count", len(rules)),
        rules=rules,
        present=True,
    )


def harness_github_then_direct():
    return {
        "policies": ["GITHUB", "DIRECT", "FINAL"],
        "rules": [
            "RULE-SET,github,GITHUB",
            "RULE-SET,Direct,DIRECT",
            "MATCH,FINAL",
        ],
    }


POLICY = {
    "domains": {
        "github.com": {"allowed": ["GITHUB"], "forbidden": ["DIRECT", "REJECT", "CHINA", "FINAL", "PROXY"]},
        "openai.com": {"allowed": ["AI"], "forbidden": ["DIRECT", "REJECT"]},
    }
}
PROTECTED = {"domains": ["github.com", "openai.com"], "default_forbidden": ["REJECT"]}
GOLDEN = {"critical": ["github.com"], "representative": {}, "learned": []}
THRESH = {
    "file_size": {"warn_percent": 20, "fail_percent": 70},
    "entry_count": {"fail_shrink_percent": 50, "fail_if_below": 8},
    "broad_suffix": {"fail_on_critical": True},
}


def engine(old, new, harness, golden=GOLDEN, known=None, full=False, missing=False):
    oracle_old = FixtureOracle(harness["rules"], {n: (s.behavior, list(s.rules or ())) for n, s in old.items()})
    oracle_new = FixtureOracle(harness["rules"], {n: (s.behavior, list(s.rules or ())) for n, s in new.items()})
    return run_engine(
        baseline=old,
        candidate=new,
        harness=harness,
        policy_doc=POLICY,
        golden_doc=golden,
        protected_doc=PROTECTED,
        known_doc=known or {"decisions": []},
        thresholds=THRESH,
        oracle_old=oracle_old,
        oracle_new=oracle_new,
        full_regression=full,
        missing_baseline=missing,
        mihomo_version="v1.19.15",
        oracle_kind="fixture",
    )


class AttackCases(unittest.TestCase):
    def test_case1_semantic_change_routing_unchanged_pass(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n+.github.com\n", sha256="direct-new"),
        }
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.decision, "PASS", result.reasons)
        self.assertEqual(result.report["added"], 1)
        self.assertEqual(result.report["routing_changes"], 0)
        self.assertTrue(result.publish_allowed)

    def test_case2_direct_before_github_fail(self):
        harness = {
            "policies": ["GITHUB", "DIRECT", "FINAL"],
            "rules": ["RULE-SET,Direct,DIRECT", "RULE-SET,github,GITHUB", "MATCH,FINAL"],
        }
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n+.github.com\n", sha256="direct-new"),
        }
        result = engine(old, new, harness)
        self.assertEqual(result.decision, "FAIL", result.reasons)
        self.assertFalse(result.publish_allowed)

    def test_case3_remove_github_falls_to_direct_fail(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.github.com\n"),
        }
        new = {
            "github": snap("github", "payload: []\n", sha256="gh-empty"),
            "Direct": snap("Direct", "+.github.com\n"),
        }
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.decision, "FAIL", result.reasons)

    def test_case4_plus_com_critical_fail(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n+.com\n", sha256="wide"),
        }
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.decision, "FAIL", result.reasons)
        self.assertTrue(any("CRITICAL" in x or "+.com" in x for x in result.reasons))

    def test_case5_unknown_routing_change_review(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n+.new.example.com\n", sha256="ex"),
        }
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.decision, "REVIEW", result.reasons)
        self.assertFalse(result.publish_allowed)

    def test_case6_known_decision_pass(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n+.new.example.com\n", sha256="ex"),
        }
        known = {"decisions": [{"domain": "new.example.com", "expected": "DIRECT"}]}
        result = engine(old, new, harness_github_then_direct(), known=known)
        self.assertEqual(result.decision, "PASS", result.reasons)

    def test_case7_mass_shrink_fail(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n", entry_count=100000, sha256="big"),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n", entry_count=5000, sha256="small", size=500),
        }
        # force counts: reconstruct with explicit entry_count after parse
        old["Direct"].entry_count = 100000
        old["Direct"].size = 7_000_000
        new["Direct"].entry_count = 5000
        new["Direct"].size = 500_000
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.decision, "FAIL", result.reasons)

    def test_case8_rules_order_change_full_regression(self):
        old = new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        result = engine(old, new, harness_github_then_direct(), full=True)
        self.assertTrue(result.full_regression)
        self.assertEqual(result.decision, "PASS", result.reasons)

    def test_case9_mihomo_version_change_is_full_regression_flag(self):
        # The version trigger lives in run_audit; engine honors the flag the same way as case 8.
        old = new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": snap("Direct", "+.unrelated.test\n"),
        }
        result = engine(old, new, harness_github_then_direct(), full=True)
        self.assertTrue(result.full_regression)
        self.assertIn("full regression triggered", result.reasons)

    def test_case10_mode_c_no_fake_semantic_review(self):
        old = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": ProviderSnapshot(
                name="Direct",
                path="domain/Direct.mrs",
                behavior="domain",
                format="mrs",
                sha256="aaa",
                size=1000,
                trust_mode="C",
                semantic_diff="UNAVAILABLE",
                entry_count=None,
                rules=None,
                present=True,
            ),
        }
        new = {
            "github": snap("github", "payload:\n  - DOMAIN-SUFFIX,github.com\n"),
            "Direct": ProviderSnapshot(
                name="Direct",
                path="domain/Direct.mrs",
                behavior="domain",
                format="mrs",
                sha256="bbb",
                size=1100,
                trust_mode="C",
                semantic_diff="UNAVAILABLE",
                entry_count=None,
                rules=None,
                present=True,
            ),
        }
        result = engine(old, new, harness_github_then_direct())
        self.assertEqual(result.report["added"], 0)
        self.assertEqual(result.report["removed"], 0)
        self.assertIn("Direct", result.report["mode_c_changed"])
        self.assertEqual(result.decision, "REVIEW", result.reasons)
        self.assertFalse(result.publish_allowed)


class BlastAndParse(unittest.TestCase):
    def test_plus_com_critical(self):
        rules = parse_ruleset_text("+.com\n")
        self.assertEqual(rules[0].kind, "DOMAIN-SUFFIX")
        self.assertEqual(blast_radius(rules[0]), "CRITICAL")

    def test_semantic_diff_kinds_not_strings(self):
        old = parse_ruleset_text("DOMAIN,github.com\n")
        new = parse_ruleset_text("DOMAIN-SUFFIX,github.com\n")
        diff = semantic_diff(old, new)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["removed"]), 1)
        self.assertEqual(diff["added"][0].kind, "DOMAIN-SUFFIX")

    def test_missing_baseline_fail_closed(self):
        result = decide(
            load_errors=[],
            broad_critical=[],
            size_fails=[],
            count_fails=[],
            golden_results=[],
            routing_changes=[],
            policy_doc=POLICY,
            protected_doc=PROTECTED,
            known_doc={"decisions": []},
            mode_c_changed=[],
            missing_baseline=True,
            oracle_error=None,
            full_regression=False,
        )
        self.assertEqual(result.decision, "FAIL")
        self.assertFalse(result.publish_allowed)


if __name__ == "__main__":
    unittest.main()
