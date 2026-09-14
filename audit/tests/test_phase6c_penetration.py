#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.models import MatchResult, ProviderSnapshot, Rule
from routing_audit.oracle import FixtureOracle
from routing_audit.run import run_engine

AUDIT = Path(__file__).resolve().parents[1]


def snap(name: str, rules_list: list[str], behavior: str = "ip") -> ProviderSnapshot:
    rule_objs = tuple(Rule(kind="IP-CIDR", value=r.strip(), raw=r.strip()) for r in rules_list)
    sha = hashlib.sha256(("\n".join(rules_list)).encode("utf-8")).hexdigest()
    return ProviderSnapshot(
        name=name,
        path=f"ip/{name}.txt",
        behavior=behavior,
        format="text",
        sha256=sha,
        size=1000,
        trust_mode="A",
        semantic_diff="AVAILABLE",
        entry_count=100,
        rules=rule_objs,
        readable_sha256=None,
        present=True,
    )


class CIDRFixtureOracle(FixtureOracle):
    def match(self, host: str, ip: str | None = None) -> MatchResult:
        for index, raw in enumerate(self.rules):
            line = raw.strip()
            if line.startswith("IP-CIDR,"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3 and ip:
                    try:
                        net = ipaddress.ip_network(parts[1])
                        target_ip = ipaddress.ip_address(ip)
                        if target_ip in net:
                            return MatchResult(ip, index, line, parts[2], parts[1], source="fixture")
                    except ValueError:
                        pass
                continue
            if line.startswith("MATCH,"):
                return MatchResult(host, index, line, line.split(",", 1)[1].strip(), source="fixture")
            if line.startswith("RULE-SET,"):
                parts = [p.strip() for p in line.split(",")]
                name, policy = parts[1], parts[2]
                spec = self.providers.get(name)
                if not spec:
                    continue
                behavior, rules = spec
                for rule in rules:
                    if ip:
                        try:
                            net = ipaddress.ip_network(rule.value)
                            if ipaddress.ip_address(ip) in net:
                                return MatchResult(ip, index, line, policy, rule.raw, source="fixture")
                        except ValueError:
                            pass
        return MatchResult(host, -1, "UNMATCHED", "UNMATCHED", source="fixture")


def make_harness():
    return {
        "policies": ["FINAL", "CHINA"],
        "rules": [
            "IP-CIDR,103.144.41.0/24,FINAL,no-resolve",
            "IP-CIDR,103.177.70.0/23,CHINA,no-resolve",
            "RULE-SET,ChinaIP,CHINA",
            "MATCH,FINAL",
        ],
    }


def run_test_engine(old, new, harness):
    oracle_old = CIDRFixtureOracle(harness["rules"], {n: (s.behavior, list(s.rules or ())) for n, s in old.items()})
    oracle_new = CIDRFixtureOracle(harness["rules"], {n: (s.behavior, list(s.rules or ())) for n, s in new.items()})
    return run_engine(
        baseline=old,
        candidate=new,
        harness=harness,
        policy_doc={"domains": {}},
        golden_doc={"critical": [], "representative": {}, "learned": []},
        protected_doc={"domains": [], "default_forbidden": []},
        known_doc={"decisions": []},
        thresholds={
            "file_size": {"fail_percent": 9999},
            "entry_count": {"fail_shrink_percent": 9999, "fail_if_below": 0},
        },
        oracle_old=oracle_old,
        oracle_new=oracle_new,
        full_regression=False,
        missing_baseline=False,
        mihomo_version="v1.19.15",
        oracle_kind="fixture",
    )


class TestPhase6cPenetration(unittest.TestCase):
    def test_a_primary_shadowed_fallback_hits(self):
        """A: primary IP 均被截获，fallback 穿透并命中 RuleSet(ChinaIP)"""
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        rules = [
            "103.144.41.1/32",
            "103.144.41.2/32",
            "103.144.41.3/32",
            "103.144.41.4/32",
            "103.144.41.5/32",
            "103.144.41.6/32",
            "114.114.114.0/24",
        ]
        new = {"ChinaIP": snap("ChinaIP", rules)}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertEqual(fb.get("result"), "EXERCISED")
        self.assertIn(fb.get("hit_side"), ["NEW", "BOTH"])
        self.assertNotIn("ChinaIP", res.report.get("changed_unexercised", []))

    def test_b_all_fallback_shadowed(self):
        """B: primary + fallback 全部被前置规则截获，ChinaIP 仍为 CHANGED_BUT_UNEXERCISED"""
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        rules = [f"103.144.41.{i}/32" for i in range(1, 16)]
        new = {"ChinaIP": snap("ChinaIP", rules)}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertEqual(fb.get("result"), "NOT_EXERCISED")
        self.assertIn("ChinaIP", res.report.get("changed_unexercised", []))
        self.assertEqual(res.decision, "REVIEW")

    def test_c_fallback_limit(self):
        """C: 提供 >20 candidate，实际额外执行 <= 8"""
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        rules = [f"103.144.41.{i}/32" for i in range(1, 26)]
        new = {"ChinaIP": snap("ChinaIP", rules)}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertLessEqual(fb.get("count", 0), 8)
        self.assertEqual(fb.get("count", 0), 8)

    def test_d_deterministic(self):
        """D: 同一 diff 连跑两次，fallback candidate 顺序完全一致"""
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        rules = ["103.144.41.9/32", "103.144.41.2/32", "103.144.41.7/32", "114.114.114.0/24"]
        new = {"ChinaIP": snap("ChinaIP", rules)}
        harness = make_harness()

        res1 = run_test_engine(old, new, harness)
        res2 = run_test_engine(old, new, harness)
        fb1 = res1.report.get("coverage_fallback", {}).get("ChinaIP", {})
        fb2 = res2.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertEqual(fb1.get("attempted"), fb2.get("attempted"))

    def test_e_removed_only_old_hit(self):
        """E: removed-only 规则在 OLD 命中，NEW 走 FINAL，依然算 ChinaIP exercised"""
        old_rules = [
            "103.177.70.1/32",
            "103.177.70.2/32",
            "103.177.70.3/32",
            "114.114.114.0/24",
        ]
        new_rules = ["103.144.41.1/32"]
        old = {"ChinaIP": snap("ChinaIP", old_rules + new_rules)}
        new = {"ChinaIP": snap("ChinaIP", new_rules)}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertEqual(fb.get("result"), "EXERCISED")
        self.assertIn(fb.get("hit_side"), ["OLD", "BOTH"])
        self.assertNotIn("ChinaIP", res.report.get("changed_unexercised", []))

    def test_f_fallback_routing_change_visible(self):
        """F: fallback 探测发现的路由策略变化必须记录在 routing_changes 中"""
        rules_new = [
            "103.144.41.1/32",
            "103.144.41.2/32",
            "103.144.41.3/32",
            "114.114.114.0/24",
        ]
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        new = {"ChinaIP": snap("ChinaIP", rules_new)}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        details = res.report.get("routing_change_details", [])
        self.assertTrue(any("114.114.114" in d.get("host", "") for d in details))

    def test_g_same_policy_inline_not_provider_hit(self):
        """G: 命中 inline IP-CIDR -> CHINA，policy 虽为 CHINA，但无 RuleSet(ChinaIP)，不得算 ChinaIP exercised"""
        old = {"ChinaIP": snap("ChinaIP", ["103.144.41.1/32"])}
        new = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP", {})
        self.assertEqual(fb.get("result"), "NOT_EXERCISED")
        self.assertIn("ChinaIP", res.report.get("changed_unexercised", []))

    def test_h_normal_provider_no_extra_probe(self):
        """H: 如果 primary probe 已直接命中 ChinaIP，fallback probe count = 0"""
        old = {"ChinaIP": snap("ChinaIP", ["103.177.70.1/32"])}
        new = {"ChinaIP": snap("ChinaIP", ["114.114.114.0/24"])}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("ChinaIP")
        self.assertIsNone(fb)
        self.assertNotIn("ChinaIP", res.report.get("changed_unexercised", []))

    def test_i_out_of_scope_facebook_ip(self):
        """I: FacebookIP 不在 harness 中，不得启动 penetration fallback"""
        old = {"FacebookIP": snap("FacebookIP", ["1.1.1.1/32"])}
        new = {"FacebookIP": snap("FacebookIP", ["2.2.2.2/32"])}
        harness = make_harness()

        res = run_test_engine(old, new, harness)
        fb = res.report.get("coverage_fallback", {}).get("FacebookIP")
        self.assertIsNone(fb)


if __name__ == "__main__":
    unittest.main()
