#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.decision import decide, known_expected
from routing_audit.models import MatchResult, RoutingChange

AUDIT_DIR = Path(__file__).resolve().parents[1]


class TestPhase6eCidrDecision(unittest.TestCase):
    def setUp(self):
        self.known_path = AUDIT_DIR / "known-decisions.yaml"
        with self.known_path.open(encoding="utf-8") as f:
            self.known_doc = yaml.safe_load(f)

    def test_a_witness_in_cidr(self):
        """A: 103.238.46.1 命中 103.238.46.0/23 -> CHINA"""
        self.assertEqual(known_expected("103.238.46.1", self.known_doc), "CHINA")

    def test_b_boundary_ip_in_cidr(self):
        """B: 103.238.47.200 也命中该 /23 -> CHINA"""
        self.assertEqual(known_expected("103.238.47.200", self.known_doc), "CHINA")

    def test_c_next_subnet_out_of_cidr(self):
        """C: 103.238.48.1 不得命中 -> None"""
        self.assertIsNone(known_expected("103.238.48.1", self.known_doc))

    def test_d_previous_subnet_out_of_cidr(self):
        """D: 103.238.45.255 不得命中 -> None"""
        self.assertIsNone(known_expected("103.238.45.255", self.known_doc))

    def test_e_nodeseek_domain(self):
        """E: 原有 nodeseek.org 仍为 PROXY"""
        self.assertEqual(known_expected("nodeseek.org", self.known_doc), "PROXY")

    def test_f_nodeseek_subdomain(self):
        """F: www.nodeseek.org 仍为 PROXY"""
        self.assertEqual(known_expected("www.nodeseek.org", self.known_doc), "PROXY")

    def test_g_invalid_cidr_fail_closed(self):
        """G: invalid CIDR 不得崩溃或错误匹配"""
        bad_doc = {"decisions": [{"cidr": "103.238.bad/23", "expected": "CHINA"}]}
        self.assertIsNone(known_expected("103.238.46.1", bad_doc))

    def test_h_ipv6_generic_cidr(self):
        """H: IPv6 generic CIDR 支持 2401:fa00::1 in 2401:fa00::/32"""
        ipv6_doc = {"decisions": [{"cidr": "2401:fa00::/32", "expected": "PROXY"}]}
        self.assertEqual(known_expected("2401:fa00::1", ipv6_doc), "PROXY")
        self.assertIsNone(known_expected("2401:fb00::1", ipv6_doc))

    def test_i_routing_change_accepted(self):
        """I: 模拟 103.238.46.1 FINAL -> CHINA，known decision 吸收，不升级 REVIEW"""
        change = RoutingChange(
            host="103.238.46.1",
            old=MatchResult("103.238.46.1", 3, "MATCH,FINAL", "FINAL"),
            new=MatchResult("103.238.46.1", 2, "RULE-SET,ChinaIP,CHINA", "CHINA"),
            reason="policy changed",
        )
        res = decide(
            load_errors=[],
            broad_critical=[],
            size_fails=[],
            count_fails=[],
            golden_results=[],
            routing_changes=[change],
            policy_doc={},
            protected_doc={},
            known_doc=self.known_doc,
            mode_c_changed=[],
            missing_baseline=False,
            oracle_error=None,
            full_regression=False,
        )
        self.assertEqual(res.decision, "PASS")
        self.assertIn("known decision 103.238.46.1 -> CHINA", res.reasons)
        self.assertFalse(any("unreviewed routing change" in r for r in res.reasons))

    def test_j_reverse_routing_change_requires_review(self):
        """J: 反向变化 CHINA -> FINAL，known expected 为 CHINA，不得吸收，必须 REVIEW"""
        change = RoutingChange(
            host="103.238.46.1",
            old=MatchResult("103.238.46.1", 2, "RULE-SET,ChinaIP,CHINA", "CHINA"),
            new=MatchResult("103.238.46.1", 3, "MATCH,FINAL", "FINAL"),
            reason="policy changed",
        )
        res = decide(
            load_errors=[],
            broad_critical=[],
            size_fails=[],
            count_fails=[],
            golden_results=[],
            routing_changes=[change],
            policy_doc={},
            protected_doc={},
            known_doc=self.known_doc,
            mode_c_changed=[],
            missing_baseline=False,
            oracle_error=None,
            full_regression=False,
        )
        self.assertEqual(res.decision, "REVIEW")
        self.assertTrue(any("unreviewed routing change 103.238.46.1: CHINA -> FINAL" in r for r in res.reasons))


if __name__ == "__main__":
    unittest.main()
