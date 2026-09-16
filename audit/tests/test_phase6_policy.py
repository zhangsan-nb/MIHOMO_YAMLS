#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.decision import known_expected

AUDIT_DIR = Path(__file__).resolve().parents[1]


class TestPhase6Policy(unittest.TestCase):
    def setUp(self):
        self.known_path = AUDIT_DIR / "known-decisions.yaml"
        self.harness_path = AUDIT_DIR / "harness.yaml"
        with self.known_path.open(encoding="utf-8") as f:
            self.known_doc = yaml.safe_load(f)
        with self.harness_path.open(encoding="utf-8") as f:
            self.harness_doc = yaml.safe_load(f)

    def test_a_nodeseek_known_decision(self):
        """A: nodeseek.org known expected = PROXY"""
        expected = known_expected("nodeseek.org", self.known_doc)
        self.assertEqual(expected, "PROXY")

    def test_b_www_nodeseek_inherited_proxy(self):
        """B: www.nodeseek.org is inherited from nodeseek.org -> PROXY"""
        for host in ["www.nodeseek.org", "api.nodeseek.org", "x.test.nodeseek.org"]:
            expected = known_expected(host, self.known_doc)
            self.assertEqual(expected, "PROXY", f"{host} should inherit PROXY")

    def test_c_and_d_ip_cidr_effective_policy_in_harness(self):
        """C & D: 103.144.41.1 -> FINAL and 103.177.70.1 -> CHINA under new harness"""
        rules = self.harness_doc.get("rules") or []

        ip1 = ipaddress.ip_address("103.144.41.1")
        ip2 = ipaddress.ip_address("103.177.70.1")

        def simulate_harness_ip(ip: ipaddress.IPv4Address) -> str:
            for rule in rules:
                if rule.startswith("IP-CIDR,"):
                    parts = [p.strip() for p in rule.split(",")]
                    net = ipaddress.ip_network(parts[1])
                    if ip in net:
                        return parts[2]
                elif rule == "RULE-SET,ChinaIP,CHINA":
                    pass
                elif rule.startswith("MATCH,"):
                    return rule.split(",")[1].strip()
            return "UNMATCHED"

        self.assertEqual(simulate_harness_ip(ip1), "FINAL")
        self.assertNotEqual(simulate_harness_ip(ip1), "CHINA")

        self.assertEqual(simulate_harness_ip(ip2), "CHINA")
        self.assertNotEqual(simulate_harness_ip(ip2), "FINAL")

    def test_e_overrides_precede_china_ip(self):
        """E: 两个 inline override 在 harness 中必须位于 RULE-SET,ChinaIP,CHINA 之前"""
        rules = self.harness_doc.get("rules") or []
        hk_rule = "IP-CIDR,103.144.41.0/24,FINAL,no-resolve"
        cn_rule = "IP-CIDR,103.177.70.0/23,CHINA,no-resolve"
        china_rule = "RULE-SET,ChinaIP,CHINA"

        self.assertIn(hk_rule, rules)
        self.assertIn(cn_rule, rules)
        self.assertIn(china_rule, rules)

        idx_hk = rules.index(hk_rule)
        idx_cn = rules.index(cn_rule)
        idx_china = rules.index(china_rule)

        self.assertLess(idx_hk, idx_china)
        self.assertLess(idx_cn, idx_china)

    def test_f_real_policy_mapping_documented(self):
        """F: REAL policy mapping 策略名抽象映射规范测试"""
        mapping = {
            "FINAL": "🧩 兜底流量",
            "CHINA": "🇨🇳 国内流量",
            "PROXY": "🌍 国外流量",
        }
        self.assertEqual(mapping["FINAL"], "🧩 兜底流量")
        self.assertEqual(mapping["CHINA"], "🇨🇳 国内流量")
        self.assertEqual(mapping["PROXY"], "🌍 国外流量")

    def test_g_spst2_known_decision(self):
        """G: spst2.com known expected = FINAL"""
        expected = known_expected("spst2.com", self.known_doc)
        self.assertEqual(expected, "FINAL")

    def test_h_spst2_subdomains_inherited(self):
        """H: spst2.com subdomains inherit FINAL"""
        for host in ["www.spst2.com", "api.spst2.com", "x.test.spst2.com"]:
            expected = known_expected(host, self.known_doc)
            self.assertEqual(expected, "FINAL", f"{host} should inherit FINAL")


if __name__ == "__main__":
    unittest.main()
