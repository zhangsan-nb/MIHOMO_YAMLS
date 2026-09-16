#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.dns_oracle import (
    DnsLookup,
    evaluate_dns,
    lookup_with_retry,
    wait_dns_ready,
)


class TestDnsReadiness(unittest.TestCase):
    def test_lookup_immediate_match(self):
        """首次查询即命中预期类型，立即返回"""
        with patch("routing_audit.dns_oracle.lookup") as mock_lookup:
            mock_lookup.return_value = DnsLookup("baidu.com", "REAL_IP", "9.9.9.9")
            res = lookup_with_retry("baidu.com", "127.0.0.1", 5353, expected_kind="REAL_IP", max_retries=3, retry_interval=0.01)
            self.assertEqual(res.kind, "REAL_IP")
            self.assertEqual(mock_lookup.call_count, 1)

    def test_lookup_retry_delayed_success(self):
        """模拟启动后前两次返回 FAKE_IP，第三次 ruleset 就绪返回 REAL_IP"""
        returns = [
            DnsLookup("baidu.com", "FAKE_IP", "198.18.0.4"),
            DnsLookup("baidu.com", "FAKE_IP", "198.18.0.4"),
            DnsLookup("baidu.com", "REAL_IP", "9.9.9.9"),
        ]
        with patch("routing_audit.dns_oracle.lookup", side_effect=returns) as mock_lookup:
            res = lookup_with_retry("baidu.com", "127.0.0.1", 5353, expected_kind="REAL_IP", max_retries=5, retry_interval=0.01)
            self.assertEqual(res.kind, "REAL_IP")
            self.assertEqual(mock_lookup.call_count, 3)

    def test_lookup_retry_persistent_failure_fail_closed(self):
        """模拟始终返回 FAKE_IP，重试耗尽后如实返回最后结果，evaluate_dns 判定 FAIL (fail-closed)"""
        with patch("routing_audit.dns_oracle.lookup") as mock_lookup:
            mock_lookup.return_value = DnsLookup("baidu.com", "FAKE_IP", "198.18.0.4")
            res = lookup_with_retry("baidu.com", "127.0.0.1", 5353, expected_kind="REAL_IP", max_retries=3, retry_interval=0.01)
            self.assertEqual(res.kind, "FAKE_IP")
            self.assertEqual(mock_lookup.call_count, 3)

            verd = evaluate_dns(
                old=DnsLookup("baidu.com", "REAL_IP", "9.9.9.9"),
                new=res,
                must_real_ip=["baidu.com"],
                must_fake_ip=[],
            )
            self.assertEqual(verd, "FAIL")

    def test_wait_dns_ready_delayed_success(self):
        """模拟 wait_dns_ready 在第 2 次探测就绪返回 True"""
        returns = [
            DnsLookup("baidu.com", "FAKE_IP", "198.18.0.4"),
            DnsLookup("baidu.com", "REAL_IP", "9.9.9.9"),
        ]
        with patch("routing_audit.dns_oracle.lookup", side_effect=returns):
            ready = wait_dns_ready("127.0.0.1", 5353, ["baidu.com"], max_wait=1.0, poll_interval=0.01)
            self.assertTrue(ready)

    def test_wait_dns_ready_timeout_false(self):
        """模拟始终无法返回 REAL_IP，超时返回 False，不崩溃"""
        with patch("routing_audit.dns_oracle.lookup", return_value=DnsLookup("baidu.com", "FAKE_IP", "198.18.0.4")):
            ready = wait_dns_ready("127.0.0.1", 5353, ["baidu.com"], max_wait=0.05, poll_interval=0.01)
            self.assertFalse(ready)


if __name__ == "__main__":
    unittest.main()
