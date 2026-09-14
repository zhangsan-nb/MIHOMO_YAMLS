#!/usr/bin/env python3

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# 动态加载 send-rule-report.py 模块
SCRIPT_PATH = Path(__file__).resolve().parents[1] / "send-rule-report.py"
spec = importlib.util.spec_from_file_location("send_rule_report", SCRIPT_PATH)
send_rule_report = importlib.util.module_from_spec(spec)
sys.modules["send_rule_report"] = send_rule_report
spec.loader.exec_module(send_rule_report)


class TestEmailReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_audit_report(self, decision: str, risk: str = "LOW", reasons: list[str] | None = None) -> Path:
        data = {
            "decision": decision,
            "risk": risk,
            "reasons": reasons if reasons is not None else [],
        }
        p = self.dir_path / "audit-report.json"
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return p

    def test_case_1_pass(self):
        """CASE 1 — PASS: 全部步骤正常完成，整体状态为成功"""
        audit_path = self._write_audit_report(decision="PASS", risk="LOW", reasons=[])
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "success",
            "PUBLISH_OUTCOME": "success",
            "PURGE_OUTCOME": "success",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [{"path": f"domain/rule_{i}.yaml", "status": "UNCHANGED"} for i in range(43)]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("成功", subject)
        self.assertIn("[MIHOMO YAMLS规则] 成功 | 校验 43 | 变化 0", subject)
        self.assertIn("MIHOMO YAMLS规则镜像：成功", body)
        self.assertIn("- 下载校验：成功", body)
        self.assertIn("- 供应链审计：通过", body)
        self.assertIn("- 发布分支：成功", body)
        self.assertIn("- 刷新 CDN：成功", body)

    def test_case_2_review(self):
        """CASE 2 — REVIEW: 需人工审核，发布和刷新跳过，整体状态为需审核"""
        reasons = [
            "unreviewed routing change nodeseek.org: FINAL -> PROXY",
            "unreviewed routing change 103.144.41.1: FINAL -> CHINA",
        ]
        audit_path = self._write_audit_report(decision="REVIEW", risk="MEDIUM", reasons=reasons)
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "failure",
            "PUBLISH_OUTCOME": "skipped",
            "PURGE_OUTCOME": "skipped",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [
            {"path": "domain/NodeSeek.yaml", "status": "UPDATED"},
            {"path": "ip/NodeSeek.yaml", "status": "NEW"},
            {"path": "domain/Direct.yaml", "status": "UNCHANGED"},
        ]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("需审核", subject)
        self.assertIn("发布已阻断", subject)
        self.assertNotIn("规则镜像：失败", body)
        self.assertIn("MIHOMO YAMLS规则镜像：需审核", body)
        self.assertIn("- 下载校验：成功", body)
        self.assertIn("- 供应链审计：需人工审核", body)
        self.assertIn("- 发布分支：已阻断", body)
        self.assertIn("- 刷新 CDN：已跳过", body)
        self.assertIn("Decision: REVIEW", body)
        self.assertIn("Risk: MEDIUM", body)
        self.assertIn("nodeseek.org: FINAL -> PROXY", body)

    def test_case_3_fail(self):
        """CASE 3 — FAIL: 审计拒绝阻断，整体状态为安全阻断"""
        reasons = ["broad rule CRITICAL: ChinaIP 2402:73e0::/32"]
        audit_path = self._write_audit_report(decision="FAIL", risk="CRITICAL", reasons=reasons)
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "failure",
            "PUBLISH_OUTCOME": "skipped",
            "PURGE_OUTCOME": "skipped",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [
            {"path": "ip/ChinaIP.yaml", "status": "UPDATED"},
            {"path": "domain/Direct.yaml", "status": "UNCHANGED"},
        ]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("安全阻断", subject)
        self.assertIn("发布已阻断", subject)
        self.assertNotIn("运行失败", body)
        self.assertNotIn("规则镜像：失败", body)
        self.assertIn("MIHOMO YAMLS规则镜像：安全阻断", body)
        self.assertIn("- 下载校验：成功", body)
        self.assertIn("- 供应链审计：安全阻断", body)
        self.assertIn("- 发布分支：已阻断", body)
        self.assertIn("- 刷新 CDN：已跳过", body)
        self.assertIn("Decision: FAIL", body)
        self.assertIn("Risk: CRITICAL", body)

    def test_case_4_audit_technical_failure(self):
        """CASE 4 — audit technical failure: 报告文件缺失或无法解析，整体状态为运行失败"""
        missing_path = self.dir_path / "non_existent_audit_report.json"
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "failure",
            "PUBLISH_OUTCOME": "skipped",
            "PURGE_OUTCOME": "skipped",
            "AUDIT_REPORT": str(missing_path),
        }
        rows = [{"path": "domain/Direct.yaml", "status": "UNCHANGED"}]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, missing_path)

        self.assertIn("运行失败", subject)
        self.assertIn("MIHOMO YAMLS规则镜像：运行失败", body)
        self.assertIn("- 供应链审计：失败", body)

    def test_case_5_pass_but_publish_failure(self):
        """CASE 5 — PASS but publish failure: 审计通过但发布分支执行异常，整体状态为运行失败"""
        audit_path = self._write_audit_report(decision="PASS", risk="LOW", reasons=[])
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "success",
            "PUBLISH_OUTCOME": "failure",
            "PURGE_OUTCOME": "skipped",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [{"path": "domain/Direct.yaml", "status": "UNCHANGED"}]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("运行失败", subject)
        self.assertIn("MIHOMO YAMLS规则镜像：运行失败", body)
        self.assertIn("- 发布分支：失败", body)

    def test_case_6_pass_but_purge_failure(self):
        """CASE 6 — PASS but purge failure: 审计和发布正常但 CDN 刷新失败，整体状态为运行失败"""
        audit_path = self._write_audit_report(decision="PASS", risk="LOW", reasons=[])
        env = {
            "MIRROR_OUTCOME": "success",
            "AUDIT_OUTCOME": "success",
            "PUBLISH_OUTCOME": "success",
            "PURGE_OUTCOME": "failure",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [{"path": "domain/Direct.yaml", "status": "UNCHANGED"}]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("运行失败", subject)
        self.assertIn("MIHOMO YAMLS规则镜像：运行失败", body)
        self.assertIn("- 刷新 CDN：失败", body)

    def test_mirror_failure(self):
        """规则下载或校验失败时，整体状态必须为运行失败"""
        audit_path = self._write_audit_report(decision="PASS", risk="LOW", reasons=[])
        env = {
            "MIRROR_OUTCOME": "failure",
            "AUDIT_OUTCOME": "skipped",
            "PUBLISH_OUTCOME": "skipped",
            "PURGE_OUTCOME": "skipped",
            "AUDIT_REPORT": str(audit_path),
        }
        rows = [
            {"path": "domain/Direct.yaml", "status": "FAILED", "detail": "下载失败"},
        ]

        with patch.dict(os.environ, env, clear=True):
            subject, body = send_rule_report.build_message(rows, audit_path)

        self.assertIn("运行失败", subject)
        self.assertIn("校验失败 1", subject)
        self.assertIn("MIHOMO YAMLS规则镜像：运行失败", body)
        self.assertIn("- 下载校验：失败", body)


if __name__ == "__main__":
    unittest.main()
