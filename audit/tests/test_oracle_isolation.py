from __future__ import annotations

import io
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from routing_audit.models import MatchResult
from routing_audit.oracle import (
    SYNTHETIC_DIRECT,
    MihomoOracle,
    OracleError,
    _normalize_policy,
    _rewrite_rule_direct,
    build_harness_config,
)
from routing_audit.ruleset import parse_ruleset_text


class TestOracleIsolation(unittest.TestCase):
    def test_1_direct_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            harness = {
                "policies": ["DIRECT", "REJECT", "LOCATION", "XPTV_GROUP"],
                "rules": [
                    "RULE-SET,XPTV,DIRECT",
                    "RULE-SET,Direct,DIRECT",
                    "DOMAIN-SUFFIX,steamserver.net,DIRECT",
                    "MATCH,FINAL",
                ],
            }
            cfg_path = build_harness_config(
                harness=harness,
                provider_files={},
                mixed_port=12345,
                api_port=12346,
                secret="sec",
                workdir=workdir,
            )
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

            # Must have synthetic group with REJECT only
            groups = {g["name"]: g for g in cfg["proxy-groups"]}
            self.assertIn(SYNTHETIC_DIRECT, groups)
            self.assertEqual(groups[SYNTHETIC_DIRECT]["proxies"], ["REJECT"])

            # Rules must be rewritten to synthetic direct
            rules = cfg["rules"]
            self.assertIn(f"RULE-SET,XPTV,{SYNTHETIC_DIRECT}", rules)
            self.assertIn(f"RULE-SET,Direct,{SYNTHETIC_DIRECT}", rules)
            self.assertIn(f"DOMAIN-SUFFIX,steamserver.net,{SYNTHETIC_DIRECT}", rules)

    def test_2_semantic_normalization(self):
        # Direct policy normalization
        self.assertEqual(_normalize_policy(SYNTHETIC_DIRECT), "DIRECT")
        self.assertEqual(_normalize_policy(f"{SYNTHETIC_DIRECT}[REJECT]"), "DIRECT")
        self.assertEqual(_normalize_policy("GITHUB[REJECT]"), "GITHUB")
        self.assertEqual(_normalize_policy("DIRECT"), "DIRECT")

        # Log parsing normalization
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            log_path = workdir / "mihomo.log"
            log_path.write_text(
                f'time="2026-09-13T00:00:00" level=info msg="[TCP] 127.0.0.1:54321 --> baidu.com:80 match RuleSet(XPTV) using {SYNTHETIC_DIRECT}[REJECT]"\n',
                encoding="utf-8",
            )
            oracle = MihomoOracle(Path("dummy"), workdir, workdir / "harness.yaml", 1000, 1001, "sec")
            match = oracle._match_from_log("baidu.com")
            self.assertIsNotNone(match)
            self.assertEqual(match.policy, "DIRECT")
            self.assertEqual(match.rule_text, "RuleSet(XPTV)")

    def test_3_baidu_path(self):
        harness = {
            "rules": [
                "RULE-SET,XPTV,DIRECT",
                "RULE-SET,China,CHINA",
                "MATCH,FINAL",
            ]
        }
        rewritten = [_rewrite_rule_direct(r) for r in harness["rules"]]
        self.assertEqual(rewritten[0], f"RULE-SET,XPTV,{SYNTHETIC_DIRECT}")
        self.assertEqual(rewritten[1], "RULE-SET,China,CHINA")
        # Normalization test for the baidu match line
        raw_log_policy = f"{SYNTHETIC_DIRECT}[REJECT]"
        self.assertEqual(_normalize_policy(raw_log_policy), "DIRECT")

    def test_4_delayed_log_flush(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            log_path = workdir / "mihomo.log"
            log_path.touch()
            oracle = MihomoOracle(Path("dummy"), workdir, workdir / "harness.yaml", 1000, 1001, "sec")

            def append_later():
                time.sleep(0.15)
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(
                        f'time="2026-09-13T00:00:01" level=info msg="[TCP] 127.0.0.1:54321 --> delayed.test:80 match RuleSet(XPTV) using {SYNTHETIC_DIRECT}[REJECT]"\n'
                    )

            t = threading.Thread(target=append_later)
            t.start()

            # Emulate bounded observation polling loop
            start_offset = 0
            deadline = time.monotonic() + 1.5
            found = None
            while time.monotonic() < deadline:
                found = oracle._match_from_log("delayed.test", start_offset=start_offset)
                if found:
                    break
                time.sleep(0.04)

            t.join()
            self.assertIsNotNone(found)
            self.assertEqual(found.policy, "DIRECT")
            self.assertEqual(found.host, "delayed.test")

    def test_5_stale_log_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            log_path = workdir / "mihomo.log"
            # First probe log
            log_path.write_text(
                'time="2026-09-13T00:00:01" level=info msg="[TCP] 127.0.0.1:11111 --> same.host:80 match RuleSet(OLD) using OLD_POLICY"\n',
                encoding="utf-8",
            )
            oracle = MihomoOracle(Path("dummy"), workdir, workdir / "harness.yaml", 1000, 1001, "sec")

            # Second probe starts after offset
            offset = log_path.stat().st_size
            with log_path.open("a", encoding="utf-8") as f:
                f.write(
                    f'time="2026-09-13T00:00:02" level=info msg="[TCP] 127.0.0.1:22222 --> same.host:80 match RuleSet(NEW) using {SYNTHETIC_DIRECT}[REJECT]"\n'
                )

            # Read with offset: only sees NEW
            res = oracle._match_from_log("same.host", start_offset=offset)
            self.assertIsNotNone(res)
            self.assertEqual(res.rule_text, "RuleSet(NEW)")
            self.assertEqual(res.policy, "DIRECT")

    def test_6_true_unmatched(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            log_path = workdir / "mihomo.log"
            log_path.touch()
            oracle = MihomoOracle(Path("dummy"), workdir, workdir / "harness.yaml", 1000, 1001, "sec")

            # Polling with no evidence should return None
            res = oracle._match_from_log("never.matched", start_offset=0)
            self.assertIsNone(res)

    def test_7_ordinary_proxy_groups_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            harness = {
                "policies": ["GITHUB", "AI", "GOOGLE", "YOUTUBE", "DIRECT", "REJECT"],
                "rules": [
                    "RULE-SET,github,GITHUB",
                    "RULE-SET,AI,AI",
                    "RULE-SET,Google,GOOGLE",
                    "RULE-SET,YouTube,YOUTUBE",
                    "RULE-SET,XPTV,DIRECT",
                ],
            }
            cfg_path = build_harness_config(
                harness=harness,
                provider_files={},
                mixed_port=12345,
                api_port=12346,
                secret="sec",
                workdir=workdir,
            )
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            groups = {g["name"]: g for g in cfg["proxy-groups"]}

            for name in ["GITHUB", "AI", "GOOGLE", "YOUTUBE"]:
                self.assertIn(name, groups)
                self.assertEqual(groups[name]["proxies"], ["REJECT", "DIRECT"])

            # Only __AUDIT_DIRECT__ is REJECT only
            self.assertEqual(groups[SYNTHETIC_DIRECT]["proxies"], ["REJECT"])

    def test_8_no_real_direct_route_in_generated_audit_config(self):
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            harness = {
                "policies": ["DIRECT", "REJECT", "CHINA"],
                "rules": [
                    "RULE-SET,Private,DIRECT",
                    "RULE-SET,Direct,DIRECT",
                    "RULE-SET,XPTV,DIRECT",
                    "RULE-SET,Download,DIRECT",
                    "RULE-SET,AppleCN,DIRECT",
                    "DOMAIN-SUFFIX,steamserver.net,DIRECT",
                    "RULE-SET,PrivateIP,DIRECT",
                    "RULE-SET,XPTVIP,DIRECT",
                    "RULE-SET,China,CHINA",
                    "MATCH,FINAL",
                ],
            }
            cfg_path = build_harness_config(
                harness=harness,
                provider_files={},
                mixed_port=12345,
                api_port=12346,
                secret="sec",
                workdir=workdir,
            )
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            for rule in cfg["rules"]:
                parts = [p.strip() for p in rule.split(",")]
                # None of the rules should target bare DIRECT
                self.assertNotIn("DIRECT", parts, msg=f"Bare DIRECT found in generated rule: {rule}")


if __name__ == "__main__":
    unittest.main()