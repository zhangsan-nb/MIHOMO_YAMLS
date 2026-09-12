from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
import yaml

from .models import MatchResult, OracleKind
from .ruleset import rule_matches_host, rule_matches_ip

_LOG_MATCH = re.compile(
    r"-->\s+(?P<host>[^:\s]+):\d+\s+match\s+(?P<rule>.+?)\s+using\s+(?P<policy>[^\s\[]+)",
    re.I,
)


def _normalize_policy(policy: str) -> str:
    policy = (policy or "").strip().strip('"').strip("'")
    if "[" in policy:
        policy = policy.split("[", 1)[0].strip()
    return policy


class OracleError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FixtureOracle:
    """First-match RULE-SET simulator for unit fixtures only. Not the production oracle."""

    kind: OracleKind = "fixture"

    def __init__(self, rules: list[str], providers: dict[str, tuple[str, list]]):
        self.rules = list(rules)
        self.providers = providers  # name -> (behavior, [Rule])

    def match(self, host: str, ip: str | None = None) -> MatchResult:
        for index, raw in enumerate(self.rules):
            line = raw.strip()
            if line.startswith("MATCH,"):
                return MatchResult(host, index, line, line.split(",", 1)[1], source="fixture")
            if line.startswith("DOMAIN-SUFFIX,"):
                _, rest = line.split(",", 1)
                suffix, policy = rest.split(",", 1)
                suffix, policy = suffix.strip().lower(), policy.strip()
                h = host.lower().rstrip(".")
                if h == suffix or h.endswith("." + suffix):
                    return MatchResult(host, index, line, policy, suffix, source="fixture")
                continue
            if line.startswith("DOMAIN-KEYWORD,"):
                _, rest = line.split(",", 1)
                kw, policy = rest.split(",", 1)
                if kw.strip().lower() in host.lower():
                    return MatchResult(host, index, line, policy.strip(), kw.strip(), source="fixture")
                continue
            if line.startswith("DOMAIN,"):
                _, rest = line.split(",", 1)
                name, policy = rest.split(",", 1)
                if host.lower().rstrip(".") == name.strip().lower():
                    return MatchResult(host, index, line, policy.strip(), name.strip(), source="fixture")
                continue
            if line.startswith("RULE-SET,"):
                parts = [p.strip() for p in line.split(",")]
                name, policy = parts[1], parts[2]
                spec = self.providers.get(name)
                if not spec:
                    continue
                behavior, rules = spec
                for rule in rules:
                    if ip and rule_matches_ip(rule, ip):
                        return MatchResult(ip, index, line, policy, rule.raw, source="fixture")
                    if host and rule_matches_host(rule, host):
                        return MatchResult(host, index, line, policy, rule.raw, source="fixture")
        return MatchResult(host, -1, "UNMATCHED", "UNMATCHED", source="fixture")

    def close(self) -> None:
        return None


class MihomoOracle:
    kind: OracleKind = "mihomo"

    def __init__(
        self,
        binary: Path,
        workdir: Path,
        config_path: Path,
        mixed_port: int,
        api_port: int,
        secret: str,
    ):
        self.binary = binary
        self.workdir = workdir
        self.config_path = config_path
        self.mixed_port = mixed_port
        self.api_port = api_port
        self.secret = secret
        self.proc: subprocess.Popen | None = None
        self.log_path = workdir / "mihomo.log"
        self._version = ""
        self.hitcount_supported = False
        self.oracle_mode = "log_fallback"
        self.dns_listen: int | None = None

    @property
    def version(self) -> str:
        return self._version

    def start(self, timeout: float = 30.0) -> None:
        log_handle = self.log_path.open("wb")
        self.proc = subprocess.Popen(
            [str(self.binary), "-d", str(self.workdir), "-f", str(self.config_path)],
            cwd=str(self.workdir),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + timeout
        last_err = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                raise OracleError(f"mihomo exited {self.proc.returncode}: {tail}")
            try:
                payload = self._api("GET", "/version")
                self._version = str(payload.get("version") or payload)
                try:
                    from .hitcount import hitcount_supported, select_oracle_mode

                    rules = self._api("GET", "/rules")
                    self.hitcount_supported = hitcount_supported(rules)
                    self.oracle_mode = select_oracle_mode(rules)
                except Exception:
                    self.hitcount_supported = False
                    self.oracle_mode = "log_fallback"
                return
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                time.sleep(0.15)
        raise OracleError(f"mihomo API not ready: {last_err}")

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def __enter__(self) -> "MihomoOracle":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def match(self, host: str, ip: str | None = None) -> MatchResult:
        # Matcher runs on the HTTP-proxy request line. Groups select REJECT so
        # there is no real outbound. HTTP status is never the oracle.
        target = ip or host
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.mixed_port}"})
        )
        try:
            opener.open(f"http://{target}/", timeout=0.8)
        except Exception:
            pass
        if self.hitcount_supported:
            try:
                from .hitcount import cross_check, match_from_hitcount, snapshot_hits

                before = snapshot_hits(self._api("GET", "/rules"))
                try:
                    opener.open(f"http://{target}/", timeout=0.8)
                except Exception:
                    pass
                after = snapshot_hits(self._api("GET", "/rules"))
                api_match = match_from_hitcount(before, after, host if not ip else target)
                logged = self._match_from_log(host if not ip else target)
                if api_match and logged:
                    cross_check(api_match, logged)
                    return api_match
                if api_match:
                    return api_match
            except OracleError:
                raise
            except Exception:
                pass
        logged = self._match_from_log(host if not ip else target)
        if logged:
            return logged
        conn = self._match_from_connections(host, ip)
        if conn:
            return conn
        raise OracleError(f"no match observed for {host}")

    def _match_from_connections(self, host: str, ip: str | None) -> MatchResult | None:
        try:
            data = self._api("GET", "/connections")
        except Exception:
            return None
        connections = data.get("connections") if isinstance(data, dict) else data
        if not isinstance(connections, list):
            return None
        host_l = host.lower()
        for item in reversed(connections):
            meta = (item or {}).get("metadata") or {}
            h = str(meta.get("host") or meta.get("sniffHost") or "").lower()
            dest = str(meta.get("destinationIP") or "")
            if h != host_l and dest != (ip or "") and host_l not in h:
                continue
            rule = str(item.get("rule") or meta.get("rule") or "")
            payload = str(item.get("rulePayload") or meta.get("rulePayload") or "")
            chains = item.get("chains") or []
            policy = str(chains[-1] if chains else item.get("chain") or "")
            policy = _normalize_policy(policy)
            return MatchResult(
                host=host,
                rule_index=-1,
                rule_text=rule or payload,
                policy=policy or "UNKNOWN",
                payload=payload or None,
                source="mihomo",
            )
        return None

    def _match_from_log(self, host: str) -> MatchResult | None:
        if not self.log_path.is_file():
            return None
        text = self.log_path.read_text(encoding="utf-8", errors="replace")
        host_l = host.lower().rstrip(".")
        for line in reversed(text.splitlines()):
            m = _LOG_MATCH.search(line)
            if not m:
                continue
            if m.group("host").lower().rstrip(".") != host_l:
                continue
            return MatchResult(
                host=host,
                rule_index=-1,
                rule_text=m.group("rule").strip(),
                policy=_normalize_policy(m.group("policy")),
                source="mihomo",
            )
        return None

    def _api(self, method: str, path: str) -> dict:
        url = f"http://127.0.0.1:{self.api_port}{path}"
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self.secret}")
        with urllib.request.urlopen(req, timeout=2) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        if not raw:
            return {}
        return json.loads(raw)


def build_harness_config(
    *,
    harness: dict,
    provider_files: dict[str, dict],
    mixed_port: int,
    api_port: int,
    secret: str,
    workdir: Path,
    dns: dict | None = None,
) -> Path:
    """provider_files: name -> {path, behavior, format} relative to workdir."""
    groups = []
    reserved = {"DIRECT", "REJECT", "PASS", "COMPATIBLE"}
    for name in harness.get("policies") or []:
        if str(name).upper() in reserved:
            continue
        groups.append({"name": name, "type": "select", "proxies": ["REJECT", "DIRECT"]})
    providers = {}
    for name, spec in provider_files.items():
        providers[name] = {
            "type": "file",
            "behavior": spec.get("behavior") or "domain",
            "format": spec.get("format") or "text",
            "path": spec["path"],
        }
    cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": secret,
        "unified-delay": True,
        "dns": dns
        or {
            "enable": False,
            "ipv6": False,
        },
        "proxy-groups": groups,
        "rule-providers": providers,
        "rules": list(harness.get("rules") or []),
    }
    path = workdir / "harness.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def probe_match_api(oracle: MihomoOracle) -> str:
    """Return SUPPORTED / NOT DIRECTLY SUPPORTED / UNKNOWN."""
    for path in ("/match", "/debug/match", "/rules/match"):
        try:
            oracle._api("GET", path)
            return f"SUPPORTED:{path}"
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                return f"SUPPORTED:{path}"
            continue
        except Exception:
            continue
        try:
            url = f"http://127.0.0.1:{oracle.api_port}{path}"
            req = urllib.request.Request(url, data=b'{"host":"example.com"}', method="POST")
            req.add_header("Authorization", f"Bearer {oracle.secret}")
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=2)
            return f"SUPPORTED:POST {path}"
        except Exception:
            continue
    return "NOT DIRECTLY SUPPORTED"
