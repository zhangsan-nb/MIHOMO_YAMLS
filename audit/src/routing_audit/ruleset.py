"""Parse readable rulesets. MRS bytes are never treated as a domain list."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .models import Rule

_COMMENT = re.compile(r"^\s*(#|//)")
_CLASSICAL = re.compile(
    r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|GEOSITE|IP-CIDR6|IP-CIDR|SRC-IP-CIDR|PROCESS-NAME|PROCESS-PATH|DST-PORT|SRC-PORT)"
    r"\s*,\s*([^,]+)",
    re.I,
)


def parse_ruleset_text(text: str, *, behavior: str = "domain", format_hint: str = "text") -> list[Rule]:
    if not text:
        return []
    stripped = text.lstrip()
    if stripped.lower().startswith("payload:") or "\npayload:" in text[:400].lower():
        return _parse_yaml_payload(text)
    rules: list[Rule] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or _COMMENT.match(line):
            continue
        if line in ("payload:", "payload: []"):
            continue
        if line.startswith("- "):
            line = line[2:].strip().strip("'\"")
        rule = _parse_line(line, behavior=behavior)
        if rule:
            rules.append(rule)
    return rules


def parse_ruleset_file(path: Path, *, behavior: str, format_hint: str) -> list[Rule]:
    suffix = path.suffix.lower()
    if suffix == ".mrs":
        raise ValueError("refusing to parse MRS as text")
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_ruleset_text(text, behavior=behavior, format_hint=format_hint or suffix.lstrip("."))


def _parse_yaml_payload(text: str) -> list[Rule]:
    rules: list[Rule] = []
    in_payload = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if _COMMENT.match(line.strip()):
            continue
        if re.match(r"^payload\s*:", line.strip()):
            in_payload = True
            continue
        if not in_payload:
            continue
        if line and not line.startswith((" ", "\t", "-")):
            break
        item = line.strip()
        if item.startswith("- "):
            item = item[2:].strip().strip("'\"")
        elif item.startswith("-"):
            item = item[1:].strip().strip("'\"")
        if not item:
            continue
        rule = _parse_line(item, behavior="classical")
        if rule:
            rules.append(rule)
    return rules


def _parse_line(line: str, *, behavior: str) -> Rule | None:
    line = line.strip().strip("'\"")
    if not line:
        return None
    m = _CLASSICAL.match(line)
    if m:
        kind = m.group(1).upper().replace("IP-CIDR6", "IP-CIDR6")
        value = m.group(2).strip().strip("'\"")
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            value = value.split(",", 1)[0].strip()
        return Rule(kind=kind, value=_norm_value(kind, value), raw=line)
    if behavior == "ipcidr" or _looks_cidr(line):
        cidr = line.split(",", 1)[0].strip()
        kind = "IP-CIDR6" if ":" in cidr else "IP-CIDR"
        return Rule(kind=kind, value=cidr, raw=line)
    if line.startswith("+."):
        return Rule(kind="DOMAIN-SUFFIX", value=_norm_host(line[2:]), raw=line)
    if line.startswith("."):
        return Rule(kind="DOMAIN-SUFFIX", value=_norm_host(line[1:]), raw=line)
    if line.startswith("*") and line.endswith("*") and len(line) > 2:
        return Rule(kind="DOMAIN-KEYWORD", value=line[1:-1].lower(), raw=line)
    if behavior == "classical":
        return Rule(kind="OTHER", value=line.lower(), raw=line)
    return Rule(kind="DOMAIN", value=_norm_host(line), raw=line)


def _norm_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _norm_value(kind: str, value: str) -> str:
    if kind.startswith("DOMAIN") or kind == "GEOSITE":
        return _norm_host(value)
    return value.strip()


def _looks_cidr(line: str) -> bool:
    token = line.split(",", 1)[0].strip()
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def rule_matches_host(rule: Rule, host: str) -> bool:
    host = _norm_host(host)
    if rule.kind == "DOMAIN":
        return host == rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return host == rule.value or host.endswith("." + rule.value)
    if rule.kind == "DOMAIN-KEYWORD":
        return rule.value in host
    return False


def rule_matches_ip(rule: Rule, ip: str) -> bool:
    if rule.kind not in {"IP-CIDR", "IP-CIDR6"}:
        return False
    try:
        network = ipaddress.ip_network(rule.value, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False
