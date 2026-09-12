from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from .models import Rule

CRITICAL_TLDS_DEFAULT = {
    "com", "net", "org", "cn", "info", "xyz", "top", "io", "co", "cc", "me",
    "tv", "app", "dev", "edu", "gov", "uk", "jp", "kr", "ru", "de", "fr",
    "us", "br", "in", "au",
}


def semantic_diff(old: Iterable[Rule] | None, new: Iterable[Rule] | None) -> dict:
    if old is None or new is None:
        return {
            "available": False,
            "added": [],
            "removed": [],
            "unchanged": 0,
        }
    old_map = {r.key(): r for r in old}
    new_map = {r.key(): r for r in new}
    added = [new_map[k] for k in new_map.keys() - old_map.keys()]
    removed = [old_map[k] for k in old_map.keys() - new_map.keys()]
    return {
        "available": True,
        "added": added,
        "removed": removed,
        "unchanged": len(old_map.keys() & new_map.keys()),
    }


def blast_radius(rule: Rule, critical_tlds: Iterable[str] | None = None) -> str:
    tlds = set(critical_tlds or CRITICAL_TLDS_DEFAULT)
    if rule.kind == "DOMAIN-KEYWORD":
        if rule.value in {"", "*", ".", "com", "net", "org", "cn"}:
            return "CRITICAL"
        return "MEDIUM"
    if rule.kind in {"DOMAIN-SUFFIX", "DOMAIN"}:
        labels = [p for p in rule.value.split(".") if p]
        if not labels or rule.value in {"*", "+"}:
            return "CRITICAL"
        if len(labels) == 1 and labels[0].lower() in tlds:
            return "CRITICAL"
        if len(labels) == 1:
            return "CRITICAL"
        if rule.kind == "DOMAIN-SUFFIX" and len(labels) == 2:
            return "MEDIUM"
        return "LOW"
    if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
        try:
            net = ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return "MEDIUM"
        if net.version == 4 and net.prefixlen <= 8:
            return "CRITICAL"
        if net.version == 4 and net.prefixlen <= 12:
            return "HIGH"
        if net.version == 6 and net.prefixlen <= 32:
            return "CRITICAL"
        if net.num_addresses >= 65536:
            return "HIGH"
        return "LOW"
    if rule.value in {"*", "+.com", "+.net", "+.org", "+.cn"}:
        return "CRITICAL"
    return "LOW"


def generate_witnesses(rule: Rule, limit: int = 6) -> list[str]:
    if rule.kind == "DOMAIN":
        return [rule.value]
    if rule.kind == "DOMAIN-SUFFIX":
        root = rule.value
        return [root, f"www.{root}", f"api.{root}", f"x.test.{root}"][:limit]
    if rule.kind == "DOMAIN-KEYWORD":
        kw = rule.value
        return [f"{kw}.example.test", f"www.{kw}.com", f"{kw}cdn.net"][:limit]
    if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
        try:
            net = ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return []
        hosts: list[str] = []
        if net.num_addresses == 1:
            return [str(net.network_address)]
        hosts.append(str(net.network_address + (1 if net.num_addresses > 1 else 0)))
        mid = int(net.network_address) + max(net.num_addresses // 2, 1)
        try:
            hosts.append(str(ipaddress.ip_address(mid)))
        except ValueError:
            pass
        last = net.broadcast_address if net.version == 4 else net.network_address + (net.num_addresses - 2)
        hosts.append(str(last))
        # unique, still in net
        out = []
        for h in hosts:
            try:
                if ipaddress.ip_address(h) in net and h not in out:
                    out.append(h)
            except ValueError:
                continue
        return out[:limit]
    return []
