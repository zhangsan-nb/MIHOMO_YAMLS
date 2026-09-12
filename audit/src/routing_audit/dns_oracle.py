"""Isolated fake-ip vs real-ip DNS oracle. No proxy subscriptions."""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
import threading
from dataclasses import dataclass


FAKE_NET = ipaddress.ip_network("198.18.0.0/16")
DUMMY_A = "9.9.9.9"


@dataclass
class DnsLookup:
    host: str
    kind: str  # FAKE_IP | REAL_IP | ERROR
    address: str = ""


class DummyDns:
    """UDP DNS that answers A=9.9.9.9 for every query."""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.port = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, 0))
        sock.settimeout(0.3)
        self.port = sock.getsockname()[1]
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=1)

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                break
            if len(data) < 12:
                continue
            try:
                self._sock.sendto(_answer_a(data, DUMMY_A), addr)
            except OSError:
                break


def _answer_a(query: bytes, ip: str) -> bytes:
    tid = query[:2]
    # copy question, add one A answer
    header = tid + b"\x81\x80" + query[4:6] + b"\x00\x01" + b"\x00\x00\x00\x00"
    # question starts at 12
    qend = 12
    while qend < len(query) and query[qend] != 0:
        qend += query[qend] + 1
    qend += 5  # zero + type + class
    question = query[12:qend]
    rr = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack("!I", 30) + b"\x00\x04"
    rr += socket.inet_aton(ip)
    return header + question + rr


def build_query(name: str) -> bytes:
    tid = random.randint(0, 65535).to_bytes(2, "big")
    header = tid + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    body = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna")
        body += bytes([len(raw)]) + raw
    body += b"\x00\x00\x01\x00\x01"
    return header + body


def parse_a_records(resp: bytes) -> list[str]:
    if len(resp) < 12:
        return []
    qd = int.from_bytes(resp[4:6], "big")
    an = int.from_bytes(resp[6:8], "big")
    i = 12
    for _ in range(qd):
        while i < len(resp) and resp[i] != 0:
            if resp[i] & 0xC0 == 0xC0:
                i += 2
                break
            i += resp[i] + 1
        else:
            i += 1
        i += 4
    out: list[str] = []
    for _ in range(an):
        if i + 12 > len(resp):
            break
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(resp) and resp[i] != 0:
                i += resp[i] + 1
            i += 1
        typ = int.from_bytes(resp[i : i + 2], "big")
        i += 8
        rdlen = int.from_bytes(resp[i : i + 2], "big")
        i += 2
        rdata = resp[i : i + rdlen]
        i += rdlen
        if typ == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rdata))
    return out


def classify_ip(ip: str, fake_net: ipaddress.IPv4Network | None = None) -> str:
    net = fake_net or FAKE_NET
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "ERROR"
    if addr in net:
        return "FAKE_IP"
    return "REAL_IP"


def lookup(name: str, server: str, port: int, timeout: float = 1.5) -> DnsLookup:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(name), (server, port))
        resp, _ = sock.recvfrom(512)
    except OSError:
        return DnsLookup(host=name, kind="ERROR")
    finally:
        sock.close()
    addrs = parse_a_records(resp)
    if not addrs:
        return DnsLookup(host=name, kind="ERROR")
    kind = classify_ip(addrs[0])
    return DnsLookup(host=name, kind=kind, address=addrs[0])


def evaluate_dns(
    *,
    old: DnsLookup,
    new: DnsLookup,
    must_real_ip: list[str],
    must_fake_ip: list[str],
) -> str:
    """PASS | FAIL | REVIEW"""
    host = new.host.lower().rstrip(".")
    if new.kind == "ERROR":
        return "FAIL"
    if host in {h.lower().rstrip(".") for h in must_real_ip} and new.kind != "REAL_IP":
        return "FAIL"
    if host in {h.lower().rstrip(".") for h in must_fake_ip} and new.kind != "FAKE_IP":
        return "FAIL"
    if old.kind != new.kind:
        return "REVIEW"
    return "PASS"
