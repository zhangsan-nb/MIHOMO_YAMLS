"""Optional MRS decode vs readable txt. Decode is never the trust upgrade."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .ruleset import parse_ruleset_text


def normalize_rule_keys(text: str, *, behavior: str) -> set[tuple[str, str]]:
    return {r.key() for r in parse_ruleset_text(text, behavior=behavior)}


def optional_decode_mrs(
    binary: Path,
    mrs_path: Path,
    dest: Path,
    *,
    behavior: str = "domain",
) -> str | None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [str(binary), "convert-ruleset", behavior, "mrs", str(mrs_path), str(dest)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return None
    if proc.returncode != 0 or not dest.is_file() or dest.stat().st_size == 0:
        return None
    return dest.read_text(encoding="utf-8", errors="replace")


def compare_source_and_decoded(
    txt: str,
    decoded: str | None,
    *,
    behavior: str,
) -> str:
    """equal | mismatch | decode_unavailable"""
    if decoded is None:
        return "decode_unavailable"
    if normalize_rule_keys(txt, behavior=behavior) != normalize_rule_keys(decoded, behavior=behavior):
        return "mismatch"
    return "equal"


def source_mrs_lockstep(
    *,
    mrs_changed: bool,
    txt_changed: bool,
    has_both: bool,
) -> str | None:
    """Return SOURCE_MRS_INCONSISTENT if one side moved without the other."""
    if not has_both:
        return None
    if mrs_changed != txt_changed:
        return "SOURCE_MRS_INCONSISTENT"
    return None
