"""Pair deployed MRS with readable txt only when MRS bytes match one immutable commit."""
from __future__ import annotations

from dataclasses import dataclass, field

from .upstream import sha256_bytes


@dataclass
class PairResult:
    name: str
    status: str  # paired | unverified | missing_txt | commit_mismatch
    commit: str = ""
    mrs_sha256: str = ""
    source_sha256: str = ""
    txt_bytes: bytes | None = None
    reason: str = ""


def pair_readable(
    *,
    name: str,
    deployed_mrs: bytes,
    upstream_mrs: bytes,
    upstream_txt: bytes | None,
    commit: str,
    mrs_commit: str | None = None,
    txt_commit: str | None = None,
) -> PairResult:
    if mrs_commit and txt_commit and mrs_commit != txt_commit:
        return PairResult(
            name=name,
            status="commit_mismatch",
            commit=commit,
            mrs_sha256=sha256_bytes(deployed_mrs),
            reason="source and MRS fetched from different upstream commits",
        )
    dep = sha256_bytes(deployed_mrs)
    up = sha256_bytes(upstream_mrs)
    if dep != up:
        return PairResult(
            name=name,
            status="unverified",
            commit=commit,
            mrs_sha256=dep,
            reason="BOOTSTRAP_UNVERIFIED: deployed MRS != upstream@commit MRS",
        )
    if not upstream_txt:
        return PairResult(
            name=name,
            status="missing_txt",
            commit=commit,
            mrs_sha256=dep,
            reason="no readable txt at this commit",
        )
    return PairResult(
        name=name,
        status="paired",
        commit=commit,
        mrs_sha256=dep,
        source_sha256=sha256_bytes(upstream_txt),
        txt_bytes=upstream_txt,
    )
