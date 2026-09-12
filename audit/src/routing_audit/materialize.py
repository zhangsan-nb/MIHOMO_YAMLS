"""Pin 666OS files to one commit and write .audit/ next to published rules."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .bootstrap import pair_readable
from .upstream import GitHubClient, infer_upstream, sha256_bytes


def materialize_paired_sources(
    *,
    specs: list[dict],
    baseline_dir: Path | None,
    candidate_dir: Path,
    client: GitHubClient | None = None,
    repo: str = "666OS/rules",
    ref: str = "release",
    commit: str | None = None,
    workers: int = 8,
) -> dict:
    client = client or GitHubClient()
    if commit is None:
        commit = client.resolve_commit(repo, ref)

    jobs = []
    for spec in specs:
        inferred = infer_upstream(spec.get("artifact_url") or spec.get("url") or "")
        if not inferred or inferred.get("repo") != repo:
            continue
        jobs.append((spec, inferred))

    def one(spec, inferred):
        mrs_path = inferred["mrs_path"]
        txt_path = inferred["txt_path"]
        mrs = client.fetch(repo, commit, mrs_path)
        try:
            txt = client.fetch(repo, commit, txt_path)
        except Exception:
            txt = None
        return spec, mrs, txt

    fetched: dict[str, tuple[dict, bytes, bytes | None]] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, spec, inf) for spec, inf in jobs]
        for fut in as_completed(futs):
            try:
                spec, mrs, txt = fut.result()
                fetched[spec["name"]] = (spec, mrs, txt)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

    audit_dir = candidate_dir / ".audit"
    src_dir = audit_dir / "sources"
    src_dir.mkdir(parents=True, exist_ok=True)

    paired = []
    unverified = []
    missing_txt = []
    commit_mismatch = []
    providers_meta = {}

    for name, (spec, up_mrs, up_txt) in fetched.items():
        deployed_path = candidate_dir / spec["path"]
        if not deployed_path.is_file():
            deployed_path.parent.mkdir(parents=True, exist_ok=True)
            deployed_path.write_bytes(up_mrs)
            deployed = up_mrs
        else:
            deployed = deployed_path.read_bytes()
        # Candidate must be the immutable commit artifact.
        if sha256_bytes(deployed) != sha256_bytes(up_mrs):
            deployed_path.write_bytes(up_mrs)
            deployed = up_mrs

        result = pair_readable(
            name=name,
            deployed_mrs=deployed,
            upstream_mrs=up_mrs,
            upstream_txt=up_txt,
            commit=commit,
            mrs_commit=commit,
            txt_commit=commit if up_txt is not None else None,
        )
        rel_txt = spec.get("source_path") or f"sources/{Path(spec['path']).stem}.txt"
        # store under .audit/sources mirroring domain/Direct.txt
        dest = src_dir / Path(spec["path"]).with_suffix(".txt").name
        # keep folder structure: domain/Direct.txt
        dest = src_dir / Path(spec["path"]).with_suffix(".txt")
        if result.status == "paired" and result.txt_bytes:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(result.txt_bytes)
            paired.append(name)
            spec_readable = dest
        elif result.status == "unverified":
            unverified.append(name)
        elif result.status == "missing_txt":
            missing_txt.append(name)
        elif result.status == "commit_mismatch":
            commit_mismatch.append(name)
        providers_meta[name] = {
            "status": result.status,
            "commit": commit,
            "mrs_sha256": result.mrs_sha256,
            "source_sha256": result.source_sha256,
            "behavior": spec.get("behavior"),
            "format": spec.get("format"),
            "path": spec["path"],
            "readable": str(dest.relative_to(candidate_dir)).replace("\\", "/")
            if result.status == "paired"
            else None,
        }

        # Baseline pairing: only attach txt if baseline MRS == this commit MRS.
        if baseline_dir is not None:
            base_mrs = baseline_dir / spec["path"]
            if base_mrs.is_file() and result.status == "paired" and result.txt_bytes:
                if sha256_bytes(base_mrs.read_bytes()) == sha256_bytes(up_mrs):
                    bdest = baseline_dir / ".audit" / "sources" / Path(spec["path"]).with_suffix(".txt")
                    bdest.parent.mkdir(parents=True, exist_ok=True)
                    bdest.write_bytes(result.txt_bytes)

    manifest = {
        "upstream_repo": repo,
        "upstream_ref": ref,
        "upstream_commit": commit,
        "paired": paired,
        "unverified": unverified,
        "missing_txt": missing_txt,
        "commit_mismatch": commit_mismatch,
        "fetch_errors": errors,
        "providers": providers_meta,
    }
    (audit_dir / "baseline.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def attach_readable_from_audit(root: Path, spec: dict) -> str | None:
    """Prefer .audit/sources next to the published MRS."""
    rel = Path(spec["path"]).with_suffix(".txt")
    for cand in (
        root / ".audit" / "sources" / rel,
        root / spec.get("source_path", ""),
    ):
        if cand and cand.is_file() and cand.suffix.lower() != ".mrs":
            return cand.read_text(encoding="utf-8", errors="replace")
    return None
