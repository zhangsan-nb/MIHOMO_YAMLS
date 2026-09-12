from __future__ import annotations

from pathlib import Path

import yaml

from .models import ProviderSnapshot, TrustMode
from .ruleset import parse_ruleset_text


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected mapping in {path}")
    return data


def load_providers_catalog(audit_dir: Path) -> list[dict]:
    data = load_yaml(audit_dir / "providers.yaml")
    return list(data.get("providers") or [])


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_trust(*, artifact_format: str, readable_text: str | None, decoded_mrs: bool) -> tuple[TrustMode, str]:
    """Trust comes from readable source, never from unverified MRS decode."""
    fmt = (artifact_format or "").lower()
    has_readable = bool(readable_text and readable_text.strip())
    if fmt in {"text", "yaml", "list", "txt"} and has_readable:
        return "A", "AVAILABLE"
    if fmt == "mrs" and has_readable:
        return "B", "AVAILABLE"
    if decoded_mrs and not has_readable:
        # Optional decode must not upgrade trust or invent MODE A/B.
        return "C", "UNAVAILABLE"
    return "C", "UNAVAILABLE"


def snapshot_provider(
    spec: dict,
    root: Path,
    *,
    readable_text: str | None = None,
) -> ProviderSnapshot:
    path = root / spec["path"]
    present = path.is_file()
    digest = sha256_file(path) if present else ""
    size = path.stat().st_size if present else 0
    readable = readable_text
    source_path = spec.get("source_path") or ""
    if readable is None and source_path:
        src = root / source_path
        if src.is_file() and src.suffix.lower() != ".mrs":
            readable = src.read_text(encoding="utf-8", errors="replace")
    if readable is None and path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".list", ".txt"}:
        readable = path.read_text(encoding="utf-8", errors="replace")

    rules = None
    entry_count = None
    load_error = None if present else "missing artifact"
    if readable:
        try:
            parsed = parse_ruleset_text(
                readable,
                behavior=spec.get("behavior") or "domain",
                format_hint=spec.get("format") or "",
            )
            rules = tuple(parsed)
            entry_count = len(parsed)
        except Exception as exc:  # noqa: BLE001 — surface parser faults as load errors
            load_error = f"readable parse failed: {exc}"

    trust, semantic = classify_trust(
        artifact_format=spec.get("format") or path.suffix.lstrip("."),
        readable_text=readable,
        decoded_mrs=False,
    )
    readable_sha = None
    if readable is not None:
        import hashlib

        readable_sha = hashlib.sha256(readable.encode("utf-8", errors="replace")).hexdigest()

    return ProviderSnapshot(
        name=spec["name"],
        path=spec["path"],
        behavior=spec.get("behavior") or "domain",
        format=spec.get("format") or path.suffix.lstrip("."),
        sha256=digest,
        size=size,
        trust_mode=trust,
        semantic_diff=semantic,
        entry_count=entry_count,
        rules=rules,
        readable_sha256=readable_sha,
        present=present,
        load_error=load_error,
    )


def fingerprint_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
