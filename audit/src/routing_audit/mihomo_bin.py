from __future__ import annotations

import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PINNED = "v1.19.15"
RELEASE = "https://github.com/MetaCubeX/mihomo/releases/download"


def pinned_version() -> str:
    return os.environ.get("MIHOMO_VERSION", PINNED)


def find_mihomo(cache_dir: Path | None = None) -> Path | None:
    env = os.environ.get("MIHOMO_BIN")
    if env:
        path = Path(env)
        if path.is_file():
            return path
    for name in ("mihomo", "mihomo.exe", "clash-meta", "clash-meta.exe"):
        found = shutil.which(name)
        if found:
            return Path(found)
    if cache_dir and cache_dir.is_dir():
        for cand in cache_dir.glob("mihomo*.exe"):
            return cand
        for cand in cache_dir.glob("mihomo"):
            if cand.is_file():
                return cand
    return None


def _asset_name(version: str) -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "amd64"
    if machine in {"arm64", "aarch64"}:
        arch = "arm64"
    if system.startswith("win"):
        return f"mihomo-windows-{arch}-compatible-{version}.zip", "zip"
    if system == "darwin":
        return f"mihomo-darwin-{arch}-compatible-{version}.gz", "gz"
    return f"mihomo-linux-{arch}-compatible-{version}.gz", "gz"


def download_mihomo(cache_dir: Path, version: str | None = None, pin: dict | None = None) -> Path:
    version = version or pinned_version()
    cache_dir.mkdir(parents=True, exist_ok=True)
    existing = find_mihomo(cache_dir)
    if existing:
        return existing
    asset, kind = _asset_name(version)
    url = f"{RELEASE}/{version}/{asset}"
    dest = cache_dir / asset
    if not dest.is_file():
        _fetch(url, dest)
    expected = None
    if pin:
        for spec in (pin.get("assets") or {}).values():
            if spec.get("file") == asset:
                expected = spec.get("sha256")
    if expected:
        import hashlib

        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if digest != expected:
            dest.unlink(missing_ok=True)
            raise RuntimeError(f"mihomo asset sha256 mismatch for {asset}")

    if kind == "zip":
        with zipfile.ZipFile(dest) as zf:
            zf.extractall(cache_dir)
        for cand in cache_dir.glob("mihomo*.exe"):
            return cand
        for cand in cache_dir.glob("*.exe"):
            return cand
    else:
        out = cache_dir / "mihomo"
        # .gz of a single binary, or a tar.gz
        if tarfile.is_tarfile(dest):
            with tarfile.open(dest) as tf:
                tf.extractall(cache_dir)
        else:
            import gzip

            with gzip.open(dest, "rb") as src, out.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        if out.is_file():
            out.chmod(out.stat().st_mode | stat.S_IEXEC)
            return out
        for cand in cache_dir.glob("mihomo*"):
            if cand.is_file() and cand.suffix not in {".gz", ".zip", ".sha256sum"}:
                cand.chmod(cand.stat().st_mode | stat.S_IEXEC)
                return cand
    raise FileNotFoundError(f"mihomo binary missing after extracting {dest}")


def _fetch(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "MIHOMO-YAMLS-audit/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as handle:
        shutil.copyfileobj(resp, handle)
