"""Fetch upstream files by immutable git SHA. Never mix branch-HEAD downloads."""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

GITHUB_API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"


class UpstreamError(RuntimeError):
    pass


def infer_upstream(url: str) -> dict | None:
    """Parse a raw.githubusercontent.com URL into repo + git path (no ref)."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.netloc not in {"raw.githubusercontent.com", "github.com"}:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    # raw.githubusercontent.com/{owner}/{repo}/{ref}/{path...}
    if parsed.netloc == "raw.githubusercontent.com" and len(parts) >= 4:
        owner, repo, _ref, *rest = parts
        git_path = "/".join(rest)
        txt_path = git_path
        if git_path.endswith(".mrs"):
            txt_path = git_path[:-4] + ".txt"
        return {
            "repo": f"{owner}/{repo}",
            "mrs_path": git_path,
            "txt_path": txt_path,
            "ref_in_url": _ref,
        }
    return None


def commit_raw_url(repo: str, sha: str, path: str) -> str:
    if sha in {"main", "master", "release", "HEAD"} or "/" in sha:
        raise UpstreamError(f"refusing mutable ref in raw URL: {sha}")
    if len(sha) < 12:
        raise UpstreamError(f"commit SHA too short: {sha}")
    return f"{RAW}/{repo}/{sha}/{path.lstrip('/')}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class GitHubClient:
    opener: urllib.request.OpenerDirector | None = None
    user_agent: str = "MIHOMO-YAMLS-audit/1.0"

    def _open(self, url: str, timeout: int = 60):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/vnd.github+json",
            },
        )
        opener = self.opener or urllib.request.build_opener()
        return opener.open(req, timeout=timeout)

    def resolve_commit(self, repo: str, ref: str) -> str:
        url = f"{GITHUB_API}/repos/{repo}/commits/{ref}"
        with self._open(url, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        sha = str(data.get("sha") or "")
        if len(sha) < 12:
            raise UpstreamError(f"cannot resolve {repo}@{ref}")
        return sha

    def fetch(self, repo: str, sha: str, path: str) -> bytes:
        url = commit_raw_url(repo, sha, path)
        with self._open(url, timeout=60) as resp:
            return resp.read()


def same_commit(sha_a: str, sha_b: str) -> bool:
    if not sha_a or not sha_b:
        return False
    n = min(len(sha_a), len(sha_b), 40)
    return sha_a[:n].lower() == sha_b[:n].lower() and n >= 12
