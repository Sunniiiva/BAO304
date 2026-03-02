from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from pydriller import Repository
from src.repo.utils import _repo_dir_name

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def crawl_repo_for_cve(
    repo_url: str,
    cve_id: str,
    *,
    branch: Optional[str] = None,
    max_commits: int = 20000,
) -> list[dict]:
    """
    Crawl EN repository history og returner commit 'headers' som nevner gitt CVE ID.
    Output dict matcher hva main.py forventer: commit_hash, commit_message, author, date, repo_url.
    """
    if not repo_url:
        raise ValueError("repo_url must be set")
    if not cve_id:
        raise ValueError("cve_id must be set")

    cve_id = cve_id.upper()

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    kwargs = {
        "path_to_repo": repo_url,
        "clone_repo_to": str(repo_dir),
    }
    if branch:
        kwargs["only_in_branch"] = branch

    repo = Repository(**kwargs)

    out: list[dict] = []
    count = 0

    for commit in repo.traverse_commits():
        count += 1
        if count > max_commits:
            break

        msg = commit.msg or ""
        mentioned = {m.upper() for m in CVE_RE.findall(msg)}
        if cve_id in mentioned:
            out.append(
                {
                    "commit_hash": commit.hash,
                    "commit_message": msg,
                    "author": commit.author.name if commit.author else "unknown",
                    "date": str(commit.committer_date) if commit.committer_date else "",
                    "repo_url": repo_url,
                    "mentioned_cves": sorted(mentioned),
                    "mentions_target_cve": True,
                    "discovery_method": "repo_history_message_regex",
                }
            )

    return out