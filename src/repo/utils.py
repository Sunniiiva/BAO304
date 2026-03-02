# Felles funksjoner (hindrer circular imports mellom moduler)
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydriller import Repository


# Felles funksjoner for parsing av repo-URL-er og commit-data
def extract_repo_url_from_github(any_github_url: str) -> str | None:
    """
    Extract base repo URL from any GitHub URL:
    https://github.com/owner/repo/anything -> https://github.com/owner/repo
    """
    if not any_github_url:
        return None

    # Handle markdown [text](url)
    if "(" in any_github_url and ")" in any_github_url:
        any_github_url = any_github_url.split("(", 1)[-1].split(")", 1)[0]

    parsed = urlparse(any_github_url)
    if not parsed.netloc or "github.com" not in parsed.netloc.lower():
        return None

    parts = [p for p in (parsed.path or "").strip("/").split("/") if p]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]
    return f"https://github.com/{owner}/{repo}"


def extract_repo_and_hash(commit_url: str) -> dict[str, str] | None:
    """Ekstraher repo URL og commit hash fra GitHub commit URL."""
    if not commit_url:
        return None

    # Håndterer markdown [text](url)
    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(", 1)[-1].split(")", 1)[0]

    parsed = urlparse(commit_url)
    clean_path = (parsed.path or "").strip("/")
    parts = [p for p in clean_path.split("/") if p]

    # /owner/repo/commit/<hash>
    if parsed.netloc.lower().endswith("github.com"):
        if len(parts) >= 4 and parts[2].lower() == "commit":
            owner, repo, commit_hash = parts[0], parts[1], parts[3]
            return {"repo_url": f"https://github.com/{owner}/{repo}", "commit_hash": commit_hash}

    return None


def fetch_commit_data(repo_url: str, commit_hash: str) -> dict[str, Any]:
    """Hent commit data med pydriller - robust versjon."""
    try:
        repo = Repository(repo_url)
        commit = None

        for c in repo.traverse_commits():
            if c.hash == commit_hash:
                commit = c
                break

        if not commit:
            return {"error": f"Commit {commit_hash} ikke funnet i {repo_url}"}

        files_data: list[dict[str, Any]] = []
        for file in commit.modified_files:
            try:
                diff_text = str(file.diff) if getattr(file, "diff", None) else ""

                # Stats (sikker tilgang)
                added = 0
                deleted = 0
                ds = getattr(file, "diff_stats", None)
                if ds is not None:
                    added = getattr(ds, "additions", 0) or 0
                    deleted = getattr(ds, "deletions", 0) or 0

                files_data.append(
                    {
                        "file_path": file.new_path or file.old_path or "unknown",
                        "change_type": str(file.change_type) if hasattr(file, "change_type") else "unknown",
                        "patch_text": diff_text,
                        "lines_added": added,
                        "lines_deleted": deleted,
                    }
                )
            except Exception as file_err:
                files_data.append(
                    {
                        "file_path": file.new_path or file.old_path or "unknown",
                        "change_type": "unknown",
                        "patch_text": "",
                        "lines_added": 0,
                        "lines_deleted": 0,
                        "error": str(file_err),
                    }
                )

        return {
            "commit_hash": commit.hash,
            "commit_message": commit.msg,
            "author": commit.author.name if commit.author else "unknown",
            "date": str(commit.committer_date) if commit.committer_date else "",
            "repo_url": repo_url,
            "modified_files": files_data,
        }

    except Exception as e:
        return {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {str(e)}"}


def _repo_dir_name(repo_url: str) -> str:
    """
    Lager et stabilt og lesbart mappenavn basert på repo_url.

    Eksempel:
      https://github.com/kpdecker/jsdiff -> kpdecker_jsdiff
    """
    p = urlparse(repo_url)
    parts = [x for x in p.path.strip("/").split("/") if x]
    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"
    return parts[-1] if parts else "repo"


def fetch_commit_modified_files(repo_url: str, commit_sha: str) -> list[dict[str, Any]]:
    """
    Hent alle modified files for en commit, men returner KUN patch/diff + filsti.

    Viktig:
    - Returnerer IKKE hele filinnholdet (before/after), fordi det gir enorm output/DB-størrelse.
    - before/after (endrede linjer) skal bygges fra parse_patch(patch_text).
    """
    if not repo_url:
        raise ValueError("repo_url må settes")
    if not commit_sha:
        raise ValueError("commit_sha må settes")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),
        single=commit_sha,
    )

    out: list[dict[str, Any]] = []
    for c in repo.traverse_commits():
        for mf in c.modified_files:
            file_path = mf.new_path or mf.old_path or ""
            patch_text = getattr(mf, "diff", None) or ""
            patch_text = str(patch_text)  # sørg for ren tekst

            # Stats (valgfritt, men ofte nyttig)
            added = 0
            deleted = 0
            ds = getattr(mf, "diff_stats", None)
            if ds is not None:
                added = getattr(ds, "additions", 0) or 0
                deleted = getattr(ds, "deletions", 0) or 0

            out.append(
                {
                    "file_path": file_path,
                    "patch_text": patch_text,
                    "lines_added": added,
                    "lines_deleted": deleted,
                    "change_type": str(getattr(mf, "change_type", "unknown")),
                }
            )

    return out
