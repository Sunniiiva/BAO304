# Felles funksjoner (hindrer circular imports mellom moduler)
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydriller import Repository


def extract_repo_and_hash(commit_url: str):
    """
    Ekstraherer repo-URL og commit-hash fra en GitHub-commit-URL.

    Støtter:
    - Full URL:  https://github.com/owner/repo/commit/<hash>
    - Markdown:  [tekst](https://github.com/owner/repo/commit/<hash>)
    - Returnerer dict med 'repo_url' og 'commit_hash', eller None hvis parsing feiler.
    """
    if not commit_url or "github.com" not in commit_url:
        return None

    # Hvis URL-en er inne i markdown-lenke [tekst](url), plukk ut url-delen
    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(")[-1].split(")")[0]

    # Fjern protokoll, query-parametre og fragments
    clean_url = (
        commit_url.replace("https://", "")
        .replace("http://", "")
        .split("?")[0]
        .split("#")[0]
    )

    # Del opp på '/' og fjern tomme deler
    parts = [p for p in clean_url.strip("/").split("/") if p]

    # Format: github.com/<owner>/<repo>/commit/<hash>
    if len(parts) >= 5 and parts[0] == "github.com" and parts[3] == "commit":
        owner = parts[1]
        repo = parts[2]
        commit_hash = parts[4]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    # Format: <owner>/<repo>/commit/<hash>
    if len(parts) >= 4 and parts[2] == "commit":
        owner = parts[0]
        repo = parts[1]
        commit_hash = parts[3]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    return None


def fetch_commit_data(repo_url: str, commit_hash: str):
    """
    Henter metadata og filendringer for en gitt commit ved hjelp av PyDriller.

    Returnerer dict med commit-info og en liste over endrede filer.
    Ved feil returneres dict med 'error'.
    """
    try:
        repo = Repository(repo_url)
        commit = None

        # Finn commiten vi er ute etter
        for c in repo.traverse_commits():
            if c.hash == commit_hash:
                commit = c
                break

        if not commit:
            return {"error": f"Commit {commit_hash} ikke funnet i {repo_url}"}

        files_data = []
        for file in commit.modified_files:
            try:
                diff_text = str(file.diff) if getattr(file, "diff", None) else ""

                if getattr(file, "diff_stats", None):
                    added = getattr(file.diff_stats, "additions", 0)
                    deleted = getattr(file.diff_stats, "deletions", 0)
                else:
                    added = 0
                    deleted = 0

                files_data.append(
                    {
                        "file_path": file.new_path or file.old_path or "unknown",
                        "change_type": str(file.change_type)
                        if hasattr(file, "change_type")
                        else "unknown",
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
    Henter detaljer om alle filer som er endret i én spesifikk commit.

    Repoet klones til en lokal temp_repos/-mappe, i en egen undermappe per repo.

    Returnerer liste av:
      {
        "file_path": ...,
        "patch_text": ...,
        "before_code": ...,
        "after_code": ...
      }
    """
    if not repo_url:
        raise ValueError("repo_url må settes")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),  # Klon til vår mappe (ikke OS-temp)
        single=commit_sha,            # Begrenser til kun denne commiten
    )

    out: list[dict[str, Any]] = []
    for c in repo.traverse_commits():
        for mf in c.modified_files:
            file_path = mf.new_path or mf.old_path or ""
            patch_text = getattr(mf, "diff", None) or ""

            before_code = getattr(mf, "source_code_before", None)
            after_code = getattr(mf, "source_code", None)

            if before_code is None:
                before_code = getattr(mf, "content_before", None)
            if after_code is None:
                after_code = getattr(mf, "content", None)

            out.append(
                {
                    "file_path": file_path,
                    "patch_text": patch_text,
                    "before_code": before_code or "",
                    "after_code": after_code or "",
                }
            )

    return out


def _handle_remove_readonly(func, path, exc_info):
    """
    Håndterer PermissionError ved sletting på Windows.

    shutil.rmtree kaller denne hvis den møter en fil/mappe den ikke får slettet.
    Vi gjør path skrivbar (fjerner read-only) og prøver igjen.
    """
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    func(path)


def cleanup_all_temp_repos():
    """
    Sletter hele temp_repos/-mappen med alle undermapper.

    Bruker onerror-callback for å takle Windows-problemer med read-only .git-filer.
    """
    clone_root = Path("temp_repos")
    if clone_root.exists():
        shutil.rmtree(clone_root, onerror=_handle_remove_readonly)
        print("Alle temp_repos slettet!")
