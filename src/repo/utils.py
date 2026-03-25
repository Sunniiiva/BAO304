#---------------------------------------------------------------------
# Generelle hjelpefunksjoner for parsing av CVE-er, commits og patcher.
#---------------------------------------------------------------------

#Imports 
from __future__ import annotations

import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydriller import Repository

#---------------------------------------------------------------------
# Funksjon for å parse Github commit-referanser fra CVE-data
#---------------------------------------------------------------------
def extract_repo_and_hash(commit_url: str):
    """
    Parser GitHub commit-URL og returnerer:
      {
        "repo_url": "https://github.com/owner/repo",
        "commit_hash": "<sha>"
      }

    Støtter:
    - Vanlig URL: https://github.com/owner/repo/commit/<hash>
    - Markdown:  [tekst](https://github.com/owner/repo/commit/<hash>)
    - Returnerer dict med 'repo_url' og 'commit_hash', eller None hvis parsing feiler.
    """
    if not commit_url or "github.com" not in commit_url:
        return None

    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(")[-1].split(")")[0]

    clean_url = (
        commit_url.replace("https://", "")
        .replace("http://", "")
        .split("?")[0]
        .split("#")[0]
    )

    parts = [p for p in clean_url.strip("/").split("/") if p]

    if len(parts) >= 5 and parts[0] == "github.com" and parts[3] == "commit":
        owner = parts[1]
        repo = parts[2]
        commit_hash = parts[4]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    if len(parts) >= 4 and parts[2] == "commit":
        owner = parts[0]
        repo = parts[1]
        commit_hash = parts[3]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    return None


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


def _load_single_commit(repo_url: str, commit_hash: str):
    """
    Traverserer nøyaktig én commit fra repoet.
    """
    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),
        single=commit_hash,
    )

    for commit in repo.traverse_commits():
        if commit.hash == commit_hash:
            return commit

    return None


def fetch_commit_metadata(repo_url: str, commit_hash: str):
    """
    Henter kun metadata for en commit.
    Dette er lettere enn å bygge full fil-/patch-struktur.
    """
    try:
        commit = _load_single_commit(repo_url, commit_hash)
        if not commit:
            return {"error": f"Commit {commit_hash} ikke funnet i {repo_url}"}

        return {
            "commit_hash": commit.hash,
            "commit_message": commit.msg,
            "author": commit.author.name if commit.author else "unknown",
            "date": str(commit.committer_date) if commit.committer_date else "",
            "repo_url": repo_url,
        }

    except Exception as e:
        return {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {str(e)}"}


def fetch_commit_bundle(repo_url: str, commit_hash: str):
    """
    Henter både commit metadata og endrede filer i én traversering.
    Brukes for optimalisert run-all.
    """
    try:
        commit = _load_single_commit(repo_url, commit_hash)
        if not commit:
            return {"error": f"Commit {commit_hash} ikke funnet i {repo_url}"}

        files_data: list[dict[str, Any]] = []

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


def fetch_commit_data(repo_url: str, commit_hash: str):
    """
    Beholder gammel funksjon for kompatibilitet.
    """
    return fetch_commit_bundle(repo_url, commit_hash)


def fetch_commit_modified_files(repo_url: str, commit_sha: str) -> list[dict[str, Any]]:
    """
    Henter detaljer om alle filer som er endret i én spesifikk commit.
    """
    bundle = fetch_commit_bundle(repo_url, commit_sha)
    if not bundle or "error" in bundle:
        raise RuntimeError(bundle.get("error", "Ukjent feil ved henting av commit-filer"))

    out: list[dict[str, Any]] = []
    for item in bundle.get("modified_files", []):
        out.append(
            {
                "file_path": item.get("file_path", ""),
                "patch_text": item.get("patch_text", ""),
            }
        )

    return out


def _handle_remove_readonly(func, path, exc_info):
    """
    Håndterer PermissionError ved sletting på Windows.
    """
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass

    try:
        func(path)
    except FileNotFoundError:
        return
    except PermissionError:
        raise


def _rmtree_with_retries(path: Path, retries: int = 20, delay: float = 0.2) -> bool:
    """
    Returnerer True hvis slettet (eller allerede borte), False hvis fortsatt låst etter retries.
    """
    for _ in range(retries):
        if not path.exists():
            return True
        try:
            shutil.rmtree(path, onerror=_handle_remove_readonly)
            return True
        except (PermissionError, FileNotFoundError, OSError):
            time.sleep(delay)
    return not path.exists()


def cleanup_all_temp_repos():
    """
    Sletter temp_repos. På Windows kan filer være låst en kort stund (WinError 32),
    så vi retryer. Hvis det fortsatt er låst, kræsjer vi ikke ingest.
    """
    clone_root = Path("temp_repos")
    if not clone_root.exists():
        return

    try:
        os.chdir(Path(__file__).resolve().parents[2])
    except Exception:
        pass

    ok = _rmtree_with_retries(clone_root, retries=25, delay=0.2)
    if ok:
        print("Alle temp_repos slettet!")
        return

    ts = int(time.time())
    stale = Path(f"temp_repos__stale_{ts}")
    try:
        clone_root.rename(stale)
        print(f"temp_repos var låst – flyttet til {stale} (kan slettes senere).")
    except Exception:
        print("temp_repos var låst og kunne ikke slettes – lar den ligge.")