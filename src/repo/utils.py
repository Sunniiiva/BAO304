#---------------------------------------------------------------------
# Generelle hjelpefunksjoner for parsing av CVE-er, commits og patcher.
#---------------------------------------------------------------------

#Imports 
from __future__ import annotations

import gc
import hashlib
import os
import shutil
import stat
import subprocess
import threading
import time

from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydriller import Repository

# Cache for repo-tilgjengelighet så vi slipper å kjøre git ls-remote
# for samme repo tusenvis av ganger i samme kjøring.
_REPO_ACCESS_CACHE: dict[str, tuple[bool, str | None]] = {}
_REPO_ACCESS_LOCK = threading.Lock()


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


def _repo_dir_name(repo_url: str, commit_hash: str) -> str:
    """
    Lager et unikt mappenavn basert på en kort SHA256-hash av repo_url + commit_hash.
    Unik per commit slik at parallelle workers aldri kolliderer på samme mappe.
    Unngår også for lange stier på Windows (MAX_PATH = 260 tegn).
    """
    key = f"{repo_url}#{commit_hash}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]

@contextmanager
def _non_interactive_git_env():
    """
    Hindrer git fra å åpne login prompt / credential popup.
    Fungerer spesielt viktig på Windows.
    """
    old_env = os.environ.copy()

    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GCM_INTERACTIVE"] = "Never"
    os.environ["GIT_ASKPASS"] = "echo"

    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)

def _inject_token(repo_url: str) -> str:
    """
    Injiserer GITHUB_TOKEN fra miljøvariabel inn i GitHub-URL hvis tilgjengelig.
    Øker rate limit fra 60 til 5000 forespørsler per time.
    Tokenet settes som miljøvariabel og lagres aldri i kildekoden.

    Eksempel:
      GITHUB_TOKEN=ghp_abc123 python -m src.main ingest
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token and "github.com" in repo_url:
        return repo_url.replace("https://", f"https://{token}@")
    return repo_url


def _repo_is_accessible(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """
    Sjekker om repoet kan nås uten interaktiv autentisering.
    Returnerer (True, None) hvis tilgjengelig,
    ellers (False, feilmelding).
    """
    cmd = ["git", "ls-remote", _inject_token(repo_url), "HEAD"]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_ASKPASS"] = "echo"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        if result.returncode == 0:
            return True, None

        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        msg = stderr or stdout or "Ukjent git-feil"

        lowered = msg.lower()

        if any(x in lowered for x in [
            "could not read username",
            "authentication failed",
            "repository not found",
            "fatal: could not",
            "terminal prompts disabled",
            "support for password authentication was removed",
        ]):
            return False, f"Repo utilgjengelig eller privat: {msg}"

        return False, f"Repo ikke tilgjengelig: {msg}"

    except subprocess.TimeoutExpired:
        return False, "Timeout ved tilgangssjekk mot repo"
    except Exception as e:
        return False, f"Feil ved repo-sjekk: {e}"

def get_cached_repo_access(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """
    Returnerer cached resultat for repo-tilgjengelighet hvis tilgjengelig.
    Trådsikkert: bruker lock slik at flere workers ikke sjekker samme repo samtidig.
    """
    with _REPO_ACCESS_LOCK:
        cached = _REPO_ACCESS_CACHE.get(repo_url)
        if cached is not None:
            return cached

    result = _repo_is_accessible(repo_url, timeout=timeout)

    with _REPO_ACCESS_LOCK:
        _REPO_ACCESS_CACHE[repo_url] = result
    return result


def clear_repo_access_cache() -> None:
    """
    Tømmer cache for repo-tilgjengelighet.
    Praktisk ved testkjøringer eller hvis man vil starte helt rent.
    """
    _REPO_ACCESS_CACHE.clear()

def _extract_commit_data(commit, repo_url: str) -> dict:
    """
    Trekker ut all nødvendig data fra PyDriller-commitobjektet mens repoet
    fortsatt finnes på disk. Returnerer ren dict uten referanser til git-objekter.
    """
    files_data = []
    functions_data = []
    seen = set()

    for mf in commit.modified_files:
        file_path = mf.old_path or mf.new_path or "unknown"

        # --- patch-data ---
        try:
            diff_text = str(mf.diff) if getattr(mf, "diff", None) else ""
            if getattr(mf, "diff_stats", None):
                added = getattr(mf.diff_stats, "additions", 0)
                deleted = getattr(mf.diff_stats, "deletions", 0)
            else:
                added = 0
                deleted = 0

            files_data.append({
                "file_path": mf.new_path or mf.old_path or "unknown",
                "change_type": str(mf.change_type) if hasattr(mf, "change_type") else "unknown",
                "patch_text": diff_text,
                "lines_added": added,
                "lines_deleted": deleted,
            })
        except Exception as e:
            files_data.append({
                "file_path": mf.new_path or mf.old_path or "unknown",
                "change_type": "unknown",
                "patch_text": "",
                "lines_added": 0,
                "lines_deleted": 0,
                "error": str(e),
            })

        # --- funksjon-data ---
        if not mf.source_code_before or not mf.changed_methods:
            continue

        for changed_method in mf.changed_methods:
            # finn before-metode
            before_method = None
            for m in mf.methods_before:
                if m.name == changed_method.name:
                    before_method = m
                    break

            # finn after-metode
            after_method = None
            for m in mf.methods:
                if (m.name == changed_method.name
                        and m.start_line == changed_method.start_line
                        and m.end_line == changed_method.end_line):
                    after_method = m
                    break
            if not after_method:
                for m in mf.methods:
                    if m.name == changed_method.name:
                        after_method = m
                        break
            if not after_method:
                after_method = changed_method

            if not before_method and not after_method:
                continue

            method_obj = before_method or after_method
            key = (
                "combined", file_path, method_obj.name,
                before_method.start_line if before_method else None,
                before_method.end_line if before_method else None,
                after_method.start_line if after_method else None,
                after_method.end_line if after_method else None,
            )
            if key in seen:
                continue
            seen.add(key)

            def _extract(source, start, end):
                if not source or not start or not end:
                    return None
                lines = source.splitlines()
                if start > len(lines):
                    return None
                end = min(end, len(lines))
                code = "\n".join(lines[start - 1:end])
                return code if code.strip() else None

            vuln_code = _extract(
                mf.source_code_before,
                before_method.start_line if before_method else None,
                before_method.end_line if before_method else None,
            )
            patch_code = _extract(
                mf.source_code,
                after_method.start_line if after_method else None,
                after_method.end_line if after_method else None,
            )

            if not vuln_code and not patch_code:
                continue

            functions_data.append({
                "file_path": file_path,
                "method_name": method_obj.name,
                "vuln_start_line": before_method.start_line if before_method else None,
                "vuln_end_line": before_method.end_line if before_method else None,
                "vuln_function": vuln_code,
                "patched_start_line": after_method.start_line if after_method else None,
                "patched_end_line": after_method.end_line if after_method else None,
                "patch_function": patch_code,
            })

    return {
        "commit_hash": commit.hash,
        "commit_message": commit.msg,
        "author": commit.author.name if commit.author else "unknown",
        "date": str(commit.committer_date) if commit.committer_date else "",
        "repo_url": repo_url,
        "modified_files": files_data,
        "functions": functions_data,
    }


def _load_single_commit(repo_url: str, commit_hash: str):
    """
    Kloner repoet, trekker ut all nødvendig data mens repoet er på disk,
    og sletter det umiddelbart etter. Returnerer ren dict — ingen referanser
    til git-objekter som krever at repoet fortsatt finnes.
    """
    accessible, reason = get_cached_repo_access(repo_url)
    if not accessible:
        return {"error": reason, "skip_reason": "repo_inaccessible"}

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url, commit_hash)
    repo_dir.mkdir(parents=True, exist_ok=True)

    result = {"error": f"Commit {commit_hash} ikke funnet i {repo_url}", "skip_reason": "commit_not_found"}

    try:
        with _non_interactive_git_env():
            repo = Repository(
                _inject_token(repo_url),
                clone_repo_to=str(repo_dir),
                single=commit_hash,
            )

            for commit in repo.traverse_commits():
                if commit.hash == commit_hash:
                    # Trekk ut ALT mens repoet fortsatt er på disk
                    result = _extract_commit_data(commit, repo_url)
                    break

    except Exception as e:
        msg = str(e)
        lowered = msg.lower()

        if any(x in lowered for x in [
            "could not read username",
            "authentication failed",
            "repository not found",
            "terminal prompts disabled",
        ]):
            result = {"error": f"Privat/utilgjengelig repo: {msg}", "skip_reason": "repo_inaccessible"}
        else:
            result = {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {msg}", "skip_reason": "commit_fetch_failed"}

    finally:
        gc.collect()
        _rmtree_with_retries(repo_dir)

    return result

def load_single_commit(repo_url: str, commit_hash: str):
    """
    Offentlig wrapper rundt _load_single_commit, så resten av koden
    slipper å importere en intern hjelpefunksjon direkte.
    """
    return _load_single_commit(repo_url, commit_hash)


def _chmod_tree(path: Path) -> None:
    """
    Setter skrive-tillatelse rekursivt på alle filer og mapper i treet.
    Må gjøres før rmtree på Windows, siden git markerer mange filer som read-only.
    """
    for root, dirs, files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            except Exception:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass


def _rmtree_with_retries(path: Path, retries: int = 20, delay: float = 0.2) -> bool:
    """
    Setter skrive-tillatelse på hele treet før sletting, deretter retryer.
    Returnerer True hvis slettet (eller allerede borte), False hvis fortsatt låst.
    """
    for _ in range(retries):
        if not path.exists():
            return True
        try:
            _chmod_tree(path)
            shutil.rmtree(path)
            return True
        except (PermissionError, FileNotFoundError, OSError):
            time.sleep(delay)
    return not path.exists()


def cleanup_all_temp_repos():
    """
    Sletter temp_repos. På Windows kan filer være låst en kort stund (WinError 32),
    så vi retryer. Hvis det fortsatt er låst, kræsjer vi ikke ingest.
    """
    clear_repo_access_cache()
    
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