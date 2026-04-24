#---------------------------------------------------------------------
# Generelle hjelpefunksjoner for parsing av CVE-er, commits og patcher.
#
# Støtter flere git-plattformer:
#   - GitHub     (github.com)
#   - GitLab     (gitlab.com)
#   - Bitbucket  (bitbucket.org)
#
# Designvalg (inspirert av CVEfixes):
#   Vi bruker én felles regex for å detektere plattform + parse
#   owner/repo/hash fra commit-URL-er. Selve kloningen og traverseringen
#   skjer med PyDriller/git, som er plattformuavhengig.
#---------------------------------------------------------------------

from __future__ import annotations

import gc
import hashlib
import os
import re
import shutil
import stat
import subprocess
import threading
import time

from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydriller import Repository

_REPO_ACCESS_CACHE: dict[str, tuple[bool, str | None]] = {}
_REPO_ACCESS_LOCK = threading.Lock()


#---------------------------------------------------------------------
# Plattform-konfigurasjon
#---------------------------------------------------------------------
SUPPORTED_PLATFORMS: dict[str, dict[str, Any]] = {
    "github": {
        "hosts": ("github.com",),
        "token_env": "GITHUB_TOKEN",
        "commit_segments": ("commit", "commits"),
    },
    "gitlab": {
        "hosts": ("gitlab.com",),
        "token_env": "GITLAB_TOKEN",
        "commit_segments": ("commit", "commits"),
    },
    "bitbucket": {
        "hosts": ("bitbucket.org",),
        "token_env": "BITBUCKET_TOKEN",
        "commit_segments": ("commits", "commit"),
    },
}

# Felles regex for alle tre plattformer (inspirert av CVEfixes).
_COMMIT_URL_REGEX = re.compile(
    r"https?://"
    r"(?P<host>github\.com|gitlab\.com|bitbucket\.org)/"
    r"(?P<owner>[^/\s]+)/"
    r"(?P<repo>[^/\s]+)"
    r"(?:/-)?"                       # GitLab kan ha "/-" før /commit/
    r"/(?:commit|commits)/"
    r"(?P<hash>[0-9a-fA-F]{7,40})",
    re.IGNORECASE,
)


def detect_platform(url: str) -> str | None:
    """
    Returnerer plattform-nøkkelen ("github" | "gitlab" | "bitbucket")
    for en gitt URL, eller None hvis den ikke er støttet.
    """
    if not url:
        return None
    lowered = url.lower()
    for platform, cfg in SUPPORTED_PLATFORMS.items():
        for host in cfg["hosts"]:
            if host in lowered:
                return platform
    return None


#---------------------------------------------------------------------
# Funksjon for å parse commit-referanser fra CVE-data
#---------------------------------------------------------------------
def extract_repo_and_hash(commit_url: str):
    """
    Parser commit-URL fra GitHub, GitLab eller Bitbucket og returnerer:
      {
        "repo_url":    "https://<host>/<owner>/<repo>",
        "commit_hash": "<sha>",
        "platform":    "github" | "gitlab" | "bitbucket"
      }

    Støtter:
    - GitHub:    https://github.com/owner/repo/commit/<hash>
    - GitLab:    https://gitlab.com/owner/repo/-/commit/<hash>
                 https://gitlab.com/owner/repo/commit/<hash>
    - Bitbucket: https://bitbucket.org/owner/repo/commits/<hash>
                 https://bitbucket.org/owner/repo/commit/<hash>
    - Markdown-wrappede URL-er: [tekst](https://...)
    """
    if not commit_url:
        return None

    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(")[-1].split(")")[0]

    cleaned = commit_url.split("?")[0].split("#")[0].strip()

    match = _COMMIT_URL_REGEX.search(cleaned)
    if not match:
        return None

    host = match.group("host").lower()
    owner = match.group("owner")
    repo = match.group("repo")
    commit_hash = match.group("hash")

    if repo.endswith(".git"):
        repo = repo[:-4]

    platform = detect_platform(host)
    if platform is None:
        return None

    return {
        "repo_url": f"https://{host}/{owner}/{repo}",
        "commit_hash": commit_hash,
        "platform": platform,
    }


def _repo_dir_name(repo_url: str, commit_hash: str) -> str:
    """Lager et unikt mappenavn basert på SHA256 av repo_url + commit_hash."""
    key = f"{repo_url}#{commit_hash}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@contextmanager
def _non_interactive_git_env():
    """Hindrer git fra å åpne login prompt / credential popup."""
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
    Injiserer riktig plattform-token fra miljøvariabel inn i repo-URL-en.

    Tokens per plattform:
      GITHUB_TOKEN     -> https://<token>@github.com/...
      GITLAB_TOKEN     -> https://oauth2:<token>@gitlab.com/...
      BITBUCKET_TOKEN  -> https://x-token-auth:<token>@bitbucket.org/...
                          (fallback: BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD)
    """
    platform = detect_platform(repo_url)
    if platform is None:
        return repo_url

    cfg = SUPPORTED_PLATFORMS[platform]
    token = os.environ.get(cfg["token_env"], "").strip()

    if not token:
        if platform == "bitbucket":
            user = os.environ.get("BITBUCKET_USERNAME", "").strip()
            app_pw = os.environ.get("BITBUCKET_APP_PASSWORD", "").strip()
            if user and app_pw:
                return repo_url.replace("https://", f"https://{user}:{app_pw}@")
        return repo_url

    if platform == "github":
        return repo_url.replace("https://", f"https://{token}@")
    elif platform == "gitlab":
        return repo_url.replace("https://", f"https://oauth2:{token}@")
    elif platform == "bitbucket":
        return repo_url.replace("https://", f"https://x-token-auth:{token}@")

    return repo_url


def _repo_is_accessible(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """Sjekker om repoet kan nås uten interaktiv autentisering."""
    cmd = ["git", "ls-remote", _inject_token(repo_url), "HEAD"]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_ASKPASS"] = "echo"

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env,
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
            "project not found",
            "access denied",
            "not enough permissions",
        ]):
            return False, f"Repo utilgjengelig eller privat: {msg}"

        return False, f"Repo ikke tilgjengelig: {msg}"

    except subprocess.TimeoutExpired:
        return False, "Timeout ved tilgangssjekk mot repo"
    except Exception as e:
        return False, f"Feil ved repo-sjekk: {e}"


def get_cached_repo_access(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """Returnerer cached resultat for repo-tilgjengelighet hvis tilgjengelig."""
    with _REPO_ACCESS_LOCK:
        cached = _REPO_ACCESS_CACHE.get(repo_url)
        if cached is not None:
            return cached

    result = _repo_is_accessible(repo_url, timeout=timeout)

    with _REPO_ACCESS_LOCK:
        _REPO_ACCESS_CACHE[repo_url] = result
    return result


def clear_repo_access_cache() -> None:
    """Tømmer cache for repo-tilgjengelighet."""
    _REPO_ACCESS_CACHE.clear()


def _extract_commit_data(commit, repo_url: str) -> dict:
    """Trekker ut all nødvendig data fra PyDriller-commitobjektet."""
    files_data = []
    functions_data = []
    seen = set()

    for mf in commit.modified_files:
        file_path = mf.old_path or mf.new_path or "unknown"

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

        if not mf.source_code_before or not mf.changed_methods:
            continue

        for changed_method in mf.changed_methods:
            before_method = None
            for m in mf.methods_before:
                if m.name == changed_method.name:
                    before_method = m
                    break

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
        "platform": detect_platform(repo_url),
        "modified_files": files_data,
        "functions": functions_data,
    }


def _load_single_commit(repo_url: str, commit_hash: str):
    """Kloner repoet, trekker ut data, sletter repoet etter. Fungerer for alle støttede plattformer."""
    if detect_platform(repo_url) is None:
        return {
            "error": f"Ustøttet git-plattform for {repo_url}",
            "skip_reason": "unsupported_platform",
        }

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
            "project not found",
            "access denied",
        ]):
            result = {"error": f"Privat/utilgjengelig repo: {msg}", "skip_reason": "repo_inaccessible"}
        else:
            result = {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {msg}", "skip_reason": "commit_fetch_failed"}

    finally:
        gc.collect()
        _rmtree_with_retries(repo_dir)

    return result


def load_single_commit(repo_url: str, commit_hash: str):
    """Offentlig wrapper rundt _load_single_commit."""
    return _load_single_commit(repo_url, commit_hash)


def _chmod_tree(path: Path) -> None:
    """Setter skrive-tillatelse rekursivt. Nødvendig før rmtree på Windows."""
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
    """Setter skrive-tillatelse, retryer rmtree. Returnerer True hvis slettet."""
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
    """Sletter temp_repos. Windows-trygg med retries."""
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