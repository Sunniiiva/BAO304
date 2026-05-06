# ---------------------------------------------------------------------
# Commit loading: clones the repo, extracts commit data with PyDriller,
# and returns a structured dict.
# ---------------------------------------------------------------------

from __future__ import annotations

import gc
import os
import subprocess
import typer

from pathlib import Path

from pydriller import Repository

from src.utils.file_filter import should_skip_file
from src.utils.git_access import (
    _non_interactive_git_env,   # disables Git password prompts
    _inject_token,              # adds auth token to repo URL
    _rmtree_with_retries,       # robust folder deletion (handles Windows file locks)
    get_cached_repo_access,     # checks if a repo is reachable, with caching
)
from src.commit.method_matching import (
    _extract_code_block,
    _find_best_after_method,
    _find_best_before_method,
    _is_valid_method_name,
    _looks_like_function,
    _methods_match_well,
    _valid_line_range,
)

# Prosjektlokal temp-mappe 
_TEMP_ROOT = Path("temp_repos")


def _make_local_temp_dir() -> Path:
    """
    Oppretter en unik undermappe under temp_repos/ i prosjektkatalogen.
    """
    _TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    import uuid
    repo_dir = _TEMP_ROOT / f"cve_{uuid.uuid4().hex[:12]}"
    repo_dir.mkdir(parents=True, exist_ok=True)
    return repo_dir


def _shallow_clone(repo_url: str, commit_hash: str, target_dir: Path) -> bool:
    """
    Gjør en shallow clone med dybde 2 (nok til at PyDriller kan se
    source_code_before på foreldrecommiten) og sjekker ut kun én commit.

    Returnerer True hvis vellykket, False ellers.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_ASKPASS"] = "echo"

    authed_url = _inject_token(repo_url)

    try:
        # Steg 1: Init tomt repo
        subprocess.run(
            ["git", "init", str(target_dir)],
            capture_output=True, env=env, timeout=30, check=True,
        )

        # Steg 2: Legg til remote
        subprocess.run(
            ["git", "-C", str(target_dir), "remote", "add", "origin", authed_url],
            capture_output=True, env=env, timeout=30, check=True,
        )

        # Steg 3: Fetch kun den spesifikke commiten (shallow, dybde 2)
        # --depth=2 gir oss commiten OG forelderen → PyDriller kan diff'e
        result = subprocess.run(
            ["git", "-C", str(target_dir), "fetch",
             "--depth=2", "--no-tags",
             "origin", commit_hash],
            capture_output=True, env=env, timeout=120,
        )

        if result.returncode != 0:
            # Noen repos støtter ikke fetch av enkeltkommer direkte.
            # Fallback: shallow clone av HEAD med dybde 1 (gir ikke source_code_before,
            # men unngår full klon)
            result2 = subprocess.run(
                ["git", "-C", str(target_dir), "fetch",
                 "--depth=1", "--no-tags",
                 "origin", f"+{commit_hash}:refs/remotes/origin/target"],
                capture_output=True, env=env, timeout=120,
            )
            if result2.returncode != 0:
                return False

        # Steg 4: Checkout commiten
        subprocess.run(
            ["git", "-C", str(target_dir), "checkout", commit_hash],
            capture_output=True, env=env, timeout=60,
        )

        return True

    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False

def _full_clone(repo_url: str, target_dir: Path) -> bool:
    """
    Full clone uten depth-begrensning. Brukes som fallback når shallow feiler.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_ASKPASS"] = "echo"

    authed_url = _inject_token(repo_url)

    try:
        result = subprocess.run(
            ["git", "clone", "--no-tags", "--quiet", authed_url, str(target_dir)],
            capture_output=True, env=env, timeout=300,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def _extract_commit_data(commit, repo_url: str) -> dict:
    """
    Extract all needed data from the PyDriller commit object while the repo
    still exists on disk. Returns a plain dict with no references to git objects.
    """
    files_data = []
    functions_data = []
    # Used to deduplicate function rows within the same commit
    seen = set()

    for mf in commit.modified_files:
        # Use old_path first so renames still get a usable identifier
        file_path = mf.old_path or mf.new_path or "unknown"

        # Filter out test files / irrelevant files (lockfiles, generated code, etc.)
        if should_skip_file(file_path):
            continue

        # --- patch data ---
        try:
            # PyDriller exposes the unified diff as mf.diff
            diff_text = str(mf.diff) if getattr(mf, "diff", None) else ""
            # diff_stats may be missing on binary files or huge diffs
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
            # Don't lose the file just because metadata extraction failed —
            # store a stub row with the error so the caller can still see it
            files_data.append({
                "file_path": mf.new_path or mf.old_path or "unknown",
                "change_type": "unknown",
                "patch_text": "",
                "lines_added": 0,
                "lines_deleted": 0,
                "error": str(e),
            })

        # --- function data ---
        # Need both before/after source AND a list of changed methods to pair them up
        if not mf.source_code_before or not mf.source_code or not mf.changed_methods:
            continue

        for changed_method in mf.changed_methods:
            # Pair each changed method with its best match in the before/after method lists
            before_method = _find_best_before_method(changed_method, mf.methods_before)
            after_method = _find_best_after_method(changed_method, mf.methods)

            # Need both halves to build a vulnerable->patched pair
            if not before_method or not after_method:
                continue

            # Reject pairs that don't really look like the same function
            if not _methods_match_well(before_method, after_method):
                continue

            method_name = (before_method.name or after_method.name or "").strip()
            if not _is_valid_method_name(method_name):
                continue

            # Both line ranges must be valid before extracting code
            if not _valid_line_range(before_method.start_line, before_method.end_line):
                continue
            if not _valid_line_range(after_method.start_line, after_method.end_line):
                continue

            # Dedup key: same file + method + line ranges
            key = (
                "combined",
                file_path,
                method_name,
                before_method.start_line,
                before_method.end_line,
                after_method.start_line,
                after_method.end_line,
            )
            if key in seen:
                continue
            seen.add(key)

            # Extract the actual code text for vuln and patched versions
            vuln_code = _extract_code_block(
                mf.source_code_before,
                before_method.start_line,
                before_method.end_line,
            )
            patch_code = _extract_code_block(
                mf.source_code,
                after_method.start_line,
                after_method.end_line,
            )

            # Require a complete vulnerability -> patch pair (both must be present)
            if not vuln_code or not patch_code:
                continue

            # Reject code blocks that aren't real functions
            # (e.g. catch/else/finally blocks misidentified by the parser)
            if not _looks_like_function(vuln_code) or not _looks_like_function(patch_code):
                continue

            functions_data.append({
                "file_path": file_path,
                "method_name": method_name,
                "vuln_start_line": before_method.start_line,
                "vuln_end_line": before_method.end_line,
                "vuln_function": vuln_code,
                "patched_start_line": after_method.start_line,
                "patched_end_line": after_method.end_line,
                "patch_function": patch_code,
            })

    # ── Postprosessering: fjern bulk-refaktorering ──
    _BULK_THRESHOLD = 10
    same_len = [
        fn for fn in functions_data
        if len(fn["vuln_function"]) == len(fn["patch_function"])
    ]
    if len(same_len) > _BULK_THRESHOLD:
        # Keep only the rows where lengths actually differ
        functions_data = [
            fn for fn in functions_data
            if len(fn["vuln_function"]) != len(fn["patch_function"])
        ]

    # Return everything as a plain dict — no PyDriller objects survive past this point,
    # which means the temp repo can be safely deleted afterwards
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
 
    accessible, reason = get_cached_repo_access(repo_url)
    if not accessible:
        return {"error": reason, "skip_reason": "repo_inaccessible"}

    # Each call gets its own temp folder so parallel workers don't collide
    repo_dir = Path(tempfile.mkdtemp(prefix="cve_"))

    # Default result if we never find the requested commit
    result = {"error": f"Commit {commit_hash} not found in {repo_url}", "skip_reason": "commit_not_found"}

    try:
        # Disable interactive git prompts so the process doesn't hang on auth errors
        with _non_interactive_git_env():
            cloned = _full_clone(repo_url, repo_dir)

            if not cloned:
                return {"error": f"Kloning feilet for {repo_url}", "skip_reason": "commit_fetch_failed"}

            repo = Repository(str(repo_dir), single=commit_hash)

            # Iterate until we find the target commit, then extract and stop
            for commit in repo.traverse_commits():
                if commit.hash == commit_hash:
                    result = _extract_commit_data(commit, repo_url)
                    break

    except Exception as e:
        msg = str(e).lower()
        if any(x in msg for x in ["could not read username", "authentication failed",
                                   "repository not found", "terminal prompts disabled"]):
            result = {"error": f"Privat/utilgjengelig repo: {e}", "skip_reason": "repo_inaccessible"}
        else:
            result = {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {e}", "skip_reason": "commit_fetch_failed"}

    finally:
        # Force GC before deleting — PyDriller may still hold file handles on Windows
        gc.collect()
        # Always clean up the temp clone, even on error
        _rmtree_with_retries(repo_dir)

    return result

def load_single_commit(repo_url: str, commit_hash: str):
    """
    Public wrapper around _load_single_commit, so the rest of the code
    doesn't have to import an internal helper directly.
    """
    return _load_single_commit(repo_url, commit_hash)