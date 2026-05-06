#---------------------------------------------------------------------
# Commit-lasting: shallow-kloner repo, trekker ut commit-data med PyDriller,
# og returnerer strukturert dict.
#---------------------------------------------------------------------

from __future__ import annotations

import gc
import os
import subprocess
import typer

from pathlib import Path

from pydriller import Repository

from src.utils.file_filter import should_skip_file
from src.utils.git_access import (
    _non_interactive_git_env,
    _inject_token,
    _rmtree_with_retries,
    get_cached_repo_access,
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
    Trekker ut all nødvendig data fra PyDriller-commitobjektet mens repoet
    fortsatt finnes på disk. Returnerer ren dict uten referanser til git-objekter.
    """
    files_data = []
    functions_data = []
    seen = set()

    for mf in commit.modified_files:
        file_path = mf.old_path or mf.new_path or "unknown"

        # Filtrer bort testfiler / irrelevante filer
        if should_skip_file(file_path):
            continue

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
        if not mf.source_code_before or not mf.source_code or not mf.changed_methods:
            continue

        for changed_method in mf.changed_methods:
            before_method = _find_best_before_method(changed_method, mf.methods_before)
            after_method = _find_best_after_method(changed_method, mf.methods)

            if not before_method or not after_method:
                continue

            if not _methods_match_well(before_method, after_method):
                continue

            method_name = (before_method.name or after_method.name or "").strip()
            if not _is_valid_method_name(method_name):
                continue

            if not _valid_line_range(before_method.start_line, before_method.end_line):
                continue
            if not _valid_line_range(after_method.start_line, after_method.end_line):
                continue

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

            # Krev komplett vulnerability -> patch par
            if not vuln_code or not patch_code:
                continue

            # Avvis kodeblokker som ikke er reelle funksjoner
            # (f.eks. catch/else/finally-blokker feilidentifisert av parseren)
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
        functions_data = [
            fn for fn in functions_data
            if len(fn["vuln_function"]) != len(fn["patch_function"])
        ]

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

    repo_dir = _make_local_temp_dir()
    result = {"error": f"Commit {commit_hash} ikke funnet i {repo_url}", "skip_reason": "commit_not_found"}

    try:
        with _non_interactive_git_env():
            cloned = _full_clone(repo_url, repo_dir)

            if not cloned:
                return {"error": f"Kloning feilet for {repo_url}", "skip_reason": "commit_fetch_failed"}

            repo = Repository(str(repo_dir), single=commit_hash)

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
        gc.collect()
        _rmtree_with_retries(repo_dir)

    return result

def load_single_commit(repo_url: str, commit_hash: str):
    """
    Offentlig wrapper rundt _load_single_commit, så resten av koden
    slipper å importere en intern hjelpefunksjon direkte.
    """
    return _load_single_commit(repo_url, commit_hash)