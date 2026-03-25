# Impterer biblotekenne somtrengs i programmet.
from __future__ import annotations
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from pydriller import Repository


# En funksjon som lager et lokalt mappenavvn basert på en Git repo URL
# Brukes for å lagre klonede repos i en midlertidig mappe
def _repo_dir_name(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    parts = [x for x in parsed.path.strip("/").split("/") if x]

    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"

    return parts[-1] if parts else "repo"

# Funksjon som henter ut et spesifikt kodeområde. 
# brukes til å hente selve funskjonen / metoden som har blitt endret i en commit
# Hvis linjene er ugyldige eller koden mangler, retuneres en tom streng
def extract_code_block(source_code: str | None, start_line: int, end_line: int) -> str:
    if not source_code:
        return ""

    lines = source_code.splitlines()

    if start_line < 1 or end_line < start_line:
        return ""

    if start_line > len(lines):
        return ""

    end_line = min(end_line, len(lines))
    return "\n".join(lines[start_line - 1:end_line])

# Funkjson som finner riktig metode etter at en commit er blitt brukt (patch versjonen av koden)
# prøver først å finne en metode med samme navn og linjeområde.
# hvis ikke funnet, søker den kunn etter samme navn
def _find_matching_method_after_change(mf, changed_method):
    for method in mf.methods:
        if (
            method.name == changed_method.name
            and method.start_line == changed_method.start_line
            and method.end_line == changed_method.end_line
        ):
            return method

    for method in mf.methods:
        if method.name == changed_method.name:
            return method

    return changed_method

# Funksjon som finner riktig metode før en commit ble brukt (sårbare versjonen av funskjonen)
# Den sammenligner mmethods_before og finner en metode med samme navn
def _find_matching_method_before_change(mf, changed_method):
    for method in mf.methods_before:
        if method.name == changed_method.name:
            return method

    return None

# Funksjon som henter den patched (fiksete) versjonen av en endret funksjon fra en commit
"""def patch_function(repo_url: str, commit_hash: str) -> list[dict[str, Any]]:
    if not repo_url:
        raise ValueError("repo_url må være satt")

    if not commit_hash:
        raise ValueError("commit_hash må være satt")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),
        single=commit_hash,
    )

    results: list[dict[str, Any]] = []
    seen = set()

    for commit in repo.traverse_commits():
        for mf in commit.modified_files:
            file_path = mf.new_path or mf.old_path or "unknown"

            if not mf.source_code:
                continue

            if not mf.changed_methods:
                continue

            for changed_method in mf.changed_methods:
                method_obj = _find_matching_method_after_change(mf, changed_method)

                key = ("patch", file_path, method_obj.name, method_obj.start_line, method_obj.end_line)
                if key in seen:
                    continue
                seen.add(key)

                function_code = extract_code_block(
                    mf.source_code,
                    method_obj.start_line,
                    method_obj.end_line
                )

                if not function_code.strip():
                    continue

                results.append(
                    {
                        "commit_hash": commit.hash,
                        "file_path": file_path,
                        "method_name": method_obj.name,
                        "start_line": method_obj.start_line,
                        "end_line": method_obj.end_line,
                        "patch_function": function_code,
                    }
                )

    return results"""


# Funksjon som henter den sårbare og patchede versjonen av funksjonen
# Implementerer funksjonaliteten av de to tidligere funksjonene og legger til i en liste
# Vi får tak i funksjonen slik den var flr sikkrhetsfiksen. 
def vuln_and_patch_function(repo_url: str, commit_hash: str) -> list[dict[str, Any]]:
    if not repo_url:
        raise ValueError("repo_url må være satt")

    if not commit_hash:
        raise ValueError("commit_hash må være satt")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),
        single=commit_hash,
    )

    results: list[dict[str, Any]] = []
    seen = set()

    for commit in repo.traverse_commits():
        for mf in commit.modified_files:
            file_path = mf.old_path or mf.new_path or "unknown"

            if not mf.source_code_before:
                continue

            if not mf.changed_methods:
                continue

            for changed_method in mf.changed_methods:
                before_method = _find_matching_method_before_change(mf, changed_method)
                after_method = _find_matching_method_after_change(mf, changed_method)

                if not before_method and not after_method:
                    continue

                method_obj = before_method or after_method

                key = ("combined",
                    
                    file_path,
                    method_obj.name,
                    before_method.start_line if before_method else None,
                    before_method.end_line if before_method else None,
                    after_method.start_line if after_method else None,
                    after_method.end_line if after_method else None,
                )
                if key in seen:
                    continue
                seen.add(key)

                vuln_code = None
                if before_method and mf.source_code_before:
                    vuln_code = extract_code_block(
                        mf.source_code_before,
                        before_method.start_line,
                        before_method.end_line
                    )

                    if not vuln_code.strip():
                        vuln_code = None

                patch_code = None
                if after_method and mf.source_code:
                    patch_code = extract_code_block(
                        mf.source_code,
                        after_method.start_line,
                        after_method.end_line
                    )

                    if not patch_code.strip():
                        patch_code = None
                if not vuln_code and not patch_code:
                    continue

                results.append(
                    {
                        "commit_hash": commit.hash,
                        "file_path": file_path,
                        "method_name": method_obj.name,
                        "vuln_start_line": before_method.start_line if before_method else None,
                        "vuln_end_line": before_method.end_line if before_method else None,
                        "vuln_function": vuln_code,
                        "patched_start_line": after_method.start_line if after_method else None,
                        "patched_end_line": after_method.end_line if after_method else None,
                        "patch_function": patch_code,
                    }
                )

    return results


# Funksjon som henter den sårbare versjonen av funksjonen før comitten ble brukt
# fungerer nesten likt som patch_function men bruker source_code_before og methods_before
# Vi får tak i funksjonen slik den var flr sikkrhetsfiksen.  
"""def vuln_function(repo_url: str, commit_hash: str) -> list[dict[str, Any]]:
    if not repo_url:
        raise ValueError("repo_url må være satt")

    if not commit_hash:
        raise ValueError("commit_hash må være satt")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),
        single=commit_hash,
    )

    results: list[dict[str, Any]] = []
    seen = set()

    for commit in repo.traverse_commits():
        for mf in commit.modified_files:
            file_path = mf.old_path or mf.new_path or "unknown"

            if not mf.source_code_before:
                continue

            if not mf.changed_methods:
                continue

            for changed_method in mf.changed_methods:
                method_obj = _find_matching_method_before_change(mf, changed_method)

                if not method_obj:
                    continue

                key = ("vuln", file_path, method_obj.name, method_obj.start_line, method_obj.end_line)
                if key in seen:
                    continue
                seen.add(key)

                function_code = extract_code_block(
                    mf.source_code_before,
                    method_obj.start_line,
                    method_obj.end_line
                )

                if not function_code.strip():
                    continue

                results.append(
                    {
                        "commit_hash": commit.hash,
                        "file_path": file_path,
                        "method_name": method_obj.name,
                        "patched_start_line": method_obj.start_line,
                        "patched_end_line": method_obj.end_line,
                        "vuln_start_line"
                        "vuln_end_line"
                        "vuln_function": function_code,
                    }
                )

    return results"""