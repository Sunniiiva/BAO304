from __future__ import annotations

from typing import Any

from src.repo.utils import _load_single_commit


# Funksjon som henter ut et spesifikt kodeområde.
# Brukes til å hente selve funksjonen/metoden som har blitt endret i en commit.
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


# Prøver først å finne en metode med samme navn og linjeområde.
# Hvis ikke funnet, søker den kun etter samme navn.
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


# Finner riktig metode før committen ble brukt.
def _find_matching_method_before_change(mf, changed_method):
    for method in mf.methods_before:
        if method.name == changed_method.name:
            return method

    return None


# Henter den sårbare og patchede versjonen av funksjonen
def vuln_and_patch_function(repo_url: str, commit_hash: str) -> list[dict[str, Any]]:
    if not repo_url:
        raise ValueError("repo_url må være satt")

    if not commit_hash:
        raise ValueError("commit_hash må være satt")

    loaded = _load_single_commit(repo_url, commit_hash)

    if isinstance(loaded, dict) and "error" in loaded:
        raise RuntimeError(loaded["error"])

    if not loaded:
        raise RuntimeError(f"Commit {commit_hash} ikke funnet i {repo_url}")

    commit = loaded

    results: list[dict[str, Any]] = []
    seen = set()

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

            key = (
                "combined",
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
                    before_method.end_line,
                )

                if not vuln_code.strip():
                    vuln_code = None

            patch_code = None
            if after_method and mf.source_code:
                patch_code = extract_code_block(
                    mf.source_code,
                    after_method.start_line,
                    after_method.end_line,
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