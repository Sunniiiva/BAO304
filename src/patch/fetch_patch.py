from __future__ import annotations

from repo.fetch_commit import fetch_commit_modified_files
from patch.parse_patch import parse_patch
from patch.language_detection import detect_language_from_path

def fetch_patch_data(repo_url: str, commit_hash: str):
    modified_files = fetch_commit_modified_files(repo_url, commit_hash) # Henter modified files objektet fra fetch_commit.py
    patch_data = []

    # Går gjennom hver fil i modified_files
    for file in modified_files:
        file_path = file.get("file_path", "")
        patch_text = file.get("patch_text")  

        parsed = parse_patch(patch_text)

        # Lager en strukturert representasjon av hver fil med nødvendige data
        patch_data.append({
            # Metadata
            "repo_url": repo_url,
            "commit_hash": commit_hash,
            "file_path": file_path,
            "language": detect_language_from_path(file_path),

            # Counts
            "added_lines": parsed["added_lines"],
            "removed_lines": parsed["removed_lines"],
            "changed_lines": parsed["changed_lines"],
            "hunk_count": parsed["hunk_count"],

            # Raw data
            "patch_text": patch_text or "",
            "before_code": parsed["before_code"],
            "after_code": parsed["after_code"],
        })

    return patch_data
    
# ??output: repo_url, commit_hash, file_path, added_lines, removed_lines, patch_text, before_code, after_code, language



