from __future__ import annotations

from src.patch.parse_patch import parse_patch
from src.patch.language_detection import detect_language_from_path
from src.utils.file_filter import should_skip_file

#-----------------------------------------------------------------
# Funksjon for å bygge patch-data fra en liste med modified_files
#-----------------------------------------------------------------
def build_patch_data_from_modified_files(
    repo_url: str,
    commit_sha: str,
    modified_files: list[dict],
) -> list[dict]:
    """
    Bygger patch-rader fra en allerede hentet liste med modified_files.
    Brukes i optimalisert run-all for å unngå ny commit-traversering.
    """
    patch_data: list[dict] = []

    for file in modified_files:
        # The file path tells us which file was changed in this commit
        file_path = file.get("file_path", "")
        if should_skip_file(file_path):
            continue

        patch_text = file.get("patch_text", "")
        parsed = parse_patch(patch_text)

        # Assemble the final row.
        # .get(..., default) is used everywhere so a missing field never crashes the pipeline —
        # we just fall back to a sensible default (0 for counts, "" for text)
        patch_data.append(
            {
                "repo_url": repo_url,
                "commit_sha": commit_sha,
                "file_path": file_path,
                "language": detect_language_from_path(file_path),
                "added_lines": parsed.get("added_lines", 0),
                "removed_lines": parsed.get("removed_lines", 0),
                "changed_lines": parsed.get("changed_lines", 0),
                "hunk_count": parsed.get("hunk_count", 0),
                "diff_text": parsed.get("diff_only", ""),
                "before_code": parsed.get("before_code", ""),
                "after_code": parsed.get("after_code", ""),
            }
        )

    return patch_data