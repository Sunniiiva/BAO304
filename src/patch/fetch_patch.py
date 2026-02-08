from __future__ import annotations

from src.repo.utils import fetch_commit_modified_files
from src.patch.parse_patch import parse_patch
from src.patch.language_detection import detect_language_from_path


def fetch_patch_data(repo_url: str, commit_sha: str) -> list[dict]:
    """
    Fetch and parse patch data for all modified files in a commit.

    Returns a list of dicts. Keys are aligned with database naming:
    - repo_url
    - commit_sha
    - file_path
    - language
    - added_lines / removed_lines / changed_lines / hunk_count
    - diff_text
    - before_code / after_code
    """
    modified_files = fetch_commit_modified_files(repo_url, commit_sha)
    patch_data: list[dict] = []

    for file in modified_files:
        file_path = file.get("file_path", "")
        patch_text = file.get("patch_text")

        parsed = parse_patch(patch_text)

        patch_data.append(
            {
                # Metadata (aligned with DB)
                "repo_url": repo_url,
                "commit_sha": commit_sha,
                "file_path": file_path,
                "language": detect_language_from_path(file_path),

                # Counts
                "added_lines": parsed.get("added_lines", 0),
                "removed_lines": parsed.get("removed_lines", 0),
                "changed_lines": parsed.get("changed_lines", 0),
                "hunk_count": parsed.get("hunk_count", 0),

                # Raw data (aligned with DB)
                "diff_text": patch_text or "",
                "before_code": parsed.get("before_code", ""),
                "after_code": parsed.get("after_code", ""),
            }
        )

    return patch_data


# Output (keys):
# repo_url, commit_sha, file_path, language,
# added_lines, removed_lines, changed_lines, hunk_count,
# diff_text, before_code, after_code