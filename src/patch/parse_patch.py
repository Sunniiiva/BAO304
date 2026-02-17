from __future__ import annotations

from typing import Dict, Any, Optional

# Prefixer av diff-metadata som skal ignoreres
_DIFF_META_PREFIXES = (
    "diff --git",
    "index ",
    "--- ",
    "+++ ",
    "new file mode",
    "deleted file mode",
    "similarity index",
    "rename from",
    "rename to",
)


def parse_patch(patch_text: str | None) -> dict:
    patch_text = patch_text or ""

    before_lines = []
    after_lines = []
    added = removed = 0
    hunk_count = 0

    for line in patch_text.splitlines():
        # skip diff headers
        if line.startswith(("diff --git", "index ", "---", "+++", "@@")):
            if line.startswith("@@"):
                hunk_count += 1
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added += 1
            after_lines.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
            before_lines.append(line[1:])
        else:
            # kontekstlinjer ignoreres (eller ta de med hvis du vil ha mer)
            pass

    changed = added + removed

    return {
        "added_lines": added,
        "removed_lines": removed,
        "changed_lines": changed,
        "hunk_count": hunk_count,
        "before_code": "\n".join(before_lines),
        "after_code": "\n".join(after_lines),
    }
