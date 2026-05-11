from __future__ import annotations

from typing import Dict, Any, Optional

# Prefixer av diff-metadata som skal ignoreres
_DIFF_META_PREFIXES = (
    "diff --git",
    "index ",
    "--- ",
    "+++ ",
    "@@",
    "new file mode",
    "deleted file mode",
    "similarity index",
    "rename from",
    "rename to",
)

#Src -> extract cve, file level, patch level, function level 

# Function for parsing patch text and extracting relevant information
def parse_patch(patch_text: str | None) -> dict[str, Any]:
    patch_text = patch_text or ""

    before_lines: list[str] = []
    after_lines: list[str] = []
    diff_lines: list[str] = []

    added = removed = 0
    hunk_count = 0

    for line in patch_text.splitlines():
        # skip diff headers / metadata
        if line.startswith(_DIFF_META_PREFIXES):
            if line.startswith("@@"):
                hunk_count += 1
            continue

        # only changed lines
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
            content = line[1:]
            after_lines.append(content)
            diff_lines.append(f"+ {content}")

        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
            content = line[1:]
            before_lines.append(content)
            diff_lines.append(f"- {content}")

        else:
            # context lines ignored
            pass

    changed = added + removed

    return {
        "added_lines": added,
        "removed_lines": removed,
        "changed_lines": changed,
        "hunk_count": hunk_count,

        # ONLY changed lines (what you want to print/store)
        "before_code": "\n".join(before_lines),
        "after_code": "\n".join(after_lines),
        "diff_only": "\n".join(diff_lines),
    }
