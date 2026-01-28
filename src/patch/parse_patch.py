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


def parse_patch(patch_text: Optional[str]) -> Dict[str, Any]:
   
    # Håndterer tomme patch-tekster
    if not patch_text:
        return {
            "added_lines": 0,
            "removed_lines": 0,
            "changed_lines": 0,
            "hunk_count": 0,
            "before_code": "",
            "after_code": "",
        }

    added_lines = 0
    removed_lines = 0
    hunk_count = 0

    before_code: list[str] = []
    after_code: list[str] = []

    # Går gjennom hver linje i patch-teksten
    for line in patch_text.splitlines():
        #Hopper over linjer som bare inneholder "\ No newline at end of file"
        if line.startswith("\\"):
            continue

        # Hopper over hunk header linjer og teller hunks
        if line.startswith("@@"):
            hunk_count += 1
            continue

        # Hopper over diff metadata
        if any(line.startswith(p) for p in _DIFF_META_PREFIXES):
            continue

        # Added line
        if line.startswith("+"):
            added_lines += 1
            after_code.append(line[1:])
            continue

        # Removed line
        if line.startswith("-"):
            removed_lines += 1
            before_code.append(line[1:])
            continue

        # Context line
        if line.startswith(" "):
            content = line[1:]
        else:
            content = line

        before_code.append(content)
        after_code.append(content)

    # Returnerer parsed data
    return {
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "changed_lines": added_lines + removed_lines,
        "hunk_count": hunk_count,
        "before_code": "\n".join(before_code),
        "after_code": "\n".join(after_code),
    }

