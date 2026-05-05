# ---------------------------------------------------------------------
# Method matching: validation, line-range overlap, and pairing of
# before/after methods from PyDriller.
# ---------------------------------------------------------------------

from __future__ import annotations

import re


def _is_valid_method_name(name: str | None) -> bool:
    # Filters out junk method names that the parser sometimes returns
    if not name:
        return False

    name = name.strip()
    if not name:
        return False

    # Reject placeholder names that don't represent a real method
    lowered = name.lower()
    if lowered in {"(anonymous)", "anonymous", "<anonymous>", "unknown"}:
        return False

    # Require at least two consecutive letters — this filters out
    # operators and parser artifacts like "+", ";", "=", "(", "&&"
    if not re.search(r"[a-zA-Z]{2}", name):
        return False

    return True


def _valid_line_range(start: int | None, end: int | None) -> bool:
    # A valid range must have both endpoints, start at line 1+, and end >= start
    if start is None or end is None:
        return False
    return start > 0 and end >= start


def _extract_code_block(source: str | None, start: int | None, end: int | None) -> str | None:
    # Pull lines [start..end] out of the full file source
    if not source or not _valid_line_range(start, end):
        return None

    lines = source.splitlines()
    if start > len(lines):
        return None

    # Clamp end to the actual file length to avoid IndexError
    end = min(end, len(lines))
    # Convert 1-based line numbers to 0-based slice indexes
    code = "\n".join(lines[start - 1:end])
    code = _clean_extracted_code(code)
    return code if code.strip() else None


# ---------------------------------------------------------------------
# Cleanup and validation of extracted code blocks
# ---------------------------------------------------------------------

# Lines that are just leftovers from the previous function or from comment blocks —
# not part of the function itself, but get included due to imprecise line boundaries.
_JUNK_LINE_RE = re.compile(
    r"^\s*(?:"
    r"\}[;\s]*"           # lone } possibly followed by ; and whitespace
    r"|[%]{3,}"           # %%% comment lines (ImageMagick style)
    r"|#\s*(?:endif|else|if)\b.*"  # C/C++ preprocessor guards
    r"|[/*]+\s*$"         # empty comment lines like /, /* or *
    r")$"
)


def _clean_extracted_code(code: str) -> str:
    """
    Remove leading junk lines that don't belong to the function:
    lone '}', %%% comment blocks, preprocessor guards, etc.
    Lets us still use functions that have imprecise start boundaries.
    """
    lines = code.splitlines()

    # Strip leading junk lines
    while lines and _JUNK_LINE_RE.match(lines[0]):
        lines.pop(0)

    # Strip leading blank lines
    while lines and not lines[0].strip():
        lines.pop(0)

    return "\n".join(lines)


# Keywords that start a control-flow block, never a function definition.
# Also matches the variant where } and the keyword are on the same line.
_NON_FUNCTION_STARTS = re.compile(
    r"^\s*\}?\s*(?:"
    r"catch\s*\("
    r"|else\s*[\{:]"
    r"|else\s+if\s*\("
    r"|elif\s"
    r"|except\b"
    r"|finally\s*[\{:]"
    r"|case\s+.+:"
    r"|default\s*:"
    r")"
)


def _looks_like_function(code: str) -> bool:
    """
    Check that the extracted code actually looks like a real function,
    not a random catch/else/finally block that the parser mistakenly
    identified as a method.
    """
    if not code:
        return False

    # Find the first non-empty line and check it
    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Reject if the first real line starts with a control-flow keyword
        if _NON_FUNCTION_STARTS.match(stripped):
            return False
        return True

    return False


def _line_overlap(
    a_start: int | None,
    a_end: int | None,
    b_start: int | None,
    b_end: int | None,
) -> int:
    # Returns the number of overlapping lines between two ranges (0 if none)
    if None in (a_start, a_end, b_start, b_end):
        return 0
    return max(0, min(a_end, b_end) - max(a_start, b_start) + 1)


def _line_distance(
    a_start: int | None,
    a_end: int | None,
    b_start: int | None,
    b_end: int | None,
) -> int:
    # Returns the gap in lines between two ranges. 10**9 = "infinitely far"
    if None in (a_start, a_end, b_start, b_end):
        return 10**9

    # Overlapping ranges have distance 0
    if _line_overlap(a_start, a_end, b_start, b_end) > 0:
        return 0

    # a is fully before b
    if a_end < b_start:
        return b_start - a_end

    # b is fully before a
    if b_end < a_start:
        return a_start - b_end

    return 10**9


def _find_best_before_method(changed_method, methods_before):
    """
    Find the best matching "before" method.
    Priority:
    1) Same name + line overlap
    2) Same name + closest range
    """
    # Filter to candidates with the same name first — name match is required
    same_name = [m for m in methods_before if m.name == changed_method.name]
    if not same_name:
        return None

    # Prefer methods that overlap the changed range
    overlapping = [
        m for m in same_name
        if _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line) > 0
    ]
    if overlapping:
        # If multiple overlap, pick the one with the largest overlap
        return max(
            overlapping,
            key=lambda m: _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
        )

    # Fallback: no overlap — pick the closest by line distance
    return min(
        same_name,
        key=lambda m: _line_distance(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
    )


def _find_best_after_method(changed_method, methods_after):
    """
    Find the best matching "after" method.
    Priority:
    1) Same name + exact line match
    2) Same name + line overlap
    3) Same name + closest range
    """
    # Step 1: exact match on both name and line range — the safest case
    exact = [
        m for m in methods_after
        if m.name == changed_method.name
        and m.start_line == changed_method.start_line
        and m.end_line == changed_method.end_line
    ]
    if exact:
        return exact[0]

    same_name = [m for m in methods_after if m.name == changed_method.name]
    if not same_name:
        return None

    # Step 2: same name and overlapping line range
    overlapping = [
        m for m in same_name
        if _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line) > 0
    ]
    if overlapping:
        return max(
            overlapping,
            key=lambda m: _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
        )

    # Step 3: fallback — closest method by line distance
    return min(
        same_name,
        key=lambda m: _line_distance(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
    )


def _strip_comments(code: str) -> str:
    """Remove block and line comments from code."""
    # Block comments: /* ... */ and /** ... */ (DOTALL so . also matches newlines)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # Line comments: // ...
    code = re.sub(r"//[^\n]*", "", code)
    # Python / shell / PHP comments: # ...
    code = re.sub(r"#[^\n]*", "", code)
    return code


def _has_meaningful_code_change(vuln_code: str | None, patch_code: str | None) -> bool:
    """
    Return True only if vuln and patch contain a real code change —
    filters out changes that are only whitespace and/or comments.
    """
    if not vuln_code or not patch_code:
        return False

    # Helper: remove all whitespace so two pieces of code can be compared
    # ignoring indentation, trailing spaces, and newlines
    def _normalize(s: str) -> str:
        return re.sub(r"\s+", "", s)

    # Step 1: check if the change is whitespace only
    if _normalize(vuln_code) == _normalize(patch_code):
        return False

    # Step 2: check if the change is only in comments (after whitespace removal)
    vuln_stripped = _strip_comments(vuln_code)
    patch_stripped = _strip_comments(patch_code)
    if _normalize(vuln_stripped) == _normalize(patch_stripped):
        return False

    return True


def _methods_match_well(before_method, after_method) -> bool:
    """
    Require that before/after actually look like the same function.
    """
    if not before_method or not after_method:
        return False

    before_name = (before_method.name or "").strip()
    after_name = (after_method.name or "").strip()

    if not before_name or not after_name:
        return False

    # Must be the same function name
    if before_name != after_name:
        return False

    # Strong signal: line ranges overlap → same function
    overlap = _line_overlap(
        before_method.start_line,
        before_method.end_line,
        after_method.start_line,
        after_method.end_line,
    )
    if overlap > 0:
        return True

    # Otherwise: accept only if the function moved less than 15 lines.
    # Prevents pairing two unrelated methods that happen to share a name
    distance = _line_distance(
        before_method.start_line,
        before_method.end_line,
        after_method.start_line,
        after_method.end_line,
    )
    return distance <= 15