#---------------------------------------------------------------------
# Metode-matching: validering, linje-overlapp og kobling av
# before/after-metoder fra PyDriller.
#---------------------------------------------------------------------

from __future__ import annotations

import re


def _is_valid_method_name(name: str | None) -> bool:
    if not name:
        return False

    name = name.strip()
    if not name:
        return False

    lowered = name.lower()
    if lowered in {"(anonymous)", "anonymous", "<anonymous>", "unknown"}:
        return False

    # Krev minst to sammenhengende bokstaver — filtrerer bort
    # operatorer og parser-artefakter som "+", ";", "=", "(", "&&"
    if not re.search(r"[a-zA-Z]{2}", name):
        return False

    return True


def _valid_line_range(start: int | None, end: int | None) -> bool:
    if start is None or end is None:
        return False
    return start > 0 and end >= start


def _extract_code_block(source: str | None, start: int | None, end: int | None) -> str | None:
    if not source or not _valid_line_range(start, end):
        return None

    lines = source.splitlines()
    if start > len(lines):
        return None

    end = min(end, len(lines))
    code = "\n".join(lines[start - 1:end])
    return code if code.strip() else None


def _line_overlap(
    a_start: int | None,
    a_end: int | None,
    b_start: int | None,
    b_end: int | None,
) -> int:
    if None in (a_start, a_end, b_start, b_end):
        return 0
    return max(0, min(a_end, b_end) - max(a_start, b_start) + 1)


def _line_distance(
    a_start: int | None,
    a_end: int | None,
    b_start: int | None,
    b_end: int | None,
) -> int:
    if None in (a_start, a_end, b_start, b_end):
        return 10**9

    if _line_overlap(a_start, a_end, b_start, b_end) > 0:
        return 0

    if a_end < b_start:
        return b_start - a_end

    if b_end < a_start:
        return a_start - b_end

    return 10**9


def _find_best_before_method(changed_method, methods_before):
    """
    Finn best mulig before-metode.
    Prioritet:
    1) Samme navn + linjeoverlapp
    2) Samme navn + nærmeste range
    """
    same_name = [m for m in methods_before if m.name == changed_method.name]
    if not same_name:
        return None

    overlapping = [
        m for m in same_name
        if _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line) > 0
    ]
    if overlapping:
        return max(
            overlapping,
            key=lambda m: _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
        )

    return min(
        same_name,
        key=lambda m: _line_distance(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
    )


def _find_best_after_method(changed_method, methods_after):
    """
    Finn best mulig after-metode.
    Prioritet:
    1) Samme navn + eksakt linjematch
    2) Samme navn + linjeoverlapp
    3) Samme navn + nærmeste range
    """
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

    overlapping = [
        m for m in same_name
        if _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line) > 0
    ]
    if overlapping:
        return max(
            overlapping,
            key=lambda m: _line_overlap(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
        )

    return min(
        same_name,
        key=lambda m: _line_distance(m.start_line, m.end_line, changed_method.start_line, changed_method.end_line)
    )


def _methods_match_well(before_method, after_method) -> bool:
    """
    Krev at before/after faktisk ser ut som samme funksjon.
    """
    if not before_method or not after_method:
        return False

    before_name = (before_method.name or "").strip()
    after_name = (after_method.name or "").strip()

    if not before_name or not after_name:
        return False

    if before_name != after_name:
        return False

    overlap = _line_overlap(
        before_method.start_line,
        before_method.end_line,
        after_method.start_line,
        after_method.end_line,
    )
    if overlap > 0:
        return True

    distance = _line_distance(
        before_method.start_line,
        before_method.end_line,
        after_method.start_line,
        after_method.end_line,
    )
    return distance <= 15
