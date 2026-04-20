"""
patch package

Ansvar:
- Parse unified diffs til counts + før/etter-snippets
- Detektere språk fra filsti/filendelse
- Bygge patch-data per fil i en commit (brukes av pipeline i main)
"""

from .parse_patch import parse_patch
from .language_detection import detect_language_from_path

__all__ = [
    "parse_patch",
    "detect_language_from_path",
]
