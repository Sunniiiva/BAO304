"""
patch package

Ansvar:
- Parse unified diffs til counts + før/etter-snippets
- Detektere språk fra filsti/filendelse
- Bygge patch-data per fil i en commit (brukes av pipeline i main)
"""

from .fetch_patch import fetch_patch_data
from .parse_patch import parse_patch
from .language_detection import detect_language_from_path

__all__ = [
    "fetch_patch_data",
    "parse_patch",
    "detect_language_from_path",
]
