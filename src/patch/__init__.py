"""
patch package

Responsibilities:
- Parse unified diffs into line counts and before/after snippets
- Detect language from file path / extension
- Build patch data per file in a commit (used by the pipeline in main)
"""

from .parse_patch import parse_patch
from .language_detection import detect_language_from_path

# Public API of the package — controls `from src.patch import *`
__all__ = [
    "parse_patch",
    "detect_language_from_path",
]