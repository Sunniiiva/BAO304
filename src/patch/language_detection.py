from __future__ import annotations
from pathlib import Path

# Mapping of file extensions to language names.
# Used to tag each patch with the language of the modified file, so the dataset
# can later be filtered or analyzed per language (e.g. only Python vulnerabilities).
# To add support for a new language, just add a new entry below.
_EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".kt": "kotlin",
    ".swift": "swift",
    ".sql": "sql",
    ".sh": "bash",
    ".ps1": "powershell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
}


# Detects the language of a file based on its path.
# Used by the patch pipeline to tag each modified file with a language label
def detect_language_from_path(file_path: str) -> str:
    # Path(...).suffix returns the last extension including the dot (e.g. ".py")
    # .lower() makes the lookup case-insensitive (".PY" and ".py" should both work)
    ext = Path(file_path).suffix.lower()

    # Files with no extension (Makefile, README, Dockerfile, etc.) cannot be
    # identified this way — return "unknown" so the caller can decide what to do
    if not ext:
        return "unknown"

    # dict.get with a default falls back to "unknown" for any extension we don't know.
    # This means new file types never crash the pipeline, they just get tagged as unknown
    return _EXTENSION_TO_LANGUAGE.get(ext, "unknown")