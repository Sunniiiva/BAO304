from __future__ import annotations
from pathlib import Path

# Språk som støttes basert på filendelser
_EXTENSION_TO_LANGUAGE = {
    # Python
    ".py": "python",
    ".pyi": "python",
    # JavaScript / TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # JVM
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    # C / C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    # C#
    ".cs": "csharp",
    # Go
    ".go": "go",
    # Ruby
    ".rb": "ruby",
    ".erb": "ruby",
    # PHP
    ".php": "php",
    ".ctp": "php",
    # Rust
    ".rs": "rust",
    # Swift / Objective-C
    ".swift": "swift",
    ".m": "objectivec",
    ".mm": "objectivec",
    # Perl
    ".pl": "perl",
    ".pm": "perl",
    ".t": "perl",
    # Shell
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".ps1": "powershell",
    # Markup / config
    ".sql": "sql",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "scss",
    ".less": "less",
}

# Detekterer språk basert på fil path
def detect_language_from_path(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if not ext:
        return "unknown"
    return _EXTENSION_TO_LANGUAGE.get(ext, "unknown")

