from __future__ import annotations
from pathlib import Path

# Språk som støttes basert på filendelser
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

# Detekterer språk basert på fil path
def detect_language_from_path(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if not ext:
        return "unknown"
    return _EXTENSION_TO_LANGUAGE.get(ext, "unknown")

