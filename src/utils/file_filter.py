from __future__ import annotations

from pathlib import PurePosixPath


# Extensions vi aldri vil lagre/print'e patches for
SKIP_EXTENSIONS = {
    # docs / text
    ".md", ".rst", ".txt", ".adoc",
    # data / configs
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    # logs / misc
    ".log", ".csv",
    # images / binaries
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
}

# Eksakte filnavn vi alltid skipper
SKIP_FILENAMES = {
    "readme", "readme.md", "readme.rst", "readme.txt",
    "changelog", "changelog.md", "changelog.rst", "changelog.txt",
    "license", "license.md", "license.txt",
    "copying",
    "code_of_conduct.md",
    "contributing.md",
    "security.md",
    "release-notes.md",
}

# Folder-mønstre vi vanligvis ikke vil ha med
SKIP_DIR_PARTS = {
    "docs", "doc", ".github",
    ".vscode", ".idea",
    "examples", "example",
    "test", "tests", "__tests__", "testing",
    "tester", "spec", "specs",
    "benchmark", "benchmarks",
    "dist", "build", "out", "target",
    "node_modules", "vendor",
    "grammars", "generated",
}


def should_skip_file(file_path: str) -> bool:
    """
    Return True hvis vi skal hoppe over fila (ikke lagre patch, ikke print).
    Filtrerer på extension, filnavn og mappestruktur.
    """
    if not file_path:
        return True

    # Normaliser path (git paths er typisk posix, men Windows bruker backslash)
    p = PurePosixPath(file_path.replace("\\", "/"))
    name_lower = p.name.lower()

    # Skip eksakt filnavn
    if name_lower in SKIP_FILENAMES:
        return True

    # Skip extension
    suffix = p.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return True

    # Skip minifiserte filer (f.eks. tarteaucitron.min.js, sm2.min.cjs)
    if ".min." in name_lower:
        return True

    # Skip folder parts
    parts_lower = {part.lower() for part in p.parts}
    if parts_lower & SKIP_DIR_PARTS:
        return True

    # Skip testfiler basert på filnavn (f.eks. functional_test.py, test_utils.py)
    stem = p.stem.lower()
    if stem.startswith("test_") or stem.endswith("_test"):
        return True

    return False