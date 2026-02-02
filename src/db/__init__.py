"""
db package

Ansvar:
- Opprette/initialisere SQLite database og schema
- Tilby enkle funksjoner for å lagre og hente:
  - CVE
  - commits
  - patch-rader
  - kobling CVE <-> commit
"""

from .database import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    link_cve_commit,
    get_commits_for_cve,
    get_patches_for_commit,
)

__all__ = [
    "connect",
    "init_db",
    "upsert_cve",
    "upsert_commit",
    "insert_patch",
    "link_cve_commit",
    "get_commits_for_cve",
    "get_patches_for_commit",
]

