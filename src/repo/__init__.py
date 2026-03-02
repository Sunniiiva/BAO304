"""
Repo package

Ansvar:
- Hente commit-data fra repositories (via PyDriller)
- Ekstrahere repo_url + commit_hash fra GitHub commit-URL
- Tilby hjelpefunksjoner for patch-modulen
"""

# Kun eksponer OFFENTLIG API fra riktige moduler
from .utils import (
    extract_repo_and_hash,
    fetch_commit_data,
    fetch_commit_modified_files
)

from .parse_commit import (
    process_cve_references
)

__all__ = [
    "extract_repo_and_hash",
    "fetch_commit_data",
    "fetch_commit_modified_files", 
    "process_cve_references"
]

from .crawl_repo import crawl_repo_for_cve

__all__ = [
    "extract_repo_and_hash",
    "fetch_commit_data",
    "fetch_commit_modified_files",
    "process_cve_references",
    "crawl_repo_for_cve",
]