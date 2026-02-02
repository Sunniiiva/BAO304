"""
repo package

Ansvar:
- Hente commit-data fra repositories (via PyDriller)
- Ekstrahere repo_url + commit_hash fra GitHub commit-URL
- Tilby hjelpefunksjoner for patch-modulen
"""

from .fetch_commit import (
    extract_repo_and_hash,
    fetch_commit_data,
    fetch_commit_modified_files,
    process_cve_references,
    save_results,
)

__all__ = [
    "extract_repo_and_hash",
    "fetch_commit_data",
    "fetch_commit_modified_files",
    "process_cve_references",
    "save_results",
]
