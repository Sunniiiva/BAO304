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
    fetch_commit_data
)

from .parse_commit import (
    process_cve_references
)

__all__ = [
    "extract_repo_and_hash",
    "fetch_commit_data", 
    "process_cve_references"
]
