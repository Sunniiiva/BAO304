# Contains the functions used to manage the SQLite database in the project

# Imports database functions so they can be used directly from the db package
from .database import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    insert_function,
    link_cve_commit,
    get_sync_state,
    upsert_sync_state,
    get_unenriched_commits,
)

# Public API for the db package
__all__ = [
    "connect",
    "init_db",
    "upsert_cve",
    "upsert_commit",
    "insert_patch",
    "insert_function",
    "link_cve_commit",
    "get_sync_state",
    "upsert_sync_state",
    "get_unenriched_commits",
]
