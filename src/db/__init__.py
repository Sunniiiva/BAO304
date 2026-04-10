# -------------------------------------------------------------------------
# DB-pakke fo rdatabasehpntering
# Samler funksjonene som brukes til å håntere SQLite.databasen i prosjektet
#---------------------------------------------------------------------------

# import av DB-funksjoner, så de brukes direkte fra db-pakken
from .database import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    insert_function,
    link_cve_commit,
    get_commits_for_cve,
    get_patches_for_commit,
    get_sync_state,
    upsert_sync_state,
    get_unenriched_commits,
    get_functions_for_commit,
)

# offentlig API for db-pakken
__all__ = [
    "connect",
    "init_db",
    "upsert_cve",
    "upsert_commit",
    "insert_patch",
    "insert_function",
    "link_cve_commit",
    "get_commits_for_cve",
    "get_patches_for_commit",
    "get_sync_state",
    "upsert_sync_state",
    "get_unenriched_commits",
    "get_functions_for_commit",
]
