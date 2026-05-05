from __future__ import annotations

from src.utils.parse_url import extract_repo_and_hash
from src.cve.parse_cve import extract_grouped_references

#---------------------------------------------------------
# Funksjon for å trekke ut commit-referanser fra CVE-data
#---------------------------------------------------------
def extract_commit_references(cve_data: dict) -> list[dict]:
    """
    Leser GitHub /commit/-referanser fra én CVE og returnerer en liste som:
    [
        {
            "repo_url": "...",
            "commit_sha": "...",
            "commit_url": "..."
        }
    ]
    """
    # CVE references are pre-grouped by type (commit, advisory, patch, etc.)
    # We only care about the "commit" group here
    grouped_refs = extract_grouped_references(cve_data)

    commit_refs: list[dict] = []

    for commit_url in grouped_refs.get("commit", []):
        # Parse the URL into (repo_url, commit_hash, platform).
        # Returns None for unsupported hosts or malformed URLs — those are skipped
        info = extract_repo_and_hash(commit_url)
        if not info:
            continue

        commit_refs.append(
            {
                "repo_url": info["repo_url"],
                "commit_sha": info["commit_hash"],
                "commit_url": commit_url,
            }
        )

    return commit_refs