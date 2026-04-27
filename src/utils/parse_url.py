#---------------------------------------------------------------------
# Hjelpefunksjoner for parsing av GitHub-URLer og mappenavn.
#---------------------------------------------------------------------

from __future__ import annotations

import hashlib


#---------------------------------------------------------------------
# Funksjon for å parse Github commit-referanser fra CVE-data
#---------------------------------------------------------------------
def extract_repo_and_hash(commit_url: str):
    """
    Parser GitHub commit-URL og returnerer:
      {
        "repo_url": "https://github.com/owner/repo",
        "commit_hash": "<sha>"
      }

    Støtter:
    - Vanlig URL: https://github.com/owner/repo/commit/<hash>
    - Markdown:  [tekst](https://github.com/owner/repo/commit/<hash>)
    - Returnerer dict med 'repo_url' og 'commit_hash', eller None hvis parsing feiler.
    """
    if not commit_url or "github.com" not in commit_url:
        return None

    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(")[-1].split(")")[0]

    clean_url = (
        commit_url.replace("https://", "")
        .replace("http://", "")
        .split("?")[0]
        .split("#")[0]
    )

    parts = [p for p in clean_url.strip("/").split("/") if p]

    if len(parts) >= 5 and parts[0] == "github.com" and parts[3] == "commit":
        owner = parts[1]
        repo = parts[2]
        commit_hash = parts[4]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    if len(parts) >= 4 and parts[2] == "commit":
        owner = parts[0]
        repo = parts[1]
        commit_hash = parts[3]
        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "commit_hash": commit_hash,
        }

    return None


def _repo_dir_name(repo_url: str, commit_hash: str) -> str:
    """
    Lager et unikt mappenavn basert på en kort SHA256-hash av repo_url + commit_hash.
    Unik per commit slik at parallelle workers aldri kolliderer på samme mappe.
    Unngår også for lange stier på Windows (MAX_PATH = 260 tegn).
    """
    key = f"{repo_url}#{commit_hash}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]