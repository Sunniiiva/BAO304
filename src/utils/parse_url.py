#---------------------------------------------------------------------
# Hjelpefunksjoner for parsing av commit-URLer og mappenavn.
# Støtter GitHub, GitLab og Bitbucket (inspirert av CVEfixes).
#---------------------------------------------------------------------

from __future__ import annotations

import hashlib
import re
from typing import Any

#---------------------------------------------------------------------
# Plattform-konfigurasjon
#---------------------------------------------------------------------
SUPPORTED_PLATFORMS: dict[str, dict[str, Any]] = {
    "github": {
        "hosts": ("github.com",),
        "token_env": "GITHUB_TOKEN",
        "commit_segments": ("commit", "commits"),
    },
    "gitlab": {
        "hosts": ("gitlab.com",),
        "token_env": "GITLAB_TOKEN",
        "commit_segments": ("commit", "commits"),
    },
    "bitbucket": {
        "hosts": ("bitbucket.org",),
        "token_env": "BITBUCKET_TOKEN",
        "commit_segments": ("commits", "commit"),
    },
}

# Felles regex for alle tre plattformer (inspirert av CVEfixes).
_COMMIT_URL_REGEX = re.compile(
    r"https?://"
    r"(?P<host>github\.com|gitlab\.com|bitbucket\.org)/"
    r"(?P<owner>[^/\s]+)/"
    r"(?P<repo>[^/\s]+)"
    r"(?:/-)?"                       # GitLab kan ha "/-" før /commit/
    r"/(?:commit|commits)/"
    r"(?P<hash>[0-9a-fA-F]{7,40})",
    re.IGNORECASE,
)


def detect_platform(url: str) -> str | None:
    """
    Returnerer plattform-nøkkelen ("github" | "gitlab" | "bitbucket")
    for en gitt URL, eller None hvis den ikke er støttet.
    """
    if not url:
        return None
    lowered = url.lower()
    for platform, cfg in SUPPORTED_PLATFORMS.items():
        for host in cfg["hosts"]:
            if host in lowered:
                return platform
    return None


#---------------------------------------------------------------------
# Funksjon for å parse commit-referanser fra CVE-data
#---------------------------------------------------------------------
def extract_repo_and_hash(commit_url: str):
    """
    Parser commit-URL fra GitHub, GitLab eller Bitbucket og returnerer:
      {
        "repo_url":    "https://<host>/<owner>/<repo>",
        "commit_hash": "<sha>",
        "platform":    "github" | "gitlab" | "bitbucket"
      }

    Støtter:
    - GitHub:    https://github.com/owner/repo/commit/<hash>
    - GitLab:    https://gitlab.com/owner/repo/-/commit/<hash>
                 https://gitlab.com/owner/repo/commit/<hash>
    - Bitbucket: https://bitbucket.org/owner/repo/commits/<hash>
                 https://bitbucket.org/owner/repo/commit/<hash>
    - Markdown-wrappede URL-er: [tekst](https://...)
    """
    if not commit_url:
        return None

    if "(" in commit_url and ")" in commit_url:
        commit_url = commit_url.split("(")[-1].split(")")[0]

    cleaned = commit_url.split("?")[0].split("#")[0].strip()

    match = _COMMIT_URL_REGEX.search(cleaned)
    if not match:
        return None

    host = match.group("host").lower()
    owner = match.group("owner")
    repo = match.group("repo")
    commit_hash = match.group("hash")

    if repo.endswith(".git"):
        repo = repo[:-4]

    platform = detect_platform(host)
    if platform is None:
        return None

    return {
        "repo_url": f"https://{host}/{owner}/{repo}",
        "commit_hash": commit_hash,
        "platform": platform,
    }


def _repo_dir_name(repo_url: str, commit_hash: str) -> str:
    """
    Lager et unikt mappenavn basert på en kort SHA256-hash av repo_url + commit_hash.
    Unik per commit slik at parallelle workers aldri kolliderer på samme mappe.
    Unngår også for lange stier på Windows (MAX_PATH = 260 tegn).
    """
    key = f"{repo_url}#{commit_hash}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]