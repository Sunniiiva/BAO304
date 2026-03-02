import re

from src.cve.parse_cve import extract_grouped_references
from src.repo.utils import extract_repo_and_hash
from src.repo.crawl_repo import crawl_repo_for_cve


def extract_cve_from_commit(commit_message):
    pattern = r"CVE-\d{4}-\d{4,}"
    matches = re.findall(pattern, commit_message or "", re.IGNORECASE)
    return list(set(cve.upper() for cve in matches))


def process_cve_references(cve_data, *, max_commits_per_repo: int = 20000):
    """
    NEW behavior:
      1) Use CVE JSON references to extract repo_url(s)
      2) Crawl each repo history to discover commits mentioning the CVE ID
      3) ALSO include any explicit commit URLs (seeds)
      4) Return commit_data in the shape main.py already uses
    """
    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "unknown").upper()
    grouped_refs = extract_grouped_references(cve_data)

    repo_urls = set(grouped_refs.get("repo", []))

    # Seed commits from explicit commit URLs (if present)
    seed_commits: list[dict] = []
    for commit_url in grouped_refs.get("commit", []):
        info = extract_repo_and_hash(commit_url)
        if info:
            repo_urls.add(info["repo_url"])
            seed_commits.append(
                {
                    "commit_hash": info["commit_hash"],
                    "commit_message": "",  # will be filled later by main.py via patches/commit fetch if desired
                    "author": "",
                    "date": "",
                    "repo_url": info["repo_url"],
                    "mentioned_cves": [],
                    "mentions_target_cve": False,  # unknown until we read message
                    "discovery_method": "explicit_commit_reference",
                }
            )

    # Crawl repos for commits mentioning the CVE ID
    crawled_commits: list[dict] = []
    for repo_url in sorted(repo_urls):
        crawled_commits.extend(
            crawl_repo_for_cve(
                repo_url,
                cve_id,
                max_commits=max_commits_per_repo,
            )
        )

    # Merge + dedupe by (repo_url, sha)
    seen = set()
    merged: list[dict] = []
    for item in seed_commits + crawled_commits:
        key = (item.get("repo_url"), item.get("commit_hash"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    return {
        "cve_id": cve_id,
        "classified_refs": grouped_refs,
        "repo_urls": sorted(repo_urls),
        "commit_data": merged,
        "statistics": {
            "repos_found": len(repo_urls),
            "seed_commits": len(seed_commits),
            "crawled_commits": len(crawled_commits),
            "total_unique_commits": len(merged),
        },
    }