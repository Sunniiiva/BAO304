import re
from src.repo.utils import extract_repo_and_hash, fetch_commit_data
from src.cve.parse_cve import extract_grouped_references


# Koble commits til CVE-IDer via enkel regex matching



def extract_cve_from_commit(commit_message):
    """
    Ekstraher CVE-IDer fra commit message via regex.

    """
    pattern = r'CVE-\d{4}-\d{4,}'
    matches = re.findall(pattern, commit_message, re.IGNORECASE)
    return list(set(cve.upper() for cve in matches))


def link_cve_to_commits(cve_id, commit_data_list):
    """
    Kobler CVE-ID til commits med ENKEL true/false klassifisering.

    """
    enriched_commits = []
    
    for commit in commit_data_list:
        # Skip error commits
        if 'error' in commit:
            enriched_commits.append(commit)
            continue
        
        commit_msg = commit.get('commit_message', '')
        
        # Sjekk om VÅR CVE-ID finnes i commit message
        mentioned_cves = extract_cve_from_commit(commit_msg)
        mentions_target_cve = cve_id in mentioned_cves
        
        # Legg til ENKELT boolean flagg
        enriched_commit = {
            **commit,
            'mentioned_cves': mentioned_cves,      # Alle CVEs funnet
            'mentions_target_cve': mentions_target_cve  # True/False
        }
        
        enriched_commits.append(enriched_commit)
        
        # Logging
        if mentions_target_cve:
            print(f"Commit nevner {cve_id} direkte!")
    
    return enriched_commits


def process_cve_references(cve_data):
    """
    Hovedfunksjon: Prosesser CVE -> hent commits -> boolean CVE-linking.

    """
    cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'unknown')
    grouped_refs = extract_grouped_references(cve_data)
    
    results = {
        'cve_id': cve_id,
        'classified_refs': grouped_refs,
        'commit_data': []
    }
    
    # Hent alle commit data
    for commit_url in grouped_refs.get('commit', []):
        info = extract_repo_and_hash(commit_url)
        if info:
            print(f"\nHenter commit: {info['commit_hash'][:8]}...")
            commit_data = fetch_commit_data(info['repo_url'], info['commit_hash'])
            results['commit_data'].append(commit_data)
    
    # Boolean CVE-linking
    print(f"\nAnalyserer CVE-referanser for {cve_id}...")
    results['commit_data'] = link_cve_to_commits(cve_id, results['commit_data'])
    
    # ENKEL statistikk
    total_commits = len(results['commit_data'])
    cve_mentions = sum(1 for c in results['commit_data'] if c.get('mentions_target_cve', False))
    
    results['statistics'] = {
        'total_commits': total_commits,
        'commits_mentioning_cve': cve_mentions,
        'commits_without_cve_mention': total_commits - cve_mentions
    }
    
    print(f"\nResultat:")
    print(f"  Total commits: {total_commits}")
    print(f"  Nevner CVE direkte: {cve_mentions}")
    print(f"  Uten CVE-nevnelse: {total_commits - cve_mentions}")
    
    return results
