import json
import re
import os
from datetime import datetime
from pydriller import Repository
from src.cve.parse_cve import extract_grouped_references


output_dir = 'data/raw/commits'
os.makedirs(output_dir, exist_ok=True)





# Formål: Ekstrahere commit metadata og diffs fra GitHub repositories



def extract_repo_and_hash(commit_url):
    """
    Trekker ut repository URL og commit hash fra en GitHub commit URL.
    
    """
    match = re.match(r'(https://github\.com/[^/]+/[^/]+)/commit/([a-f0-9]+)', commit_url)
    if match:
        return {
            'repo_url': match.group(1),
            'commit_hash': match.group(2)
        }
    return None


def fetch_commit_data(repo_url, commit_hash):
    """
    Henter commit metadata og filendringer ved hjelp av PyDriller.
    
    """
    print(f"  Prøver å klone: {repo_url}")
    print(f"  Henter commit: {commit_hash}")
    
    try:
        # PyDriller håndterer automatisk repository kloning og caching
        for commit in Repository(repo_url, single=commit_hash).traverse_commits():
            print(f"  Commit funnet")
            modified_files = []
            
            # Prosesser hver modifisert fil i commiten
            for mod in commit.modified_files:
                modified_files.append({
                    'file_path': mod.new_path or mod.old_path,  # Håndterer renames/deletions
                    'change_type': mod.change_type.name,        # ADD, MODIFY, DELETE, RENAME
                    'added_lines': mod.added_lines,
                    'deleted_lines': mod.deleted_lines,
                    'patch_text': mod.diff  # Full unified diff output
                })
            
            # Strukturer data for videre prosessering (Sunniva sin patch modul)
            result = {
                'repo_url': repo_url,
                'commit_hash': commit.hash,
                'commit_message': commit.msg,
                'commit_date': commit.committer_date.isoformat(),
                'author': commit.author.name,
                'modified_files': modified_files
            }
            print(f"  Data hentet: {len(modified_files)} filer modifisert")
            return result
            
    except Exception as e:
        # Returner feilinformasjon for debugging/logging
        print(f"  FEIL: {e}")
        return {'error': str(e), 'repo_url': repo_url, 'commit_hash': commit_hash}


def fetch_commit_modified_files(repo_url, commit_hash):
    """
    Hjelpefunksjon for patch processing modulen (Sunniva sin fetch_patch.py).

    """
    commit_data = fetch_commit_data(repo_url, commit_hash)
    
    # Håndter feil ved å returnere tom array
    if 'error' in commit_data:
        return []
    
    return commit_data.get('modified_files', [])


def process_cve_references(cve_data):
    """
    Prosesserer alle commit referanser fra en CVE record.

    """
    cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'unknown')
    
    
    # Returnerer dict med nøkler: 'commit', 'pull', 'issues', 'security-advisories'
    grouped_refs = extract_grouped_references(cve_data)
    
    results = {
        'cve_id': cve_id,
        'classified_refs': grouped_refs,
        'commit_data': []
    }
    
    # Prosesser hver commit referanse
    for commit_url in grouped_refs.get('commit', []):
        info = extract_repo_and_hash(commit_url)
        if info:
            print(f"\nHenter commit: {info['commit_hash'][:8]}...")
            commit_data = fetch_commit_data(info['repo_url'], info['commit_hash'])
            results['commit_data'].append(commit_data)
    
    return results


def save_results(results, cve_id):
    """
    Lagrer commit data til JSON fil.

    """
    filepath = os.path.join(output_dir, f"{cve_id}_commits.json")
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nLagret til {filepath}")
    return filepath


if __name__ == "__main__":
    import glob
    from src.cve.fetch_cve import load_cve_from_file
    
    # Forsøk å prosessere alle CVE filer i data directory
    cve_files = glob.glob('data/raw/cve/*.json')
    
    if not cve_files:
        print("ADVARSEL: Ingen CVE filer funnet i data/raw/cve/")
        print("Bruker hardkodet testdata for demonstrasjon...")
        
        # Fallback testdata som matcher NVD JSON format
        test_cve = {
            "cveMetadata": {"cveId": "CVE-2026-24001"},
            "containers": {
                "cna": {
                    "references": [
                        {"url": "https://github.com/kpdecker/jsdiff/commit/15a1585230748c8ae6f8274c202e0c87309142f5"}
                    ]
                }
            }
        }
        results = process_cve_references(test_cve)
        save_results(results, test_cve['cveMetadata']['cveId'])
    else:
        print(f"Prosesserer {len(cve_files)} CVE filer...\n")
        
        # Prosesser hver CVE fil sekvensiellt
        for cve_file in cve_files:
            print(f"Leser: {cve_file}")
            cve_data = load_cve_from_file(cve_file)  
            
            results = process_cve_references(cve_data)
            save_results(results, results['cve_id'])
    
    print("\nProsessering fullført.")
