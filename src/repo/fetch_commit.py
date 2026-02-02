import json
import re
import os
import glob
from datetime import datetime
from pydriller import Repository
from src.cve.fetch_cve import load_cve_from_file
from src.repo.utils import extract_repo_and_hash, fetch_commit_data
from src.repo.parse_commit import process_cve_references

output_dir = 'data/raw/commits'
os.makedirs(output_dir, exist_ok=True)

# Commit fetcher modul

def extract_repo_and_hash(commit_url):
    """
    Trekker ut repository URL og commit hash fra en GitHub commit URL.
    
    """
    # Regex pattern: capture base repo URL og commit hash separat
    match = re.match(r'(https://github\.com/[^/]+/[^/]+)/commit/([a-f0-9]+)', commit_url)
    
    if match:
        return {
            'repo_url': match.group(1),
            'commit_hash': match.group(2)
        }
    
    return None


def fetch_commit_data(repo_url, commit_hash):
    """
    Henter full commit data fra GitHub repository via PyDriller.
    
    """
    print(f"  Prøver å klone: {repo_url}")
    print(f"  Henter commit: {commit_hash}")
    
    try:
        # PyDriller håndterer git operations automatisk
        # single=commit_hash gir direkte lookup av spesifikk commit
        for commit in Repository(repo_url, single=commit_hash).traverse_commits():
            print(f"  Commit funnet")
            
            modified_files = []
            
            # Iterer over alle modifiserte filer i commiten
            for mod in commit.modified_files:
                # Ekstraher relevant data fra ModifiedFile objekt
                file_data = {
                    'file_path': mod.new_path or mod.old_path,  # new_path er None ved deletion
                    'change_type': mod.change_type.name,        # Enum -> string
                    'added_lines': mod.added_lines,
                    'deleted_lines': mod.deleted_lines,
                    'patch_text': mod.diff
                }
                modified_files.append(file_data)
            
            # Bygg strukturert result objekt
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
        # Log error og returner error dict istedenfor å krasje
        print(f"  FEIL: {e}")
        return {
            'error': str(e), 
            'repo_url': repo_url, 
            'commit_hash': commit_hash
        }


def fetch_commit_modified_files(repo_url, commit_hash):
    """
    Hjelpefunksjon for downstream patch processing.

    """
    commit_data = fetch_commit_data(repo_url, commit_hash)
    
    # Returner tom liste ved error istedenfor None
    if 'error' in commit_data:
        return []
    
    return commit_data.get('modified_files', [])


def save_results(results, cve_id):
    """
    Serialiser og lagre results til JSON fil.
    
    """
    filepath = os.path.join(output_dir, f"{cve_id}_commits.json")
    
    # Skriv JSON med formatting for lesbarhet
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nLagret til {filepath}")
    return filepath



if __name__ == "__main__":

    
    print("=" * 70)
    print("Commit fetcher")
    print("Hente commit data fra GitHub")
    print("=" * 70)
    
    # Scan for CVE filer i data directory
    cve_files = glob.glob('data/raw/cve/*.json')
    
    if not cve_files:
        # Fallback til test data hvis ingen filer finnes
        print("\nIngen CVE filer funnet i data/raw/cve/")
        print("Bruker hardkodet test data for demonstrasjon\n")
        
        # Minimal valid NVD JSON struktur
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
        # Normal execution path: prosesser alle CVE filer
        print(f"\nProsesserer {len(cve_files)} CVE filer\n")
        
        for cve_file in cve_files:
            print(f"\n{'='*70}")
            print(f"Leser: {cve_file}")
            print('='*70)
            
            # Last CVE data fra fil 
            cve_data = load_cve_from_file(cve_file)
            
            # Prosesser CVE 
            results = process_cve_references(cve_data)
            
            # Lagre results
            save_results(results, results['cve_id'])
    
    print("\n" + "=" * 70)
    print("Prosessering fullført")
    print("=" * 70)
