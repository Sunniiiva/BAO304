import os
import glob
from src.cve.fetch_cve import load_cve_from_file
from src.repo.parse_commit import process_cve_references

def main():
    print("=" * 70)
    print("Commit fetcher")
    print("Hente commit data fra GitHub")
    print("=" * 70)
    
    cve_files = glob.glob('data/raw/cve/*.json')
    
    if not cve_files:
        print("\nIngen CVE filer funnet - Bruker testdata")
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
        print(f"Test-CVE fullført: {results['cve_id']}")
        print(f"{results['statistics']}")
    else:
        print(f"\nProsesserer {len(cve_files)} CVE filer")
        for cve_file in cve_files:
            print(f"\n{'='*70}")
            print(f"Leser: {cve_file}")
            print('='*70)
            
            cve_data = load_cve_from_file(cve_file)
            results = process_cve_references(cve_data)
            print(f"{results['cve_id']} fullført!")
    
    print("\n" + "=" * 70)
    print("Prosessering fullført ")
    print("=" * 70)

if __name__ == "__main__":
    main()
