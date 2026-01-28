# Hente CVE data som ID, 
# Ha med tittel som ligger under containers og cna. 
# objekt som henter Referanse Url.  så fetch_commit.py henter og soterer etter hva som er link til reposoroty, commits, etc.... hva som hører til hva basicly
# under affected skal du ha med product.
# ------------------------------------------------------- #

# Koden skal lese inn cve data:

import json
def load_cve_from_file(filepath):
    with open(filepath, 'r', ) as f:
        return json.load(f)
    
# Dette er en test: for og sjekke at filen leser riktig
if __name__ == "__main__":
    data = load_cve_from_file("../../data/raw/cve/CVE-2026-24001.json")
    print("JSON-DATA is loaded")
    print("CVE-ID:", data["cveMetadata"]["cveId"])
    
    
    
   


