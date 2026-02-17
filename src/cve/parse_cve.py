# denne filen skal trekke ut og strukturere den rellevante dataen fra CVE

from collections import defaultdict

# Funkjon som skal hente ut ID og tittel
def extract_cve_info(cve_data):
    meta = cve_data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "unknown")
    state = meta.get("state", "")

    cna = cve_data.get("containers", {}).get("cna", {})

    # Normal tittel hvis den finnes
    title = cna.get("title")

    # REJECTED: lag en tittel fra rejectedReasons
    if not title and state == "REJECTED":
        reasons = cna.get("rejectedReasons", [])
        reason = reasons[0].get("value") if reasons else None
        title = f"REJECTED: {reason}" if reason else "REJECTED"

    # Fallback: bruk første beskrivelse som “tittel”
    if not title:
        descs = cna.get("descriptions", [])
        title = (descs[0].get("value") if descs else None) or "Uten tittel"

    return cve_id, title


# Funksjon som skal retunere en lisste med berørte produkter
def extract_products(cve_data):
    affected = cve_data["containers"]["cna"].get("affected", [])
    return [entry["product"] for entry in affected]

# Funkjon som skal grupere referansene etter typen deres
# commit, pull, issues, repo, Security-advisories
def extract_grouped_references(cve_data):
    refs = cve_data["containers"]["cna"].get("references", [])
    grouped = defaultdict(list)

    for ref in refs:
        url = ref.get("url", "")
        if "commit" in url:
            grouped["commit"].append(url)
        elif "pull" in url:
            grouped["pull"].append(url)
        elif "issues" in url:
            grouped["issues"].append(url)
        elif "repo" in url:
            grouped["repo"].append(url)
        else:
            grouped["security-advisories"].append(url)

    return grouped


# ------------ TEST FOR OUTPUT ------------------------ #

if __name__ == "__main__":
    from fetch_cve import load_cve_from_file
    
    data = load_cve_from_file("../../data/raw/cve/CVE-2026-24001.json") 
    
    cve_id, title = extract_cve_info(data)
    print(f"\n CVE ID:", cve_id)
    print(f"Title:", title)
    
    products = extract_products(data)
    print("\n PRODUCTS:")
    for product in products:
        print(f" - {product}")
        
        grouped_refs = extract_grouped_references(data)
        print("\n REFRENCES (GROUPED BY TYPE):")
        for category, urls in grouped_refs.items():
            print(f"\n{category.upper()}:")
            for url in urls:
                print(f" - {url}")


        






