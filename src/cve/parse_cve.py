# denne filen skal trekke ut og strukturere den rellevante dataen fra CVE

from collections import defaultdict
import re 
from urllib.parse import urlparse



#----------------------------------
# Funkjon for CVE informasjon
#----------------------------------

def extract_cve_info(cve_data):
    cve_id = cve_data["cveMetadata"]["cveId"]
    title = cve_data["containers"]["cna"]["title"]
    return cve_id, title

# Funksjon som skal retunere en lisste med berørte produkter
def extract_products(cve_data):
    
    # Retunerer en lisste over berørte produkter. 
    affected = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("affected", [])
        )
    return [entry.get("product", "") for entry in affected if entry.get("product")]

#----------------------------
# Funkjson for Description
#----------------------------
def extract_description(cve_data, lang="en"):
    # henter CVE beskrivelse bassert på språk

    description = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("descriptions", [])
    )
    
    for desc in description:
        if desc.get("lang", "") == lang:
            return desc.get("value", "Description is not available")
    
    return "Description is not collected"

#-------------------------
# Funkjson for CWE ID
#-------------------------
def extract_cwe_ids(cve_data):
    # Henter alle unike CWE-id fra problemTypes
    cwe_ids = set()

    problem_types = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("problemTypes", [])
    )

    for problem in problem_types:
        descriptions = problem.get("descriptions", [])
        for desc in descriptions:
            if desc.get("type") == "CWE" and desc.get("cweId"):
                cwe_ids.add(desc.get("cweId"))

    return list(cwe_ids)

    
#-------------------------------------------
# Funkjonfor å hente CVSS score og severity
#---------------------------------------------
def extract_cvss_score(cve_data):
    
    metrics = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("metrics", {})
    )   
    
    for metrics in metrics:
        if "cvssV4_0" in metrics:
            cvss = metrics["cvssV4_0"]
            return {
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString"),
                "version": cvss.get("version")
            }
        return None
#-----------------------------
# Funksjon for refrences
#-----------------------------

def extract_grouped_references(cve_data):
    # grupperer referanser etter typene deres

    refs = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("references", [])
    )

    grouped = {
        "commit": [],
        "pull": [],
        "issues": [],
        "repo": [],
        "security-advisories": [],
        "other": []
    }

    for ref in refs:
        url = ref.get("url", "")
        parsed = urlparse(url)
        path = parsed.path.lower()

        # presis commit identifikasjon
        if re.search(r"/commit/[0-9a-f]{40}/?", path):
            grouped["commit"].append(url)

        elif re.search(r"/pull/\d+", path):
            grouped["pull"].append(url)

        elif re.search(r"/issues/\d+", path):
            grouped["issues"].append(url)

        elif re.search(r"/repo/\d+", path):
            grouped["repo"].append(url)

        elif re.search(r"/security/advisories/", path):
            grouped["security-advisories"].append(url)

        else:
            grouped["other"].append(url)

    return grouped


#--------------------------------
# Funksjon for enkel validering av CVE-data
#--------------------------------
def validate_cve_data(cve_data):
    
    if not isinstance(cve_data, dict):
        return False, "CVE data must be a dictonary"
    
    required_top_fields = ["dataType", "dataVersion", "cveMetadata", "containers"]
    for field in required_top_fields:
        if field not in cve_data:
            return False, f"Missing top-level field: {field}"
        
# Validere CVE-ID format
    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
    if not re.match(r"CVE-\d{4}-\d{4,7}", cve_id):
        return False, "Invalid CVE ID format"
    
# Sjekk at CNA-containers finnes
    if "cna" not in cve_data.get("containers", {}):
        return False, "Missing containers.cna section"
    
    return True, "Validation passed"



# ---------------------------
# Test-blokk
# ---------------------------
if __name__ == "__main__":

    from src.cve.fetch_cve import load_cve_from_file

    # Last inn CVE-fil
    data = load_cve_from_file("data/raw/cve/CVE-2026-24001.json")

    # ---------------------------
    # 1. Valider data først
    # ---------------------------
    is_valid, message = validate_cve_data(data)

    if not is_valid:
        print(f"Validation failed: {message}")
        exit()

    print("Validation successful!\n")

    # ---------------------------
    # 2. Grunnleggende CVE-info
    # ---------------------------
    cve_id, title = extract_cve_info(data)
    print("CVE INFO:")
    print(f"ID: {cve_id}")
    print(f"Title: {title}")

    # ---------------------------
    # 3. CWE
    # ---------------------------
    print("\nCWE IDs:")
    cwe_ids = extract_cwe_ids(data)
    for cwe in cwe_ids:
        print(f"  - {cwe}")

    # ---------------------------
    # 4. CVSS
    # ---------------------------
    print("\nCVSS INFO:")
    cvss = extract_cvss_score(data)

    if cvss:
        print(f"Score: {cvss['score']}")
        print(f"Severity: {cvss['severity']}")
        print(f"Vector: {cvss['vector']}")
        print(f"Version: {cvss['version']}")
    else:
        print("No CVSS data found")

    # ---------------------------
    # 5. References
    # ---------------------------
    print("\nREFERENCES:")
    refs = extract_grouped_references(data)

    for category, urls in refs.items():
        if urls:
            print(f"\n{category.upper()}:")
            for url in urls:
                print(f"  - {url}")

    # ---------------------------
    # 6. Products
    # ---------------------------
    print("\nPRODUCTS:")
    products = extract_products(data)
    for product in products:
        print(f"  - {product}")

    # ---------------------------
    # 7. Description
    # ---------------------------
    print("\nDESCRIPTION:")
    print(extract_description(data))
