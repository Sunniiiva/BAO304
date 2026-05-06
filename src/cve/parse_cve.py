import re
from urllib.parse import urlparse

# ----------------------------------
# Funksjon for CVE informasjon
# ----------------------------------
def extract_cve_info(cve_data):

    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "UNKNOWN")

    cna = cve_data.get("containers", {}).get("cna", {})
    title = cna.get("title")

    # Hvis CNA-title mangler, bruk første description
    if not title:
        descriptions = cna.get("descriptions", [])
        if descriptions:
            title = descriptions[0].get("value", "No title available")
        else:
            title = "No title available"

    return cve_id, title


#--------------------------------------------
# Funkjon som viser STATE data til cve filen
#---------------------------------------------
def extract_state(cve_data):
    return cve_data.get("cveMetadata", {}).get("state", "UNKNOWN")
                                               
                                               
# ----------------------------------
# Funksjon for Products
# ----------------------------------
def extract_products(cve_data):

    affected = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("affected", [])
    )

    return [
        entry.get("product", "")
        for entry in affected
        if entry.get("product")
    ]

# ------------------------------------------
# Funksjon for Description: henter ut navnene 
# på produktene som er berørt av sårbarheten
# -------------------------------------------
def extract_description(cve_data, lang="en"):

    descriptions = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("descriptions", [])
    )

    for desc in descriptions:
        if desc.get("lang", "") == lang:
            return desc.get("value", "Description not available")

    return "Description not collected"


# ---------------------------------------------------------------------
# Funksjon for CWE ID: Henter ut alle CWE-IDer som er knyttet til CVEen
# ----------------------------------------------------------------------
def extract_cwe_ids(cve_data):

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


# --------------------------------------------
# Funksjon for CVSS score og severity:        
# Henter CVSS-score og serverity fra en CVE,  
# og velder den høyeste versjonen automatisk  
# ---------------------------------------------
def extract_cvss_score(cve_data):

    metrics_list = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("metrics", [])
    )

    best_cvss = None
    best_version = 0.0  # start på 0, ikke None

    for metric in metrics_list:
        for key, value in metric.items():

            # Sjekk at nøkkelen starter med "cvssV"
            if key.startswith("cvssV") and isinstance(value, dict):

                version = value.get("version", "")

                try:
                    version_number = float(version)
                except (ValueError, TypeError):
                    continue

                # Velg høyeste versjon
                if version_number > best_version:
                    best_version = version_number
                    best_cvss = {
                        "score": value.get("baseScore"),
                        "severity": value.get("baseSeverity"),
                        "vector": value.get("vectorString"),
                        "version": version
                    }

    return best_cvss

# ------------------------------------------------------------
# Funksjon for å grupere referanser
# Grupperer CVE-referanser etter type
# Brukes for å identifisere commits til videre patch-analye
# -------------------------------------------------------------
def extract_grouped_references(cve_data):
    refs = (
        cve_data
        .get("containers", {})
        .get("cna", {})
        .get("references", [])
    )

    grouped = {
        "commit": [],
        "pull": [],
        "security-advisories": [],
        "other": []
    }

    for ref in refs:
        url = ref.get("url")

        if not url:
            continue

        parsed = urlparse(url)
        path = parsed.path.lower()

        if "/commit/" in path:
            grouped["commit"].append(url)

        elif "/pull/" in path:
            grouped["pull"].append(url)

        elif "/security/advisories/" in path:
            grouped["security-advisories"].append(url)

        else:
            grouped["other"].append(url)

    return grouped


# ----------------------------------
# Enkel validering av CVE-data
# ----------------------------------

def validate_cve_data(cve_data):

    if not isinstance(cve_data, dict):
        return False, "CVE data must be a dictionary"

    required_top_fields = ["dataType", "dataVersion", "cveMetadata", "containers"]

    for field in required_top_fields:
        if field not in cve_data:
            return False, f"Missing top-level field: {field}"

    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")

    # sjekker at CVE id har riktig format
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return False, "Invalid CVE ID format"
      
      # Sjekker at containers.cna finnes
    if "cna" not in cve_data.get("containers", {}):
        return False, "Missing containers.cna section"
     
    return True, "Validation passed"
