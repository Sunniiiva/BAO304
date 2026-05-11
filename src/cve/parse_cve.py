import re
from urllib.parse import urlparse


# Function for CVE information

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



# Function that shows the STATE data from the CVE file

def extract_state(cve_data):
    return cve_data.get("cveMetadata", {}).get("state", "UNKNOWN")
                                               
                                               
# Function for products

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

# Function for Description: extracts the names
# of the products affected by the vulnerability

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


# Function for CWE ID: extracts all CWE IDs linked to the CVE
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


# Function for CVSS score and severity:
# Extracts the CVSS score and severity from a CVE,
# and automatically selects the highest available version 

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

# Function for grouping references
# Groups CVE references by type
# Used to identify commits for further patch analysis

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


# Simple validation of CVE data

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
