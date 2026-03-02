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
        "repo": [],
        "commit": [],
        "pull": [],
        "issue": [],
        "security-advisories": [],
        "other": []
    }

    seen = {k: set() for k in grouped.keys()}

    # GitHub paths that are NOT git repos
    NON_REPO_TOPLEVEL = {"advisories", "security", "login", "settings", "marketplace"}

    for ref in refs:
        url = ref.get("url") or ref.get("name")
        if not url:
            continue

        parsed = urlparse(url)
        path = parsed.path or ""
        path_lower = path.lower()

        # --- classify first ---
        if "github.com/advisories/" in url.lower() or "/security/advisories/" in path_lower:
            if url not in seen["security-advisories"]:
                grouped["security-advisories"].append(url)
                seen["security-advisories"].add(url)
            # IMPORTANT: do NOT treat this as a repo
            continue

        if "/commit/" in path_lower:
            if url not in seen["commit"]:
                grouped["commit"].append(url)
                seen["commit"].add(url)

        elif "/pull/" in path_lower:
            if url not in seen["pull"]:
                grouped["pull"].append(url)
                seen["pull"].add(url)

        elif "/issues/" in path_lower:
            if url not in seen["issue"]:
                grouped["issue"].append(url)
                seen["issue"].add(url)

        else:
            if url not in seen["other"]:
                grouped["other"].append(url)
                seen["other"].add(url)

        # --- repo extraction (ONLY owner/repo) ---
        if parsed.netloc.lower().endswith("github.com"):
            parts = [p for p in path.strip("/").split("/") if p]
            # Need at least owner/repo
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                # Skip non-repo top-level paths like /advisories/...
                if owner.lower() in NON_REPO_TOPLEVEL:
                    continue
                base_repo = f"https://github.com/{owner}/{repo}"
                if base_repo not in seen["repo"]:
                    grouped["repo"].append(base_repo)
                    seen["repo"].add(base_repo)

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

# ----------------------------------------------------
# Test for og se hvordan koden kan kjøre i terminal (main.py)
# ------------------------------------------------------

if __name__ == "__main__":

    from pathlib import Path
    from src.cve.fetch_cve import load_cve_from_file

    cve_folder = Path("data/raw/cve")

    if not cve_folder.exists():
        print("CVE-mappen finnes ikke.")
        exit()

    total_files = 0
    processed = 0
    skipped_rejected = 0
    skipped_invalid = 0

    for file in cve_folder.glob("*.json"):

        total_files += 1

        print("\n" + "=" * 60)
        print(f"Processing: {file.name}")
        print("=" * 60)

        try:
            data = load_cve_from_file(file)

            # -------------------
            # 1. Valider
            # -------------------
            is_valid, message = validate_cve_data(data)
            if not is_valid:
                print(f"Skipping (validation failed): {message}")
                skipped_invalid += 1
                continue

            # -------------------
            # 2. Hent metadata
            # -------------------
            cve_id, title = extract_cve_info(data)
            state = extract_state(data)

            # -------------------
            # 3. Hopp over REJECTED
            # -------------------
            if state == "REJECTED":
                print(f"\nID: {cve_id}")
                print("State: REJECTED")
                print("Skipping REJECTED CVE")
                skipped_rejected += 1
                continue

            # -------------------
            # 4. Print grunninfo
            # -------------------
            print(f"\nID: {cve_id}")
            print(f"State: {state}")
            print(f"Title: {title}")

            # -------------------
            # 5. CWE
            # -------------------
            cwe_ids = extract_cwe_ids(data)
            print(f"CWE: {', '.join(cwe_ids) if cwe_ids else 'None'}")

            # -------------------
            # 6. CVSS
            # -------------------
            cvss = extract_cvss_score(data)
            if cvss:
                print(f"CVSS Score: {cvss['score']} ({cvss['severity']})")
            else:
                print("CVSS: Not available")

            # -------------------
            # 7. References
            # -------------------
            grouped_refs = extract_grouped_references(data)

            print("References:")
            for ref_type, urls in grouped_refs.items():
                if urls:
                    print(f"  {ref_type}: {len(urls)}")

            processed += 1

        except Exception as e:
            print(f"Error processing {file.name}: {e}")

    # -------------------
    # Sluttstatistikk
    # -------------------
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total files: {total_files}")
    print(f"Processed CVE: {processed}")
    print(f"Skipped REJECTED: {skipped_rejected}")
    print(f"Skipped invalid: {skipped_invalid}")
