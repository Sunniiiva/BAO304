"""
Testfil for BAO304 - CVE og patch-analyse pipeline
Tester parse_cve, parse_patch og file_filter modulene
"""

import sys
import os

# Legg til src i path slik at imports fungerer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import pytest

from cve.parse_cve import (
    extract_cve_info,
    extract_state,
    extract_products,
    extract_description,
    extract_cwe_ids,
    extract_cvss_score,
    extract_grouped_references,
    validate_cve_data,
)
from patch.parse_patch import parse_patch
from patch.file_filter import should_skip_file


# ============================================================
# Hjelpefunksjon: lager et minimalt gyldig CVE-dataobjekt
# ============================================================

def make_cve(
    cve_id="CVE-2023-12345",
    title="Test sårbarhet",
    state="PUBLISHED",
    products=None,
    descriptions=None,
    cwe_ids=None,
    cvss_version="3.1",
    cvss_score=7.5,
    cvss_severity="HIGH",
    references=None,
):
    """Lager et minimalt, gyldig CVE-dataobjekt for testing."""
    affected = [{"product": p} for p in (products or ["TestProduct"])]
    desc_list = descriptions or [{"lang": "en", "value": "En test-beskrivelse."}]
    problem_types = []
    if cwe_ids:
        problem_types = [
            {"descriptions": [{"type": "CWE", "cweId": cid} for cid in cwe_ids]}
        ]
    metrics = []
    if cvss_score is not None:
        metrics = [
            {
                f"cvssV{cvss_version.replace('.', '_')}": {
                    "version": cvss_version,
                    "baseScore": cvss_score,
                    "baseSeverity": cvss_severity,
                    "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            }
        ]

    ref_list = references or []

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {"cveId": cve_id, "state": state},
        "containers": {
            "cna": {
                "title": title,
                "affected": affected,
                "descriptions": desc_list,
                "problemTypes": problem_types,
                "metrics": metrics,
                "references": ref_list,
            }
        },
    }


# ============================================================
# Tester for extract_cve_info
# ============================================================

class TestExtractCveInfo:

    def test_returnerer_id_og_tittel(self):
        data = make_cve(cve_id="CVE-2023-00001", title="Buffer overflow")
        cve_id, title = extract_cve_info(data)
        assert cve_id == "CVE-2023-00001"
        assert title == "Buffer overflow"

    def test_bruker_description_naar_title_mangler(self):
        data = make_cve(descriptions=[{"lang": "en", "value": "Ingen tittel, kun desc"}])
        # Fjern title fra cna
        data["containers"]["cna"].pop("title")
        _, title = extract_cve_info(data)
        assert title == "Ingen tittel, kun desc"

    def test_fallback_naar_ingenting_finnes(self):
        data = make_cve()
        data["containers"]["cna"].pop("title")
        data["containers"]["cna"]["descriptions"] = []
        _, title = extract_cve_info(data)
        assert title == "No title available"

    def test_ukjent_id_naar_metadata_mangler(self):
        cve_id, _ = extract_cve_info({})
        assert cve_id == "UNKNOWN"


# ============================================================
# Tester for extract_state
# ============================================================

class TestExtractState:

    def test_published(self):
        assert extract_state(make_cve(state="PUBLISHED")) == "PUBLISHED"

    def test_rejected(self):
        assert extract_state(make_cve(state="REJECTED")) == "REJECTED"

    def test_ukjent_state(self):
        assert extract_state({}) == "UNKNOWN"


# ============================================================
# Tester for extract_products
# ============================================================

class TestExtractProducts:

    def test_ett_produkt(self):
        assert extract_products(make_cve(products=["Linux kernel"])) == ["Linux kernel"]

    def test_flere_produkter(self):
        result = extract_products(make_cve(products=["nginx", "Apache", "OpenSSL"]))
        assert set(result) == {"nginx", "Apache", "OpenSSL"}

    def test_tomt_naar_ingen_produkter(self):
        data = make_cve()
        data["containers"]["cna"]["affected"] = []
        assert extract_products(data) == []


# ============================================================
# Tester for extract_description
# ============================================================

class TestExtractDescription:

    def test_engelsk_beskrivelse(self):
        data = make_cve(descriptions=[{"lang": "en", "value": "En sårbarhet ble funnet."}])
        assert extract_description(data) == "En sårbarhet ble funnet."

    def test_annet_sprak_mangler(self):
        data = make_cve(descriptions=[{"lang": "en", "value": "Only English"}])
        result = extract_description(data, lang="fr")
        assert result == "Description not collected"

    def test_tom_liste(self):
        data = make_cve()
        data["containers"]["cna"]["descriptions"] = []
        assert extract_description(data) == "Description not collected"


# ============================================================
# Tester for extract_cwe_ids
# ============================================================

class TestExtractCweIds:

    def test_en_cwe(self):
        result = extract_cwe_ids(make_cve(cwe_ids=["CWE-79"]))
        assert "CWE-79" in result

    def test_flere_cwe(self):
        result = extract_cwe_ids(make_cve(cwe_ids=["CWE-79", "CWE-89", "CWE-22"]))
        assert set(result) == {"CWE-79", "CWE-89", "CWE-22"}

    def test_ingen_cwe(self):
        data = make_cve()
        data["containers"]["cna"]["problemTypes"] = []
        assert extract_cwe_ids(data) == []


# ============================================================
# Tester for extract_cvss_score
# ============================================================

class TestExtractCvssScore:

    def test_cvss_v3(self):
        result = extract_cvss_score(make_cve(cvss_version="3.1", cvss_score=9.8, cvss_severity="CRITICAL"))
        assert result is not None
        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["version"] == "3.1"

    def test_ingen_metrics(self):
        data = make_cve()
        data["containers"]["cna"]["metrics"] = []
        assert extract_cvss_score(data) is None

    def test_velger_hoeyeste_versjon(self):
        """Når det finnes to CVSS-versjoner skal den høyeste velges."""
        data = make_cve()
        data["containers"]["cna"]["metrics"] = [
            {"cvssV2_0": {"version": "2.0", "baseScore": 6.0, "baseSeverity": "MEDIUM", "vectorString": "x"}},
            {"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "y"}},
        ]
        result = extract_cvss_score(data)
        assert result["version"] == "3.1"
        assert result["score"] == 9.8


# ============================================================
# Tester for extract_grouped_references
# ============================================================

class TestExtractGroupedReferences:

    def test_commit_url(self):
        refs = [{"url": "https://github.com/owner/repo/commit/abc123"}]
        result = extract_grouped_references(make_cve(references=refs))
        assert "https://github.com/owner/repo/commit/abc123" in result["commit"]

    def test_pull_url(self):
        refs = [{"url": "https://github.com/owner/repo/pull/42"}]
        result = extract_grouped_references(make_cve(references=refs))
        assert result["pull"][0].endswith("/pull/42")

    def test_advisory_url(self):
        refs = [{"url": "https://github.com/owner/repo/security/advisories/GHSA-xxxx"}]
        result = extract_grouped_references(make_cve(references=refs))
        assert result["security-advisories"]

    def test_other_url(self):
        refs = [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"}]
        result = extract_grouped_references(make_cve(references=refs))
        assert result["other"]

    def test_ingen_referanser(self):
        result = extract_grouped_references(make_cve(references=[]))
        assert result == {"commit": [], "pull": [], "security-advisories": [], "other": []}


# ============================================================
# Tester for validate_cve_data
# ============================================================

class TestValidateCveData:

    def test_gyldig_data(self):
        valid, msg = validate_cve_data(make_cve())
        assert valid is True
        assert "passed" in msg.lower()

    def test_ikke_dict(self):
        valid, msg = validate_cve_data("ikke et dict")
        assert valid is False

    def test_mangler_topfelt(self):
        data = make_cve()
        del data["containers"]
        valid, msg = validate_cve_data(data)
        assert valid is False
        assert "containers" in msg

    def test_ugyldig_cve_id_format(self):
        data = make_cve()
        data["cveMetadata"]["cveId"] = "IKKE-GYLDIG"
        valid, msg = validate_cve_data(data)
        assert valid is False

    def test_mangler_cna(self):
        data = make_cve()
        del data["containers"]["cna"]
        valid, msg = validate_cve_data(data)
        assert valid is False


# ============================================================
# Tester for parse_patch
# ============================================================

class TestParsePatch:

    def test_enkel_patch(self):
        patch = (
            "@@ -1,3 +1,3 @@\n"
            " context\n"
            "-gammel linje\n"
            "+ny linje\n"
        )
        result = parse_patch(patch)
        assert result["added_lines"] == 1
        assert result["removed_lines"] == 1
        assert result["hunk_count"] == 1
        assert "ny linje" in result["after_code"]
        assert "gammel linje" in result["before_code"]

    def test_tom_patch(self):
        result = parse_patch(None)
        assert result["added_lines"] == 0
        assert result["removed_lines"] == 0
        assert result["before_code"] == ""
        assert result["after_code"] == ""

    def test_bare_tillegg(self):
        patch = "@@ -0,0 +1,2 @@\n+linje1\n+linje2\n"
        result = parse_patch(patch)
        assert result["added_lines"] == 2
        assert result["removed_lines"] == 0

    def test_bare_fjerning(self):
        patch = "@@ -1,2 +0,0 @@\n-gammel1\n-gammel2\n"
        result = parse_patch(patch)
        assert result["added_lines"] == 0
        assert result["removed_lines"] == 2

    def test_flere_hunks(self):
        patch = (
            "@@ -1,2 +1,2 @@\n-a\n+b\n"
            "@@ -10,2 +10,2 @@\n-c\n+d\n"
        )
        result = parse_patch(patch)
        assert result["hunk_count"] == 2

    def test_changed_lines_er_sum(self):
        patch = "@@ -1,3 +1,3 @@\n-x\n-y\n+z\n"
        result = parse_patch(patch)
        assert result["changed_lines"] == result["added_lines"] + result["removed_lines"]


# ============================================================
# Tester for should_skip_file (file_filter)
# ============================================================

class TestShouldSkipFile:

    # Filer som SKAL hoppes over
    def test_skip_markdown(self):
        assert should_skip_file("README.md") is True

    def test_skip_yaml(self):
        assert should_skip_file("config/settings.yml") is True

    def test_skip_json(self):
        assert should_skip_file("package.json") is True

    def test_skip_docs_mappe(self):
        assert should_skip_file("docs/guide.py") is True

    def test_skip_test_mappe(self):
        assert should_skip_file("tests/test_utils.py") is True

    def test_skip_bilderfil(self):
        assert should_skip_file("assets/logo.png") is True

    def test_skip_tom_streng(self):
        assert should_skip_file("") is True

    def test_skip_none(self):
        assert should_skip_file(None) is True

    # Filer som IKKE skal hoppes over
    def test_behold_python_fil(self):
        assert should_skip_file("src/auth/login.py") is False

    def test_behold_c_fil(self):
        assert should_skip_file("lib/crypto/aes.c") is False

    def test_behold_java_fil(self):
        assert should_skip_file("src/main/Security.java") is False

    def test_behold_go_fil(self):
        assert should_skip_file("pkg/server/handler.go") is False
