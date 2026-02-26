"""
cve package

Ansvar:
- Leser CVE JSON fra fil (fetch_cve)
- Trekker ut/strukturere relevant CVE-data (parse_cve)
"""

from .fetch_cve import load_cve_from_file
from .parse_cve import (
    extract_cve_info,
    extract_products,
    extract_grouped_references,
    extract_state,
    extract_cwe_ids,
    extract_cvss_score,
)

__all__ = [
    "load_cve_from_file",
    "extract_cve_info",
    "extract_products",
    "extract_grouped_references",
    "extract_state",
    "extract_cwe_ids",
    "extract_cvss_score",
]

