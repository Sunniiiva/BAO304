"""
cve package

Ansvar:
- Leser CVE JSON fra offisiell zip-kilde (source)
- Trekker ut/strukturere relevant CVE-data (parse_cve)
"""

from .source import (
    get_latest_release_info,
    find_release_zip_asset,
    download_release_zip,
    iter_cve_records_from_zip,
    iter_cve_records_from_official_source,
)

from .parse_cve import (
    extract_cve_info,
    extract_products,
    extract_grouped_references,
    extract_state,
    extract_cwe_ids,
    extract_cvss_score,
)

__all__ = [
    "get_latest_release_info",
    "find_release_zip_asset",
    "download_release_zip",
    "iter_cve_records_from_zip",
    "iter_cve_records_from_official_source",
    "extract_cve_info",
    "extract_products",
    "extract_grouped_references",
    "extract_state",
    "extract_cwe_ids",
    "extract_cvss_score",
]