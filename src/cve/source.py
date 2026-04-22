#-----------------------------------------------------------------------
# Funksjoner for å hente CVE-data fra offisiell kilde (cvelistV5 på GitHub).
#-----------------------------------------------------------------------

#imports
from __future__ import annotations

import io
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Generator, Iterable

import requests

#filsti til latest release zip på GitHub
GITHUB_RELEASES_LATEST_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

#-----------------------------------------------------------------------
# Funksjon for å hente metadata om nyeste release 
#-----------------------------------------------------------------------
def get_latest_release_info() -> dict:
    """
    Henter metadata om nyeste offisielle release fra cvelistV5.
    """
    response = requests.get(GITHUB_RELEASES_LATEST_API, timeout=60)
    response.raise_for_status()
    return response.json()

#-----------------------------------------------------------------------
# Funksjon for å finne zip-asset i nyeste release
#-----------------------------------------------------------------------
def find_release_zip_asset(release_data: dict) -> tuple[str, str]:
    """
    Finner zip-asset i GitHub-release.
    Returnerer (filnavn, download_url).
    """
    assets = release_data.get("assets", [])
    for asset in assets:
        name = asset.get("name", "")
        download_url = asset.get("browser_download_url", "")
        if name.endswith(".zip") and download_url:
            return name, download_url

    raise RuntimeError("Fant ingen zip-asset i latest cvelistV5 release.")

#-----------------------------------------------------------------------
# Funksjon for å laste ned release-zip til en midlertidig fil
#-----------------------------------------------------------------------
def download_release_zip(download_url: str) -> Path:
    """
    Laster ned release-zip til en midlertidig fil og returnerer path.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp_path = Path(tmp.name)

    with requests.get(download_url, stream=True, timeout=300) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                tmp.write(chunk)

    tmp.close()
    return tmp_path

#-----------------------------------------------------------------------
# Funksjon for å iterere gjennom CVE-records fra en zip-fil
#-----------------------------------------------------------------------
def iter_cve_records_from_zip(zip_path: str | Path):
    zip_path = Path(zip_path)

    with zipfile.ZipFile(zip_path, "r") as outer_zip:

        for info in outer_zip.infolist():
            normalized_outer = info.filename.replace("\\", "/")
            normalized_outer_lower = normalized_outer.lower()
            outer_name = Path(normalized_outer).name

            # Hvis filen er en nested zip, åpne den også
            if normalized_outer_lower.endswith(".zip"):
                with outer_zip.open(info) as nested_file:
                    nested_bytes = nested_file.read()

                with zipfile.ZipFile(io.BytesIO(nested_bytes), "r") as inner_zip:
                    for inner_info in inner_zip.infolist():
                        filename = inner_info.filename.replace("\\", "/")
                        normalized = filename.lower()
                        base_name = Path(filename).name

                        if not normalized.endswith(".json"):
                            continue

                        # VIKTIG: kun ekte CVE-records under cves/
                        if not normalized.startswith("cves/"):
                            continue

                        if not base_name.startswith("CVE-"):
                            continue

                        try:
                            with inner_zip.open(inner_info, "r") as raw_file:
                                text_file = io.TextIOWrapper(raw_file, encoding="utf-8")
                                data = json.load(text_file)

                            if not isinstance(data, dict):
                                print(f"Skipper ikke-CVE JSON (ikke dict): {filename}")
                                continue

                            yield data

                        except json.JSONDecodeError:
                            print(f"JSON decode-feil: {filename}")
                            continue
                        except UnicodeDecodeError:
                            print(f"Unicode-feil: {filename}")
                            continue

            # Hvis det skulle ligge JSON direkte i ytterste zip
            elif normalized_outer_lower.endswith(".json"):
                if not normalized_outer_lower.startswith("cves/"):
                    continue

                if not outer_name.startswith("CVE-"):
                    continue

                try:
                    with outer_zip.open(info, "r") as raw_file:
                        text_file = io.TextIOWrapper(raw_file, encoding="utf-8")
                        data = json.load(text_file)

                    if not isinstance(data, dict):
                        print(f"Skipper ikke-CVE JSON (ikke dict): {info.filename}")
                        continue

                    yield data

                except json.JSONDecodeError:
                    print(f"JSON decode-feil: {info.filename}")
                    continue
                except UnicodeDecodeError:
                    print(f"Unicode-feil: {info.filename}")
                    continue


#-----------------------------------------------------------------------
# Funksjon for å iterere gjennom CVE-records fra den offisielle kilden
#-----------------------------------------------------------------------
def iter_cve_records_from_official_source() -> Generator[dict, None, None]:
    """
    Full pipeline:
    - finner latest release
    - laster ned zip
    - itererer over CVE records
    - rydder opp temp-fil til slutt
    """
    release_data = get_latest_release_info()
    _, download_url = find_release_zip_asset(release_data)
    zip_path = download_release_zip(download_url)

    try:
        yield from iter_cve_records_from_zip(zip_path)
    finally:
        zip_path.unlink(missing_ok=True)