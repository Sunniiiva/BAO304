import json
from pathlib import Path


def load_cve_from_file(filepath):

    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"CVE-fil ikke funnet: {filepath}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
