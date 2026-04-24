# SmartSecLab CVE and patch links

Programvare-sårbarheter utgjør en betydelig risiko for brukere, både for organisasjoner og for
privatpersoner. Når en sårbarhet oppdages blir den ofte publisert som en CVE, common
vulnerabilities and exposures, hvor sårbarheten beskrives, hva som er feil, hvilke systemer
som er rammet og sårbarhetens alvorlighetsgrad.

Det som derimot ofte mangler er en tydelig kobling til hvordan sårbarheten blir rettet i kode. I
praksis skjer retting av sårbarheter gjennom kodeendringer kalt patches i
versjonskontrollsystemer som Git. Disse patchesene finnes i commits i åpne kildekode
repositories, som på GitHub. Å manuelt identifisere hvilke commits som representerer
sikkerhets patches og å koble dem til riktig CVE er tidskrevende og lite effektivt.

Dette prosjektet adresserer dette problemet ved å designe og utvikle et automatisert
rammeverk i Python som samler inn, identifiserer og strukturerer sikkerhets-patches fra
kildekode-repositories i Git og kobler dem opp til kjente sårbarheter oppført i CVE-databasen.
Rammeverket støtter flere programmeringsspråk.

---

## Installasjon

Klon prosjektet:
```bash
git clone https://github.com/Sunniiiva/BAO304.git
cd BAO304
```

Installer avhengigheter:
```bash
pip install -e .
```

---

## Bruk

Verktøyet brukes via kommandolinjen. For full oversikt over tilgjengelige kommandoer:
```bash
python -m src.main --help
```

### Hent kun CVE-metadata (uten commit-enrich)
```bash
python -m src.main ingest --metadata-only
```

### Full pipeline (CVE-metadata + commit-enrich)
```bash
python -m src.main ingest --full
```

### Enrich commits separat (f.eks. etter en tidligere metadata-only kjøring)
```bash
python -m src.main enrich-commits
```

### Begrens antall CVE-er som prosesseres (anbefalt for testing)
```bash
python -m src.main ingest --full --limit 100
```

---

## Parallell kjøring og ytelse

Commit-enrich er den tidkrevende delen av pipelinen da den kloner Git-repositorier over nettverket.
For å redusere kjøretid bruker pipelinen parallelle workers (standard: 6).

Antall workers kan justeres med `--workers`:
```bash
python -m src.main enrich-commits --workers 8
python -m src.main ingest --full --workers 4
```

Anbefalt antall workers: **4–8**. Høyere verdier gir ikke nødvendigvis raskere kjøring
og kan trigge GitHubs misbruksdeteksjon ved mange samtidige klone-forespørsler.

---

## GitHub Token (valgfritt)

Uten token behandler GitHub alle forespørsler som anonyme med en grense på 60 forespørsler per time.
Med et personlig token øker grensen til 5000 per time, noe som gjør lange kjøringer mer stabile.

Tokenet settes som miljøvariabel og lagres aldri i kildekoden:

**Windows (PowerShell):**
```powershell
$env:GITHUB_TOKEN = "ditt_token_her"
```

**Mac/Linux:**
```bash
export GITHUB_TOKEN="ditt_token_her"
```

Et GitHub-token opprettes under: GitHub → Settings → Developer settings →
Personal access tokens → Tokens (classic). For offentlige repositorier trengs ingen spesielle tillatelser.

Pipelinen kjører uten token hvis miljøvariabelen ikke er satt.

---

## Databasen

Data lagres i `data/processed/cve_commits.db` (SQLite). Databasen inneholder følgende tabeller:

| Tabell | Innhold |
|---|---|
| `cve` | CVE-metadata (ID, tittel, CVSS-score, CWE, alvorlighetsgrad) |
| `cve_commit` | Kobling mellom CVE og commit-referanser |
| `commits` | Commit-metadata (SHA, dato, forfatter, melding) |
| `patch` | Fil-nivå patch-data (diff, før/etter kode, språk) |
| `functions` | Funksjonsnivå sårbar og patchet kode |
| `sync_state` | Holder styr på hvilken CVE-release som sist ble synket |

En ferdig utfylt database kan brukes direkte uten å kjøre pipelinen på nytt.