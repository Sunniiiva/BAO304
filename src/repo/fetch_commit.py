import glob
from src.cve.fetch_cve import load_cve_from_file
from src.repo.parse_commit import process_cve_references


def main():
    # Skriv en enkel header i terminalen så brukeren ser hva programmet gjør
    print("=" * 70)
    print("Commit fetcher")
    print("Hente commit data fra GitHub")
    print("=" * 70)

    # Finn alle CVE-jsonfiler i data-mappa (forventet input til programmet)
    cve_files = glob.glob('data/raw/cve/*.json')

    # Hvis vi ikke finner noen CVE-filer, gir vi beskjed og avslutter rolig
    if not cve_files:
        print("\nIngen CVE-filer funnet i data/raw/cve/*.json")
        return

    # Informer om hvor mange CVE-filer som skal behandles
    print(f"\nProsesserer {len(cve_files)} CVE-filer")

    # Gå gjennom hver CVE-fil én og én
    for cve_file in cve_files:
        # Vis tydelig i terminalen hvilken fil som prosesseres nå
        print(f"\n{'=' * 70}")
        print(f"Leser: {cve_file}")
        print('=' * 70)

        # Les inn CVE-data fra fil (JSON -> Python-dict)
        cve_data = load_cve_from_file(cve_file)

        # Kjør hovedlogikken som:
        #  - finner referanser (f.eks. commit-URLer) i CVE-en
        #  - henter commit-data fra GitHub
        #  - kobler commits til CVE-ID via commit-meldinger
        results = process_cve_references(cve_data)

        # Gi en kort status på at denne CVE-en er ferdig behandlet
        print(f"{results['cve_id']} fullført!")

    # Når alle filer er ferdig behandlet, skriv en slutt-melding
    print("\n" + "=" * 70)
    print("Prosessering fullført")
    print("=" * 70)


# Sørger for at main() bare kjører når filen kjøres direkte,
# og ikke når den importeres som et bibliotek/modul i annet kode.
if __name__ == "__main__":
    main()
