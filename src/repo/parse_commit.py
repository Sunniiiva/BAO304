import re
from src.repo.utils import extract_repo_and_hash, fetch_commit_data
from src.cve.parse_cve import extract_grouped_references

# Koble commits til CVE-IDer via enkel regex-matching


def extract_cve_from_commit(commit_message):
    """
    Ekstraherer CVE-IDer fra en commit-melding ved hjelp av regex.
    Forventer mønster på formen: CVE-ÅÅÅÅ-NNNN (minst 4 sifre på slutten).
    """
    pattern = r'CVE-\d{4}-\d{4,}'
    # Finn alle forekomster av CVE-ID i commit-meldingen (case-insensitive)
    matches = re.findall(pattern, commit_message, re.IGNORECASE)
    # Normaliser til store bokstaver og fjern duplikater
    return list(set(cve.upper() for cve in matches))


def link_cve_to_commits(cve_id, commit_data_list):
    """
    Kobler én CVE-ID til en liste med commits ved å sjekke commit-meldinger.
    Resultatet er en ny liste med commits som har ekstra felter:
      - 'mentioned_cves': alle CVE-er funnet i meldingen
      - 'mentions_target_cve': True/False for om denne CVE-en nevnes
    """
    enriched_commits = []

    for commit in commit_data_list:
        # Hopp over commits der henting feilet (commit har 'error'-felt)
        if 'error' in commit:
            enriched_commits.append(commit)
            continue

        # Hent commit-melding, eller tom streng hvis feltet mangler
        commit_msg = commit.get('commit_message', '')

        # Finn alle CVE-IDer som nevnes i denne commit-meldingen
        mentioned_cves = extract_cve_from_commit(commit_msg)

        # Sjekk om "vår" CVE-ID finnes blant de nevnte
        mentions_target_cve = cve_id in mentioned_cves

        # Lag en kopi av commit-objektet med to ekstra felt
        enriched_commit = {
            **commit,
            'mentioned_cves': mentioned_cves,            # Alle CVE-er funnet i meldingen
            'mentions_target_cve': mentions_target_cve   # True/False for mål-CVE
        }

        enriched_commits.append(enriched_commit)

        # Enkel logging til terminalen dersom commit nevner ønsket CVE-ID
        if mentions_target_cve:
            print(f"Commit nevner {cve_id} direkte!")

    return enriched_commits


def process_cve_references(cve_data):
    """
    Hovedfunksjon for denne modulen:
      1) Leser CVE-ID og referanser fra CVE-data
      2) Henter commit-data for alle commit-URLer som er referert
      3) Sjekker om commit-meldinger nevner CVE-IDen (boolean linking)
      4) Lager enkel statistikk over treff
    """
    # Hent CVE-ID fra CVE-JSON-strukturen (fallback til 'unknown' hvis noe mangler)
    cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'unknown')

    # Ekstraher og grupper alle referanser i CVE-en (f.eks. commits, PRs, issues, advisories)
    grouped_refs = extract_grouped_references(cve_data)

    # Forbered resultat-struktur som vi bygger opp underveis
    results = {
        'cve_id': cve_id,
        'classified_refs': grouped_refs,  # Alle referanser, gruppert etter type
        'commit_data': []                 # Blir fylt med commit-objekter under
    }

    # Hent commit-data for alle referanser som er klassifisert som "commit"
    for commit_url in grouped_refs.get('commit', []):
        # Parse URL til repo-URL + commit-hash (for eksempel fra GitHub-lenke)
        info = extract_repo_and_hash(commit_url)
        if info:
            print(f"\nHenter commit: {info['commit_hash'][:8]}...")
            # Bruk PyDriller (eller tilsvarende) via fetch_commit_data for å hente metadata + filendringer
            commit_data = fetch_commit_data(info['repo_url'], info['commit_hash'])
            results['commit_data'].append(commit_data)

    # Kjør enkel, tekstbasert linking mellom CVE-ID og commits (bare basert på commit-melding)
    print(f"\nAnalyserer CVE-referanser for {cve_id}...")
    results['commit_data'] = link_cve_to_commits(cve_id, results['commit_data'])

    # ENKEL statistikk: hvor mange commits totalt, og hvor mange nevner CVE-IDen eksplisitt
    total_commits = len(results['commit_data'])
    cve_mentions = sum(
        1 for c in results['commit_data']
        if c.get('mentions_target_cve', False)
    )

    results['statistics'] = {
        'total_commits': total_commits,
        'commits_mentioning_cve': cve_mentions,
        'commits_without_cve_mention': total_commits - cve_mentions
    }

    # Skriv statistikk til terminalen slik at brukeren får et raskt overblikk
    print(f"\nResultat:")
    print(f"  Total commits: {total_commits}")
    print(f"  Nevner CVE direkte: {cve_mentions}")
    print(f"  Uten CVE-nevnelse: {total_commits - cve_mentions}")

    return results
