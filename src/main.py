"""
Main CLI for CVE Commit Analysis Pipeline.
Henter CVE-data, finner commits, patches og lagrer alt i SQLite.
"""

import glob
from pathlib import Path
import typer

from src.cve import (
    load_cve_from_file,
    extract_cve_info,
    extract_products,
    extract_grouped_references,
)
from src.repo import process_cve_references
from src.patch import fetch_patch_data
from src.db import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    link_cve_commit,
    get_commits_for_cve,
    get_patches_for_commit,
)

app = typer.Typer()
DB_PATH = Path("data/processed/cve_commits.db")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """CVE Commit Analysis Pipeline"""
    if ctx.invoked_subcommand is None:
        typer.echo("Ingen kommando er gitt. bruk --help for mer informasjon.")
        raise typer.Exit(code=0)


@app.command()
def hello():
    """Sier hello (testkommando)"""
    typer.echo("Hello, CVE Commit Analysis Pipeline!")


@app.command()
def ingest():
    """
    Leser CVE-filer, finner commits og patches, og lagrer alt i SQLite.
    """
    typer.echo("Starter ingest-pipeline...")

    # Koble til / opprett database
    conn = connect(DB_PATH)
    init_db(conn)
    typer.echo(f"Database klar: {DB_PATH}")

    # Finn alle CVE-filer
    cve_files = glob.glob("data/raw/cve/*.json")
    if not cve_files:
        typer.echo("Ingen CVE-filer funnet i data/raw/cve")
        raise typer.Exit(code=1)

    typer.echo(f"Fant {len(cve_files)} CVE-fil(er)")

    for cve_file in cve_files:
        typer.echo(f"\nProsesserer {Path(cve_file).name}")
        cve_data = load_cve_from_file(cve_file)

        # Hent basisinfo om CVE
        cve_id, title = extract_cve_info(cve_data)
        products = extract_products(cve_data)

        # CVE JSON-struktur fra CVE-skjemaet.
        description = (
            cve_data.get("containers", {})
            .get("cna", {})
            .get("description", "")
        )
        published = cve_data.get("cveMetadata", {}).get("datePublished")

        typer.echo(f"  CVE: {cve_id}")
        typer.echo(f"  Tittel: {title}")
        typer.echo(f"  Produkter: {len(products)} stk")

        # Lagre CVE i databasen
        upsert_cve(
            conn,
            cve_id=cve_id,
            description=description,
            published=published,
            severity=None,
            cvss_score=None,
        )
        typer.echo("  CVE lagret")

        # Hent commits for denne CVE-en
        results = process_cve_references(cve_data)
        commits = results.get("commit_data", [])

        typer.echo(f"  Fant {len(commits)} commit(s)")

        for commit in commits:
            if "error" in commit:
                typer.echo(f"    Skipper: {commit['error']}")
                continue

            sha = commit["commit_hash"]
            msg = commit.get("commit_message", "")
            author = commit.get("author", "")
            date = commit.get("date", "")

            # Lagre commit i databasen
            upsert_commit(
                conn,
                sha=sha,
                url=None,
                message=msg,
                commit_date=date,
                author=author,
                authored_date=None,
                repo_url=commit.get('repo_url')
            )

            # Lagre kobling CVE ↔ commit
            link_cve_commit(
                conn,
                cve_id=cve_id,
                repo_url=commit.get('repo_url'),
                commit_sha=sha,
                method="message_regex",
                confidence=1.0 if commit.get("mentions_target_cve") else 0.5,
            )

            typer.echo(f"    Commit {sha[:8]} lagret")

            # Hent patch-data for denne committen
            try:
                patch_list = fetch_patch_data(commit.get('repo_url', ''), sha)
                for patch in patch_list:
                    insert_patch(
                        conn,
                        commit_sha=sha,
                        file_path=patch["file_path"],
                        language=patch["language"],
                        added_lines=patch["added_lines"],
                        removed_lines=patch["removed_lines"],
                        diff_text=patch["patch_text"],
                    )
                typer.echo(f"      {len(patch_list)} patch(er) lagret")
            except Exception as e:
                typer.echo(f"      Patch-henting feilet: {e}")

    conn.close()
    typer.echo("\nIngest fullført – data lagret i databasen!")


@app.command()
def stats():
    """
    Viser statistikk fra databasen.
    """
    conn = connect(DB_PATH)
    
    # Totalt antall CVE-er, commits, patches
    total_cve = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    total_commits = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
    total_patches = conn.execute("SELECT COUNT(*) FROM patch").fetchone()[0]
    
    typer.echo(f"""
Database-statistikk:
  CVE-er: {total_cve}
  Commits: {total_commits}
  Patch-filer: {total_patches}
    """)

    conn.close()


@app.command()
def show(cve_id: str):
    """
    Vis detaljer for en spesifikk CVE-ID.
    """
    conn = connect(DB_PATH)
    
    # Hent CVE-info
    cve_row = conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if not cve_row:
        typer.echo(f"CVE {cve_id} ikke funnet")
        return

    typer.echo(f"CVE {cve_id}:")
    typer.echo(f"  Beskrivelse: {cve_row['description'][:100]}...")
    
    # Hent commits for denne CVE-en
    commits = get_commits_for_cve(conn, cve_id)
    typer.echo(f"\nKoblede commits: {len(commits)}")
    
    for commit in commits[:5]:  # Vis maks 5
        typer.echo(f"  {commit['sha'][:8]}: {commit['message'][:50]}...")
        patches = get_patches_for_commit(conn, commit['sha'])
        typer.echo(f"    {len(patches)} filer endret")

    conn.close()


if __name__ == "__main__":
    app()