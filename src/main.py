"""
Main CLI for CVE Commit Analysis Pipeline.
Henter CVE-data, finner commits, patches og lagrer alt i SQLite.
"""

import glob
from pathlib import Path
import typer
from textwrap import indent

from src.cve import (
    load_cve_from_file,
    extract_cve_info,
    extract_products,
    extract_grouped_references,
)

from src.repo.crawl_repo import crawl_repo_for_cve
from src.repo import process_cve_references
from src.patch import fetch_patch_data
from src.patch.parse_patch import parse_patch

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


# ----------------------------------
# Hovedkommando som viser hjelpefuksjon
# ----------------------------------
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """CVE Commit Analysis Pipeline"""
    if ctx.invoked_subcommand is None:
        typer.echo("Ingen kommando er gitt. bruk --help for mer informasjon.")
        raise typer.Exit(code=0)


# ----------------------------------
# Kommando for å crawle repo for en gitt CVE-fil
# ----------------------------------
@app.command()
def crawl_repo(
    cve_file: Path = typer.Argument(..., help="Path to a CVE JSON file in data/raw/cve"),
    max_commits: int = typer.Option(20000, help="Max commits to scan per repo"),
):
    """
    JSON -> repo -> crawl repo history -> store commits+patches into DB (single CVE file).
    """
    conn = connect(DB_PATH)
    init_db(conn)

    cve_data = load_cve_from_file(str(cve_file))

    cve_id, title = extract_cve_info(cve_data)
    description = (
        cve_data.get("containers", {})
        .get("cna", {})
        .get("description", "")
    )
    published = cve_data.get("cveMetadata", {}).get("datePublished")

    upsert_cve(
        conn,
        cve_id=cve_id,
        description=description,
        published=published,
        severity=None,
        cvss_score=None,
        cve_title=title,
    )

    results = process_cve_references(cve_data, max_commits_per_repo=max_commits)
    commits = results.get("commit_data", [])

    typer.echo(f"Repos found: {results['statistics']['repos_found']}")
    typer.echo(f"Commits found (unique): {results['statistics']['total_unique_commits']}")

    for commit in commits:
        repo_url = commit.get("repo_url") or ""
        sha = commit.get("commit_hash") or ""
        if not repo_url or not sha:
            continue

        upsert_commit(
            conn,
            repo_url=repo_url,
            sha=sha,
            url=None,
            message=commit.get("commit_message") or None,
            commit_date=commit.get("date") or None,
            author=commit.get("author") or None,
            authored_date=None,
        )

        link_cve_commit(
            conn,
            cve_id=cve_id,
            repo_url=repo_url,
            commit_sha=sha,
            method=commit.get("discovery_method") or "repo_history_message_regex",
            confidence=1.0 if commit.get("mentions_target_cve") else 0.6,
        )

        # Fetch + store patches
        try:
            patch_list = fetch_patch_data(repo_url, sha)
            for patch in patch_list:
                insert_patch(
                    conn,
                    repo_url=patch["repo_url"],
                    commit_sha=patch["commit_sha"],
                    file_path=patch["file_path"],
                    language=patch["language"],
                    added_lines=patch["added_lines"],
                    removed_lines=patch["removed_lines"],
                    hunk_count=patch.get("hunk_count"),
                    diff_text=patch["diff_text"],
                    before_code=patch.get("before_code"),
                    after_code=patch.get("after_code"),
                )
        except Exception as e:
            typer.echo(f"Patch-henting feilet for {sha[:8]}: {e}")

    conn.close()
    typer.echo("crawl_repo ferdig.")


# ----------------------------------
# Test kommando
# ----------------------------------
@app.command()
def hello():
    """Sier hello (testkommando)"""
    typer.echo("Hello, CVE Commit Analysis Pipeline!")


# ----------------------------------
# Ingest kommando: Full pipeline for å lese CVE-filer, finne commits og patches, og lagre i DB.
# ----------------------------------
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
                patch_list = fetch_patch_data(commit.get("repo_url", ""), sha)
                for patch in patch_list:
                   insert_patch(
                        conn,
                        repo_url=patch["repo_url"],
                        commit_sha=patch["commit_sha"],
                        file_path=patch["file_path"],
                        language=patch["language"],
                        added_lines=patch["added_lines"],
                        removed_lines=patch["removed_lines"],
                        hunk_count=patch.get("hunk_count"),
                        diff_text=patch["diff_text"],
                        before_code=patch.get("before_code"),
                        after_code=patch.get("after_code"),
    )
                typer.echo(f"      {len(patch_list)} patch(er) lagret")
            except Exception as e:
                typer.echo(f"      Patch-henting feilet: {e}")

    conn.close()
    typer.echo("\nIngest fullført – data lagret i databasen!")


# ----------------------------------
# Kommando for å vise statistikk og detaljer fra databasen
# ----------------------------------
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

# ----------------------------------
# Kommando for å vise detaljer for en spesifikk CVE-ID
# ----------------------------------
@app.command()
def show(cve_id: str):
    """
    Vis detaljer for en spesifikk CVE-ID.
    """
    conn = connect(DB_PATH)

    cve_row = conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if not cve_row:
        typer.echo(f"CVE {cve_id} ikke funnet")
        conn.close()
        return

    commits = get_commits_for_cve(conn, cve_id)
    if not commits:
        typer.echo(f"Ingen commits funnet for {cve_id}")
        conn.close()
        return

    for commit in commits:
        patches_rows = get_patches_for_commit(conn, commit["repo_url"], commit["sha"])

        typer.echo("=" * 70)
        typer.echo(f"CVE: {cve_id}")
        typer.echo(f"Commit: {commit['sha'][:12]}...")
        typer.echo(f"Repository: {commit['repo_url']}")
        typer.echo(f"Files modified: {len(patches_rows)}")
        typer.echo("=" * 70)
        typer.echo("")

        total_added = 0
        total_removed = 0
        total_type_changes = 0

        patches = [dict(r) for r in patches_rows]

        for idx, patch in enumerate(patches, start=1):
            # --- finn filsti (DB kan ha ulike kolonnenavn) ---
            path = (
                patch.get("path")
                or patch.get("file_path")
                or patch.get("filepath")
                or patch.get("new_path")
                or patch.get("old_path")
                or "(unknown file)"
            )

            # --- finn diff/patch-tekst ---
            diff_text = (
                patch.get("diff_text")  
                or patch.get("diff")
                or patch.get("patch_text")
                or patch.get("patch")
                or ""
            )

            # --- finn BEFORE/AFTER ---
            before = patch.get("before") or patch.get("before_code") or ""
            after = patch.get("after") or patch.get("after_code") or ""

            # Hvis BEFORE/AFTER ikke ligger i DB, bygg dem fra diff
            if not before and not after and diff_text:
                parsed = parse_patch(diff_text)
                before = parsed.get("before_code", "")
                after = parsed.get("after_code", "")
                # lines
                total_added += parsed.get("added_lines", 0)
                total_removed += parsed.get("removed_lines", 0)
            else:
                # ellers: ta linjetall fra DB hvis dere lagrer det
                total_added += patch.get("lines_added", patch.get("added_lines", 0)) or 0
                total_removed += patch.get("lines_removed", patch.get("removed_lines", 0)) or 0

            # type_changes er valgfritt – summer hvis finnes
            total_type_changes += patch.get("type_changes", 0) or 0

            typer.echo(f"[{idx}/{len(patches)}] File: {path}")
            typer.echo("-" * 70)

            typer.echo("--- BEFORE")
            typer.echo(before.strip() or "(empty)")
            typer.echo("")
            typer.echo("+++ AFTER")
            typer.echo(after.strip() or "(empty)")
            typer.echo("")
            typer.echo("--- DIFF")
            typer.echo(diff_text.strip() or "(empty)")
            typer.echo("")
            typer.echo("-" * 70)
            typer.echo("")

        typer.echo("Summary:")
        typer.echo(f"- Files processed: {len(patches)}")
        typer.echo(f"- Lines added: {total_added}")
        typer.echo(f"- Lines removed: {total_removed}")
        # Bare print type changes hvis dere faktisk bruker det
        if total_type_changes:
            typer.echo(f"- Type changes detected: {total_type_changes}")
        typer.echo("=" * 70)
        typer.echo("")

    conn.close()


if __name__ == "__main__":
    app()