from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer

from src.cve import (
    extract_cve_info,
    extract_cvss_score,
    extract_cwe_ids,
    extract_state,
)
from src.cve.source import get_latest_release_info, iter_cve_records_from_official_source
from src.db import (
    connect,
    get_commits_for_cve,
    get_patches_for_commit,
    get_sync_state,
    get_unenriched_commits,
    init_db,
    insert_patch,
    link_cve_commit,
    upsert_commit,
    upsert_cve,
    upsert_sync_state,
)
from src.patch.fetch_patch import build_patch_data_from_modified_files
from src.repo import extract_commit_references
from src.repo.utils import cleanup_all_temp_repos, fetch_commit_data

app = typer.Typer(help="CVE -> commit -> patch pipeline")


DEFAULT_DB_PATH = Path("data/processed/cve_commits.db")


def get_db_path() -> Path:
    return DEFAULT_DB_PATH

#-----------------------------------------------------------------------
# Funksjon for å prosessere én CVE og lagre metadata + commit-referanser
#-----------------------------------------------------------------------
def process_single_cve_metadata(conn, cve_data: dict) -> str | None:
    """
    Prosesserer metadata for én CVE og lagrer commit-referanser tidlig i cve_commit.
    Returnerer cve_id hvis prosessert, ellers None.
    """
    cve_id, title = extract_cve_info(cve_data)
    state = extract_state(cve_data)

    if state == "REJECTED":
        return None

    cvss = extract_cvss_score(cve_data) or {}
    score = cvss.get("score")
    severity = cvss.get("severity")
    cwe_list = extract_cwe_ids(cve_data)
    published = cve_data.get("cveMetadata", {}).get("datePublished")

    upsert_cve(
        conn,
        cve_id=cve_id,
        title=title,
        published=published,
        severity=severity,
        cvss_score=score,
        cwe=",".join(cwe_list) if cwe_list else None,
        state=state,
    )

    commit_refs = extract_commit_references(cve_data)
    for ref in commit_refs:
        link_cve_commit(
            conn,
            cve_id=cve_id,
            repo_url=ref["repo_url"],
            commit_sha=ref["commit_sha"],
            commit_url=ref["commit_url"],
            method="reference_url",
            confidence=1.0,
        )

    return cve_id

#--------------------------------------------
# Funksjon for å enrich-e unike commits med PyDriller
#---------------------------------------------
def enrich_unique_commits(conn, limit: int | None = None) -> dict:
    """
    Henter alle unike commits som finnes i cve_commit, men ikke i commits.
    Prosesserer hver commit én gang med PyDriller og lagrer patch én gang per file_path.
    """
    stats = {
        "commits_found": 0,
        "commits_saved": 0,
        "patches_saved": 0,
        "commits_failed": 0,
    }

    missing_commits = get_unenriched_commits(conn, limit=limit)
    stats["commits_found"] = len(missing_commits)

    for item in missing_commits:
        repo_url = item["repo_url"]
        sha = item["commit_sha"]
        commit_url = item.get("commit_url")

        commit = fetch_commit_data(repo_url, sha)
        if not isinstance(commit, dict) or "error" in commit:
            stats["commits_failed"] += 1
            err = commit.get("error") if isinstance(commit, dict) else "Ukjent feil"
            typer.echo(f"  Feil ved commit-henting for {repo_url}@{sha}: {err}")
            continue

        msg = commit.get("commit_message", "")
        author = commit.get("author", "")
        date = commit.get("date", "")
        modified_files = commit.get("modified_files", [])

        upsert_commit(
            conn,
            repo_url=repo_url,
            sha=sha,
            commit_url=commit_url,
            message=msg,
            commit_date=date,
            author=author,
            authored_date=None,
        )
        stats["commits_saved"] += 1

        try:
            patch_list = build_patch_data_from_modified_files(
                repo_url=repo_url,
                commit_sha=sha,
                modified_files=modified_files,
            )

            for patch in patch_list:
                insert_patch(
                    conn,
                    repo_url=repo_url,
                    commit_sha=sha,
                    file_path=patch["file_path"],
                    language=patch.get("language"),
                    added_lines=patch.get("added_lines"),
                    removed_lines=patch.get("removed_lines"),
                    hunk_count=patch.get("hunk_count"),
                    diff_text=patch.get("diff_text"),
                    before_code=patch.get("before_code"),
                    after_code=patch.get("after_code"),
                )
                stats["patches_saved"] += 1

        except Exception as e:
            typer.echo(f"  Patch-henting feilet for {repo_url}@{sha[:8]}: {e}")

    return stats


#--------------------------------------------
# Kommando for ingest 
#---------------------------------------------
@app.command("ingest")
def ingest(
    full: bool = typer.Option(
        False,
        "--full",
        help="Kjør full pipeline: lagre CVE + commit-referanser + enrich unike commits",
    ),
    metadata_only: bool = typer.Option(
        False,
        "--metadata-only",
        help="Lagre bare CVE-data og commit-referanser, uten commit/patch-enrichment",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        help="Maks antall CVE-er å prosessere",
    ),
    batch_size: int = typer.Option(
        200,
        "--batch-size",
        help="Vis fremdrift per batch",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Kjør selv om release_tag allerede er synket",
    ),
) -> None:
    """
    Leser CVE-er fra kilde, lagrer CVE-data og commit-referanser,
    og kan deretter enrich-e unike commits med PyDriller.
    """
    if full and metadata_only:
        raise typer.BadParameter("Bruk enten --full eller --metadata-only, ikke begge.")

    if not full and not metadata_only:
        metadata_only = True

    db_path = get_db_path()
    conn = connect(db_path)
    init_db(conn)

    typer.echo("Starter ingest fra CVE-database...")

    release_info = get_latest_release_info()
    release_tag = release_info.get("tag_name", "ukjent-release")
    typer.echo(f"Nyeste release: {release_tag}")

    previous_sync = get_sync_state(conn, "official_cvelist")
    if previous_sync and previous_sync.get("release_tag") == release_tag and not force:
        typer.echo("Denne releasen er allerede synket. Bruk --force for å kjøre på nytt.")
        conn.close()
        return

    if metadata_only:
        typer.echo("Modus: metadata only")
    else:
        typer.echo("Modus: full enrich")

    typer.echo(f"Batch size: {batch_size}")

    processed = 0
    rejected = 0
    skipped_errors = 0
    commit_total = 0
    patch_total = 0

    try:
        for idx, cve_data in enumerate(iter_cve_records_from_official_source(), start=1):
            if limit is not None and processed >= limit:
                break

            try:
                saved_cve_id = process_single_cve_metadata(conn, cve_data)
                if not saved_cve_id:
                    rejected += 1
                    continue

                processed += 1

                if processed % batch_size == 0:
                    typer.echo(f"Prosessert så langt: {processed}")

            except Exception as e:
                skipped_errors += 1
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "ukjent")
                typer.echo(f"Skipper {cve_id} pga feil: {e}")

        if not metadata_only:
            typer.echo("\nStarter enrich av unike commits...")
            enrich_stats = enrich_unique_commits(conn)
            commit_total += enrich_stats["commits_saved"]
            patch_total += enrich_stats["patches_saved"]

            typer.echo(
                f"Unike commits funnet: {enrich_stats['commits_found']} | "
                f"lagret: {enrich_stats['commits_saved']} | "
                f"feilet: {enrich_stats['commits_failed']} | "
                f"patches: {enrich_stats['patches_saved']}"
            )

        synced_at = datetime.now(timezone.utc).isoformat()
        upsert_sync_state(
            conn,
            source_name="official_cvelist",
            release_tag=release_tag,
            synced_at=synced_at,
        )

    finally:
        try:
            cleanup_all_temp_repos()
        except Exception:
            typer.echo("temp_repos var låst og kunne ikke slettes – lar den ligge.")
        conn.close()

    typer.echo("\nOffisiell ingest fullført!")
    typer.echo(f"Prosessert: {processed}")
    typer.echo(f"Rejected: {rejected}")
    typer.echo(f"Skippet pga feil: {skipped_errors}")
    typer.echo(f"Commits lagret: {commit_total}")
    typer.echo(f"Patches lagret: {patch_total}")


#--------------------------------------------
# Kommando for enrich av commits
#---------------------------------------------
@app.command("enrich-commits")
def enrich_commits(
    limit: int | None = typer.Option(
        None,
        "--limit",
        help="Maks antall unike commits å enrich-e",
    ),
) -> None:
    """
    Enricher commits som finnes i cve_commit, men som ikke finnes i commits ennå.
    """
    db_path = get_db_path()
    conn = connect(db_path)
    init_db(conn)

    try:
        stats = enrich_unique_commits(conn, limit=limit)
        typer.echo("Commit enrich fullført!")
        typer.echo(f"Unike commits funnet: {stats['commits_found']}")
        typer.echo(f"Commits lagret: {stats['commits_saved']}")
        typer.echo(f"Commits feilet: {stats['commits_failed']}")
        typer.echo(f"Patches lagret: {stats['patches_saved']}")
    finally:
        try:
            cleanup_all_temp_repos()
        except Exception:
            typer.echo("temp_repos var låst og kunne ikke slettes – lar den ligge.")
        conn.close()

if __name__ == "__main__":
    app()


    #Slettet show kommando
    #Slettet stats kommando 
