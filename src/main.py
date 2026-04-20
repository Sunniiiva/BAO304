from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    get_sync_state,
    get_unenriched_commits,
    init_db,
    insert_patch,
    insert_function,
    link_cve_commit,
    upsert_commit,
    upsert_cve,
    upsert_sync_state,
)

from src.patch.fetch_patch import build_patch_data_from_modified_files
from src.repo import extract_commit_references

from src.repo.utils import (
    cleanup_all_temp_repos,
    load_single_commit,
)

app = typer.Typer(help="CVE -> commit -> patch pipeline")

DEFAULT_DB_PATH = Path("data/processed/cve_commits.db")

# -----------------------------------------------------------------------
# Funksjon for å prosessere én CVE og lagre metadata + commit-referanser
# -----------------------------------------------------------------------
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


# --------------------------------------------
# Funksjon for å enrich-e én commit (kjøres i egen tråd)
# ---------------------------------------------
def _enrich_one_commit(item: dict, db_path: Path, stats: dict, stats_lock: threading.Lock) -> None:
    """
    Henter, parser og lagrer én commit med tilhørende patcher og funksjoner.
    Åpner egen DB-tilkobling per tråd — SQLite-tilkoblinger kan ikke deles på tvers av tråder.
    """
    repo_url = item["repo_url"]
    sha = item["commit_sha"]
    commit_url = item.get("commit_url")

    conn = connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000;")

    try:
        commit = load_single_commit(repo_url, sha)

        if "error" in commit:
            err = commit.get("error", "Ukjent feil")
            skip_reason = commit.get("skip_reason")
            if skip_reason == "repo_inaccessible":
                typer.echo(f"  [{sha[:8]}] Skipper privat/utilgjengelig repo: {err}")
            elif skip_reason == "commit_not_found":
                typer.echo(f"  [{sha[:8]}] Skipper commit som ikke finnes: {err}")
            else:
                typer.echo(f"  [{sha[:8]}] Feil ved commit-henting: {err}")
            with stats_lock:
                stats["commits_failed"] += 1
            return

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

        patches_saved = 0
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
                patches_saved += 1
        except Exception as e:
            typer.echo(f"  [{sha[:8]}] Patch-henting feilet: {e}")

        try:
            combined_functions = commit.get("functions", [])
            for fn in combined_functions:
                insert_function(
                    conn,
                    repo_url=repo_url,
                    commit_sha=sha,
                    file_path=fn["file_path"],
                    method_name=fn["method_name"],
                    patched_start_line=fn["patched_start_line"],
                    patched_end_line=fn["patched_end_line"],
                    vuln_start_line=fn["vuln_start_line"],
                    vuln_end_line=fn["vuln_end_line"],
                    vuln_function=fn["vuln_function"],
                    patch_function=fn["patch_function"],
                )
            typer.echo(f"  [{sha[:8]}] {len(combined_functions)} funksjon(er), {patches_saved} patch(er) lagret")
        except Exception as e:
            typer.echo(f"  [{sha[:8]}] Funksjonshenting feilet: {e}")

        conn.commit()

        with stats_lock:
            stats["commits_saved"] += 1
            stats["patches_saved"] += patches_saved

    except Exception as e:
        conn.rollback()
        typer.echo(f"  [{sha[:8]}] DB/transaksjonsfeil: {e}")
        with stats_lock:
            stats["commits_failed"] += 1
    finally:
        conn.close()


# --------------------------------------------
# Funksjon for å enrich-e unike commits med PyDriller
# ---------------------------------------------
def enrich_unique_commits(
    conn,
    db_path: Path,
    limit: int | None = None,
    workers: int = 6,
) -> dict:
    """
    Enricher commits parallelt med ThreadPoolExecutor.
    Hver tråd åpner sin egen DB-tilkobling for å unngå konflikter.
    """
    stats = {
        "commits_found": 0,
        "commits_saved": 0,
        "patches_saved": 0,
        "commits_failed": 0,
    }
    stats_lock = threading.Lock()

    missing_commits = get_unenriched_commits(conn, limit=limit)
    stats["commits_found"] = len(missing_commits)

    if not missing_commits:
        return stats

    typer.echo(f"Starter parallell enrich med {workers} workers ({len(missing_commits)} commits)...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_enrich_one_commit, item, db_path, stats, stats_lock): item
            for item in missing_commits
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                item = futures[future]
                typer.echo(f"  [{item['commit_sha'][:8]}] Uventet feil i worker: {e}")
                with stats_lock:
                    stats["commits_failed"] += 1

    return stats


# --------------------------------------------
# Kommando for ingest
# ---------------------------------------------
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
    workers: int = typer.Option(
        6,
        "--workers",
        help="Antall parallelle workers for commit-enrich (anbefalt: 4-8)",
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

    db_path = DEFAULT_DB_PATH
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
                    conn.commit()
                    typer.echo(f"Prosessert så langt: {processed}")

            except Exception as e:
                skipped_errors += 1
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "ukjent")
                typer.echo(f"Skipper {cve_id} pga feil: {e}")

        conn.commit()

        if not metadata_only:
            typer.echo("\nStarter enrich av unike commits...")
            enrich_stats = enrich_unique_commits(conn, db_path=db_path, workers=workers)
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
        conn.commit()

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


# --------------------------------------------
# Kommando for enrich av commits
# ---------------------------------------------
@app.command("enrich-commits")
def enrich_commits(
    limit: int | None = typer.Option(
        None,
        "--limit",
        help="Maks antall unike commits å enrich-e",
    ),
    workers: int = typer.Option(
        6,
        "--workers",
        help="Antall parallelle workers for commit-enrich (anbefalt: 4-8)",
    ),
) -> None:
    """
    Enricher commits som finnes i cve_commit, men som ikke finnes i commits ennå.
    """
    db_path = DEFAULT_DB_PATH
    conn = connect(db_path)
    init_db(conn)

    try:
        stats = enrich_unique_commits(conn, db_path=db_path, limit=limit, workers=workers)
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