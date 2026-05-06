from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import typer

# Helpers that pull metadata fields out of a raw CVE record
from src.cve import (
    extract_cve_info,
    extract_cvss_score,
    extract_cwe_ids,
    extract_state,
)

# Reads CVEs straight from the official CVE list on GitHub
from src.cve.source import get_latest_release_info, iter_cve_records_from_official_source

# DB layer: connection, init, upsert/insert/lookup
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

# Builds patch rows (diff, before/after, language) from a commit's modified files
from src.patch.fetch_patch import build_patch_data_from_modified_files

# Pulls commit URLs out of a CVE record
from src.commit import extract_commit_references

# Filters out function changes that are only whitespace
from src.commit.method_matching import _has_meaningful_code_change

# Cleans temp clones, enables long Windows paths
from src.utils.git_access import cleanup_all_temp_repos, enable_git_longpaths

# Clones and parses one commit using PyDriller
from src.commit.load_commit import load_single_commit

# Typer app powers the CLI
app = typer.Typer(help="CVE -> commit -> patch pipeline")

# Default SQLite path
DEFAULT_DB_PATH = Path("data/processed/cve_commits.db")


@app.callback()
def _startup() -> None:
    """Runs before any command."""
    # Required on Windows for some repos with deep paths
    enable_git_longpaths()



# Process one CVE and save metadata + commit references

def process_single_cve_metadata(conn, cve_data: dict) -> str | None:
    """
    Save metadata for one CVE and any commit references it points to.
    Returns cve_id if saved, otherwise None.
    """
    # Pull cve_id and title from the raw record
    cve_id, title = extract_cve_info(cve_data)
    state = extract_state(cve_data)

    # Skip withdrawn CVEs, no value for the dataset
    if state == "REJECTED":
        return None

    # CVSS may be missing on older or partial CVEs
    cvss = extract_cvss_score(cve_data) or {}
    score = cvss.get("score")
    severity = cvss.get("severity")

    # CWE describes the type of vulnerability (e.g. CWE-79 for XSS)
    cwe_list = extract_cwe_ids(cve_data)
    published = cve_data.get("cveMetadata", {}).get("datePublished")

    upsert_cve(
        conn,
        cve_id=cve_id,
        title=title,
        published=published,
        severity=severity,
        cvss_score=score,
        cwe=",".join(cwe_list) if cwe_list else None,  # store as comma-separated text
        state=state,
    )

    # Link CVE to its commits. Commit content is fetched later in the enrich phase.
    commit_refs = extract_commit_references(cve_data)
    for ref in commit_refs:
        link_cve_commit(
            conn,
            cve_id=cve_id,
            repo_url=ref["repo_url"],
            commit_sha=ref["commit_sha"],
            commit_url=ref["commit_url"],
            method="reference_url",  # how the link was found
            confidence=1.0,           # 1.0 since the CVE itself points to it
        )

    return cve_id



# Enrich one commit (runs in its own thread)

def _enrich_one_commit(item: dict, db_path: Path, stats: dict, stats_lock: threading.Lock) -> None:
    """
    Fetch, parse and save one commit with its patches and functions.
    Each thread needs its own DB connection (SQLite limitation).
    """
    repo_url = item["repo_url"]
    sha = item["commit_sha"]
    commit_url = item.get("commit_url")

    # One connection per thread
    conn = connect(db_path)
    # Wait instead of failing if another thread holds the lock
    conn.execute("PRAGMA busy_timeout = 5000;")

    try:
        # Clones the repo if needed and gets metadata + modified files
        commit = load_single_commit(repo_url, sha)

        # Expected errors: private repo, deleted commit, etc.
        if "error" in commit:
            err = commit.get("error", "Unknown error")
            skip_reason = commit.get("skip_reason")
            if skip_reason == "repo_inaccessible":
                typer.echo(f"  [{sha[:8]}] Skipping private/inaccessible repo: {err}")
            elif skip_reason == "commit_not_found":
                typer.echo(f"  [{sha[:8]}] Skipping commit that does not exist: {err}")
            else:
                typer.echo(f"  [{sha[:8]}] Error fetching commit: {err}")
            # Lock since stats is shared between threads
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
        )

        # Save patches
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
            # Don't kill the whole commit if a patch fails
            typer.echo(f"  [{sha[:8]}] Patch fetch failed: {e}")

        # Saves modified functions (one row per method) 
        try:
            combined_functions = commit.get("functions", [])
            saved_functions = 0
            skipped_ws = 0   # whitespace-only changes
            skipped_dup = 0  # duplicates within the same commit
            seen_keys: set[tuple[str, str, str]] = set()

            for fn in combined_functions:
                # Need both versions for ML training data
                if fn.get("vuln_function") is None or fn.get("patch_function") is None:
                    continue

                # Skip whitespace-only diffs
                if not _has_meaningful_code_change(fn["vuln_function"], fn["patch_function"]):
                    skipped_ws += 1
                    continue

                # Dedup on file + method + start line
                dedup_key = (
                    fn["file_path"],
                    fn["method_name"],
                    str(fn.get("vuln_start_line")),
                )
                if dedup_key in seen_keys:
                    skipped_dup += 1
                    continue
                seen_keys.add(dedup_key)

                # Save the vulnerable + patched pair
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
                saved_functions += 1

            # Status line for this commit
            skip_msg = ""
            if skipped_ws or skipped_dup:
                skip_msg = f" (filtered: {skipped_ws} whitespace, {skipped_dup} duplicate)"
            typer.echo(f"  [{sha[:8]}] {saved_functions} function(s), {patches_saved} patch(es) saved{skip_msg}")
        except Exception as e:
            typer.echo(f"  [{sha[:8]}] Function fetch failed: {e}")

        # Commit the whole thing as one transaction
        conn.commit()

        # Update shared stats safely
        with stats_lock:
            stats["commits_saved"] += 1
            stats["patches_saved"] += patches_saved

    except Exception as e:
        # Roll back so the DB doesn't end up half-written
        conn.rollback()
        typer.echo(f"  [{sha[:8]}] DB/transaction error: {e}")
        with stats_lock:
            stats["commits_failed"] += 1
    finally:
        # Always close, success or fail
        conn.close()



# Enrich unique commits with PyDriller

def enrich_unique_commits(
    conn,
    db_path: Path,
    limit: int | None = None,
    workers: int = 6,
) -> dict:
    """
    Enrich commits in parallel. Each thread opens its own DB connection.
    """
    # Shared stats updated by all workers
    stats = {
        "commits_found": 0,
        "commits_saved": 0,
        "patches_saved": 0,
        "commits_failed": 0,
    }
    # Lock so two threads can't update stats at once
    stats_lock = threading.Lock()

    # Commits referenced in cve_commit but not yet enriched
    missing_commits = get_unenriched_commits(conn, limit=limit)
    stats["commits_found"] = len(missing_commits)

    if not missing_commits:
        return stats

    typer.echo(f"Starting parallel enrich with {workers} workers ({len(missing_commits)} commits)...")

    # Threads, not processes: work is I/O bound (clone, network, disk)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_enrich_one_commit, item, db_path, stats, stats_lock): item
            for item in missing_commits
        }
        # as_completed yields each future as soon as it finishes
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                # Catch anything that escaped the worker
                item = futures[future]
                typer.echo(f"  [{item['commit_sha'][:8]}] Unexpected error in worker: {e}")
                with stats_lock:
                    stats["commits_failed"] += 1

    return stats



# Ingest command

@app.command("ingest")
def ingest(
    full: bool = typer.Option(
        False,
        "--full",
        help="Run full pipeline: save CVE + commit references + enrich unique commits",
    ),
    metadata_only: bool = typer.Option(
        False,
        "--metadata-only",
        help="Only save CVE data and commit references, without commit/patch enrichment",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        help="Max number of CVEs to process",
    ),
    batch_size: int = typer.Option(
        200,
        "--batch-size",
        help="Show progress per batch",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Run even if release_tag has already been synced",
    ),
    workers: int = typer.Option(
        6,
        "--workers",
        help="Number of parallel workers for commit enrich (recommended: 4-8)",
    ),
) -> None:
    """
    Read CVEs from source, save CVE data and commit references,
    and optionally enrich the commits with PyDriller.
    """
    # Mutually exclusive flags
    if full and metadata_only:
        raise typer.BadParameter("Use either --full or --metadata-only, not both.")

    # Default to metadata only (fastest)
    if not full and not metadata_only:
        metadata_only = True

    # Open connection and create tables if missing
    db_path = DEFAULT_DB_PATH
    conn = connect(db_path)
    init_db(conn)

    typer.echo("Starting ingest from CVE database...")

    # Which release version we're about to fetch
    release_info = get_latest_release_info()
    release_tag = release_info.get("tag_name", "unknown-release")
    typer.echo(f"Latest release: {release_tag}")

    # Skip if already synced, unless --force
    previous_sync = get_sync_state(conn, "official_cvelist")
    if previous_sync and previous_sync.get("release_tag") == release_tag and not force:
        typer.echo("This release has already been synced. Use --force to run again.")
        conn.close()
        return

    if metadata_only:
        typer.echo("Mode: metadata only")
    else:
        typer.echo("Mode: full enrich")

    typer.echo(f"Batch size: {batch_size}")

    # Counters for the final summary
    processed = 0
    rejected = 0
    skipped_errors = 0
    commit_total = 0
    patch_total = 0

    try:
        # Stream CVEs one at a time, never load the whole dataset
        for idx, cve_data in enumerate(iter_cve_records_from_official_source(), start=1):
            # Stop early if --limit set
            if limit is not None and processed >= limit:
                break

            try:
                saved_cve_id = process_single_cve_metadata(conn, cve_data)
                if not saved_cve_id:
                    # Was REJECTED, skipped
                    rejected += 1
                    continue

                processed += 1

                # Periodic commit so we don't lose everything if it crashes
                if processed % batch_size == 0:
                    conn.commit()
                    typer.echo(f"Processed so far: {processed}")

            except Exception as e:
                # One bad CVE shouldn't stop the run
                skipped_errors += 1
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "unknown")
                typer.echo(f"Skipping {cve_id} due to error: {e}")

        # Flush whatever's left
        conn.commit()

        # Phase two: enrich commits (only if --full)
        if not metadata_only:
            typer.echo("\nStarting enrich of unique commits...")
            enrich_stats = enrich_unique_commits(conn, db_path=db_path, workers=workers)
            commit_total += enrich_stats["commits_saved"]
            patch_total += enrich_stats["patches_saved"]

            typer.echo(
                f"Unique commits found: {enrich_stats['commits_found']} | "
                f"saved: {enrich_stats['commits_saved']} | "
                f"failed: {enrich_stats['commits_failed']} | "
                f"patches: {enrich_stats['patches_saved']}"
            )

        # Mark this release as synced so the next run skips it
        synced_at = datetime.now(timezone.utc).isoformat()
        upsert_sync_state(
            conn,
            source_name="official_cvelist",
            release_tag=release_tag,
            synced_at=synced_at,
        )
        conn.commit()

    finally:
        # Free disk space
        try:
            cleanup_all_temp_repos()
        except Exception:
            # Files sometimes locked by AV/Git on Windows
            typer.echo("temp_repos was locked and could not be deleted, leaving it as is.")
        conn.close()

    # Summary
    typer.echo("\nOfficial ingest complete!")
    typer.echo(f"Processed: {processed}")
    typer.echo(f"Rejected: {rejected}")
    typer.echo(f"Skipped due to errors: {skipped_errors}")
    typer.echo(f"Commits saved: {commit_total}")
    typer.echo(f"Patches saved: {patch_total}")



# Enrich-commits command

@app.command("enrich-commits")
def enrich_commits(
    limit: int | None = typer.Option(
        None,
        "--limit",
        help="Max number of unique commits to enrich",
    ),
    workers: int = typer.Option(
        6,
        "--workers",
        help="Number of parallel workers for commit enrich (recommended: 4-8)",
    ),
) -> None:
    """
    Enrich commits that exist in cve_commit but not yet in commits.
    """
    # Useful when metadata was previously ingested with --metadata-only
    db_path = DEFAULT_DB_PATH
    conn = connect(db_path)
    init_db(conn)

    try:
        stats = enrich_unique_commits(conn, db_path=db_path, limit=limit, workers=workers)
        typer.echo("Commit enrich complete!")
        typer.echo(f"Unique commits found: {stats['commits_found']}")
        typer.echo(f"Commits saved: {stats['commits_saved']}")
        typer.echo(f"Commits failed: {stats['commits_failed']}")
        typer.echo(f"Patches saved: {stats['patches_saved']}")
    finally:
        try:
            cleanup_all_temp_repos()
        except Exception:
            typer.echo("temp_repos was locked and could not be deleted, leaving it as is.")
        conn.close()


if __name__ == "__main__":
    # Run as a CLI when this file is executed directly
    app()