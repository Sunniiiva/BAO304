import glob
from pathlib import Path
import typer

# CVE
from cve import (
    load_cve_from_file,
    extract_cve_info,
    extract_products,
    extract_grouped_references,
)

# Repo / commits
from repo import (
    extract_repo_and_hash,
    fetch_commit_data,
)

# Patch
from patch.fetch_patch import fetch_patch_data

# Database (your updated API)
from db.database import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    link_cve_commit,
)

app = typer.Typer()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("Ingen kommando er gitt. bruk --help for mer informasjon.")
        raise typer.Exit(code=0)


@app.command()
def hello():
    """Sier hello (testkommando)"""
    print("hello")


@app.command()
def kallmoduler(
    cve_file: str = typer.Option(
        "data/raw/cve/CVE-2026-24001.json",
        help="Path til CVE JSON-fil (relativ til prosjektroten)",
    ),
    db_path: str = typer.Option(
        "data/processed/test.db",
        help="Path til SQLite databasefil",
    ),
):
    """
    Kaller moduler i rekkefølge og lagrer resultat i DB:
    CVE -> commits -> patches -> koblinger
    """

    project_root = Path(__file__).resolve().parents[1]
    cve_path = (project_root / cve_file).resolve()
    db_file = (project_root / db_path).resolve()

    # 1) DB
    conn = connect(db_file)
    init_db(conn)

    # 2) Load CVE
    raw = load_cve_from_file(str(cve_path))

    # Forventet: extract_cve_info returnerer dict med felter.
    cve_info = extract_cve_info(raw)

    cve_id = cve_info.get("cve_id") or cve_info.get("id")
    if not cve_id:
        raise typer.BadParameter("Fant ikke cve_id i extract_cve_info-output")

    upsert_cve(
        conn,
        cve_id=cve_id,
        description=cve_info.get("description"),
        published=cve_info.get("published"),
        severity=cve_info.get("severity"),
        cvss_score=cve_info.get("cvss_score"),
    )

    # (Optional) products – brukes ikke direkte i DB nå, men nyttig å printe for debugging
    _ = extract_products(raw)

    # 3) Finn repo + commit hashes fra references
    refs = extract_grouped_references(raw)

    repo_sha_pairs: list[tuple[str, str]] = []
    for ref in refs:
        # extract_repo_and_hash må håndtere input-typen dere bruker (string/dict)
        pair = extract_repo_and_hash(ref)
        if not pair:
            continue

        # Støtter begge: (repo_url, sha) eller dict med keys
        if isinstance(pair, tuple) and len(pair) == 2:
            repo_url, sha = pair
        elif isinstance(pair, dict):
            repo_url = pair.get("repo_url")
            sha = pair.get("sha") or pair.get("commit_sha") or pair.get("commit_hash")
        else:
            continue

        if repo_url and sha:
            repo_sha_pairs.append((repo_url, sha))

    # Fjern duplikater
    repo_sha_pairs = list(dict.fromkeys(repo_sha_pairs))

    if not repo_sha_pairs:
        typer.echo("Fant ingen (repo_url, sha) i references. DB har bare CVE-data.")
        return

    # 4) For hver commit: hent commit metadata, lagre commit, link CVE<->commit, hent patches, lagre patches
    inserted_patches = 0

    for repo_url, sha in repo_sha_pairs:
        # fetch_commit_data forventes å returnere dict med commit metadata
        commit = fetch_commit_data(repo_url, sha) or {}

        upsert_commit(
            conn,
            repo_url=repo_url,
            sha=sha,
            url=commit.get("url"),
            message=commit.get("message"),
            commit_date=commit.get("commit_date"),
            author=commit.get("author"),
            authored_date=commit.get("authored_date"),
        )

        link_cve_commit(
            conn,
            cve_id=cve_id,
            repo_url=repo_url,
            commit_sha=sha,
            method="reference",
            confidence=1.0,
        )

        # Patch per fil
        patches = fetch_patch_data(repo_url, sha)
        for p in patches:
            insert_patch(
                conn,
                repo_url=p["repo_url"],
                commit_sha=p["commit_sha"],
                file_path=p["file_path"],
                language=p.get("language"),
                added_lines=p.get("added_lines"),
                removed_lines=p.get("removed_lines"),
                diff_text=p.get("diff_text"),
            )
            inserted_patches += 1

    typer.echo(f"OK ✅ Lagret CVE: {cve_id}")
    typer.echo(f"OK ✅ Lagret commits: {len(repo_sha_pairs)}")
    typer.echo(f"OK ✅ Lagret patches: {inserted_patches}")
    typer.echo(f"DB: {db_file}")


if __name__ == "__main__":
    app()