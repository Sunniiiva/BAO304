"""
Main CLI for CVE Commit Analysis Pipeline.
Henter CVE-data, finner commits, patches og lagrer alt i SQLite.
"""

import glob
from pathlib import Path
import typer
import re

from src.cve import (
    load_cve_from_file,
    extract_cve_info,
    extract_products,
    extract_grouped_references,
    extract_state,
    extract_cwe_ids,
    extract_cvss_score,
)
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

from src.repo.utils import cleanup_all_temp_repos

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
       
       #Hopper over CVE-er med rejected states 
        state = extract_state(cve_data)
        if state == "REJECTED":
            typer.echo(f"hopper over {cve_id}, state ble rejected")
            continue

        # Ekstraher CVSS-score og alvorlighetsgrad, samt CWE-IDer
        cvss_score = extract_cvss_score(cve_data) or {}
        score = cvss_score.get("score")
        severity = cvss_score.get("severity")
        cwe_list = extract_cwe_ids(cve_data)

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
        typer.echo(f"  Cvss_score: {score}")
        typer.echo(f"  alvorlighetsgrad: {severity}")

        # Lagre CVE i databasen - må skaleres når database blir oppdatert
        upsert_cve(
            conn,
            cve_id=cve_id,
            description=description,
            published=published,
            severity=severity,
            cvss_score=score,
            cve_title=title,
            cwe=",".join(cwe_list) if cwe_list else None,
            state=state
        )
        typer.echo("  CVE lagret")

        # Her må kode for å lagre informasjon om cwe legges til
        #upsert_cwe()
        

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
                        repo_url=commit.get("repo_url"),
                        commit_sha=sha,
                        file_path=patch["file_path"],
                        language=patch["language"],
                        added_lines=patch["added_lines"],
                        removed_lines=patch["removed_lines"],
                        hunk_count=patch["hunk_count"],
                        diff_text=patch["diff_text"],
                        before_code=patch.get("before_code"),
                        after_code=patch.get("after_code"),
                    )
                typer.echo(f"      {len(patch_list)} patch(er) lagret")
            except Exception as e:
                typer.echo(f"      Patch-henting feilet: {e}")

    conn.close()
    
    try:
        cleanup_all_temp_repos()
    except Exception as e:
        typer.echo(f"Cleanup av temp_repos feilet, men ingest fortsetter. ({e})")
     
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
    import re

    conn = connect(DB_PATH)

    def _safe(v) -> str:
        return "" if v is None else str(v)

    def _count_type_changes(diff_text: str) -> int:
        """Heuristikk: teller -/+ linjepar med felles identifikator(er) og typeord."""
        if not diff_text:
            return 0

        type_words = {
            # C/C++
            "int", "char", "short", "long", "float", "double", "size_t", "ssize_t", "bool",
            "unsigned", "signed", "const", "volatile", "struct", "enum", "void",
            # Java/C#
            "boolean", "string", "String", "Integer", "Long", "Double", "Float", "Object",
            # TS/JS
            "number", "any", "unknown", "never",
        }
        keywords = {
            "return", "if", "else", "for", "while", "switch", "case", "break", "continue",
            "static", "public", "private", "protected", "final", "class", "interface", "def",
        }

        lines = diff_text.splitlines()
        content = [ln for ln in lines if not ln.startswith(("diff --git", "index ", "---", "+++", "@@"))]

        type_changes = 0
        i = 0
        while i < len(content) - 1:
            a = content[i]
            b = content[i + 1]
            if a.startswith("-") and b.startswith("+") and not a.startswith("---") and not b.startswith("+++"):
                a_txt = a[1:].strip()
                b_txt = b[1:].strip()

                a_has_type = any(re.search(rf"\b{re.escape(t)}\b", a_txt) for t in type_words)
                b_has_type = any(re.search(rf"\b{re.escape(t)}\b", b_txt) for t in type_words)
                if a_has_type or b_has_type:
                    a_ids = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", a_txt)) - keywords
                    b_ids = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", b_txt)) - keywords
                    if a_ids & b_ids:
                        type_changes += 1
                i += 2
                continue
            i += 1
        return type_changes

    def _slim_diff(diff_text: str) -> str:
        """Kun +/- linjer, uten diff-metadata (slik skjermbildet ditt viser)."""
        if not diff_text:
            return ""
        out_lines: list[str] = []
        for ln in diff_text.splitlines():
            if ln.startswith(("diff --git", "index ", "@@", "---", "+++")):
                continue
            if ln.startswith("+") and not ln.startswith("+++"):
                out_lines.append(f"+ {ln[1:]}")
            elif ln.startswith("-") and not ln.startswith("---"):
                out_lines.append(f"- {ln[1:]}")
        return "\n".join(out_lines)

    cve_row = conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if not cve_row:
        typer.echo(f"CVE {cve_id} ikke funnet")
        conn.close()
        return

    commits = get_commits_for_cve(conn, cve_id)
    sep = "=" * 70

    if not commits:
        typer.echo(sep)
        typer.echo(f"CVE: {cve_id}")
        typer.echo(f"Title: {_safe(cve_row['cve_title'])}")
        typer.echo(f"Description: {_safe(cve_row['description'])}")
        typer.echo(f"CVSS: {_safe(cve_row['cvss_score'])} ({_safe(cve_row['severity'])})")
        typer.echo(f"CWE: {_safe(cve_row['cwe'])}")
        typer.echo(f"Published: {_safe(cve_row['published'])}")
        typer.echo(f"State: {_safe(cve_row['state'])}")
        typer.echo(sep)
        conn.close()
        return

    for commit in commits:
        repo_url = commit["repo_url"]
        sha = commit["sha"]
        patches = get_patches_for_commit(conn, repo_url, sha)

        typer.echo(sep)
        typer.echo(f"CVE: {cve_id}")
        typer.echo(f"Title: {_safe(cve_row['cve_title'])}")
        typer.echo(f"Description: {_safe(cve_row['description'])}")
        typer.echo(f"CVSS: {_safe(cve_row['cvss_score'])} ({_safe(cve_row['severity'])})")
        typer.echo(f"CWE: {_safe(cve_row['cwe'])}")
        typer.echo(f"Published: {_safe(cve_row['published'])}")
        typer.echo(f"State: {_safe(cve_row['state'])}")
        typer.echo(f"Commit: {sha[:12]}...")
        typer.echo(f"Repository: {repo_url}")
        typer.echo(f"Files modified: {len(patches)}")
        typer.echo(sep)
        typer.echo("")

        total_added = 0
        total_removed = 0
        type_changes = 0

        for idx, p in enumerate(patches, start=1):
            file_path = p["file_path"]
            before_code = _safe(p["before_code"] if "before_code" in p.keys() else None)
            after_code = _safe(p["after_code"] if "after_code" in p.keys() else None)
            diff_text = _safe(p["diff_text"] if "diff_text" in p.keys() else None)

            total_added += int(p["added_lines"] or 0)
            total_removed += int(p["removed_lines"] or 0)
            type_changes += _count_type_changes(diff_text)

            typer.echo(f"[{idx}/{len(patches)}] File: {file_path}")
            typer.echo("-" * 70)
            typer.echo("")
            typer.echo("--- BEFORE")
            typer.echo(before_code.rstrip())
            typer.echo("")
            typer.echo("+++ AFTER")
            typer.echo(after_code.rstrip())
            typer.echo("")
            typer.echo("--- DIFF")
            slim = _slim_diff(diff_text)
            typer.echo((slim or diff_text).rstrip())
            typer.echo("")
            typer.echo("-" * 70)
            typer.echo("")

        typer.echo(sep)
        typer.echo("Summary:")
        typer.echo(f"- Files processed: {len(patches)}")
        typer.echo(f"- Lines added: {total_added}")
        typer.echo(f"- Lines removed: {total_removed}")
        typer.echo(f"- Type changes detected: {type_changes}")
        typer.echo(sep)

    conn.close()


if __name__ == "__main__":
    app()