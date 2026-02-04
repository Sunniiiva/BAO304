
import glob
import typer
from pathlib import Path

# CVE

from src.cve import (
    load_cve_from_file,
    extract_cve_info,
    extract_products,
   extract_grouped_references,)

 #Repo / commits
from src.repo import (
    extract_repo_and_hash,
    fetch_commit_data, 
    fetch_commit_modified_files,)

# Patch
from src.patch import fetch_patch_data

# Database
from src.db import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    link_cve_commit,
)



app = typer.Typer()

# kode som kjøres dersom parametere ikke er gitt

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("Ingen kommando er gitt. bruk --help for mer informasjon.")
        raise typer.Exit(code=0)
#test kode
@app.command()
def hello():
    """Sier hello (testkommando)"""
    print("hello")

# kalle moduler i rekkefølge: fetch_cve, fetch_commit, fetch_patch.
@app.command()
def kallmoduler():
    data = load_cve_from_file("../../data/raw/cve/CVE-2026-24001.json")
    




if __name__ == "__main__":
    app()
 




# logging og feilhåntering
