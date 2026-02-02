
from cve.fetch_cve import load_cve_from_file
from repo.fetch_commit import extract_repo_and_hash
from patch.fetch_patch import fetch_patch_data
from db.database import init_db
import typer 

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
