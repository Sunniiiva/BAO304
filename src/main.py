from cve import fetch_cve
from repo import fetch_commit

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
    """kaller fetch_cve, fetch_commit, fetch_patch"""
    




if __name__ == "__main__":
    app()
 




# logging og feilhåntering
