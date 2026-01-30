from cve import fetch_cve
from repo import fetch_commit
from patch import fetch_patch
import typer 

app = typer.Typer()

#kode som kjøres uten parametere

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("Ingen kommando er gitt. bruk --help for mer informasjon.")
        raise typer.Exit(code=0)

@app.command()
def hello():
    print("hello")
    

if __name__ == "__main__":
    app()
# kalle moduler i rekkefølge: fetch_cve, fetch_commit, fetch_patch, 




# logging og feilhåntering
