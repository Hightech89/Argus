"""Command-line interface for Argus."""

import typer

from argus import __version__

app = typer.Typer(
    help="Evidence-driven Security Operations Copilot for Home SOC environments."
)


@app.callback()
def main() -> None:
    """Argus command group."""


@app.command()
def brief() -> None:
    """Show the current Argus brief."""
    typer.echo(f"ARGUS v{__version__.removesuffix('.0')}")
    typer.echo()
    typer.echo("Evidence-driven Security Operations Copilot")
    typer.echo()
    typer.echo("No collectors configured.")


if __name__ == "__main__":
    app()
