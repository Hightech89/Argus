"""Command-line interface for Argus."""

import typer

from argus import __version__
from argus.collectors import collect_crowdsec_evidence, collect_docker_evidence
from argus.report import render_brief

app = typer.Typer(
    help="Evidence-driven Security Operations Copilot for Home SOC environments."
)


@app.callback()
def main() -> None:
    """Argus command group."""


@app.command()
def brief() -> None:
    """Show the current Argus brief."""
    evidence = collect_docker_evidence()
    evidence.extend(collect_crowdsec_evidence())
    typer.echo(render_brief(evidence, version=__version__))


if __name__ == "__main__":
    app()
