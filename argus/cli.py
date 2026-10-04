"""Command-line interface for Argus."""

from datetime import datetime, timedelta, timezone

import typer

from argus import __version__
from argus.analysis import build_daily_security_brief, select_event_window
from argus.collectors import collect_crowdsec_evidence, collect_docker_evidence
from argus.events import crowdsec_events_from_evidence
from argus.report import render_brief, render_daily_security_brief

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


@app.command()
def daily() -> None:
    """Show CrowdSec security activity from the rolling 24-hour window."""
    evidence = collect_crowdsec_evidence()
    now = _utc_now()
    events = crowdsec_events_from_evidence(evidence)
    event_window = select_event_window(events, now=now)
    brief = build_daily_security_brief(
        event_window,
        window_start=now - timedelta(hours=24),
        window_end=now,
    )
    typer.echo(render_daily_security_brief(brief))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


if __name__ == "__main__":
    app()
