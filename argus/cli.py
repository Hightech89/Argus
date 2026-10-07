"""Command-line interface for Argus."""

from datetime import datetime, timedelta, timezone

import typer

from argus import __version__
from argus.analysis import build_daily_security_brief, select_event_window
from argus.collectors import collect_crowdsec_evidence, collect_docker_evidence
from argus.events import crowdsec_events_from_evidence
from argus.report import render_brief, render_daily_security_brief
from argus.storage import EvidenceStore, default_database_path

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


@app.command()
def collect() -> None:
    """Collect and persist one Docker and CrowdSec telemetry snapshot."""
    try:
        database_path = default_database_path()
        database_path.parent.mkdir(parents=True, exist_ok=True)

        store = EvidenceStore(database_path)
        store.initialize()
        collected_at = _utc_now()

        docker_evidence = collect_docker_evidence()
        crowdsec_evidence = collect_crowdsec_evidence()
        evidence = [*docker_evidence, *crowdsec_evidence]
        collection_id = store.add_collection(evidence, collected_at=collected_at)
    except Exception as error:
        typer.echo(f"ARGUS COLLECTION FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error

    typer.echo(
        "\n".join(
            (
                "ARGUS COLLECTION COMPLETE",
                "",
                f"Collection: {collection_id}",
                f"Evidence stored: {len(evidence)}",
                f"Docker records: {len(docker_evidence)}",
                f"CrowdSec records: {len(crowdsec_evidence)}",
                f"Database: {database_path}",
            )
        )
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


if __name__ == "__main__":
    app()
