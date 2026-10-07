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


@app.command()
def history(
    limit: int = typer.Option(10, min=1, help="Maximum collection runs to show."),
) -> None:
    """Show recent stored collection snapshots and observation counts."""
    try:
        database_path = default_database_path()
        if not database_path.is_file():
            typer.echo(_empty_history())
            return
        store = EvidenceStore(database_path)
        collections = store.list_collections()[:limit]
        sections: list[str] = []
        for collection in collections:
            evidence = store.list_collection_evidence(collection.id)
            docker_count = sum(
                record.source.startswith("docker.") for record in evidence
            )
            crowdsec_count = sum(
                record.source.startswith("crowdsec.") for record in evidence
            )
            other_count = len(evidence) - docker_count - crowdsec_count
            lines = [
                f"Collection {collection.id}",
                f"Time: {collection.collected_at.isoformat()}",
                f"Evidence: {len(evidence)}",
                f"Docker records: {docker_count}",
                f"CrowdSec records: {crowdsec_count}",
            ]
            if other_count:
                lines.append(f"Other records: {other_count}")
            sections.append("\n".join(lines))
    except Exception as error:
        typer.echo(f"ARGUS HISTORY FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error

    if not collections:
        typer.echo(_empty_history())
        return
    typer.echo(
        "ARGUS HISTORY\n\n"
        "Stored observations grouped by collection run.\n\n"
        + "\n\n".join(sections)
    )


def _empty_history() -> str:
    return (
        "ARGUS HISTORY\n\n"
        "No collection history found.\n"
        "Run `argus collect` to save a telemetry snapshot."
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


if __name__ == "__main__":
    app()
