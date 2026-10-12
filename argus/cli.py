"""Command-line interface for Argus."""

import shutil
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path

import typer

from argus import __version__
from argus.analysis import (
    build_daily_security_brief,
    select_event_window,
)
from argus.collection_lock import collection_lock
from argus.collectors import (
    collect_crowdsec_evidence,
    collect_docker_evidence,
    collect_linux_auth_evidence,
)
from argus.events import crowdsec_events_from_evidence, linux_auth_events_from_evidence
from argus.historical import reconstruct_historical_events
from argus.report import (
    render_brief,
    render_daily_security_brief,
    render_investigation,
    render_security_summary,
)
from argus.security_summary import build_security_summary
from argus.storage import EvidenceStore, StorageCounts, default_database_path

LOW_SPACE_WARNING_BYTES = 1024**3

app = typer.Typer(
    help="Evidence-driven Security Operations Copilot for Home SOC environments."
)


class InvestigationSource(StrEnum):
    ALL = "all"
    CROWDSEC = "crowdsec"
    LINUX_AUTH = "linux-auth"


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
    """Show CrowdSec and SSH security activity from the rolling 24-hour window."""
    crowdsec_evidence = collect_crowdsec_evidence()
    linux_auth_evidence = collect_linux_auth_evidence()
    now = _utc_now()
    events = [
        *crowdsec_events_from_evidence(crowdsec_evidence),
        *linux_auth_events_from_evidence(linux_auth_evidence),
    ]
    event_window = select_event_window(events, now=now)
    brief = build_daily_security_brief(
        event_window,
        window_start=now - timedelta(hours=24),
        window_end=now,
    )
    typer.echo(render_daily_security_brief(brief))


@app.command()
def collect() -> None:
    """Collect and persist one Docker, CrowdSec, and Linux auth snapshot."""
    try:
        database_path = default_database_path()
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with collection_lock(database_path):
            store = EvidenceStore(database_path)
            store.initialize()
            collected_at = _utc_now()

            docker_evidence = collect_docker_evidence()
            crowdsec_evidence = collect_crowdsec_evidence()
            linux_auth_evidence = collect_linux_auth_evidence()
            evidence = [*docker_evidence, *crowdsec_evidence, *linux_auth_evidence]
            collection_id = store.add_collection(evidence, collected_at=collected_at)
            stored_evidence = store.list_collection_evidence(collection_id)
    except Exception as error:
        typer.echo(f"ARGUS COLLECTION FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error

    typer.echo(
        "\n".join(
            (
                "ARGUS COLLECTION COMPLETE",
                "",
                f"Collection: {collection_id}",
                f"Evidence collected: {len(evidence)}",
                f"Evidence stored: {len(stored_evidence)}",
                f"Docker records: {len(docker_evidence)}",
                f"CrowdSec records: {len(crowdsec_evidence)}",
                f"Linux auth records collected: {len(linux_auth_evidence)}",
                "Linux auth records stored: "
                f"{sum(record.source.startswith('linux.auth.') for record in stored_evidence)}",
                f"Database: {database_path}",
            )
        )
    )


@app.command()
def storage() -> None:
    """Report local SQLite size, evidence counts, and available disk space."""
    try:
        database_path = default_database_path()
        if database_path.exists() and not database_path.is_file():
            raise OSError(f"database path is not a file: {database_path}")
        exists = database_path.is_file()
        counts = (
            EvidenceStore(database_path).storage_counts()
            if exists else StorageCounts(0, 0, ())
        )
        database_bytes = database_path.stat().st_size if exists else 0
        auxiliary_bytes = sum(
            auxiliary.stat().st_size
            for suffix in ("-wal", "-shm", "-journal")
            if (auxiliary := Path(f"{database_path}{suffix}")).is_file()
        )
        filesystem_path = database_path.parent
        while not filesystem_path.exists():
            filesystem_path = filesystem_path.parent
        available_bytes = shutil.disk_usage(filesystem_path).free
    except Exception as error:
        typer.echo(f"ARGUS STORAGE FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error

    lines = [
        "ARGUS STORAGE",
        "",
        f"Database: {database_path}",
        f"Database file size: {database_bytes} bytes",
        f"SQLite auxiliary files: {auxiliary_bytes} bytes",
        f"Total SQLite files: {database_bytes + auxiliary_bytes} bytes",
        f"Available filesystem space: {available_bytes} bytes",
        f"Collection runs: {counts.collection_runs}",
        f"Evidence records: {counts.evidence_records}",
        "Evidence by source:",
        *(f"  {source}: {count}" for source, count in counts.by_source),
    ]
    if not counts.by_source:
        lines.append("  None")
    if not exists:
        lines.append("No database found; run `argus collect` to create one.")
    if available_bytes < LOW_SPACE_WARNING_BYTES:
        lines.append("WARNING: available disk space is below 1 GiB.")
    typer.echo("\n".join(lines))


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
            linux_auth_count = sum(
                record.source.startswith("linux.auth.") for record in evidence
            )
            other_count = (
                len(evidence) - docker_count - crowdsec_count - linux_auth_count
            )
            lines = [
                f"Collection {collection.id}",
                f"Time: {collection.collected_at.isoformat()}",
                f"Evidence: {len(evidence)}",
                f"Docker records: {docker_count}",
                f"CrowdSec records: {crowdsec_count}",
                f"Linux auth records: {linux_auth_count}",
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


@app.command()
def investigate(
    limit: int = typer.Option(100, min=1, help="Maximum events to show."),
    source: InvestigationSource = typer.Option(
        InvestigationSource.ALL, help="Security event source."
    ),
    hours: int | None = typer.Option(
        None, min=1, help="Look back this many hours (default: 24)."
    ),
    all_history: bool = typer.Option(
        False, "--all", help="Search all stored history."
    ),
) -> None:
    """Reconstruct security events from stored Evidence within a time window."""
    if hours is not None and all_history:
        raise typer.BadParameter(
            "--hours cannot be combined with --all", param_hint="--hours"
        )

    try:
        now = _utc_now()
        lookback = timedelta(hours=hours if hours is not None else 24)
        window_start = None if all_history else now - lookback
        database_path = default_database_path()
        selection = reconstruct_historical_events(
            EvidenceStore(database_path) if database_path.is_file() else None,
            source=source.value,
            now=now,
            window=None if all_history else lookback,
        )
        displayed = selection.events[:limit]
    except Exception as error:
        typer.echo(f"ARGUS INVESTIGATION FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error

    typer.echo(
        render_investigation(
            displayed,
            window_start=window_start,
            window_end=now,
            matching_total=len(selection.events),
        )
    )


@app.command()
def summary(
    hours: int | None = typer.Option(
        None, min=1, help="Look back this many hours (default: 24)."
    ),
    all_history: bool = typer.Option(
        False, "--all", help="Summarize all stored history."
    ),
) -> None:
    """Summarize stored security activity without live collection."""
    if hours is not None and all_history:
        raise typer.BadParameter(
            "--hours cannot be combined with --all", param_hint="--hours"
        )
    try:
        now = _utc_now()
        lookback = timedelta(hours=hours if hours is not None else 24)
        window_start = None if all_history else now - lookback
        database_path = default_database_path()
        selection = reconstruct_historical_events(
            EvidenceStore(database_path) if database_path.is_file() else None,
            source="all",
            now=now,
            window=None if all_history else lookback,
        )
        report = build_security_summary(
            selection.events,
            selection.collections,
            window_start=window_start,
            window_end=now,
            all_collection_count=selection.all_collection_count,
        )
    except Exception as error:
        typer.echo(f"ARGUS SUMMARY FAILED: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(render_security_summary(report))


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
