"""Report helpers for Argus."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from argus.analysis import DailySecurityBrief
from argus.models import Evidence, SecurityEvent, Severity, TimestampBasis

CHECK = "\u2713"
BULLET = "\u2022"

_DETAIL_LABELS = {
    "alert_id": "Alert ID",
    "scenario": "Scenario",
    "source_scope": "Source Scope",
    "source_value": "Source",
    "country": "Country",
    "as_number": "ASN",
    "as_name": "AS Name",
    "event_count": "Events",
    "machine": "Machine",
    "start_at": "Start",
    "stop_at": "Stop",
    "decision_type": "Decision",
    "decision_scope": "Decision Scope",
    "decision_value": "Decision Value",
    "decision_duration": "Decision Duration",
    "remote_ip": "Remote IP",
}


def render_daily_security_brief(brief: DailySecurityBrief) -> str:
    """Render precomputed Daily Security Brief data for an operator."""
    lines = [
        "ARGUS DAILY SECURITY BRIEF",
        "",
        "Window",
        f"{brief.window_start.isoformat()} -> {brief.window_end.isoformat()}",
        "",
    ]
    lines.extend(
        _render_daily_event_group(
            title="Known Security Events",
            total=brief.occurred_count,
            severity_counts=brief.occurred_severity_counts,
            category_counts=brief.occurred_category_counts,
            event_title="Recent Events",
            events=brief.occurred,
        )
    )
    lines.extend(
        [
            "",
            "Observed - Event Time Unknown",
            f"Total: {brief.observed_count}",
            "",
            "These alerts were observed during the window, but their true occurrence",
            "time could not be determined.",
            "",
        ]
    )
    lines.extend(
        _render_daily_details(
            severity_counts=brief.observed_severity_counts,
            category_counts=brief.observed_category_counts,
            event_title="Observed Alerts",
            events=brief.observed,
        )
    )
    return "\n".join(lines)


def render_investigation(
    events: Iterable[tuple[SecurityEvent, int]],
    *,
    window_start: datetime | None,
    window_end: datetime,
    matching_total: int,
) -> str:
    """Render deduplicated historical events with their stored collection IDs."""
    displayed = tuple(events)
    window_label = (
        f"Window (UTC, inclusive): {window_start.isoformat()} -> {window_end.isoformat()}"
        if window_start is not None
        else "Window (UTC): All stored history (unbounded)"
    )
    lines = [
        "ARGUS INVESTIGATION",
        "",
        window_label,
        f"Reference time (UTC): {window_end.isoformat()}",
        f"Matching events: {matching_total}",
        f"Displayed: {len(displayed)}",
        "",
        "Security events reconstructed from stored observations.",
        "Repeated identities use the earliest stored collection; this may not be "
        "the event's first occurrence.",
    ]
    if not displayed:
        lines.extend(
            [
                "",
                "No stored security events found.",
                "The selected window may contain no matching events.",
                "Run `argus collect` to save a telemetry snapshot.",
            ]
        )
    for event, collection_id in displayed:
        basis = (
            "SOURCE (occurrence time)"
            if event.timestamp_basis is TimestampBasis.SOURCE
            else "OBSERVED (observation time; occurrence unknown)"
        )
        lines.extend(
            [
                "",
                f"{BULLET} {event.timestamp.isoformat()} | {basis} | "
                f"{event.source} | {event.severity.value} | {event.summary}",
                f"  Collection: {collection_id}",
            ]
        )
        lines.extend(_render_event_details(event.details))
    return "\n".join(lines)


def render_brief(evidence: Iterable[Evidence], version: str) -> str:
    """Render a short operational brief from collected evidence."""
    records = list(evidence)
    lines = [
        f"ARGUS v{version.removesuffix('.0')}",
        "",
        "Evidence-driven Security Operations Copilot",
        "",
    ]
    lines.extend(_render_docker_section(records))
    lines.extend([""])
    lines.extend(_render_crowdsec_section(records))

    return "\n".join(lines)


def _render_daily_event_group(
    *,
    title: str,
    total: int,
    severity_counts: tuple[tuple[Severity, int], ...],
    category_counts: tuple[tuple[str, int], ...],
    event_title: str,
    events: tuple[SecurityEvent, ...],
) -> list[str]:
    return [title, f"Total: {total}", ""] + _render_daily_details(
        severity_counts=severity_counts,
        category_counts=category_counts,
        event_title=event_title,
        events=events,
    )


def _render_daily_details(
    *,
    severity_counts: tuple[tuple[Severity, int], ...],
    category_counts: tuple[tuple[str, int], ...],
    event_title: str,
    events: tuple[SecurityEvent, ...],
) -> list[str]:
    lines = ["Severity"]
    lines.extend(
        f"{severity.value.capitalize()}: {count}"
        for severity, count in severity_counts
    )
    lines.extend(["", "Categories"])
    if category_counts:
        lines.extend(f"{category}: {count}" for category, count in category_counts)
    else:
        lines.append("None")

    lines.extend(["", event_title])
    if events:
        for event in events:
            lines.append(
                f"{BULLET} {event.timestamp.isoformat()} | "
                f"{event.severity.value} | {event.summary}"
            )
            lines.extend(_render_event_details(event.details))
    else:
        lines.append("None")
    return lines


def _detail_label(key: str) -> str:
    return _DETAIL_LABELS.get(key, key.replace("_", " ").title())


def _render_event_details(details: tuple[tuple[str, str], ...]) -> list[str]:
    lines: list[str] = []
    index = 0
    while index < len(details):
        key, value = details[index]
        next_detail = details[index + 1] if index + 1 < len(details) else None

        if key == "source_scope" and next_detail and next_detail[0] == "source_value":
            lines.append(f"  Source: {value} {next_detail[1]}")
            index += 2
            continue
        if key == "as_number" and next_detail and next_detail[0] == "as_name":
            lines.append(f"  ASN: {value} {next_detail[1]}")
            index += 2
            continue

        lines.append(f"  {_detail_label(key)}: {value}")
        index += 1
    return lines


def _render_docker_section(records: list[Evidence]) -> list[str]:
    installed = _boolean_value(records, "docker.installed")
    daemon_running = _boolean_value(records, "docker.daemon_running")
    running = _contents(records, "docker.container.running")
    exited = _contents(records, "docker.container.exited")
    unhealthy = _contents(records, "docker.container.unhealthy")
    total = _single_content(records, "docker.containers.total")
    errors = _contents(records, "docker.error")

    lines = [
        "Docker",
        _status_line(installed, "Docker installed", "Docker not installed"),
        _status_line(
            daemon_running,
            "Docker daemon running",
            "Docker daemon not running or unavailable",
        ),
    ]

    if errors:
        lines.extend(["", _clean_error(errors[0])])

    if installed and daemon_running:
        lines.extend(
            [
                "",
                "Containers",
                f"Total: {_display_count(total)}",
                f"Running: {len(running)}",
                f"Exited: {len(exited)}",
                f"Unhealthy: {len(unhealthy)}",
            ]
        )

        if running:
            lines.extend(["", "Running Containers"])
            lines.extend(f"{BULLET} {name}" for name in running)
        else:
            lines.extend(["", "Running Containers", "None"])

        if exited:
            lines.extend(["", "Exited Containers"])
            lines.extend(f"{BULLET} {name}" for name in exited)

        if unhealthy:
            lines.extend(["", "Unhealthy Containers"])
            lines.extend(f"{BULLET} {name}" for name in unhealthy)

    return lines


def _render_crowdsec_section(records: list[Evidence]) -> list[str]:
    available = _boolean_value(records, "crowdsec.available")
    container_running = _boolean_value(records, "crowdsec.container_running")
    api_healthy = _boolean_value(records, "crowdsec.api_healthy")
    container_health = _single_content(records, "crowdsec.container_health")
    active_count = _single_content(records, "crowdsec.alerts.active_count")
    latest_alert = _single_content(records, "crowdsec.alert.latest")
    latest_reason = _single_content(records, "crowdsec.alert.latest_reason")
    latest_timestamp = _single_content(records, "crowdsec.alert.latest_timestamp")
    errors = _contents(records, "crowdsec.error")

    lines = [
        "CrowdSec",
        _status_line(available, "CrowdSec available", "CrowdSec unavailable"),
        _status_line(
            container_running,
            "CrowdSec container running",
            "CrowdSec container not running",
        ),
        _status_line(
            api_healthy,
            "CrowdSec API healthy",
            "CrowdSec API unavailable",
        ),
    ]

    if container_health:
        lines.append(f"Container Health: {container_health}")

    if errors and not (available and container_running and api_healthy):
        lines.extend(["", _clean_error(errors[0], fallback="CrowdSec is unavailable.")])

    if active_count is not None:
        lines.extend(["", "CrowdSec Alerts", f"Active: {active_count}"])

    if latest_alert:
        lines.extend(
            [
                "",
                "Latest Alert",
                latest_alert,
                f"Reason: {_display_value(latest_reason)}",
                f"Timestamp: {_display_value(latest_timestamp)}",
            ]
        )

    return lines


def _status_line(value: bool | None, positive: str, negative: str) -> str:
    if value is True:
        return f"{CHECK} {positive}"
    if value is False:
        return f"x {negative}"
    return f"? {negative}"


def _boolean_value(records: list[Evidence], source: str) -> bool | None:
    content = _single_content(records, source)
    if content == "true":
        return True
    if content == "false":
        return False
    return None


def _single_content(records: list[Evidence], source: str) -> str | None:
    for record in records:
        if record.source == source:
            return record.content
    return None


def _contents(records: list[Evidence], source: str) -> list[str]:
    return [record.content for record in records if record.source == source]


def _display_count(value: str | None) -> str:
    return value if value is not None else "unknown"


def _display_value(value: str | None) -> str:
    return value if value else "unknown"


def _clean_error(error: str, fallback: str = "Docker is unavailable.") -> str:
    if not error:
        return fallback
    return error.splitlines()[0]
