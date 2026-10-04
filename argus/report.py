"""Report helpers for Argus."""

from __future__ import annotations

from collections.abc import Iterable

from argus.analysis import DailySecurityBrief
from argus.models import Evidence, SecurityEvent, Severity

CHECK = "\u2713"
BULLET = "\u2022"


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
        lines.extend(
            f"{BULLET} {event.timestamp.isoformat()} | {event.severity.value} | {event.summary}"
            for event in events
        )
    else:
        lines.append("None")
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
