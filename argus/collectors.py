"""Read-only Docker and CrowdSec evidence collectors."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any

from argus.models import Evidence

DOCKER_TIMEOUT_SECONDS = 10
JOURNAL_TIMEOUT_SECONDS = 10
CROWDSEC_CONTAINER_NAME = "crowdsec"


def collect_linux_auth_evidence() -> list[Evidence]:
    """Collect sshd journal observations from the previous 24 hours."""
    observed_at = _utc_now()
    command = [
        "journalctl",
        "--no-pager",
        "--output=json",
        "--since",
        "24 hours ago",
        "SYSLOG_IDENTIFIER=sshd",
        "+",
        "SYSLOG_IDENTIFIER=sshd-session",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=JOURNAL_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return _linux_auth_failure("journalctl command not found.", observed_at)
    except subprocess.TimeoutExpired:
        return _linux_auth_failure("journalctl command timed out.", observed_at)
    except OSError as error:
        return _linux_auth_failure(f"journalctl could not run: {error}", observed_at)

    if result.returncode != 0:
        return _linux_auth_failure(
            result.stderr.strip()
            or f"journalctl exited with status {result.returncode}.",
            observed_at,
        )

    raw_records: list[Evidence] = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            raw_records.append(
                Evidence(
                    source="linux.auth.raw",
                    content=json.dumps(record, sort_keys=True, separators=(",", ":")),
                    observed_at=observed_at,
                )
            )
    return [
        _boolean_evidence("linux.auth.available", True, observed_at),
        Evidence("linux.auth.records_count", str(len(raw_records)), observed_at),
        *raw_records,
    ]


def _linux_auth_failure(message: str, observed_at: datetime) -> list[Evidence]:
    return [
        _boolean_evidence("linux.auth.available", False, observed_at),
        Evidence("linux.auth.error", message, observed_at),
    ]


def collect_docker_evidence() -> list[Evidence]:
    """Collect read-only Docker operational evidence."""
    observed_at = _utc_now()
    evidence: list[Evidence] = []

    version_code, _, version_error = _run_docker(["--version"])
    docker_installed = version_code == 0
    evidence.append(_boolean_evidence("docker.installed", docker_installed, observed_at))

    if not docker_installed:
        evidence.append(Evidence(source="docker.error", content=version_error, observed_at=observed_at))
        evidence.append(_boolean_evidence("docker.daemon_running", False, observed_at))
        return evidence

    info_code, _, info_error = _run_docker(
        ["info", "--format", "{{json .ServerVersion}}"]
    )
    daemon_running = info_code == 0
    evidence.append(_boolean_evidence("docker.daemon_running", daemon_running, observed_at))

    if not daemon_running:
        evidence.append(Evidence(source="docker.error", content=info_error, observed_at=observed_at))
        return evidence

    ps_code, ps_output, ps_error = _run_docker(
        ["ps", "-a", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"]
    )

    if ps_code != 0:
        evidence.append(Evidence(source="docker.error", content=ps_error, observed_at=observed_at))
        return evidence

    containers = sorted(_parse_containers(ps_output), key=lambda item: item["name"])
    evidence.append(
        Evidence(source="docker.containers.total", content=str(len(containers)), observed_at=observed_at)
    )

    for container in containers:
        name = container["name"]
        state = container["state"]
        status = container["status"]

        if state == "running":
            evidence.append(Evidence(source="docker.container.running", content=name, observed_at=observed_at))
        elif state == "exited":
            evidence.append(Evidence(source="docker.container.exited", content=name, observed_at=observed_at))

        if "(unhealthy)" in status:
            evidence.append(Evidence(source="docker.container.unhealthy", content=name, observed_at=observed_at))

    return evidence


def collect_crowdsec_evidence() -> list[Evidence]:
    """Collect read-only CrowdSec operational evidence from its container."""
    observed_at = _utc_now()
    evidence: list[Evidence] = []

    ps_code, ps_output, ps_error = _run_docker(
        [
            "ps",
            "-a",
            "--filter",
            f"name={CROWDSEC_CONTAINER_NAME}",
            "--format",
            "{{.Names}}\t{{.State}}\t{{.Status}}",
        ]
    )

    if ps_code != 0:
        evidence.append(_boolean_evidence("crowdsec.available", False, observed_at))
        evidence.append(_boolean_evidence("crowdsec.container_running", False, observed_at))
        evidence.append(_boolean_evidence("crowdsec.api_healthy", False, observed_at))
        evidence.append(Evidence(source="crowdsec.error", content=ps_error, observed_at=observed_at))
        return evidence

    container = _select_crowdsec_container(_parse_containers(ps_output))
    if container is None:
        evidence.append(_boolean_evidence("crowdsec.available", False, observed_at))
        evidence.append(_boolean_evidence("crowdsec.container_running", False, observed_at))
        evidence.append(_boolean_evidence("crowdsec.api_healthy", False, observed_at))
        evidence.append(Evidence(source="crowdsec.alerts.active_count", content="0", observed_at=observed_at))
        return evidence

    name = container["name"]
    running = container["state"] == "running"
    evidence.append(_boolean_evidence("crowdsec.available", True, observed_at))
    evidence.append(Evidence(source="crowdsec.container.name", content=name, observed_at=observed_at))
    evidence.append(_boolean_evidence("crowdsec.container_running", running, observed_at))
    evidence.append(
        Evidence(
            source="crowdsec.container_health",
            content=_container_health(container["status"], running),
            observed_at=observed_at,
        )
    )

    if not running:
        evidence.append(_boolean_evidence("crowdsec.api_healthy", False, observed_at))
        return evidence

    api_code, _, api_error = _run_docker(["exec", name, "cscli", "lapi", "status"])
    api_healthy = api_code == 0
    evidence.append(_boolean_evidence("crowdsec.api_healthy", api_healthy, observed_at))

    if not api_healthy:
        evidence.append(Evidence(source="crowdsec.error", content=api_error, observed_at=observed_at))
        return evidence

    alerts_code, alerts_output, alerts_error = _run_docker(
        ["exec", name, "cscli", "alerts", "list", "-o", "json"]
    )

    if alerts_code != 0:
        evidence.append(Evidence(source="crowdsec.error", content=alerts_error, observed_at=observed_at))
        return evidence

    alerts = _parse_crowdsec_alerts(alerts_output)
    evidence.append(
        Evidence(source="crowdsec.alerts.active_count", content=str(len(alerts)), observed_at=observed_at)
    )
    for alert in alerts:
        evidence.append(
            Evidence(
                source="crowdsec.alert.raw",
                content=json.dumps(alert, sort_keys=True, separators=(",", ":")),
                observed_at=observed_at,
            )
        )

    latest_alert = _latest_alert(alerts)
    if latest_alert is not None:
        evidence.append(
            Evidence(source="crowdsec.alert.latest", content=_alert_summary(latest_alert), observed_at=observed_at)
        )
        evidence.append(
            Evidence(source="crowdsec.alert.latest_reason", content=_alert_reason(latest_alert), observed_at=observed_at)
        )
        evidence.append(
            Evidence(
                source="crowdsec.alert.latest_timestamp",
                content=_alert_timestamp(latest_alert),
                observed_at=observed_at,
            )
        )

    return evidence


def _run_docker(args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["docker", *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return 127, "", "Docker CLI not found."
    except subprocess.TimeoutExpired as error:
        return 124, _as_text(error.stdout), "Docker CLI command timed out."

    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _parse_containers(output: str) -> list[dict[str, str]]:
    containers: list[dict[str, str]] = []

    for line in output.splitlines():
        parts = line.split("\t", maxsplit=2)
        if len(parts) != 3:
            continue

        name, state, status = parts
        if not name:
            continue

        containers.append(
            {
                "name": name,
                "state": state.lower(),
                "status": status.lower(),
            }
        )

    return containers


def _select_crowdsec_container(
    containers: list[dict[str, str]],
) -> dict[str, str] | None:
    for container in containers:
        if container["name"] == CROWDSEC_CONTAINER_NAME:
            return container

    for container in containers:
        if CROWDSEC_CONTAINER_NAME in container["name"]:
            return container

    return None


def _container_health(status: str, running: bool) -> str:
    if not running:
        return "not running"
    if "(unhealthy)" in status:
        return "unhealthy"
    if "(healthy)" in status:
        return "healthy"
    return "unknown"


def _parse_crowdsec_alerts(output: str) -> list[dict[str, Any]]:
    if not output:
        return []

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []

    if isinstance(payload, list):
        return [alert for alert in payload if isinstance(alert, dict)]

    if isinstance(payload, dict):
        for key in ("alerts", "items", "data"):
            alerts = payload.get(key)
            if isinstance(alerts, list):
                return [alert for alert in alerts if isinstance(alert, dict)]

    return []


def _latest_alert(alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not alerts:
        return None
    return max(alerts, key=lambda alert: _alert_timestamp(alert))


def _alert_summary(alert: dict[str, Any]) -> str:
    alert_id = alert.get("id")
    scenario = alert.get("scenario")

    if alert_id is not None and scenario:
        return f"{alert_id}: {scenario}"
    if alert_id is not None:
        return str(alert_id)
    if scenario:
        return str(scenario)
    return _alert_reason(alert)


def _alert_reason(alert: dict[str, Any]) -> str:
    for key in ("message", "reason", "scenario"):
        value = alert.get(key)
        if value:
            return str(value)
    return "Unknown"


def _alert_timestamp(alert: dict[str, Any]) -> str:
    for key in ("created_at", "start_at", "stop_at", "updated_at"):
        value = alert.get(key)
        if value:
            return str(value)
    return ""


def _boolean_evidence(source: str, value: bool, observed_at: datetime) -> Evidence:
    return Evidence(source=source, content="true" if value else "false", observed_at=observed_at)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)
