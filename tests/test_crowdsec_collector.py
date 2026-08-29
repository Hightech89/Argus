"""CrowdSec collector behavior tests."""

from __future__ import annotations

import subprocess
import unittest
from collections.abc import Iterable
from unittest.mock import patch

from argus.collectors import collect_crowdsec_evidence
from argus.models import Evidence


class CrowdSecCollectorTests(unittest.TestCase):
    def test_crowdsec_unavailable_when_docker_cli_is_missing(self) -> None:
        with patch("argus.collectors.subprocess.run", side_effect=FileNotFoundError):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.available"], "false")
        self.assertEqual(records["crowdsec.container_running"], "false")
        self.assertEqual(records["crowdsec.api_healthy"], "false")
        self.assertEqual(records["crowdsec.error"], "Docker CLI not found.")

    def test_crowdsec_unavailable_when_container_is_missing(self) -> None:
        runner = _DockerRunner({_docker_ps_command(): _completed("")})

        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.available"], "false")
        self.assertEqual(records["crowdsec.container_running"], "false")
        self.assertEqual(records["crowdsec.api_healthy"], "false")
        self.assertEqual(records["crowdsec.alerts.active_count"], "0")

    def test_crowdsec_zero_alerts(self) -> None:
        runner = _DockerRunner(
            {
                _docker_ps_command(): _completed(
                    "crowdsec\trunning\tUp 3 hours (healthy)"
                ),
                _lapi_status_command(): _completed("OK"),
                _alerts_command(): _completed("[]"),
            }
        )

        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.available"], "true")
        self.assertEqual(records["crowdsec.container_running"], "true")
        self.assertEqual(records["crowdsec.container_health"], "healthy")
        self.assertEqual(records["crowdsec.api_healthy"], "true")
        self.assertEqual(records["crowdsec.alerts.active_count"], "0")
        self.assertNotIn("crowdsec.alert.latest", records)

    def test_crowdsec_active_alerts(self) -> None:
        alerts = """
        [
          {
            "id": 10,
            "scenario": "crowdsecurity/ssh-bf",
            "message": "SSH brute force from 203.0.113.10",
            "created_at": "2026-08-29T10:00:00Z"
          },
          {
            "id": 11,
            "scenario": "crowdsecurity/http-probing",
            "message": "HTTP probing from 198.51.100.20",
            "created_at": "2026-08-29T10:05:00Z"
          }
        ]
        """
        runner = _DockerRunner(
            {
                _docker_ps_command(): _completed("crowdsec\trunning\tUp 3 hours"),
                _lapi_status_command(): _completed("OK"),
                _alerts_command(): _completed(alerts),
            }
        )

        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.alerts.active_count"], "2")
        self.assertEqual(
            records["crowdsec.alert.latest"], "11: crowdsecurity/http-probing"
        )
        self.assertEqual(
            records["crowdsec.alert.latest_reason"],
            "HTTP probing from 198.51.100.20",
        )
        self.assertEqual(
            records["crowdsec.alert.latest_timestamp"], "2026-08-29T10:05:00Z"
        )


class _DockerRunner:
    def __init__(
        self, responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]]
    ) -> None:
        self.responses = responses

    def __call__(self, args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        key = tuple(args)
        if key not in self.responses:
            raise AssertionError(f"unexpected command: {key}")
        return self.responses[key]


def _completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _docker_ps_command() -> tuple[str, ...]:
    return (
        "docker",
        "ps",
        "-a",
        "--filter",
        "name=crowdsec",
        "--format",
        "{{.Names}}\t{{.State}}\t{{.Status}}",
    )


def _lapi_status_command() -> tuple[str, ...]:
    return ("docker", "exec", "crowdsec", "cscli", "lapi", "status")


def _alerts_command() -> tuple[str, ...]:
    return ("docker", "exec", "crowdsec", "cscli", "alerts", "list", "-o", "json")


def _records(evidence: Iterable[Evidence]) -> dict[str, str]:
    return {record.source: record.content for record in evidence}


if __name__ == "__main__":
    unittest.main()
