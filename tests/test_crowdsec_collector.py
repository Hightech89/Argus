"""CrowdSec collector behavior tests."""

from __future__ import annotations

import json
import subprocess
import unittest
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from argus.collectors import collect_crowdsec_evidence
from argus.models import Evidence

_OBSERVED_AT = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


class CrowdSecCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        clock = patch("argus.collectors._utc_now", return_value=_OBSERVED_AT)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    def test_crowdsec_unavailable_when_docker_cli_is_missing(self) -> None:
        with patch("argus.collectors.subprocess.run", side_effect=FileNotFoundError):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.available"], "false")
        self.assertEqual(records["crowdsec.container_running"], "false")
        self.assertEqual(records["crowdsec.api_healthy"], "false")
        self.assertEqual(records["crowdsec.error"], "Docker CLI not found.")
        self.assert_observed(evidence)

    def test_crowdsec_unavailable_when_container_is_missing(self) -> None:
        runner = _DockerRunner({_docker_ps_command(): _completed("")})

        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        records = _records(evidence)
        self.assertEqual(records["crowdsec.available"], "false")
        self.assertEqual(records["crowdsec.container_running"], "false")
        self.assertEqual(records["crowdsec.api_healthy"], "false")
        self.assertEqual(records["crowdsec.alerts.active_count"], "0")
        self.assert_observed(evidence)

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
        self.assertEqual(_contents(evidence, "crowdsec.alert.raw"), [])
        self.assert_observed(evidence)

    def test_one_alert_creates_one_deterministic_raw_record(self) -> None:
        alert = {
            "scenario": "crowdsecurity/ssh-bf",
            "id": 10,
            "source": {"scope": "Ip", "ip": "203.0.113.10"},
            "created_at": "2026-08-29T10:00:00Z",
        }
        runner = _DockerRunner(
            {
                _docker_ps_command(): _completed("crowdsec\trunning\tUp 3 hours"),
                _lapi_status_command(): _completed("OK"),
                _alerts_command(): _completed(json.dumps([alert])),
            }
        )

        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        raw = [
            record for record in evidence if record.source == "crowdsec.alert.raw"
        ]
        self.assertEqual(len(raw), 1)
        self.assertEqual(
            raw[0].content,
            '{"created_at":"2026-08-29T10:00:00Z","id":10,'
            '"scenario":"crowdsecurity/ssh-bf",'
            '"source":{"ip":"203.0.113.10","scope":"Ip"}}',
        )
        self.assertEqual(json.loads(raw[0].content), alert)
        self.assertIs(raw[0].observed_at, _OBSERVED_AT)
        self.assert_observed(evidence)

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
        raw = _contents(evidence, "crowdsec.alert.raw")
        self.assertEqual(len(raw), 2)
        self.assertEqual(json.loads(raw[0])["id"], 10)
        self.assertEqual(json.loads(raw[0])["message"], "SSH brute force from 203.0.113.10")
        self.assertEqual(json.loads(raw[1])["id"], 11)
        self.assertEqual(json.loads(raw[1])["message"], "HTTP probing from 198.51.100.20")
        raw_records = [
            record for record in evidence if record.source == "crowdsec.alert.raw"
        ]
        self.assertTrue(
            all(record.observed_at is _OBSERVED_AT for record in raw_records)
        )
        self.assertNotEqual(records["crowdsec.alert.latest_timestamp"], _OBSERVED_AT.isoformat())
        self.assert_observed(evidence)

    def test_non_dict_alert_entries_are_ignored(self) -> None:
        alerts = json.dumps(
            [
                "invalid",
                {"id": 12, "scenario": "crowdsecurity/ssh-bf"},
                None,
                42,
            ]
        )
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
        self.assertEqual(records["crowdsec.alerts.active_count"], "1")
        self.assertEqual(
            _contents(evidence, "crowdsec.alert.raw"),
            ['{"id":12,"scenario":"crowdsecurity/ssh-bf"}'],
        )
        self.assertEqual(
            records["crowdsec.alert.latest"], "12: crowdsecurity/ssh-bf"
        )
        self.assert_observed(evidence)

    def test_docker_listing_error_is_observed(self) -> None:
        runner = _DockerRunner({_docker_ps_command(): _completed(stderr="denied", returncode=1)})
        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        self.assertEqual(_records(evidence)["crowdsec.error"], "denied")
        self.assert_observed(evidence)

    def test_lapi_error_is_observed(self) -> None:
        runner = _DockerRunner({
            _docker_ps_command(): _completed("crowdsec\trunning\tUp 3 hours"),
            _lapi_status_command(): _completed(stderr="LAPI unavailable", returncode=1),
        })
        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        self.assertEqual(_records(evidence)["crowdsec.error"], "LAPI unavailable")
        self.assert_observed(evidence)

    def test_alert_listing_error_is_observed(self) -> None:
        runner = _DockerRunner({
            _docker_ps_command(): _completed("crowdsec\trunning\tUp 3 hours"),
            _lapi_status_command(): _completed("OK"),
            _alerts_command(): _completed(stderr="alerts unavailable", returncode=1),
        })
        with patch("argus.collectors.subprocess.run", side_effect=runner):
            evidence = collect_crowdsec_evidence()

        self.assertEqual(_records(evidence)["crowdsec.error"], "alerts unavailable")
        self.assert_observed(evidence)

    def test_collection_timestamp_is_captured_before_docker_commands(self) -> None:
        def run(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
            self.clock.assert_called_once_with()
            return _completed(stderr="Docker unavailable", returncode=1)

        with patch("argus.collectors.subprocess.run", side_effect=run):
            evidence = collect_crowdsec_evidence()

        self.assert_observed(evidence)

    def assert_observed(self, evidence: list[Evidence]) -> None:
        self.assertTrue(evidence)
        self.clock.assert_called_once_with()
        for record in evidence:
            self.assertIs(record.observed_at, _OBSERVED_AT)
            self.assertIsNotNone(record.observed_at.tzinfo)
            self.assertEqual(record.observed_at.utcoffset(), timedelta(0))


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


def _contents(evidence: Iterable[Evidence], source: str) -> list[str]:
    return [record.content for record in evidence if record.source == source]


if __name__ == "__main__":
    unittest.main()
