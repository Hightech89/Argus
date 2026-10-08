"""Linux SSH journal collector tests; no live journal access."""

from __future__ import annotations

import json
import subprocess
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from argus.collectors import collect_linux_auth_evidence
from argus.models import Evidence

_NOW = datetime(2026, 10, 7, 18, 30, tzinfo=timezone.utc)
_COMMAND = [
    "journalctl", "--no-pager", "--output=json", "--since", "24 hours ago",
    "SYSLOG_IDENTIFIER=sshd",
]


class LinuxAuthCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        clock = patch("argus.collectors._utc_now", return_value=_NOW)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    def test_journalctl_unavailable_returns_error_evidence(self) -> None:
        with patch("argus.collectors.subprocess.run", side_effect=FileNotFoundError) as run:
            evidence = collect_linux_auth_evidence()

        self.assertEqual(
            evidence,
            [
                Evidence("linux.auth.available", "false", _NOW),
                Evidence("linux.auth.error", "journalctl command not found.", _NOW),
            ],
        )
        run.assert_called_once()
        self.clock.assert_called_once_with()

    def test_journalctl_failure_returns_stderr_as_evidence(self) -> None:
        with patch(
            "argus.collectors.subprocess.run",
            return_value=subprocess.CompletedProcess(_COMMAND, 1, "", "Permission denied\n"),
        ) as run:
            evidence = collect_linux_auth_evidence()

        self.assertEqual(
            evidence,
            [
                Evidence("linux.auth.available", "false", _NOW),
                Evidence("linux.auth.error", "Permission denied", _NOW),
            ],
        )
        run.assert_called_once_with(
            _COMMAND, capture_output=True, check=False, text=True, timeout=10
        )

    def test_timeout_returns_error_evidence(self) -> None:
        with patch(
            "argus.collectors.subprocess.run",
            side_effect=subprocess.TimeoutExpired(_COMMAND, 10),
        ):
            evidence = collect_linux_auth_evidence()

        self.assertEqual(evidence[0].content, "false")
        self.assertEqual(evidence[1].content, "journalctl command timed out.")

    def test_zero_records_reports_available_and_zero_count(self) -> None:
        with patch(
            "argus.collectors.subprocess.run",
            return_value=subprocess.CompletedProcess(_COMMAND, 0, "", ""),
        ):
            evidence = collect_linux_auth_evidence()

        self.assertEqual(
            evidence,
            [
                Evidence("linux.auth.available", "true", _NOW),
                Evidence("linux.auth.records_count", "0", _NOW),
            ],
        )

    def test_valid_objects_become_sorted_atomic_raw_evidence(self) -> None:
        first = {"z": 2, "MESSAGE": "Accepted password for alice from 192.0.2.1 port 22"}
        second = {"__CURSOR": "cursor-2", "MESSAGE": "Invalid user bob from 192.0.2.2"}
        output = "\n".join((json.dumps(first), json.dumps(second)))
        with patch(
            "argus.collectors.subprocess.run",
            return_value=subprocess.CompletedProcess(_COMMAND, 0, output, ""),
        ):
            evidence = collect_linux_auth_evidence()

        self.assertEqual([record.source for record in evidence], [
            "linux.auth.available", "linux.auth.records_count", "linux.auth.raw",
            "linux.auth.raw",
        ])
        self.assertEqual(evidence[1].content, "2")
        self.assertEqual(evidence[2].content, json.dumps(first, sort_keys=True, separators=(",", ":")))
        self.assertEqual(evidence[3].content, json.dumps(second, sort_keys=True, separators=(",", ":")))
        self.assertTrue(all(record.observed_at is _NOW for record in evidence))
        self.clock.assert_called_once_with()

    def test_malformed_lines_and_nonobjects_are_skipped(self) -> None:
        output = '\n'.join(('garbage', '[]', '{"MESSAGE":"ok"}', '{broken', '42'))
        with patch(
            "argus.collectors.subprocess.run",
            return_value=subprocess.CompletedProcess(_COMMAND, 0, output, ""),
        ):
            evidence = collect_linux_auth_evidence()

        self.assertEqual(evidence[1].content, "1")
        self.assertEqual(json.loads(evidence[2].content), {"MESSAGE": "ok"})


if __name__ == "__main__":
    unittest.main()
