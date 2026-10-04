"""Report rendering tests using in-memory evidence."""

from __future__ import annotations

import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from argus.collectors import collect_docker_evidence
from argus.models import Evidence
from argus.report import BULLET, CHECK, render_brief


class RenderBriefTests(unittest.TestCase):
    def test_renders_container_listing_error_after_successful_daemon_check(self) -> None:
        responses = [
            CompletedProcess(["docker"], 0, "Docker version 27.0", ""),
            CompletedProcess(["docker"], 0, '"27.0"', ""),
            CompletedProcess(["docker"], 1, "", "permission denied"),
        ]
        with patch("argus.collectors.subprocess.run", side_effect=responses) as run:
            evidence = collect_docker_evidence()

        self.assertEqual(run.call_count, 3)
        records = {(record.source, record.content) for record in evidence}
        self.assertIn(("docker.installed", "true"), records)
        self.assertIn(("docker.daemon_running", "true"), records)
        self.assertIn(("docker.error", "permission denied"), records)
        self.assertIn("permission denied", render_brief(evidence, "0.2.0"))

    def test_renders_container_counts_lists_and_crowdsec_alert(self) -> None:
        evidence = [
            Evidence("docker.installed", "true"),
            Evidence("docker.daemon_running", "true"),
            Evidence("docker.containers.total", "3"),
            Evidence("docker.container.running", "api"),
            Evidence("docker.container.running", "web"),
            Evidence("docker.container.exited", "db"),
            Evidence("docker.container.unhealthy", "api"),
            Evidence("crowdsec.available", "true"),
            Evidence("crowdsec.container_running", "true"),
            Evidence("crowdsec.api_healthy", "true"),
            Evidence("crowdsec.container_health", "healthy"),
            Evidence("crowdsec.alerts.active_count", "1"),
            Evidence(
                "crowdsec.alert.raw",
                '{"id":42,"message":"SSH brute force","scenario":"ssh-bf"}',
            ),
            Evidence("crowdsec.alert.latest", "42: ssh-bf"),
            Evidence("crowdsec.alert.latest_reason", "SSH brute force"),
            Evidence("crowdsec.alert.latest_timestamp", "2026-08-29T10:05:00Z"),
        ]

        self.assertEqual(
            render_brief(evidence, "0.2.0"),
            "\n".join(
                [
                    "ARGUS v0.2",
                    "",
                    "Evidence-driven Security Operations Copilot",
                    "",
                    "Docker",
                    f"{CHECK} Docker installed",
                    f"{CHECK} Docker daemon running",
                    "",
                    "Containers",
                    "Total: 3",
                    "Running: 2",
                    "Exited: 1",
                    "Unhealthy: 1",
                    "",
                    "Running Containers",
                    f"{BULLET} api",
                    f"{BULLET} web",
                    "",
                    "Exited Containers",
                    f"{BULLET} db",
                    "",
                    "Unhealthy Containers",
                    f"{BULLET} api",
                    "",
                    "CrowdSec",
                    f"{CHECK} CrowdSec available",
                    f"{CHECK} CrowdSec container running",
                    f"{CHECK} CrowdSec API healthy",
                    "Container Health: healthy",
                    "",
                    "CrowdSec Alerts",
                    "Active: 1",
                    "",
                    "Latest Alert",
                    "42: ssh-bf",
                    "Reason: SSH brute force",
                    "Timestamp: 2026-08-29T10:05:00Z",
                ]
            ),
        )

    def test_renders_unavailable_sources_without_container_section(self) -> None:
        evidence = [
            Evidence("docker.installed", "false"),
            Evidence("docker.error", "Docker CLI not found.\nadditional details"),
            Evidence("docker.daemon_running", "false"),
            Evidence("crowdsec.available", "false"),
            Evidence("crowdsec.container_running", "false"),
            Evidence("crowdsec.api_healthy", "false"),
            Evidence("crowdsec.error", "Docker CLI not found."),
        ]

        self.assertEqual(
            render_brief(iter(evidence), "0.2.0"),
            "\n".join(
                [
                    "ARGUS v0.2",
                    "",
                    "Evidence-driven Security Operations Copilot",
                    "",
                    "Docker",
                    "x Docker not installed",
                    "x Docker daemon not running or unavailable",
                    "",
                    "Docker CLI not found.",
                    "",
                    "CrowdSec",
                    "x CrowdSec unavailable",
                    "x CrowdSec container not running",
                    "x CrowdSec API unavailable",
                    "",
                    "Docker CLI not found.",
                ]
            ),
        )

    def test_renders_no_containers_and_zero_alerts(self) -> None:
        evidence = [
            Evidence("docker.installed", "true"),
            Evidence("docker.daemon_running", "true"),
            Evidence("docker.containers.total", "0"),
            Evidence("crowdsec.available", "false"),
            Evidence("crowdsec.container_running", "false"),
            Evidence("crowdsec.api_healthy", "false"),
            Evidence("crowdsec.alerts.active_count", "0"),
        ]

        report = render_brief(evidence, "0.2.0")

        self.assertIn("Total: 0\nRunning: 0\nExited: 0\nUnhealthy: 0", report)
        self.assertIn("Running Containers\nNone", report)
        self.assertIn("CrowdSec Alerts\nActive: 0", report)
        self.assertNotIn("Latest Alert", report)


if __name__ == "__main__":
    unittest.main()
