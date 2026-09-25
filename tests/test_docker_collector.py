"""Docker collector behavior tests."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from argus.collectors import collect_docker_evidence
from argus.models import Evidence


_VERSION = ("docker", "--version")
_INFO = ("docker", "info", "--format", "{{json .ServerVersion}}")
_PS = (
    "docker",
    "ps",
    "-a",
    "--format",
    "{{.Names}}\t{{.State}}\t{{.Status}}",
)


class DockerCollectorTests(unittest.TestCase):
    def test_docker_cli_missing(self) -> None:
        with patch("argus.collectors.subprocess.run", side_effect=FileNotFoundError) as run:
            evidence = collect_docker_evidence()

        self.assertEqual(
            evidence,
            [
                Evidence("docker.installed", "false"),
                Evidence("docker.error", "Docker CLI not found."),
                Evidence("docker.daemon_running", "false"),
            ],
        )
        self.assertEqual(run.call_count, 1)

    def test_docker_daemon_unavailable(self) -> None:
        evidence, calls = _collect(
            {
                _VERSION: _completed("Docker version 27.0"),
                _INFO: _completed(stderr="Cannot connect to the Docker daemon", returncode=1),
            }
        )

        self.assertEqual(
            evidence,
            [
                Evidence("docker.installed", "true"),
                Evidence("docker.daemon_running", "false"),
                Evidence("docker.error", "Cannot connect to the Docker daemon"),
            ],
        )
        self.assertEqual(calls, [_VERSION, _INFO])

    def test_no_containers(self) -> None:
        evidence, calls = _collect({_PS: _completed()})

        self.assertEqual(evidence, _base_evidence() + [Evidence("docker.containers.total", "0")])
        self.assertEqual(calls, [_VERSION, _INFO, _PS])

    def test_running_containers(self) -> None:
        evidence, _ = _collect(
            {_PS: _completed("web\trunning\tUp 2 hours (healthy)\nworker\trunning\tUp 1 hour")}
        )

        self.assertEqual(
            evidence,
            _base_evidence()
            + [
                Evidence("docker.containers.total", "2"),
                Evidence("docker.container.running", "web"),
                Evidence("docker.container.running", "worker"),
            ],
        )

    def test_exited_containers(self) -> None:
        evidence, _ = _collect({_PS: _completed("db\texited\tExited (0) 5 minutes ago")})

        self.assertEqual(
            evidence,
            _base_evidence()
            + [Evidence("docker.containers.total", "1"), Evidence("docker.container.exited", "db")],
        )

    def test_unhealthy_container_is_also_running(self) -> None:
        evidence, _ = _collect({_PS: _completed("api\trunning\tUp 5 minutes (unhealthy)")})

        self.assertEqual(
            evidence,
            _base_evidence()
            + [
                Evidence("docker.containers.total", "1"),
                Evidence("docker.container.running", "api"),
                Evidence("docker.container.unhealthy", "api"),
            ],
        )

    def test_multiple_containers_are_sorted_by_name(self) -> None:
        output = "\n".join(
            [
                "z-worker\trunning\tUp 1 hour",
                "m-db\texited\tExited (0) 2 hours ago",
                "a-api\trunning\tUp 5 minutes (unhealthy)",
                "b-cache\trunning\tUp 10 minutes",
            ]
        )
        evidence, _ = _collect({_PS: _completed(output)})

        self.assertEqual(
            evidence,
            _base_evidence()
            + [
                Evidence("docker.containers.total", "4"),
                Evidence("docker.container.running", "a-api"),
                Evidence("docker.container.unhealthy", "a-api"),
                Evidence("docker.container.running", "b-cache"),
                Evidence("docker.container.exited", "m-db"),
                Evidence("docker.container.running", "z-worker"),
            ],
        )

    def test_container_listing_failure_has_no_container_count(self) -> None:
        evidence, calls = _collect({_PS: _completed(stderr="permission denied", returncode=1)})

        self.assertEqual(
            evidence,
            _base_evidence() + [Evidence("docker.error", "permission denied")],
        )
        self.assertEqual(calls, [_VERSION, _INFO, _PS])


def _base_evidence() -> list[Evidence]:
    return [Evidence("docker.installed", "true"), Evidence("docker.daemon_running", "true")]


def _completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _collect(
    responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]],
) -> tuple[list[Evidence], list[tuple[str, ...]]]:
    defaults = {_VERSION: _completed("Docker version 27.0"), _INFO: _completed('"27.0"')}
    defaults.update(responses)
    calls: list[tuple[str, ...]] = []

    def run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        command = tuple(args)
        calls.append(command)
        if command not in defaults:
            raise AssertionError(f"unexpected command: {command}")
        return defaults[command]

    with patch("argus.collectors.subprocess.run", side_effect=run):
        return collect_docker_evidence(), calls


if __name__ == "__main__":
    unittest.main()
