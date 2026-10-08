"""Deterministic interpretation of raw sshd journal Evidence."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from argus.analysis import deduplicate_events
from argus.events import linux_auth_events_from_evidence
from argus.models import Evidence, Severity, TimestampBasis

_NOW = datetime(2026, 10, 7, 18, 30, tzinfo=timezone.utc)
_MICROSECONDS = int(_NOW.timestamp()) * 1_000_000 + 123456


def _raw(message: object, **fields: object) -> Evidence:
    return Evidence(
        "linux.auth.raw",
        json.dumps({"MESSAGE": message, **fields}, sort_keys=True),
        _NOW,
    )


class LinuxAuthEventTests(unittest.TestCase):
    def test_supported_ssh_messages_have_stable_event_details(self) -> None:
        cases = (
            ("Accepted password for alice from 192.0.2.1 port 22 ssh2",
             "SSH login accepted", "ssh_login_success", Severity.INFO, "alice", "192.0.2.1", "password"),
            ("Accepted publickey for bob from 2001:db8::2 port 4422 ssh2",
             "SSH login accepted", "ssh_login_success", Severity.INFO, "bob", "2001:db8::2", "publickey"),
            ("Failed password for carol from 192.0.2.3 port 6022 ssh2",
             "SSH login failed", "ssh_login_failure", Severity.LOW, "carol", "192.0.2.3", "password"),
            ("Failed publickey for dave from 192.0.2.4 port 22 ssh2",
             "SSH login failed", "ssh_login_failure", Severity.LOW, "dave", "192.0.2.4", "publickey"),
            ("Invalid user eve from 192.0.2.5 port 22",
             "SSH invalid user", "ssh_invalid_user", Severity.LOW, "eve", "192.0.2.5", None),
            ("Failed password for invalid user frank from 192.0.2.6 port 22 ssh2",
             "SSH login failed", "ssh_login_failure", Severity.LOW, "frank", "192.0.2.6", "password"),
        )
        for message, summary, event_type, severity, username, remote_ip, method in cases:
            with self.subTest(message=message):
                raw = _raw(message)
                events = linux_auth_events_from_evidence([raw])
                self.assertEqual(len(events), 1)
                event = events[0]
                self.assertEqual(event.source, "linux-auth")
                self.assertEqual(event.category, "authentication")
                self.assertIs(event.severity, severity)
                self.assertEqual(event.summary, summary)
                expected = (
                    ("event_type", event_type),
                    ("username", username),
                    ("remote_ip", remote_ip),
                )
                if method is not None:
                    expected += (("auth_method", method),)
                self.assertEqual(event.details, expected)
                self.assertEqual(event.evidence, (raw,))
                self.assertIs(event.evidence[0], raw)

    def test_unrelated_and_malformed_journal_records_are_ignored(self) -> None:
        records = [
            _raw("Connection closed by 192.0.2.1 port 22"),
            _raw("pam_unix(sshd:session): session opened for user alice"),
            _raw(["Accepted password for alice from 192.0.2.1"]),
            Evidence("linux.auth.raw", "not json", _NOW),
            Evidence("linux.auth.raw", "[]", _NOW),
            Evidence("crowdsec.alert.raw", _raw("Accepted password for alice from 192.0.2.1").content, _NOW),
        ]

        self.assertEqual(linux_auth_events_from_evidence(records), [])

    def test_source_timestamp_uses_microseconds_and_utc(self) -> None:
        raw = _raw(
            "Accepted password for alice from 192.0.2.1 port 22",
            __REALTIME_TIMESTAMP=str(_MICROSECONDS),
        )

        event = linux_auth_events_from_evidence([raw])[0]

        self.assertEqual(event.timestamp, _NOW + timedelta(microseconds=123456))
        self.assertIs(event.timestamp.tzinfo, timezone.utc)
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)

    def test_integer_source_timestamp_is_accepted(self) -> None:
        raw = _raw(
            "Accepted publickey for alice from 192.0.2.1 port 22",
            __REALTIME_TIMESTAMP=_MICROSECONDS,
        )

        event = linux_auth_events_from_evidence([raw])[0]

        self.assertEqual(event.timestamp, _NOW + timedelta(microseconds=123456))
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)

    def test_unusable_source_timestamp_falls_back_to_observation(self) -> None:
        for value in (None, "", "not a number", True, 1.5, -10**30):
            with self.subTest(value=value):
                raw = _raw(
                    "Failed publickey for alice from 192.0.2.1 port 22",
                    __REALTIME_TIMESTAMP=value,
                )
                event = linux_auth_events_from_evidence([raw])[0]
                self.assertIs(event.timestamp, _NOW)
                self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_no_usable_timestamp_skips_event(self) -> None:
        raw = Evidence(
            "linux.auth.raw",
            _raw("Invalid user alice from 192.0.2.1").content,
            None,
        )

        self.assertEqual(linux_auth_events_from_evidence([raw]), [])

    def test_trimmed_cursor_is_authoritative_identity(self) -> None:
        raw = _raw("Invalid user alice from 192.0.2.1", __CURSOR="  s=42;i=7  ")

        event = linux_auth_events_from_evidence([raw])[0]

        self.assertEqual(event.identity, "linux-auth:journal:s=42;i=7")
        self.assertIs(event.evidence[0], raw)

    def test_same_cursor_forms_a_deduplicated_derived_view(self) -> None:
        records = [
            _raw("Invalid user alice from 192.0.2.1", __CURSOR="cursor-a"),
            _raw("Invalid user alice from 192.0.2.1", __CURSOR="cursor-a"),
            _raw("Invalid user alice from 192.0.2.1", __CURSOR="cursor-b"),
        ]

        events = linux_auth_events_from_evidence(records)
        view = deduplicate_events(events)

        self.assertEqual(view, (events[0], events[2]))
        self.assertEqual(len(records), 3)

    def test_missing_or_unusable_cursor_does_not_invent_identity(self) -> None:
        for cursor in (None, "", "  ", 42, [], {}):
            with self.subTest(cursor=cursor):
                raw = _raw("Invalid user alice from 192.0.2.1", __CURSOR=cursor)
                self.assertIsNone(linux_auth_events_from_evidence([raw])[0].identity)

    def test_event_order_matches_raw_input_order(self) -> None:
        records = [
            _raw("Invalid user alice from 192.0.2.1"),
            _raw("Accepted publickey for bob from 192.0.2.2 port 22"),
            _raw("Failed password for carol from 192.0.2.3 port 22"),
        ]

        events = linux_auth_events_from_evidence(iter(records))

        self.assertEqual(
            [event.summary for event in events],
            ["SSH invalid user", "SSH login accepted", "SSH login failed"],
        )
        self.assertTrue(all(event.evidence[0] is raw for event, raw in zip(events, records)))


if __name__ == "__main__":
    unittest.main()
