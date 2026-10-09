# Argus Architecture

## What Argus Is

Argus is an evidence-driven Security Operations (SOC) copilot for Home SOC
environments. It collects read-only evidence and presents deterministic,
traceable operational and security summaries to a human operator.

## What Argus Is Not

Argus is not a chatbot, not an autonomous agent, and not a system-change tool.
It does not make changes to hosts, containers, firewalls, services, or security
controls.

## Core Philosophy

Argus starts with evidence. Findings should be explainable, traceable, and tied
to observable inputs. The operator remains responsible for decisions and
actions.

## High-Level Architecture

The architecture is intentionally small:

- `argus.cli` exposes the command-line interface.
- `argus.models` contains shared data structures.
- `argus.collectors` collects read-only evidence from supported sources.
- `argus.events` deterministically interprets evidence as security events.
- `argus.analysis` applies deterministic event selection and analysis policies.
- `argus.report` renders collected evidence into operator-facing summaries.

Version 0.3 development includes Docker, CrowdSec, and Linux SSH authentication
evidence collection. There are no background processes, correlation, or AI
features.

`SecurityEvent` in `argus.models` is an immutable
interpretation of one or more `Evidence` records. It has a timezone-aware
timestamp, source, flexible category, summary, and a severity from `info`,
`low`, `medium`, `high`, or `critical`. Supporting evidence is retained as a
nonempty tuple. Its optional `details` field is an immutable tuple of string
key-value tuples. This generic representation can carry source-specific context
without adding CrowdSec fields to the shared event model.

`SecurityEvent.identity` is an optional, source-agnostic string representing
authoritative source identity. For raw CrowdSec alerts, only the alert `id`
defines `crowdsec:alert:<id>`: nonblank strings are trimmed and preserved;
finite numeric IDs use a deterministic decimal representation (integral floats
match integer IDs). Booleans and structured or non-finite values are unusable.
Missing or unusable IDs yield `identity=None`, meaning Argus cannot safely
assert sameness. No fallback hash or heuristic identity is generated.

`argus.analysis.deduplicate_events()` produces a derived event view: it keeps
the first occurrence of each identity in caller-supplied input order and every
event with `identity=None`, returning an immutable tuple of the original events.
It does not mutate or merge events or their evidence. Evidence observations are
always preserved in SQLite, including duplicates. Live `argus daily` does not
apply this deduplication view.

`Evidence.observed_at` is the timezone-aware UTC time Argus began a collector
invocation. Every record from that invocation shares the same observation time;
the field remains optional for evidence created outside the live collectors.
`SecurityEvent.timestamp` uses source-native event time when available and a
timezone-aware Evidence observation time as its fallback. Its required
`timestamp_basis` records whether the value came from the underlying source
(`source`) or from Evidence observation time (`observed`).

CrowdSec collection preserves every parsed alert atomically as a compact,
deterministic JSON `crowdsec.alert.raw` Evidence record before interpretation.
The event interpretation layer can convert those records into ordered,
independently traceable `SecurityEvent` objects without mixing alert fields.
For CrowdSec events, it extracts usable scalar values already present in the
alert or its nested `source` object. The fixed detail order is `alert_id`,
`scenario`, `source_scope`, `source_value`, `country`, `as_number`, `as_name`,
`event_count`, `machine`, `start_at`, `stop_at`, `decision_type`,
`decision_scope`, `decision_value`, and `decision_duration`. If a decisions
array is present, the first decision object supplies decision details. Missing,
blank, structured, or otherwise unusable optional values are omitted. The raw
Evidence record remains unchanged and attached to the event.

Linux auth collection runs local `journalctl` for `SYSLOG_IDENTIFIER=sshd` over
the previous 24 hours. Every valid journal JSON object is preserved as one
`linux.auth.raw` Evidence observation. Supported OpenSSH messages produce
successful login, failed login, or invalid user `SecurityEvent` records with
fixed `event_type`, `username`, `remote_ip`, and applicable `auth_method` details.
Journald `__REALTIME_TIMESTAMP` provides UTC source time when usable; otherwise
Evidence observation time is the fallback. A nonblank journald `__CURSOR`
provides `linux-auth:journal:<cursor>` identity. No cursor means no identity.
CrowdSec is intrusion/detection telemetry, Linux auth is direct SSH
authentication telemetry, and Docker remains operational telemetry. Argus does
not correlate CrowdSec and Linux auth events.

The Daily Security Brief renderer reads only `SecurityEvent.details` when it
shows indented context beneath an event. It does not parse supporting Evidence,
alter summaries, or change aggregation counts.

Version 0.3 introduces optional local Evidence persistence through
`argus.storage.EvidenceStore`:

```text
Docker ─────┐
CrowdSec ───┼──> Evidence ──> CollectionRun/EvidenceStore
Linux auth ─┘
```

The store uses a caller-supplied SQLite file and deterministic insertion IDs.
`argus collect` explicitly stores one Docker, CrowdSec, and Linux auth snapshot.
For unattended operation, `deploy/systemd/argus-collect.service` invokes the
same CLI as `joshpi` in a oneshot service. The corresponding calendar timer
requests activation every 15 minutes and schedules one catch-up run after
downtime. systemd does not overlap activations of that service; no Python daemon
or custom scheduler is involved. A non-blocking OS advisory lock beside the
database covers initialization, all collectors, and the atomic snapshot write.
Thus a concurrent manual invocation using the same database path fails before
collecting or creating another run. Process exit releases the lock, including
after failure. SQLite transaction failures still return nonzero, and systemd
records CLI stdout/stderr and exit status. Deployment is explicit; repository
files do not install or enable the timer.
`argus brief` and `argus daily` remain read-only, `SecurityEvent` records are not
persisted, and duplicate Evidence rows are intentionally preserved.
`default_database_path()` resolves a nonblank
`ARGUS_DB_PATH` override or defaults to `~/.argus/argus.db`.

Collection runs are snapshot boundaries, not incidents, unique alerts, or
deduplicated events. `add_collection()` stores one run with its timezone-aware
collection time and all Evidence observations in a single transaction;
`list_collection_evidence()` retrieves them in insertion order. Duplicate
Evidence across runs remains valid; storage never deduplicates observations.
Standalone `add()` and `add_many()` records have no collection association.
Initialization upgrades existing databases in place, preserving their Evidence.
The stored records are observations, not unique incidents. `argus brief` and
`argus daily` do not persist their observations.
`argus history` reads recent `CollectionRun` records and reports their stored
Evidence counts by source family. It does not interpret observations as
incidents, deduplicate them, calculate trends, or persist `SecurityEvent`
records.

`argus investigate` reads stored collections in ID order, interprets CrowdSec
and Linux auth Evidence, applies an optional source filter, and passes the
resulting events to `deduplicate_events()`. It attributes a retained event to
the earliest stored collection containing that identity, which may not be its
first real occurrence. Events without identity remain separate. A pure selector
then keeps events whose own timestamps fall within the inclusive UTC window:
24 hours by default, a positive `--hours` lookback, or all history with `--all`.
Collection time is attribution metadata, never the event-time filter. `SOURCE`
timestamps represent occurrence; `OBSERVED` timestamps represent observation
only, with actual occurrence unknown. Retained events sort newest first with
input order preserved for ties, then the display limit (100 by default) applies.
The report shows window bounds, matching count before the limit, and displayed
count. The command reads stored Evidence only; no event rows or schema changes
are involved.

Rolling windows use inclusive cutoff and current-time boundaries. Events with
source timestamps are selected as known occurrences; events using observation
time are selected separately because their actual occurrence time is unknown.
The deterministic data flow is `Evidence` -> `SecurityEvent` -> `EventWindow`
-> `DailySecurityBrief` -> `argus.report` renderer.

`argus brief` presents current Docker and CrowdSec operational status. `argus
daily` combines CrowdSec events first and Linux auth events second for a rolling
24-hour security activity brief.

## Design Principles

- Keep the foundation simple enough to fit on a whiteboard.
- Prefer explicit modules over framework-heavy architecture.
- Add abstractions only when real behavior requires them.
- Preserve traceability from findings back to evidence.
- Present evidence without performing system changes.

## Version 0.2.0 Scope

`argus brief` collects read-only Docker and CrowdSec evidence and renders a
current operational summary. `argus daily` collects CrowdSec evidence and runs
the deterministic rolling 24-hour Daily Security Brief pipeline. Docker
security-event interpretation is not part of this release.

## Future Roadmap

- Refine deterministic collection and reporting from operational experience.
- Add read-only evidence coverage when concrete use cases justify it.
- Evaluate broader analysis capabilities only after their evidence and policy
  requirements are defined.
