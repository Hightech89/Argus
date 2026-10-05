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

Version 0.2.0 includes Docker and CrowdSec evidence collection. There are no
background processes, databases, external API integrations, correlation, or AI
features.

`SecurityEvent` in `argus.models` is an immutable
interpretation of one or more `Evidence` records. It has a timezone-aware
timestamp, source, flexible category, summary, and a severity from `info`,
`low`, `medium`, `high`, or `critical`. Supporting evidence is retained as a
nonempty tuple. Its optional `details` field is an immutable tuple of string
key-value tuples. This generic representation can carry source-specific context
without adding CrowdSec fields to the shared event model.

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

The Daily Security Brief renderer reads only `SecurityEvent.details` when it
shows indented context beneath an event. It does not parse supporting Evidence,
alter summaries, or change aggregation counts.

Rolling windows use inclusive cutoff and current-time boundaries. Events with
source timestamps are selected as known occurrences; events using observation
time are selected separately because their actual occurrence time is unknown.
The deterministic data flow is `Evidence` -> `SecurityEvent` -> `EventWindow`
-> `DailySecurityBrief` -> `argus.report` renderer.

`argus brief` presents current Docker and CrowdSec operational status. `argus
daily` orchestrates the CrowdSec pipeline above for a rolling 24-hour security
activity brief.

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
