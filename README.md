# Argus

Argus is an evidence-driven Security Operations (SOC) copilot for Home SOC
environments. It collects read-only evidence from security tools and presents
deterministic, traceable operational summaries for a human operator.

Argus does not make autonomous changes. Version 0.3 development adds explicit
local snapshot persistence, but has no AI, background monitoring, correlation,
or automated response features.

## Philosophy

Argus starts with observable evidence from known sources. Interpretation and
reporting remain deterministic, and supporting evidence stays attached to each
security event.

The architecture is intentionally small and explicit so its behavior is easy to
understand, test, and audit.

## Version 0.3 Development

The current read-only collectors are:

- Docker
- CrowdSec
- Linux SSH authentication via the local systemd journal

Five CLI commands are available:

- `argus brief` reports current Docker and CrowdSec operational status.
- `argus daily` produces a deterministic rolling 24-hour CrowdSec and Linux SSH
  authentication security brief.
- `argus collect` explicitly saves one Docker, CrowdSec, and Linux auth telemetry
  snapshot.
- `argus history` shows recent stored collection snapshots and observation
  counts.
- `argus investigate` reconstructs historical CrowdSec and Linux SSH security
  events from stored observations.

The Daily Security Brief pipeline is:

```text
CrowdSec + Linux SSH authentication
-> Evidence
-> SecurityEvent
-> EventWindow
-> DailySecurityBrief
-> renderer
```

`SOURCE` timestamps represent known event occurrence time. CrowdSec uses its
source timestamp; Linux SSH authentication uses journald's microsecond Unix
timestamp. When either is unusable, Argus uses the Evidence observation time
with an `OBSERVED` timestamp basis. Observed-time fallback events are displayed
separately so they are not presented as known occurrence-time events.

Docker contributes operational status to `argus brief`; Docker security events
are not implemented.

Version 0.3 development enriches CrowdSec `SecurityEvent` records with
structured alert context already supplied by CrowdSec, such as source,
network, event-count, machine, timing, and decision details. The Daily Security
Brief displays only the context present in each alert and retains the original
raw Evidence for traceability.

## Installation

Use a virtual environment for local installation:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\activate
```

Or activate it on Linux:

```bash
source .venv/bin/activate
```

Then install Argus in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

Debian-family distributions may block system-level pip installation in an
externally managed Python environment. A virtual environment is the preferred
installation path and avoids modifying the system Python installation.

## CLI Usage

```bash
argus brief
argus daily
argus collect
argus history
argus investigate
```

Representative `argus brief` header:

```text
ARGUS v0.2

Evidence-driven Security Operations Copilot
```

`argus brief` shows current Docker and CrowdSec operational status. `argus daily`
shows the current rolling CrowdSec and Linux SSH security view. Neither command
writes to storage. `argus collect` explicitly saves one telemetry snapshot
without interpreting Evidence as security events. The Linux auth collector runs
local `journalctl` for sshd records from the previous 24 hours; journal access
depends on the host's permissions. CrowdSec supplies intrusion/detection
telemetry, Linux auth supplies direct SSH authentication telemetry, and Docker
supplies operational telemetry. Argus does not correlate the two security event
sources.
`argus history` reads up to 10 recent snapshots by default; use `--limit` to
choose another positive number. Its counts describe stored observations grouped
by collection run. They are not unique attacks, incidents, or deduplicated
security events.

`argus investigate` reads saved collection runs without collecting live data or
changing the database. It interprets CrowdSec and Linux auth Evidence, retains
the earliest stored observation of each authoritative identity, and keeps every
event without an identity. By default it selects the last 24 hours and displays
up to 100 events, newest first. Use `--hours` for a positive integer lookback or
`--all` for the entire stored history; these options cannot be combined. For
example:

```bash
argus investigate --limit 50 --source linux-auth
argus investigate --hours 48
argus investigate --hours 168
argus investigate --all
```

`--source` accepts `all` (default), `crowdsec`, or `linux-auth`. Source filtering
and deduplication happen before the inclusive event-time window; sorting and
`--limit` happen afterward. The report shows the UTC window, total matching
events before the limit, and number displayed. Every event shows its stored
collection ID. A `SOURCE` timestamp is occurrence time. An `OBSERVED` timestamp
is the time Argus saw the Evidence; the actual occurrence time is unknown.
Collection time does not determine window membership. The retained collection
is the earliest saved observation of an identity, which may not be the event's
first occurrence.

By default, snapshots are stored in:

```text
~/.argus/argus.db
```

Set `ARGUS_DB_PATH` to use another SQLite database file:

```bash
ARGUS_DB_PATH=/path/to/argus.db argus collect
```

On PowerShell:

```powershell
$env:ARGUS_DB_PATH = "C:\path\to\argus.db"
argus collect
```

`argus daily` reads CrowdSec telemetry through the existing CrowdSec container
and does not require a separate API integration.

## Testing

Run the complete automated test suite with:

```bash
python -m unittest discover -s tests -v
```

The automated tests mock subprocess and collector boundaries and do not require
live Docker, CrowdSec, or journal access.

## Project Goals

- Keep every interpreted event traceable to collected evidence.
- Prefer deterministic code over optional higher-level interpretation.
- Preserve read-only operation and human control.
- Keep the architecture simple enough to inspect and test thoroughly.

## Future Roadmap

- Refine deterministic collection and reporting based on Home SOC usage.
- Expand read-only evidence coverage when concrete operational needs justify it.
- Evaluate broader analysis capabilities only after their evidence and policy
  requirements are clear.
