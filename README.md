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

Seven CLI commands are available:

- `argus brief` reports current Docker and CrowdSec operational status.
- `argus daily` produces a deterministic rolling 24-hour CrowdSec and Linux SSH
  authentication security brief.
- `argus collect` explicitly saves one Docker, CrowdSec, and Linux auth telemetry
  snapshot.
- `argus history` shows recent stored collection snapshots and observation
  counts.
- `argus investigate` reconstructs historical CrowdSec and Linux SSH security
  events from stored observations.
- `argus storage` reports database size, evidence counts, and available disk space.
- `argus summary` gives a deterministic historical security activity report.

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
argus storage
argus summary
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

## Historical security summary

`argus summary` reconstructs CrowdSec and Linux SSH events from stored Evidence
without running collectors or modifying the database. It uses the same
identity deduplication and inclusive UTC event-time selection as
`argus investigate`, but calculates over **all** matching events rather than
the first 100 displayed there. The default is the previous 24 hours:

```bash
argus summary
argus summary --hours 48
argus summary --hours 168
argus summary --all
```

`--hours` requires a positive integer and cannot be combined with `--all`.
The report shows deduplicated event totals, successful/failed/invalid-user SSH
counts, CrowdSec alert counts, severity counts, and up to five source IPs.
Structured SSH `remote_ip` and CrowdSec IP source details supply those IPs;
CrowdSec detections are counted separately from SSH authentication events.
Other or unclassified event types remain visible in their own count.

Noteworthy observations include at least **three** failed SSH authentication
events from one IP, a SOURCE-timestamped failure followed by a SOURCE-timestamped
success from the same IP within **15 minutes**, and up to five recent CrowdSec
detections with available scenario, source, and severity. These are deterministic
observations, not incident or compromise claims. Each finding cites stored
collection IDs and existing authoritative identities when available. SOURCE
timestamps are occurrence times; OBSERVED timestamps only establish when Argus
saw a record. Collection timestamps describe stored observation coverage and
do not prove continuous monitoring or complete source activity. A zero-event
report does not mean the system is secure.

## Storage efficiency and monitoring

Every `argus collect` still creates an auditable collection run. The SSH journal
collector reads the previous 24 hours on each invocation, so the same journal
record can recur across many 15-minute runs. For `linux.auth.raw` only, storage
uses a nonblank string `__CURSOR` as authoritative identity and stores its raw
Evidence on the first encounter. A later row with the same cursor is not stored
again. The first row keeps its complete raw content and observation timestamp;
source timestamps still represent occurrence, and observation timestamps do
not become occurrence times. A run with no new raw journal rows still exists.
Cursorless, malformed, and unusable-cursor rows are stored every time. Docker
and CrowdSec Evidence retain their existing per-snapshot behavior. The
`argus collect` output distinguishes `Evidence collected` from `Evidence stored`
and reports both collected and stored Linux auth record counts. `argus history`
continues to count stored Evidence per run, so a repeated journal row is absent
from that run's Evidence count.

Run `argus storage` to inspect the configured database without running
collectors or writing Evidence. It shows the main SQLite file size, current
`-wal`, `-shm`, and `-journal` sidecar sizes when present, their combined size,
available space on the database filesystem, run and Evidence totals, and counts
by exact Evidence source. It warns below **1 GiB** of available space. These
SQLite file sizes are a snapshot, not total Argus disk usage; lock files,
backups, and filesystem overhead are excluded. Historical duplicate rows remain
in existing databases and are never deleted automatically. A repeated cursor
is attributed to its earliest stored row; Argus does not retain a separate
per-cursor observation for every subsequent run.

The first `argus collect` after upgrading an existing database creates and
backfills a small cursor index in one SQLite transaction. It leaves existing
Evidence and CollectionRun rows unchanged, including old duplicates. Before a
Home SOC upgrade, use a maintenance window: stop the timer, wait for any active
service run to finish, and make a SQLite backup as `joshpi` before installing
the new code. For example:

```bash
sudo systemctl stop argus-collect.timer
while sudo systemctl is-active --quiet argus-collect.service; do sleep 1; done
sudo systemctl status argus-collect.service --no-pager
/home/joshpi/argus/.venv/bin/python - <<'PY'
import sqlite3
from contextlib import closing
from pathlib import Path
database = Path('/home/joshpi/.argus/argus.db')
backup_path = database.with_name('argus.db.pre-cursor-upgrade')
if backup_path.exists():
    raise SystemExit(f'Backup already exists: {backup_path}')
with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(backup_path)) as backup:
    source.backup(backup)
PY
```

After upgrading the code, run one manual `argus collect`, then check
`argus storage`, `argus history`, and `argus investigate --all`. Start the timer
again only after those checks pass: `sudo systemctl start argus-collect.timer`.
The commands above are guidance; this repository change does not touch the
running Pi timer or database.

## Scheduled collection on the Raspberry Pi

The repository includes a systemd oneshot service and timer under
`deploy/systemd/`. The service runs the existing virtual-environment CLI as
`joshpi` from `/home/joshpi/argus`, using that user's default database at
`/home/joshpi/.argus/argus.db`. The timer requests a collection at each quarter
hour. It does not run a persistent Python process. After downtime,
`Persistent=true` schedules one catch-up activation rather than replaying every
missed quarter hour. systemd will not overlap activations of the same service.
Manual and timer-triggered `argus collect` processes use a non-blocking advisory
lock at `/home/joshpi/.argus/argus.db.lock`; an overlapping invocation fails
with a nonzero exit and a message in the service journal. The lock file may
remain after exit, but the OS releases its lock when the process exits.

On the Pi, from `/home/joshpi/argus`, install and **manually validate** the units
before enabling unattended collection:

```bash
sudo install -m 0644 deploy/systemd/argus-collect.service /etc/systemd/system/argus-collect.service
sudo install -m 0644 deploy/systemd/argus-collect.timer /etc/systemd/system/argus-collect.timer
sudo systemd-analyze verify /etc/systemd/system/argus-collect.service /etc/systemd/system/argus-collect.timer
systemd-analyze calendar '*:0/15'
sudo systemctl daemon-reload
sudo systemctl start argus-collect.service
sudo systemctl status argus-collect.service --no-pager
sudo journalctl -u argus-collect.service -n 50 --no-pager
sudo systemctl status argus-collect.timer --no-pager
```

The manual service run should show `ARGUS COLLECTION COMPLETE` in the journal,
and `argus history` should show the new snapshot. A failed service reports its
error in the journal and exits nonzero. `systemd-analyze verify` and `calendar`
check syntax and schedule on the Pi; they do not enable the timer.

After manual validation, **enable unattended collection** with:

```bash
sudo systemctl enable --now argus-collect.timer
systemctl list-timers argus-collect.timer --all
sudo systemctl status argus-collect.timer --no-pager
```

To stop and disable the timer:

```bash
sudo systemctl disable --now argus-collect.timer
```

The service runs without root privileges; `joshpi` still needs access to Docker,
CrowdSec, the system journal, and the database directory. Collector-returned
error Evidence remains part of a stored snapshot under the existing policy.
The lock coordinates invocations using the same database path; it does not
prevent independent collection into another database path.

## Testing

Run the complete automated test suite with:

```bash
python -m unittest discover -s tests -v
python -m pytest -q
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
