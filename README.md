# Argus

Argus is an evidence-driven Security Operations (SOC) copilot for Home SOC
environments. It collects read-only evidence from security tools and presents
deterministic, traceable operational summaries for a human operator.

Argus does not make autonomous changes. Version 0.2.0 has no AI, persistence,
database, background monitoring, correlation, or automated response features.

## Philosophy

Argus starts with observable evidence from known sources. Interpretation and
reporting remain deterministic, and supporting evidence stays attached to each
security event.

The architecture is intentionally small and explicit so its behavior is easy to
understand, test, and audit.

## Version 0.2.0

The current read-only collectors are:

- Docker
- CrowdSec

Two CLI commands are available:

- `argus brief` reports current Docker and CrowdSec operational status.
- `argus daily` produces a deterministic rolling 24-hour CrowdSec security
  activity brief.

The Daily Security Brief pipeline is:

```text
CrowdSec
-> Evidence
-> SecurityEvent
-> EventWindow
-> DailySecurityBrief
-> renderer
```

`SOURCE` timestamps represent known event occurrence time. When CrowdSec does
not provide a usable event timestamp, Argus uses the Evidence collection time
with an `OBSERVED` timestamp basis. Observed-time fallback alerts are displayed
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
```

Representative `argus brief` header:

```text
ARGUS v0.2

Evidence-driven Security Operations Copilot
```

Both commands use local Docker access. `argus daily` reads CrowdSec telemetry
through the existing CrowdSec container and does not require a separate API
integration.

## Testing

Run the complete automated test suite with:

```bash
python -m unittest discover -s tests -v
```

The automated tests mock subprocess and collector boundaries and do not require
live Docker or CrowdSec services.

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
