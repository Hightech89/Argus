# Argus

Argus is an evidence-driven Security Operations (SOC) copilot for Home SOC
environments.

Argus collects and organizes evidence, correlates information, explains
findings, and recommends next steps. It is designed to support investigation
and operator judgment, not to make changes on its own.

## Philosophy

Argus is built around evidence first. Every finding should be traceable to
observable information from a known source.

The project favors simple, explicit architecture over early abstraction. The
foundation should be easy to understand, easy to test, and easy to extend when
real collectors and reporting workflows are introduced later.

## Current Status

Argus includes the version 0.1 operational brief and the deterministic version
0.2 CrowdSec Daily Security Brief pipeline:

```bash
argus brief
argus daily
```

`argus brief` reports current Docker and CrowdSec operational status.
`argus daily` reports CrowdSec security activity from a rolling 24-hour window.

No additional collectors, integrations, databases, background workers, external
API clients, or AI features exist yet.

## Installation

Installation packaging is intentionally minimal at this stage.

For local development, install the project in editable mode:

```bash
python -m pip install -e .
```

## Example CLI Usage

```bash
argus brief
argus daily
```

Representative `argus brief` output:

```text
ARGUS v0.1

Evidence-driven Security Operations Copilot

Docker
✓ Docker installed
✓ Docker daemon running

Containers
Total: 6
Running: 5
Exited: 1
Unhealthy: 0

CrowdSec
✓ CrowdSec available
✓ CrowdSec container running
✓ CrowdSec API healthy

CrowdSec Alerts
Active: 0
```

## Project Goals

- Provide a clear foundation for a Home SOC investigation assistant.
- Keep evidence and findings explainable.
- Avoid autonomous system changes.
- Keep early architecture simple enough to fit on a whiteboard.
- Grow through clean organization before introducing new abstractions.

## Planned Roadmap

- Refine collector interfaces as more evidence sources are selected.
- Add local evidence collection from explicitly selected sources.
- Introduce correlation and report generation workflows.
- Add tests around models, collectors, and reporting behavior as features grow.
- Evaluate AI-assisted explanation only after evidence handling is mature.
