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

Argus is at version 0.1 foundation stage.

Current functionality is limited to a placeholder CLI command:

```bash
argus brief
```

No collectors, integrations, databases, background workers, API clients, or AI
features exist yet.

## Installation

Installation packaging is intentionally minimal at this stage.

For local development, install the project in editable mode:

```bash
python -m pip install -e .
```

## Example CLI Usage

```bash
argus brief
```

Expected output:

```text
ARGUS v0.1

Evidence-driven Security Operations Copilot

No collectors configured.
```

## Project Goals

- Provide a clear foundation for a Home SOC investigation assistant.
- Keep evidence and findings explainable.
- Avoid autonomous system changes.
- Keep early architecture simple enough to fit on a whiteboard.
- Grow through clean organization before introducing new abstractions.

## Planned Roadmap

- Define collector interfaces after real evidence sources are selected.
- Add local evidence collection from explicitly configured sources.
- Introduce correlation and report generation workflows.
- Add tests around models, collectors, and reporting behavior as features grow.
- Evaluate AI-assisted explanation only after evidence handling is mature.
