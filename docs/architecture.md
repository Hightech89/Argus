# Argus Architecture

## What Argus Is

Argus is an evidence-driven Security Operations (SOC) copilot for Home SOC
environments. It is intended to collect evidence, correlate information, explain
findings, and recommend next steps.

## What Argus Is Not

Argus is not a chatbot, not an autonomous agent, and not a system-change tool.
It does not make changes to hosts, containers, firewalls, services, or security
controls.

## Core Philosophy

Argus starts with evidence. Findings should be explainable, traceable, and tied
to observable inputs. The operator remains responsible for decisions and
actions.

## High-Level Architecture

The initial architecture is intentionally small:

- `argus.cli` exposes the command-line interface.
- `argus.models` contains shared data structures.
- `argus.collectors` collects read-only evidence from supported sources.
- `argus.report` renders collected evidence into operator-facing summaries.

Version 0.1 includes Docker and CrowdSec evidence collection. There are no
background processes, databases, external API integrations, or AI features.

Version 0.2 introduces `SecurityEvent` in `argus.models` as an immutable
interpretation of one or more `Evidence` records. It has a timezone-aware
timestamp, source, flexible category, summary, and a severity from `info`,
`low`, `medium`, `high`, or `critical`. Supporting evidence is retained as a
nonempty tuple. Collectors and the `brief` command still use the v0.1 pipeline.

## Design Principles

- Keep the foundation simple enough to fit on a whiteboard.
- Prefer explicit modules over framework-heavy architecture.
- Add abstractions only when real behavior requires them.
- Preserve traceability from findings back to evidence.
- Recommend actions without performing them.

## Version 0.1 Scope

Version 0.1 establishes the project structure, package metadata, CLI, simple
evidence model, Docker collector, CrowdSec collector, and architecture
documentation.

The only CLI command is:

```bash
argus brief
```

It collects read-only Docker and CrowdSec evidence and renders a short
operational summary.

## Future Roadmap

- Refine collector design as more evidence sources are selected.
- Add additional local, read-only evidence collectors.
- Add correlation and report generation.
- Expand tests around evidence handling and reporting.
- Consider AI-assisted explanation after evidence workflows are reliable.
