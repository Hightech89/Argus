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
- `argus.collectors` reserves the future boundary for evidence collection.
- `argus.report` reserves the future boundary for reporting behavior.

There are no collectors, integrations, background processes, databases, or AI
features in version 0.1.

## Design Principles

- Keep the foundation simple enough to fit on a whiteboard.
- Prefer explicit modules over framework-heavy architecture.
- Add abstractions only when real behavior requires them.
- Preserve traceability from findings back to evidence.
- Recommend actions without performing them.

## Version 0.1 Scope

Version 0.1 establishes the project structure, package metadata, placeholder CLI,
simple evidence model, and architecture documentation.

The only CLI command is:

```bash
argus brief
```

It reports that no collectors are configured.

## Future Roadmap

- Add collector design once initial evidence sources are selected.
- Implement local, read-only evidence collection.
- Add correlation and report generation.
- Expand tests around evidence handling and reporting.
- Consider AI-assisted explanation after evidence workflows are reliable.
