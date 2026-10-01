# Repository instructions for AI agents

This repository is documentation-sensitive. Any AI agent working in this repo must keep the architecture documentation and diagrams synchronized with code changes.

Required behavior:
- Before finishing a task, review whether any implementation, configuration, deployment, security, or runtime behavior changed.
- If a change affects the system design, APIs, deployment flow, security model, or operational behavior, update the relevant files in [docs/](docs/) and [diagrams/](diagrams/).
- Treat the documentation as part of the code change. Do not leave it stale.
- Update existing docs or add new ones when the change introduces new behavior, removes behavior, or changes architecture assumptions.
- Keep Mermaid diagrams accurate to the implemented system.
- When a change is made, update the relevant documentation and diagram files in the same change set before completion.
- If a doc or diagram is not clearly applicable, explain the gap in the final summary rather than silently skipping it.

In scope:
- source code changes in [src/](src/)
- deployment and install changes in [deploy/](deploy/)
- configuration or environment changes
- security, identity, tunnel, or certificate lifecycle updates
- any change that alters runtime topology, ports, services, or data flow

Minimum expectation:
- Keep [docs/architecture.md](docs/architecture.md), [docs/executive-summary.md](docs/executive-summary.md), [docs/deployment.md](docs/deployment.md), [docs/security.md](docs/security.md), and the relevant Mermaid files in sync with real implementation.
- If a task changes one of those areas, update the corresponding docs and diagrams in the same patch.

Do not treat documentation as optional or a separate follow-up task.
