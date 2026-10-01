# Executive Summary

This repository implements a self-hosted management plane for multiple Prowler App deployments. The actual system is not a single monolithic application; it is a Node.js coordinator that provisions, configures, monitors, and updates several isolated Docker Compose stacks, each tied to one Microsoft 365 tenant. The project’s actual behavior is defined by the service entrypoint in [src/server.js](../src/server.js), the stack orchestration in [src/prowler.js](../src/prowler.js), the certificate and Entra ID integration in [src/certs.js](../src/certs.js), and the Linux install/service logic in [deploy/install.sh](../deploy/install.sh) and [deploy/prowler-manage.service](../deploy/prowler-manage.service).

The manager exposes a local browser UI from [public/index.html](../public/index.html) and [public/app.js](../public/app.js), while the backend performs settings management, instance lifecycle operations, tenant onboarding, Cloudflare publishing, and certificate renewal. Storage is intentionally file-based and local: the app keeps registry data under the data directory and each instance under its own subdirectory, as described by the settings object in [src/store.js](../src/store.js) and the filesystem paths in [README.md](../README.md).

## Core findings

- Multi-instance tenancy: each instance is created as a separate Docker Compose project named `prowler-<slug>`, with isolated ports, secrets, and database data. This is implemented by the `projectName`, `buildOverride`, `writeStack`, and `compose` logic in [src/prowler.js](../src/prowler.js).
- Local-only runtime architecture: the manager binds its HTTP API and UI to loopback, while each tenant stack is also loopback-only; public access is achieved through Cloudflare tunnel ingress rather than direct host exposure. See [src/server.js](../src/server.js), [src/prowler.js](../src/prowler.js), and [README.md](../README.md).
- Microsoft 365 identity integration: the app supports MSP, dedicated app, and manual app registration patterns, and uses certificate-based Entra app authentication with automatic renewal logic. The evidence is in [src/certs.js](../src/certs.js), [src/msp.js](../src/msp.js), and [src/renewal.js](../src/renewal.js).
- Security by separation: certificate private keys are encrypted at rest, the service runs under a dedicated system user, and the service is hardened with systemd security directives. See [src/secrets.js](../src/secrets.js), [deploy/prowler-manage.service](../deploy/prowler-manage.service), and the security section in [README.md](../README.md).
- Deployment model: on Linux it is installed as a systemd service and updated via a root-owned update trigger and helper script. See [deploy/install.sh](../deploy/install.sh), [deploy/update.sh](../deploy/update.sh), [deploy/prowler-manage-update.path](../deploy/prowler-manage-update.path), and [deploy/prowler-manage-update.service](../deploy/prowler-manage-update.service).

## Architectural conclusion

This is a security-focused operations manager for Prowler installations, not an Azure-hosted application. It runs locally on a Linux or Windows machine and orchestrates external Microsoft 365 access plus Cloudflare ingress. The actual tenant workloads are Dockerized Prowler stacks, while the manager handles identity, certificate rotation, configuration persistence, and service supervision.

```mermaid
flowchart LR
    Admin[Administrator] --> UI[Browser UI\npublic/index.html + public/app.js]
    UI --> API[Express API\nsrc/server.js]
    API --> Manager[Manager services\nstore.js / jobs.js / prowler.js]
    Manager --> Docker[Docker Compose stacks\nprowler-<slug>]
    Manager --> CF[Cloudflare tunnel]\n    Manager --> Entra[Microsoft Entra / Microsoft Graph]
    Docker --> Prowler[Prowler UI + API + worker + DB services]
    Entra --> M365[Microsoft 365 tenant]
    CF --> Public[Public hostname]
```

## Recommendation

The repository is production-oriented for a managed Prowler environment and is well-suited to centralized administration of many tenant-specific deployments. The major operational concerns are certificate lifecycle management, Cloudflare access protection, and the fact that the manager stores sensitive data locally rather than in a centralized database or an external identity vault.
