# Application Flow

This document tracks the major runtime flows implemented in the codebase.

## 1. Manager startup and API bootstrap
The Express app is created in [src/server.js](../src/server.js) and starts with the selected host and port. It binds static assets from [public/](../public), serves the dashboard, and defines routes for settings and instance operations. The OAuth callback path is also mounted here so Microsoft sign-in can redirect back into the manager.

```mermaid
sequenceDiagram
    participant Admin as Browser/admin
    participant Server as Express API
    participant Store as store.js
    participant Prowler as prowler.js

    Admin->>Server: GET /api/settings
    Server->>Store: read persisted settings
    Store-->>Server: config + tunnel metadata
    Server-->>Admin: JSON settings

    Admin->>Server: POST /api/instances or PUT /api/settings
    Server->>Store: save or patch registry
    Store-->>Server: updated record
    Server-->>Admin: success payload
```

## 2. Creating and launching an instance
The instance flow is orchestrated in the `launch` function in [src/server.js](../src/server.js). It prepares bootstrap material for certificate-based auth, rewrites the instance environment, runs Docker Compose, waits for health endpoints, ensures consent or certificate readiness, initializes Prowler, and then publishes the instance through Cloudflare if a hostname is configured.

```mermaid
sequenceDiagram
    participant Admin as Operator
    participant Server as Manager API
    participant Prowler as Prowler engine
    participant Docker as Docker Compose
    participant M365 as Microsoft 365 tenant
    participant CF as Cloudflare tunnel

    Admin->>Server: Create instance / Launch
    Server->>Prowler: rewriteConfig + writeStack
    Prowler->>Docker: docker compose up -d
    opt api marked unhealthy during first-boot migrations
        Prowler->>Docker: docker compose logs api (tail)
        Prowler->>Prowler: waitApi() until /health/live answers
        Prowler->>Docker: docker compose up -d (retry once)
    end
    Docker-->>Prowler: services start
    Prowler->>Prowler: waitHealthy()
    Server->>M365: consent / app setup / connection validation
    Server->>Prowler: initialize() admin account + provider + secret
    alt hostname exists
        Server->>CF: publish(public hostname -> localhost:uiPort)
    end
    Server-->>Admin: instance ready
```

## 3. Certificate bootstrap and renewal
Certificate generation and Graph operations are in [src/certs.js](../src/certs.js), while the renewal logic is in [src/renewal.js](../src/renewal.js). The sequence below describes the standard certificate lifecycle:

```mermaid
sequenceDiagram
    participant M as Manager
    participant Cert as certs.js
    participant Graph as Microsoft Graph
    participant P as Prowler

    M->>Cert: createCertificate()
    Cert-->>M: self-signed RSA certificate + private key
    M->>Graph: upload certificate / addKey
    Graph-->>M: accepted key credential
    M->>P: switch Prowler to new certificate
    M->>Graph: monitor renewal window and remove stale key when expired
```

## 4. Tenant onboarding and consent flow
The onboarding flow is implemented in [src/onboarding.js](../src/onboarding.js) and [src/msp.js](../src/msp.js). It supports direct app creation, MSP app flows, and device-code fallbacks when the Graph Command Line Tools public client is used.

```mermaid
sequenceDiagram
    participant Admin as Global admin
    participant Manager as Manager
    participant MS as Microsoft sign-in
    participant Graph as Entra Graph

    Admin->>Manager: choose tenant onboarding mode
    Manager->>MS: start sign-in / consent
    MS-->>Manager: callback + tenant context
    Manager->>Graph: create app or enterprise app relationship
    Manager->>Graph: assign required directory roles / permissions
    Manager-->>Admin: proceed to instance launch
```

## 5. Update flow
The self-update mechanism is represented by [src/updater.js](../src/updater.js) and the root-owned systemd units in [deploy/prowler-manage-update.path](../deploy/prowler-manage-update.path) and [deploy/prowler-manage-update.service](../deploy/prowler-manage-update.service). The logic is designed to avoid in-place mutation while the service is running and to switch to a staged replacement when the update succeeds.

```mermaid
sequenceDiagram
    participant UI as Manager UI
    participant Svc as Prowler service
    participant Req as update request file
    participant Root as systemd path/service
    participant Git as GitHub repository
    participant New as staged replacement

    UI->>Svc: Update now
    Svc->>Req: write request.json
    Root->>Root: watch PathExists
    Root->>Root: run update.sh
    Root->>Git: fetch latest committed version
    Git-->>Root: tag / commit metadata
    Root->>New: stage new install
    New-->>Svc: restart with new version
```
