# Deployment Architecture

The repository is designed to run as a locally managed service on a Linux or Windows machine. Several deployment assumptions are visible in [README.md](../README.md), [deploy/install.sh](../deploy/install.sh), and [deploy/prowler-manage.service](../deploy/prowler-manage.service).

## Linux deployment model

The Linux model is the most explicit. The installer:

- creates a dedicated `prowler-manage` user and group;
- copies the application to `/opt/prowler-manage`;
- creates data directories under `/var/lib/prowler-manage`;
- installs systemd service units;
- configures a master key source for encrypted certs and certificate renewal;
- registers the manager as a background service.

This is described in [README.md](../README.md) and the service file in [deploy/prowler-manage.service](../deploy/prowler-manage.service).

## Windows deployment model

The Windows deployment is lighter and is described in the Windows section of [README.md](../README.md). It uses Docker Desktop, cloudflared as a Windows service, and DPAPI encryption tied to the Windows account. This means the Windows machine is treated as the source of trust for secret material and certificate protection.

## Runtime topology

```mermaid
flowchart LR
    subgraph Host[Host machine]
        PM[prowler-manage service]
        DS[Docker service]
        CF[cloudflared]
        Data[/var/lib/prowler-manage]
        Inst[/var/lib/prowler-manage/instances]
    end

    PM --> DS
    PM --> Data
    PM --> Inst
    PM --> CF
    DS --> Stack1[Instance 1\nprowler-<slug>]
    DS --> Stack2[Instance 2\nprowler-<slug>]
    DS --> StackN[Instance N\nprowler-<slug>]
    CF --> Public[Public hostname]
```

## Port semantics

The design avoids host-wide exposure. Each instance binds its UI/API to loopback only and uses per-instance ports. This behavior is created in the override file in [src/prowler.js](../src/prowler.js) and is described in [README.md](../README.md). Public exposure happens only after Cloudflare routing is configured, so traffic reaches the application through the tunnel instead of by exposing all container ports. The override also lengthens health-check grace periods (postgres 180s, neo4j 300s, api 600s) because a first boot on Docker Desktop bind mounts, and the API's Django migrations in particular, can outlast the upstream defaults; otherwise `worker` and `worker-beat` fail with "dependency failed to start: container ...-api-1 is unhealthy". If `up` still fails, `launch` logs the API's last output, waits up to 15 minutes for `/health/live`, and retries once.

## Update deployment semantics

The update design is intentionally staged and guarded:

1. the service writes a request file;
2. the root path unit watches for it;
3. the update service runs [deploy/update.sh](../deploy/update.sh);
4. the new version is installed beside the old one and switched in.

This pattern is implemented in [deploy/prowler-manage-update.path](../deploy/prowler-manage-update.path), [deploy/prowler-manage-update.service](../deploy/prowler-manage-update.service), and [src/updater.js](../src/updater.js).

## Operational deployment conclusion

This repository is a host-operated control plane, not a cloud-native cluster deployment. Its deployment model is a single trusted machine running Docker, a managed tunnel, and a credentials-aware service process.
