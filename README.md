# Prowler Manager

A small web app for running many [Prowler App](https://github.com/prowler-cloud/prowler) installations on one Linux server or Windows machine. Each installation is tied to one Microsoft 365 tenant and published through the host's existing Cloudflare Tunnel.

## What an instance is

Each instance is a separate Docker Compose project (`prowler-<slug>`) in `instances/<slug>/`, with its own:

- Prowler UI, API, worker, beat, MCP server, Postgres, Valkey and Neo4j containers, data and generated secrets
- UI and API ports, bound to `127.0.0.1` only (starting at 3100 and 8100). No other service is published on the host.
- Prowler admin account, M365 provider, stored app credentials and daily scan schedule
- Public hostname, routed by cloudflared to `http://localhost:<uiPort>`

## Requirements

- Docker with the Compose plugin 2.24.4 or later (Docker Engine on Linux, Docker Desktop on Windows)
- Node.js 20 or later (and pnpm for development)
- cloudflared, already installed and running as a service (systemd on Linux, a Windows service on Windows)
- For client tenants: a Global Administrator of your own MSP tenant, once, to create the MSP app. Then, per customer, approval by their Global Admin or by you through GDAP. Alternatively, a customer admin who can sign in once, or an existing app registration set up per Prowler's [M365 authentication guide](https://docs.prowler.com/user-guide/providers/microsoft365/authentication).

## Run

On a Linux server, install it as a service: see [Running on Linux](#running-on-linux-recommended-for-production). For development, or on Windows:

```bash
pnpm install
pnpm start         # http://127.0.0.1:4500
```

Environment variables:
- `PORT` (default 4500) and `HOST` (default 127.0.0.1)
- `PROWLER_MANAGE_DATA` (default `./data`) and `PROWLER_MANAGE_INSTANCES` (default `./instances`)
- `PROWLER_MANAGE_KEY_FILE` (Linux master key, see below)
- `CLOUDFLARE_API_TOKEN` (optional alternative to the token in Settings)

## Running on Linux (recommended for production)

The manager runs on any systemd-based Linux server with Docker, such as Ubuntu 22.04/24.04, Debian 12 or RHEL 9. It installs the Prowler instances on that same server.

### Prerequisites

- **Docker Engine** with the **Compose plugin 2.24.4 or later**. Install `docker-ce` and `docker-compose-plugin` from [Docker's repository](https://docs.docker.com/engine/install/); distribution packages are often too old.
- **Node.js 20 or later**, installed system-wide, for example from [NodeSource](https://github.com/nodesource/distributions) or the official tarball in `/usr/local`.
- **cloudflared** installed as a service, for example with `sudo cloudflared service install <token>`.
- For several instances, plan for about 4 GB of RAM per instance.

### Install

```bash
git clone <this repository> prowler-manage && cd prowler-manage
sudo ./deploy/install.sh               # add --cloudflared-local for a locally-managed tunnel
```

The installer:
- checks the prerequisites
- creates the unprivileged system user `prowler-manage`, a member of the `docker` group
- copies the app to `/opt/prowler-manage` and installs its dependencies
- creates the master key that encrypts certificate private keys (see below)
- installs and starts the `prowler-manage` systemd service

Run it again after `git pull` to upgrade, or use the **Updates** button (see [Updating Prowler Manager](#updating-prowler-manager)). Data, instances and the master key are kept.

The service listens on `127.0.0.1:4500` only and has no login of its own. Open it from your workstation through an SSH tunnel:

```bash
ssh -L 4500:localhost:4500 <server>
# then browse to http://localhost:4500
```

The tunnel also makes the Microsoft sign-in popups work: they redirect to `http://localhost:4500`, which the tunnel forwards to the server.

| What | Where |
|---|---|
| Application | `/opt/prowler-manage` |
| Settings, instance registry, certificates | `/var/lib/prowler-manage/data` (mode 0700) |
| Prowler instances (compose files, `.env`, databases) | `/var/lib/prowler-manage/instances/<slug>` (mode 0700) |
| Master key | `/etc/prowler-manage/master-key.cred` (systemd-creds) or `/etc/prowler-manage/master-key` |
| Service logs | `journalctl -u prowler-manage -f` |

**Back up `/var/lib/prowler-manage` and the master key together.** Without the master key, the stored certificate keys can't be decrypted, and the MSP app or dedicated apps then need new certificates uploaded by hand.

### How private keys are protected on Linux

Certificate private keys are encrypted with AES-256-GCM using a 32-byte master key. The key comes from the first available of:
1. **A systemd credential** (`LoadCredentialEncrypted`). On systemd 250 and later the installer encrypts it with `systemd-creds`, which binds it to the machine's host key, or to the TPM if there is one. A copied `.cred` file is useless elsewhere.
2. **A root-only key file** passed as a systemd credential (`LoadCredential`), on older systemd.
3. **A key file readable only by the service user** (`PROWLER_MANAGE_KEY_FILE`), on systems that can't pass credentials to services, such as containers and WSL. The installer detects this.
4. When run by hand (`pnpm start`), `data/master.key` is created with mode 0600.

If a configured key source is missing, the manager refuses to start any certificate operation rather than silently creating a new key. Settings shows which key source is in use.

### cloudflared on Linux

The manager reads the `cloudflared` systemd unit:
- **Token-based tunnel** (`cloudflared service install <token>`): routes are added through the Cloudflare API, the same as on Windows. Nothing on the server changes.
- **Locally-managed tunnel** (`/etc/cloudflared/config.yml`): install with `--cloudflared-local`. That lets the service user edit the config and run `systemctl restart cloudflared` through a single sudoers rule.

### Uninstall

```bash
sudo systemctl disable --now prowler-manage
# Stop instances first if you want them gone: for each folder in /var/lib/prowler-manage/instances,
#   sudo docker compose -p prowler-<slug> --project-directory <folder> down -v
sudo systemctl disable --now prowler-manage-update.path
sudo rm -rf /opt/prowler-manage /etc/systemd/system/prowler-manage.service /etc/systemd/system/prowler-manage-update.{service,path} /etc/sudoers.d/prowler-manage
sudo rm -rf /var/lib/prowler-manage /etc/prowler-manage      # deletes all data and the master key
sudo userdel prowler-manage
```

## Updating Prowler Manager

The **Updates** button in the header shows where this copy was installed from: the GitHub repository and branch, as a link. It also shows the installed and latest versions and the commits in between. **Update now** installs them and restarts the manager. Prowler instances keep running through the restart, and the page reloads itself on the new version. A dot on the button means an update is available; the manager checks every 6 hours. Updating is refused while an install, renewal or other job is running.

**Git clone (development, Windows).**
- The source is the clone's `origin` remote.
- Updating runs `git pull --ff-only`, then `pnpm install`, then restarts the process. The new process logs to `data/manager.log`; under `pnpm dev` the watcher restarts it instead.
- Updates are refused while the clone has uncommitted changes or commits that aren't on GitHub.
- Your existing git login is used, so private repositories work.

**Linux service.** The source is recorded at install time: the clone's GitHub `origin` and branch, or `--repo OWNER/NAME --branch BRANCH`. It's kept in `/etc/prowler-manage/install.conf`. Re-running the installer keeps it unless you pass `--repo`. How an update runs:
1. The service can't modify `/opt`. **Update now** only drops a request file.
2. The root-owned `prowler-manage-update.path` unit sees the file and runs `deploy/update.sh`.
3. That script asks GitHub for the head of the recorded branch, downloads it and runs its installer.
4. The installer stages the new version beside the old one and swaps it in. If the new version doesn't start, it rolls back to the previous one, and the dialog reports the failure.
5. The updater always installs the **head of the recorded branch**, whatever the request file says.

For a **private repository**, the service needs a GitHub token. Create a fine-grained token with read-only **Contents** access to this repository, then:

```bash
sudo ./deploy/install.sh --github-token-file ./token.txt     # stored as /etc/prowler-manage/github-token (0640)
```

An update never downgrades. If the installed version is newer than GitHub, the dialog says so and offers nothing. If the installed version isn't on GitHub at all (installed from local changes), the dialog warns that updating replaces it with the GitHub version.

Status and logs: `journalctl -u prowler-manage-update` and `/var/lib/prowler-manage/update/status.json`. GitHub Enterprise: `--github-api https://ghe.example.com/api/v3`.

## Running on Windows

Docker Desktop and cloudflared as a Windows service. Start the manager with `pnpm start`, as above. Private keys are encrypted with Windows DPAPI for the account running the manager, so another Windows account, or a Linux server, can't decrypt them. To move a Windows setup to Linux, create new certificates there (Settings → Renew certificate now, or Renew cert per instance).


## First-time setup (Settings)

1. **Cloudflare mode.** The app reads the cloudflared service's command line to detect the tunnel type:
   - **Remotely-managed** (`cloudflared tunnel run --token …`, the setup on this machine): the app edits the tunnel's ingress rules and creates a proxied CNAME through the Cloudflare API. Create an API token with **Account › Cloudflare Tunnel › Edit**, **Zone › DNS › Edit** and **Zone › Zone › Read**, and paste it into Settings. The account and tunnel IDs are taken from the service automatically.
   - **Locally-managed** (config.yml): the app adds an ingress rule to config.yml (keeping a `.bak` copy), runs `cloudflared tunnel route dns` and restarts the service. Restarting needs admin rights on Windows, or the `--cloudflared-local` install option on Linux.
   - **None**: instances are only reachable on localhost.
2. **Base domain** (optional): new instances default to `prowler-<name>.<base domain>`.
3. **Certificate lifetime / renewal window**: 6 months and 14 days by default.
4. **MSP app** (for client tenants): **Create MSP app**, see below.

## Connecting a tenant

New instance offers three ways to connect a customer's Microsoft 365 tenant.

| Option | Who signs in | What ends up in the customer's tenant |
|---|---|---|
| **Through my MSP app** (default) | You, through GDAP, or the customer's Global Admin | An enterprise app for your MSP app, created by admin consent |
| **Create a dedicated app** | A Global Admin of the customer's tenant | A dedicated app registration owned by the customer |
| **Use an existing app registration** | Nobody; you enter the IDs | Whatever you already set up |

All three request the same permissions for Prowler:
- **Microsoft Graph application permissions:** `AccessReview.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`, `OnPremDirectorySynchronization.Read.All`, `Policy.Read.All`, `RoleManagementPolicy.Read.Directory`, `SecurityIdentitiesHealth.Read.All`, `SecurityIdentitiesSensors.Read.All`, `SharePointTenantSettings.Read.All`, `ThreatHunting.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`
- **Other APIs:** `Exchange.ManageAsApp` (Office 365 Exchange Online) and `application_access` (Skype and Teams Tenant Admin API)
- **Directory role:** **Global Reader**, which the Exchange and Teams checks require

### Through my MSP app (for client tenants)

**One-time setup: Settings → MSP app → Create MSP app.** Sign in as a Global Administrator of *your own* (MSP) tenant. The manager creates a multi-tenant app named **Prowler – <your organization>** there:
- It requests the permissions above from each customer.
- It also has two delegated permissions, `User.Read` and `RoleManagement.ReadWrite.Directory`, so that "Approve now" can assign Global Reader.
- Its credential is a certificate that renews automatically. For that, the app is an owner of itself and holds `Application.ReadWrite.OwnedBy` **in your tenant only**; this is never requested from customers.
- Its redirect URIs are `http://localhost:<PORT>` and Microsoft's `…/oauth2/nativeclient` blank page.

**Per customer:** enter the customer's domain (any verified domain, e.g. `contoso.com`). The manager looks up the tenant ID from it. Then either:
- **Approve now.** A popup opens Microsoft's admin-consent page for your app in the customer's tenant. Sign in with your partner account; with GDAP you need Global Administrator, or Privileged Role Administrator plus Cloud Application Administrator, for that customer. The customer's Global Admin can also sign in on this machine. Clicking **Accept** makes Microsoft create the enterprise app in their tenant. The popup then signs you in once more, usually without asking again, so the manager can assign Global Reader. If that second step fails, the approval still stands and the instance shows **Global Reader missing**.
- **Just click Create.** The install starts straight away. The progress dialog shows the **consent link**, also available from **Copy consent link**, for you to send to the customer's Global Administrator. After they accept, Microsoft shows a blank page; that's expected. The manager checks every 15 seconds and carries on with setup. If nobody approves within an hour, the job stops; click **Launch** after they approve.

Consent alone can't assign a directory role. If the customer approved through the link, the Credential column shows **Global Reader missing**. Use the instance's **Approve** button to sign in (through GDAP or as their admin) and assign it, or have the customer assign Global Reader to your app under *Roles & admins*.

All MSP instances share your MSP app's certificate. When it renews (Settings shows its status, plus **Renew certificate now**), every running instance switches to the new certificate straight away. Stopped instances switch on their next Launch, and the old certificate stays valid for 14 days. Customers never have to do anything for a renewal.

Deleting an MSP instance leaves your app in the customer's *Enterprise applications*. The customer can remove it there to revoke access.

Customers' consent screens show your app as **unverified** until you complete [publisher verification](https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview) with your Partner Center (MPN) ID. Admins can still approve an unverified app.

### Create a dedicated app in the customer's tenant

1. **Sign in.** A popup opens Microsoft's sign-in page. Sign in as a Global Administrator of the customer's tenant. Microsoft asks you to let the manager create applications (`Application.ReadWrite.All`) and assign directory roles (`RoleManagement.ReadWrite.Directory`). The tenant ID and domain come from the sign-in.
2. **Registration.** The manager creates **Prowler – <name>** in that tenant with:
   - the permissions above, plus `Application.ReadWrite.OwnedBy` so it can renew its own certificate
   - a newly generated certificate (no secret is ever created)
   - itself as owner
   - the Global Reader role
3. **Permission approval.** The popup moves to Microsoft's admin-consent page for the new app. Click **Accept**.
4. The manager removes the temporary redirect URI and waits until the permissions are active. Then click **Create**.

Deleting such an instance can also delete its app registration (a checkbox in the Delete dialog). Entra ID keeps deleted apps restorable for 30 days.

### Use an existing app registration

Enter the tenant domain, tenant ID and client ID, then choose a certificate or a client secret, as described under [Tenant authentication](#tenant-authentication).

### Sign-in notes

- Admin sign-in tokens stay in the manager's memory and are discarded as soon as a flow finishes. They're never written to disk.
- The MSP-app setup and the dedicated-app sign-in use Microsoft's own **Microsoft Graph Command Line Tools** public client (`14d82eec-204b-4c2f-b7e8-296a70dab67e`), the same one `Connect-MgGraph` uses. If a tenant blocks it, register your own public client (redirect URI `http://localhost`) and set `setupClientId` in `data/settings.json`.
- Microsoft redirects back to `http://localhost:<PORT>`, so the browser doing the sign-in must be on the machine running the manager. The consent link sent to customers doesn't have this restriction.

## Tenant authentication

MSP instances use the MSP app's shared certificate (see above). Every other instance authenticates to its tenant with its own **certificate** (the default) or a **client secret**.

### Certificate with automatic renewal

1. **First certificate.** Tenants connected with Microsoft sign-in get it registered automatically, so skip to step 3. For an existing app registration: when you create the instance, the manager generates a self-signed RSA-2048 certificate valid for 6 months. The progress dialog shows a **Download certificate (.cer)** button. Upload the file to the app registration under *Certificates & secrets → Certificates*. The manager checks Entra ID every 15 seconds and carries on with setup once the certificate is accepted (it waits up to 60 minutes; after that, use Launch to resume).
2. **Allow the app to renew itself (once per tenant):**
   - Grant the Microsoft Graph **application** permission `Application.ReadWrite.OwnedBy`, with admin consent.
   - Make the app's own service principal an owner of its app registration:
     ```powershell
     az ad app owner add --id <client-id> --owner-object-id $(az ad sp show --id <client-id> --query id -o tsv)
     ```
   The Credential column shows "auto-renew not ready" (hover for the reason) until both are in place. The check runs at every launch and once a day.
3. **Automatic renewal.** 14 days before the certificate expires, the manager:
   1. generates the next certificate;
   2. registers it on the app registration with Graph [`addKey`](https://learn.microsoft.com/graph/api/application-addkey), proving possession of the current certificate;
   3. waits until Entra ID accepts the new certificate;
   4. switches Prowler to it and re-tests the connection;
   5. leaves the old certificate registered until it expires (the 2-week overlap), then removes it with `removeKey`.

   Renewal is checked every hour while the manager runs. A renewal interrupted partway resumes without registering a duplicate key. A failed attempt is retried after 6 hours and shown in the Credential column. If Prowler is stopped during a renewal, it receives the new certificate on the next Launch.
4. **Renew cert** (row action) renews immediately. It works automatically if the app can renew itself; otherwise, or if the certificate has already expired, it asks you to upload a new `.cer` as in step 1.

**The manager must run during the 14-day renewal window.** An app can only register a new key while it still has a valid certificate. If the certificate expires first, scans fail until you use Renew cert and upload the new certificate by hand. Running the manager as a service (the systemd unit on Linux) avoids this.

The private key is never stored in clear. Prowler keeps its own encrypted copy. The manager's copy is encrypted with the master key on Linux (see [How private keys are protected on Linux](#how-private-keys-are-protected-on-linux)), or with Windows DPAPI for the account running the manager on Windows.

### Client secret

Paste the secret when you create the instance. It's sent to Prowler and never written to disk. Rotating it is manual: create a new secret in Entra ID and enter it under Edit.

Switching an instance between the two methods under Edit is supported. Switching to a certificate starts over at step 1.

## Operations

| Action | What happens |
|---|---|
| **New instance** | Looks up the latest Prowler release on GitHub, downloads that release's `docker-compose.yml` and `.env`, writes a per-instance `.env` (fresh secrets, pinned image versions, `AUTH_URL` set to the public hostname) and a `docker-compose.override.yml` (ports), pulls the images and starts the stack. Once the stack is healthy, it creates the Prowler admin user, registers the tenant as an M365 provider, stores the app credentials, queues a connection test, schedules daily scans and adds the tunnel route and DNS record. |
| **Launch / Open** | Starts a stopped stack and finishes any setup steps that didn't complete. Opens the URL when the instance is already running. |
| **Stop** | `docker compose stop` |
| **Edit** | Change the name, hostname (the tunnel route and DNS record are moved), authentication method or app credentials (the Prowler secret is updated and the connection re-tested). Optionally upgrades to the latest Prowler release (downloads new compose files, pulls, recreates; the API runs migrations on start). The tenant domain can't be changed. |
| **Renew cert** | Renews the tenant certificate now (see above). |
| **Sign-in** | Shows the Prowler admin email and password for the instance. |
| **Logs** | Tail of `docker compose logs`, filterable by service. |
| **Delete** | Removes the tunnel route and DNS record, then runs `docker compose down -v` and deletes the instance folder. This destroys all scan data. |

## Notes

- **Secrets:** `data/instances.json` holds each instance's Prowler admin password and the generated stack secrets in plain text. It is git-ignored; keep the folder private. Certificate private keys in it are encrypted (master key on Linux, DPAPI on Windows). On Linux the folder is mode 0700 and its files 0600. The M365 client secret is never written to disk: it goes straight into Prowler, which stores it encrypted, and is kept only in memory until setup finishes.
- **No manager login:** the manager listens on 127.0.0.1 only. Reach it through an SSH tunnel; don't expose it through Cloudflare.
- **Resources:** each instance runs 9 containers. Neo4j memory defaults to 512M per instance (Settings); upstream uses 1G.
- **Status:** background jobs are held in memory. If the manager restarts during a job, the instance is marked as interrupted; use Launch to resume.
