#!/usr/bin/env bash
# Install or upgrade Prowler Manager as a systemd service on Linux.
#
#   sudo ./deploy/install.sh [options]
#
#   --cloudflared-local       Allow the service to edit /etc/cloudflared/config.yml and restart
#                             cloudflared (only for a locally-managed tunnel; token tunnels use the API).
#   --no-cloudflared-local    Undo --cloudflared-local.
#   --port PORT               Listen port (default 4500, loopback only).
#   --github-token-file FILE  Read-only GitHub token for self-updates from a private repository.
#   --repo OWNER/NAME         GitHub repository for self-updates (default: this clone's origin).
#   --branch BRANCH           Branch to follow for self-updates (default: this clone's branch).
#   --github-api URL          GitHub API base for GitHub Enterprise (default https://api.github.com).
#
# Options are remembered in /etc/prowler-manage/install.conf. Re-running upgrades the code in
# /opt/prowler-manage and keeps data, instances, the master key and the GitHub token.
set -euo pipefail

APP_USER=prowler-manage
APP_DIR=/opt/prowler-manage
STATE_DIR=/var/lib/prowler-manage
ETC_DIR=/etc/prowler-manage
CONF="$ETC_DIR/install.conf"
UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Defaults, then what a previous install remembered, then command-line options.
PORT=4500
CF_LOCAL=0
REPO=""
BRANCH=""
GITHUB_API=https://api.github.com
# shellcheck source=/dev/null
[[ -f "$CONF" ]] && . "$CONF"
TOKEN_FILE_ARG=""
FROM_UPDATE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cloudflared-local) CF_LOCAL=1 ;;
    --no-cloudflared-local) CF_LOCAL=0 ;;
    --port) PORT="${2:?--port needs a value}"; shift ;;
    --github-token-file) TOKEN_FILE_ARG="${2:?--github-token-file needs a file}"; shift ;;
    --repo) REPO="${2:?--repo needs OWNER/NAME}"; shift ;;
    --branch) BRANCH="${2:?--branch needs a value}"; shift ;;
    --github-api) GITHUB_API="${2:?--github-api needs a URL}"; shift ;;
    --from-update) FROM_UPDATE=1 ;;   # used by deploy/update.sh
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || die "This installer is for Linux."
[[ $EUID -eq 0 ]] || die "Run as root (sudo $0)."
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die "systemd is required."
[[ "$PORT" =~ ^[0-9]+$ ]] || die "Invalid port: $PORT"

# ---- prerequisites -------------------------------------------------------------------------
info "Checking prerequisites"
command -v docker >/dev/null || die "Docker is not installed. See https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker is installed but the engine isn't running (systemctl start docker)."
COMPOSE_VERSION="$(docker compose version --short 2>/dev/null | sed 's/^v//')" \
  || die "Docker Compose plugin missing. Install docker-compose-plugin from Docker's repository."
if ! printf '%s\n%s\n' "2.24.4" "$COMPOSE_VERSION" | sort -V -C; then
  die "Docker Compose $COMPOSE_VERSION is too old; 2.24.4 or later is required (docker-compose-plugin from Docker's repository)."
fi
NODE_BIN="$(command -v node || true)"
[[ -n "$NODE_BIN" ]] || die "Node.js 20+ is required (e.g. https://nodejs.org/en/download or NodeSource packages)."
NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]')"
(( NODE_MAJOR >= 20 )) || die "Node.js $NODE_MAJOR found; 20 or later is required."
case "$NODE_BIN" in
  /root/*|/home/*) die "node is at $NODE_BIN, which the service user can't reach. Install Node.js system-wide." ;;
esac
command -v curl >/dev/null || warn "curl not found; self-updates need it."
command -v cloudflared >/dev/null || warn "cloudflared not found; instances won't be published until it is installed and running."

# ---- where this code comes from (shown in the UI, used for self-updates) -------------------
SHA="${PM_SOURCE_SHA:-}"
if [[ -n "${PM_SOURCE_REPO:-}" ]]; then
  REPO="$PM_SOURCE_REPO"; BRANCH="${PM_SOURCE_BRANCH:-$BRANCH}"
elif command -v git >/dev/null && [[ -e "$SRC_DIR/.git" ]]; then
  g() { git -c safe.directory="$SRC_DIR" -C "$SRC_DIR" "$@"; }
  ORIGIN="$(g remote get-url origin 2>/dev/null || true)"
  if [[ -z "$REPO" && "$ORIGIN" =~ github\.com[:/]([^/]+/[^/]+)$ ]]; then REPO="${BASH_REMATCH[1]%.git}"; fi
  [[ -n "$BRANCH" ]] || BRANCH="$(g rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  SHA="$(g rev-parse HEAD 2>/dev/null || true)"
  if [[ -n "$(g status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
    warn "Installing a clone with uncommitted changes; the recorded version won't match GitHub exactly."
  fi
fi
BRANCH="${BRANCH:-main}"
if [[ -n "$REPO" && ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then die "Invalid --repo: $REPO"; fi
[[ -n "$REPO" ]] || warn "No GitHub repository known (use --repo OWNER/NAME); the Updates button will be unavailable."

# ---- service account and directories ------------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
  info "Creating system user $APP_USER"
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --user-group "$APP_USER"
fi
usermod -aG docker "$APP_USER"
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$STATE_DIR" "$STATE_DIR/data" "$STATE_DIR/instances" "$STATE_DIR/.docker" "$STATE_DIR/update"
# Traversable but not listable: each file inside sets its own access (key, token, conf).
install -d -o root -g root -m 0711 "$ETC_DIR"

cat > "$CONF.tmp" <<EOF
# Written by deploy/install.sh; read by install.sh and update.sh.
PORT=$PORT
CF_LOCAL=$CF_LOCAL
REPO=$REPO
BRANCH=$BRANCH
GITHUB_API=$GITHUB_API
EOF
chmod 0644 "$CONF.tmp" && mv "$CONF.tmp" "$CONF"

if [[ -n "$TOKEN_FILE_ARG" || -n "${GITHUB_TOKEN:-}" ]]; then
  info "Storing the GitHub token for self-updates"
  if [[ -n "$TOKEN_FILE_ARG" ]]; then tr -d '[:space:]' < "$TOKEN_FILE_ARG" > "$ETC_DIR/github-token.tmp"; else printf '%s' "$GITHUB_TOKEN" > "$ETC_DIR/github-token.tmp"; fi
  chown root:"$APP_USER" "$ETC_DIR/github-token.tmp"
  chmod 0640 "$ETC_DIR/github-token.tmp"
  mv "$ETC_DIR/github-token.tmp" "$ETC_DIR/github-token"
fi

# ---- application code (staged next to the live copy, then swapped) -------------------------
info "Preparing application in $APP_DIR.new"
rm -rf "$APP_DIR.new"
install -d -m 0755 "$APP_DIR.new"
for item in src public deploy package.json pnpm-lock.yaml README.md; do
  [[ -e "$SRC_DIR/$item" ]] && cp -R "$SRC_DIR/$item" "$APP_DIR.new/"
done
printf '{"repo":"%s","branch":"%s","sha":"%s","installedAt":"%s"}\n' "$REPO" "$BRANCH" "$SHA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$APP_DIR.new/VERSION.json"

info "Installing dependencies"
PNPM_VERSION="$("$NODE_BIN" -p 'require("'"$APP_DIR.new"'/package.json").packageManager?.split("@")[1] || ""')"
if command -v pnpm >/dev/null; then
  (cd "$APP_DIR.new" && pnpm install --prod --frozen-lockfile)
else
  (cd "$APP_DIR.new" && npx --yes "pnpm@${PNPM_VERSION:-latest}" install --prod --frozen-lockfile)
fi
chown -R root:root "$APP_DIR.new"
chmod -R u=rwX,go=rX "$APP_DIR.new"

# ---- master key (encrypts certificate private keys at rest) -------------------------------
# Preferred: a systemd credential, encrypted with the host key (and TPM if present) by systemd-creds
# on systemd 250+. Some environments (containers, WSL) can't pass credentials to services; there the
# key is a file readable only by the service user.
PROBE="$(mktemp)"
echo probe > "$PROBE"
CREDS_OK=0
# shellcheck disable=SC2016  # $CREDENTIALS_DIRECTORY is expanded by the probe's shell, not here
if systemd-run --quiet --wait --pipe -p "LoadCredential=probe:$PROBE" /bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/probe"' 2>/dev/null; then
  CREDS_OK=1
fi
rm -f "$PROBE"

new_key() { head -c 32 /dev/urandom | base64; }
KEY_LINES=()
if (( CREDS_OK )) && command -v systemd-creds >/dev/null && systemd-creds --version >/dev/null 2>&1; then
  KEY_FILE="$ETC_DIR/master-key.cred"
  if [[ ! -f "$KEY_FILE" ]]; then
    info "Creating master key (systemd-creds, bound to this machine)"
    new_key | systemd-creds encrypt --name=master-key - "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
  fi
  KEY_LINES=("LoadCredentialEncrypted=master-key:$KEY_FILE")
elif (( CREDS_OK )); then
  KEY_FILE="$ETC_DIR/master-key"
  if [[ ! -f "$KEY_FILE" ]]; then
    info "Creating master key ($KEY_FILE, root-only, passed to the service as a systemd credential)"
    (umask 077; new_key > "$KEY_FILE")
  fi
  KEY_LINES=("LoadCredential=master-key:$KEY_FILE")
else
  warn "This system can't pass credentials to services (container/WSL?); using a key file readable only by $APP_USER."
  KEY_FILE="$ETC_DIR/master-key"
  if [[ ! -f "$KEY_FILE" && -f "$ETC_DIR/master-key.cred" ]]; then
    systemd-creds decrypt --name=master-key "$ETC_DIR/master-key.cred" - > "$KEY_FILE" \
      || die "Could not migrate $ETC_DIR/master-key.cred to a key file"
  fi
  if [[ ! -f "$KEY_FILE" ]]; then
    info "Creating master key ($KEY_FILE)"
    (umask 077; new_key > "$KEY_FILE")
  fi
  chown "$APP_USER:$APP_USER" "$KEY_FILE"
  chmod 0400 "$KEY_FILE"
  KEY_LINES=("# systemd credentials are unavailable on this system; the key file is passed by path instead."
             "Environment=PROWLER_MANAGE_KEY_FILE=$KEY_FILE")
fi

# ---- optional: locally-managed cloudflared tunnel -----------------------------------------
SUDOERS=/etc/sudoers.d/prowler-manage
if (( CF_LOCAL )); then
  info "Allowing $APP_USER to edit /etc/cloudflared and restart cloudflared"
  install -d -m 0775 -g "$APP_USER" /etc/cloudflared
  [[ -f /etc/cloudflared/config.yml ]] && chgrp "$APP_USER" /etc/cloudflared/config.yml && chmod g+rw /etc/cloudflared/config.yml
  SYSTEMCTL="$(command -v systemctl)"
  printf '%s ALL=(root) NOPASSWD: %s restart cloudflared\n' "$APP_USER" "$SYSTEMCTL" > "$SUDOERS.tmp"
  visudo -cf "$SUDOERS.tmp" >/dev/null || die "Generated sudoers rule failed validation"
  install -m 0440 "$SUDOERS.tmp" "$SUDOERS"
  rm -f "$SUDOERS.tmp"
elif [[ -f "$SUDOERS" ]]; then
  rm -f "$SUDOERS"
fi

# ---- swap in the new code and (re)start --------------------------------------------------
info "Activating the new version"
rm -rf "$APP_DIR.prev"
[[ -d "$APP_DIR" ]] && mv "$APP_DIR" "$APP_DIR.prev"
mv "$APP_DIR.new" "$APP_DIR"

UNIT_BACKUP=""
if [[ -f "$UNIT_DIR/prowler-manage.service" ]]; then
  UNIT_BACKUP="$(mktemp)"
  cp "$UNIT_DIR/prowler-manage.service" "$UNIT_BACKUP"
fi
while IFS= read -r line; do
  if [[ "$line" == "@KEY_CREDENTIAL@" ]]; then
    printf '%s\n' "${KEY_LINES[@]}"
  else
    line="${line//@NODE@/$NODE_BIN}"
    [[ "$line" == Environment=PORT=* ]] && line="Environment=PORT=$PORT"
    printf '%s\n' "$line"
  fi
done < "$APP_DIR/deploy/prowler-manage.service" > "$UNIT_DIR/prowler-manage.service.tmp"
if (( CF_LOCAL )); then
  sed -i -e '/^NoNewPrivileges=/d' \
         -e 's|^# install.sh adds "ReadWritePaths=/etc/cloudflared".*|ReadWritePaths=/etc/cloudflared|' "$UNIT_DIR/prowler-manage.service.tmp"
fi
mv "$UNIT_DIR/prowler-manage.service.tmp" "$UNIT_DIR/prowler-manage.service"
install -m 0644 "$APP_DIR/deploy/prowler-manage-update.service" "$UNIT_DIR/prowler-manage-update.service"
install -m 0644 "$APP_DIR/deploy/prowler-manage-update.path" "$UNIT_DIR/prowler-manage-update.path"
chmod 0644 "$UNIT_DIR/prowler-manage.service"
systemctl daemon-reload
systemctl enable prowler-manage >/dev/null
if [[ -n "$REPO" ]]; then systemctl enable --now prowler-manage-update.path >/dev/null; fi
systemctl restart prowler-manage

sleep 3
if ! systemctl is-active --quiet prowler-manage; then
  journalctl -u prowler-manage -n 30 --no-pager >&2 || true
  if [[ -d "$APP_DIR.prev" ]]; then
    warn "The new version failed to start; rolling back to the previous one."
    rm -rf "$APP_DIR.failed" && mv "$APP_DIR" "$APP_DIR.failed" && mv "$APP_DIR.prev" "$APP_DIR"
    if [[ -n "$UNIT_BACKUP" ]]; then cp "$UNIT_BACKUP" "$UNIT_DIR/prowler-manage.service" && systemctl daemon-reload; fi
    systemctl restart prowler-manage || true
  fi
  die "The service failed to start (see the log above)."
fi
rm -rf "$APP_DIR.prev" "$APP_DIR.failed"
[[ -n "$UNIT_BACKUP" ]] && rm -f "$UNIT_BACKUP"
info "Prowler Manager is running${SHA:+ (version ${SHA:0:7})}"

(( FROM_UPDATE )) && exit 0
cat <<EOF

  Open the UI from your workstation through an SSH tunnel:

      ssh -L $PORT:localhost:$PORT $(hostname -f 2>/dev/null || hostname)
      → http://localhost:$PORT

  (Microsoft sign-in flows redirect to http://localhost:$PORT, which the tunnel forwards here.)

  Installed from: ${REPO:+https://github.com/$REPO} (branch $BRANCH)${SHA:+ at ${SHA:0:7}}
  Logs:     journalctl -u prowler-manage -f
  Data:     $STATE_DIR      Master key: $KEY_FILE   ← back these up together
EOF
if [[ -n "$REPO" && ! -s "$ETC_DIR/github-token" ]] \
   && ! curl -fsS -o /dev/null -H 'User-Agent: prowler-manage-installer' "$GITHUB_API/repos/$REPO" 2>/dev/null; then
  echo
  warn "$REPO isn't readable without a token (private?), so the Updates button can't reach it;"
  warn "re-run with --github-token-file <file> (a fine-grained token with read-only Contents access)."
fi
