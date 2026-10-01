#!/usr/bin/env bash
# Install or upgrade Prowler Manager as a systemd service on Linux.
#
#   sudo ./deploy/install.sh [--cloudflared-local] [--port PORT]
#
#   --cloudflared-local  Allow the service to edit /etc/cloudflared/config.yml and restart cloudflared
#                        (only needed for a locally-managed tunnel; token-based tunnels use the API).
#   --port PORT          Listen port (default 4500, loopback only).
#
# Re-running upgrades the code in /opt/prowler-manage and keeps data, instances and the master key.
set -euo pipefail

APP_USER=prowler-manage
APP_DIR=/opt/prowler-manage
STATE_DIR=/var/lib/prowler-manage
ETC_DIR=/etc/prowler-manage
UNIT=/etc/systemd/system/prowler-manage.service
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF_LOCAL=0
PORT=4500

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cloudflared-local) CF_LOCAL=1 ;;
    --port) PORT="${2:?--port needs a value}"; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
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
command -v cloudflared >/dev/null || warn "cloudflared not found; instances won't be published until it is installed and running."

# ---- service account and directories ------------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
  info "Creating system user $APP_USER"
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --user-group "$APP_USER"
fi
usermod -aG docker "$APP_USER"
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$STATE_DIR" "$STATE_DIR/data" "$STATE_DIR/instances" "$STATE_DIR/.docker"
install -d -o root -g root -m 0700 "$ETC_DIR"

# ---- application code ---------------------------------------------------------------------
info "Installing application to $APP_DIR"
install -d -m 0755 "$APP_DIR"
for item in src public deploy package.json pnpm-lock.yaml README.md; do
  [[ -e "$SRC_DIR/$item" ]] || continue
  rm -rf "${APP_DIR:?}/$item"
  cp -R "$SRC_DIR/$item" "$APP_DIR/"
done
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

info "Installing dependencies"
PNPM_VERSION="$("$NODE_BIN" -p 'require("'"$APP_DIR"'/package.json").packageManager?.split("@")[1] || ""')"
cd "$APP_DIR"
if command -v pnpm >/dev/null; then
  pnpm install --prod --frozen-lockfile
else
  npx --yes "pnpm@${PNPM_VERSION:-latest}" install --prod --frozen-lockfile
fi

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
  chmod 0711 "$ETC_DIR"
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

# ---- systemd unit -------------------------------------------------------------------------
info "Installing systemd unit"
while IFS= read -r line; do
  if [[ "$line" == "@KEY_CREDENTIAL@" ]]; then
    printf '%s\n' "${KEY_LINES[@]}"
  else
    line="${line//@NODE@/$NODE_BIN}"
    [[ "$line" == Environment=PORT=* ]] && line="Environment=PORT=$PORT"
    printf '%s\n' "$line"
  fi
done < "$APP_DIR/deploy/prowler-manage.service" > "$UNIT.tmp"
if (( CF_LOCAL )); then
  sed -i -e '/^NoNewPrivileges=/d' \
         -e 's|^# install.sh adds "ReadWritePaths=/etc/cloudflared".*|ReadWritePaths=/etc/cloudflared|' "$UNIT.tmp"
fi
mv "$UNIT.tmp" "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable prowler-manage >/dev/null
systemctl restart prowler-manage

sleep 2
if systemctl is-active --quiet prowler-manage; then
  info "Prowler Manager is running"
else
  journalctl -u prowler-manage -n 30 --no-pager >&2 || true
  die "The service failed to start (see the log above)."
fi

cat <<EOF

  Open the UI from your workstation through an SSH tunnel:

      ssh -L $PORT:localhost:$PORT $(hostname -f 2>/dev/null || hostname)
      → http://localhost:$PORT

  (Microsoft sign-in flows redirect to http://localhost:$PORT, which the tunnel forwards here.)

  Logs:     journalctl -u prowler-manage -f
  Data:     $STATE_DIR      Master key: $KEY_FILE   ← back these up together
EOF
