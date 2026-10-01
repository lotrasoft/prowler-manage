#!/usr/bin/env bash
# Root-side self-update for the Prowler Manager service. Started by prowler-manage-update.path when
# the manager (unprivileged) drops /var/lib/prowler-manage/update/request.json.
#
# The request file is only a trigger: this script always installs the current head of the
# repository and branch recorded at install time (/etc/prowler-manage/install.conf), never a
# commit named by the request. GitHub serves commits from forks under the same URLs, so accepting
# a commit id from an unprivileged process would let it install arbitrary code as root.
set -euo pipefail

ETC_DIR=/etc/prowler-manage
STATE_DIR=/var/lib/prowler-manage
UPDATE_DIR="$STATE_DIR/update"
APP_DIR=/opt/prowler-manage
APP_USER=prowler-manage

write_status() { # state message
  local tmp="$UPDATE_DIR/status.json.tmp"
  printf '{"state":"%s","message":"%s","finishedAt":"%s"}\n' "$1" "${2//\"/\'}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp"
  chown "$APP_USER:$APP_USER" "$tmp" 2>/dev/null || true
  mv "$tmp" "$UPDATE_DIR/status.json"
}
fail() { write_status failed "$1"; echo "ERROR: $1" >&2; exit 1; }

exec 9>/run/prowler-manage-update.lock
flock -n 9 || { echo "Another update is running"; exit 0; }
rm -f "$UPDATE_DIR/request.json"   # consume the trigger first so a failure can't loop

[[ -f "$ETC_DIR/install.conf" ]] || fail "missing $ETC_DIR/install.conf; re-run deploy/install.sh"
# shellcheck source=/dev/null
. "$ETC_DIR/install.conf"
[[ "${REPO:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "no valid GitHub repository in install.conf"
[[ "${BRANCH:-}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "no valid branch in install.conf"

AUTH=()
if [[ -s "$ETC_DIR/github-token" ]]; then AUTH=(-H "Authorization: Bearer $(tr -d '[:space:]' < "$ETC_DIR/github-token")"); fi
API="${GITHUB_API:-https://api.github.com}"
api() { curl -fsSL --retry 2 -H 'Accept: application/vnd.github+json' -H 'User-Agent: prowler-manage-updater' "${AUTH[@]}" "$@"; }

write_status running "Checking $REPO@$BRANCH"
NODE_BIN="$(command -v node)"
SHA="$(api "$API/repos/$REPO/commits/$BRANCH" | "$NODE_BIN" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).sha||""))')" \
  || fail "could not read $REPO@$BRANCH from GitHub (token missing or without access?)"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || fail "unexpected commit id from GitHub"
CURRENT="$("$NODE_BIN" -p 'try{require("'"$APP_DIR"'/VERSION.json").sha||""}catch{""}' 2>/dev/null || true)"
if [[ "$SHA" == "$CURRENT" ]]; then write_status up-to-date "Already at ${SHA:0:7}"; exit 0; fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
write_status running "Downloading ${SHA:0:7}"
api -o "$WORK/src.tgz" "$API/repos/$REPO/tarball/$SHA" || fail "download of ${SHA:0:7} failed"
mkdir "$WORK/src"
tar -xzf "$WORK/src.tgz" -C "$WORK/src" --strip-components=1 || fail "could not unpack ${SHA:0:7}"
[[ -f "$WORK/src/deploy/install.sh" && -f "$WORK/src/src/server.js" ]] || fail "${SHA:0:7} does not look like Prowler Manager"

write_status running "Installing ${SHA:0:7}"
if PM_SOURCE_REPO="$REPO" PM_SOURCE_BRANCH="$BRANCH" PM_SOURCE_SHA="$SHA" bash "$WORK/src/deploy/install.sh" --from-update; then
  write_status succeeded "Updated ${CURRENT:0:7} → ${SHA:0:7}"
else
  fail "installing ${SHA:0:7} failed; the previous version is still installed (journalctl -u prowler-manage-update)"
fi
