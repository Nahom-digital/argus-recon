#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Argus Recon — one-shot installer
#
#   * installs all dependencies (Python venv + external recon tools)
#   * registers the dashboard as a systemd *user* service called
#     "argusscanner" so it keeps running on http://127.0.0.1:7666 even after
#     you close the terminal (and after logout / reboot, via linger)
#
# Usage:   ./install.sh              install everything + start the service
#          ./install.sh --upgrade    pull the latest from GitHub + restart
#          ./install.sh --restart    bounce the running service
#          ./install.sh --uninstall  remove the service
# Manage:  systemctl --user {status|restart|stop|start} argusscanner
# Logs:    journalctl --user -u argusscanner -f
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="argusscanner"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/$SERVICE.service"
PORT="${ARGUS_WEB_PORT:-7666}"
HOST="${ARGUS_WEB_HOST:-127.0.0.1}"

say()  { printf '\033[1;36m[argus]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[argus]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[argus]\033[0m %s\n' "$*" >&2; }

# --------------------------------------------------------------------------- #
# --uninstall
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--uninstall" ]; then
  say "stopping and removing the $SERVICE service …"
  systemctl --user disable --now "$SERVICE.service" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl --user daemon-reload 2>/dev/null || true
  say "done. (venv and scans left untouched; delete .venv manually if you want)"
  exit 0
fi

# --------------------------------------------------------------------------- #
# --upgrade : check GitHub for a newer version, pull it, refresh deps, restart
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--upgrade" ]; then
  command -v git >/dev/null || { err "git is not installed"; exit 1; }
  [ -d "$HERE/.git" ] || { err "this folder isn't a git checkout — clone the repo from GitHub to use --upgrade"; exit 1; }

  say "checking GitHub for updates …"
  git -C "$HERE" fetch --quiet origin || { err "git fetch failed (network / auth?)"; exit 1; }
  branch="$(git -C "$HERE" rev-parse --abbrev-ref HEAD)"
  local_rev="$(git -C "$HERE" rev-parse HEAD)"
  remote_rev="$(git -C "$HERE" rev-parse "origin/$branch" 2>/dev/null || true)"
  [ -n "$remote_rev" ] || { err "no upstream 'origin/$branch' to compare against"; exit 1; }

  if [ "$local_rev" = "$remote_rev" ]; then
    say "already up to date ($branch @ ${local_rev:0:7}) — nothing to upgrade."
    exit 0
  fi
  behind="$(git -C "$HERE" rev-list --count "HEAD..origin/$branch" 2>/dev/null || echo '?')"
  say "update available: $behind new commit(s) on origin/$branch."

  # never clobber local edits — stash them first
  if ! git -C "$HERE" diff --quiet || ! git -C "$HERE" diff --cached --quiet; then
    warn "local uncommitted changes detected — stashing them before pulling."
    git -C "$HERE" stash push -u -m "argus --upgrade autostash" >/dev/null 2>&1 || true
  fi

  say "pulling latest …"
  git -C "$HERE" pull --ff-only origin "$branch" \
    || { err "fast-forward pull failed (branch diverged) — resolve manually with git"; exit 1; }

  say "refreshing dependencies …"
  # shellcheck source=/dev/null
  source "$HERE/bootstrap.sh"; _argus_bootstrap "$HERE" || warn "dependency refresh reported problems"

  systemctl --user daemon-reload 2>/dev/null || true
  if systemctl --user is-enabled --quiet "$SERVICE.service" 2>/dev/null; then
    say "restarting $SERVICE with the new version …"
    systemctl --user restart "$SERVICE.service"
    if systemctl --user is-active --quiet "$SERVICE.service"; then
      say "✔ upgraded to ${remote_rev:0:7} and restarted → http://$HOST:$PORT"
    else
      err "service failed to restart — journalctl --user -u $SERVICE -e"; exit 1
    fi
  else
    say "✔ upgraded to ${remote_rev:0:7}. Service not installed yet — run ./install.sh to set it up."
  fi
  exit 0
fi

# --------------------------------------------------------------------------- #
# 0. sanity
# --------------------------------------------------------------------------- #
[ -f "$HERE/serve" ]  || { err "serve launcher not found in $HERE — run this from the argus-recon dir"; exit 1; }
command -v systemctl >/dev/null || { err "systemd not available on this machine"; exit 1; }

# --------------------------------------------------------------------------- #
# 0b. already running?  detect an active instance and re-run idempotently.
#     Pass --force to reinstall from scratch; --restart to just bounce it.
# --------------------------------------------------------------------------- #
if systemctl --user is-active --quiet "$SERVICE.service"; then
  RUNNING_PID="$(systemctl --user show -p MainPID --value "$SERVICE.service" 2>/dev/null || echo '?')"
  say "$SERVICE is already active (pid $RUNNING_PID) → http://$HOST:$PORT"
  case "${1:-}" in
    --force)
      say "--force: tearing down and reinstalling …"
      systemctl --user disable --now "$SERVICE.service" 2>/dev/null || true
      ;;
    --restart)
      say "--restart: bouncing the service and exiting."
      systemctl --user restart "$SERVICE.service"
      systemctl --user is-active --quiet "$SERVICE.service" \
        && say "✔ $SERVICE restarted → http://$HOST:$PORT" \
        || { err "restart failed — see: journalctl --user -u $SERVICE -e"; exit 1; }
      exit 0
      ;;
    *)
      say "nothing to do. It's already running and set to start on boot."
      echo "   re-run options:  ./install.sh --restart   (bounce it)"
      echo "                    ./install.sh --force     (reinstall deps + unit)"
      echo "                    ./install.sh --uninstall (remove the service)"
      exit 0
      ;;
  esac
fi

# --------------------------------------------------------------------------- #
# 1. base system packages  (fresh-server safe)
#    Everything Argus needs to even bootstrap: python venv/pip, pipx, curl.
#    apt is used when present; otherwise we warn and rely on what's installed.
# --------------------------------------------------------------------------- #
export PATH="$HOME/.local/bin:$PATH"
HAVE_APT=0; command -v apt-get >/dev/null && HAVE_APT=1
APT_UPDATED=0
apt_install() {                     # apt_install pkg1 pkg2 …  (idempotent-ish)
  [ "$HAVE_APT" = 1 ] || { warn "apt-get not found — install manually: $*"; return 1; }
  if [ "$APT_UPDATED" = 0 ]; then sudo apt-get update -qq || true; APT_UPDATED=1; fi
  sudo apt-get install -y "$@" || { warn "apt install failed: $*"; return 1; }
}

say "checking base system packages …"
base_apt=()
command -v python3 >/dev/null            || base_apt+=(python3)
python3 -c 'import venv'  2>/dev/null     || base_apt+=(python3-venv)
python3 -m pip --version 2>/dev/null >/dev/null || base_apt+=(python3-pip)
command -v curl >/dev/null                || base_apt+=(curl)
if [ "${#base_apt[@]}" -gt 0 ]; then
  say "installing base packages: ${base_apt[*]}  (needs sudo)"
  apt_install "${base_apt[@]}" || warn "some base packages missing — bootstrap may fail"
else
  say "python3 + venv + pip + curl already present ✔"
fi

# --------------------------------------------------------------------------- #
# 2. external recon tools  (only install what's missing)
# --------------------------------------------------------------------------- #
say "checking external recon tools …"

need_apt=()
command -v whatweb >/dev/null || need_apt+=(whatweb)
command -v ffuf    >/dev/null || command -v feroxbuster >/dev/null || need_apt+=(ffuf)
if [ "${#need_apt[@]}" -gt 0 ]; then
  say "installing recon tools: ${need_apt[*]}  (needs sudo)"
  apt_install "${need_apt[@]}" || warn "install manually later: ${need_apt[*]}"
else
  say "whatweb + ffuf/feroxbuster already present ✔"
fi

# bbot (passive subdomain / infra enum) via pipx — install pipx first if needed
if command -v bbot >/dev/null; then
  say "bbot already present ✔"
else
  if ! command -v pipx >/dev/null; then
    say "pipx not found — installing it (needed for bbot) …"
    apt_install pipx || "$(command -v python3)" -m pip install --user pipx 2>/dev/null || true
    command -v pipx >/dev/null && pipx ensurepath >/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
  if command -v pipx >/dev/null; then
    say "installing bbot via pipx …"
    pipx install bbot || warn "pipx install bbot failed — Argus falls back to crt.sh + DNS"
  else
    warn "could not install pipx — bbot skipped; Argus falls back to crt.sh + DNS"
  fi
fi

# --------------------------------------------------------------------------- #
# 3. Python venv + requirements  (serve/bootstrap.sh does this idempotently)
# --------------------------------------------------------------------------- #
say "setting up Python virtualenv + requirements …"
# shellcheck source=/dev/null
source "$HERE/bootstrap.sh"
_argus_bootstrap "$HERE" || { err "python bootstrap failed"; exit 1; }
say "python environment ready ✔  ($ARGUS_PY)"

# --------------------------------------------------------------------------- #
# 4. systemd user service: argusscanner
# --------------------------------------------------------------------------- #
say "writing systemd user unit → $UNIT"
mkdir -p "$UNIT_DIR"
cat > "$UNIT" <<EOF
[Unit]
Description=Argus Recon dashboard ($HOST:$PORT)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$HERE
Environment=PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=ARGUS_WEB_HOST=$HOST
Environment=ARGUS_WEB_PORT=$PORT
ExecStart="$HERE/serve"
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

# keep the service alive after logout / across reboot (no active login needed)
say "enabling linger so the service survives logout/reboot …"
loginctl enable-linger "$USER" 2>/dev/null \
  || warn "could not enable linger (service still runs while you're logged in)"

say "starting the $SERVICE service …"
systemctl --user daemon-reload
systemctl --user enable --now "$SERVICE.service"

# --------------------------------------------------------------------------- #
# 4. verify
# --------------------------------------------------------------------------- #
sleep 2
if systemctl --user is-active --quiet "$SERVICE.service"; then
  say "✔ $SERVICE is running → http://$HOST:$PORT"
  echo
  echo "   status : systemctl --user status $SERVICE"
  echo "   logs   : journalctl --user -u $SERVICE -f"
  echo "   restart: systemctl --user restart $SERVICE"
  echo "   stop   : systemctl --user stop $SERVICE"
  echo "   remove : ./install.sh --uninstall"
else
  err "$SERVICE failed to start. First launch installs deps and can take a minute."
  err "Inspect with: journalctl --user -u $SERVICE -e"
  exit 1
fi
