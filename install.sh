#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Argus Recon — installer and service manager
#
# Registers Argus Recon as a systemd *user* service named "argus-recon". Once
# installed, the dashboard is the product: it stays up across logout and
# reboot, and every scan is started from the web UI. Nothing scans from the
# terminal any more.
#
#   ./install.sh              install everything, register the service, start it
#   ./install.sh --upgrade    pull the latest from GitHub + restart the service
#   ./install.sh --status     is it live?
#   ./install.sh --restart    bounce the service
#   ./install.sh --force      reinstall dependencies + unit, then restart
#   ./install.sh --uninstall  stop and remove the service
#
# Manage directly:  systemctl --user {status|restart|stop|start} argus-recon
# Logs:             journalctl --user -u argus-recon -f
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="argus-recon"
LEGACY_SERVICES=(argusscanner)          # earlier releases used this unit name
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/$SERVICE.service"
PORT="${ARGUS_WEB_PORT:-7666}"
HOST="${ARGUS_WEB_HOST:-127.0.0.1}"
URL="http://$HOST:$PORT"

# Privileged installs run directly when we're already root (a minimal server may
# not even ship sudo, and calling sudo as root just adds a needless dependency);
# otherwise prefix with sudo.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

say()  { printf '\033[1;36m[argus]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[argus]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[argus]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[argus]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------- #
# `systemctl --user` finds the per-user manager through XDG_RUNTIME_DIR. Shells
# that aren't a real login session (ssh root@host 'cmd', su, cron, docker exec)
# never set it, and then every --user call dies with "Failed to connect to user
# scope bus". Rebuild the pointers ourselves, and start the manager if needed.
# --------------------------------------------------------------------------- #
user_bus_ok() { systemctl --user show -p Version --value >/dev/null 2>&1; }

ensure_user_bus() {
  user_bus_ok && return 0
  local uid; uid="$(id -u)"
  export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$uid}"
  [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$XDG_RUNTIME_DIR/bus" ] \
    && export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
  user_bus_ok && return 0

  # No manager running yet: linger creates it and keeps it after logout.
  loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
  { sudo -n systemctl start "user@$uid.service" >/dev/null 2>&1 \
    || systemctl start "user@$uid.service" >/dev/null 2>&1; } || true
  local tries=10
  while [ "$tries" -gt 0 ]; do
    user_bus_ok && return 0
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

if command -v systemctl >/dev/null 2>&1 && ! ensure_user_bus; then
  warn "cannot reach the systemd user manager for $(id -un) — every"
  warn "'systemctl --user' below will fail. On a login-less shell try:"
  warn "  loginctl enable-linger $(id -un) && export XDG_RUNTIME_DIR=/run/user/$(id -u)"
fi

# --------------------------------------------------------------------------- #
# Liveness: systemd says "active", the port answers, and the answer is ours.
# --------------------------------------------------------------------------- #
unit_active() { systemctl --user is-active --quiet "$SERVICE.service" 2>/dev/null; }
unit_exists() { [ -f "$UNIT" ]; }

http_live() {
  command -v curl >/dev/null || return 1
  curl -fsS --max-time 3 "$URL/api/status" >/dev/null 2>&1
}

# Wait up to $1 seconds for the dashboard to answer (first boot installs deps).
wait_live() {
  local tries="${1:-25}"
  while [ "$tries" -gt 0 ]; do
    http_live && return 0
    sleep 1
    tries=$((tries - 1))
  done
  return 1
}

svc_pid()    { systemctl --user show -p MainPID --value "$SERVICE.service" 2>/dev/null; }
svc_since()  {
  local ts; ts="$(systemctl --user show -p ActiveEnterTimestamp --value "$SERVICE.service" 2>/dev/null)"
  [ -n "$ts" ] && date -d "$ts" '+%Y-%m-%d %H:%M' 2>/dev/null || true
}
version_of() { git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo 'unknown'; }

# The banner every path prints when Argus is up.
report_live() {
  local pid since
  pid="$(svc_pid)"; since="$(svc_since)"
  echo
  ok "LIVE  ·  $URL"
  echo "        service   $SERVICE (pid ${pid:-?})"
  [ -n "$since" ] && echo "        up since  $since"
  echo "        version   $(version_of)"
  echo "        scans     started from the dashboard, not the terminal"
  echo
  echo "   open    : xdg-open $URL"
  echo "   logs    : journalctl --user -u $SERVICE -f"
  echo "   upgrade : ./install.sh --upgrade"
  echo
}

report_down() {
  echo
  warn "NOT LIVE  ·  $URL is not answering"
  if unit_exists; then
    echo "        the unit is installed but the dashboard is not up."
    echo "        start it : systemctl --user start $SERVICE"
    echo "        why      : journalctl --user -u $SERVICE -e"
  else
    echo "        the service is not installed yet — run ./install.sh"
  fi
  echo
}

# --------------------------------------------------------------------------- #
# Retire units from earlier releases so two copies never fight over the port.
# --------------------------------------------------------------------------- #
migrate_legacy() {
  local legacy found=0
  for legacy in "${LEGACY_SERVICES[@]}"; do
    if [ -f "$UNIT_DIR/$legacy.service" ] || systemctl --user is-active --quiet "$legacy.service" 2>/dev/null; then
      found=1
      say "retiring the old '$legacy' service (renamed to '$SERVICE') …"
      systemctl --user disable --now "$legacy.service" >/dev/null 2>&1 || true
      rm -f "$UNIT_DIR/$legacy.service"
    fi
  done
  [ "$found" = 1 ] && systemctl --user daemon-reload >/dev/null 2>&1 || true
  return 0
}

write_unit() {
  say "writing systemd user unit → $UNIT"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT" <<EOF
[Unit]
Description=Argus Recon dashboard ($URL)
Documentation=https://github.com/Nahom-digital/argus-recon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$HERE
Environment=PATH=$HOME/.local/bin:$HOME/go/bin:/usr/local/bin:/usr/bin:/bin
Environment=ARGUS_WEB_HOST=$HOST
Environment=ARGUS_WEB_PORT=$PORT
ExecStart="$HERE/serve"
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
}

# --------------------------------------------------------------------------- #
# Dependency installers.
#
# Defined once, called from BOTH a fresh install and --upgrade, so either path
# always converges on the full toolset — an --upgrade used to only refresh the
# Python venv and never noticed a missing whatweb/ffuf/bbot or the Go speed
# tools (httpx/katana/subfinder/dnsx). Every function here is idempotent:
# whatever is already present and validated is left alone.
# --------------------------------------------------------------------------- #
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
HAVE_APT=0; command -v apt-get >/dev/null && HAVE_APT=1
APT_UPDATED=0
apt_install() {                     # apt_install pkg1 pkg2 …  (idempotent-ish)
  [ "$HAVE_APT" = 1 ] || { warn "apt-get not found — install manually: $*"; return 1; }
  if [ -n "$SUDO" ] && ! command -v sudo >/dev/null 2>&1; then
    warn "need root to install ($*) but neither root nor sudo is available — install manually"; return 1
  fi
  if [ "$APT_UPDATED" = 0 ]; then $SUDO apt-get update -qq || true; APT_UPDATED=1; fi
  $SUDO apt-get install -y "$@" || { warn "apt install failed: $*"; return 1; }
}

install_base_packages() {
  say "checking base system packages …"
  local base_apt=()
  command -v python3 >/dev/null                   || base_apt+=(python3)
  python3 -c 'import venv'  2>/dev/null            || base_apt+=(python3-venv)
  python3 -m pip --version 2>/dev/null >/dev/null  || base_apt+=(python3-pip)
  command -v curl >/dev/null                       || base_apt+=(curl)
  command -v git  >/dev/null                       || base_apt+=(git)
  if [ "${#base_apt[@]}" -gt 0 ]; then
    say "installing base packages: ${base_apt[*]}  (needs sudo)"
    apt_install "${base_apt[@]}" || warn "some base packages missing — bootstrap may fail"
  else
    say "python3 + venv + pip + curl + git already present ✔"
  fi
}

install_apt_recon_tools() {
  say "checking external recon tools …"
  local need_apt=()
  command -v whatweb >/dev/null || need_apt+=(whatweb)
  command -v ffuf    >/dev/null || command -v feroxbuster >/dev/null || need_apt+=(ffuf)
  # tor + torsocks power the optional "via Tor" scan. Not fatal if absent — the
  # toggle just stays locked in the dashboard — but install them so it works.
  command -v tor      >/dev/null || need_apt+=(tor)
  command -v torsocks >/dev/null || need_apt+=(torsocks)
  if [ "${#need_apt[@]}" -gt 0 ]; then
    say "installing recon tools: ${need_apt[*]}  (needs sudo)"
    apt_install "${need_apt[@]}" || warn "install manually later: ${need_apt[*]}"
  else
    say "whatweb + ffuf/feroxbuster + tor already present ✔"
  fi
}

# A Go toolchain is the one prerequisite the PD speed tools actually need. Try
# apt first (golang-go), snap as a fallback, and degrade to a warning rather
# than failing the install — everything downstream already tolerates these
# tools being absent.
install_go_toolchain() {
  command -v go >/dev/null 2>&1 && return 0
  say "Go toolchain not found — installing (needed for the recon speed tools) …"
  if apt_install golang-go; then
    hash -r 2>/dev/null || true
  fi
  if ! command -v go >/dev/null 2>&1 && command -v snap >/dev/null 2>&1; then
    say "apt did not provide Go — trying snap …"
    { [ -n "$SUDO" ] && $SUDO snap install go --classic; } >/dev/null 2>&1 \
      || snap install go --classic >/dev/null 2>&1 || true
  fi
  if command -v go >/dev/null 2>&1; then
    say "Go toolchain ready ✔  ($(go version 2>/dev/null))"
    return 0
  fi
  warn "could not install a Go toolchain — httpx/katana/subfinder/dnsx will stay"
  warn "  on Argus's built-in Python fallback. Install Go manually and re-run"
  warn "  ./install.sh --force (or --upgrade) to pick them up later."
  return 1
}

# ProjectDiscovery Go tools — the fast passes: mass HTTP probe (httpx), JS-aware
# crawler (katana), quick passive name enum (subfinder), bulk resolver (dnsx).
# Each is optional: Argus validates the binary (some distros ship an unrelated
# `httpx`) and falls back to its built-in path when one is missing. Installed via
# `go install` into ~/go/bin, which Argus searches even when it is off PATH.
install_go_tools() {
  local gobin="${GOBIN:-${GOPATH:-$HOME/go}/bin}"
  declare -A pdtools=(
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  )
  # Already present (validated PD binary)?  ~/go/bin/<tool> or a *-pd alias.
  local missing=() t
  for t in "${!pdtools[@]}"; do
    if [ -x "$gobin/$t" ] || [ -x "$gobin/$t-pd" ] || command -v "$t-pd" >/dev/null 2>&1; then
      continue
    fi
    missing+=("$t")
  done
  [ "${#missing[@]}" -eq 0 ] && { say "recon speed tools already present ✔"; return 0; }

  install_go_toolchain || return 0    # non-fatal: falls back to the Python path

  mkdir -p "$gobin"
  say "installing recon speed tools: ${missing[*]}  (go install → $gobin)"
  for t in "${missing[@]}"; do
    say "  $t …"
    GOBIN="$gobin" go install "${pdtools[$t]}" \
      || warn "  could not install $t — Argus falls back to its built-in path"
  done
  # A distro `httpx` (python3-httpx) can shadow ours on PATH. A -pd alias next to
  # our binary gives Argus an unambiguous name to resolve first.
  [ -x "$gobin/httpx" ] && ln -sf "$gobin/httpx" "$gobin/httpx-pd" 2>/dev/null || true
  case ":$PATH:" in *":$gobin:"*) ;; *) export PATH="$PATH:$gobin" ;; esac
}

# bbot (passive subdomain / infra enum) via pipx — install pipx first if needed.
install_bbot() {
  if command -v bbot >/dev/null; then
    say "bbot already present ✔"
    return 0
  fi
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
}

# The one call both a fresh install and --upgrade make: every external tool
# Argus can use, installing whatever is missing and leaving the rest alone.
install_external_tools() {
  install_apt_recon_tools
  install_go_tools
  install_bbot
}

install_python_env() {
  say "setting up the Python virtualenv + requirements …"
  # shellcheck source=/dev/null
  source "$HERE/bootstrap.sh"
  _argus_bootstrap "$HERE" || { err "python bootstrap failed"; exit 1; }
  say "python environment ready ✔  ($ARGUS_PY)"
}

usage() {
  cat <<EOF
Argus Recon — installer and service manager

  ./install.sh              install everything, register the service, start it
  ./install.sh --upgrade    pull the latest from GitHub + restart the service
  ./install.sh --status     is it live?
  ./install.sh --restart    bounce the service
  ./install.sh --force      reinstall dependencies + unit, then restart
  ./install.sh --uninstall  stop and remove the service

Service : systemctl --user {status|restart|stop|start} $SERVICE
Logs    : journalctl --user -u $SERVICE -f
Scans   : started from the dashboard at $URL (not from the terminal)
EOF
  exit 0
}

# --------------------------------------------------------------------------- #
# --help / --status / --uninstall / --restart : quick paths
# --------------------------------------------------------------------------- #
case "${1:-}" in
  --help|-h) usage ;;

  --status)
    if unit_active && http_live; then report_live; exit 0; fi
    if unit_active && ! http_live; then
      warn "the $SERVICE service is running but $URL is not answering yet."
      echo "        it may still be installing dependencies — check:"
      echo "        journalctl --user -u $SERVICE -f"
      exit 1
    fi
    report_down; exit 1
    ;;

  --uninstall)
    say "stopping and removing the $SERVICE service …"
    systemctl --user disable --now "$SERVICE.service" >/dev/null 2>&1 || true
    rm -f "$UNIT"
    migrate_legacy
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    ok "removed. Scans in ./scans and the .venv were left untouched."
    exit 0
    ;;

  --restart)
    unit_exists || { err "the service is not installed — run ./install.sh first"; exit 1; }
    say "restarting $SERVICE …"
    systemctl --user restart "$SERVICE.service"
    if wait_live 25; then report_live; else
      err "restarted, but $URL is not answering. journalctl --user -u $SERVICE -e"; exit 1
    fi
    exit 0
    ;;
esac

# --------------------------------------------------------------------------- #
# --upgrade : pull from GitHub, refresh deps, restart the service
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

  # Only commits we are *behind* are an update. A checkout that is ahead (local
  # commits not pushed yet) is up to date as far as upgrading goes.
  behind="$(git -C "$HERE" rev-list --count "HEAD..origin/$branch" 2>/dev/null || echo 0)"
  ahead="$(git -C "$HERE" rev-list --count "origin/$branch..HEAD" 2>/dev/null || echo 0)"

  if [ "$behind" = "0" ]; then
    say "already up to date ($branch @ ${local_rev:0:7})."
    [ "$ahead" != "0" ] && say "($ahead local commit(s) not pushed to origin/$branch.)"
  else
    say "update available: $behind new commit(s) on origin/$branch."

    # never clobber local edits — stash them first
    if ! git -C "$HERE" diff --quiet || ! git -C "$HERE" diff --cached --quiet; then
      warn "local uncommitted changes detected — stashing them before pulling."
      git -C "$HERE" stash push -u -m "argus --upgrade autostash" >/dev/null 2>&1 || true
    fi

    say "pulling latest …"
    if ! git -C "$HERE" pull --ff-only origin "$branch"; then
      err "cannot fast-forward: this checkout has $ahead local commit(s) not on"
      err "origin/$branch, so the branch has diverged. Nothing was changed. They are:"
      git -C "$HERE" --no-pager log --oneline "origin/$branch..HEAD" 2>/dev/null | sed 's/^/          /' >&2 || true
      err "Then re-run --upgrade after choosing one:"
      err "  push them    : git -C \"$HERE\" push origin $branch"
      err "  discard them : git -C \"$HERE\" reset --hard origin/$branch   (throws the commits away)"
      exit 1
    fi
    say "now at $(version_of)."
  fi

  say "refreshing dependencies …"
  # Same checks a fresh install runs — an --upgrade used to only refresh the
  # Python venv, so a newer commit that started using a tool you didn't have
  # yet (or a speed tool you never installed) went unnoticed until a scan hit
  # the gap. Every check here is idempotent; nothing already present is touched.
  install_base_packages
  install_external_tools
  # shellcheck source=/dev/null
  source "$HERE/bootstrap.sh"; _argus_bootstrap "$HERE" || warn "dependency refresh reported problems"

  # An upgrade always lands on a running service: install the unit if the
  # checkout predates it, refresh it if the paths changed, then restart.
  migrate_legacy
  write_unit
  systemctl --user enable "$SERVICE.service" >/dev/null 2>&1 || true
  say "restarting $SERVICE on the new version …"
  systemctl --user restart "$SERVICE.service"
  if wait_live 40; then
    ok "upgraded and restarted."
    report_live
  else
    err "the service did not come back up — journalctl --user -u $SERVICE -e"; exit 1
  fi
  exit 0
fi

# --------------------------------------------------------------------------- #
# 0. sanity
# --------------------------------------------------------------------------- #
[ -f "$HERE/serve" ]  || { err "serve launcher not found in $HERE — run this from the argus-recon dir"; exit 1; }
command -v systemctl >/dev/null || { err "systemd not available on this machine"; exit 1; }

# --------------------------------------------------------------------------- #
# 0b. already live? say so and stop. --force reinstalls over the top.
# --------------------------------------------------------------------------- #
if [ "${1:-}" != "--force" ] && unit_active && http_live; then
  say "$SERVICE is already installed and answering."
  report_live
  echo "   nothing to do. To reinstall anyway: ./install.sh --force"
  echo
  exit 0
fi
if [ "${1:-}" = "--force" ]; then
  say "--force: tearing down and reinstalling …"
  systemctl --user disable --now "$SERVICE.service" >/dev/null 2>&1 || true
fi

migrate_legacy

# --------------------------------------------------------------------------- #
# 1. base system packages  (fresh-server safe)
# --------------------------------------------------------------------------- #
install_base_packages

# --------------------------------------------------------------------------- #
# 2. external recon tools + recon speed tools + bbot  (only install what's missing)
# --------------------------------------------------------------------------- #
install_external_tools

# --------------------------------------------------------------------------- #
# 3. Python venv + requirements
# --------------------------------------------------------------------------- #
install_python_env

# --------------------------------------------------------------------------- #
# 4. register the service
# --------------------------------------------------------------------------- #
write_unit

# keep the service alive after logout / across reboot (no active login needed)
say "enabling linger so the service survives logout and reboot …"
loginctl enable-linger "$(id -un)" 2>/dev/null \
  || warn "could not enable linger (service still runs while you're logged in)"

say "starting $SERVICE …"
systemctl --user enable --now "$SERVICE.service"

# --------------------------------------------------------------------------- #
# 5. verify it is actually serving, not just "active"
# --------------------------------------------------------------------------- #
# A stray `./serve` from before the service existed still owns the port, and the
# server's single-instance guard makes our unit exit 0 on top of it. The port
# answers, so wait_live passes — but nothing is supervised. Catch that here
# rather than printing LIVE for a process systemd cannot restart.
if ! unit_active; then
  err "the unit exited immediately — something else already owns $URL."
  err "Find it and stop it, then re-run this installer:"
  err "  ss -tlnp | grep ${PORT}          # or: cat $HERE/.web.pid"
  err "  journalctl --user -u $SERVICE -e"
  exit 1
fi

if wait_live 40; then
  ok "install complete."
  report_live
else
  err "$SERVICE started but $URL never answered."
  err "First launch installs dependencies and can take a minute — check:"
  err "  journalctl --user -u $SERVICE -f"
  exit 1
fi
