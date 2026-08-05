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
#   ./install.sh --upgrade    pull the latest from GitHub, reinstall the unit + restart
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
ENV_FILE="$HERE/.env"

# --------------------------------------------------------------------------- #
# The dashboard port is remembered across runs. Precedence: an explicit
# ARGUS_WEB_PORT in the environment wins; otherwise the value last saved to .env
# (by `--p PORT`); otherwise the built-in default. So once someone runs
# `./install.sh --p 8080`, every later ./install.sh / ./argus / serve agrees on
# 8080 without needing the variable re-exported each time.
# --------------------------------------------------------------------------- #
env_file_value() {                      # env_file_value KEY -> prints saved value
  [ -f "$ENV_FILE" ] || return 0
  # last matching line, with surrounding quotes / whitespace stripped
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1 | sed -e 's/^[[:space:]"'\'']*//' -e 's/[[:space:]"'\'']*$//'
}

# --p / --port PORT is pulled out of the argument list before anything else so it
# can front any action (`--p 9000`, `--p 9000 --force`, `--p 9000 --restart`).
NEW_PORT=""
_args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --p|--port)
      NEW_PORT="${2:-}"
      [ -n "$NEW_PORT" ] || { printf 'argus: --p needs a port number, e.g. ./install.sh --p 8080\n' >&2; exit 1; }
      shift 2 ;;
    --p=*|--port=*) NEW_PORT="${1#*=}"; shift ;;
    *) _args+=("$1"); shift ;;
  esac
done
if [ "${#_args[@]}" -gt 0 ]; then set -- "${_args[@]}"; else set --; fi

DOCTOR_REPAIR=0                         # --check sets this to 1 (repair the store)

PORT="${ARGUS_WEB_PORT:-$(env_file_value ARGUS_WEB_PORT)}"
PORT="${PORT:-7666}"
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

# Upsert a single KEY=value line in .env, preserving the rest (mirrors
# config.save_env_key so the file the dashboard reads stays the source of truth).
env_file_set() {
  local key="$1" val="$2" tmp
  touch "$ENV_FILE"
  tmp="$(mktemp)"
  local found=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*) printf '%s=%s\n' "$key" "$val" >> "$tmp"; found=1 ;;
      *)        printf '%s\n' "$line" >> "$tmp" ;;
    esac
  done < "$ENV_FILE"
  [ "$found" = 1 ] || printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# --p PORT: validate, persist, and force a reconfigure so the change actually
# lands (write the unit with the new port + restart, not "already live, skip").
PORT_CHANGED=0
if [ -n "$NEW_PORT" ]; then
  if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
    err "invalid port '$NEW_PORT' — use a number between 1 and 65535"
    exit 1
  fi
  if [ "$NEW_PORT" -lt 1024 ] && [ "$(id -u)" -ne 0 ]; then
    warn "port $NEW_PORT is privileged (<1024); a --user service usually cannot bind it."
    warn "  pick a port ≥1024 unless you know this user may bind low ports."
  fi
  PORT="$NEW_PORT"
  URL="http://$HOST:$PORT"
  env_file_set ARGUS_WEB_PORT "$PORT"
  PORT_CHANGED=1
  say "dashboard port set to $PORT (saved to .env)"
fi

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
# A scan runs as a detached child of the dashboard. With the default
# KillMode=control-group, restarting the dashboard (on-failure, an upgrade, or a
# reboot) would SIGTERM the whole group and kill any scan mid-run · which is
# exactly the "killed by signal 15" a large scan used to hit. KillMode=process
# signals only the dashboard, so running scans survive a restart and the
# dashboard re-attaches to them when it comes back up.
KillMode=process
# If a single process is OOM-killed, do not tear the whole service down with it.
OOMPolicy=continue

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

# waybackurls — the web-archive pass. Optional in the strict sense (Argus falls
# back to querying the archive's CDX index over plain HTTP), but the binary is
# both faster and wider, so install it alongside the other Go tools.
install_wayback() {
  local gobin="${GOBIN:-${GOPATH:-$HOME/go}/bin}"
  if command -v waybackurls >/dev/null 2>&1 || [ -x "$gobin/waybackurls" ]; then
    say "web-archive engine already present ✔"
    return 0
  fi
  install_go_toolchain || return 0     # non-fatal: the HTTP index path still works
  mkdir -p "$gobin"
  say "installing the web-archive engine (waybackurls) …"
  GOBIN="$gobin" go install github.com/tomnomnom/waybackurls@latest \
    || warn "  could not install waybackurls — Argus queries the archive index over HTTP instead"
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
  install_wayback
  install_bbot
}

install_python_env() {
  say "setting up the Python virtualenv + requirements …"
  # shellcheck source=/dev/null
  source "$HERE/bootstrap.sh"
  _argus_bootstrap "$HERE" || { err "python bootstrap failed"; exit 1; }
  say "python environment ready ✔  ($ARGUS_PY)"
}

# --------------------------------------------------------------------------- #
# Administrator account.
#
# The dashboard is open until key.json exists; from the moment it does, every
# page and every API route needs a signed session. So the installer creates the
# first administrator here, once, and the dashboard is authenticated from its
# very first boot rather than "we'll lock it down later".
#
# The password is read with the terminal echo off and handed to Python through
# the environment, never on a command line where `ps` would show it. It is
# stored as a PBKDF2 hash (modules/auth.py) · never in plaintext, and never in
# .env.
# --------------------------------------------------------------------------- #
KEY_FILE="$HERE/key.json"

argus_py() {
  if [ -x "$HERE/.venv/bin/python" ]; then printf '%s' "$HERE/.venv/bin/python"
  else command -v python3; fi
}

admin_exists() {
  local py; py="$(argus_py)" || return 1
  [ -n "$py" ] || return 1
  "$py" - "$HERE" <<'PY' >/dev/null 2>&1
import sys
sys.path.insert(0, sys.argv[1])
from modules import auth
sys.exit(0 if auth.configured() else 1)
PY
}

create_admin() {                        # create_admin <username> <password via $ARGUS_NEW_PW>
  local py; py="$(argus_py)"
  ARGUS_NEW_USER="$1" "$py" - "$HERE" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
from modules import auth
try:
    user = auth.bootstrap(os.environ["ARGUS_NEW_USER"], os.environ["ARGUS_NEW_PW"])
except auth.AuthError as exc:
    print(f"error: {exc}", file=sys.stderr)
    sys.exit(1)
print(f"created administrator '{user['username']}'")
PY
}

setup_admin() {
  if admin_exists; then
    say "administrator account already configured ✔  (manage it at $URL/recon/admin)"
    return 0
  fi
  if [ ! -t 0 ]; then
    warn "no terminal to ask on — the dashboard will start WITHOUT authentication."
    warn "  Anyone who can reach $URL can use it. To lock it down, run:"
    warn "    ./install.sh --admin"
    return 0
  fi

  echo
  printf '\033[1m  Create the administrator account\033[0m\n'
  echo   "  Argus requires a sign-in once this account exists. The administrator"
  echo   "  can create operators, set what each of them may scan and how often,"
  echo   "  and see every scan and every access to the dashboard."
  echo   "  Stored hashed in $KEY_FILE (never in plaintext, never in .env)."
  echo

  local user pw pw2
  while :; do
    read -r -p "  admin username [admin]: " user
    user="${user:-admin}"
    # must match modules.auth.USERNAME_RE
    if [[ "$user" =~ ^[a-z0-9][a-z0-9._-]{2,31}$ ]]; then break; fi
    warn "  3-32 characters: lowercase letters, digits, dot, dash or underscore."
  done
  while :; do
    read -r -s -p "  password (min 8 chars): " pw; echo
    if [ "${#pw}" -lt 8 ]; then warn "  too short — at least 8 characters."; continue; fi
    read -r -s -p "  repeat password: " pw2; echo
    if [ "$pw" != "$pw2" ]; then warn "  they do not match — try again."; continue; fi
    break
  done

  if ARGUS_NEW_PW="$pw" create_admin "$user"; then
    unset pw pw2
    chmod 600 "$KEY_FILE" 2>/dev/null || true
    ok "authentication is on. Sign in at $URL/login"
    echo "        admin area : $URL/recon/admin"
    echo
  else
    unset pw pw2
    err "could not create the administrator account — the dashboard will start open."
  fi
}

# --------------------------------------------------------------------------- #
# --check : doctor. Forces every dependency check and prints a readiness report,
# the way a "system ready?" health check would. It is read-only with one
# deliberate repair — a stale or corrupt SQLite store (the cache the dashboard
# reads a finished scan out of) is migrated or rebuilt in place, because a broken
# store is one of the things that makes a completed scan open to an empty panel
# and empty graph.
# --------------------------------------------------------------------------- #
D_PASS=0; D_WARN=0; D_FAIL=0
dcheck() {                              # dcheck pass|warn|fail "label" "detail"
  case "$1" in
    pass) D_PASS=$((D_PASS+1)); printf '  \033[1;32m✔\033[0m  %-24s %s\n' "$2" "${3:-}" ;;
    warn) D_WARN=$((D_WARN+1)); printf '  \033[1;33m!\033[0m  %-24s %s\n' "$2" "${3:-}" ;;
    fail) D_FAIL=$((D_FAIL+1)); printf '  \033[1;31m✘\033[0m  %-24s %s\n' "$2" "${3:-}" ;;
  esac
}
dsection() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# App-level checks (external tools, graph backend, SQLite store) run through the
# project's own Python so the doctor reports exactly what the running dashboard
# would see — validated Go binaries included. Emits "status|label|detail" lines.
doctor_python() {
  local py="$HERE/.venv/bin/python"
  [ -x "$py" ] || py="$(command -v python3 || true)"
  [ -n "$py" ] || return 1
  ARGUS_STORE_REPAIR="${1:-0}" "$py" - "$HERE" <<'PY'
import os, sys, importlib
root = sys.argv[1]
sys.path.insert(0, root)

def emit(status, label, detail=""):
    print(f"{status}|{label}|{detail}")

try:
    from modules import config
    from modules.util import resolve_tool, resolve_recon_tool
except Exception as exc:
    emit("fail", "load config", f"cannot import project modules: {exc}")
    sys.exit(0)

# Python requirements the pipeline imports at runtime.
for mod, label in [("flask","flask"),("httpx","httpx"),("bs4","beautifulsoup4"),
                   ("lxml","lxml"),("dns","dnspython"),("tldextract","tldextract"),
                   ("jsbeautifier","jsbeautifier"),("requests","requests"),
                   ("socks","PySocks")]:
    try:
        importlib.import_module(mod)
        emit("pass", f"py: {label}")
    except Exception:
        emit("fail", f"py: {label}", "missing — pip install -r requirements.txt")

# External recon tools. Validated where the app validates them.
def tool(label, name):
    p = resolve_tool(name)
    emit("pass" if p else "warn", f"tool: {label}", p or "not found (a stage falls back)")

tool("fingerprint (whatweb)", config.WHATWEB_BIN)
if resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN):
    emit("pass", "tool: content brute", resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN))
else:
    emit("warn", "tool: content brute", "ffuf/feroxbuster not found")
tool("passive enum (bbot)", config.BBOT_BIN)
tool("tor", config.TOR_BIN)
tool("torsocks", config.TORSOCKS_BIN)

# Port-scan engine — the toggle is locked without it.
ps = resolve_tool(config.PORTSCAN_BIN)
emit("pass" if ps else "warn", "tool: port scan", ps or "not found — port-scan toggle stays locked")

# Web-archive engine — optional: without it Argus queries the archive index over
# plain HTTP, which is slower and narrower but always available.
wb = resolve_tool(config.WAYBACK_BIN)
emit("pass" if wb else "warn", "tool: web archive", wb or "not found — the archive index over HTTP is used instead")

# Go speed tools: validated (an unrelated httpx on PATH must not count).
for label, name in [("http probe","httpx"),("deep crawl","katana"),
                    ("passive names","subfinder"),("bulk DNS","dnsx")]:
    aliases = config.TOOL_ALIASES.get(name)
    p = resolve_recon_tool(getattr(config, name.upper()+"_BIN", name), aliases)
    emit("pass" if p else "warn", f"speed: {label}", p or "not validated — Python fallback")

# Graph backend.
try:
    import kuzu  # noqa
    emit("pass", "graph: kuzu", "embedded backend importable")
except Exception:
    emit("warn", "graph: kuzu", "not installed — graph renders from JSON")

# Accounts. An open dashboard is a warning, not a failure: a fresh checkout that
# has not been through the installer yet is a legitimate state.
try:
    from modules import auth
    if auth.configured():
        users = auth.list_users()
        admins = sum(1 for u in users if u["role"] == "admin")
        mode = oct(auth.store_path().stat().st_mode & 0o777)[2:]
        if mode != "600":
            emit("warn", "auth: key.json", f"mode {mode} — should be 600 (chmod 600 {auth.store_path()})")
        else:
            emit("pass", "auth: key.json", f"{len(users)} account(s), {admins} admin(s), mode 600")
    else:
        emit("warn", "auth: accounts", "none — the dashboard is OPEN. Run ./install.sh --admin")
except Exception as exc:
    emit("warn", "auth: accounts", f"{exc}")

# SQLite store: integrity + schema migration, with an opt-in rebuild if corrupt.
import sqlite3
db = config.STORE_DB
repair = os.environ.get("ARGUS_STORE_REPAIR") == "1"
try:
    if db.exists():
        conn = sqlite3.connect(str(db), timeout=5)
        integ = conn.execute("PRAGMA integrity_check").fetchone()[0]
        conn.close()
        if integ != "ok":
            if repair:
                for suf in ("", "-wal", "-shm"):
                    try: os.remove(str(db)+suf)
                    except OSError: pass
                emit("warn", "store: sqlite", f"was corrupt ({integ}) — rebuilt (derived cache)")
            else:
                emit("fail", "store: sqlite", f"corrupt: {integ} — re-run with --check to rebuild")
        else:
            emit("pass", "store: integrity", "ok")
    else:
        emit("pass", "store: sqlite", "no cache yet (built on first scan)")
except Exception as exc:
    emit("warn", "store: sqlite", f"unreadable: {exc}")

# Trigger the store's own connect (runs the schema migration incl. the `panel`
# column an older DB predates) and confirm the columns the dashboard needs.
try:
    from modules import store
    conn = store._connect()
    if conn is not None:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
        need = {"summary", "panel"}
        missing = need - cols
        if missing:
            emit("fail", "store: schema", f"missing columns {sorted(missing)}")
        else:
            emit("pass", "store: schema", "summary + panel cache present")
    else:
        emit("pass", "store: schema", "store disabled (ARGUS_STORE=0)")
except Exception as exc:
    emit("warn", "store: schema", f"{exc}")
PY
}

doctor() {
  echo
  printf '\033[1m  Argus Recon — system doctor\033[0m\n'
  echo   "  checkout: $HERE"

  dsection "Base system"
  command -v python3 >/dev/null && dcheck pass "python3" "$(python3 -V 2>&1)" || dcheck fail "python3" "not installed"
  python3 -c 'import venv' 2>/dev/null && dcheck pass "python venv module" || dcheck fail "python venv module" "install python3-venv"
  python3 -m pip --version >/dev/null 2>&1 && dcheck pass "pip" || dcheck warn "pip" "install python3-pip"
  command -v curl >/dev/null && dcheck pass "curl" || dcheck warn "curl" "install curl"
  command -v git  >/dev/null && dcheck pass "git"  || dcheck warn "git" "install git"
  command -v systemctl >/dev/null && dcheck pass "systemd" || dcheck fail "systemd" "required to run as a service"
  command -v go >/dev/null 2>&1 && dcheck pass "go toolchain" "$(go version 2>/dev/null | awk '{print $3}')" \
    || dcheck warn "go toolchain" "absent — speed tools use the Python fallback"

  dsection "Python virtualenv"
  if [ -x "$HERE/.venv/bin/python" ]; then
    dcheck pass "venv" "$HERE/.venv"
  else
    dcheck fail "venv" "not created — run ./install.sh"
  fi

  dsection "Dependencies, tools & storage"
  local out
  if out="$(doctor_python "$DOCTOR_REPAIR" 2>/dev/null)"; then
    while IFS='|' read -r st label detail; do
      [ -n "$st" ] && dcheck "$st" "$label" "$detail"
    done <<< "$out"
  else
    dcheck fail "app checks" "could not run project Python checks"
  fi

  dsection "Service"
  if unit_exists; then
    dcheck pass "unit installed" "$UNIT"
    unit_active && dcheck pass "unit active" "pid $(svc_pid)" || dcheck fail "unit active" "not running — systemctl --user start $SERVICE"
    if systemctl --user is-enabled --quiet "$SERVICE.service" 2>/dev/null; then
      dcheck pass "unit enabled" "starts on login/boot"
    else
      dcheck warn "unit enabled" "not enabled — systemctl --user enable $SERVICE"
    fi
    if loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null | grep -qi yes; then
      dcheck pass "linger" "survives logout"
    else
      dcheck warn "linger" "off — service stops at logout (loginctl enable-linger $(id -un))"
    fi
  else
    dcheck warn "unit installed" "not installed — run ./install.sh"
  fi

  dsection "Network"
  dcheck pass "configured port" "$PORT ($URL)"
  if http_live; then
    dcheck pass "dashboard" "answering at $URL"
  elif unit_active; then
    dcheck warn "dashboard" "unit up but $URL not answering yet (may be installing deps)"
  else
    dcheck warn "dashboard" "not answering (service not running)"
  fi

  echo
  local total=$((D_PASS + D_WARN + D_FAIL))
  printf '  \033[1mResult:\033[0m %d checks · \033[1;32m%d ok\033[0m · \033[1;33m%d warn\033[0m · \033[1;31m%d fail\033[0m\n' \
    "$total" "$D_PASS" "$D_WARN" "$D_FAIL"
  if [ "$D_FAIL" -eq 0 ] && [ "$D_WARN" -eq 0 ]; then
    ok "system is ready."
  elif [ "$D_FAIL" -eq 0 ]; then
    say "system is functional; warnings are optional capabilities (a missing tool just disables one stage)."
  else
    err "system is NOT ready — resolve the ✘ items above (usually: ./install.sh, or ./install.sh --force)."
  fi
  echo
  [ "$D_FAIL" -eq 0 ]
}

usage() {
  cat <<EOF
Argus Recon — installer and service manager

  ./install.sh              install everything, register the service, start it
  ./install.sh --p PORT     change the dashboard port (persists + restarts)
  ./install.sh --admin      create the administrator account (turns auth on)
  ./install.sh --check      doctor: force every dependency check, report readiness
  ./install.sh --upgrade    pull the latest from GitHub, reinstall the unit + restart
  ./install.sh --status     is it live?
  ./install.sh --restart    bounce the service
  ./install.sh --force      reinstall dependencies + unit, then restart
  ./install.sh --uninstall  stop and remove the service

--p PORT may front any action:  ./install.sh --p 8080 --force

Service : systemctl --user {status|restart|stop|start} $SERVICE
Logs    : journalctl --user -u $SERVICE -f
Scans   : started from the dashboard at $URL (not from the terminal)
EOF
  exit 0
}

# --------------------------------------------------------------------------- #
# --p PORT reconfigure. A port change must rewrite the unit on the new port and
# bring the service up on it — not hit the "already live, nothing to do" path.
# If the service is not installed yet, fall through to a normal install (which
# now uses the new PORT).
# --------------------------------------------------------------------------- #
if [ "$PORT_CHANGED" = 1 ]; then
  case "${1:-}" in
    --uninstall|--help|-h|--check) : ;;   # let these run as themselves
    *)
      if command -v systemctl >/dev/null && unit_exists; then
        migrate_legacy
        write_unit
        systemctl --user enable "$SERVICE.service" >/dev/null 2>&1 || true
        say "restarting $SERVICE on port $PORT …"
        systemctl --user restart "$SERVICE.service"
        if wait_live 40; then
          ok "dashboard now on port $PORT."
          report_live
        else
          err "restarted, but $URL is not answering — journalctl --user -u $SERVICE -e"
          exit 1
        fi
        exit 0
      fi
      say "service not installed yet — installing it on port $PORT …"
      # fall through to the full install below, which uses $PORT
      ;;
  esac
fi

# --------------------------------------------------------------------------- #
# --help / --status / --uninstall / --restart : quick paths
# --------------------------------------------------------------------------- #
case "${1:-}" in
  --help|-h) usage ;;

  --admin)
    # Needs the venv to import modules.auth; build it if this is a bare checkout.
    [ -x "$HERE/.venv/bin/python" ] || install_python_env
    setup_admin
    if unit_active; then
      say "restarting $SERVICE so it picks up the account store …"
      systemctl --user restart "$SERVICE.service" >/dev/null 2>&1 || true
    fi
    exit 0
    ;;

  --check)
    # A second --check asks the doctor to repair the SQLite store if it is
    # corrupt (the rebuild is safe — the store is a derived cache).
    DOCTOR_REPAIR=1
    doctor; exit $?
    ;;

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

  # An upgrade always lands on a running service. Do a full force-style unit
  # reinstall rather than a soft restart: tear the unit down, rewrite it, reload
  # and bring it back up. A plain `restart` re-executes the process but can keep
  # the old cgroup settings live, so a unit change (KillMode, OOMPolicy, paths)
  # a new version ships would not actually take effect until the next reboot.
  # Stopping the unit first guarantees the new one is the one that starts.
  migrate_legacy
  say "reinstalling the service unit (force) …"
  systemctl --user disable --now "$SERVICE.service" >/dev/null 2>&1 || true
  write_unit
  systemctl --user enable --now "$SERVICE.service" >/dev/null 2>&1 \
    || systemctl --user restart "$SERVICE.service"
  if wait_live 40; then
    ok "upgraded, unit reinstalled and restarted."
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
# 4. administrator account (turns authentication on)
# --------------------------------------------------------------------------- #
setup_admin

# --------------------------------------------------------------------------- #
# 5. register the service
# --------------------------------------------------------------------------- #
write_unit

# keep the service alive after logout / across reboot (no active login needed)
say "enabling linger so the service survives logout and reboot …"
loginctl enable-linger "$(id -un)" 2>/dev/null \
  || warn "could not enable linger (service still runs while you're logged in)"

say "starting $SERVICE …"
systemctl --user enable --now "$SERVICE.service"

# --------------------------------------------------------------------------- #
# 6. verify it is actually serving, not just "active"
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
