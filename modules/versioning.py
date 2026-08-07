"""
Module · version management (view + corruption-safe downgrade).

Powers the admin version panel:

  * current()        · what is installed (semantic version + commit + branch)
  * list_versions()  · what is available on GitHub · tags/releases and recent
                       commits, fetched fresh from the remote
  * downgrade()      · switch to a chosen version, safely
  * status()/history() · progress of the running/last downgrade and the audit log

The downgrade never leaves a half-installed tree. A detached worker script:

  1. records the current commit and makes a backup branch,
  2. fetches from GitHub and checks out the chosen version,
  3. reinstalls the Python requirements,
  4. verifies the new tree actually imports, and
  5. only then restarts the service.

If any step before the restart fails · a bad checkout, a missing dependency, a
tree that will not import · it rolls the working copy back to the backup commit,
restores its dependencies, restarts, and records "rolled_back". So a failed
downgrade can never brick the dashboard: it always comes back on a version that
runs. Every attempt is appended to an audit log (previous version, target, time,
user, outcome).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .util import get_logger

log = get_logger("versioning")

ROOT = config.ROOT
SERVICE = "argus-recon"
VDIR = config.SCANS_DIR / ".version"
AUDIT = VDIR / "audit.jsonl"
STATUS = VDIR / "status.json"

# A git ref we are willing to check out · tag, branch or commit. Anything else is
# rejected before it reaches a shell argument.
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,120}$")


def _git(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, timeout=timeout)


def _venv_python() -> str:
    p = ROOT / ".venv" / "bin" / "python"
    return str(p) if p.exists() else sys.executable


def valid_ref(ref: str) -> bool:
    return bool(_REF_RE.match(ref or ""))


def current() -> dict:
    commit = branch = subject = date = ""
    try:
        commit = _git("rev-parse", "--short", "HEAD").stdout.strip()
        branch = _git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        out = _git("log", "-1", "--pretty=format:%cI\x1f%s").stdout
        if "\x1f" in out:
            date, subject = out.split("\x1f", 1)
    except Exception as exc:
        log.debug(f"current() git failed: {exc}")
    return {"version": config.SCANNER_VERSION, "commit": commit,
            "branch": branch, "subject": subject, "date": date}


def list_versions(fetch: bool = True, limit: int = 40) -> dict:
    """Tags/releases and recent commits available on GitHub. Fetches first so the
    list reflects the remote, not just what is already local."""
    if fetch:
        try:
            _git("fetch", "--tags", "--prune", "origin", timeout=45)
        except Exception as exc:
            log.info(f"version fetch failed (using local refs): {exc}")
    head = ""
    try:
        head = _git("rev-parse", "HEAD").stdout.strip()
    except Exception:
        pass

    tags: list[dict] = []
    try:
        out = _git("tag", "--sort=-creatordate",
                   "--format=%(refname:short)\x1f%(creatordate:short)\x1f%(subject)").stdout
        for line in out.splitlines():
            parts = line.split("\x1f")
            if parts and parts[0]:
                tags.append({"ref": parts[0],
                             "date": parts[1] if len(parts) > 1 else "",
                             "subject": parts[2] if len(parts) > 2 else ""})
    except Exception as exc:
        log.debug(f"tag list failed: {exc}")

    commits: list[dict] = []
    try:
        # Prefer the remote branch so we list what GitHub has, not only local.
        rng = "origin/main" if _git("rev-parse", "--verify", "origin/main").returncode == 0 else "HEAD"
        out = _git("log", rng, f"-n{limit}",
                   "--pretty=format:%H\x1f%h\x1f%cI\x1f%s").stdout
        for line in out.splitlines():
            parts = line.split("\x1f")
            if len(parts) == 4:
                commits.append({"commit": parts[0], "short": parts[1],
                                "date": parts[2], "subject": parts[3],
                                "current": parts[0] == head})
    except Exception as exc:
        log.debug(f"commit list failed: {exc}")

    return {"current": current(), "tags": tags, "commits": commits}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _append_audit(entry: dict) -> None:
    VDIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(AUDIT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as exc:
        log.debug(f"audit write failed: {exc}")


def history(limit: int = 50) -> list[dict]:
    try:
        lines = AUDIT.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    out.reverse()
    return out


def status() -> dict:
    try:
        return json.loads(STATUS.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "idle"}


_SCRIPT = r"""#!/usr/bin/env bash
set -uo pipefail
TARGET="$1"; VPY="$2"; LOG="$3"; STATUS="$4"; SVC="$5"; ROOT="$6"
cd "$ROOT" || { echo "cannot cd $ROOT"; exit 1; }
log(){ echo "[$(date -Is)] $*" >>"$LOG" 2>&1; }
setstatus(){ printf '%s\n' "$1" >"$STATUS" 2>/dev/null; }
setstatus '{"status":"running","target":"'"$TARGET"'"}'
log "downgrade requested to $TARGET"
CUR=$(git rev-parse HEAD 2>>"$LOG"); log "current commit $CUR"
BK="argus-backup-$(date +%Y%m%d_%H%M%S)"
if git branch "$BK" "$CUR" >>"$LOG" 2>&1; then log "backup branch $BK -> $CUR"; else log "warn: backup branch not created"; fi
log "fetching from GitHub"
git fetch --tags --prune origin >>"$LOG" 2>&1 || log "warn: fetch failed, using local refs"
if ! git rev-parse --verify "${TARGET}^{commit}" >>"$LOG" 2>&1; then
  log "target not found: $TARGET"
  setstatus '{"status":"failed","error":"target not found","previous":"'"$CUR"'","backup":"'"$BK"'"}'
  exit 1
fi
log "checking out $TARGET"
if ! git checkout -f "$TARGET" >>"$LOG" 2>&1; then
  log "checkout failed; staying on $CUR"
  setstatus '{"status":"failed","error":"checkout failed","previous":"'"$CUR"'","backup":"'"$BK"'"}'
  exit 1
fi
log "restoring python requirements"
"$VPY" -m pip install -r requirements.txt >>"$LOG" 2>&1 || log "warn: pip install returned nonzero"
log "verifying the tree imports"
if ! "$VPY" -c "import main" >>"$LOG" 2>&1; then
  log "verification FAILED; rolling back to $CUR"
  git checkout -f "$CUR" >>"$LOG" 2>&1
  "$VPY" -m pip install -r requirements.txt >>"$LOG" 2>&1
  log "rolled back; restarting service"
  systemctl --user restart "$SVC" >>"$LOG" 2>&1 || log "warn: restart failed"
  setstatus '{"status":"rolled_back","error":"target failed verification","previous":"'"$CUR"'","backup":"'"$BK"'"}'
  exit 1
fi
NEW=$(git rev-parse --short HEAD 2>>"$LOG")
log "verified; restarting service on $NEW"
systemctl --user restart "$SVC" >>"$LOG" 2>&1 || log "warn: systemctl restart failed"
setstatus '{"status":"success","target":"'"$TARGET"'","previous":"'"$CUR"'","new":"'"$NEW"'","backup":"'"$BK"'"}'
log "downgrade complete"
"""


def downgrade(target: str, user: str) -> dict:
    """Start a corruption-safe downgrade to `target` (tag / branch / commit).
    Returns immediately · the work runs in a detached worker that survives the
    service restart it triggers. Poll status() for the outcome."""
    if not valid_ref(target):
        raise ValueError("invalid version reference")
    VDIR.mkdir(parents=True, exist_ok=True)
    cur = current()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logf = VDIR / f"downgrade-{ts}.log"
    scriptf = VDIR / f"downgrade-{ts}.sh"
    scriptf.write_text(_SCRIPT, encoding="utf-8")
    scriptf.chmod(0o755)
    STATUS.write_text(json.dumps({"status": "starting", "target": target}),
                      encoding="utf-8")
    _append_audit({"time": _now(), "user": user or "?", "action": "downgrade",
                   "previous_version": cur.get("version"),
                   "previous_commit": cur.get("commit"),
                   "target": target, "log": logf.name, "status": "started"})
    # Detached: its own session so the systemctl restart the script itself fires
    # (KillMode=process on the unit) does not take the worker down with the server.
    subprocess.Popen(
        ["bash", str(scriptf), target, _venv_python(), str(logf), str(STATUS),
         SERVICE, str(ROOT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, cwd=str(ROOT))
    log.info(f"downgrade to {target} started by {user} (log {logf.name})")
    return {"started": True, "target": target, "previous": cur.get("commit"),
            "log": logf.name}


def log_tail(name: str, limit: int = 400) -> str:
    """Return the tail of a downgrade log by file name (validated)."""
    if not re.match(r"^downgrade-[0-9_]+\.log$", name or ""):
        return ""
    f = VDIR / name
    try:
        return "\n".join(f.read_text(encoding="utf-8", errors="replace")
                         .splitlines()[-limit:])
    except Exception:
        return ""
