"""
Dashboard access log.

Appends one JSON record per meaningful HTTP request the dashboard serves: who
connected (client IP, honouring a trusted proxy's X-Forwarded-For), when, what
they asked for (method + path + trimmed query), and how it went (status, bytes,
duration), plus the client's User-Agent and Referer. Records are written as JSON
Lines (one object per line) under scans/.access, one file per day, so the log
stays valid, appendable and easy to grep or load back.

Only metadata is stored. Request bodies and headers other than User-Agent and
Referer are never written, so a key or credential posted to the dashboard cannot
leak into the log. Static assets, the favicon and the client's version poll are
skipped as noise. Everything here is best-effort: a logging failure never affects
the response. Disable entirely with ARGUS_ACCESS_LOG=0.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone

from . import config

ENABLED = os.environ.get("ARGUS_ACCESS_LOG", "1") != "0"
LOG_DIR = config.SCANS_DIR / ".access"

_LOCK = threading.Lock()
_MAX_QUERY = 300
_MAX_UA = 400
_MAX_REF = 400

# Requests that are not a "visit": static files, the favicon, and the build-token
# poll the client runs every 45s (web/static/js/version.js). Logging them would
# bury the actual accesses in noise.
_SKIP_EXACT = {"/favicon.ico", "/api/version"}


def _skip(path: str) -> bool:
    return path.startswith("/static/") or path in _SKIP_EXACT


def _response_bytes(response) -> int | None:
    try:
        n = response.calculate_content_length()
        if n is not None:
            return int(n)
    except Exception:
        pass
    try:
        cl = response.headers.get("Content-Length")
        return int(cl) if cl is not None else None
    except Exception:
        return None


def record(request, response, *, started: float | None = None,
           user: str | None = None) -> None:
    """Append one line for this request. Never raises.

    `user` is the signed-in account the request was made as (None for an
    anonymous hit, which after ./install.sh means a failed or absent login).
    Naming it here is what lets the admin page answer "who looked at what".
    """
    if not ENABLED:
        return
    try:
        path = request.path or "/"
        if _skip(path):
            return
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        rec = {
            "ts": ts,
            # ProxyFix has already promoted a trusted X-Forwarded-For to remote_addr
            "ip": request.remote_addr or "",
            "user": (user or "")[:64],
            "method": request.method,
            "path": path,
            "query": request.query_string.decode("utf-8", "replace")[:_MAX_QUERY],
            "status": getattr(response, "status_code", None),
            "bytes": _response_bytes(response),
            "ua": (request.headers.get("User-Agent") or "")[:_MAX_UA],
            "referer": (request.headers.get("Referer") or "")[:_MAX_REF],
        }
        # keep the raw forwarded chain when a proxy is in front, for provenance
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            rec["forwarded"] = xff[:200]
        if started is not None:
            rec["ms"] = round((time.time() - started) * 1000, 1)

        line = json.dumps(rec, ensure_ascii=False)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fpath = LOG_DIR / f"access-{ts[:10]}.jsonl"
        with _LOCK:
            with open(fpath, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Reading it back (the admin page's access history)
# --------------------------------------------------------------------------- #
def days() -> list[str]:
    """Dates that have a log file, newest first."""
    try:
        return sorted((p.stem.replace("access-", "")
                       for p in LOG_DIR.glob("access-*.jsonl")), reverse=True)
    except Exception:
        return []


def read(*, day: str | None = None, limit: int = 500, user: str | None = None,
         q: str | None = None) -> list[dict]:
    """Most recent records first, optionally narrowed to one account or a
    substring of the path/IP/user-agent.

    Reads the file backwards a block at a time: a busy day's log is megabytes and
    the page only ever wants the tail of it, so parsing the whole file to throw
    away all but the last few hundred lines would be the wrong shape entirely.
    """
    picked = [d for d in days() if not day or d == day]
    needle = (q or "").strip().lower()
    out: list[dict] = []
    for d in picked:
        path = LOG_DIR / f"access-{d}.jsonl"
        for line in reversed(_tail_lines(path, limit * 4)):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            # "anonymous" is what the summary calls a record with no account,
            # so selecting it from the UI has to match the empty field.
            who = rec.get("user") or "anonymous"
            if user and who != user:
                continue
            if needle:
                hay = " ".join(str(rec.get(k) or "") for k in
                               ("path", "ip", "ua", "user", "query")).lower()
                if needle not in hay:
                    continue
            out.append(rec)
            if len(out) >= limit:
                return out
    return out


def _tail_lines(path, want: int) -> list[str]:
    """The last `want` non-empty lines of a file, read from the end."""
    try:
        size = path.stat().st_size
    except OSError:
        return []
    block = 64 * 1024
    data = b""
    try:
        with open(path, "rb") as fh:
            pos = size
            while pos > 0 and data.count(b"\n") <= want:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
    except Exception:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return [ln for ln in lines if ln.strip()][-want:]


def summary(limit_days: int = 14) -> dict:
    """Coarse per-day / per-user counts for the admin page's header."""
    per_day: dict[str, int] = {}
    per_user: dict[str, int] = {}
    for d in days()[:limit_days]:
        path = LOG_DIR / f"access-{d}.jsonl"
        n = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    n += 1
                    try:
                        who = json.loads(line).get("user") or "anonymous"
                    except Exception:
                        who = "anonymous"
                    per_user[who] = per_user.get(who, 0) + 1
        except Exception:
            continue
        per_day[d] = n
    return {"per_day": per_day, "per_user": per_user,
            "total": sum(per_day.values())}
