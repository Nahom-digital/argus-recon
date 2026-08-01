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


def record(request, response, *, started: float | None = None) -> None:
    """Append one line for this request. Never raises."""
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
