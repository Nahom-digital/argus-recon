#!/usr/bin/env python3
"""
Argus Recon · local web dashboard.

Flask app served on http://127.0.0.1:7666. Reads scan JSON straight from
./scans (the home page lists them). A scan view exposes:

  * /api/scan/<id>          full scan document
  * /api/scan/<id>/graph    connected graph (Neo4j when reachable, else built
                            from the JSON via modules.graph_loader.graph_from_scan)
  * /api/status             external-tool + Neo4j availability
  * /api/scan  (POST)       kick off a new scan in the background (optional)

The graph endpoint is the same node model modules.graph_loader pushes to Neo4j,
so the view is identical whether or not the database is running.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# Make the project root importable (modules/ lives one level up).
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import (Flask, jsonify, render_template, send_from_directory,
                   send_file, request, abort, g, redirect, url_for, make_response)
from werkzeug.middleware.proxy_fix import ProxyFix

from modules import config
from modules import graph_loader
from modules import scan_stream
from modules import store
from modules import tor
from modules import portscan
from modules import wayback
from modules import securitytrails
from modules import shodan_enrich
from modules import xss_scan
from modules import sqli_scan
from modules import nuclei_scan
from modules import access_log
from modules import auth
from modules.util import resolve_tool

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["JSON_SORT_KEYS"] = False

# A reverse proxy may mount the dashboard under a path prefix and strip it before
# forwarding (nginx: `location /scanner/ { proxy_pass http://127.0.0.1:7666/; }`,
# handing the prefix back as X-Forwarded-Prefix). ProxyFix promotes that header to
# SCRIPT_NAME so url_for() and request.script_root rebuild external URLs with the
# prefix instead of emitting root-absolute paths that escape the mount point.
# One hop is trusted: the port is bound to loopback, so only the proxy reaches it.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Inline the icon sprite once so <use href="#i-name"> resolves in templates and
# in JS-generated markup alike (no external fetch, no cross-file quirks).
_SPRITE = ""
try:
    _SPRITE = (Path(__file__).parent / "static" / "icons" / "sprite.svg").read_text(encoding="utf-8")
except Exception:
    pass


# --------------------------------------------------------------------------- #
# Asset versioning (cache-busting + live reload)
#
# The browser caches CSS/JS aggressively, so after a UI change a returning tab
# can keep painting the old build. Two mechanisms fix that together:
#   1. every static URL carries `?v=<token>`, where the token is a hash of the
#      CSS/JS files on disk · a changed file is a new URL, so the browser cannot
#      serve the stale copy from cache, and
#   2. /api/version serves that same token, which the client polls (web/static/
#      js/version.js): when it changes under an open tab, the page reloads once
#      and pulls the new build through the freshly-versioned URLs.
# The HTML itself is sent no-cache (see _cache_control) so the versioned links a
# page hands out are always the current ones.
# --------------------------------------------------------------------------- #
_STATIC_DIR = Path(__file__).parent / "static"


def _compute_asset_version() -> str:
    h = hashlib.sha1()
    for sub in ("css", "js"):
        d = _STATIC_DIR / sub
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.*")):
            try:
                st = f.stat()
            except OSError:
                continue
            h.update(f"{f.name}:{int(st.st_mtime)}:{st.st_size};".encode())
    return h.hexdigest()[:12]


# Re-hashing every asset on each request is wasteful; a short TTL keeps the
# stat() work off the hot path while still noticing a change within seconds.
_ASSET_V: dict = {"at": 0.0, "value": ""}
_ASSET_V_TTL = 2.0


def asset_version() -> str:
    now = time.time()
    if _ASSET_V["value"] and now - _ASSET_V["at"] < _ASSET_V_TTL:
        return _ASSET_V["value"]
    _ASSET_V.update(at=now, value=_compute_asset_version())
    return _ASSET_V["value"]


@app.context_processor
def _inject_sprite():
    from markupsafe import Markup
    return {"sprite": Markup(_SPRITE), "asset_v": asset_version(),
            "theme": _theme_pref()}


def _theme_pref() -> str:
    """The saved light/dark choice for this browser, or "" when none. Read from
    the httpOnly cookie so the template can render the chosen theme server side
    (no first-paint flash) even though page scripts cannot see the value."""
    val = (request.cookies.get(THEME_COOKIE) or "").strip().lower()
    return val if val in THEME_VALUES else ""


import gzip as _gzip


@app.after_request
def _compress(resp):
    """gzip sizeable JSON/text responses. Scan documents are highly repetitive and
    compress ~8x, so a 15 MB list view is ~2 MB on the wire. Works with or without
    nginx in front (nginx passes an already-encoded body through untouched)."""
    try:
        if resp.direct_passthrough or resp.status_code >= 300:
            return resp
        if "gzip" not in request.headers.get("Accept-Encoding", ""):
            return resp
        if resp.headers.get("Content-Encoding"):
            return resp
        ct = resp.content_type or ""
        if not ("application/json" in ct or ct.startswith("text/")):
            return resp
        data = resp.get_data()
        # below ~1 KB the gzip header costs more than it saves; above ~40 MB the
        # synchronous compression stall isn't worth it (only the raw-JSON dump)
        if not (1024 <= len(data) <= 40_000_000):
            return resp
        comp = _gzip.compress(data, 5)
        resp.set_data(comp)
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers["Content-Length"] = str(len(comp))
        resp.headers.setdefault("Vary", "Accept-Encoding")
    except Exception:
        pass
    return resp


@app.after_request
def _security_headers(resp):
    """Baseline hardening on every response. The dashboard is an authenticated
    surface that a proxy now exposes to the internet, so:

      * X-Frame-Options / frame-ancestors · it is never meant to be framed, so
        deny it · that closes clickjacking of the login form and the admin area,
      * X-Content-Type-Options: nosniff · a browser must not re-interpret a scan
        JSON or an asset as something executable,
      * Referrer-Policy: no-referrer · the URL can carry a ?next= and the session
        lives on this origin; never leak either in a Referer to a third party,
      * a conservative Permissions-Policy · this tool needs none of these APIs.
    """
    try:
        h = resp.headers
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        h.setdefault("Permissions-Policy",
                     "geolocation=(), microphone=(), camera=(), interest-cohort=()")
    except Exception:
        pass
    return resp


@app.after_request
def _cache_control(resp):
    """HTML pages are sent no-cache so the browser always revalidates them and
    picks up the current ?v= asset token; the versioned static files it then
    points at are safe to cache. Never weakens caching on anything else."""
    try:
        ct = resp.content_type or ""
        if ct.startswith("text/html"):
            resp.headers["Cache-Control"] = "no-cache"
    except Exception:
        pass
    return resp


# --------------------------------------------------------------------------- #
# Authentication
#
# The dashboard is only "safe because it is on loopback" until the day it is
# published behind a proxy. So: once modules.auth reports an account store with
# an administrator in it (created by ./install.sh), every page and every API
# route needs a signed session token. With no store the dashboard runs open, so
# a fresh checkout still works before the installer has been through it.
#
# The token travels in an httpOnly, SameSite=Lax cookie · unreadable to any
# script, and not attached to a cross-site form post. State-changing API calls
# additionally have to echo the CSRF value carried inside the signed token,
# which only a page that could read /api/me can know.
# --------------------------------------------------------------------------- #
SESSION_COOKIE = "argus_session"
CSRF_HEADER = "X-Argus-CSRF"

# The light/dark choice rides in its own httpOnly cookie, signed by nobody
# because it is not a secret · it only has to survive a restart and be readable
# by the server so the page can be rendered in the chosen theme before first
# paint (no flash, and the same choice on every device this browser signs in
# from). httpOnly keeps it out of reach of page scripts, exactly like the
# session cookie, which is what the operator asked for.
THEME_COOKIE = "argus_theme"
THEME_VALUES = ("light", "dark")

# Reachable without a session: the login page and its endpoint, the static
# assets a login page needs, the build-token poll, and the theme switch (a
# preference, not a privileged action · it must work on the login page too).
_OPEN_PATHS = {"/login", "/api/auth/login", "/api/auth/state", "/api/version",
               "/api/theme", "/favicon.ico"}


def _open_path(path: str) -> bool:
    return path in _OPEN_PATHS or path.startswith("/static/")


def _bearer() -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def _claims():
    """Verified claims for this request, or None."""
    token = request.cookies.get(SESSION_COOKIE) or _bearer()
    return auth.verify_token(token) if token else None


def _safe_next(raw: str | None) -> str:
    """A prefix-less, in-app relative path safe to echo back into the login page's
    ?next=. Strips the mount prefix (so the client cannot double it into
    /scanner/scanner/…) and rejects anything that is not a clean same-origin path:
    absolute URLs (http:, javascript:, data:), protocol-relative //host, backslash
    tricks /\\host, and any control/whitespace smuggling. Mirrors safeInApp() on
    the client so the value is normalised the same way on both sides."""
    p = raw or "/"
    root = request.script_root or ""
    if root and (p == root or p.startswith(root + "/")):
        p = p[len(root):] or "/"
    if not p.startswith("/") or p[:2] in ("//", "/\\"):
        return "/"
    if any(c in p for c in "\x00\r\n\t \\"):
        return "/"
    return p


def _login_redirect():
    nxt = _safe_next(request.full_path if request.query_string else request.path)
    return redirect(url_for("login_page", next=nxt))


@app.before_request
def _auth_gate():
    g._req_start = time.time()
    g.user = None
    if not auth.configured():
        return None                       # no accounts yet · dashboard is open
    path = request.path or "/"
    if _open_path(path):
        return None
    claims = _claims()
    if not claims:
        if path.startswith("/api/"):
            return jsonify({"error": "authentication required",
                            "auth": "required"}), 401
        return _login_redirect()
    g.user = claims
    # CSRF: a cross-site POST can ride the cookie but cannot read the token, so
    # requiring the value from inside it is what makes the difference.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get(CSRF_HEADER, "")
        if not (sent and hmac.compare_digest(sent, claims.get("csrf", ""))):
            return jsonify({"error": "missing or stale CSRF token · reload the page"}), 403
    return None


def current_user() -> dict | None:
    return getattr(g, "user", None)


def _require_admin():
    """abort(403) unless this request is an administrator. With no account store
    configured the dashboard has no admin concept and the admin area is closed
    rather than open to everyone."""
    user = current_user()
    if not auth.configured():
        abort(404)
    if not user or user.get("role") != "admin":
        abort(403, "administrator access required")
    return user


def _may(permission: str) -> bool:
    user = current_user()
    if not user:
        return True                       # auth not configured
    if user.get("role") == "admin":
        return True
    return bool((user.get("limits") or {}).get(permission))


@app.after_request
def _access_log(resp):
    """Append a JSON line recording who accessed the dashboard and what for
    (modules.access_log · saved under scans/.access). Best-effort."""
    user = current_user() or {}
    access_log.record(request, resp, started=getattr(g, "_req_start", None),
                      user=user.get("sub"))
    return resp

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
JOBS_DIR = config.SCANS_DIR / ".jobs"
JOBS_DIR.mkdir(exist_ok=True)

# The scan job table. It used to live only in memory, so a dashboard restart (a
# crash, a redeploy, or the OOM killer taking the process during a huge scan)
# wiped every running job · the scan simply vanished from the list with no error.
# It is now mirrored to disk and reconciled on startup so a run is never lost
# silently: it is either still followed, or reported as interrupted with a reason.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_JOBS_FILE = JOBS_DIR / "jobs.json"
_JOBS_MAX = 250                     # most job records to keep on disk
_JOBS_KEEP_SEC = 7 * 86400          # drop finished jobs older than a week on load
_ACTIVE_STATES = ("queued", "running", "stopping")


def _persist_jobs() -> None:
    """Mirror the whole job table to disk. It is small, so a full atomic rewrite
    (temp file renamed over the target) keeps the file consistent and cheap.
    Best-effort: a write failure never affects a running scan."""
    try:
        with _JOBS_LOCK:
            data = list(_JOBS.values())
        tmp = _JOBS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(_JOBS_FILE)
    except Exception:
        pass


def _save_job(_job_id: str | None = None) -> None:
    """Persist after a job changed. The argument is accepted for readability at
    call sites; the whole table is written either way."""
    _persist_jobs()


def _log_tail_error(job_id: str, limit: int = 600) -> str:
    """A short, human reason lifted from the end of a failed job's log, so the UI
    can show what actually went wrong instead of only the word 'failed'."""
    log_path = JOBS_DIR / f"{job_id}.log"
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    for ln in reversed(lines[-40:]):
        low = ln.lower()
        if any(k in low for k in ("error", "traceback", "exception",
                                  "aborted", "fatal", "cannot", "failed")):
            return ln.strip()[:limit]
    return lines[-1][:limit]


def _log_stage_warning(job_id: str) -> str:
    """A finished scan can still have had a tool fail mid-run · the engine marks
    that on its last log line (main.STAGE_ERROR_MARKER). Return a short summary
    when present, so the UI can flag a completed-with-errors run."""
    log_path = JOBS_DIR / f"{job_id}.log"
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    for ln in reversed(text.splitlines()):
        if ln.startswith("##ARGUS_STAGE_ERRORS"):
            body = ln[len("##ARGUS_STAGE_ERRORS"):].strip()
            parts = body.split(" ", 1)
            n = parts[0] if parts else "?"
            detail = parts[1] if len(parts) > 1 else ""
            return (f"{n} stage(s) reported errors · the scan finished with the "
                    f"rest. {detail}").strip()[:600]
    return ""


def _find_scan_after(domain: str, since: float):
    """A saved scan for `domain` written at/after `since`. Used when reconciling
    an orphaned job to tell whether it actually finished before the restart. The
    match is lenient because a subdomain target is saved under its apex (the scan
    pivots scope), so `app.example.com` may land as `example.com_...`."""
    domain = (domain or "").lower()
    try:
        for p in _scan_files():
            if p.stat().st_mtime < since - 2:
                continue
            base = p.name.rsplit("_", 2)[0].lower()   # strip _YYYYmmdd_HHMMSS.json
            if base and (base == domain or domain.endswith("." + base)):
                return p
    except Exception:
        pass
    return None


def _finalize_orphan(job_id: str) -> None:
    """Close out a job whose worker is no longer running after a restart: mark it
    done if its scan landed, otherwise interrupted with a plain reason."""
    job = _JOBS.get(job_id)
    if not job:
        return
    if _find_scan_after(job.get("domain", ""), job.get("started", 0)) is not None:
        job.update(status="done", finished=time.time(),
                   note="finished while the dashboard was restarting")
    else:
        job.update(status="interrupted", finished=time.time(),
                   error="The dashboard restarted while this scan was running, so "
                         "it did not finish. Nothing was saved · start it again.")
    _save_job(job_id)


def _reattach_job(job_id: str, pid: int) -> None:
    """Follow a scan whose worker outlived a dashboard restart. The worker runs in
    its own session (start_new_session), so it survives us · poll until it exits,
    then finalize from whatever it left behind."""
    while _pid_alive(pid):
        time.sleep(2)
    job = _JOBS.get(job_id)
    if job and job.get("status") in _ACTIVE_STATES:
        _finalize_orphan(job_id)


def _load_jobs() -> None:
    """Restore the job table a previous dashboard wrote, then reconcile every job
    that was mid-run when we last stopped: re-attach if its worker is still alive,
    otherwise report it interrupted instead of letting it disappear."""
    try:
        raw = json.loads(_JOBS_FILE.read_text(encoding="utf-8"))
    except Exception:
        raw = []
    now = time.time()
    for job in raw if isinstance(raw, list) else []:
        jid = job.get("id")
        if not jid:
            continue
        st = job.get("status")
        if st in _ACTIVE_STATES:
            _JOBS[jid] = job
            pid = job.get("pid")
            if pid and _pid_alive(pid):
                threading.Thread(target=_reattach_job, args=(jid, pid),
                                 daemon=True).start()
            else:
                _finalize_orphan(jid)
        else:
            done_at = job.get("finished") or job.get("started") or now
            if now - done_at <= _JOBS_KEEP_SEC:
                _JOBS[jid] = job
    if len(_JOBS) > _JOBS_MAX:
        keep = sorted(_JOBS.values(), key=lambda j: j.get("started", 0),
                      reverse=True)[:_JOBS_MAX]
        _JOBS.clear()
        _JOBS.update({j["id"]: j for j in keep})
    _persist_jobs()


# --------------------------------------------------------------------------- #
# Scan discovery
# --------------------------------------------------------------------------- #
def _scan_files() -> list[Path]:
    return sorted(config.SCANS_DIR.glob("*.json"),
                  key=lambda p: p.stat().st_mtime, reverse=True)


# Hidden scans · a soft "remove from Recent Scans" that keeps the scan file on
# disk (still reachable by its id, and un-hideable) rather than deleting it. The
# set is a small JSON file next to the scans.
_HIDDEN_FILE = config.SCANS_DIR / ".hidden.json"
_HIDDEN_LOCK = threading.Lock()


def _load_hidden() -> set[str]:
    try:
        data = json.loads(_HIDDEN_FILE.read_text(encoding="utf-8"))
        return set(data.get("hidden") or [])
    except Exception:
        return set()


def _set_hidden(scan_id: str, hidden: bool) -> None:
    with _HIDDEN_LOCK:
        cur = _load_hidden()
        if hidden:
            cur.add(scan_id)
        else:
            cur.discard(scan_id)
        try:
            tmp = _HIDDEN_FILE.with_suffix(".json.tmp")
            tmp.write_text(json.dumps({"hidden": sorted(cur)}), encoding="utf-8")
            tmp.replace(_HIDDEN_FILE)
        except Exception:
            pass


# A full scan document can be tens of MB. Parsing it on every request (the graph
# builder, a raw-JSON open, and each expanded row all call _load) is what made a
# big scan feel like the dashboard had gone offline. Cache the most-recently-read
# document keyed by (scan_id, mtime); a single entry keeps memory bounded while
# still serving a browsing session's repeated reads from RAM.
_DOC_CACHE: dict = {}


def _scan_path(scan_id: str) -> Path:
    """Validated path to a scan file, or abort. Shared by every reader so the
    id check and the traversal guard live in one place."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists() or path.parent != config.SCANS_DIR:
        abort(404, "scan not found")
    return path


def _is_large(path: Path) -> bool:
    """A scan too big to parse whole into memory · read it off disk instead
    (modules.scan_stream). See config.INMEM_MAX_BYTES."""
    try:
        return config.INMEM_MAX_BYTES > 0 and path.stat().st_size >= config.INMEM_MAX_BYTES
    except OSError:
        return False


def _load(scan_id: str) -> dict:
    path = _scan_path(scan_id)
    mtime = path.stat().st_mtime
    hit = _DOC_CACHE.get(scan_id)
    if hit and hit[0] == mtime:
        return hit[1]
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    # Never pin a huge document in the single-entry cache · one gigabyte-scale
    # scan held in RAM is exactly the pressure this guard exists to avoid. Big
    # scans are served from the streaming readers and the SQLite index instead.
    _DOC_CACHE.clear()          # hold only the most-recently-viewed scan
    if not _is_large(path):
        _DOC_CACHE[scan_id] = (mtime, doc)
    return doc


# Per-endpoint fields the request *table* never shows: response/request bodies,
# the captured DOM, every "found on" URL, and raw headers. They are the bulk of a
# large scan (tens of MB) and are only needed when one row is expanded · served
# then by /api/scan/<id>/endpoint/<eid>. Stripping them from the list view is what
# keeps the scan page loadable when a scan has tens of thousands of endpoints.
_ENDPOINT_HEAVY = ("resp_body", "req_body", "dom", "found_on",
                   "req_headers", "resp_headers", "notes", "js_origin")


def _light_scan(d: dict) -> dict:
    """The scan document with heavy per-endpoint fields removed · everything the
    left panel, the request table, its filters and the graph client need, and
    nothing that only the expanded-row detail uses."""
    out = dict(d)
    out["endpoints"] = [{k: v for k, v in e.items() if k not in _ENDPOINT_HEAVY}
                        for e in d.get("endpoints", [])]
    return out


def _annotate_view(doc: dict, cap: int | None) -> dict:
    """Tell the scan page how much of the endpoint surface it is actually holding.

    The table renders whatever endpoints are in this document; on a huge scan
    that is a capped, highest-priority slice, not the whole crawl. `endpoints_
    total` (the real count, from meta.stats) and `endpoints_capped` let the page
    show "top N of TOTAL" instead of silently implying it has everything."""
    stats = (doc.get("meta") or {}).get("stats") or {}
    shown = len(doc.get("endpoints") or [])
    total = stats.get("endpoints")
    total = int(total) if total is not None else shown
    doc["endpoints_shown"] = shown
    doc["endpoints_total"] = total
    doc["endpoints_capped"] = bool(cap and total > shown)
    return doc


def _light_view(scan_id: str) -> dict:
    """Light document for the scan page, served whole from the SQLite index when
    it is fresh · panel data *and* a table-ready endpoint slice.

    Serving only the endpoints from the store was pointless: the panel came from
    `_load()`, which was called unconditionally, so every view of a 141 MB scan
    still parsed 141 MB of JSON (~20 s and a gigabyte of interpreter heap) before
    it could answer. The store now holds the panel document too, so a hit here
    never opens the file at all.

    The endpoint list is capped to config.VIEW_ENDPOINT_CAP (highest-priority
    first): a deep crawl holds over a million endpoints · ~400 MB of JSON no
    browser can lay out · so the page is served the slice worth showing and told
    the true total, instead of a response that never finishes rendering."""
    path = config.SCANS_DIR / f"{scan_id}.json"
    cap = config.VIEW_ENDPOINT_CAP or None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0
    if mtime:
        cached = store.light_view(scan_id, mtime, limit=cap)
        if cached is not None:
            return _annotate_view(cached, cap)
    # Cache miss (first view of a new scan, or store disabled). A big scan is read
    # off disk with the streaming reader · panel + table-ready endpoints, never the
    # whole file in memory · and the already-light doc is what backfills the index.
    if _is_large(path):
        light = scan_stream.stream_light_doc(path)
        try:
            store.index_scan(scan_id, light, path)
        except Exception:
            pass
        if cap and len(light.get("endpoints") or []) > cap:
            light = dict(light)
            light["endpoints"] = light["endpoints"][:cap]
        return _annotate_view(light, cap)
    # Small scan: parse once, strip inline, and backfill the index so every later
    # view skips the file.
    doc = _load(scan_id)
    light = _light_scan(doc)
    try:
        store.index_scan(scan_id, doc, path)
    except Exception:
        pass
    if cap and len(light.get("endpoints") or []) > cap:
        light = dict(light)
        light["endpoints"] = light["endpoints"][:cap]
    return _annotate_view(light, cap)


# Summaries are read for every scan on the home page. Parsing a multi-MB file
# just to pull `meta` is wasteful, so cache the summary by (scan_id, mtime).
_SUMMARY_CACHE: dict = {}


def _summary(path: Path) -> dict:
    stem = path.stem
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0
    hit = _SUMMARY_CACHE.get(stem)
    if hit and hit[0] == mtime:
        return hit[1]
    # Persistent cache first: the store keeps a summary per scan keyed by mtime,
    # so listing the library survives a server restart without re-parsing every
    # multi-MB file. In-memory cache is still the fastest hop for a live session.
    cached = store.get_summary(stem, mtime) if mtime else None
    if cached is not None:
        _SUMMARY_CACHE[stem] = (mtime, cached)
        return cached
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    # The summary is built from meta alone. For a big scan, stream just that
    # object off disk · the home page listing every scan must never parse a
    # gigabyte-scale file (and every one of them) into memory to draw a card.
    # A full index is deferred to the first time the scan is actually opened.
    if _is_large(path):
        try:
            summary = store.build_summary({"meta": scan_stream.stream_meta(path)},
                                          scan_id=stem, mtime=mtime, size=size)
            _SUMMARY_CACHE[stem] = (mtime, summary)
            return summary
        except Exception:
            return {"scan_id": stem, "domain": stem, "error": True,
                    "stats": {}, "started_at": None}
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return {"scan_id": stem, "domain": stem, "error": True,
                "stats": {}, "started_at": None}
    summary = store.build_summary(d, scan_id=stem, mtime=mtime, size=size)
    _SUMMARY_CACHE[stem] = (mtime, summary)
    # Backfill the store so the next process/request is served from it.
    try:
        store.index_scan(stem, d, path)
    except Exception:
        pass
    return summary


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan/<scan_id>")
def scan_page(scan_id):
    if not SCAN_ID_RE.match(scan_id):
        abort(404)
    _require_scan_access(scan_id)
    return render_template("scan.html", scan_id=scan_id)


@app.route("/login")
def login_page():
    if not auth.configured():
        return redirect(url_for("index"))
    if _claims():                                   # already signed in
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/recon/admin")
def admin_page():
    _require_admin()
    return render_template("admin.html")


# --------------------------------------------------------------------------- #
# Session endpoints
# --------------------------------------------------------------------------- #
def _set_session_cookie(resp, token: str, expires: int):
    resp.set_cookie(
        SESSION_COOKIE, token,
        max_age=max(60, expires - int(time.time())),
        httponly=True,                 # unreadable to any script on the page
        samesite="Lax",                # not sent on a cross-site form post
        secure=request.is_secure,      # https only when we are actually on https
        path=request.script_root or "/",
    )
    return resp


@app.route("/api/auth/state")
def api_auth_state():
    """Whether this dashboard requires a sign-in, and who is signed in. The one
    endpoint reachable without a session, so the client can tell the difference
    between 'open dashboard' and 'you are logged out'."""
    claims = _claims() if auth.configured() else None
    return jsonify({
        "required": auth.configured(),
        "authenticated": bool(claims) or not auth.configured(),
        "user": _session_user(claims),
    })


def _session_user(claims) -> dict | None:
    if not claims:
        return None
    return {"username": claims.get("sub"), "role": claims.get("role"),
            "limits": claims.get("limits") or {}, "csrf": claims.get("csrf"),
            "quota": auth.quota(claims.get("sub"))}


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    if not auth.configured():
        return jsonify({"error": "authentication is not configured"}), 400
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    # A brute-force guard that does not depend on the account existing: the
    # per-account lockout in modules.auth cannot slow down a spray across many
    # usernames from one address, so the address is rate-limited too.
    who = access_log.client_ip(request) or "?"
    if not _login_rate_ok(who):
        return jsonify({"error": "too many sign-in attempts · wait a minute"}), 429
    try:
        user = auth.verify(username, password)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 401
    token, csrf, exp = auth.issue_token(username)
    _login_rate_clear(who)
    resp = make_response(jsonify({"user": {**user, "csrf": csrf},
                                  "expires_at": exp}))
    return _set_session_cookie(resp, token, exp)


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SESSION_COOKIE, path=request.script_root or "/")
    return resp


@app.route("/api/theme", methods=["POST"])
def api_set_theme():
    """Remember the operator's light/dark choice in an httpOnly cookie so the
    server can render every page in it from the first paint, on this device and
    the next. Open and CSRF-free on purpose: a theme is a preference, not a
    privileged action, and it has to work on the login page before any session
    exists. `theme` must be exactly "light" or "dark"; anything else clears it."""
    body = request.get_json(silent=True) or {}
    want = (body.get("theme") or "").strip().lower()
    resp = make_response(jsonify({"theme": want if want in THEME_VALUES else None}))
    if want in THEME_VALUES:
        resp.set_cookie(
            THEME_COOKIE, want,
            max_age=60 * 60 * 24 * 365,    # a year · a preference should stick
            httponly=True,                 # unreadable to any script on the page
            samesite="Lax",
            secure=request.is_secure,
            path=request.script_root or "/",
        )
    else:
        resp.delete_cookie(THEME_COOKIE, path=request.script_root or "/")
    return resp


@app.route("/api/me")
def api_me():
    """The signed-in account, its permissions, its remaining allowance and the
    CSRF value every state-changing call has to echo."""
    claims = current_user()
    if not auth.configured():
        return jsonify({"required": False, "user": None})
    return jsonify({"required": True, "user": _session_user(claims)})


@app.route("/api/me/password", methods=["POST"])
def api_change_own_password():
    """Change your own password · the current one is required, and every session
    token already issued for the account stops working."""
    claims = current_user()
    if not claims:
        abort(401)
    body = request.get_json(silent=True) or {}
    try:
        auth.set_password(claims["sub"], body.get("new_password") or "",
                          current_password=body.get("current_password") or "")
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    token, csrf, exp = auth.issue_token(claims["sub"])
    resp = make_response(jsonify({"ok": True, "csrf": csrf}))
    return _set_session_cookie(resp, token, exp)


# Per-address sign-in throttle. Small, in-memory, and deliberately not a
# dependency: it only has to make a spray expensive.
_LOGIN_HITS: dict[str, list] = {}
_LOGIN_WINDOW = 60.0
_LOGIN_MAX = 10


def _login_rate_ok(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _LOGIN_HITS.get(ip, []) if now - t < _LOGIN_WINDOW]
    hits.append(now)
    _LOGIN_HITS[ip] = hits
    if len(_LOGIN_HITS) > 2000:                      # bound the map
        for key in [k for k, v in _LOGIN_HITS.items()
                    if not v or now - v[-1] > _LOGIN_WINDOW]:
            _LOGIN_HITS.pop(key, None)
    return len(hits) <= _LOGIN_MAX


def _login_rate_clear(ip: str) -> None:
    _LOGIN_HITS.pop(ip, None)


# --------------------------------------------------------------------------- #
# Scan ownership
#
# A scan belongs to the account that started it (the engine stamps meta.owner).
# An operator sees their own runs; an administrator, or an account granted
# "see all", sees every one. Scans from before accounts existed have no owner
# and are treated the same way · visible to whoever can see everything.
# --------------------------------------------------------------------------- #
def _owner_of(scan_id: str) -> str | None:
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    return (_summary(path) or {}).get("owner")


def _require_scan_access(scan_id: str) -> None:
    if not auth.configured():
        return
    if not auth.may_see(current_user(), _owner_of(scan_id)):
        abort(403, "this scan belongs to another account")


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/scans")
def api_scans():
    show_all = request.args.get("all") in ("1", "true", "yes", "on")
    hidden = _load_hidden()
    user = current_user() if auth.configured() else None
    out = []
    for r in (_summary(p) for p in _scan_files()):
        sid = r.get("scan_id")
        is_hidden = sid in hidden
        if is_hidden and not show_all:
            continue
        if is_hidden:
            r["hidden"] = True
        if user is not None and not auth.may_see(user, r.get("owner")):
            continue
        out.append(r)
    return jsonify(out)


@app.route("/api/scan/<scan_id>/hide", methods=["POST"])
def api_scan_hide(scan_id):
    """Soft-remove a scan from Recent Scans without deleting it (or restore it
    with {"hidden": false}). The scan file stays on disk and reachable by id."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    _require_scan_access(scan_id)
    if not _may("delete"):
        return jsonify({"error": "your account cannot manage scans"}), 403
    body = request.get_json(silent=True) or {}
    hide = bool(body.get("hidden", True))
    _set_hidden(scan_id, hide)
    _SUMMARY_CACHE.pop(scan_id, None)
    return jsonify({"scan_id": scan_id, "hidden": hide})


@app.route("/api/scan/<scan_id>")
def api_scan(scan_id):
    # The full document (raw-JSON link, downloads, backward compatibility). The
    # scan UI uses /view instead so it never pulls the heavy per-endpoint fields.
    _require_scan_access(scan_id)
    path = _scan_path(scan_id)
    # Stream the file straight off disk · the bytes are already valid JSON, so
    # parsing a multi-hundred-megabyte document into the heap and re-serialising
    # it just to hand it back is pure memory pressure (and, on a gigabyte scan,
    # the 502 this whole change exists to stop). send_file streams in chunks and
    # marks the response direct-passthrough, so _compress leaves it alone.
    return send_file(path, mimetype="application/json", conditional=True,
                     last_modified=path.stat().st_mtime,
                     download_name=f"{scan_id}.json")


@app.route("/api/scan/<scan_id>/view")
def api_scan_view(scan_id):
    """Light document for the scan page: panel data plus table-ready endpoints,
    without response bodies / DOM / headers. This is what makes a huge scan open.
    The endpoint list is served from the SQLite index when it is fresh."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    _require_scan_access(scan_id)
    return jsonify(_light_view(scan_id))


@app.route("/api/scan/<scan_id>/endpoint/<eid>")
def api_scan_endpoint(scan_id, eid):
    """Full record for one endpoint (bodies, headers, found-on, JS origin),
    fetched only when a row is expanded."""
    if not re.match(r"^[A-Fa-f0-9]{6,40}$", eid):
        abort(400, "bad endpoint id")
    _require_scan_access(scan_id)
    path = _scan_path(scan_id)
    # A big scan holds tens of thousands of endpoints · stream the array to find
    # the one row that was expanded rather than parsing the whole file for it.
    if _is_large(path):
        ep = scan_stream.find_endpoint(path, eid)
        if ep is not None:
            return jsonify(ep)
        abort(404, "endpoint not found")
    for e in _load(scan_id).get("endpoints", []):
        if e.get("id") == eid:
            return jsonify(e)
    abort(404, "endpoint not found")


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def api_scan_delete(scan_id):
    """Delete a saved scan (from the home library). Path-traversal guarded."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    _require_scan_access(scan_id)
    if not _may("delete"):
        return jsonify({"error": "your account cannot delete scans"}), 403
    path = config.SCANS_DIR / f"{scan_id}.json"
    if path.parent != config.SCANS_DIR or not path.exists():
        abort(404, "scan not found")
    try:
        path.unlink()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    # best-effort: also drop the matching subgraph and the SQLite cache rows
    try:
        graph_loader.delete_scan(scan_id)
    except Exception:
        pass
    try:
        store.forget(scan_id)
    except Exception:
        pass
    # Temporary files · the built graph caches for this scan (keyed by mtime).
    try:
        for gz in config.GRAPHCACHE_DIR.glob(f"{scan_id}.*.json.gz"):
            gz.unlink(missing_ok=True)
    except Exception:
        pass
    # Related logs · only when explicitly asked (?logs=1): the streamed job log
    # and its record for whichever job produced this scan.
    purged_logs = 0
    if request.args.get("logs") in ("1", "true", "yes", "on"):
        try:
            with _JOBS_LOCK:
                for jid, job in list(_JOBS.items()):
                    if job.get("scan_id") == scan_id:
                        (JOBS_DIR / f"{jid}.log").unlink(missing_ok=True)
                        _JOBS.pop(jid, None)
                        purged_logs += 1
            if purged_logs:
                _persist_jobs()
        except Exception:
            pass
    _SUMMARY_CACHE.pop(scan_id, None)
    _set_hidden(scan_id, False)     # a deleted scan is no longer merely hidden
    return jsonify({"deleted": scan_id, "logs_purged": purged_logs})


# --------------------------------------------------------------------------- #
# Graph
#
# Building a graph for a big scan is slow in a way no HTTP client will wait
# through: with no graph DB loaded it means parsing a multi-hundred-megabyte
# JSON document and walking every endpoint. Held open long enough, a proxy in
# front gives up and answers 504/524 · which is what "Graph unavailable 524"
# was: the dashboard faithfully reporting that the reverse proxy had timed out
# on a request the server was still working on.
#
# So the build is not done inside the request any more. The first call starts it
# on a worker and waits a few seconds in case it is quick; if it is not, the
# request returns 202 "building" straight away and the client polls. The result
# is cached against the file's mtime, so every later view of that scan is served
# from memory instantly.
# --------------------------------------------------------------------------- #
_GRAPH_BUILDS: dict[tuple, dict] = {}
_GRAPH_BUILD_LOCK = threading.Lock()
_GRAPH_DONE: dict[tuple, dict] = {}        # key -> built payload (bounded)
_GRAPH_DONE_MAX = 3
# How long a request will wait for a fresh build before handing the client a
# "building" answer to poll on. Comfortably under any proxy's read timeout.
_GRAPH_SYNC_WAIT = 8.0


def _graph_key(scan_id: str, max_nodes: int) -> tuple:
    try:
        mtime = (config.SCANS_DIR / f"{scan_id}.json").stat().st_mtime
    except OSError:
        mtime = 0.0
    return (scan_id, mtime, max_nodes)


# Built graph payloads are also cached on disk (keyed by the scan file's mtime)
# so the one-off cost of building a huge scan's graph · tens of seconds of
# streaming · is paid once and survives a restart. The in-memory _GRAPH_DONE
# above serves repeat views inside one process; this serves the first view after
# a restart, and the JSON-built graph for a scan with no graph DB behind it.
def _graph_cache_file(scan_id: str, max_nodes: int) -> Path:
    try:
        mtime = int((config.SCANS_DIR / f"{scan_id}.json").stat().st_mtime)
    except OSError:
        mtime = 0
    return config.GRAPHCACHE_DIR / f"{scan_id}.{mtime}.{max_nodes}.json.gz"


def _graph_cache_read(scan_id: str, max_nodes: int) -> dict | None:
    f = _graph_cache_file(scan_id, max_nodes)
    try:
        with _gzip.open(f, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _graph_cache_write(scan_id: str, max_nodes: int, payload: dict) -> None:
    try:
        config.GRAPHCACHE_DIR.mkdir(parents=True, exist_ok=True)
        f = _graph_cache_file(scan_id, max_nodes)
        tmp = f.with_suffix(".tmp")
        with _gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh)
        tmp.replace(f)
        # Drop stale builds for this scan (older mtimes / other budgets).
        for old in config.GRAPHCACHE_DIR.glob(f"{scan_id}.*.json.gz"):
            if old != f:
                old.unlink(missing_ok=True)
    except Exception:
        pass


def _graph_from_store(scan_id: str, path: Path, max_nodes: int,
                      max_edges: int) -> dict | None:
    """Build the graph entirely from the SQLite index · the complete shell
    (panel) plus the top-`max_nodes` endpoints by rank · so even a gigabyte scan
    is served without opening the file. None if the store has not indexed it.

    This is the whole reason a huge scan's graph now loads: the store already
    holds a light, ranked copy of every endpoint, so choosing the few thousand
    the view renders is an indexed `LIMIT`, not a walk over a million-record,
    gigabyte JSON array."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    panel = store.get_panel(scan_id, mtime)
    if panel is None:
        return None
    eps = store.light_endpoints(scan_id, mtime, limit=max_nodes)
    if eps is None:
        return None
    return graph_loader.graph_from_endpoints(panel, eps, max_nodes=max_nodes,
                                             max_edges=max_edges)


def _build_graph_payload(scan_id: str, max_nodes: int, max_edges: int,
                         want_json: bool) -> dict:
    """The actual work · graph DB first, then the store, then the file."""
    path = config.SCANS_DIR / f"{scan_id}.json"
    large = _is_large(path)
    # A small scan loaded into a graph DB is authoritative and fast, so use it.
    # A large scan is deliberately NOT loaded into the DB (it is what OOM'd the
    # worker · see _drain_graph_queue), and any partial rows a past failed load
    # left behind would misreport its size · so a large scan's graph always comes
    # from the store/JSON path, which reads its true totals from meta.
    if not want_json and not large:
        g = graph_loader.fetch_graph(scan_id, max_nodes=max_nodes,
                                     max_edges=max_edges)
        if g:
            return g
    # A JSON-built graph depends only on the file and the node budget, so a build
    # from a previous request/boot is reusable · check the on-disk cache first.
    cached = _graph_cache_read(scan_id, max_nodes)
    if cached is not None:
        return cached
    if large:
        # Big scan · never load it whole. The store holds a ranked, light copy of
        # every endpoint, so the graph is the complete shell plus the top-max_nodes
        # endpoints by rank · an indexed LIMIT, not a walk over a gigabyte. (The
        # light copy drops per-endpoint `found_on`, so the page→endpoint edges are
        # not drawn; at a 6k-node budget over a million endpoints almost none of
        # those pages are in view anyway.) Store miss falls back to a bounded read.
        g = _graph_from_store(scan_id, path, max_nodes, max_edges)
        if g is None:
            try:
                panel = store.get_panel(scan_id, path.stat().st_mtime)
            except Exception:
                panel = None
            g = graph_loader.graph_from_scan_streaming(
                path, max_nodes=max_nodes, max_edges=max_edges, panel=panel)
    else:
        # Small scan · build from the whole document so the graph keeps every edge
        # (found_on page links included). This is unchanged from before and fast.
        g = graph_loader.graph_from_scan(_load(scan_id), max_nodes=max_nodes,
                                         max_edges=max_edges)
    g["source"] = "json"
    _graph_cache_write(scan_id, max_nodes, g)
    return g


def _graph_worker(key: tuple, scan_id: str, max_nodes: int, max_edges: int,
                  want_json: bool) -> None:
    job = _GRAPH_BUILDS[key]
    try:
        payload = _build_graph_payload(scan_id, max_nodes, max_edges, want_json)
        job.update(status="done", result=payload, finished=time.time())
        with _GRAPH_BUILD_LOCK:
            _GRAPH_DONE[key] = payload
            while len(_GRAPH_DONE) > _GRAPH_DONE_MAX:
                _GRAPH_DONE.pop(next(iter(_GRAPH_DONE)))
    except Exception as exc:
        job.update(status="error", error=str(exc)[:300], finished=time.time())
    finally:
        job["event"].set()


@app.route("/api/scan/<scan_id>/graph")
def api_graph(scan_id):
    """The scan's graph, bounded by a node/edge budget.

    Two things this deliberately does not do. It does not parse the scan JSON to
    ask the graph backend for a graph · the backend is keyed by scan_id, which is
    already in the URL, so the old `_load()` here was a multi-hundred-megabyte
    parse to recover a string we were handed. And it does not return the full
    stored graph: a large crawl is ~67k nodes / ~218k edges, which is a 30 MB
    response the browser cannot lay out, so the page renders nothing at all.
    ?limit=N raises the node budget for a caller that really wants more.

    202 with {"status": "building"} means the build is under way · poll the same
    URL. See the block comment above.
    """
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists():
        abort(404, "scan not found")
    _require_scan_access(scan_id)

    max_nodes = config.GRAPH_VIEW_NODES
    raw = request.args.get("limit")
    if raw:
        try:
            max_nodes = max(200, min(int(raw), config.GRAPH_VIEW_MAX))
        except ValueError:
            pass
    max_edges = max(config.GRAPH_VIEW_EDGES, max_nodes * 2)
    want_json = request.args.get("source") == "json"
    key = _graph_key(scan_id, max_nodes) + (want_json,)

    with _GRAPH_BUILD_LOCK:
        cached = _GRAPH_DONE.get(key)
        if cached is not None:
            return jsonify(cached)
        job = _GRAPH_BUILDS.get(key)
        if job is None or job["status"] == "error":
            job = {"status": "building", "started": time.time(),
                   "event": threading.Event(), "result": None, "error": None}
            _GRAPH_BUILDS[key] = job
            threading.Thread(target=_graph_worker,
                             args=(key, scan_id, max_nodes, max_edges, want_json),
                             daemon=True).start()

    # Wait briefly: a small scan finishes here and the client never learns there
    # was a queue at all.
    job["event"].wait(_GRAPH_SYNC_WAIT)
    if job["status"] == "done":
        _GRAPH_BUILDS.pop(key, None)
        return jsonify(job["result"])
    if job["status"] == "error":
        _GRAPH_BUILDS.pop(key, None)
        return jsonify({"error": job["error"] or "graph build failed"}), 500
    return jsonify({"status": "building",
                    "elapsed_sec": round(time.time() - job["started"], 1),
                    "scan_id": scan_id,
                    "note": "This scan is large · the graph is being built. "
                            "The page keeps checking."}), 202


SERVICE_UNIT = "argus-recon"
STARTED_AT = time.time()


def _git_rev() -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=3)
        return out.stdout.strip() or None
    except Exception:
        return None


# /api/status is polled by the home page, so the shell-outs behind it are cached.
# A slow status response used to let the first-run key prompt race ahead of it.
_SVC_CACHE: dict = {"at": 0.0, "value": None}
_SVC_TTL = 15.0


def _service_state() -> dict:
    """Is this process supervised by the argus-recon user unit? Answering from
    inside the server is what lets the dashboard say 'Live' honestly."""
    now = time.time()
    if _SVC_CACHE["value"] is not None and now - _SVC_CACHE["at"] < _SVC_TTL:
        return _SVC_CACHE["value"]
    managed, enabled = False, False
    try:
        r = subprocess.run(["systemctl", "--user", "is-active", f"{SERVICE_UNIT}.service"],
                           capture_output=True, text=True, timeout=3)
        managed = r.stdout.strip() == "active"
        r = subprocess.run(["systemctl", "--user", "is-enabled", f"{SERVICE_UNIT}.service"],
                           capture_output=True, text=True, timeout=3)
        enabled = r.stdout.strip() in ("enabled", "enabled-runtime", "static")
    except Exception:
        pass
    state = {"unit": SERVICE_UNIT, "managed": managed, "enabled": enabled,
             "version": _git_rev()}
    _SVC_CACHE.update(at=now, value=state)
    return state


@app.route("/api/status")
def api_status():
    # No tool names are exposed here · the dashboard only needs to know whether
    # deep DNS is unlocked and whether the graph DB is live. Engine readiness is
    # a single anonymous flag (the real toolchain is documented in the README).
    engines_ready = all([
        resolve_tool(config.BBOT_BIN), resolve_tool(config.WHATWEB_BIN),
        resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN),
    ])
    # Per-tool presence, so the launcher can lock a tool it cannot run rather than
    # letting the scan fail at that stage. A false here means "not installed".
    tools = {
        "bbot": bool(resolve_tool(config.BBOT_BIN)),
        "httpx": bool(resolve_tool(config.HTTPX_BIN)),
        "whatweb": bool(resolve_tool(config.WHATWEB_BIN)),
        "katana": bool(resolve_tool(config.KATANA_BIN)),
        "ffuf": bool(resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN)),
        "nmap": portscan.available(),
        "wayback_engine": bool(wayback.binary()),
        "securitytrails": bool(config.SECURITYTRAILS_KEY),
        "ipinfo": bool(config.IPINFO_TOKEN),
    }
    svc = _service_state()
    graph = _graph_status()
    return jsonify({
        "deep_available": bool(config.SECURITYTRAILS_KEY),
        "graph_db": graph["available"],
        "graph": graph,
        "engines_ready": engines_ready,
        "tools": tools,
        "ipinfo_token": bool(config.IPINFO_TOKEN),
        # can a scan actually be routed over Tor from this machine? The launcher
        # locks the toggle rather than letting a run fail at the first step.
        "tor": tor.availability(),
        # is the port-scan engine installed? (gates the "port scan" toggle)
        "portscan_available": portscan.available(),
        # the web-archive pass always has a path that works (the index over HTTP
        # when the engine is absent), so the toggle is never locked · but say
        # which one it will use.
        "wayback_available": wayback.available(),
        "wayback_engine": bool(wayback.binary()),
        "service": {**svc, "uptime_sec": round(time.time() - STARTED_AT),
                    "url": f"http://{config.WEB_HOST}:{config.WEB_PORT}"},
        # who is asking, and what they are allowed to do
        "auth": {"required": auth.configured(),
                 "user": _session_user(current_user())},
        # the launcher form shows these as the real defaults rather than inventing numbers
        "defaults": {"max_pages": config.CRAWL_MAX_PAGES,
                     "max_depth": config.CRAWL_MAX_DEPTH,
                     "modules": SCAN_MODULES},
    })


@app.route("/api/config/key/check")
def api_key_check():
    """Where the deep-DNS key stands before a scan commits to using it · so an
    exhausted allowance is a question asked up front rather than a stage that
    quietly returns nothing after several minutes."""
    return jsonify(securitytrails.check(force=request.args.get("force") == "1"))


# Graph-backend state is also polled repeatedly (status + the graph view) and a
# neo4j ping is a socket round-trip, so cache it like the service state.
_GRAPH_CACHE: dict = {"at": 0.0, "value": None}
_GRAPH_TTL = 12.0


def _graph_status() -> dict:
    now = time.time()
    if _GRAPH_CACHE["value"] is not None and now - _GRAPH_CACHE["at"] < _GRAPH_TTL:
        return _GRAPH_CACHE["value"]
    try:
        st = graph_loader.backend_status()
    except Exception:
        st = {"available": False, "backend": "none"}
    st["queued"] = store.queue_depth()
    _GRAPH_CACHE.update(at=now, value=st)
    return st


# --------------------------------------------------------------------------- #
# Graph-load queue drain
#
# A scan finishes whether or not a graph backend was up. Those that could not be
# loaded are queued (modules.store); this worker retries them once a backend is
# reachable, so the graph catches up on its own instead of the load being lost.
# --------------------------------------------------------------------------- #
def _drain_graph_queue():
    while True:
        try:
            pending = store.pending_graph()
            if pending and graph_loader.active_backend() != "none":
                for job in pending:
                    sid = job["scan_id"]
                    path = config.SCANS_DIR / f"{sid}.json"
                    if not path.exists():
                        store.dequeue_graph(sid)      # scan was deleted
                        continue
                    if _is_large(path):
                        # A gigabyte crawl is not worth pushing into the embedded
                        # graph DB · loading a million endpoints is exactly what
                        # OOM'd this worker and pinned a core retrying forever. The
                        # dashboard graph for a large scan is served fast from the
                        # store/JSON path anyway, so drop it from the queue instead
                        # of loading it.
                        store.dequeue_graph(sid)
                        continue
                    try:
                        # Only small scans reach here (large ones were dequeued
                        # above): parse and load the whole document.
                        with open(path, encoding="utf-8") as fh:
                            doc = json.load(fh)
                        ok = graph_loader.load(doc)
                        if ok:
                            store.dequeue_graph(sid)
                            _GRAPH_CACHE["value"] = None
                        else:
                            store.mark_attempt(sid, "load returned false")
                    except Exception as exc:
                        store.mark_attempt(sid, str(exc)[:200])
        except Exception:
            pass
        time.sleep(20)


def _start_graph_worker():
    t = threading.Thread(target=_drain_graph_queue, daemon=True)
    t.start()


@app.route("/api/config/key", methods=["POST"])
def api_set_key():
    """First-run / settings: set the deep-DNS key. Blank clears it.

    `persist` (default true) writes it to .env so it survives a restart. Sending
    false keeps it in this running dashboard only · which is what you want for a
    borrowed key you are using to finish one job, and the reason the exhausted-
    quota prompt can offer "use this key for now" without committing it to disk.
    """
    if not _may("deep"):
        return jsonify({"error": "your account cannot change the deep-DNS key"}), 403
    body = request.get_json(silent=True) or {}
    key = (body.get("key") or "").strip()
    if len(key) > 200:
        return jsonify({"error": "that does not look like an API key"}), 400
    persist = body.get("persist", True)
    if persist:
        config.save_env_key("SECURITYTRAILS_KEY", key)
    config.SECURITYTRAILS_KEY = key
    securitytrails.forget_usage()
    out = {"deep_available": bool(key), "persisted": bool(persist)}
    if key and body.get("check", True):
        out["quota"] = securitytrails.check(force=True)
    return jsonify(out)


# --------------------------------------------------------------------------- #
# Optional: launch a scan from the dashboard
# --------------------------------------------------------------------------- #
def _run_job(job_id: str, domain: str, extra: list[str], owner: str | None = None):
    log_path = JOBS_DIR / f"{job_id}.log"
    py = sys.executable
    cmd = [py, str(ROOT / "main.py"), domain, *extra]
    _JOBS[job_id].update(status="running", cmd=" ".join(cmd))
    _save_job(job_id)
    # The engine refuses to run from a terminal; this flag marks it as ours.
    # Its own process group lets "stop" take the whole tool subtree with it.
    # ARGUS_OWNER is stamped into the scan document so the library can show an
    # operator their own runs (see modules.auth.may_see).
    env = {**os.environ, "ARGUS_INTERNAL": "1", "PYTHONUNBUFFERED": "1"}
    if owner:
        env["ARGUS_OWNER"] = owner
    with open(log_path, "w", encoding="utf-8") as log:
        try:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=str(ROOT), env=env, start_new_session=True)
            _JOBS[job_id]["pid"] = proc.pid
            _save_job(job_id)
            rc = proc.wait()
            if _JOBS[job_id].get("status") == "stopping":
                _JOBS[job_id].update(status="stopped", returncode=rc,
                                     finished=time.time())
            elif rc == 0:
                # Done, but a tool may have failed mid-run · surface that as a
                # warning on the finished job rather than a silent success.
                warn = _log_stage_warning(job_id)
                fields = {"status": "done", "returncode": rc,
                          "finished": time.time()}
                if warn:
                    fields["warning"] = warn
                _JOBS[job_id].update(fields)
            else:
                # A non-zero exit, or a negative code (killed by a signal). Name
                # the signal honestly · SIGKILL is the out-of-memory killer, while
                # SIGTERM is a polite stop (a dashboard restart or a shutdown), not
                # a crash. Lift the real reason out of the log for ordinary exits,
                # so it reaches the UI as an alert instead of only the terminal.
                if rc == -9:
                    reason = ("The scan was killed (SIGKILL) · the machine ran out "
                              "of memory. Endpoints now spill to disk, so retry it; "
                              "if it recurs, lower the page cap or drop a stage.")
                elif rc == -15:
                    reason = ("The scan was stopped by the system (SIGTERM), usually "
                              "a dashboard restart or shutdown rather than a crash. "
                              "The service now keeps scans running across restarts, "
                              "so starting it again should hold.")
                elif rc < 0:
                    reason = (f"The scan was killed by signal {-rc}. "
                              + (_log_tail_error(job_id) or "")).strip()
                else:
                    reason = _log_tail_error(job_id) or f"The scan exited with code {rc}."
                _JOBS[job_id].update(status="failed", returncode=rc,
                                     error=reason, finished=time.time())
        except Exception as exc:
            _JOBS[job_id].update(status="failed",
                                 error=f"Could not start the scan: {exc}",
                                 finished=time.time())
    _save_job(job_id)


# Pipeline stages the dashboard can switch off (mirrors main.ALL_MODULES).
SCAN_MODULES = ["subdomain", "fingerprint", "http_analysis", "tls", "crawl",
                "bruteforce", "bypass", "paramscan", "ip_enrich", "shodan",
                "classify", "graph"]


@app.route("/api/scan", methods=["POST"])
def api_launch():
    """Start a scan. This is the only way to start one · the engine refuses to
    run from a terminal · so every pipeline option is reachable from here."""
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", domain):
        return jsonify({"error": "invalid domain"}), 400
    if any(j["domain"] == domain and j["status"] in ("queued", "running")
           for j in _JOBS.values()):
        return jsonify({"error": f"a scan of {domain} is already running"}), 409

    single = bool(body.get("single"))
    want_tor = bool(body.get("tor"))
    if want_tor and not tor.availability()["available"]:
        return jsonify({"error": "Tor is not available on this machine · install "
                                 "tor (and the Python SOCKS dependency) first"}), 400
    want_portscan = bool(body.get("portscan"))
    if want_portscan and body.get("passive"):
        return jsonify({"error": "a port scan is an active probe · it cannot run in "
                                 "a passive scan"}), 400
    if want_portscan and not portscan.available():
        return jsonify({"error": "the port-scan engine is not installed on this "
                                 "machine · run ./install.sh to add it"}), 400
    want_wayback = bool(body.get("wayback"))
    want_xss = bool(body.get("xss"))
    want_sqli = bool(body.get("sqli"))
    want_nuclei = bool(body.get("nuclei"))
    # The active vulnerability scanners are intrusive: they cannot run in a
    # passive scan, and each needs its engine installed.
    for label, want, mod in (("XSS", want_xss, xss_scan),
                             ("SQL injection", want_sqli, sqli_scan),
                             ("Nuclei", want_nuclei, nuclei_scan)):
        if want and body.get("passive"):
            return jsonify({"error": f"{label} testing is an active probe · it "
                                     "cannot run in a passive scan"}), 400
        if want and not mod.available():
            return jsonify({"error": f"the {label} engine is not installed on this "
                                     "machine · run ./install.sh to add it"}), 400

    # Allowance: daily scans, how many at once, and which of the heavier options
    # this account may reach for at all.
    user = current_user()
    owner = user.get("sub") if user else None
    if auth.configured() and owner:
        running = sum(1 for j in _JOBS.values()
                      if j.get("owner") == owner and j["status"] in ("queued", "running"))
        try:
            auth.check_scan_allowed(owner, running=running, options={
                "portscan": want_portscan, "tor": want_tor,
                "wayback": want_wayback, "deep": bool(body.get("deep")),
                "xss": want_xss, "sqli": want_sqli, "nuclei": want_nuclei})
        except auth.AuthError as exc:
            return jsonify({"error": str(exc), "quota": auth.quota(owner)}), 429

    extra: list[str] = ["--no-prompt"]   # background job: never block on stdin
    if body.get("passive"):
        extra.append("--passive")
    if body.get("deep") and config.SECURITYTRAILS_KEY:
        extra.append("--deep")
    if single:
        extra.append("--single")         # implies exact scope in the engine
    elif body.get("exact_scope"):
        extra.append("--exact-scope")
    if want_tor:
        extra.append("--tor")
    if want_portscan:
        extra.append("--portscan")
    if want_wayback:
        extra.append("--wayback")
    if want_xss:
        extra.append("--xss")
    if want_sqli:
        extra.append("--sqli")
    if want_nuclei:
        extra.append("--nuclei")
    if body.get("no_bbot"):
        extra.append("--no-bbot")
    if body.get("no_probe"):
        extra.append("--no-probe")
    if body.get("no_deepcrawl"):
        extra.append("--no-deepcrawl")
    if body.get("no_graph"):
        extra.append("--no-graph")
    for key, flag in (("max_pages", "--max-pages"), ("max_depth", "--max-depth")):
        if body.get(key):
            try:
                val = int(body[key])
            except (TypeError, ValueError):
                return jsonify({"error": f"{key} must be a number"}), 400
            if not 1 <= val <= 100_000:
                return jsonify({"error": f"{key} out of range"}), 400
            extra += [flag, str(val)]
    skip = [m for m in (body.get("skip") or []) if m in SCAN_MODULES]
    if skip:
        extra += ["--skip", ",".join(skip)]

    # Tools switched off that are not one of the pipeline stages · shown on the
    # job row so a trimmed-down run is never a mystery after the fact.
    off_tools = []
    if body.get("no_bbot"):
        off_tools.append("no BBOT")
    if body.get("no_probe"):
        off_tools.append("no httpx probe")
    if body.get("no_deepcrawl"):
        off_tools.append("no katana")

    job_id = uuid.uuid4().hex[:12]
    _JOBS[job_id] = {"id": job_id, "domain": domain, "status": "queued",
                     "started": time.time(), "owner": owner, "options": {
                         "passive": bool(body.get("passive")),
                         "deep": bool(body.get("deep") and config.SECURITYTRAILS_KEY),
                         "exact_scope": bool(body.get("exact_scope")) and not single,
                         "single": single,
                         "tor": want_tor,
                         "portscan": want_portscan,
                         "wayback": want_wayback,
                         "no_bbot": bool(body.get("no_bbot")),
                         "no_probe": bool(body.get("no_probe")),
                         "no_deepcrawl": bool(body.get("no_deepcrawl")),
                         "off_tools": off_tools,
                         "skipped": skip + (["graph"] if body.get("no_graph") and "graph" not in skip else []),
                     }}
    _save_job(job_id)
    if auth.configured() and owner:
        auth.record_scan(owner)
    threading.Thread(target=_run_job, args=(job_id, domain, extra, owner),
                     daemon=True).start()
    return jsonify({"job_id": job_id, "domain": domain,
                    "quota": auth.quota(owner) if (auth.configured() and owner) else None})


@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def api_job_stop(job_id):
    """Cancel a running scan. Without a terminal there is nothing else to Ctrl-C,
    so the UI needs this. Signals the whole process group (the engine plus any
    external tool it is currently running)."""
    if not SCAN_ID_RE.match(job_id):
        abort(400)
    job = _JOBS.get(job_id)
    if not job:
        abort(404, "unknown job")
    if not _may_see_job(job):
        abort(403, "this scan belongs to another account")
    if job["status"] not in ("queued", "running"):
        return jsonify({"job": job, "note": "not running"})
    pid = job.get("pid")
    if not pid:
        job.update(status="stopped", finished=time.time())
        _save_job(job_id)
        return jsonify({"job": job})
    job["status"] = "stopping"
    _save_job(job_id)
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        job.update(status="stopped", finished=time.time())
        _save_job(job_id)
        return jsonify({"job": job})

    def _hard_kill():
        time.sleep(6)
        if _JOBS.get(job_id, {}).get("status") == "stopping":
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                pass
    threading.Thread(target=_hard_kill, daemon=True).start()
    return jsonify({"job": job})


def _may_see_job(job: dict) -> bool:
    """A running scan is visible on the same terms as a finished one."""
    if not auth.configured():
        return True
    return auth.may_see(current_user(), job.get("owner"))


@app.route("/api/jobs")
def api_jobs():
    jobs = [j for j in _JOBS.values() if _may_see_job(j)]
    return jsonify(sorted(jobs, key=lambda j: j.get("started", 0), reverse=True))


@app.route("/api/jobs/<job_id>/log")
def api_job_log(job_id):
    if not SCAN_ID_RE.match(job_id):
        abort(400)
    job = _JOBS.get(job_id)
    if job and not _may_see_job(job):
        abort(403, "this scan belongs to another account")
    log_path = JOBS_DIR / f"{job_id}.log"
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    # strip ANSI colour codes for the browser
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return jsonify({"job": _JOBS.get(job_id, {}), "log": text[-16000:]})


@app.route("/api/version")
def api_version():
    """The current UI build token. Polled by web/static/js/version.js: when it
    changes under an open tab the client reloads once, pulling the new assets
    through their freshly-versioned URLs."""
    return jsonify({"version": asset_version()})


# --------------------------------------------------------------------------- #
# Admin API
#
# Every route here goes through _require_admin() first, so a non-admin session
# gets 403 no matter which one it reaches for, and an unauthenticated one never
# gets past the gate at all. Nothing in the responses carries a password hash or
# the signing secret · modules.auth only ever hands out the public view.
# --------------------------------------------------------------------------- #
@app.route("/api/admin/users")
def api_admin_users():
    _require_admin()
    return jsonify({"users": auth.list_users(),
                    "defaults": auth.DEFAULT_LIMITS})


@app.route("/api/admin/users", methods=["POST"])
def api_admin_create_user():
    me = _require_admin()
    body = request.get_json(silent=True) or {}
    try:
        user = auth.create_user(
            body.get("username") or "", body.get("password") or "",
            role=(body.get("role") or "user"),
            limits=body.get("limits") or {}, by=me.get("sub", "admin"))
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": user}), 201


@app.route("/api/admin/users/<username>", methods=["POST"])
def api_admin_update_user(username):
    me = _require_admin()
    body = request.get_json(silent=True) or {}
    # An admin demoting or disabling themselves would lock the door with the key
    # inside. The store also refuses to strip the last admin, but saying it here
    # gives a message that names what actually happened.
    if username == me.get("sub") and (body.get("role") == "user"
                                      or body.get("enabled") is False):
        return jsonify({"error": "you cannot demote or disable your own account"}), 400
    try:
        user = auth.update_user(
            username,
            role=body.get("role"),
            enabled=body.get("enabled"),
            limits=body.get("limits"),
            unlock=bool(body.get("unlock")))
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": user})


@app.route("/api/admin/users/<username>/password", methods=["POST"])
def api_admin_set_password(username):
    me = _require_admin()
    body = request.get_json(silent=True) or {}
    # Changing your own password still requires the current one, even as admin.
    current = body.get("current_password") if username == me.get("sub") else None
    try:
        auth.set_password(username, body.get("new_password") or "",
                          current_password=current)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    if username == me.get("sub"):
        token, csrf, exp = auth.issue_token(username)
        resp = make_response(jsonify({"ok": True, "csrf": csrf}))
        return _set_session_cookie(resp, token, exp)
    return jsonify({"ok": True})


@app.route("/api/admin/users/<username>", methods=["DELETE"])
def api_admin_delete_user(username):
    me = _require_admin()
    if username == me.get("sub"):
        return jsonify({"error": "you cannot delete your own account"}), 400
    try:
        auth.delete_user(username)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"deleted": username})


@app.route("/api/admin/access")
def api_admin_access():
    _require_admin()
    try:
        limit = max(1, min(2000, int(request.args.get("limit", 300))))
    except ValueError:
        limit = 300
    day = request.args.get("day") or None
    if day and not re.match(r"^\d{4}-\d{2}-\d{2}$", day):
        abort(400, "bad day")
    return jsonify({
        "days": access_log.days(),
        "records": access_log.read(day=day, limit=limit,
                                   user=request.args.get("user") or None,
                                   q=request.args.get("q") or None),
        "summary": access_log.summary(),
        "enabled": access_log.ENABLED,
    })


@app.route("/api/admin/overview")
def api_admin_overview():
    _require_admin()
    scans = [_summary(p) for p in _scan_files()]
    per_owner: dict[str, int] = {}
    for s in scans:
        per_owner[s.get("owner") or "unassigned"] = \
            per_owner.get(s.get("owner") or "unassigned", 0) + 1
    active = [j for j in _JOBS.values() if j["status"] in ("queued", "running")]
    return jsonify({
        "users": len(auth.list_users()),
        "scans": len(scans),
        "scans_by_owner": per_owner,
        "running": [{"id": j["id"], "domain": j["domain"], "owner": j.get("owner"),
                     "status": j["status"], "started": j.get("started")}
                    for j in active],
        "recent_scans": [{"scan_id": s["scan_id"], "domain": s["domain"],
                          "owner": s.get("owner"), "started_at": s.get("started_at"),
                          "size": s.get("size")} for s in scans[:12]],
        "key_file": str(auth.store_path()),
        "access_log": access_log.ENABLED,
    })


# --------------------------------------------------------------------------- #
# Integrations · the external API keys the pipeline can be given. Each is stored
# in .env (config.save_env_key, survives a restart) and mirrored onto the live
# config object so it takes effect without one. The admin page lists and sets
# them; the value itself is never sent back to a browser · only whether one is
# present. Add a service here and it shows up in the admin page automatically.
# --------------------------------------------------------------------------- #
INTEGRATIONS = [
    {"id": "securitytrails", "env": "SECURITYTRAILS_KEY", "attr": "SECURITYTRAILS_KEY",
     "label": "SecurityTrails", "unlocks": "Deep DNS",
     "desc": "Passive subdomain discovery and DNS history. Without a key the "
             "deep-DNS stage stays locked.",
     "get_url": "https://securitytrails.com/app/account/credentials"},
    {"id": "shodan", "env": "SHODAN_KEY", "attr": "SHODAN_KEY",
     "label": "Shodan", "unlocks": "Port scan enrichment",
     "desc": "Folds Shodan's known open ports, services, versions and CVEs for "
             "each IP into the port scan. Without a key the free InternetDB "
             "source is used instead.",
     "get_url": "https://account.shodan.io/"},
    {"id": "ipinfo", "env": "IPINFO_TOKEN", "attr": "IPINFO_TOKEN",
     "label": "IPinfo", "unlocks": "IP enrichment",
     "desc": "Geolocation, ASN and owner lookups for resolved IPs. Falls back to "
             "the rate-limited free tier when unset.",
     "get_url": "https://ipinfo.io/account/token"},
]
_INTEGRATIONS_BY_ID = {i["id"]: i for i in INTEGRATIONS}


def _integration_state(meta: dict) -> dict:
    val = getattr(config, meta["attr"], "") or ""
    return {"id": meta["id"], "label": meta["label"], "unlocks": meta["unlocks"],
            "desc": meta["desc"], "get_url": meta.get("get_url"),
            "configured": bool(val.strip())}


@app.route("/api/admin/integrations")
def api_admin_integrations():
    """Every external API key the pipeline knows about, and whether each is set.
    The keys themselves never leave the server."""
    _require_admin()
    return jsonify({"integrations": [_integration_state(m) for m in INTEGRATIONS]})


@app.route("/api/admin/integrations/<key_id>", methods=["POST"])
def api_admin_set_integration(key_id):
    """Set (or clear, with a blank value) one integration's API key. Written to
    .env so it survives a restart and mirrored onto the running config so it is
    live immediately · no restart, no re-deploy."""
    _require_admin()
    meta = _INTEGRATIONS_BY_ID.get(key_id)
    if not meta:
        return jsonify({"error": "unknown integration"}), 404
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    if len(value) > 400:
        return jsonify({"error": "that value is too long to be an API key"}), 400
    config.save_env_key(meta["env"], value)
    setattr(config, meta["attr"], value)
    out = {"integration": _integration_state(meta), "saved": True}
    # The deep-DNS key gets an immediate liveness check so the admin sees at once
    # whether it actually works, and any stale quota reading is dropped.
    if key_id == "securitytrails":
        securitytrails.forget_usage()
        if value and body.get("check", True):
            try:
                out["quota"] = securitytrails.check(force=True)
            except Exception as exc:
                out["quota_error"] = str(exc)[:200]
    # Shodan gets the same immediate liveness check · the admin sees at once
    # whether the key works and how many query credits remain.
    if key_id == "shodan" and body.get("check", True):
        try:
            out["shodan"] = shodan_enrich.check(force=True)
        except Exception as exc:
            out["shodan_error"] = str(exc)[:200]
    return jsonify(out)


@app.route("/api/admin/integrations/<key_id>/test")
def api_admin_test_integration(key_id):
    """Test connection for an integration without changing its key · powers the
    admin 'Test connection' button and the API-status line."""
    _require_admin()
    if key_id == "shodan":
        return jsonify({"shodan": shodan_enrich.check(force=True)})
    if key_id == "securitytrails":
        try:
            return jsonify({"quota": securitytrails.check(force=True)})
        except Exception as exc:
            return jsonify({"error": str(exc)[:200]})
    return jsonify({"error": "no connection test available for this integration"}), 400


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "icons/favicon.svg",
                               mimetype="image/svg+xml")


# --------------------------------------------------------------------------- #
# Single-instance / port management ("register itself as a service")
# --------------------------------------------------------------------------- #
PID_FILE = JOBS_DIR / "server.pid"


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host if host != "0.0.0.0" else "127.0.0.1", port)) == 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _pid_on_port(port: int) -> int | None:
    try:
        out = subprocess.run(["ss", "-ltnpH", f"sport = :{port}"],
                             capture_output=True, text=True, timeout=4).stdout
        m = re.search(r"pid=(\d+)", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def _our_pid() -> int | None:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _resolve_port(host: str, port: int) -> int | None:
    """Return a bindable port, or None to abort. Handles: already-running-us
    (exit gracefully) and foreign-process-on-port (prompt kill / choose port)."""
    ours = _our_pid()
    if _port_in_use(host, port):
        if ours and _pid_alive(ours):
            print(f"\n  Argus Recon is already running (pid {ours}) at "
                  f"http://{host}:{port}\n  Open that URL · not starting a second instance.\n")
            return None
        holder = _pid_on_port(port)
        print(f"\n  Port {port} is already in use"
              + (f" by pid {holder}." if holder else "."))
        if not sys.stdin.isatty():
            print("  Set ARGUS_WEB_PORT to a free port and retry.\n")
            return None
        while True:
            ans = input("  [k] kill it and take the port · [number] use another port · "
                        "[q] quit > ").strip().lower()
            if ans == "q" or ans == "":
                return None
            if ans == "k":
                if holder:
                    try:
                        os.kill(holder, signal.SIGTERM)
                        time.sleep(1.0)
                        if _port_in_use(host, port):
                            os.kill(holder, signal.SIGKILL)
                            time.sleep(0.6)
                        print(f"  freed port {port}.")
                        return port
                    except Exception as exc:
                        print(f"  could not kill pid {holder}: {exc}")
                        continue
                print("  could not identify the process holding the port.")
                continue
            if ans.isdigit() and 1024 <= int(ans) <= 65535:
                if _port_in_use(host, int(ans)):
                    print(f"  port {ans} is also busy · pick another.")
                    continue
                return int(ans)
            print("  enter 'k', a port number (1024-65535), or 'q'.")
    return port


def _write_pid():
    try:
        PID_FILE.write_text(str(os.getpid()))
    except Exception:
        pass


def _cleanup_pid(*_):
    try:
        if _our_pid() == os.getpid():
            PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    sys.exit(0)


if __name__ == "__main__":
    host = config.WEB_HOST
    port = _resolve_port(host, config.WEB_PORT)
    if port is None:
        sys.exit(0)
    _write_pid()
    signal.signal(signal.SIGTERM, _cleanup_pid)
    signal.signal(signal.SIGINT, _cleanup_pid)
    import atexit
    atexit.register(lambda: _cleanup_pid())
    # Restore and reconcile the job table before serving, so a scan that was
    # running when the dashboard last stopped is followed or reported, never lost.
    _load_jobs()
    _start_graph_worker()
    print(f"\n  Argus Recon dashboard  →  http://{host}:{port}")
    print(f"  Serving scans from     →  {config.SCANS_DIR}")
    print(f"  Deep DNS               →  {'unlocked' if config.SECURITYTRAILS_KEY else 'locked (no key)'}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
