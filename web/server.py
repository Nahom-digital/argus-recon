#!/usr/bin/env python3
"""
Argus Recon — local web dashboard.

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
                   request, abort)
from werkzeug.middleware.proxy_fix import ProxyFix

from modules import config
from modules import graph_loader
from modules import store
from modules import tor
from modules import portscan
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


@app.context_processor
def _inject_sprite():
    from markupsafe import Markup
    return {"sprite": Markup(_SPRITE)}


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

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
JOBS_DIR = config.SCANS_DIR / ".jobs"
JOBS_DIR.mkdir(exist_ok=True)
_JOBS: dict[str, dict] = {}


# --------------------------------------------------------------------------- #
# Scan discovery
# --------------------------------------------------------------------------- #
def _scan_files() -> list[Path]:
    return sorted(config.SCANS_DIR.glob("*.json"),
                  key=lambda p: p.stat().st_mtime, reverse=True)


# A full scan document can be tens of MB. Parsing it on every request (the graph
# builder, a raw-JSON open, and each expanded row all call _load) is what made a
# big scan feel like the dashboard had gone offline. Cache the most-recently-read
# document keyed by (scan_id, mtime); a single entry keeps memory bounded while
# still serving a browsing session's repeated reads from RAM.
_DOC_CACHE: dict = {}


def _load(scan_id: str) -> dict:
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists() or path.parent != config.SCANS_DIR:
        abort(404, "scan not found")
    mtime = path.stat().st_mtime
    hit = _DOC_CACHE.get(scan_id)
    if hit and hit[0] == mtime:
        return hit[1]
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    _DOC_CACHE.clear()          # hold only the most-recently-viewed scan
    _DOC_CACHE[scan_id] = (mtime, doc)
    return doc


# Per-endpoint fields the request *table* never shows: response/request bodies,
# the captured DOM, every "found on" URL, and raw headers. They are the bulk of a
# large scan (tens of MB) and are only needed when one row is expanded — served
# then by /api/scan/<id>/endpoint/<eid>. Stripping them from the list view is what
# keeps the scan page loadable when a scan has tens of thousands of endpoints.
_ENDPOINT_HEAVY = ("resp_body", "req_body", "dom", "found_on",
                   "req_headers", "resp_headers", "notes", "js_origin")


def _light_scan(d: dict) -> dict:
    """The scan document with heavy per-endpoint fields removed — everything the
    left panel, the request table, its filters and the graph client need, and
    nothing that only the expanded-row detail uses."""
    out = dict(d)
    out["endpoints"] = [{k: v for k, v in e.items() if k not in _ENDPOINT_HEAVY}
                        for e in d.get("endpoints", [])]
    return out


def _light_view(scan_id: str) -> dict:
    """Light document for the scan page, served whole from the SQLite index when
    it is fresh — panel data *and* the endpoint list.

    Serving only the endpoints from the store was pointless: the panel came from
    `_load()`, which was called unconditionally, so every view of a 141 MB scan
    still parsed 141 MB of JSON (~20 s and a gigabyte of interpreter heap) before
    it could answer. The store now holds the panel document too, so a hit here
    never opens the file at all."""
    path = config.SCANS_DIR / f"{scan_id}.json"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0
    if mtime:
        cached = store.light_view(scan_id, mtime)
        if cached is not None:
            return cached
    # Cache miss (first view of a new scan, or store disabled): parse once, strip
    # inline, and backfill the index so every later view skips the file.
    doc = _load(scan_id)
    light = _light_scan(doc)
    try:
        store.index_scan(scan_id, doc, path)
    except Exception:
        pass
    return light


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
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return {"scan_id": stem, "domain": stem, "error": True,
                "stats": {}, "started_at": None}
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
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
    return render_template("scan.html", scan_id=scan_id)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/scans")
def api_scans():
    return jsonify([_summary(p) for p in _scan_files()])


@app.route("/api/scan/<scan_id>")
def api_scan(scan_id):
    # The full document (raw-JSON link, downloads, backward compatibility). The
    # scan UI uses /view instead so it never pulls the heavy per-endpoint fields.
    return jsonify(_load(scan_id))


@app.route("/api/scan/<scan_id>/view")
def api_scan_view(scan_id):
    """Light document for the scan page: panel data plus table-ready endpoints,
    without response bodies / DOM / headers. This is what makes a huge scan open.
    The endpoint list is served from the SQLite index when it is fresh."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    return jsonify(_light_view(scan_id))


@app.route("/api/scan/<scan_id>/endpoint/<eid>")
def api_scan_endpoint(scan_id, eid):
    """Full record for one endpoint (bodies, headers, found-on, JS origin),
    fetched only when a row is expanded."""
    if not re.match(r"^[A-Fa-f0-9]{6,40}$", eid):
        abort(400, "bad endpoint id")
    for e in _load(scan_id).get("endpoints", []):
        if e.get("id") == eid:
            return jsonify(e)
    abort(404, "endpoint not found")


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def api_scan_delete(scan_id):
    """Delete a saved scan (from the home library). Path-traversal guarded."""
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
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
    _SUMMARY_CACHE.pop(scan_id, None)
    return jsonify({"deleted": scan_id})


@app.route("/api/scan/<scan_id>/graph")
def api_graph(scan_id):
    """The scan's graph, bounded by a node/edge budget.

    Two things this deliberately does not do. It does not parse the scan JSON to
    ask the graph backend for a graph — the backend is keyed by scan_id, which is
    already in the URL, so the old `_load()` here was a multi-hundred-megabyte
    parse to recover a string we were handed. And it does not return the full
    stored graph: a large crawl is ~67k nodes / ~218k edges, which is a 30 MB
    response the browser cannot lay out, so the page renders nothing at all.
    ?limit=N raises the node budget for a caller that really wants more.
    """
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists():
        abort(404, "scan not found")

    max_nodes = config.GRAPH_VIEW_NODES
    raw = request.args.get("limit")
    if raw:
        try:
            max_nodes = max(200, min(int(raw), config.GRAPH_VIEW_MAX))
        except ValueError:
            pass
    max_edges = max(config.GRAPH_VIEW_EDGES, max_nodes * 2)

    # Prefer the live graph DB if one is up; fall back to JSON-derived.
    if request.args.get("source") != "json":
        g = graph_loader.fetch_graph(scan_id, max_nodes=max_nodes,
                                     max_edges=max_edges)
        if g:
            return jsonify(g)
    g = graph_loader.graph_from_scan(_load(scan_id), max_nodes=max_nodes,
                                     max_edges=max_edges)
    g["source"] = "json"
    return jsonify(g)


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
    # No tool names are exposed here — the dashboard only needs to know whether
    # deep DNS is unlocked and whether the graph DB is live. Engine readiness is
    # a single anonymous flag (the real toolchain is documented in the README).
    engines_ready = all([
        resolve_tool(config.BBOT_BIN), resolve_tool(config.WHATWEB_BIN),
        resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN),
    ])
    svc = _service_state()
    graph = _graph_status()
    return jsonify({
        "deep_available": bool(config.SECURITYTRAILS_KEY),
        "graph_db": graph["available"],
        "graph": graph,
        "engines_ready": engines_ready,
        "ipinfo_token": bool(config.IPINFO_TOKEN),
        # can a scan actually be routed over Tor from this machine? The launcher
        # locks the toggle rather than letting a run fail at the first step.
        "tor": tor.availability(),
        # is the port-scan engine installed? (gates the "port scan" toggle)
        "portscan_available": portscan.available(),
        "service": {**svc, "uptime_sec": round(time.time() - STARTED_AT),
                    "url": f"http://{config.WEB_HOST}:{config.WEB_PORT}"},
        # the launcher form shows these as the real defaults rather than inventing numbers
        "defaults": {"max_pages": config.CRAWL_MAX_PAGES,
                     "max_depth": config.CRAWL_MAX_DEPTH,
                     "modules": SCAN_MODULES},
    })


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
                    try:
                        with open(path, encoding="utf-8") as fh:
                            doc = json.load(fh)
                        if graph_loader.load(doc):
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
    """First-run / settings: persist the deep-DNS key to .env. Blank clears it."""
    body = request.get_json(silent=True) or {}
    key = (body.get("key") or "").strip()
    config.save_env_key("SECURITYTRAILS_KEY", key)
    config.SECURITYTRAILS_KEY = key
    return jsonify({"deep_available": bool(key)})


# --------------------------------------------------------------------------- #
# Optional: launch a scan from the dashboard
# --------------------------------------------------------------------------- #
def _run_job(job_id: str, domain: str, extra: list[str]):
    log_path = JOBS_DIR / f"{job_id}.log"
    py = sys.executable
    cmd = [py, str(ROOT / "main.py"), domain, *extra]
    _JOBS[job_id].update(status="running", cmd=" ".join(cmd))
    # The engine refuses to run from a terminal; this flag marks it as ours.
    # Its own process group lets "stop" take the whole tool subtree with it.
    env = {**os.environ, "ARGUS_INTERNAL": "1", "PYTHONUNBUFFERED": "1"}
    with open(log_path, "w", encoding="utf-8") as log:
        try:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=str(ROOT), env=env, start_new_session=True)
            _JOBS[job_id]["pid"] = proc.pid
            rc = proc.wait()
            if _JOBS[job_id].get("status") == "stopping":
                _JOBS[job_id].update(status="stopped", returncode=rc,
                                     finished=time.time())
            else:
                _JOBS[job_id].update(status="done" if rc == 0 else "failed",
                                     returncode=rc, finished=time.time())
        except Exception as exc:
            _JOBS[job_id].update(status="failed", error=str(exc),
                                 finished=time.time())


# Pipeline stages the dashboard can switch off (mirrors main.ALL_MODULES).
SCAN_MODULES = ["subdomain", "fingerprint", "crawl", "bruteforce",
                "ip_enrich", "classify", "graph"]


@app.route("/api/scan", methods=["POST"])
def api_launch():
    """Start a scan. This is the only way to start one — the engine refuses to
    run from a terminal — so every pipeline option is reachable from here."""
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
        return jsonify({"error": "Tor is not available on this machine — install "
                                 "tor (and the Python SOCKS dependency) first"}), 400
    want_portscan = bool(body.get("portscan"))
    if want_portscan and body.get("passive"):
        return jsonify({"error": "a port scan is an active probe — it cannot run in "
                                 "a passive scan"}), 400
    if want_portscan and not portscan.available():
        return jsonify({"error": "the port-scan engine is not installed on this "
                                 "machine — run ./install.sh to add it"}), 400

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
    if body.get("no_bbot"):
        extra.append("--no-bbot")
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

    job_id = uuid.uuid4().hex[:12]
    _JOBS[job_id] = {"id": job_id, "domain": domain, "status": "queued",
                     "started": time.time(), "options": {
                         "passive": bool(body.get("passive")),
                         "deep": bool(body.get("deep") and config.SECURITYTRAILS_KEY),
                         "exact_scope": bool(body.get("exact_scope")) and not single,
                         "single": single,
                         "tor": want_tor,
                         "portscan": want_portscan,
                         "skipped": skip + (["graph"] if body.get("no_graph") and "graph" not in skip else []),
                     }}
    threading.Thread(target=_run_job, args=(job_id, domain, extra),
                     daemon=True).start()
    return jsonify({"job_id": job_id, "domain": domain})


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
    if job["status"] not in ("queued", "running"):
        return jsonify({"job": job, "note": "not running"})
    pid = job.get("pid")
    if not pid:
        job.update(status="stopped", finished=time.time())
        return jsonify({"job": job})
    job["status"] = "stopping"
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        job.update(status="stopped", finished=time.time())
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


@app.route("/api/jobs")
def api_jobs():
    return jsonify(sorted(_JOBS.values(), key=lambda j: j.get("started", 0),
                          reverse=True))


@app.route("/api/jobs/<job_id>/log")
def api_job_log(job_id):
    if not SCAN_ID_RE.match(job_id):
        abort(400)
    log_path = JOBS_DIR / f"{job_id}.log"
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    # strip ANSI colour codes for the browser
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return jsonify({"job": _JOBS.get(job_id, {}), "log": text[-16000:]})


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
                  f"http://{host}:{port}\n  Open that URL — not starting a second instance.\n")
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
                    print(f"  port {ans} is also busy — pick another.")
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
    _start_graph_worker()
    print(f"\n  Argus Recon dashboard  →  http://{host}:{port}")
    print(f"  Serving scans from     →  {config.SCANS_DIR}")
    print(f"  Deep DNS               →  {'unlocked' if config.SECURITYTRAILS_KEY else 'locked (no key)'}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
