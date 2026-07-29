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

from modules import config
from modules import graph_loader
from modules.util import resolve_tool

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["JSON_SORT_KEYS"] = False

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


def _load(scan_id: str) -> dict:
    if not SCAN_ID_RE.match(scan_id):
        abort(400, "bad scan id")
    path = config.SCANS_DIR / f"{scan_id}.json"
    if not path.exists() or path.parent != config.SCANS_DIR:
        abort(404, "scan not found")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _summary(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return {"scan_id": path.stem, "domain": path.stem, "error": True,
                "stats": {}, "started_at": None}
    meta = d.get("meta", {})
    return {
        "scan_id": path.stem,
        "domain": meta.get("domain", path.stem),
        "started_at": meta.get("started_at"),
        "finished_at": meta.get("finished_at"),
        "duration_sec": meta.get("duration_sec"),
        "stats": meta.get("stats", {}),
        "modules": meta.get("modules", {}),
        "size": path.stat().st_size,
    }


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
    return jsonify(_load(scan_id))


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
    # best-effort: also drop the matching Neo4j subgraph if the DB is up
    try:
        graph_loader.delete_scan(scan_id)
    except Exception:
        pass
    return jsonify({"deleted": scan_id})


@app.route("/api/scan/<scan_id>/graph")
def api_graph(scan_id):
    data = _load(scan_id)
    # Prefer the live Neo4j graph if the DB is up; fall back to JSON-derived.
    if request.args.get("source") != "json":
        g = graph_loader.fetch_graph(data["meta"]["scan_id"])
        if g:
            return jsonify(g)
    g = graph_loader.graph_from_scan(data)
    g["source"] = "json"
    return jsonify(g)


@app.route("/api/status")
def api_status():
    # No tool names are exposed here — the dashboard only needs to know whether
    # deep DNS is unlocked and whether the graph DB is live. Engine readiness is
    # a single anonymous flag (the real toolchain is documented in the README).
    engines_ready = all([
        resolve_tool(config.BBOT_BIN), resolve_tool(config.WHATWEB_BIN),
        resolve_tool(config.FFUF_BIN) or resolve_tool(config.FEROX_BIN),
    ])
    return jsonify({
        "deep_available": bool(config.SECURITYTRAILS_KEY),
        "graph_db": graph_loader.ping(),
        "engines_ready": engines_ready,
        "ipinfo_token": bool(config.IPINFO_TOKEN),
    })


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
    with open(log_path, "w", encoding="utf-8") as log:
        try:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=str(ROOT))
            _JOBS[job_id]["pid"] = proc.pid
            rc = proc.wait()
            _JOBS[job_id].update(status="done" if rc == 0 else "failed",
                                 returncode=rc, finished=time.time())
        except Exception as exc:
            _JOBS[job_id].update(status="failed", error=str(exc))


@app.route("/api/scan", methods=["POST"])
def api_launch():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", domain):
        return jsonify({"error": "invalid domain"}), 400
    extra: list[str] = ["--no-prompt"]   # background job: never block on stdin
    if body.get("passive"):
        extra.append("--passive")
    if body.get("deep") and config.SECURITYTRAILS_KEY:
        extra.append("--deep")
    if body.get("exact_scope"):
        extra.append("--exact-scope")
    if body.get("no_bbot"):
        extra.append("--no-bbot")
    if body.get("no_graph"):
        extra.append("--no-graph")
    for key, flag in (("max_pages", "--max-pages"), ("max_depth", "--max-depth")):
        if body.get(key):
            extra += [flag, str(int(body[key]))]
    job_id = uuid.uuid4().hex[:12]
    _JOBS[job_id] = {"id": job_id, "domain": domain, "status": "queued",
                     "started": time.time()}
    threading.Thread(target=_run_job, args=(job_id, domain, extra),
                     daemon=True).start()
    return jsonify({"job_id": job_id, "domain": domain})


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
    print(f"\n  Argus Recon dashboard  →  http://{host}:{port}")
    print(f"  Serving scans from     →  {config.SCANS_DIR}")
    print(f"  Deep DNS               →  {'unlocked' if config.SECURITYTRAILS_KEY else 'locked (no key)'}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
