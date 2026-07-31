"""
SQLite (WAL) store — cache + job queue in front of the graph backend.

Two costs this removes:

  * I/O on the dashboard. The home page reads a summary for every saved scan and
    the scan page reads a per-endpoint index; without a store both mean parsing a
    multi-megabyte JSON file per request. Here the summary and endpoint index are
    written once (when the engine saves the scan) and read back as rows. The JSON
    file stays the source of truth — the store is a derived cache keyed by the
    file's mtime, so a stale or deleted row is simply rebuilt from the file.

  * Lost graph loads. The engine finishes a scan whether or not Neo4j/kuzu is up.
    A load that fails because the backend was down used to be gone; now it is
    enqueued and a worker drains the queue when the backend returns, so the graph
    catches up on its own.

WAL mode is the point: the engine process writes while the dashboard process
reads the same database file, without either blocking the other. Every function
degrades to a no-op (or a rebuild-from-file) if SQLite is unavailable or disabled
(ARGUS_STORE=0), so nothing here is load-bearing for correctness.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from . import config
from .util import get_logger

log = get_logger("store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    domain      TEXT,
    mtime       REAL,
    size        INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    summary     TEXT,          -- json: the home-page summary object
    panel       TEXT,          -- json: the scan doc minus `endpoints`
    updated     REAL
);
CREATE TABLE IF NOT EXISTS endpoints (
    scan_id  TEXT,
    eid      TEXT,
    light    TEXT,             -- json: the endpoint with heavy fields stripped
    PRIMARY KEY (scan_id, eid)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE TABLE IF NOT EXISTS graph_queue (
    scan_id   TEXT PRIMARY KEY,
    domain    TEXT,
    enqueued  REAL,
    attempts  INTEGER DEFAULT 0,
    last_error TEXT,
    last_try  REAL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""

# Per-thread connections: SQLite objects are not shareable across threads, and
# both the Flask server (many threads) and the engine touch this.
_local = threading.local()
_init_lock = threading.Lock()
_initialised = False
_DISABLED = False


def enabled() -> bool:
    return config.STORE_ENABLED and not _DISABLED


def _connect() -> sqlite3.Connection | None:
    global _initialised, _DISABLED
    if not enabled():
        return None
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn
    try:
        config.STORE_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(config.STORE_DB), timeout=10,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        with _init_lock:
            if not _initialised:
                conn.executescript(_SCHEMA)
                _migrate(conn)
                conn.commit()
                _initialised = True
        _local.conn = conn
        return conn
    except Exception as exc:
        log.warning(f"store unavailable ({exc}) — running without the cache/queue")
        _DISABLED = True
        return None


# Columns added after the first release. CREATE TABLE IF NOT EXISTS leaves an
# existing table alone, so a database created by an older build keeps the old
# shape and every query naming a new column fails — which, because every read
# here is wrapped in `except: return None`, degrades silently into "the cache
# never hits" rather than into an error anyone would see. Add them explicitly.
_ADDED_COLUMNS = {"scans": {"panel": "TEXT"}}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, cols in _ADDED_COLUMNS.items():
        try:
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        except Exception:
            continue
        for col, decl in cols.items():
            if col not in have:
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                    log.debug(f"store: added {table}.{col}")
                except Exception as exc:
                    log.debug(f"store: could not add {table}.{col}: {exc}")


# --------------------------------------------------------------------------- #
# Summary + endpoint cache
# --------------------------------------------------------------------------- #
_HEAVY = ("resp_body", "req_body", "dom", "found_on",
          "req_headers", "resp_headers", "notes", "js_origin")


def _light_endpoint(e: dict) -> dict:
    return {k: v for k, v in e.items() if k not in _HEAVY}


def build_summary(doc: dict, *, scan_id: str, mtime: float, size: int) -> dict:
    meta = doc.get("meta", {})
    tor_meta = meta.get("tor") or {}
    return {
        "scan_id": scan_id,
        "domain": meta.get("domain", scan_id),
        "started_at": meta.get("started_at"),
        "finished_at": meta.get("finished_at"),
        "duration_sec": meta.get("duration_sec"),
        "stats": meta.get("stats", {}),
        "modules": meta.get("modules", {}),
        "scope": meta.get("scope", "apex"),
        "tor": {"exit_ip": tor_meta.get("exit_ip"),
                "verified": bool(tor_meta.get("verified"))} if tor_meta else None,
        "size": size,
    }


def build_panel(doc: dict) -> dict:
    """Everything the scan page's left panel and header need — meta, subdomains,
    infra, dns, files, secrets, js_files — with the endpoint list left out.

    The endpoints are the part that scales with the crawl (tens of thousands of
    records, hundreds of megabytes); everything else stays small no matter how
    big the scan gets. Splitting them lets the scan view be answered entirely
    from SQLite instead of re-parsing the whole JSON document.
    """
    return {k: v for k, v in doc.items() if k != "endpoints"}


def index_scan(scan_id: str, doc: dict, path: Path) -> None:
    """Populate the cache for one scan document. Called by the engine after save
    and by the server on a cache miss."""
    conn = _connect()
    if conn is None:
        return
    try:
        st = path.stat()
        mtime, size = st.st_mtime, st.st_size
    except OSError:
        mtime, size = time.time(), 0
    summary = build_summary(doc, scan_id=scan_id, mtime=mtime, size=size)
    panel = json.dumps(build_panel(doc))
    meta = doc.get("meta", {})
    try:
        with conn:
            conn.execute(
                "INSERT INTO scans(scan_id,domain,mtime,size,started_at,finished_at,summary,panel,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(scan_id) DO UPDATE SET domain=excluded.domain,"
                "mtime=excluded.mtime,size=excluded.size,started_at=excluded.started_at,"
                "finished_at=excluded.finished_at,summary=excluded.summary,"
                "panel=excluded.panel,updated=excluded.updated",
                (scan_id, meta.get("domain"), mtime, size, meta.get("started_at"),
                 meta.get("finished_at"), json.dumps(summary), panel, time.time()))
            conn.execute("DELETE FROM endpoints WHERE scan_id=?", (scan_id,))
            rows = [(scan_id, e.get("id") or "", json.dumps(_light_endpoint(e)))
                    for e in doc.get("endpoints", []) if e.get("id")]
            if rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO endpoints(scan_id,eid,light) VALUES(?,?,?)",
                    rows)
    except Exception as exc:
        log.debug(f"index_scan failed for {scan_id}: {exc}")


def get_summary(scan_id: str, mtime: float) -> dict | None:
    """Cached summary if it matches the file's current mtime, else None."""
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT mtime, summary FROM scans WHERE scan_id=?",
                           (scan_id,)).fetchone()
        if row and abs((row["mtime"] or 0) - mtime) < 1e-6:
            return json.loads(row["summary"])
    except Exception:
        return None
    return None


def light_endpoints(scan_id: str, mtime: float) -> list[dict] | None:
    """Cached light endpoint list, or None if the cache is missing/stale."""
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT mtime FROM scans WHERE scan_id=?",
                           (scan_id,)).fetchone()
        if not row or abs((row["mtime"] or 0) - mtime) > 1e-6:
            return None
        cur = conn.execute("SELECT light FROM endpoints WHERE scan_id=?", (scan_id,))
        return [json.loads(r["light"]) for r in cur.fetchall()]
    except Exception:
        return None


def light_view(scan_id: str, mtime: float) -> dict | None:
    """The whole scan-page document (panel + table-ready endpoints) from cache,
    or None if anything about it is missing or stale.

    This is the one that matters for a big scan: a complete hit here means the
    multi-hundred-megabyte JSON file is never opened to render the page.
    """
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT mtime, panel FROM scans WHERE scan_id=?",
                           (scan_id,)).fetchone()
        if not row or abs((row["mtime"] or 0) - mtime) > 1e-6 or not row["panel"]:
            return None
        doc = json.loads(row["panel"])
        cur = conn.execute("SELECT light FROM endpoints WHERE scan_id=?", (scan_id,))
        doc["endpoints"] = [json.loads(r["light"]) for r in cur.fetchall()]
        return doc
    except Exception:
        return None


def forget(scan_id: str) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            conn.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
            conn.execute("DELETE FROM endpoints WHERE scan_id=?", (scan_id,))
            conn.execute("DELETE FROM graph_queue WHERE scan_id=?", (scan_id,))
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Graph-load queue
# --------------------------------------------------------------------------- #
def enqueue_graph(scan_id: str, domain: str) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            conn.execute(
                "INSERT INTO graph_queue(scan_id,domain,enqueued,attempts) VALUES(?,?,?,0) "
                "ON CONFLICT(scan_id) DO UPDATE SET enqueued=excluded.enqueued",
                (scan_id, domain, time.time()))
        log.info(f"queued graph load for {scan_id} (backend was unavailable)")
    except Exception as exc:
        log.debug(f"enqueue_graph failed: {exc}")


def dequeue_graph(scan_id: str) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            conn.execute("DELETE FROM graph_queue WHERE scan_id=?", (scan_id,))
    except Exception:
        pass


def mark_attempt(scan_id: str, error: str | None) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            conn.execute(
                "UPDATE graph_queue SET attempts=attempts+1,last_error=?,last_try=? "
                "WHERE scan_id=?", (error, time.time(), scan_id))
    except Exception:
        pass


def pending_graph(limit: int = 20) -> list[dict]:
    conn = _connect()
    if conn is None:
        return []
    try:
        cur = conn.execute(
            "SELECT scan_id,domain,attempts,last_error FROM graph_queue "
            "ORDER BY enqueued ASC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def queue_depth() -> int:
    conn = _connect()
    if conn is None:
        return 0
    try:
        return conn.execute("SELECT COUNT(*) AS c FROM graph_queue").fetchone()["c"]
    except Exception:
        return 0
