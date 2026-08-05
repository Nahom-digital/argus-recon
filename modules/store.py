"""
SQLite (WAL) store · cache + job queue in front of the graph backend.

Two costs this removes:

  * I/O on the dashboard. The home page reads a summary for every saved scan and
    the scan page reads a per-endpoint index; without a store both mean parsing a
    multi-megabyte JSON file per request. Here the summary and endpoint index are
    written once (when the engine saves the scan) and read back as rows. The JSON
    file stays the source of truth · the store is a derived cache keyed by the
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
    rank     INTEGER,          -- lower = more worth showing (see _ep_rank)
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
        log.warning(f"store unavailable ({exc}) · running without the cache/queue")
        _DISABLED = True
        return None


# Columns added after the first release. CREATE TABLE IF NOT EXISTS leaves an
# existing table alone, so a database created by an older build keeps the old
# shape and every query naming a new column fails · which, because every read
# here is wrapped in `except: return None`, degrades silently into "the cache
# never hits" rather than into an error anyone would see. Add them explicitly.
_ADDED_COLUMNS = {"scans": {"panel": "TEXT"}, "endpoints": {"rank": "INTEGER"}}


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
    # The rank index has to be created after the column is guaranteed to exist
    # (an old database gets `rank` from the ALTER above, not from _SCHEMA).
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_rank "
                     "ON endpoints(scan_id, rank)")
    except Exception as exc:
        log.debug(f"store: could not add idx_endpoints_rank: {exc}")


# --------------------------------------------------------------------------- #
# Summary + endpoint cache
# --------------------------------------------------------------------------- #
_HEAVY = ("resp_body", "req_body", "dom", "found_on",
          "req_headers", "resp_headers", "notes", "js_origin")


def _light_endpoint(e: dict) -> dict:
    return {k: v for k, v in e.items() if k not in _HEAVY}


def _ep_rank(e: dict) -> int:
    """Lower sorts first · the endpoints most worth putting in a capped view or
    graph (classified requests, forms/xhr/fetch, JS, fielded, in-scope) get the
    smallest rank. Mirrors modules.graph_loader._ep_priority so the scan page's
    top-N table and the graph's node budget agree on what "interesting" means."""
    p = 0
    if e.get("classifications"):
        p += 4
    if e.get("type") in ("form", "xhr", "fetch"):
        p += 3
    if e.get("type") == "js":
        p += 2
    if e.get("fields"):
        p += 1
    if not e.get("in_scope"):
        p -= 2
    return -p


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
        # Which account started this run · the scan library shows an operator
        # their own scans only, so the owner has to survive into the summary
        # (a scan from before accounts existed simply has none).
        "owner": meta.get("owner"),
        "tor": {"exit_ip": tor_meta.get("exit_ip"),
                "verified": bool(tor_meta.get("verified"))} if tor_meta else None,
        "size": size,
    }


def build_panel(doc: dict) -> dict:
    """Everything the scan page's left panel and header need · meta, subdomains,
    infra, dns, files, secrets, js_files · with the endpoint list left out.

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
            rows = [(scan_id, e.get("id") or "", json.dumps(_light_endpoint(e)),
                     _ep_rank(e))
                    for e in doc.get("endpoints", []) if e.get("id")]
            if rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO endpoints(scan_id,eid,light,rank) "
                    "VALUES(?,?,?,?)", rows)
    except Exception as exc:
        log.debug(f"index_scan failed for {scan_id}: {exc}")


class ScanIndexer:
    """Streaming counterpart to index_scan · fed one endpoint at a time while the
    engine writes the scan JSON, so a huge scan is indexed without the whole
    endpoint list ever being held in memory. The panel/summary row is written at
    finish(), once the file's size and mtime are known.

    Best-effort throughout: if the cache DB is unavailable the indexer quietly
    does nothing, exactly like index_scan, and the JSON on disk stays the truth.
    """

    def __init__(self, scan_id: str, panel_doc: dict):
        self.scan_id = scan_id
        self.panel_doc = panel_doc          # the shell · everything but endpoints
        self.conn = _connect()
        self._batch: list[tuple] = []
        self.ok = self.conn is not None
        if self.ok:
            try:
                with self.conn:
                    self.conn.execute("DELETE FROM endpoints WHERE scan_id=?", (scan_id,))
            except Exception as exc:
                log.debug(f"ScanIndexer reset failed for {scan_id}: {exc}")
                self.ok = False

    def add(self, ep: dict) -> None:
        if not self.ok or not ep.get("id"):
            return
        self._batch.append((self.scan_id, ep.get("id") or "",
                            json.dumps(_light_endpoint(ep)), _ep_rank(ep)))
        if len(self._batch) >= 2000:
            self._flush()

    def _flush(self) -> None:
        if not self.ok or not self._batch:
            return
        try:
            with self.conn:
                self.conn.executemany(
                    "INSERT OR REPLACE INTO endpoints(scan_id,eid,light,rank) "
                    "VALUES(?,?,?,?)", self._batch)
        except Exception as exc:
            log.debug(f"ScanIndexer flush failed for {self.scan_id}: {exc}")
            self.ok = False
        self._batch = []

    def finish(self, path: Path) -> None:
        if not self.ok:
            return
        self._flush()
        try:
            st = path.stat()
            mtime, size = st.st_mtime, st.st_size
        except OSError:
            mtime, size = time.time(), 0
        summary = build_summary(self.panel_doc, scan_id=self.scan_id, mtime=mtime, size=size)
        panel = json.dumps(build_panel(self.panel_doc))
        meta = self.panel_doc.get("meta", {})
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO scans(scan_id,domain,mtime,size,started_at,finished_at,summary,panel,updated) "
                    "VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(scan_id) DO UPDATE SET domain=excluded.domain,"
                    "mtime=excluded.mtime,size=excluded.size,started_at=excluded.started_at,"
                    "finished_at=excluded.finished_at,summary=excluded.summary,"
                    "panel=excluded.panel,updated=excluded.updated",
                    (self.scan_id, meta.get("domain"), mtime, size, meta.get("started_at"),
                     meta.get("finished_at"), json.dumps(summary), panel, time.time()))
        except Exception as exc:
            log.debug(f"ScanIndexer finish failed for {self.scan_id}: {exc}")


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


def _fresh(conn, scan_id: str, mtime: float) -> bool:
    row = conn.execute("SELECT mtime FROM scans WHERE scan_id=?",
                       (scan_id,)).fetchone()
    return bool(row) and abs((row["mtime"] or 0) - mtime) <= 1e-6


def light_endpoints(scan_id: str, mtime: float,
                    limit: int | None = None) -> list[dict] | None:
    """Cached light endpoints, or None if the cache is missing/stale.

    With `limit` set, only the top-`limit` by rank are returned · the interesting
    ones first (see _ep_rank), so a capped scan-page table or graph reads a few
    thousand rows out of a million straight from SQLite instead of shipping the
    whole array. None means every endpoint (back-compat)."""
    conn = _connect()
    if conn is None:
        return None
    try:
        if not _fresh(conn, scan_id, mtime):
            return None
        sql = "SELECT light FROM endpoints WHERE scan_id=? ORDER BY rank, rowid"
        args: tuple = (scan_id,)
        if limit is not None:
            sql += " LIMIT ?"
            args = (scan_id, int(limit))
        cur = conn.execute(sql, args)
        return [json.loads(r["light"]) for r in cur.fetchall()]
    except Exception:
        return None


def backfill_ranks(scan_id: str | None = None, batch: int = 5000) -> int:
    """Populate endpoints.rank for rows that predate the column (rank IS NULL),
    computing it from the already-stored light JSON · no scan file is opened, so
    a million-endpoint scan indexed before ranking existed gets its interesting
    endpoints (classified requests, forms, JS, fielded) sorted to the front of a
    capped view/graph without re-reading the gigabyte file. Returns rows updated.

    Streamed in batches so peak memory is one batch, not the whole endpoints
    table · the exact spike this project exists to avoid."""
    conn = _connect()
    if conn is None:
        return 0
    where = "rank IS NULL"
    pre: tuple = ()
    if scan_id:
        where += " AND scan_id=?"
        pre = (scan_id,)
    updated = 0
    try:
        while True:
            rows = conn.execute(
                f"SELECT rowid, light FROM endpoints WHERE {where} LIMIT ?",
                (*pre, batch)).fetchall()
            if not rows:
                break
            ups = []
            for r in rows:
                try:
                    e = json.loads(r["light"])
                except Exception:
                    e = {}
                ups.append((_ep_rank(e), r["rowid"]))
            with conn:
                conn.executemany("UPDATE endpoints SET rank=? WHERE rowid=?", ups)
            updated += len(ups)
            if len(rows) < batch:
                break
    except Exception as exc:
        log.debug(f"backfill_ranks failed: {exc}")
    return updated


def get_panel(scan_id: str, mtime: float) -> dict | None:
    """The scan's `panel` (everything but endpoints: meta, subdomains, infra,
    files, js_files, secrets, dns) from cache, or None if missing/stale. This is
    the complete graph "shell" · small no matter how big the crawl · so the graph
    can be built without opening the scan file at all."""
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT mtime, panel FROM scans WHERE scan_id=?",
                           (scan_id,)).fetchone()
        if not row or abs((row["mtime"] or 0) - mtime) > 1e-6 or not row["panel"]:
            return None
        return json.loads(row["panel"])
    except Exception:
        return None


def light_view(scan_id: str, mtime: float,
               limit: int | None = None) -> dict | None:
    """The whole scan-page document (panel + table-ready endpoints) from cache,
    or None if anything about it is missing or stale.

    This is the one that matters for a big scan: a complete hit here means the
    multi-hundred-megabyte JSON file is never opened to render the page. `limit`
    caps the endpoint list to the top-N by rank (the rest of the page · counts,
    panel, graph · still describe the full surface).
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
        sql = "SELECT light FROM endpoints WHERE scan_id=? ORDER BY rank, rowid"
        args: tuple = (scan_id,)
        if limit is not None:
            sql += " LIMIT ?"
            args = (scan_id, int(limit))
        cur = conn.execute(sql, args)
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
