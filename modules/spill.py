"""
spill.py · a keyed record store that overflows to SQLite.

It behaves like the plain dict of endpoint records a scan used to keep entirely
in memory, but once the working set passes a threshold the coldest records are
written to an on-disk SQLite table and dropped from RAM. A deep crawl of a
million endpoints then costs a bounded amount of memory instead of a gigabyte,
while producing the exact same records.

Small scans never touch the disk: while the working set stays under the
threshold nothing is written, no database file is created, and the store behaves
byte-for-byte like the old dict. The overflow only engages on the huge scans
that used to run the worker out of memory (and get it killed).

Records are keyed by "METHOD url", which is unique per endpoint, so the final
serialisation order (in-scope first, then host, url, method) is fully determined
by the records themselves · the in-memory path and the spilled path emit an
identical, deterministic order.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


def _sort_key(r: dict):
    # in-scope first (0 before 1), then host, url, method · mirrors the SQL
    # `ORDER BY in_scope DESC, host, url, method` used for the spilled tier
    return (0 if r.get("in_scope") else 1, r.get("host") or "",
            r.get("url") or "", r.get("method") or "")


class SpillMap:
    """A dict-like store of endpoint records that spills the coldest entries to
    SQLite once memory grows past `hot_max`."""

    def __init__(self, path, *, hot_max: int = 60000):
        self.path = Path(path)
        self.hot: dict[str, dict] = {}
        self.hot_max = max(1000, int(hot_max))
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None   # created lazily on first spill
        self._spilled = 0                            # records currently on disk

    # -- lazy disk tier ------------------------------------------------------
    def _ensure_db(self) -> sqlite3.Connection:
        if self._db is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # a stale file from a crashed prior run of the same scan id is scratch
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(self.path) + suffix).unlink()
                except OSError:
                    pass
            db = sqlite3.connect(str(self.path), check_same_thread=False)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=OFF")     # scratch data · durability not needed
            db.execute("CREATE TABLE IF NOT EXISTS ep("
                       "key TEXT PRIMARY KEY, in_scope INTEGER, host TEXT,"
                       " url TEXT, method TEXT, rec TEXT)")
            self._db = db
        return self._db

    @staticmethod
    def _row(key: str, rec: dict):
        return (key, 1 if rec.get("in_scope") else 0, rec.get("host") or "",
                rec.get("url") or "", rec.get("method") or "",
                json.dumps(rec, ensure_ascii=False))

    def _spill_if_needed(self, exclude: str | None) -> None:
        if len(self.hot) <= self.hot_max:
            return
        target = self.hot_max // 2
        victims: list[str] = []
        # dict preserves insertion order, so the front is the coldest
        for k in self.hot:
            if k == exclude:
                continue
            victims.append(k)
            if len(self.hot) - len(victims) <= target:
                break
        if not victims:
            return
        db = self._ensure_db()
        db.executemany(
            "INSERT OR REPLACE INTO ep(key,in_scope,host,url,method,rec) "
            "VALUES(?,?,?,?,?,?)", (self._row(k, self.hot[k]) for k in victims))
        for k in victims:
            del self.hot[k]
        self._spilled += len(victims)
        db.commit()

    # -- dict-ish API (what ScanResult.add_endpoint uses) --------------------
    def get(self, key: str):
        with self._lock:
            rec = self.hot.get(key)
            if rec is not None:
                return rec
            if self._db is None:
                return None
            row = self._db.execute("SELECT rec FROM ep WHERE key=?", (key,)).fetchone()
            if row is None:
                return None
            # promote back to the hot tier so the caller can merge into it, and
            # keep exactly one copy (delete the disk row)
            rec = json.loads(row[0])
            self._db.execute("DELETE FROM ep WHERE key=?", (key,))
            self._spilled -= 1
            self.hot[key] = rec
            self._spill_if_needed(exclude=key)
            return rec

    def __setitem__(self, key: str, rec: dict) -> None:
        with self._lock:
            self.hot[key] = rec
            self._spill_if_needed(exclude=key)

    def __getitem__(self, key: str):
        rec = self.get(key)
        if rec is None:
            raise KeyError(key)
        return rec

    def __contains__(self, key: str) -> bool:
        with self._lock:
            if key in self.hot:
                return True
            if self._db is None:
                return False
            return self._db.execute("SELECT 1 FROM ep WHERE key=?",
                                    (key,)).fetchone() is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self.hot) + self._spilled

    # -- iteration -----------------------------------------------------------
    def values(self):
        """Read-only iteration over every record (hot first, then disk). Disk
        records are fresh copies · use map_inplace to persist a mutation."""
        with self._lock:
            hot_snapshot = list(self.hot.values())
            db = self._db
        yield from hot_snapshot
        if db is not None:
            cur = db.execute("SELECT rec FROM ep")
            while True:
                rows = cur.fetchmany(2000)
                if not rows:
                    break
                for (rec_json,) in rows:
                    yield json.loads(rec_json)

    def map_inplace(self, fn) -> None:
        """Apply fn(rec) to every record, persisting the change. Hot records are
        mutated in place; disk records are loaded, mutated and written back in
        batches, so peak memory is one batch rather than the whole table."""
        with self._lock:
            for rec in list(self.hot.values()):
                fn(rec)
            db = self._db
            if db is None:
                return
            last = 0
            while True:
                rows = db.execute(
                    "SELECT rowid, rec FROM ep WHERE rowid>? ORDER BY rowid LIMIT 2000",
                    (last,)).fetchall()
                if not rows:
                    break
                updates = []
                for rowid, rec_json in rows:
                    rec = json.loads(rec_json)
                    fn(rec)
                    updates.append((json.dumps(rec, ensure_ascii=False), rowid))
                    last = rowid
                db.executemany("UPDATE ep SET rec=? WHERE rowid=?", updates)
            db.commit()

    def sorted_stream(self):
        """Yield every record in the scan's canonical order (in-scope first, then
        host, url, method) with bounded memory · a huge scan serialises without
        the whole list ever being resident. When nothing spilled, sort the hot
        dict in memory, which is identical to the old path."""
        with self._lock:
            if self._db is None:
                snapshot = sorted(self.hot.values(), key=_sort_key)
                db = None
            else:
                self._flush_hot_locked()
                db = self._db
        if db is None:
            yield from snapshot
            return
        cur = db.execute("SELECT rec FROM ep ORDER BY in_scope DESC, host, url, method")
        while True:
            rows = cur.fetchmany(2000)
            if not rows:
                break
            for (rec_json,) in rows:
                yield json.loads(rec_json)

    def _flush_hot_locked(self) -> None:
        if not self.hot:
            return
        db = self._ensure_db()
        db.executemany(
            "INSERT OR REPLACE INTO ep(key,in_scope,host,url,method,rec) "
            "VALUES(?,?,?,?,?,?)", (self._row(k, r) for k, r in self.hot.items()))
        self._spilled += len(self.hot)
        self.hot.clear()
        db.commit()

    # -- teardown ------------------------------------------------------------
    def close(self, *, delete: bool = True) -> None:
        with self._lock:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    pass
                self._db = None
            if delete:
                for suffix in ("", "-wal", "-shm"):
                    try:
                        Path(str(self.path) + suffix).unlink()
                    except OSError:
                        pass
