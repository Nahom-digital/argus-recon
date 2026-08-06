"""
Small on-disk cache for external JSON lookups (ipinfo, Shodan, InternetDB, ...).

A recon run looks up the same handful of IPs from several stages. Without a cache
each stage re-hits the API and burns a rate limit that is often one request per
second; with one, the second lookup of an address is served straight off disk.
It also centralises the retry / backoff / 429-handling so every caller gets the
same well-behaved client without repeating it.

Entirely best-effort: a missing or corrupt cache file just means a fresh fetch,
and the cache directory is scratch under scans/.httpcache.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import config
from .util import get_logger

log = get_logger("httpcache")


def _path(key: str) -> Path:
    h = hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()
    return config.HTTP_CACHE_DIR / f"{h}.json"


def load(key: str, ttl: int | None = None):
    """Return the cached value for `key`, or None if absent/stale/disabled."""
    if not config.HTTP_CACHE_ENABLED:
        return None
    p = _path(key)
    try:
        st = p.stat()
    except OSError:
        return None
    ttl = config.HTTP_CACHE_TTL if ttl is None else ttl
    if ttl and (time.time() - st.st_mtime) > ttl:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def store(key: str, value) -> None:
    if not config.HTTP_CACHE_ENABLED:
        return
    try:
        config.HTTP_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _path(key).write_text(json.dumps(value), encoding="utf-8")
    except Exception:
        pass


def get_json(session, url: str, *, params: dict | None = None,
             headers: dict | None = None, timeout: int | None = None,
             ttl: int | None = None, retries: int = 3,
             cache_key: str | None = None):
    """GET `url` and return parsed JSON, with a disk cache and polite retries.

    Returns:
      * the decoded JSON object on a 200,
      * {"__status__": N} for any other status (404 is cached so a miss is not
        re-fetched every run · InternetDB answers 404 for hosts it has no data
        on, which is the common case),
      * None when the request could not be completed at all.
    """
    key = cache_key or (url + "?" + "&".join(
        f"{k}={v}" for k, v in sorted((params or {}).items()) if k != "key"))
    cached = load(key, ttl=ttl)
    if cached is not None:
        return cached

    timeout = timeout or config.HTTP_TIMEOUT
    backoff = 1.0
    for attempt in range(max(1, retries)):
        try:
            resp = session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as exc:
            log.debug(f"{url}: {exc} (attempt {attempt + 1})")
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)
            continue
        code = resp.status_code
        if code == 429:                       # rate limited · honour Retry-After
            ra = resp.headers.get("Retry-After", "")
            wait = float(ra) if ra.isdigit() else backoff
            time.sleep(min(wait, 30))
            backoff = min(backoff * 2, 20)
            continue
        if code == 404:
            miss = {"__status__": 404}
            store(key, miss)
            return miss
        if code != 200:
            return {"__status__": code}
        try:
            data = resp.json()
        except Exception:
            return {"__status__": 200, "__text__": resp.text[:2000]}
        store(key, data)
        return data
    return None
