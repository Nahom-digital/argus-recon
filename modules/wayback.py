"""
Module 3b · Wayback Machine archive mining (source code "y").

The internet archive has been crawling these hosts for years. Everything it
recorded is a URL that existed at some point: retired admin panels, forgotten
API versions, backup files someone published once and deleted, query strings
that name parameters the live site no longer exposes. None of it costs the
target a single request, and none of it is reachable by crawling what is live
today.

Two ways to ask, in order of preference:

  * `waybackurls` (the Go tool) when it is installed · fastest, and it also
    pulls the Common Crawl index alongside the archive,
  * the archive's own CDX API over plain HTTP otherwise · no binary needed, so
    this stage always contributes something.

What lands in the scan:

  * every archived URL as an endpoint tagged with this module's source code, so
    a finding the live crawl also reached simply carries both sources,
  * archived files (js, json, config, backup, sql, env, …) into the file list
    with the archive's recorded status code and content type where the CDX
    index provides them,
  * the in-scope, GET-able ones handed back as crawl seeds, so the crawler
    re-checks today whether an URL the archive remembers is still alive.

Nothing here is fatal: no binary, no network, a rate limit or a slow archive
degrades to "nothing added" rather than raising.
"""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from . import config, tor
from .schema import ScanResult
from .util import (classify_resource, get_logger, host_of, in_scope,
                   is_interesting_file, is_javascript, make_session,
                   normalize_url, resolve_tool, single_host, stream_cmd)

log = get_logger("wayback")

SRC = config.SOURCE_CODES["wayback"]        # "y" · the tool name never leaks

# Archive noise: assets nobody is hunting, and the archive's own furniture.
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
             ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi",
             ".mov", ".webm", ".css.map")


def binary() -> str | None:
    return resolve_tool(config.WAYBACK_BIN)


def available() -> bool:
    """True whenever this stage can contribute · the CDX fallback needs no
    binary, so the only way it is unavailable is being switched off."""
    return True


# --------------------------------------------------------------------------- #
# Record ingestion
# --------------------------------------------------------------------------- #
def _worth_keeping(url: str) -> bool:
    path = urlparse(url).path.lower()
    if path.endswith(_SKIP_EXT):
        return False
    # the archive stores its own redirect wrappers; they are not the target
    return "web.archive.org" not in url


def _ingest(result: ScanResult, url: str, *, status=None, mime=None,
            seeds: set[str]) -> bool:
    """Record one archived URL. Returns True when it was in scope."""
    norm = normalize_url(url)
    if not norm or not _worth_keeping(norm):
        return False
    scoped = in_scope(norm, result.domain)
    etype = "js" if is_javascript(norm, mime) else "link"
    result.add_endpoint(norm, method="GET", etype=etype, source=SRC,
                        in_scope=scoped, status=status, content_type=mime,
                        note="seen in the web archive")
    if not scoped:
        return False

    host = host_of(norm)
    if host:
        result.add_subdomain(host, source=SRC)
    # Only the kinds the file list is for (config, backup, data, archive,
    # document) · every archived page is already an endpoint above.
    if is_interesting_file(norm, mime):
        kind, sub = classify_resource(norm, mime)
        result.add_file(norm, kind=kind, subtype=sub, source=SRC,
                        status=status, content_type=mime)
    if etype == "js":
        result.add_js_file(norm, source=SRC)
    seeds.add(norm)
    return True


# --------------------------------------------------------------------------- #
# Source 1 · the waybackurls binary
# --------------------------------------------------------------------------- #
def _from_binary(result: ScanResult, bin_path: str, targets: list[str],
                 seeds: set[str], timeout: int) -> int:
    """Feed the hosts in on stdin (one per line · the tool's own interface) and
    ingest each URL it prints."""
    kept = 0
    seen = 0

    def on_line(line: str) -> None:
        nonlocal kept, seen
        url = line.strip()
        if not url or not url.startswith(("http://", "https://")):
            return
        seen += 1
        if seen > config.WAYBACK_MAX_URLS:
            return
        if _ingest(result, url, seeds=seeds):
            kept += 1
        if seen % 2000 == 0:
            log.info(f"archive: {seen} URLs read, {len(seeds)} in scope")

    stream_cmd([bin_path], timeout=timeout, on_line=on_line, log=log,
               stdin_data="\n".join(targets) + "\n")
    log.info(f"archive (engine): {seen} URLs → {kept} in scope")
    return kept


# --------------------------------------------------------------------------- #
# Source 2 · the CDX index over HTTP (no binary required)
# --------------------------------------------------------------------------- #
def _cdx_rows(session, target: str, timeout: int) -> list[list]:
    """One CDX query. Returns the rows without the header, or []."""
    params = {
        "url": target,
        "output": "json",
        "fl": "original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(config.WAYBACK_CDX_LIMIT),
        "filter": "!statuscode:404",
    }
    try:
        resp = session.get(config.WAYBACK_CDX_URL, params=params, timeout=timeout)
    except Exception as exc:
        log.info(f"archive request failed for {target}: {exc}")
        return []
    if resp.status_code == 429:
        log.warning("archive rate limit hit · backing off")
        time.sleep(2.0)
        return []
    if resp.status_code != 200:
        log.info(f"archive http {resp.status_code} for {target}")
        return []
    try:
        rows = resp.json()
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    return rows[1:]                       # row 0 is the column header


def _from_cdx(result: ScanResult, targets: list[str], seeds: set[str],
              timeout: int) -> int:
    session = make_session()
    kept = 0
    seen = 0
    for target in targets:
        if seen > config.WAYBACK_MAX_URLS:
            break
        for row in _cdx_rows(session, target, timeout):
            if not row:
                continue
            url = row[0]
            status = None
            if len(row) > 1:
                try:
                    status = int(row[1])
                except (TypeError, ValueError):
                    status = None
            mime = row[2] if len(row) > 2 and row[2] not in ("warc/revisit",) else None
            seen += 1
            if seen > config.WAYBACK_MAX_URLS:
                break
            if _ingest(result, url, status=status, mime=mime, seeds=seeds):
                kept += 1
    log.info(f"archive (index): {seen} URLs → {kept} in scope")
    return kept


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _hosts(result: ScanResult) -> list[str]:
    """The bare host(s) this run is allowed to ask about · one in single-target
    mode, the apex otherwise (which covers its subdomains)."""
    if single_host():
        known = sorted(result._subdomains)          # type: ignore[attr-defined]
        return known[:1] or [result.domain]
    return [result.domain]


def _cdx_patterns(result: ScanResult) -> list[str]:
    """The same targets in the CDX index's URL-pattern syntax. A wildcard host
    is how that API is asked for a whole estate; the binary takes a bare
    hostname instead and widens to subdomains on its own, so the two forms are
    kept apart rather than shared."""
    if single_host():
        return [f"{h}/*" for h in _hosts(result)]
    return [f"*.{result.domain}/*"]


def run(result: ScanResult, *, timeout: int | None = None) -> list[str]:
    """Mine the web archive for URLs this domain used to serve. Returns the
    in-scope URLs to seed the crawler with (possibly empty · never None, this
    stage always has a path that works)."""
    t0 = time.time()
    timeout = timeout or config.WAYBACK_TIMEOUT
    hosts = _hosts(result)
    patterns = _cdx_patterns(result)
    seeds: set[str] = set()

    bin_path = binary()
    if tor.active() and bin_path:
        # The binary talks to the archive directly and has no proxy switch, so
        # over Tor the HTTP path (which honours the session proxy) is the only
        # one that keeps the circuit intact.
        log.info("archive: using the index over Tor (the engine cannot be proxied)")
        bin_path = None

    log.info(f"mining the web archive for {', '.join(hosts)}"
             + (" (engine)" if bin_path else " (index)"))
    try:
        if bin_path:
            kept = _from_binary(result, bin_path, hosts, seeds, timeout)
            if not kept:
                # engine present but silent (network, rate limit) · try the index
                kept = _from_cdx(result, patterns, seeds, timeout)
        else:
            kept = _from_cdx(result, patterns, seeds, timeout)
    except Exception as exc:
        log.warning(f"archive mining failed: {exc}")
        result.mark_module("wayback", "empty", note=str(exc)[:120],
                           duration=time.time() - t0)
        return []

    log.info(f"web archive: {len(seeds)} in-scope URLs recovered "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("wayback", "ok" if seeds else "empty",
                       note=f"{kept} archived URLs, {len(seeds)} seeds",
                       duration=time.time() - t0)
    return sorted(seeds)
