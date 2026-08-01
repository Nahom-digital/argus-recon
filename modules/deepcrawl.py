"""
Module 3a · JS-aware deep crawl pre-pass (source code "k").

Runs before our own crawler and hands it a map of the application instead of a
list of roots. Where the built-in crawler fetches HTML and reads what is in the
markup, this engine also parses the JavaScript that builds the markup: bundled
route tables, lazily-imported chunks, XHR/fetch targets assembled at runtime, and
(optionally) a real headless render for applications whose HTML is an empty div.

What it contributes to the scan:

  * endpoints and request URLs discovered in JS · the class of finding a
    regex-over-source pass systematically misses, because the string never
    appears whole in the file,
  * the source that referenced each one (tag/attribute), kept as provenance,
  * live status codes and technologies for what it visited.

Our own crawler still runs after it. It is what fetches bodies, extracts forms
and fields, maps buttons to the requests they fire and scans for secrets · this
stage does discovery, not analysis, so both are needed and neither duplicates
the other's work.

Absent binary: `run()` returns False and the pipeline proceeds with the built-in
crawler alone.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from . import config, tor
from .schema import ScanResult
from .util import (get_logger, host_of, in_scope, normalize_url, pick_flag,
                   resolve_recon_tool, single_host, stream_cmd, tool_flags)

log = get_logger("deepcrawl")

SRC = config.SOURCE_CODES["katana"]        # "k"

# tag/attribute pairs that mean "this URL is fetched by code, not navigated to"
_XHR_TAGS = {"xhr", "fetch", "websocket", "ajax"}


def binary() -> str | None:
    return resolve_recon_tool(config.KATANA_BIN, config.TOOL_ALIASES.get("katana"))


def available() -> bool:
    return bool(binary())


def _command(bin_path: str, list_file: Path) -> list[str]:
    proxy = tor.proxy_url("socks5")
    conc = min(config.KATANA_CONCURRENCY, 5) if proxy else config.KATANA_CONCURRENCY
    par = min(config.KATANA_PARALLEL, 3) if proxy else config.KATANA_PARALLEL
    rate = min(config.KATANA_RATE, 20) if proxy else config.KATANA_RATE
    flags = tool_flags(bin_path)
    cmd = [bin_path, "-list", str(list_file), "-json", "-silent"]

    def opt(*names, value=None):
        f = pick_flag(flags, *names)
        if f:
            cmd.append(f)
            if value is not None:
                cmd.append(str(value))

    opt("no-color", "nc")
    opt("js-crawl", "jc")               # parse JS files for endpoints
    opt("jsluice", "jsl")               # deeper JS extraction where supported
    opt("xhr-extraction", "xhr")        # method + URL of runtime requests
    opt("known-files", "kf", value="all")   # robots.txt / sitemap.xml
    opt("depth", "d", value=config.KATANA_DEPTH)
    opt("concurrency", "c", value=conc)
    opt("parallelism", "p", value=par)
    opt("rate-limit", "rl", value=rate)
    opt("timeout", value=config.PROBE_TIMEOUT)
    # Scope: the whole registrable domain, or exactly one host in single-target
    # mode. The engine enforces it too, and every record is re-checked here.
    opt("field-scope", "fs", value="fqdn" if single_host() else "rdn")
    opt("disable-update-check", "duc")
    if config.KATANA_HEADLESS:
        opt("headless", "hl")
        opt("no-sandbox", "ns")
    if proxy:
        opt("proxy", value=proxy)
    return cmd


def _flatten(rec: dict) -> dict:
    """katana's JSON shape moved from flat keys to request/response objects.
    Normalise both into one dict."""
    req = rec.get("request") if isinstance(rec.get("request"), dict) else {}
    resp = rec.get("response") if isinstance(rec.get("response"), dict) else {}
    return {
        "url": req.get("endpoint") or rec.get("endpoint") or rec.get("url") or "",
        "method": (req.get("method") or rec.get("method") or "GET").upper(),
        "source": req.get("source") or rec.get("source") or "",
        "tag": (req.get("tag") or rec.get("tag") or "").lower(),
        "attribute": req.get("attribute") or rec.get("attribute") or "",
        "body": req.get("body") or rec.get("body") or "",
        "status": resp.get("status_code") or rec.get("status_code"),
        "content_type": (resp.get("headers") or {}).get("content_type")
                        or (resp.get("headers") or {}).get("Content-Type"),
        "tech": resp.get("technologies") or [],
    }


def _etype(flat: dict, url: str) -> str:
    tag = flat["tag"]
    if tag in _XHR_TAGS or flat["method"] not in ("GET", ""):
        return "xhr"
    if tag == "form":
        return "form"
    if url.split("?")[0].endswith((".js", ".mjs", ".jsx", ".ts")):
        return "js"
    if tag in ("script", "link", "img", "source", "iframe", "video", "audio"):
        return "resource"
    return "link"


def _ingest(result: ScanResult, flat: dict, seeds: set[str]) -> bool:
    raw = flat["url"]
    if not raw:
        return False
    url = normalize_url(raw, flat["source"] or None)
    if not url:
        return False
    scoped = in_scope(url, result.domain)
    etype = _etype(flat, url)
    note = f"{flat['tag']}/{flat['attribute']}".strip("/") or None

    rec = result.add_endpoint(
        url, method=flat["method"], etype=etype, source=SRC,
        found_on=flat["source"] or None, in_scope=scoped,
        status=flat["status"], content_type=flat["content_type"],
        note=(f"deep crawl · {note}" if note else "deep crawl"))
    if flat["body"]:
        rec["req_body"] = rec["req_body"] or flat["body"][:config.MAX_BODY_STORE]

    if not scoped:
        return False

    host = host_of(url)
    if host:
        sub = result.add_subdomain(host, source=SRC)
        for t in flat["tech"]:
            if t and t not in sub["tech"]:
                sub["tech"].append(t)
    if etype == "js":
        result.add_js_file(url, source=SRC, found_on=flat["source"] or None)
    # Only GET-able things are worth handing to the crawler as a seed; a POST
    # target is recorded but never fetched (the crawler does not send bodies).
    if flat["method"] in ("GET", ""):
        seeds.add(url)
    return True


def run(result: ScanResult, *, roots: list[str] | None = None,
        timeout: int | None = None) -> list[str] | None:
    """Deep-crawl every live root. Returns the in-scope URLs to seed our crawler
    with, or None if the engine is unavailable."""
    bin_path = binary()
    if not bin_path:
        log.info("deep crawl engine not installed · the built-in crawler runs alone")
        return None

    t0 = time.time()
    targets = list(roots or [])
    if not targets:
        log.warning("no live roots to deep-crawl")
        result.mark_module("deepcrawl", "empty", duration=0)
        return []

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("\n".join(targets))
        list_file = Path(fh.name)

    seeds: set[str] = set()
    kept = 0
    seen = 0

    def on_line(line: str) -> None:
        nonlocal kept, seen
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return
        seen += 1
        if _ingest(result, _flatten(rec), seeds):
            kept += 1
        if seen % 500 == 0:
            log.info(f"deep crawl: {seen} records, {len(seeds)} in-scope URLs")

    try:
        log.info(f"deep-crawling {len(targets)} roots (depth {config.KATANA_DEPTH}, "
                 f"JS parsing on{', headless' if config.KATANA_HEADLESS else ''})")
        stream_cmd(_command(bin_path, list_file),
                   timeout=timeout or config.KATANA_TIMEOUT,
                   on_line=on_line, log=log)
    finally:
        list_file.unlink(missing_ok=True)

    log.info(f"deep crawl complete: {seen} records → {kept} in-scope endpoints, "
             f"{len(seeds)} crawl seeds ({time.time() - t0:.1f}s)")
    result.mark_module("deepcrawl", "ok" if seen else "empty",
                       note=f"{kept} endpoints, {len(seeds)} seeds",
                       duration=time.time() - t0)
    return sorted(seeds)
