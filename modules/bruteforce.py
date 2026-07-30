"""
Module 6 — Smart content bruteforce.

For every live subdomain root:

  1. read robots.txt and sitemap.xml first for free path hints (recorded as
     endpoints and folded into the wordlist),
  2. generate a targeted wordlist from the detected tech stack — CMS/framework
     specific paths (config.STACK_WORDLISTS) plus a stack-agnostic base list and
     any robots/sitemap hints,
  3. run ffuf with that list and the standard extension set
     (xml, json, conf, bak, env, sql, yml), with auto-calibration to suppress
     wildcard/catch-all noise.

Discovered paths become endpoints (source=bruteforce); file-like hits are also
recorded as discovered files.
"""
from __future__ import annotations

import json
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from . import config, tor
from .schema import ScanResult
from .util import (get_logger, make_session, resolve_tool, run_cmd, normalize_url,
                   in_scope, classify_resource, is_interesting_file, path_ext)

log = get_logger("bruteforce")

SRC_FFUF = config.SOURCE_CODES["ffuf"]  # "f" — the tool name never reaches the JSON
_RESP_HEADER_KEYS = ("server", "content-type", "content-length", "location",
                     "set-cookie", "x-powered-by", "last-modified", "etag",
                     "content-disposition", "www-authenticate")


def _capture_file(session, url: str) -> dict:
    """Fetch a discovered file (capped) so the Files panel can show the request
    and response (item 10). Best-effort; returns {} on failure."""
    try:
        resp = session.get(url, timeout=config.HTTP_TIMEOUT, allow_redirects=True, stream=True)
    except Exception:
        return {}
    ct = resp.headers.get("Content-Type", "")
    kind = classify_resource(resp.url, ct)[0]
    body = ""
    if kind not in ("image", "font", "archive", "media"):
        try:
            raw = resp.raw.read(6000, decode_content=True) or b""
            body = raw.decode(resp.encoding or "utf-8", "replace")
        except Exception:
            body = ""
    resp.close()
    return {
        "status": resp.status_code,
        "content_type": ct,
        "final_url": resp.url,
        "req_headers": dict(session.headers),
        "resp_headers": {k: v for k, v in resp.headers.items()
                         if k.lower() in _RESP_HEADER_KEYS},
        "resp_body": body,
    }


# --------------------------------------------------------------------------- #
# robots.txt / sitemap.xml
# --------------------------------------------------------------------------- #
def read_robots(result: ScanResult, session, root: str) -> set[str]:
    words: set[str] = set()
    url = normalize_url("/robots.txt", root)
    try:
        resp = session.get(url, timeout=config.HTTP_TIMEOUT)
    except Exception:
        return words
    if resp.status_code != 200 or "html" in resp.headers.get("Content-Type", ""):
        return words
    result.add_file(url, kind="config", subtype="robots", source="robots",
                    status=200, found_on=root, content_type=resp.headers.get("Content-Type"),
                    req_headers=dict(session.headers),
                    resp_headers={k: v for k, v in resp.headers.items()
                                  if k.lower() in _RESP_HEADER_KEYS},
                    resp_body=resp.text[:4000])
    for line in resp.text.splitlines():
        line = line.strip()
        m = re.match(r"(?:Dis)?[Aa]llow:\s*(\S+)", line)
        if m:
            path = m.group(1).split("*")[0].split("?")[0]
            if path and path.startswith("/"):
                full = normalize_url(path, root)
                if full and in_scope(full, result.domain):
                    result.add_endpoint(full, etype="link", source="robots",
                                        found_on=url, in_scope=True)
                for seg in path.strip("/").split("/"):
                    if seg and len(seg) < 40:
                        words.add(seg)
        m = re.match(r"[Ss]itemap:\s*(\S+)", line)
        if m:
            words |= read_sitemap(result, session, m.group(1))
    return words


def read_sitemap(result: ScanResult, session, sitemap_url: str, _depth: int = 0) -> set[str]:
    words: set[str] = set()
    if _depth > 2:
        return words
    try:
        resp = session.get(sitemap_url, timeout=config.HTTP_TIMEOUT)
        if resp.status_code != 200:
            return words
        root_el = ET.fromstring(resp.content)
    except Exception:
        return words
    ns = re.match(r"\{.*\}", root_el.tag)
    ns = ns.group(0) if ns else ""
    if root_el.tag.endswith("sitemapindex"):
        for loc in root_el.iterfind(f".//{ns}loc"):
            if loc.text:
                words |= read_sitemap(result, session, loc.text.strip(), _depth + 1)
        return words
    result.add_file(sitemap_url, kind="data", subtype="sitemap", source="sitemap",
                    status=200)
    for loc in root_el.iterfind(f".//{ns}loc"):
        if not loc.text:
            continue
        full = normalize_url(loc.text.strip())
        if full and in_scope(full, result.domain):
            result.add_endpoint(full, etype="link", source="sitemap",
                                found_on=sitemap_url, in_scope=True)
            for seg in urlparse(full).path.strip("/").split("/"):
                if seg and len(seg) < 40 and "." not in seg:
                    words.add(seg)
    return words


# --------------------------------------------------------------------------- #
# Wordlist generation
# --------------------------------------------------------------------------- #
def generate_wordlist(tech_tags: list[str], hints: set[str]) -> tuple[list[str], list[str]]:
    """Base list + stack-specific paths (matched from the fingerprint) + hints."""
    words: list[str] = list(config.BASE_WORDS)
    tech_blob = " ".join(tech_tags).lower()
    matched_stacks = []
    for stack, paths in config.STACK_WORDLISTS.items():
        if stack in tech_blob:
            matched_stacks.append(stack)
            words.extend(paths)
    words.extend(sorted(hints))
    # De-dup preserving order.
    seen, out = set(), []
    for w in words:
        w = w.strip().lstrip("/")
        if w and w not in seen:
            seen.add(w)
            out.append(w)
    return out, matched_stacks


# --------------------------------------------------------------------------- #
# ffuf
# --------------------------------------------------------------------------- #
def _run_ffuf(root: str, wordlist: Path, timeout: int, maxtime: int) -> list[dict]:
    ffuf = resolve_tool(config.FFUF_BIN)
    if not ffuf:
        log.warning("ffuf not found — skipping bruteforce for %s", root)
        return []
    fuzz_url = root.rstrip("/") + "/FUZZ"
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out = Path(tf.name)
    try:
        # ffuf is a Go binary — torsocks (an LD_PRELOAD shim) cannot cover it, so
        # over Tor it gets the SOCKS proxy natively. A circuit is far slower than
        # a direct connection, so the fan-out comes down with it or everything
        # just times out.
        proxy = tor.proxy_url("socks5")
        threads = min(config.BRUTE_THREADS, 8) if proxy else config.BRUTE_THREADS
        cmd = [
            ffuf, "-w", f"{wordlist}:FUZZ", "-u", fuzz_url,
            "-mc", config.BRUTE_STATUS_MATCH,
            "-e", ",".join("." + e for e in config.BRUTE_EXTENSIONS),
            "-t", str(threads), "-ac", "-noninteractive", "-s",
            "-maxtime", str(maxtime), "-timeout", "8",
            "-o", str(out), "-of", "json",
        ]
        if proxy:
            cmd += ["-x", proxy]
        proc = run_cmd(cmd, timeout=timeout, log=log)
        if proc is None:
            return []
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="replace") or "{}")
        except json.JSONDecodeError:
            return []
        return data.get("results", []) or []
    finally:
        out.unlink(missing_ok=True)


def _ingest_results(result: ScanResult, root: str, results: list[dict],
                    session=None, capture_budget: int = 40) -> int:
    added = 0
    captured = 0
    for r in results:
        url = normalize_url(r.get("url", ""))
        if not url or not in_scope(url, result.domain):
            continue
        status = r.get("status")
        ct = r.get("content-type", "")
        result.add_endpoint(url, etype="link", source=SRC_FFUF,
                            found_on=root, in_scope=True, status=status,
                            content_type=ct,
                            note=f"content-brute hit ({r.get('length')} bytes)")
        if is_interesting_file(url, ct) or path_ext(url):
            kind, sub = classify_resource(url, ct)
            if kind not in ("page",):
                extra = {}
                # fetch a bounded number of file hits to capture request/response
                if session is not None and captured < capture_budget:
                    extra = _capture_file(session, url)
                    if extra:
                        captured += 1
                result.add_file(url, kind=kind, subtype=sub, source=SRC_FFUF,
                                status=extra.get("status", status), found_on=root,
                                content_type=extra.get("content_type") or ct,
                                final_url=extra.get("final_url"),
                                req_headers=extra.get("req_headers"),
                                resp_headers=extra.get("resp_headers"),
                                resp_body=extra.get("resp_body"))
        added += 1
    return added


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(result: ScanResult, *, timeout: int = 240, maxtime: int = 120,
        max_hosts: int | None = None) -> None:
    t0 = time.time()
    session = make_session()

    live = [s for s in result._subdomains.values()  # type: ignore[attr-defined]
            if (s.get("http") or {}).get("status") and not (s.get("http") or {}).get("error")]
    if max_hosts:
        live = live[:max_hosts]

    if not live:
        log.warning("no live hosts to bruteforce")
        result.mark_module("bruteforce", "empty", duration=time.time() - t0)
        return

    total_hits = 0
    for sub in live:
        scheme = (sub.get("http") or {}).get("scheme", "https")
        root = f"{scheme}://{sub['host']}"
        log.info(f"[{sub['host']}] robots/sitemap + wordlist gen")
        hints = read_robots(result, session, root)
        words, stacks = generate_wordlist(sub.get("tech", []), hints)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as wf:
            wf.write("\n".join(words))
            wl = Path(wf.name)
        try:
            log.info(f"[{sub['host']}] ffuf {len(words)} words × ext set"
                     + (f" (stacks: {', '.join(stacks)})" if stacks else ""))
            results = _run_ffuf(root, wl, timeout=timeout, maxtime=maxtime)
            hits = _ingest_results(result, root, results, session=session)
            total_hits += hits
            log.info(f"[{sub['host']}] {hits} paths found")
        finally:
            wl.unlink(missing_ok=True)

    log.info(f"bruteforce complete: {total_hits} paths across {len(live)} hosts")
    result.mark_module("bruteforce", "ok", note=f"{total_hits} paths",
                       duration=time.time() - t0)
