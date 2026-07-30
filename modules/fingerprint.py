"""
Module 2 — Tech-stack fingerprinting.

Runs WhatWeb in aggressive mode (`-a 3`) against every subdomain BBOT found. To
target the right scheme we first do a light probe (HTTPS then HTTP) which also
fills each subdomain's HTTP metadata (status, server, title, final URL) that the
crawler reuses as its seed. WhatWeb is invoked in batches, its JSON array parsed
into readable tech tags plus the raw plugin record.
"""
from __future__ import annotations

import json
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from . import config, tor
from .schema import ScanResult
from .util import (get_logger, make_session, resolve_tool, run_cmd, host_of,
                   in_scope, is_html)

log = get_logger("fingerprint")

# WhatWeb plugins that are informational rather than tech indicators.
_INFO_PLUGINS = {
    "Country", "IP", "Title", "UncommonHeaders", "Allow", "RedirectLocation",
    "Cookies", "HttpOnly", "Strict-Transport-Security", "X-Frame-Options",
    "X-XSS-Protection", "Content-Security-Policy", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin", "X-Content-Type-Options", "Via-Proxy",
    "Email", "HTML5", "Frame", "Script", "probably-", "Referrer-Policy",
    "Permissions-Policy", "Cache-Control", "Content-Language",
}


def _probe(sub: dict, session, domain: str) -> str | None:
    """Probe https then http; record HTTP metadata on the subdomain record and
    return the working in-scope root URL (or None)."""
    host = sub["host"]
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = session.get(url, timeout=config.HTTP_TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        final = resp.url
        title = None
        if is_html(resp.headers.get("Content-Type")):
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000],
                          re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        sub["http"] = {
            "scheme": scheme,
            "status": resp.status_code,
            "server": resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
            "content_type": resp.headers.get("Content-Type"),
            "title": title,
            "final_url": final,
            "redirected_offscope": bool(final) and not in_scope(final, domain),
        }
        return url  # fingerprint the in-scope root; WhatWeb follows redirects itself
    sub["http"] = {"status": None, "error": "no-response"}
    return None


def _extract_tags(plugins: dict) -> list[str]:
    tags: list[str] = []

    def add(t):
        t = re.sub(r"\s+", " ", str(t)).strip()
        if t and t not in tags:
            tags.append(t)

    for name, body in plugins.items():
        if any(name.startswith(p) or name == p for p in _INFO_PLUGINS):
            # still mine a couple of high-signal header plugins
            if name in ("HTTPServer",):
                for v in (body or {}).get("string", []):
                    add(v)
            continue
        version = ""
        if isinstance(body, dict) and body.get("version"):
            version = "/" + str(body["version"][0])
        if name in ("HTTPServer", "X-Powered-By", "PoweredBy", "MetaGenerator"):
            for v in (body or {}).get("string", []):
                add(v)
        else:
            add(f"{name}{version}")
    return tags


def _run_whatweb(urls: list[str], timeout: int) -> list[dict]:
    ww = resolve_tool(config.WHATWEB_BIN)
    if not ww:
        log.warning("WhatWeb not found — skipping fingerprint")
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out = Path(tf.name)
    try:
        cmd = [ww, "-a", "3", "--color=never", "--quiet",
               f"--max-threads={min(config.CRAWL_THREADS, 25)}",
               "--open-timeout=8", "--read-timeout=12",
               f"--log-json={out}"] + urls
        # WhatWeb only speaks to an HTTP proxy, so over Tor it has to be wrapped.
        if tor.active():
            wrapped = tor.wrap_cmd(cmd)
            if wrapped is None:
                log.warning("fingerprint engine skipped: Tor is on but torsocks is "
                            "not installed, and running it unwrapped would bypass Tor")
                return []
            cmd = wrapped
        proc = run_cmd(cmd, timeout=timeout, log=log)
        if proc is None:
            return []
        text = out.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return []
        # WhatWeb writes a JSON array, but a killed/partial run can leave it
        # unterminated — recover line by line.
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            recs = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{") and line.endswith("}"):
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return recs
    finally:
        out.unlink(missing_ok=True)


def run(result: ScanResult, *, timeout: int = 600, batch: int = 25) -> None:
    t0 = time.time()
    session = make_session()

    # 1. Probe each subdomain to find the live scheme + fill HTTP metadata.
    targets: dict[str, str] = {}   # host -> url
    subs = [s for s in result._subdomains.values()  # type: ignore[attr-defined]
            if s["resolved"] or s["host"] == result.domain]
    log.info(f"probing {len(subs)} resolving subdomains for live scheme")
    for sub in subs:
        url = _probe(sub, session, result.domain)
        if url:
            targets[sub["host"]] = url

    if not targets:
        log.warning("no live HTTP endpoints to fingerprint")
        result.mark_module("fingerprint", "empty", note="no live hosts",
                            duration=time.time() - t0)
        return

    # 2. WhatWeb -a 3 in batches.
    log.info(f"running WhatWeb -a 3 against {len(targets)} live hosts")
    url_list = list(targets.values())
    records: list[dict] = []
    for i in range(0, len(url_list), batch):
        chunk = url_list[i:i + batch]
        records += _run_whatweb(chunk, timeout=timeout)

    # 3. Map results back to subdomains by host.
    by_host: dict[str, dict] = {}
    for rec in records:
        h = host_of(rec.get("target", ""))
        if h:
            by_host.setdefault(h, rec)  # first (usually final) response per host

    tagged = 0
    for host, url in targets.items():
        rec = by_host.get(host)
        if not rec:
            continue
        plugins = rec.get("plugins", {})
        tags = _extract_tags(plugins)
        sub = result.add_subdomain(host)
        sub["tech"] = tags
        sub["whatweb"] = {
            "target": rec.get("target"),
            "http_status": rec.get("http_status"),
            "plugins": sorted(plugins.keys()),
        }
        # The fingerprint's IP plugin can reveal an address DNS missed.
        for ip in plugins.get("IP", {}).get("string", []):
            result._link_ip(sub, ip, source=config.SOURCE_CODES["whatweb"])  # type: ignore[attr-defined]
        if tags:
            tagged += 1

    log.info(f"fingerprinted {tagged}/{len(targets)} hosts")
    result.mark_module("fingerprint", "ok", note=f"{tagged} hosts tagged",
                       duration=time.time() - t0)
