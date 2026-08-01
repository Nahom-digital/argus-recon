"""
Module 2a · mass HTTP probe (source code "h").

Runs before fingerprinting and before the crawl. One pass over every discovered
host answers the questions the rest of the pipeline keeps asking:

  * is there a live HTTP service here, and on which scheme,
  * status / title / server / content-type / redirect target,
  * a first tech guess (headers, cookies, favicon, wappalyzer-style signatures),
  * which IP actually answered, and any CNAME in front of it.

Why it matters more than the numbers suggest: the crawler and the content brute
both start from "live roots". Before this stage that list came from a sequential
Python probe of every subdomain, and dead hosts stayed in it until something
timed out on them · so a scope with 300 mostly-parked subdomains spent most of
its time discovering nothing. This does the whole sweep at Go concurrency and
hands the pipeline only hosts that answered.

Nothing here is required: if the binary is absent, `run()` returns False and
modules.fingerprint falls back to its own asynchronous probe.
"""
from __future__ import annotations

import ipaddress
import json
import tempfile
import time
from pathlib import Path

from . import config, tor
from .schema import ScanResult
from .util import (get_logger, host_of, in_scope, pick_flag, resolve_recon_tool,
                   stream_cmd, tool_flags)

log = get_logger("probe")

SRC = config.SOURCE_CODES["httpx"]        # "h"

# Tech names httpx reports that say nothing about the stack.
_TECH_NOISE = {"HSTS", "HTTP/3", "IPv6", "Cloudflare Bot Management"}


def _is_ip(v) -> bool:
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except (ValueError, TypeError):
        return False


def binary() -> str | None:
    return resolve_recon_tool(config.HTTPX_BIN, config.TOOL_ALIASES.get("httpx"))


def available() -> bool:
    return bool(binary())


def _command(bin_path: str, list_file: Path) -> list[str]:
    proxy = tor.proxy_url("socks5")
    # A circuit carries a fraction of the parallelism a direct connection does;
    # asking for 150 threads through Tor just converts them into timeouts.
    threads = min(config.PROBE_THREADS, 15) if proxy else config.PROBE_THREADS
    rate = min(config.PROBE_RATE, 30) if proxy else config.PROBE_RATE
    flags = tool_flags(bin_path)
    cmd = [bin_path, "-list", str(list_file), "-json", "-silent"]

    def opt(*names, value=None):
        f = pick_flag(flags, *names)
        if f:
            cmd.append(f)
            if value is not None:
                cmd.append(str(value))

    opt("no-color", "nc")
    opt("status-code", "sc")
    opt("title")
    opt("tech-detect", "td")
    opt("web-server", "server")
    opt("content-type", "ct")
    opt("content-length", "cl")
    opt("location")
    opt("ip")
    opt("cname")
    opt("follow-redirects", "fr")
    opt("threads", "t", value=threads)
    opt("rate-limit", "rl", value=rate)
    opt("timeout", value=config.PROBE_TIMEOUT)
    opt("retries", "retry", value=config.PROBE_RETRIES)
    opt("disable-update-check", "duc")
    if proxy:
        opt("proxy", "http-proxy", value=proxy)
    return cmd


def _ingest(result: ScanResult, rec: dict) -> str | None:
    """Fold one httpx JSON line into the scan. Returns the host if it is live."""
    url = rec.get("final_url") or rec.get("url") or ""
    inp = (rec.get("input") or "").strip()
    host = host_of(url) or host_of(f"http://{inp}") or inp.split(":")[0].lower()
    if not host or rec.get("failed"):
        return None
    # A probe result for something outside the scope (a redirect chain that left
    # the domain) must not create a subdomain record.
    if not in_scope(f"http://{host}", result.domain):
        return None

    status = rec.get("status_code")
    scheme = rec.get("scheme") or ("https" if url.startswith("https") else "http")
    sub = result.add_subdomain(host, source=SRC)
    final = url or f"{scheme}://{host}"
    http = {
        "scheme": scheme,
        "status": status,
        "server": rec.get("webserver"),
        "content_type": rec.get("content_type"),
        "title": (rec.get("title") or "")[:200] or None,
        "final_url": final,
        "content_length": rec.get("content_length"),
        "redirected_offscope": bool(final) and not in_scope(final, result.domain),
        "probe": SRC,
    }
    if rec.get("location"):
        http["location"] = rec["location"]
    sub["http"].update({k: v for k, v in http.items() if v is not None})

    # tech tags · merged with (not overwritten by) the deep fingerprint later
    tags = [t for t in (rec.get("tech") or []) if t and t not in _TECH_NOISE]
    for t in tags:
        if t not in sub["tech"]:
            sub["tech"].append(t)

    # the address that actually answered, plus any A/AAAA records reported
    ips = [rec.get("host")] if rec.get("host") else []
    ips += list(rec.get("a") or []) + list(rec.get("aaaa") or [])
    for ip in ips:
        if _is_ip(ip):
            result._link_ip(sub, str(ip), source=SRC)    # type: ignore[attr-defined]
    for cname in (rec.get("cname") or []):
        cn = str(cname).rstrip(".").lower()
        if cn:
            sub.setdefault("cname", [])
            if cn not in sub["cname"]:
                sub["cname"].append(cn)

    # the probed root is a real, confirmed endpoint
    result.add_endpoint(final, etype="page", source=SRC, status=status,
                        content_type=rec.get("content_type"),
                        title=http["title"], in_scope=True)
    return host if status else None


def run(result: ScanResult, *, hosts: list[str] | None = None,
        timeout: int | None = None) -> bool:
    """Probe every known host. Returns False if the engine is unavailable."""
    bin_path = binary()
    if not bin_path:
        log.info("mass probe engine not installed · using the built-in async probe")
        return False

    t0 = time.time()
    targets = hosts or sorted(result._subdomains.keys())   # type: ignore[attr-defined]
    if not targets:
        result.mark_module("probe", "empty", note="no hosts", duration=0)
        return True

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("\n".join(targets))
        list_file = Path(fh.name)

    live: set[str] = set()
    seen = 0

    def on_line(line: str) -> None:
        nonlocal seen
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return
        seen += 1
        host = _ingest(result, rec)
        if host:
            live.add(host)
        if seen % 200 == 0:
            log.info(f"probed {seen} hosts · {len(live)} live so far")

    try:
        log.info(f"probing {len(targets)} hosts for live HTTP services "
                 f"(concurrency {config.PROBE_THREADS})")
        stream_cmd(_command(bin_path, list_file),
                   timeout=timeout or config.PROBE_MAXTIME,
                   on_line=on_line, log=log)
    finally:
        list_file.unlink(missing_ok=True)

    # Hosts the probe never answered for are not live. Recording that explicitly
    # is what stops the crawler and the brute from queuing them again.
    for host, sub in result._subdomains.items():          # type: ignore[attr-defined]
        if host not in live and not sub["http"].get("status"):
            sub["http"].setdefault("status", None)
            sub["http"].setdefault("error", "no-response")

    log.info(f"{len(live)}/{len(targets)} hosts answered HTTP "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("probe", "ok" if live else "empty",
                       note=f"{len(live)}/{len(targets)} live",
                       duration=time.time() - t0)
    return True


def live_roots(result: ScanResult) -> list[str]:
    """`scheme://host` for every host that answered · the seed list the crawler
    and the content brute both start from."""
    roots: list[str] = []
    for sub in result._subdomains.values():               # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("status") and not http.get("error"):
            roots.append(f"{http.get('scheme', 'https')}://{sub['host']}")
    return roots
