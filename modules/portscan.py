"""
Module 7a · port / service scan (source code "p").

Every other stage looks at the target's *web* surface. This one looks at the
hosts behind it: for each discovered IP it enumerates open ports and, for each,
the service, product and version answering there, an OS guess, the default
script findings and a traceroute. That is the layer that turns "this domain
resolves to 203.0.113.10" into "203.0.113.10 is running OpenSSH 9.2 on 22, a
Postgres on 5432 that should not be public, and an admin panel on 8443".

It is deliberately opt-in (a dashboard toggle next to "Via Tor"), because unlike
the passive/web stages it probes infrastructure directly: it is slow and it is
loud. Results fold into the existing IP records (schema.add_port), so the
Infrastructure panel and the graph gain a Port layer without a new top-level
store. Open HTTP(S) ports found off 80/443 are returned as extra crawl seeds.

The engine's real name never appears in a finding, a log line or the saved JSON
· every result is tagged with the source code "p" like every other stage, and
the scanner is resolved through config.PORTSCAN_BIN so it can be swapped without
touching this module.

Nothing here is required: if the scanner is not installed, `run()` marks the
module unavailable and the pipeline continues.
"""
from __future__ import annotations

import ipaddress
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, tor
from .schema import ScanResult
from .util import get_logger, resolve_tool, run_cmd

log = get_logger("portscan")

SRC = config.SOURCE_CODES["portscan"]        # "p"

# HTTP-ish services whose open port off 80/443 is worth crawling.
_WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt",
                 "ssl/http", "http-mgmt", "sun-answerbook"}


def binary() -> str | None:
    return resolve_tool(config.PORTSCAN_BIN)


def available() -> bool:
    return bool(binary())


def _is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def _command(bin_path: str, ip: str) -> list[str]:
    """Build the scan command for one address.

    Direct: the aggressive profile as configured (service/version, OS, scripts,
    traceroute). Over Tor: raw-packet features (SYN scan, OS detection,
    traceroute) cannot cross a SOCKS proxy, so the run is wrapped in torsocks and
    reduced to a TCP-connect scan with version + default scripts · still the
    service/version intel, routed through the circuit, minus what the transport
    physically cannot carry.
    """
    proxy = tor.active()
    args = list(config.PORTSCAN_ARGS)
    cmd: list[str] = []
    if proxy:
        ts = resolve_tool(config.TORSOCKS_BIN)
        # -A implies raw packets; swap it for connect-scan + version + scripts.
        args = [a for a in args if a != "-A"]
        args += ["-sT", "-sV", "-sC", "-Pn"]
        if ts:
            cmd += [ts]
    cmd += [bin_path, *args, "-n", "-oX", "-"]
    if _is_ipv6(ip):
        cmd.append("-6")
    cmd.append(ip)
    return cmd


def _text(el, default=None):
    return el.get("name") if el is not None else default


def _parse_host(host_el) -> dict:
    """Turn one <host> element into {ports, os, traceroute}."""
    ports: list[dict] = []
    for p in host_el.findall("./ports/port"):
        state_el = p.find("state")
        if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
            continue
        svc = p.find("service")
        cpe = [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text]
        scripts = {}
        for s in p.findall("script"):
            sid, out = s.get("id"), s.get("output")
            if sid and out:
                scripts[sid] = out.strip()[:1000]
        ports.append({
            "port": int(p.get("portid")),
            "protocol": p.get("protocol", "tcp"),
            "state": state_el.get("state"),
            "reason": state_el.get("reason"),
            "service": svc.get("name") if svc is not None else None,
            "product": svc.get("product") if svc is not None else None,
            "version": svc.get("version") if svc is not None else None,
            "extrainfo": svc.get("extrainfo") if svc is not None else None,
            "tunnel": svc.get("tunnel") if svc is not None else None,
            "cpe": cpe,
            "scripts": scripts,
        })

    os_guess = None
    best = host_el.find("./os/osmatch")
    if best is not None:
        cls = best.find("osclass")
        os_guess = {
            "name": best.get("name"),
            "accuracy": int(best.get("accuracy") or 0),
            "family": cls.get("osfamily") if cls is not None else None,
            "vendor": cls.get("vendor") if cls is not None else None,
        }

    trace = []
    for hop in host_el.findall("./trace/hop"):
        trace.append({
            "hop": int(hop.get("ttl") or 0),
            "ip": hop.get("ipaddr"),
            "rtt": hop.get("rtt"),
            "host": hop.get("host") or None,
        })
    return {"ports": ports, "os": os_guess, "traceroute": trace}


def _scan_one(bin_path: str, ip: str, timeout: int) -> dict | None:
    cmd = _command(bin_path, ip)
    proc = run_cmd(cmd, timeout=timeout, log=log)
    if proc is None or not proc.stdout:
        return None
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        # A cut-off XML (timeout mid-write) still often has a usable <host> · try
        # to recover the last complete host block rather than lose the whole scan.
        chunk = proc.stdout
        end = chunk.rfind("</host>")
        if end == -1:
            return None
        start = chunk.rfind("<host", 0, end)
        if start == -1:
            return None
        try:
            root = ET.fromstring(chunk[start:end + len("</host>")])
            return _parse_host(root)
        except ET.ParseError:
            return None
    host_el = root.find("host")
    return _parse_host(host_el) if host_el is not None else {"ports": [], "os": None, "traceroute": []}


def _select_targets(result: ScanResult) -> list[str]:
    """Addresses to scan, most-connected first, capped. A public address is
    worth the time; private/reserved space (a CNAME that resolved to 10.x, a
    scan run from inside a network) is skipped · it is noise, not attack
    surface."""
    scored: list[tuple[int, str]] = []
    for rec in result._ips.values():              # type: ignore[attr-defined]
        ip = rec["ip"]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            continue
        scored.append((len(rec.get("subdomains") or []), ip))
    scored.sort(key=lambda t: t[0], reverse=True)
    ips = [ip for _, ip in scored]
    if config.PORTSCAN_MAX_TARGETS > 0:
        ips = ips[:config.PORTSCAN_MAX_TARGETS]
    return ips


def run(result: ScanResult, *, timeout: int | None = None) -> bool:
    """Scan every discovered public IP for open ports/services. Returns False if
    the scanner is not installed (the caller records the stage as unavailable)."""
    bin_path = binary()
    if not bin_path:
        log.warning("port scan engine not installed · skipping "
                    "(the Infrastructure panel keeps its DNS/enrichment data)")
        result.mark_module("portscan", "skip", note="engine not installed")
        return False

    t0 = time.time()
    targets = _select_targets(result)
    if not targets:
        log.info("no public IPs to scan")
        result.mark_module("portscan", "empty", note="no public IPs", duration=0)
        return True

    per_timeout = timeout or config.PORTSCAN_TIMEOUT
    workers = max(1, min(config.PORTSCAN_PARALLEL, len(targets)))
    log.info(f"scanning {len(targets)} IP{'s' if len(targets) != 1 else ''} for "
             f"open ports & services ({workers} at a time"
             + (", over Tor" if tor.active() else "") + ")")

    seeds: list[str] = []
    total_ports = 0
    scanned = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_scan_one, bin_path, ip, per_timeout): ip for ip in targets}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                parsed = fut.result()
            except Exception as exc:
                log.debug(f"scan of {ip} failed: {exc}")
                parsed = None
            rec = result.add_ip(ip, source=SRC)
            rec["scanned"] = True
            scanned += 1
            if not parsed:
                continue
            if parsed.get("os"):
                rec["os"] = parsed["os"]
            if parsed.get("traceroute"):
                rec["traceroute"] = parsed["traceroute"]
            for p in parsed["ports"]:
                result.add_port(ip, p["port"], protocol=p["protocol"],
                                state=p["state"], service=p.get("service"),
                                product=p.get("product"), version=p.get("version"),
                                extrainfo=p.get("extrainfo"), tunnel=p.get("tunnel"),
                                cpe=p.get("cpe"), scripts=p.get("scripts"),
                                reason=p.get("reason"), source=SRC)
                total_ports += 1
                seeds += _crawl_seeds_for(ip, rec, p)
            open_here = len(parsed["ports"])
            log.info(f"  {ip}: {open_here} open port{'s' if open_here != 1 else ''}"
                     + (f" · {rec['os']['name']}" if rec.get("os") else ""))

    log.info(f"port scan complete: {total_ports} open ports across {scanned} "
             f"IP{'s' if scanned != 1 else ''} ({time.time() - t0:.1f}s)")
    result.mark_module("portscan", "ok" if total_ports else "empty",
                       note=f"{total_ports} ports / {scanned} IPs",
                       duration=time.time() - t0)
    # de-dup seeds; the crawler dedups too but a smaller seed list is cheaper
    return sorted(set(seeds)) if config.PORTSCAN_SEED_CRAWL else True


def _crawl_seeds_for(ip: str, rec: dict, port: dict) -> list[str]:
    """A web service on a non-standard port is a crawlable root. Prefer a
    hostname that resolves to this IP over the bare address (vhosts, TLS SNI),
    and skip the ports the crawler already covers from the HTTP probe."""
    if not config.PORTSCAN_SEED_CRAWL:
        return []
    svc = (port.get("service") or "").lower()
    tunnel = (port.get("tunnel") or "").lower()
    is_web = svc in _WEB_SERVICES or "http" in svc
    if not is_web:
        return []
    pn = port["port"]
    if pn in (80, 443):
        return []                          # already the crawler's default roots
    scheme = "https" if (tunnel == "ssl" or "https" in svc or pn in (8443, 4443)) else "http"
    hosts = rec.get("subdomains") or [ip]
    return [f"{scheme}://{h}:{pn}" for h in hosts[:3]]


def get_seeds(result: ScanResult) -> list[str]:
    """Crawl seeds derived from every open web port already recorded · used when
    run() was executed elsewhere and the caller just wants the seeds."""
    if not config.PORTSCAN_SEED_CRAWL:
        return []
    seeds: list[str] = []
    for rec in result._ips.values():              # type: ignore[attr-defined]
        for p in rec.get("ports") or []:
            seeds += _crawl_seeds_for(rec["ip"], rec, p)
    return sorted(set(seeds))
