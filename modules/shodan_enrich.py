"""
Module · passive host intelligence (source code "S").

Shodan already scanned the internet; in passive-discovery mode · where nothing
may touch the target directly · that is exactly the intel to lean on. For every
resolved public IP this pulls what Shodan knows and folds it into the existing IP
records and the findings list, rather than dumping raw output:

  * open ports + service banners (product, version, CPE, module, banner hash)
  * known vulnerabilities (CVEs) and the CPEs they were matched against
  * TLS · negotiated versions, cipher, JA3S/JARM, certificate issuer/subject/expiry
  * HTTP · server, title, WAF, and the html / robots / sitemap / favicon hashes
  * org / ISP / ASN / OS / geography / hostnames / domains / tags / last-seen
  * whether a screenshot exists

With a `SHODAN_KEY` the full REST host API is used. Without one it falls back to
the free InternetDB API (ports, CPEs, hostnames, tags, vulns), so the stage still
contributes. Ports Shodan reports are merged into the same port store the active
scan writes to (schema.add_port), so the Infrastructure panel and the graph show
one unified service surface; exposure findings reuse the port-scan catalogue so a
database seen by both tools becomes one merged finding.
"""
from __future__ import annotations

import ipaddress
import time

from . import config, httpcache, portscan
from .schema import ScanResult
from .util import get_logger, make_session

log = get_logger("shodan")

SRC = config.SOURCE_CODES["shodan"]          # "S"


def available() -> bool:
    return bool(config.SHODAN_KEY) or config.SHODAN_USE_INTERNETDB


def _public_ips(result: ScanResult) -> list[str]:
    out: list[str] = []
    for rec in result._ips.values():          # type: ignore[attr-defined]
        ip = rec["ip"]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            continue
        out.append(ip)
    return out[: config.SHODAN_MAX_TARGETS]


def _vuln_list(v) -> list[str]:
    """Shodan reports vulns as a list of CVEs or a {cve: {...}} object · normalise
    both to a sorted CVE list."""
    if isinstance(v, dict):
        return sorted(v.keys())
    if isinstance(v, list):
        return sorted(str(x) for x in v)
    return []


def _parse_internetdb(data: dict) -> dict:
    ports = sorted(p for p in (data.get("ports") or []) if isinstance(p, int))
    return {
        "source": "internetdb",
        "ports": ports,
        "hostnames": data.get("hostnames") or [],
        "domains": [],
        "cpes": data.get("cpes") or [],
        "tags": data.get("tags") or [],
        "vulns": _vuln_list(data.get("vulns")),
        "org": None, "isp": None, "asn": None, "os": None,
        "city": None, "country": None, "last_update": None,
        "services": [{"port": p, "transport": "tcp"} for p in ports],
        "ssl": None, "screenshot": False,
    }


def _parse_api(data: dict) -> dict:
    services: list[dict] = []
    ssl_agg: dict | None = None
    screenshot = False
    vulns: set[str] = set(_vuln_list(data.get("vulns")))
    cpes: set[str] = set()

    for b in data.get("data", []):
        if not isinstance(b, dict):
            continue
        cpe = b.get("cpe23") or b.get("cpe") or []
        if isinstance(cpe, str):
            cpe = [cpe]
        for c in cpe:
            cpes.add(c)
        svc = {
            "port": b.get("port"),
            "transport": b.get("transport") or "tcp",
            "product": b.get("product"),
            "version": b.get("version"),
            "module": (b.get("_shodan") or {}).get("module"),
            "cpe": cpe,
            "banner_hash": b.get("hash"),
            "tags": b.get("tags") or [],
            "timestamp": b.get("timestamp"),
        }
        vulns |= set(_vuln_list(b.get("vulns")))

        http = b.get("http")
        if isinstance(http, dict):
            fav = http.get("favicon") or {}
            svc["http"] = {
                "server": http.get("server"), "title": http.get("title"),
                "status": http.get("status"), "waf": http.get("waf"),
                "html_hash": http.get("html_hash"),
                "robots_hash": http.get("robots_hash"),
                "sitemap_hash": http.get("sitemap_hash"),
                "favicon_hash": fav.get("hash"),
                "components": list((http.get("components") or {}).keys()),
            }
            if http.get("securitytxt"):
                svc["http"]["securitytxt"] = True

        ssl = b.get("ssl")
        if isinstance(ssl, dict):
            cert = ssl.get("cert") or {}
            fp = cert.get("fingerprint") or {}
            svc["ssl"] = {
                "versions": ssl.get("versions"), "cipher": ssl.get("cipher"),
                "ja3s": ssl.get("ja3s"), "jarm": ssl.get("jarm"),
                "issuer": cert.get("issuer"), "subject": cert.get("subject"),
                "expires": cert.get("expires"), "expired": cert.get("expired"),
                "sha256": fp.get("sha256"),
            }
            ssl_agg = ssl_agg or svc["ssl"]

        opts = b.get("opts") or {}
        if opts.get("screenshot") or (b.get("_shodan") or {}).get("options", {}).get("screenshot"):
            screenshot = True
        services.append(svc)

    return {
        "source": "shodan-api",
        "ports": sorted(p for p in (data.get("ports") or []) if isinstance(p, int)),
        "hostnames": data.get("hostnames") or [],
        "domains": data.get("domains") or [],
        "cpes": sorted(cpes),
        "tags": data.get("tags") or [],
        "vulns": sorted(vulns),
        "org": data.get("org"), "isp": data.get("isp"),
        "asn": data.get("asn"), "os": data.get("os"),
        "city": data.get("city"), "country": data.get("country_name"),
        "last_update": data.get("last_update"),
        "services": services, "ssl": ssl_agg, "screenshot": screenshot,
    }


def _fetch(session, ip: str, use_api: bool) -> dict | None:
    if use_api:
        url = f"{config.SHODAN_API_BASE}/shodan/host/{ip}"
        data = httpcache.get_json(
            session, url, params={"key": config.SHODAN_KEY, "minify": "false"},
            cache_key=f"shodan-api:{ip}")
        if data and "__status__" not in data:
            return _parse_api(data)
    if config.SHODAN_USE_INTERNETDB:
        url = f"{config.SHODAN_INTERNETDB_BASE}/{ip}"
        data = httpcache.get_json(session, url, cache_key=f"internetdb:{ip}")
        if data and "__status__" not in data:
            return _parse_internetdb(data)
    return None


def _merge(result: ScanResult, ip: str, parsed: dict) -> None:
    rec = result.add_ip(ip, source=SRC)
    rec["shodan"] = parsed
    # Fill infra fields the active enrichment may not have reached yet.
    if parsed.get("org") and not rec.get("org"):
        rec["org"] = rec["provider"] = parsed["org"]
    if parsed.get("asn") and not rec.get("asn"):
        rec["asn"] = parsed["asn"]
    if parsed.get("country") and not rec.get("country"):
        rec["country"] = parsed["country"]
    for host in parsed.get("hostnames", []):
        h = (host or "").strip().lower()
        if h and h not in rec["subdomains"]:
            rec["subdomains"].append(h)

    # Fold Shodan's ports into the shared port store · one unified surface.
    port_records = []
    for svc in parsed.get("services", []):
        port = svc.get("port")
        if not isinstance(port, int):
            continue
        cpe = svc.get("cpe") if isinstance(svc.get("cpe"), list) else []
        service = "http" if svc.get("http") else (svc.get("module") or None)
        result.add_port(ip, port, protocol=svc.get("transport", "tcp"),
                        state="open", service=service, product=svc.get("product"),
                        version=svc.get("version"), tunnel="ssl" if svc.get("ssl") else None,
                        cpe=cpe, source=SRC)
        port_records.append({
            "port": port, "protocol": svc.get("transport", "tcp"), "state": "open",
            "service": service, "product": svc.get("product"),
            "version": svc.get("version"), "cpe": cpe, "scripts": {}})

    # Reuse the port-scan exposure catalogue · a DB Shodan saw open raises the
    # same finding the active scan would, and the two merge.
    if port_records:
        portscan.emit_port_findings(result, ip, {"ports": port_records}, source=SRC)

    # Known vulnerabilities.
    for cve in parsed.get("vulns", []):
        if not cve.upper().startswith("CVE-"):
            continue
        result.add_finding(
            title=f"{cve} reported for {ip} by passive intel",
            category="vuln", severity="high", confidence=60, source=SRC, target=ip,
            evidence=f"{parsed['source']} lists {cve} for {ip}"
                     + (f" ({', '.join(parsed.get('cpes', [])[:2])})" if parsed.get("cpes") else ""),
            parsed={"cve": cve, "cpes": parsed.get("cpes", [])[:8],
                    "last_seen": parsed.get("last_update")},
            risk=("A public internet-intelligence source matched a known "
                  "vulnerability to a service on this host."),
            recommendation="Confirm the affected service/version and patch it.",
            refs=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            tags=["cve", "shodan"], signature=f"vuln:{cve}:{ip}")

    # A screenshot existing is itself worth surfacing (exposed UI, camera, ...).
    if parsed.get("screenshot"):
        result.add_finding(
            title=f"Shodan holds a screenshot of {ip}",
            category="exposure", severity="info", confidence=70, source=SRC,
            target=ip, evidence="a service on this host rendered a screenshot in Shodan",
            parsed={"screenshot": True},
            risk="A visually captured service (panel, camera, desktop) is exposed.",
            recommendation="Review what is visually exposed on this address.",
            tags=["shodan", "screenshot"], signature=f"screenshot:{ip}")


def run(result: ScanResult, *, passive: bool = False) -> None:
    """Enrich every public IP with passive host intelligence. `passive` is passed
    through from the pipeline for logging · the caller decides when to run this."""
    t0 = time.time()
    if not available():
        log.info("no Shodan key and InternetDB disabled · skipping")
        result.mark_module("shodan", "skip", note="no key / InternetDB off")
        return
    ips = _public_ips(result)
    if not ips:
        result.mark_module("shodan", "empty", note="no public IPs", duration=0)
        return

    session = make_session()
    use_api = bool(config.SHODAN_KEY)
    log.info(f"passive intel for {len(ips)} IP{'s' if len(ips) != 1 else ''} via "
             + ("Shodan REST API" if use_api else "InternetDB (free, no key)"))
    interval = (1.0 / config.SHODAN_RATE) if config.SHODAN_RATE > 0 else 0.0

    enriched = total_vulns = 0
    for ip in ips:
        try:
            parsed = _fetch(session, ip, use_api)
        except Exception as exc:
            log.debug(f"shodan {ip}: {exc}")
            parsed = None
        if interval:
            time.sleep(interval)
        if not parsed:
            continue
        _merge(result, ip, parsed)
        enriched += 1
        total_vulns += len(parsed.get("vulns") or [])

    log.info(f"passive intel: enriched {enriched}/{len(ips)} IPs, "
             f"{total_vulns} known vuln{'s' if total_vulns != 1 else ''} "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("shodan", "ok" if enriched else "empty",
                       note=f"{enriched} IPs, {total_vulns} vulns",
                       duration=time.time() - t0)
