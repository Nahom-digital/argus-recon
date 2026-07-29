"""
Module 1 — Subdomain discovery + infrastructure correlation.

Primary engine is BBOT (subdomain-enum + asn), invoked as a CLI and parsed from
its NDJSON event stream. Everything is best-effort: if BBOT is missing or a run
yields nothing, we fall back to crt.sh certificate transparency plus a small DNS
brute of common names. Whatever the source, every discovered host is then
DNS-resolved locally so IP linkage is reliable, and the apex domain's WHOIS is
captured once.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import tempfile
import time
from pathlib import Path

import dns.resolver
import dns.reversename

from . import config, securitytrails
from .schema import ScanResult
from .util import get_logger, in_scope, make_session, resolve_tool, run_cmd, host_of

log = get_logger("subdomain")

# Source codes (no tool names leak into findings) — see config.SOURCE_CODES.
SRC_BBOT = config.SOURCE_CODES["bbot"]    # "b"
SRC_CRTSH = config.SOURCE_CODES["crtsh"]  # "c"

COMMON_SUBS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "api", "api-v1", "api-v2", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "portal", "dashboard", "app", "apps", "mobile", "m", "beta",
    "shop", "store", "blog", "news", "support", "help", "docs", "cdn", "static",
    "assets", "img", "images", "media", "files", "download", "downloads",
    "vpn", "remote", "gateway", "gw", "proxy", "auth", "sso", "login", "secure",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence", "wiki", "status",
    "monitor", "grafana", "kibana", "prometheus", "db", "database", "sql",
    "redis", "mysql", "postgres", "mongo", "internal", "intranet", "corp",
    "vpn2", "old", "new", "backup", "demo", "sandbox", "preview", "edge",
]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 3.0
    r.lifetime = 4.0
    r.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    return r


def resolve_host(host: str) -> list[str]:
    """Return A/AAAA addresses for a host (empty list if it does not resolve)."""
    ips: list[str] = []
    r = _resolver()
    for rdtype in ("A", "AAAA"):
        try:
            for rdata in r.resolve(host, rdtype):
                ips.append(rdata.to_text())
        except Exception:
            continue
    return sorted(set(ips))


def _resolve_many(hosts: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.CRAWL_THREADS) as ex:
        futs = {ex.submit(resolve_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
def domain_whois(domain: str) -> dict:
    try:
        import whois  # python-whois
        w = whois.whois(domain)

        def norm(v):
            if isinstance(v, list):
                v = v[0] if v else None
            return str(v) if v is not None else None

        return {
            "registrar": norm(w.registrar),
            "created": norm(w.creation_date),
            "expires": norm(w.expiration_date),
            "updated": norm(w.updated_date),
            "name_servers": sorted({str(n).lower() for n in (w.name_servers or [])}) or None,
            "emails": (w.emails if isinstance(w.emails, list) else [w.emails]) if w.emails else None,
            "org": norm(getattr(w, "org", None)),
            "country": norm(getattr(w, "country", None)),
        }
    except Exception as exc:
        log.info(f"whois lookup unavailable for {domain}: {exc}")
        return {}


# --------------------------------------------------------------------------- #
# BBOT
# --------------------------------------------------------------------------- #
def _bbot_command(domain: str, outdir: Path, passive: bool) -> list[str]:
    bbot = resolve_tool(config.BBOT_BIN) or config.BBOT_BIN
    cmd = [bbot, "-t", domain, "-o", str(outdir), "-om", "json",
           "-y", "--silent", "-n", "argus"]
    if passive:
        cmd += ["-rf", "passive", "-f", "subdomain-enum"]
    else:
        # subdomain-enum + ASN correlation, but keep it non-invasive/quiet.
        cmd += ["-f", "subdomain-enum", "-m", "asn", "-ef", "deadly,web-screenshots,slow"]
    return cmd


def _parse_bbot_output(result: ScanResult, outdir: Path) -> int:
    """Parse BBOT's NDJSON output.json; return count of in-scope hosts found."""
    files = list(outdir.rglob("output.json")) + list(outdir.rglob("output.ndjson"))
    if not files:
        return 0
    found = 0
    asn_by_ip: dict[str, dict] = {}
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    etype = ev.get("type")
                    data = ev.get("data")
                    module = ev.get("module", "bbot")

                    if etype == "DNS_NAME" and isinstance(data, str):
                        h = data.lower().rstrip(".")
                        if in_scope(f"http://{h}", result.domain):
                            ips = [x for x in ev.get("resolved_hosts", [])
                                   if _looks_like_ip(x)]
                            result.add_subdomain(h, source=SRC_BBOT, ips=ips)
                            found += 1
                    elif etype == "IP_ADDRESS" and isinstance(data, str):
                        result.add_ip(data, source=SRC_BBOT)
                    elif etype == "URL" and isinstance(data, str):
                        if in_scope(data, result.domain):
                            result.add_endpoint(data, etype="link", source=SRC_BBOT,
                                                found_on="passive-enum")
                    elif etype == "ASN" and isinstance(data, dict):
                        subnet = data.get("subnet") or data.get("data")
                        rec = {"asn": _fmt_asn(data.get("asn")),
                               "org": data.get("name") or data.get("description"),
                               "country": data.get("country")}
                        if subnet:
                            asn_by_ip[str(subnet)] = rec
                    elif etype in ("FINDING", "VULNERABILITY") and isinstance(data, dict):
                        result.meta.setdefault("bbot_findings", []).append({
                            "type": etype, "description": data.get("description"),
                            "url": data.get("url") or data.get("host"),
                            "severity": data.get("severity"),
                        })
        except Exception as exc:
            log.warning(f"error parsing {path}: {exc}")
    # Attach ASN where an IP falls inside a reported subnet.
    if asn_by_ip:
        _apply_asn(result, asn_by_ip)
    return found


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _fmt_asn(a) -> str | None:
    if a is None:
        return None
    a = str(a)
    return a if a.upper().startswith("AS") else f"AS{a}"


def _apply_asn(result: ScanResult, asn_by_ip: dict[str, dict]) -> None:
    import ipaddress
    nets = []
    for subnet, rec in asn_by_ip.items():
        try:
            nets.append((ipaddress.ip_network(subnet, strict=False), rec))
        except ValueError:
            continue
    for ip, iprec in result._ips.items():  # type: ignore[attr-defined]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for net, rec in nets:
            if addr in net:
                iprec["asn"] = iprec["asn"] or rec.get("asn")
                iprec["org"] = iprec["org"] or rec.get("org")
                iprec["country"] = iprec["country"] or rec.get("country")
                break


def run_bbot(result: ScanResult, domain: str, passive: bool, timeout: int) -> int:
    bbot = resolve_tool(config.BBOT_BIN)
    if not bbot:
        log.warning("BBOT not found on PATH — using crt.sh + DNS fallback")
        return 0
    with tempfile.TemporaryDirectory(prefix="argus_bbot_") as tmp:
        outdir = Path(tmp)
        cmd = _bbot_command(domain, outdir, passive)
        log.info(f"running BBOT ({'passive' if passive else 'subdomain-enum'}) — this can take a few minutes")
        log.info("  " + " ".join(cmd))
        proc = run_cmd(cmd, timeout=timeout, log=log)
        if proc is None:
            return 0
        if proc.returncode not in (0, None):
            log.warning(f"BBOT exited {proc.returncode}: {(proc.stderr or '')[-300:]}")
        return _parse_bbot_output(result, outdir)


# --------------------------------------------------------------------------- #
# Fallback: crt.sh
# --------------------------------------------------------------------------- #
def query_dns_records(domain: str) -> dict[str, list[dict]]:
    """Resolve the apex domain's core DNS records locally (A/AAAA/MX/NS/CNAME/
    TXT/SOA). Always available (no key). Returns {rtype_lower: [ {value, ...} ]}."""
    r = _resolver()
    out: dict[str, list[dict]] = {}
    for rtype in config.DNS_RECORD_TYPES:
        recs: list[dict] = []
        try:
            answers = r.resolve(domain, rtype, raise_on_no_answer=False)
        except Exception:
            continue
        for rd in answers:
            try:
                if rtype == "MX":
                    recs.append({"value": str(rd.exchange).rstrip("."),
                                 "priority": rd.preference, "first_seen": None, "last_seen": None})
                elif rtype in ("NS", "CNAME"):
                    recs.append({"value": rd.target.to_text().rstrip("."),
                                 "first_seen": None, "last_seen": None})
                elif rtype == "SOA":
                    recs.append({"value": rd.mname.to_text().rstrip("."),
                                 "email": rd.rname.to_text().rstrip("."),
                                 "ttl": rd.minimum, "first_seen": None, "last_seen": None})
                elif rtype == "TXT":
                    txt = b"".join(rd.strings).decode("utf-8", "replace") if hasattr(rd, "strings") else str(rd)
                    recs.append({"value": txt, "first_seen": None, "last_seen": None})
                else:  # A / AAAA
                    recs.append({"value": rd.to_text(), "first_seen": None, "last_seen": None})
            except Exception:
                continue
        if recs:
            out[rtype.lower()] = recs
    return out


def crtsh_subdomains(domain: str) -> set[str]:
    subs: set[str] = set()
    try:
        sess = make_session()
        resp = sess.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        if resp.status_code == 200 and resp.text.strip():
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        subs.add(name)
    except Exception as exc:
        log.info(f"crt.sh lookup failed: {exc}")
    return subs


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(result: ScanResult, domain: str, *, passive: bool = False,
        timeout: int = 900, use_bbot: bool = True, deep: bool = False,
        input_host: str | None = None) -> None:
    t0 = time.time()
    domain = result.domain

    # If the target the user typed was itself a subdomain, record it as one so
    # it is recognised while we enumerate the rest of the apex's subdomains.
    if input_host:
        ih = input_host.strip().lower().rstrip(".")
        if ih and ih != domain and in_scope(f"http://{ih}", domain):
            result.add_subdomain(ih, source="input")

    n = run_bbot(result, domain, passive, timeout) if use_bbot else 0

    # Deep DNS (SecurityTrails, code "s") — subdomains + current & historical DNS.
    deep_added = 0
    if deep and securitytrails.available():
        log.info("deep DNS: pulling subdomains + current/historical records")
        deep_added = securitytrails.run(result, domain)
    elif deep:
        log.warning("deep DNS requested but no key configured — skipping")

    # Fallback / supplement with crt.sh if BBOT + deep gave little.
    if (n + deep_added) < 3:
        log.info("supplementing with certificate transparency")
        for h in crtsh_subdomains(domain):
            result.add_subdomain(h, source=SRC_CRTSH)

    # Always ensure apex + common names are considered.
    result.add_subdomain(domain, source="seed")
    if n == 0 and not use_bbot:
        log.info(f"DNS-brute of {len(COMMON_SUBS)} common names")
        candidates = [f"{s}.{domain}" for s in COMMON_SUBS]
        for host, ips in _resolve_many(candidates).items():
            if ips:
                result.add_subdomain(host, source="dns-brute", ips=ips)

    # Resolve everything we have so IP links are complete.
    hosts = [r["host"] for r in result._subdomains.values()]  # type: ignore[attr-defined]
    log.info(f"resolving {len(hosts)} hosts to IPs")
    for host, ips in _resolve_many(hosts).items():
        rec = result.add_subdomain(host)
        for ip in ips:
            result._link_ip(rec, ip)  # type: ignore[attr-defined]
        rec["resolved"] = bool(rec["ips"])

    # Drop unresolved noise? Keep them — a non-resolving CNAME can be a takeover
    # candidate — but mark them clearly via resolved=False.

    # Local DNS records for the DNS panel (A/AAAA/MX/NS/CNAME/TXT/SOA). Deep
    # records (with first_seen) take precedence; the resolver fills any gaps.
    log.info("resolving core DNS records (A/AAAA/MX/NS/CNAME/TXT/SOA)")
    local_dns = query_dns_records(domain)
    for rtype, recs in local_dns.items():
        if not result.dns["records"].get(rtype):
            result.set_dns_records(rtype, recs, source="dns")
        else:
            result.dns["sources"].append("dns") if "dns" not in result.dns["sources"] else None

    # Domain-level WHOIS (once). Keep the deep WHOIS if present, else python-whois.
    result.meta["domain_whois"] = domain_whois(domain)
    if not result.dns.get("whois"):
        result.dns["whois"] = result.meta["domain_whois"]

    resolved = sum(1 for r in result._subdomains.values() if r["resolved"])  # type: ignore[attr-defined]
    log.info(f"discovered {len(result._subdomains)} subdomains ({resolved} resolving), "  # type: ignore[attr-defined]
             f"{len(result._ips)} unique IPs")  # type: ignore[attr-defined]
    result.mark_module("subdomain", "ok",
                       note=f"{len(result._subdomains)} subdomains, {len(result._ips)} IPs",  # type: ignore[attr-defined]
                       duration=time.time() - t0)
