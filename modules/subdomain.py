"""
Module 1 — Subdomain discovery + infrastructure correlation.

Two passive engines run in sequence, fast one first:

  1. a lightweight passive name enum (source "n") that queries the public
     sources and returns in seconds. Everything after it — the probe, the
     crawl, the brute — can start from a real host list almost immediately
     instead of waiting on the deep sweep,
  2. BBOT (source "b"), the deep sweep: many more modules, ASN correlation,
     findings, and minutes rather than seconds. It adds to what pass 1 found.

If neither is available we fall back to crt.sh certificate transparency plus a
small DNS brute of common names. Whatever the source, every discovered host is
then resolved — through the bulk resolver (source "r") when it is installed,
otherwise the local resolver pool — and the apex domain's WHOIS is captured once.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import tempfile
import threading
import time
from pathlib import Path

import dns.resolver
import dns.reversename

from . import config, securitytrails, tor
from .schema import ScanResult
from .util import (get_logger, in_scope, make_session, pick_flag, registrable_domain,
                   resolve_recon_tool, resolve_tool, run_cmd, host_of, stream_cmd,
                   tool_flags)

log = get_logger("subdomain")

# Source codes (no tool names leak into findings) — see config.SOURCE_CODES.
SRC_BBOT = config.SOURCE_CODES["bbot"]            # "b"
SRC_CRTSH = config.SOURCE_CODES["crtsh"]          # "c"
SRC_PASSIVE = config.SOURCE_CODES["subfinder"]    # "n"
SRC_DNSX = config.SOURCE_CODES["dnsx"]            # "r"

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
    r.nameservers = list(config.DNS_NAMESERVERS)
    return r


# --------------------------------------------------------------------------- #
# DNS over HTTPS — used instead of the UDP resolver while Tor is active.
#
# A plain resolver would send every hostname we look up straight out of this
# machine, past the proxy, which defeats the point of scanning over Tor. DoH goes
# through the same proxied session as the rest of the scan and supports every
# record type we need, so Tor mode loses no capability.
# --------------------------------------------------------------------------- #
_DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
              "TXT": 16, "AAAA": 28}
_doh_session = None
_doh_lock = threading.Lock()


def _doh() -> "object":
    global _doh_session
    with _doh_lock:
        if _doh_session is None:
            _doh_session = make_session()
            _doh_session.headers.update({"Accept": "application/dns-json"})
            _doh_session.verify = True   # a DoH answer we cannot authenticate is worthless
        return _doh_session


def _doh_query(name: str, rtype: str) -> list[str]:
    """Return the raw rdata strings for one name/type, or [] on any failure."""
    sess = _doh()
    for endpoint in config.DOH_ENDPOINTS:
        try:
            resp = sess.get(endpoint, params={"name": name, "type": rtype},
                            timeout=max(config.HTTP_TIMEOUT, 20))
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue
        if data.get("Status") not in (0, None):
            return []
        want = _DOH_TYPES.get(rtype.upper())
        out = [str(a.get("data", "")).strip()
               for a in (data.get("Answer") or [])
               if want is None or a.get("type") == want]
        return [v for v in out if v]
    return []


def resolve_host(host: str) -> list[str]:
    """Return A/AAAA addresses for a host (empty list if it does not resolve)."""
    ips: list[str] = []
    if config.TOR_ACTIVE:
        for rdtype in ("A", "AAAA"):
            ips += _doh_query(host, rdtype)
        return sorted({ip for ip in ips if _looks_like_ip(ip)})
    r = _resolver()
    for rdtype in ("A", "AAAA"):
        try:
            for rdata in r.resolve(host, rdtype):
                ips.append(rdata.to_text())
        except Exception:
            continue
    return sorted(set(ips))


def _resolve_many(hosts: list[str]) -> dict[str, list[str]]:
    """Resolve a batch of hosts to A/AAAA addresses.

    Prefers the bulk resolver binary (hundreds of concurrent lookups from one
    process) and falls back to the local thread pool. Over Tor neither applies:
    UDP DNS would go straight out of this machine past the proxy, so resolution
    stays on the DoH path in `resolve_host`.
    """
    if not hosts:
        return {}
    if not config.TOR_ACTIVE:
        bulk = _dnsx_resolve(hosts)
        if bulk is not None:
            return bulk
    out: dict[str, list[str]] = {}
    # Over Tor each lookup is an HTTPS round trip through a circuit; a wide fan-out
    # buys nothing and starves the crawler's own circuits.
    workers = 6 if config.TOR_ACTIVE else config.CRAWL_THREADS
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(resolve_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


# --------------------------------------------------------------------------- #
# Bulk resolver (source "r")
# --------------------------------------------------------------------------- #
def _dnsx_bin() -> str | None:
    return resolve_recon_tool(config.DNSX_BIN, config.TOOL_ALIASES.get("dnsx"))


def _dnsx_resolve(hosts: list[str]) -> dict[str, list[str]] | None:
    """A/AAAA for every host in one pass. Returns None when unavailable, so the
    caller can fall back rather than treat "no binary" as "nothing resolves"."""
    bin_path = _dnsx_bin()
    if not bin_path:
        return None
    flags = tool_flags(bin_path)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("\n".join(hosts))
        list_file = Path(fh.name)
    cmd = [bin_path, "-list", str(list_file), "-json", "-silent"]
    for names, value in ((("a",), None), (("aaaa",), None), (("no-color", "nc"), None),
                         (("threads", "t"), config.DNSX_THREADS),
                         (("resolver", "r"), ",".join(config.DNS_NAMESERVERS)),
                         (("disable-update-check", "duc"), None)):
        f = pick_flag(flags, *names)
        if f:
            cmd.append(f)
            if value is not None:
                cmd.append(str(value))

    out: dict[str, list[str]] = {h: [] for h in hosts}

    def on_line(line: str) -> None:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return
        host = str(rec.get("host") or "").rstrip(".").lower()
        if not host:
            return
        ips = [str(x) for x in (rec.get("a") or []) + (rec.get("aaaa") or []) if x]
        if ips:
            out.setdefault(host, [])
            out[host] = sorted({*out[host], *ips})

    try:
        stream_cmd(cmd, timeout=config.DNSX_TIMEOUT, on_line=on_line, log=log)
    finally:
        list_file.unlink(missing_ok=True)
    resolved = sum(1 for v in out.values() if v)
    log.info(f"bulk resolver: {resolved}/{len(hosts)} hosts resolved")
    return out


# --------------------------------------------------------------------------- #
# Fast passive name enum (source "n")
# --------------------------------------------------------------------------- #
def _subfinder_bin() -> str | None:
    return resolve_recon_tool(config.SUBFINDER_BIN, config.TOOL_ALIASES.get("subfinder"))


def run_passive_enum(result: ScanResult, domain: str, *, timeout: int | None = None) -> int:
    """Quick passive sweep for subdomains. Returns how many in-scope hosts it
    added. Runs before the deep engine so the rest of the pipeline has something
    to work on within seconds."""
    bin_path = _subfinder_bin()
    if not bin_path:
        return 0
    flags = tool_flags(bin_path)
    cmd = [bin_path, "-domain", domain, "-json", "-silent"]
    for names, value in ((("no-color", "nc"), None),
                         (("timeout",), 20),
                         (("disable-update-check", "duc"), None)):
        f = pick_flag(flags, *names)
        if f:
            cmd.append(f)
            if value is not None:
                cmd.append(str(value))
    if config.SUBFINDER_ALL:
        f = pick_flag(flags, "all")
        if f:
            cmd.append(f)
    if tor.active():
        # A Go binary ignores torsocks' LD_PRELOAD shim, and this one has no
        # SOCKS option — running it would query every public source directly from
        # this address, which is exactly what a Tor scan is avoiding.
        log.warning("quick passive enum skipped over Tor (no SOCKS support in the engine)")
        return 0

    found: set[str] = set()

    def on_line(line: str) -> None:
        host = ""
        try:
            rec = json.loads(line)
            host = str(rec.get("host") or rec.get("input") or "")
        except json.JSONDecodeError:
            host = line                     # -silent without -json prints bare names
        host = host.strip().lower().rstrip(".")
        if host and in_scope(f"http://{host}", result.domain):
            found.add(host)

    log.info(f"quick passive enum of {domain}")
    stream_cmd(cmd, timeout=timeout or config.SUBFINDER_TIMEOUT, on_line=on_line, log=log)
    for host in found:
        result.add_subdomain(host, source=SRC_PASSIVE)
    log.info(f"quick passive enum: {len(found)} hosts")
    return len(found)


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
def domain_whois(domain: str) -> dict:
    if config.TOR_ACTIVE:
        # WHOIS is a raw port-43 conversation made outside our HTTP stack, so it
        # would go out in the clear. Skipped rather than leaked; deep DNS still
        # returns registrar data over HTTPS through the proxy.
        log.warning("WHOIS skipped over Tor (port 43 cannot be proxied here)")
        return {}
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
        # Over Tor the engine has to be torsocks-wrapped: it opens its own
        # sockets and resolvers, none of which know about our proxy.
        if tor.active():
            wrapped = tor.wrap_cmd(cmd)
            if wrapped is None:
                log.warning("passive-enum engine skipped: Tor is on but torsocks is "
                            "not installed, and running it unwrapped would bypass Tor")
                return 0
            cmd = wrapped
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
def _doh_records(domain: str) -> dict[str, list[dict]]:
    """The DoH equivalent of `query_dns_records`, parsing the wire-format rdata
    strings a JSON DoH endpoint returns into the same record shape."""
    out: dict[str, list[dict]] = {}
    for rtype in config.DNS_RECORD_TYPES:
        recs: list[dict] = []
        for data in _doh_query(domain, rtype):
            rec: dict = {"value": data, "first_seen": None, "last_seen": None}
            try:
                if rtype == "MX":
                    prio, _, host = data.partition(" ")
                    rec["value"] = host.strip().rstrip(".")
                    rec["priority"] = int(prio)
                elif rtype in ("NS", "CNAME"):
                    rec["value"] = data.rstrip(".")
                elif rtype == "TXT":
                    rec["value"] = data.strip().strip('"')
                elif rtype == "SOA":
                    # mname rname serial refresh retry expire minimum
                    parts = data.split()
                    rec["value"] = parts[0].rstrip(".")
                    rec["email"] = parts[1].rstrip(".") if len(parts) > 1 else None
                    rec["ttl"] = int(parts[6]) if len(parts) > 6 else None
            except (ValueError, IndexError):
                rec["value"] = data
            if rec["value"]:
                recs.append(rec)
        if recs:
            out[rtype.lower()] = recs
    return out


def query_dns_records(domain: str) -> dict[str, list[dict]]:
    """Resolve the apex domain's core DNS records locally (A/AAAA/MX/NS/CNAME/
    TXT/SOA). Always available (no key). Returns {rtype_lower: [ {value, ...} ]}."""
    if config.TOR_ACTIVE:
        return _doh_records(domain)
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
        input_host: str | None = None, single: bool = False) -> None:
    t0 = time.time()
    domain = result.domain

    # If the target the user typed was itself a subdomain, record it as one so
    # it is recognised while we enumerate the rest of the apex's subdomains.
    if input_host:
        ih = input_host.strip().lower().rstrip(".")
        if ih and ih != domain and in_scope(f"http://{ih}", domain, exact=False):
            result.add_subdomain(ih, source="input")

    if single:
        # Single-target scan: the target is the whole host list. No passive
        # enumeration, no certificate transparency, no name brute — the point of
        # this mode is that nothing widens the scope beyond what was asked for.
        log.info(f"single-target scan — {domain} only, no host enumeration")
        result.add_subdomain(domain, source="input")
        if deep and securitytrails.available():
            log.info("deep DNS: records + history for this host only")
            securitytrails.run(result, domain, subdomains=False)
        elif deep:
            log.warning("deep DNS requested but no key configured — skipping")
    else:
        # 1. quick pass — seconds, so the deep engine is never the only thing
        #    standing between the operator and a host list.
        quick = run_passive_enum(result, domain)

        # 2. deep pass.
        n = run_bbot(result, domain, passive, timeout) if use_bbot else 0

        # Deep DNS (SecurityTrails, code "s") — subdomains + current & historical DNS.
        deep_added = 0
        if deep and securitytrails.available():
            log.info("deep DNS: pulling subdomains + current/historical records")
            deep_added = securitytrails.run(result, domain)
        elif deep:
            log.warning("deep DNS requested but no key configured — skipping")

        # Fallback / supplement with crt.sh if the passive engines gave little.
        if (quick + n + deep_added) < 3:
            log.info("supplementing with certificate transparency")
            for h in crtsh_subdomains(domain):
                result.add_subdomain(h, source=SRC_CRTSH)

        # Always ensure apex + common names are considered.
        result.add_subdomain(domain, source="seed")
        if (quick + n) == 0:
            log.info(f"DNS-brute of {len(COMMON_SUBS)} common names")
            candidates = [f"{s}.{domain}" for s in COMMON_SUBS]
            for host, ips in _resolve_many(candidates).items():
                if ips:
                    result.add_subdomain(host, source="dns-brute", ips=ips)

    # Resolve everything we have so IP links are complete.
    hosts = [r["host"] for r in result._subdomains.values()]  # type: ignore[attr-defined]
    res_src = SRC_DNSX if (not config.TOR_ACTIVE and _dnsx_bin()) else "dns"
    log.info(f"resolving {len(hosts)} hosts to IPs")
    for host, ips in _resolve_many(hosts).items():
        rec = result.add_subdomain(host)
        for ip in ips:
            result._link_ip(rec, ip, source=res_src)  # type: ignore[attr-defined]
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
    # A subdomain has no registration of its own, so ask about the registrable
    # domain it sits under.
    result.meta["domain_whois"] = domain_whois(registrable_domain(domain))
    if not result.dns.get("whois"):
        result.dns["whois"] = result.meta["domain_whois"]

    resolved = sum(1 for r in result._subdomains.values() if r["resolved"])  # type: ignore[attr-defined]
    log.info(f"discovered {len(result._subdomains)} subdomains ({resolved} resolving), "  # type: ignore[attr-defined]
             f"{len(result._ips)} unique IPs")  # type: ignore[attr-defined]
    result.mark_module("subdomain", "ok",
                       note=f"{len(result._subdomains)} subdomains, {len(result._ips)} IPs",  # type: ignore[attr-defined]
                       duration=time.time() - t0)
