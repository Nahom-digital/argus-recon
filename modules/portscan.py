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
import json
import re
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from . import config, tor
from .schema import ScanResult
from .util import (get_logger, resolve_tool, run_cmd, stream_cmd,
                   tool_flags, pick_flag)

log = get_logger("portscan")

SRC = config.SOURCE_CODES["portscan"]        # "p"

# HTTP-ish services whose open port off 80/443 is worth crawling.
_WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt",
                 "ssl/http", "http-mgmt", "sun-answerbook"}

# --------------------------------------------------------------------------- #
# Exposure catalogue · a service that should almost never face the internet, keyed
# by port. Each entry is (label, severity, why). The port scan raises a finding
# for every one of these it sees open on a public address · the difference between
# "5432 is open" and "a PostgreSQL database is reachable from anywhere". Service
# name / product from the version scan refines the label when present.
# --------------------------------------------------------------------------- #
_RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    23:    ("Telnet", "high", "Cleartext remote shell · credentials cross the wire unencrypted."),
    21:    ("FTP", "medium", "Often cleartext and anonymous-readable; frequently a data-exfil path."),
    445:   ("SMB", "high", "File sharing exposed to the internet is a routine ransomware entry point."),
    139:   ("NetBIOS", "medium", "Legacy Windows file/printer sharing exposed publicly."),
    3389:  ("RDP", "high", "Remote Desktop on the internet is brute-forced and exploited constantly."),
    5900:  ("VNC", "high", "Remote framebuffer, often unauthenticated or weakly authenticated."),
    5901:  ("VNC", "high", "Remote framebuffer, often unauthenticated or weakly authenticated."),
    2049:  ("NFS", "high", "Network file system exports reachable publicly."),
    111:   ("rpcbind", "medium", "RPC portmapper exposes internal services and aids amplification."),
    623:   ("IPMI", "high", "Baseboard management (lights-out) exposed · full hardware control."),
    512:   ("rexec", "high", "Legacy remote exec, cleartext."),
    513:   ("rlogin", "high", "Legacy remote login, cleartext."),
    514:   ("rsh", "high", "Legacy remote shell, cleartext."),
    69:    ("TFTP", "medium", "Trivial FTP is unauthenticated by design."),
    161:   ("SNMP", "medium", "Often left on 'public' community string; leaks device internals."),
    # Databases / data stores · public exposure is high to critical.
    5432:  ("PostgreSQL", "high", "Database reachable from the internet."),
    3306:  ("MySQL/MariaDB", "high", "Database reachable from the internet."),
    1433:  ("MSSQL", "high", "Database reachable from the internet."),
    1521:  ("Oracle DB", "high", "Database reachable from the internet."),
    27017: ("MongoDB", "high", "Document store · historically default-no-auth and mass-ransomed."),
    27018: ("MongoDB", "high", "Document store · historically default-no-auth and mass-ransomed."),
    6379:  ("Redis", "high", "In-memory store · default no auth, trivially abused for RCE."),
    11211: ("Memcached", "high", "No auth by design; a well-known UDP amplification vector."),
    9200:  ("Elasticsearch", "high", "Search index · default no auth, a classic data-leak source."),
    9300:  ("Elasticsearch", "high", "Cluster transport exposed."),
    5984:  ("CouchDB", "high", "Database reachable from the internet."),
    9042:  ("Cassandra", "high", "Database reachable from the internet."),
    7000:  ("Cassandra", "medium", "Cluster inter-node port exposed."),
    8086:  ("InfluxDB", "high", "Time-series database reachable from the internet."),
    5601:  ("Kibana", "high", "Elasticsearch console · often unauthenticated, full data access."),
    2379:  ("etcd", "critical", "Cluster key-value store · holds secrets and full cluster state."),
    2380:  ("etcd", "high", "etcd peer port exposed."),
    # Orchestration / infra control planes · exposure is critical.
    2375:  ("Docker API", "critical", "Unauthenticated Docker daemon = root on the host, trivially."),
    2376:  ("Docker API (TLS)", "high", "Docker daemon exposed; misconfig grants host control."),
    10250: ("kubelet", "critical", "Kubelet API can run commands in any pod on the node."),
    6443:  ("Kubernetes API", "high", "Cluster API server exposed to the internet."),
    2181:  ("ZooKeeper", "medium", "Coordination service · leaks and lets you alter cluster config."),
    15672: ("RabbitMQ mgmt", "medium", "Broker management UI, often default guest/guest."),
    5672:  ("AMQP", "medium", "Message broker exposed."),
    9092:  ("Kafka", "medium", "Event streaming broker exposed."),
    61616: ("ActiveMQ", "medium", "Message broker exposed."),
    # Ops / debug surfaces.
    9000:  ("SonarQube/PHP-FPM", "medium", "Dev/ops surface exposed on a common port."),
    8500:  ("Consul", "high", "Service mesh control plane · holds service config and secrets."),
    4040:  ("Spark UI", "medium", "Cluster job UI can leak data and allow job submission."),
    8080:  ("HTTP-alt", "low", "Common app/proxy port · confirm what answers before trusting it."),
}


def binary() -> str | None:
    return resolve_tool(config.PORTSCAN_BIN)


def available() -> bool:
    return bool(binary())


def _is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def _command(bin_path: str, ip: str, ports: list[int] | None = None) -> list[str]:
    """Build the aggressive detail-scan command for one address.

    Direct: the aggressive profile as configured (service/version, OS, scripts,
    traceroute). Over Tor: raw-packet features (SYN scan, OS detection,
    traceroute) cannot cross a SOCKS proxy, so the run is wrapped in torsocks and
    reduced to a TCP-connect scan with version + default scripts · still the
    service/version intel, routed through the circuit, minus what the transport
    physically cannot carry.

    When `ports` is given (the full-range discovery pre-pass found the open set),
    the scan is aimed at exactly those ports with `-p`, so every open port · not
    just the ones in nmap's default top-1000 · gets version/OS/script treatment.
    Version intensity is raised and OS guessing is loosened for a better answer,
    which is the whole point of the opt-in stage.
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
    else:
        # Push service/version detection harder and let OS detection guess rather
        # than stay silent · costs a little time for a materially better result.
        if "-A" in args or "-sV" in args:
            args += ["--version-all"]
        if "-A" in args or "-O" in args:
            args += ["--osscan-guess"]
    cmd += [bin_path, *args, "-n", "-oX", "-"]
    if ports:
        cmd += ["-p", ",".join(str(p) for p in sorted(set(ports)))]
    if _is_ipv6(ip):
        cmd.append("-6")
    cmd.append(ip)
    return cmd


# --------------------------------------------------------------------------- #
# Full-range discovery pre-pass
#
# nmap's default scans the top 1000 ports · a service on 8123 or 27017 is simply
# never looked at. This pass finds every open port fast (a connect sweep across
# the whole range) so the aggressive scan above can be aimed at the real open set
# instead of a fixed list. It prefers a purpose-built fast scanner when one is
# installed (naabu, then masscan) and always has the nmap connect sweep to fall
# back on, so it works out of the box and gets faster if the operator adds tools.
# --------------------------------------------------------------------------- #
def _open_ports_from_xml(xml_text: str) -> list[int]:
    """Open port numbers from an nmap XML blob, tolerant of a truncated tail."""
    ports: set[int] = set()

    def harvest(root) -> None:
        for p in root.iter("port"):
            st = p.find("state")
            if st is not None and st.get("state") in ("open", "open|filtered"):
                try:
                    ports.add(int(p.get("portid")))
                except (TypeError, ValueError):
                    pass

    try:
        harvest(ET.fromstring(xml_text))
    except ET.ParseError:
        end = xml_text.rfind("</host>")
        start = xml_text.rfind("<host", 0, end) if end != -1 else -1
        if start != -1:
            try:
                harvest(ET.fromstring(xml_text[start:end + len("</host>")]))
            except ET.ParseError:
                pass
    return sorted(ports)


def _naabu_sweep(bin_path: str, ip: str, timeout: int, full: bool) -> list[int] | None:
    flags = tool_flags(bin_path)
    cmd = [bin_path, "-host", ip, "-silent"]
    if full:
        cmd += ["-p", "-"]
    else:
        tp = pick_flag(flags, "top-ports", "tp")
        cmd += ([tp, str(config.PORTSCAN_TOP_PORTS)] if tp else ["-p", "-"])
    rate = pick_flag(flags, "rate")
    if rate:
        cmd += [rate, str(config.PORTSCAN_DISCOVERY_RATE)]
    js = pick_flag(flags, "json", "j")
    if js:
        cmd.append(js)
    ports: set[int] = set()

    def on_line(line: str) -> None:
        line = line.strip()
        try:
            obj = json.loads(line)
            p = obj.get("port")
            if isinstance(p, int):
                ports.add(p)
                return
        except Exception:
            pass
        if ":" in line:                       # plain "ip:port" fallback
            tail = line.rsplit(":", 1)[-1]
            if tail.isdigit():
                ports.add(int(tail))

    got = stream_cmd(cmd, timeout, on_line, log=log)
    return sorted(ports) if got else None


def _masscan_sweep(bin_path: str, ip: str, timeout: int, full: bool) -> list[int] | None:
    # masscan needs raw sockets (root or CAP_NET_RAW). If it cannot open them it
    # exits immediately · which just means we fall through to the nmap sweep.
    spec = "0-65535" if full else "1-{}".format(max(1024, config.PORTSCAN_TOP_PORTS))
    cmd = [bin_path, ip, "-p", spec, "--rate", str(config.PORTSCAN_DISCOVERY_RATE),
           "-oJ", "-", "--wait", "0"]
    proc = run_cmd(cmd, timeout=timeout, log=log)
    if proc is None or not proc.stdout:
        return None
    ports: set[int] = set()
    for line in proc.stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            for pr in obj.get("ports", []):
                p = pr.get("port")
                if isinstance(p, int):
                    ports.add(p)
        except Exception:
            continue
    return sorted(ports) if ports else None


def _nmap_sweep(bin_path: str, ip: str, timeout: int, full: bool) -> list[int] | None:
    """Connect-scan sweep · always available, and Tor-safe (goes through torsocks
    like the detail scan). This is the floor everything else improves on."""
    proxy = tor.active()
    cmd: list[str] = []
    args = ["-sT", "-Pn", "-n", "-T4"]
    args += (["-p-"] if full else ["--top-ports", str(config.PORTSCAN_TOP_PORTS)])
    if not proxy:
        args += ["--min-rate", str(config.PORTSCAN_DISCOVERY_RATE)]
    else:
        ts = resolve_tool(config.TORSOCKS_BIN)
        if ts:
            cmd += [ts]
    cmd += [bin_path, *args, "-oX", "-"]
    if _is_ipv6(ip):
        cmd.append("-6")
    cmd.append(ip)
    proc = run_cmd(cmd, timeout=timeout, log=log)
    if proc is None or not proc.stdout:
        return None
    return _open_ports_from_xml(proc.stdout)


def _discover_ports(bin_path: str, ip: str, timeout: int) -> tuple[list[int] | None, str | None]:
    """(open ports, engine) for `ip`, or (None, None) if no sweep could run · the
    caller then does the original top-1000 detail scan. Tries the fast engines
    first, then the always-available nmap connect sweep."""
    full = config.PORTSCAN_FULL_RANGE
    # A generous slice of the per-target budget for discovery; the detail scan
    # gets the rest. Discovery is the cheaper half, so cap it at ~40%.
    disc_timeout = max(60, int(timeout * 0.4))
    if not tor.active():
        naabu = resolve_tool(config.NAABU_BIN)
        if naabu:
            got = _naabu_sweep(naabu, ip, disc_timeout, full)
            if got is not None:
                return got, "naabu"
        masscan = resolve_tool(config.MASSCAN_BIN)
        if masscan:
            got = _masscan_sweep(masscan, ip, disc_timeout, full)
            if got is not None:
                return got, "masscan"
    got = _nmap_sweep(bin_path, ip, disc_timeout, full)
    return (got, "nmap-sweep") if got is not None else (None, None)


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


def _parse_detail_xml(xml_text: str) -> dict | None:
    """Parse one host's aggressive-scan XML, recovering a truncated tail."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        end = xml_text.rfind("</host>")
        start = xml_text.rfind("<host", 0, end) if end != -1 else -1
        if start == -1:
            return None
        try:
            return _parse_host(ET.fromstring(xml_text[start:end + len("</host>")]))
        except ET.ParseError:
            return None
    host_el = root.find("host")
    return _parse_host(host_el) if host_el is not None else {"ports": [], "os": None, "traceroute": []}


def _scan_one(bin_path: str, ip: str, timeout: int) -> dict | None:
    """Two phases: a fast full-range sweep finds every open port, then the
    aggressive scan is aimed at exactly those ports for version/OS/script detail.
    Discovery that finds nothing (or could not run) falls back to the original
    top-1000 detail scan, so this never does worse than before · only better."""
    t0 = time.time()
    discovered, method = _discover_ports(bin_path, ip, timeout)

    # Host is up with nothing open · don't spend the detail budget on it.
    if discovered is not None and len(discovered) == 0:
        return {"ports": [], "os": None, "traceroute": [],
                "discovery": {"method": method, "open": 0}}

    detail_timeout = max(120, int(timeout - (time.time() - t0)))
    cmd = _command(bin_path, ip, ports=discovered or None)
    proc = run_cmd(cmd, timeout=detail_timeout, log=log)
    parsed = _parse_detail_xml(proc.stdout) if (proc and proc.stdout) else None
    if parsed is None:
        parsed = {"ports": [], "os": None, "traceroute": []}

    # Never drop a port discovery found just because the detail scan could not
    # fingerprint it (a filtered response, a timeout mid-port). Record it bare so
    # the open port is not silently lost.
    seen = {(p["port"], p.get("protocol", "tcp")) for p in parsed["ports"]}
    for pn in (discovered or []):
        if (pn, "tcp") not in seen:
            parsed["ports"].append({
                "port": pn, "protocol": "tcp", "state": "open", "reason": "discovery",
                "service": None, "product": None, "version": None, "extrainfo": None,
                "tunnel": None, "cpe": [], "scripts": {}})
    parsed["ports"].sort(key=lambda p: (p.get("protocol", "tcp"), p["port"]))
    parsed["discovery"] = {"method": method,
                           "open": len(discovered) if discovered is not None else None}
    return parsed


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


_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Script output phrases that are findings in their own right.
_SCRIPT_ALERTS = [
    ("anonymous ftp login allowed", "high", "Anonymous FTP login is allowed."),
    ("anonymous login", "high", "Anonymous login is allowed."),
    ("message signing enabled but not required", "medium", "SMB signing is not enforced (relay-able)."),
    ("message signing disabled", "high", "SMB signing is disabled (relay-able)."),
    ("smbv1", "medium", "SMBv1 is enabled (legacy, exploitable)."),
    ("public", "low", "SNMP is readable with the default 'public' community."),
]


def _recommendation_for(port: int, label: str) -> str:
    if port in (2375, 2376, 10250, 6443, 2379, 2380, 8500):
        return ("This is an infrastructure control plane · exposure can mean full "
                "host or cluster takeover. Firewall it now and require mutual "
                "TLS / strong authentication.")
    if port in (23, 3389, 5900, 5901, 512, 513, 514, 445, 139, 2049, 623):
        return ("Restrict remote-access services to a VPN or an IP allow-list and "
                "enforce strong authentication and MFA · never leave them open to "
                "the whole internet.")
    if label and any(db in label.lower() for db in
                     ("sql", "mongo", "redis", "elastic", "couch", "cassandra",
                      "influx", "memcached", "kibana", "database", "etcd")):
        return ("Bind the datastore to localhost or a private network, require "
                "authentication, and place it behind a firewall · it should not be "
                "reachable from the internet.")
    return ("Confirm this service must be public. If not, restrict it at the "
            "firewall / security group.")


def emit_port_findings(result: ScanResult, ip: str, parsed: dict,
                       source: str = SRC) -> None:
    """Raise normalised findings for the notable open ports on one address ·
    exposed datastores, remote-access services, control planes, and any CVE the
    version scripts named. Everything is deduped/merged by schema.add_finding.

    Reused by the Shodan stage (source "S") so a database Shodan already saw open
    raises the same exposure finding as one the port scan found · they merge."""
    for p in parsed.get("ports", []):
        port = p.get("port")
        svc = (p.get("service") or "").strip()
        product = (p.get("product") or "").strip()
        version = (p.get("version") or "").strip()
        prodver = " ".join(x for x in (product, version) if x).strip()
        target = f"{ip}:{port}"
        ev = (f"{port}/{p.get('protocol', 'tcp')} open "
              + " ".join(x for x in (svc, prodver) if x)).strip()

        risky = _RISKY_PORTS.get(port)
        if risky:
            label, sev, why = risky
            if product:                       # a confirmed product beats the guess
                label = product
            conf = 90 if prodver else (78 if svc else 62)
            result.add_finding(
                title=f"{label} exposed on port {port}",
                category="exposure", severity=sev, confidence=conf, source=source,
                target=target, evidence=ev,
                parsed={"port": port, "service": svc or None, "product": product or None,
                        "version": version or None, "cpe": p.get("cpe") or []},
                risk=why, recommendation=_recommendation_for(port, label),
                tags=["port-scan", svc or "tcp"],
                signature=f"exposure:{port}")

        # CVEs named by the version/vuln scripts · one finding per CVE.
        script_blob = " ".join((p.get("scripts") or {}).values())
        for cve in sorted(set(m.group(0).upper() for m in _CVE_RX.finditer(script_blob))):
            result.add_finding(
                title=f"{cve} on {prodver or svc or 'service'} ({target})",
                category="vuln", severity="high", confidence=70, source=source,
                target=target, evidence=script_blob[:400],
                parsed={"cve": cve, "port": port, "product": product or None,
                        "version": version or None},
                risk="A known vulnerability was matched against the detected version.",
                recommendation="Confirm the version and patch to a fixed release.",
                refs=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                tags=["cve", "port-scan"], signature=f"vuln:{cve}:{port}")

        # High-signal script phrases (anon FTP, SMB signing, SNMP public, ...).
        low_blob = script_blob.lower()
        for needle, sev, why in _SCRIPT_ALERTS:
            if needle in low_blob:
                result.add_finding(
                    title=f"{why.rstrip('.')} on {target}",
                    category="misconfig", severity=sev, confidence=72, source=source,
                    target=target, evidence=script_blob[:400],
                    parsed={"port": port, "service": svc or None},
                    risk=why, recommendation=_recommendation_for(port, svc),
                    tags=["port-scan", "script"], signature=f"script:{needle}:{port}")


def _cdn_lookup(ips: list[str]) -> dict[str, dict]:
    """Ask cdncheck which addresses belong to a CDN/WAF/cloud edge, when it is
    installed. Best-effort · an empty dict means 'not classified', never an
    error. Lets the panel read an edge IP's open ports as the edge's, not the
    origin's."""
    binp = resolve_tool(config.CDNCHECK_BIN)
    if not binp or not ips:
        return {}
    flags = tool_flags(binp)
    cmd = [binp]
    js = pick_flag(flags, "json", "j")
    resp = pick_flag(flags, "resp")
    if js:
        cmd.append(js)
    if resp:
        cmd.append(resp)
    out: dict[str, dict] = {}

    def on_line(line: str) -> None:
        line = line.strip()
        try:
            obj = json.loads(line)
        except Exception:
            return
        ip = obj.get("ip") or obj.get("input") or obj.get("host")
        name = (obj.get("cdn_name") or obj.get("itemName") or obj.get("cdn")
                or obj.get("waf_name") or obj.get("cloud_name"))
        if ip and name and not isinstance(name, bool):
            kind = ("waf" if obj.get("waf") else "cloud" if obj.get("cloud") else "cdn")
            out[ip] = {"name": name, "kind": kind}

    stream_cmd(cmd, 60, on_line, log=log, stdin_data="\n".join(ips) + "\n")
    return out


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
            # Turn the notable open ports into ranked findings (exposed DBs,
            # remote-access services, control planes, CVEs from the scripts).
            emit_port_findings(result, ip, parsed)
            open_here = len(parsed["ports"])
            disc = (parsed.get("discovery") or {}).get("method")
            log.info(f"  {ip}: {open_here} open port{'s' if open_here != 1 else ''}"
                     + (f" · via {disc}" if disc else "")
                     + (f" · {rec['os']['name']}" if rec.get("os") else ""))

    # Tag any address that belongs to a CDN/WAF/cloud edge so its open ports are
    # read as the edge's, not the origin's (best-effort · needs cdncheck).
    cdn = _cdn_lookup(targets)
    for ip, info in cdn.items():
        rec = result.add_ip(ip, source=SRC)
        rec["cdn"] = info
        result.add_finding(
            title=f"{ip} is behind {info['name']}",
            category="cdn", severity="info", confidence=80, source=SRC, target=ip,
            evidence=f"{info['kind']}: {info['name']}",
            parsed=info,
            risk=("Ports and services seen here belong to the "
                  f"{info['kind'].upper()} edge, not necessarily the origin host."),
            recommendation="Find the origin IP to assess the real service surface.",
            tags=["cdn", info["kind"]], signature=f"cdn:{ip}")

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


# --------------------------------------------------------------------------- #
# Per-port web fingerprint
#
# nmap names the service on a port ("http", "ssl/http") but not the stack behind
# it. For a web service on a non-standard port · an admin panel on :8443, a
# staging app on :8080 · run WhatWeb against the exact host:port and fold the tech
# tags onto that port record, so the Infrastructure panel and the Port node in
# the graph show what is actually answering there, not just "http".
# --------------------------------------------------------------------------- #
def _web_url_for(rec: dict, port: dict) -> str | None:
    """The host:port URL to fingerprint for one open web port, or None if it is
    not a web service (or is one the crawler already covers on 80/443)."""
    svc = (port.get("service") or "").lower()
    tunnel = (port.get("tunnel") or "").lower()
    pn = port.get("port")
    if pn is None or pn in (80, 443):
        return None
    if not (svc in _WEB_SERVICES or "http" in svc):
        return None
    scheme = "https" if (tunnel == "ssl" or "https" in svc or pn in (8443, 4443)) else "http"
    host = (rec.get("subdomains") or [rec["ip"]])[0]     # a vhost beats the bare IP
    return f"{scheme}://{host}:{pn}/"


def _host_port(url: str) -> tuple[str, int] | None:
    try:
        u = urlparse(url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        return (host, port) if host else None
    except Exception:
        return None


def fingerprint_web_ports(result: ScanResult, *, timeout: int | None = None) -> int:
    """WhatWeb every open web service that sits off 80/443, recording its tech on
    the port. Returns the number of ports tagged. No-op when WhatWeb is missing
    or nothing web-facing was found; never raises."""
    if not resolve_tool(config.WHATWEB_BIN):
        return 0
    # url -> (ip, port, protocol, host); de-duplicated by (host, port)
    targets: dict[str, tuple] = {}
    seen: set[tuple] = set()
    for rec in result._ips.values():              # type: ignore[attr-defined]
        for p in rec.get("ports") or []:
            url = _web_url_for(rec, p)
            if not url:
                continue
            hp = _host_port(url)
            if not hp or hp in seen:
                continue
            seen.add(hp)
            targets[url] = (rec["ip"], p["port"], p.get("protocol", "tcp"), hp[0])
    if not targets:
        return 0

    # Reuse the fingerprint module's WhatWeb runner (JSON parse, batching, Tor
    # wrapping) and tag extractor rather than re-implementing them here.
    from . import fingerprint as _fp
    log.info(f"fingerprinting {len(targets)} open web port"
             f"{'s' if len(targets) != 1 else ''} with WhatWeb")
    records = _fp._run_whatweb(list(targets.keys()),
                               timeout=timeout or config.PORTSCAN_TIMEOUT)
    by_hp: dict[tuple, dict] = {}
    for rec in records:
        hp = _host_port(rec.get("target", ""))
        if hp:
            by_hp.setdefault(hp, rec)

    tagged = 0
    for (ip, pn, proto, host) in targets.values():
        rec = by_hp.get((host, pn))
        if not rec:
            continue
        plugins = rec.get("plugins", {})
        tech = _fp._extract_tags(plugins)
        result.record_port_tech(ip, pn, protocol=proto, tech=tech, whatweb={
            "target": rec.get("target"), "http_status": rec.get("http_status"),
            "plugins": sorted(plugins.keys())})
        if tech:
            tagged += 1
    log.info(f"WhatWeb tagged {tagged} open web port{'s' if tagged != 1 else ''}")
    return tagged
