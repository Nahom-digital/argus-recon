"""
ScanResult · the single in-memory container every module writes into.

It owns de-duplication (so the crawler, JS parser and bruteforce can all report
the same URL without creating duplicates), merges evidence from multiple
sources, and serialises to the `{domain}_{timestamp}.json` file the spec
requires. Internally records are stored in dicts keyed for dedup; `to_dict()`
flattens them to lists for the JSON on disk.
"""
from __future__ import annotations

import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .spill import SpillMap
from .util import registrable_root, host_of, short_hash


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Findings severity ladder · higher wins when two reports of the same thing are
# merged, and the dashboard sorts on it. Kept here so every module that raises a
# finding (schema.add_finding) agrees on the same five levels.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(sev: str | int | None) -> str:
    """Coerce any of the severities modules speak (a 1..3 int from the classifier,
    a bare 'warn', a stray 'crit') onto the five-level ladder above."""
    if isinstance(sev, (int, float)):
        return {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(sev), "medium")
    s = (sev or "").strip().lower()
    if s in SEVERITY_RANK:
        return s
    return {"informational": "info", "warn": "low", "warning": "low",
            "moderate": "medium", "med": "medium", "important": "high",
            "crit": "critical", "severe": "critical"}.get(s, "info")


class ScanResult:
    def __init__(self, domain: str):
        self.domain = registrable_root(domain)
        self.started = time.time()
        self.meta: dict[str, Any] = {
            "domain": self.domain,
            "tool": "argus-recon",
            # Scanner version (semantic) · kept at the top level for backward
            # compatibility with readers that already look at meta.version.
            "version": config.SCANNER_VERSION,
            # Concrete build behind the semantic version (git short commit).
            "engine": config.BUILD_REV,
            # Full, structured version record surfaced in history / details /
            # findings / reports. `tools` is filled in by the engine once the
            # external toolchain versions have been captured for this run.
            "versions": {
                "scanner": config.SCANNER_VERSION,
                "engine": config.BUILD_REV,
                "python": platform.python_version(),
                "scanned_at": datetime.now().strftime("%Y-%m-%d"),
                "tools": {},   # tool_name -> version string
            },
            "started_at": _now_iso(),
            "finished_at": None,
            "scan_id": f"{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "modules": {},   # module_name -> {"status", "duration", "note"}
        }
        # Keyed stores for dedup ------------------------------------------------
        self._subdomains: dict[str, dict] = {}      # host -> record
        self._ips: dict[str, dict] = {}             # ip -> record
        # Endpoints are the one store that scales without bound (a deep crawl is
        # a million records). They live in a spill store: in memory while small,
        # overflowing to disk once large, so the worker's footprint stays bounded
        # instead of running the process out of memory · see modules.spill.
        self._endpoints = SpillMap(                 # "METHOD url" -> record
            config.SPILL_DIR / f"{self.meta['scan_id']}.spill.db",
            hot_max=config.ENDPOINT_HOT_MAX)
        self._files: dict[str, dict] = {}           # url -> record
        self._js_files: dict[str, dict] = {}        # url -> record
        self._secrets: dict[str, dict] = {}         # hash -> record
        # Findings · the one normalised, cross-module store. Every analysis stage
        # (port scan, HTTP/TLS review, JS analysis, Shodan, 403 bypass) reports
        # what it concludes here, deduplicated and merged, so the dashboard has a
        # single ranked list of "what is wrong / what is exposed" independent of
        # which tool noticed it. Keyed by a stable signature for auto-merge.
        self._findings: dict[str, dict] = {}        # signature hash -> record
        # DNS records + historical DNS (module 1 / SecurityTrails + resolver)
        self.dns: dict[str, Any] = {
            "records": {},      # type -> [ {value, first_seen, last_seen, ...} ]
            "history": {},      # type -> [ {value, first_seen, last_seen, ...} ]
            "sources": [],      # e.g. ["dns", "s"]
            "whois": {},
            "subdomain_count": None,
        }

    # ------------------------------------------------------------------ #
    # Subdomains
    # ------------------------------------------------------------------ #
    def add_subdomain(self, host: str, *, source: str | None = None,
                      ips: list[str] | None = None, resolved: bool | None = None) -> dict:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return {}
        rec = self._subdomains.get(host)
        if rec is None:
            rec = {
                "host": host,
                "ips": [],
                "sources": [],
                "resolved": False,
                "http": {},          # {scheme,status,title,server,final_url,content_type}
                "tech": [],          # tech tags from fingerprint
                "whatweb": {},       # raw whatweb record
            }
            self._subdomains[host] = rec
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        for ip in ips or []:
            self._link_ip(rec, ip)
        if resolved is not None:
            rec["resolved"] = rec["resolved"] or resolved
        return rec

    def _link_ip(self, sub_rec: dict, ip: str, source: str | None = None) -> None:
        ip = (ip or "").strip()
        if not ip:
            return
        if ip not in sub_rec["ips"]:
            sub_rec["ips"].append(ip)
            sub_rec["resolved"] = True
        iprec = self.add_ip(ip, source=source)
        if sub_rec["host"] not in iprec["subdomains"]:
            iprec["subdomains"].append(sub_rec["host"])

    def set_http_info(self, host: str, **kwargs) -> None:
        rec = self.add_subdomain(host)
        rec["http"].update({k: v for k, v in kwargs.items() if v is not None})

    # ------------------------------------------------------------------ #
    # Infra / IPs
    # ------------------------------------------------------------------ #
    def add_ip(self, ip: str, *, source: str | None = None) -> dict:
        ip = (ip or "").strip()
        rec = self._ips.get(ip)
        if rec is None:
            rec = {
                "ip": ip,
                "subdomains": [],
                "sources": [],
                "asn": None, "org": None, "hostname": None,
                "city": None, "region": None, "country": None, "loc": None,
                "provider": None, "type": None, "datacenter": None,
                "whois": {}, "ip_history": [],
                "cdn": None,        # {name, kind} when the address is a CDN/WAF/cloud edge
                "shodan": None,     # passive host intel (modules.shodan_enrich)
                "enriched": False,
                # port scan (module 7a) · open services on this address
                "ports": [],        # [{port, protocol, state, service, ...}]
                "os": None,         # best OS guess {name, accuracy, family}
                "traceroute": [],   # [{hop, ip, rtt, host}]
                "scanned": False,   # this address went through the port scan
            }
            self._ips[ip] = rec
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        return rec

    # ------------------------------------------------------------------ #
    # Ports / services (module 7a)
    # ------------------------------------------------------------------ #
    def add_port(self, ip: str, port: int, *, protocol: str = "tcp",
                 state: str = "open", service: str | None = None,
                 product: str | None = None, version: str | None = None,
                 extrainfo: str | None = None, tunnel: str | None = None,
                 cpe: list[str] | None = None, scripts: dict | None = None,
                 reason: str | None = None, source: str = "p") -> dict:
        """Record one open port on an address. Keyed by (port, protocol) so a
        re-scan merges into the same record instead of duplicating it."""
        rec = self.add_ip(ip, source=source)
        try:
            port = int(port)
        except (TypeError, ValueError):
            return {}
        for existing in rec["ports"]:
            if existing["port"] == port and existing["protocol"] == protocol:
                entry = existing
                break
        else:
            entry = {"port": port, "protocol": protocol, "state": state,
                     "service": None, "product": None, "version": None,
                     "extrainfo": None, "tunnel": None, "cpe": [],
                     "scripts": {}, "reason": None,
                     # tech fingerprint of the web service answering on this port
                     # (WhatWeb against host:port · see portscan.fingerprint_web_ports)
                     "tech": [], "whatweb": {}}
            rec["ports"].append(entry)
            rec["ports"].sort(key=lambda p: (p["protocol"], p["port"]))
        for key, val in (("state", state), ("service", service),
                         ("product", product), ("version", version),
                         ("extrainfo", extrainfo), ("tunnel", tunnel),
                         ("reason", reason)):
            if val and not entry.get(key):
                entry[key] = val
        for c in cpe or []:
            if c and c not in entry["cpe"]:
                entry["cpe"].append(c)
        for name, out in (scripts or {}).items():
            if name and out and name not in entry["scripts"]:
                entry["scripts"][name] = out
        return entry

    def record_port_tech(self, ip: str, port: int, *, protocol: str = "tcp",
                         tech: list[str] | None = None,
                         whatweb: dict | None = None) -> dict | None:
        """Attach a web-service fingerprint to an already-recorded open port.
        Called after the port scan runs WhatWeb against the host:port that
        answered · no-op if that port was never recorded."""
        rec = self._ips.get((ip or "").strip())
        if not rec:
            return None
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None
        for entry in rec["ports"]:
            if entry["port"] == port and entry["protocol"] == protocol:
                for t in tech or []:
                    t = (t or "").strip()
                    if t and t not in entry["tech"]:
                        entry["tech"].append(t)
                if whatweb:
                    entry["whatweb"] = whatweb
                return entry
        return None

    # ------------------------------------------------------------------ #
    # Endpoints / requests
    # ------------------------------------------------------------------ #
    def add_endpoint(self, url: str, *, method: str = "GET", etype: str = "link",
                     source: str = "crawler", found_on: str | None = None,
                     in_scope: bool | None = None, status: int | None = None,
                     content_type: str | None = None, title: str | None = None,
                     fields: list[dict] | None = None, headers: dict | None = None,
                     resp_headers: dict | None = None,
                     req_body: str | None = None, resp_body: str | None = None,
                     note: str | None = None) -> dict:
        method = (method or "GET").upper()
        key = f"{method} {url}"
        rec = self._endpoints.get(key)
        if in_scope is None:
            from .util import in_scope as _scope
            in_scope = _scope(url, self.domain)
        if rec is None:
            rec = {
                "id": short_hash(method, url),
                "url": url,
                "host": host_of(url),
                "method": method,
                "type": etype,
                "in_scope": bool(in_scope),
                "sources": [],
                "found_on": [],
                "status": status,
                "content_type": content_type,
                "title": title,
                "fields": [],
                "req_headers": headers or {},
                "resp_headers": resp_headers or {},
                "req_body": (req_body or "")[: config.MAX_BODY_STORE],
                "resp_body": (resp_body or "")[: config.MAX_BODY_STORE],
                "dom": None,             # per-page DOM detail for page endpoints
                "classifications": [],   # populated by classifier
                "notes": [],
            }
            self._endpoints[key] = rec
        # merge evidence
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        if found_on and found_on not in rec["found_on"]:
            rec["found_on"].append(found_on)
        if status is not None:
            rec["status"] = status
        if content_type and not rec["content_type"]:
            rec["content_type"] = content_type
        if title and not rec["title"]:
            rec["title"] = title
        if headers:
            rec["req_headers"].update(headers)
        if resp_headers:
            rec["resp_headers"].update(resp_headers)
        if resp_body and not rec["resp_body"]:
            rec["resp_body"] = resp_body[: config.MAX_BODY_STORE]
        if note and note not in rec["notes"]:
            rec["notes"].append(note)
        # prefer a more specific type than plain "link"
        if etype and (rec["type"] == "link" or etype in ("form", "xhr", "fetch")):
            rec["type"] = etype
        for f in fields or []:
            self._merge_field(rec, f)
        return rec

    @staticmethod
    def _merge_field(rec: dict, field: dict) -> None:
        name = (field.get("name") or "").strip()
        if not name:
            return
        for existing in rec["fields"]:
            if existing.get("name") == name:
                for k, v in field.items():
                    if v and not existing.get(k):
                        existing[k] = v
                return
        rec["fields"].append(dict(field))

    def iter_endpoints(self):
        return self._endpoints.values()

    def map_endpoints(self, fn) -> None:
        """Apply fn(endpoint) to every endpoint, persisting the change even for
        records that have spilled to disk. The classifier uses this to tag each
        endpoint · a plain iterate-and-mutate would silently drop the tags on any
        record that is no longer in memory."""
        self._endpoints.map_inplace(fn)

    # ------------------------------------------------------------------ #
    # Discovered files
    # ------------------------------------------------------------------ #
    def add_file(self, url: str, *, kind: str, subtype: str = "", source: str = "crawler",
                 status: int | None = None, size: int | None = None,
                 found_on: str | None = None, content_type: str | None = None,
                 req_headers: dict | None = None, resp_headers: dict | None = None,
                 resp_body: str | None = None, final_url: str | None = None) -> dict:
        rec = self._files.get(url)
        if rec is None:
            rec = {"url": url, "host": host_of(url), "kind": kind, "subtype": subtype,
                   "sources": [], "status": status, "size": size, "found_on": [],
                   "content_type": content_type, "final_url": final_url,
                   # verdict · set by modules.falsepos after discovery: "file"
                   # (genuine), "webpage" (HTML served for a file request) or
                   # "false_positive" (a 200 that is really an error page).
                   "verdict": "file", "fp_reason": "",
                   "req_headers": {}, "resp_headers": {}, "resp_body": ""}
            self._files[url] = rec
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        if found_on and found_on not in rec["found_on"]:
            rec["found_on"].append(found_on)
        if status is not None:
            rec["status"] = status
        if size is not None:
            rec["size"] = size
        if content_type and not rec.get("content_type"):
            rec["content_type"] = content_type
        if final_url and not rec.get("final_url"):
            rec["final_url"] = final_url
        if req_headers:
            rec.setdefault("req_headers", {}).update(req_headers)
        if resp_headers:
            rec.setdefault("resp_headers", {}).update(resp_headers)
        if resp_body and not rec.get("resp_body"):
            rec["resp_body"] = resp_body[: config.MAX_BODY_STORE]
        return rec

    # ------------------------------------------------------------------ #
    # JS files
    # ------------------------------------------------------------------ #
    def add_js_file(self, url: str, *, source: str = "crawler",
                    found_on: str | None = None) -> dict:
        rec = self._js_files.get(url)
        if rec is None:
            rec = {"url": url, "host": host_of(url), "sources": [], "found_on": [],
                   "endpoints": [], "requests": [], "secrets": [],
                   # deep-recon categories (js_parser.parse) · empty by default so
                   # a record from an older scan or a non-parsed file stays valid
                   "graphql": [], "graphql_introspection": False, "websockets": [],
                   "oauth": [], "source_maps": [], "cloud": [], "firebase": None,
                   "internal_refs": [], "analytics": [], "comments": [],
                   "params": [], "third_party": []}
            self._js_files[url] = rec
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        if found_on and found_on not in rec["found_on"]:
            rec["found_on"].append(found_on)
        return rec

    # ------------------------------------------------------------------ #
    # Secrets
    # ------------------------------------------------------------------ #
    def add_secret(self, *, kind: str, match: str, severity: str, source_url: str,
                   context: str = "", found_by: str = "js") -> dict:
        key = short_hash(kind, match, source_url)
        rec = self._secrets.get(key)
        if rec is None:
            rec = {"type": kind, "match": match, "severity": severity,
                   "source": source_url, "host": host_of(source_url),
                   "context": context[:200], "found_by": []}
            self._secrets[key] = rec
        if found_by and found_by not in rec["found_by"]:
            rec["found_by"].append(found_by)
        return rec

    # ------------------------------------------------------------------ #
    # Findings · the normalised cross-module store
    # ------------------------------------------------------------------ #
    def add_finding(self, *, title: str, category: str, severity: str = "info",
                    confidence: int = 50, source: str = "", target: str = "",
                    evidence: str = "", parsed: dict | None = None,
                    risk: str = "", recommendation: str = "",
                    screenshot: str | None = None, tags: list[str] | None = None,
                    refs: list[str] | None = None,
                    signature: str | None = None) -> dict:
        """Record one finding, merging it into an identical earlier one.

        A finding is a normalised conclusion · "this port exposes a database",
        "this cert expired", "this JS leaks a token" · carrying everything the
        dashboard shows for it: a confidence score (0..100), a severity on the
        five-level ladder, the raw evidence and a parsed breakdown of it, the
        source that noticed it, timestamps, a plain-language risk explanation, a
        recommendation, and a screenshot when one exists.

        Deduplication is by `signature` (falling back to title) scoped to the
        target, so the same issue seen by two tools (nmap says 'ssl/http' on 8443,
        the HTTP review confirms an admin panel there) becomes one record with the
        higher severity/confidence and both sources · not two rows saying the same
        thing. Returns the stored record.
        """
        title = (title or "").strip()
        category = (category or "misc").strip().lower()
        if not title:
            return {}
        sev = normalize_severity(severity)
        try:
            conf = max(0, min(100, int(confidence)))
        except (TypeError, ValueError):
            conf = 50
        target = (target or "").strip()
        sig = (signature or title).strip().lower()
        key = short_hash(category, sig, target)
        now = _now_iso()
        rec = self._findings.get(key)
        if rec is None:
            rec = {
                "id": key,
                "title": title,
                "category": category,
                "severity": sev,
                "confidence": conf,
                "sources": [],
                "target": target,
                "host": host_of(target) if "://" in target else target,
                "evidence": (evidence or "")[: config.MAX_BODY_STORE],
                "parsed": dict(parsed or {}),
                "risk": risk or "",
                "recommendation": recommendation or "",
                "screenshot": screenshot or None,
                "tags": [],
                "refs": [],
                "occurrences": 0,
                "first_seen": now,
                "last_seen": now,
            }
            self._findings[key] = rec
        else:
            # Merge · keep the worst severity and the strongest confidence, and
            # fill anything the first report left blank.
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(rec["severity"], 0):
                rec["severity"] = sev
            rec["confidence"] = max(rec["confidence"], conf)
            if evidence and not rec["evidence"]:
                rec["evidence"] = evidence[: config.MAX_BODY_STORE]
            for k, v in (parsed or {}).items():
                rec["parsed"].setdefault(k, v)
            if risk and not rec["risk"]:
                rec["risk"] = risk
            if recommendation and not rec["recommendation"]:
                rec["recommendation"] = recommendation
            if screenshot and not rec.get("screenshot"):
                rec["screenshot"] = screenshot
            rec["last_seen"] = now
        rec["occurrences"] += 1
        if source and source not in rec["sources"]:
            rec["sources"].append(source)
        for t in tags or []:
            t = (t or "").strip()
            if t and t not in rec["tags"]:
                rec["tags"].append(t)
        for r in refs or []:
            r = (r or "").strip()
            if r and r not in rec["refs"]:
                rec["refs"].append(r)
        return rec

    def _findings_sorted(self) -> list[dict]:
        """Findings worst-first · severity, then confidence, then how many times
        it was seen. This is the order the dashboard renders them in."""
        return sorted(
            self._findings.values(),
            key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 0),
                           f.get("confidence", 0), f.get("occurrences", 0)),
            reverse=True)

    def _findings_severity_counts(self) -> dict:
        """How many findings at each severity · lets the dashboard header show a
        '2 critical / 5 high' summary from meta alone."""
        counts = {s: 0 for s in SEVERITY_RANK}
        for f in self._findings.values():
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # ------------------------------------------------------------------ #
    # DNS records + historical DNS (module 1)
    # ------------------------------------------------------------------ #
    def set_dns_records(self, rtype: str, records: list[dict], *, source: str) -> None:
        rtype = rtype.lower()
        if records:
            self.dns["records"][rtype] = records
        if source and source not in self.dns["sources"]:
            self.dns["sources"].append(source)

    def set_dns_history(self, rtype: str, records: list[dict], *, source: str) -> None:
        rtype = rtype.lower()
        if records:
            self.dns["history"][rtype] = records
        if source and source not in self.dns["sources"]:
            self.dns["sources"].append(source)

    # ------------------------------------------------------------------ #
    # Module bookkeeping
    # ------------------------------------------------------------------ #
    def mark_module(self, name: str, status: str, note: str = "", duration: float | None = None):
        self.meta["modules"][name] = {"status": status, "note": note,
                                       "duration": round(duration, 1) if duration else None}

    def record_tool_version(self, name: str, version: str | None) -> None:
        """Stamp the version of an external tool used on this run. Best-effort ·
        callers pass whatever `tool --version` reported; blanks are ignored."""
        if name and version:
            self.meta["versions"]["tools"][str(name)] = str(version)[:80]

    def set_tool_versions(self, versions: dict) -> None:
        """Bulk-record captured toolchain versions (see main._capture_tool_versions)."""
        for name, ver in (versions or {}).items():
            self.record_tool_version(name, ver)

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #
    def _stats(self) -> dict:
        dns_records = sum(len(v) for v in self.dns.get("records", {}).values())
        dns_history = sum(len(v) for v in self.dns.get("history", {}).values())
        open_ports = sum(len(r.get("ports") or []) for r in self._ips.values())
        # One streaming pass over the endpoints · a huge scan's endpoint store may
        # be mostly on disk, so materialising it just to count would defeat the
        # spill. Every tally the JSON needs is accumulated here in a single walk.
        n = in_scope = out_scope = forms = requests = fields = classified = 0
        for e in self._endpoints.values():
            n += 1
            if e["in_scope"]:
                in_scope += 1
            else:
                out_scope += 1
            etype = e["type"]
            if etype == "form":
                forms += 1
            if etype in ("form", "xhr", "fetch"):
                requests += 1
            fields += sum(1 for f in (e.get("fields") or []) if f.get("name"))
            if e["classifications"]:
                classified += 1
        return {
            "subdomains": len(self._subdomains),
            "ips": len(self._ips),
            "open_ports": open_ports,
            "scanned_ips": sum(1 for r in self._ips.values() if r.get("scanned")),
            "endpoints": n,
            "in_scope_endpoints": in_scope,
            "out_of_scope_endpoints": out_scope,
            "forms": forms,
            # The graph groups form/xhr/fetch endpoints under one "Request" node
            # type and counts each named input as a "Field". Recording both here
            # means the graph legend can report the true surface of a huge scan
            # from `meta` alone · without re-walking a million endpoints to count.
            "requests": requests,
            "fields": fields,
            "js_files": len(self._js_files),
            "files": len(self._files),
            # Files re-labelled by modules.falsepos as a web page / soft-404 ·
            # surfaced so the dashboard can report "N files (M flagged)".
            "files_false_positive": sum(
                1 for r in self._files.values()
                if r.get("verdict", "file") != "file"),
            "secrets": len(self._secrets),
            "findings": len(self._findings),
            "findings_by_severity": self._findings_severity_counts(),
            "classified_requests": classified,
            "dns_records": dns_records,
            "dns_history": dns_history,
        }

    def _shell(self) -> dict:
        """The whole document except the endpoints array · every layer that stays
        small no matter how large the crawl gets (meta, dns, subdomains, infra,
        files, js_files, secrets). Stamps the closing meta fields as a side effect
        so it is the single place `finished_at` / `duration_sec` / `stats` are set."""
        self.meta["finished_at"] = _now_iso()
        self.meta["duration_sec"] = round(time.time() - self.started, 1)
        self.meta["stats"] = self._stats()
        return {
            "meta": self.meta,
            "dns": self.dns,
            "subdomains": sorted(self._subdomains.values(), key=lambda r: r["host"]),
            "infra": {"ips": sorted(self._ips.values(), key=lambda r: r["ip"])},
            "files": sorted(self._files.values(), key=lambda r: r["url"]),
            "js_files": sorted(self._js_files.values(), key=lambda r: r["url"]),
            "secrets": list(self._secrets.values()),
            "findings": self._findings_sorted(),
        }

    def to_dict(self) -> dict:
        # `endpoints` is written LAST on purpose. It is the only array that scales
        # without bound (a deep crawl is a million records / a gigabyte); every
        # other layer stays small. Keeping it last means a reader that needs only
        # the "shell" · meta, dns, subdomains, infra, files, js_files, secrets ·
        # can stream forward and stop the moment the endpoints array begins,
        # instead of parsing past a gigabyte to reach a trailing key.
        #
        # This materialises every endpoint · use `save()` (which streams) for a
        # huge scan. It is kept for callers that genuinely need the whole document
        # in hand (a Neo4j load, the tests).
        doc = self._shell()
        doc["endpoints"] = list(self._endpoints.sorted_stream())
        return doc

    def save(self, scans_dir: Path | None = None) -> Path:
        """Write the scan JSON, streaming the endpoints array straight into the
        file so the whole (potentially gigabyte) list is never resident at once,
        and index each endpoint into the SQLite cache in the same pass. This is
        what keeps a million-endpoint scan from running the worker out of memory
        at the finish line."""
        scans_dir = scans_dir or config.SCANS_DIR
        scans_dir.mkdir(parents=True, exist_ok=True)
        out = scans_dir / f"{self.meta['scan_id']}.json"
        shell = self._shell()
        # Populate the SQLite cache (summary + per-endpoint light index) so the
        # dashboard never has to parse this whole file just to list it or expand a
        # row · fed endpoint-by-endpoint here. Best-effort · the JSON is the truth.
        indexer = None
        try:
            from . import store
            indexer = store.ScanIndexer(self.meta["scan_id"], shell)
        except Exception:
            indexer = None
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("{")
            for i, (key, val) in enumerate(shell.items()):
                if i:
                    fh.write(",")
                fh.write(json.dumps(key) + ":" + json.dumps(val, ensure_ascii=False))
            fh.write(',"endpoints":[')
            first = True
            for ep in self._endpoints.sorted_stream():
                fh.write(json.dumps(ep, ensure_ascii=False) if first
                         else "," + json.dumps(ep, ensure_ascii=False))
                first = False
                if indexer is not None:
                    indexer.add(ep)
            fh.write("]}")
        if indexer is not None:
            try:
                indexer.finish(out)
            except Exception:
                pass
        return out

    def close(self) -> None:
        """Release the endpoint spill store and delete its scratch file. Safe to
        call more than once; call it when the scan is fully written."""
        try:
            self._endpoints.close()
        except Exception:
            pass
