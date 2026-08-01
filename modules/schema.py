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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .util import registrable_root, host_of, short_hash


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ScanResult:
    def __init__(self, domain: str):
        self.domain = registrable_root(domain)
        self.started = time.time()
        self.meta: dict[str, Any] = {
            "domain": self.domain,
            "tool": "argus-recon",
            "version": "1.0.0",
            "started_at": _now_iso(),
            "finished_at": None,
            "scan_id": f"{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "modules": {},   # module_name -> {"status", "duration", "note"}
        }
        # Keyed stores for dedup ------------------------------------------------
        self._subdomains: dict[str, dict] = {}      # host -> record
        self._ips: dict[str, dict] = {}             # ip -> record
        self._endpoints: dict[str, dict] = {}       # "METHOD url" -> record
        self._files: dict[str, dict] = {}           # url -> record
        self._js_files: dict[str, dict] = {}        # url -> record
        self._secrets: dict[str, dict] = {}         # hash -> record
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
                   "endpoints": [], "requests": [], "secrets": []}
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

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #
    def _stats(self) -> dict:
        eps = list(self._endpoints.values())
        dns_records = sum(len(v) for v in self.dns.get("records", {}).values())
        dns_history = sum(len(v) for v in self.dns.get("history", {}).values())
        open_ports = sum(len(r.get("ports") or []) for r in self._ips.values())
        return {
            "subdomains": len(self._subdomains),
            "ips": len(self._ips),
            "open_ports": open_ports,
            "scanned_ips": sum(1 for r in self._ips.values() if r.get("scanned")),
            "endpoints": len(eps),
            "in_scope_endpoints": sum(1 for e in eps if e["in_scope"]),
            "out_of_scope_endpoints": sum(1 for e in eps if not e["in_scope"]),
            "forms": sum(1 for e in eps if e["type"] == "form"),
            "js_files": len(self._js_files),
            "files": len(self._files),
            "secrets": len(self._secrets),
            "classified_requests": sum(1 for e in eps if e["classifications"]),
            "dns_records": dns_records,
            "dns_history": dns_history,
        }

    def to_dict(self) -> dict:
        self.meta["finished_at"] = _now_iso()
        self.meta["duration_sec"] = round(time.time() - self.started, 1)
        self.meta["stats"] = self._stats()
        return {
            "meta": self.meta,
            "dns": self.dns,
            "subdomains": sorted(self._subdomains.values(), key=lambda r: r["host"]),
            "infra": {"ips": sorted(self._ips.values(), key=lambda r: r["ip"])},
            "endpoints": sorted(self._endpoints.values(),
                                key=lambda r: (not r["in_scope"], r["host"], r["url"])),
            "files": sorted(self._files.values(), key=lambda r: r["url"]),
            "js_files": sorted(self._js_files.values(), key=lambda r: r["url"]),
            "secrets": list(self._secrets.values()),
        }

    def save(self, scans_dir: Path | None = None) -> Path:
        scans_dir = scans_dir or config.SCANS_DIR
        scans_dir.mkdir(parents=True, exist_ok=True)
        out = scans_dir / f"{self.meta['scan_id']}.json"
        doc = self.to_dict()
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        # Populate the SQLite cache (summary + per-endpoint light index) so the
        # dashboard never has to parse this whole file just to list it or expand
        # a row. Best-effort · the JSON on disk stays the source of truth.
        try:
            from . import store
            store.index_scan(self.meta["scan_id"], doc, out)
        except Exception:
            pass
        return out
