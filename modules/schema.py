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
from .spill import SpillMap
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
            "secrets": len(self._secrets),
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
