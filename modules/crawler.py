"""
Module 3 — In-scope crawler.

Starts from each subdomain root and walks the target domain breadth-first,
following internal links, form actions and JS-discovered request URLs until no
new in-domain URLs remain (bounded by page/depth safety caps). It drives the
HTML parser (module 4) and JS parser (module 5) on every page and script.

Scope rule (enforced here via util.in_scope): anything pointing outside the
target domain + subdomains is logged exactly once as an out-of-scope endpoint
entry — method, full URL, where it was found — and never fetched or followed.
"""
from __future__ import annotations

import concurrent.futures
import re
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse, parse_qsl

from . import config, html_parser, js_parser
from .schema import ScanResult
from .util import (get_logger, make_session, normalize_url, in_scope, host_of,
                   classify_resource, is_html, is_javascript, is_interesting_file)

log = get_logger("crawler")

# Kinds we record but never download the body of (binary / not worth parsing).
_LIGHT_KINDS = {"image", "font", "archive", "document", "media"}
# Kinds whose text we mine for endpoints/secrets.
_TEXT_KINDS = {"page", "js", "data", "config", "backup", "other", "style"}
_MAX_HTML_BYTES = 3_000_000

# Aggressive URL mining: absolute URLs and quoted root-relative paths that the
# structured DOM/JS parsers may have missed (inline JSON, data-* attributes,
# templated markup). Kept conservative to avoid capturing noise.
_ABS_URL_RX = re.compile(r"""https?://[a-z0-9.\-]+(?:/[^\s"'<>()\\]*)?""", re.I)
_REL_PATH_RX = re.compile(r"""["'(]\s*(/[A-Za-z0-9_\-./]{1,120}(?:\.[A-Za-z0-9]{1,6})?(?:\?[^\s"'<>()]{0,120})?)""")
# response headers that carry a next URL worth following
_LOCATION_HEADERS = ("location", "content-location")


def _query_fields(url: str) -> list[dict]:
    q = urlparse(url).query
    return [{"name": k, "type": "param", "location": "query"}
            for k, _ in parse_qsl(q, keep_blank_values=True) if k]


class Crawler:
    def __init__(self, result: ScanResult, *, max_pages: int, max_depth: int,
                 threads: int):
        self.result = result
        self.domain = result.domain
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.threads = threads
        self.session = make_session()
        self.visited: set[str] = set()
        self.js_done: set[str] = set()
        self.host_pages: dict[str, int] = defaultdict(int)
        self._seen_hosts: set[str] = set()
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Networking
    # ------------------------------------------------------------------ #
    def _fetch(self, url: str):
        """GET a URL. Returns (resp, kind, text|None). Bodies are size-capped;
        binary/asset kinds are recorded without downloading the body."""
        try:
            resp = self.session.get(url, timeout=config.HTTP_TIMEOUT,
                                    allow_redirects=True, stream=True)
        except Exception as exc:
            log.debug(f"fetch failed {url}: {exc}")
            return None, None, None
        ct = resp.headers.get("Content-Type", "")
        kind, _sub = classify_resource(resp.url, ct)
        text = None
        if kind in _LIGHT_KINDS:
            resp.close()
            return resp, kind, None
        cap = config.MAX_JS_BYTES if kind == "js" else _MAX_HTML_BYTES
        try:
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
            raw = b"".join(chunks)
            enc = resp.encoding or "utf-8"
            text = raw.decode(enc, errors="replace")
        except Exception:
            text = None
        finally:
            resp.close()
        return resp, kind, text

    # ------------------------------------------------------------------ #
    # JS handling
    # ------------------------------------------------------------------ #
    def _handle_js(self, url: str, text: str, found_on: str) -> set[str]:
        new: set[str] = set()
        parsed = js_parser.parse(text or "", url)
        with self.lock:
            jsrec = self.result.add_js_file(url, source="crawler", found_on=found_on)
            jsrec["endpoints"] = parsed["endpoints"]
            jsrec["requests"] = parsed["requests"]
            jsrec["secrets"] = parsed["secrets"]
            for s in parsed["secrets"]:
                self.result.add_secret(kind=s["type"], match=s["match"],
                                       severity=s["severity"], source_url=url,
                                       context=s.get("context", ""), found_by="js")
            # endpoints discovered as string literals
            for ep in parsed["endpoints"]:
                norm = normalize_url(ep, url)
                if not norm:
                    continue
                scoped = in_scope(norm, self.domain)
                if scoped:
                    self._register_host(norm)
                self.result.add_endpoint(
                    norm, etype="link", source="js", found_on=url,
                    in_scope=scoped, fields=_query_fields(norm))
                if scoped:
                    new.add(norm)
            # concrete request calls (fetch/axios/XHR) — the button->request map
            for r in parsed["requests"]:
                norm = normalize_url(r["url"], url)
                if not norm:
                    continue
                scoped = in_scope(norm, self.domain)
                if scoped:
                    self._register_host(norm)
                note = f"{r['kind']} call"
                if r.get("handler"):
                    note += f" in {r['handler']}()"
                rec = self.result.add_endpoint(
                    norm, method=r["method"], etype="xhr", source="js",
                    found_on=url, in_scope=scoped, fields=_query_fields(norm),
                    note=note)
                rec.setdefault("js_origin", []).append(
                    {"file": url, "line": r.get("line"), "handler": r.get("handler"),
                     "snippet": r.get("snippet"), "kind": r["kind"]})
                if scoped and r["method"] in ("GET", None):
                    new.add(norm)
        return new

    # ------------------------------------------------------------------ #
    # HTML handling
    # ------------------------------------------------------------------ #
    def _handle_html(self, url: str, text: str) -> tuple[set[str], set[str]]:
        """Return (in_scope_urls_to_enqueue, js_urls_to_fetch)."""
        dom = html_parser.parse(text or "", url)
        enqueue: set[str] = set()
        js_urls: set[str] = set()

        with self.lock:
            page = self.result.add_endpoint(url, etype="page", source="crawler")
            page["dom"] = {
                "forms": len(dom["forms"]),
                "buttons": dom["buttons"][:200],
                "images": dom["images"][:200],
                "meta": dom["meta"][:100],
                "comments": dom["comments"][:100],
                "favicon": dom["favicon"],
            }

            # forms -> endpoints with fields
            for form in dom["forms"]:
                action = form["action"]
                scoped = in_scope(action, self.domain)
                fields = list(form["fields"])
                if form["method"] == "GET":
                    fields += _query_fields(action)
                self.result.add_endpoint(
                    action, method=form["method"], etype="form", source="crawler",
                    found_on=url, in_scope=scoped, fields=fields,
                    note=f"form enctype={form['enctype']}")
                if scoped and form["method"] == "GET":
                    enqueue.add(normalize_url(action) or action)

            # favicon / images / meta as artefacts
            if dom["favicon"]:
                self.result.add_file(dom["favicon"], kind="image", subtype="favicon",
                                     source="crawler", found_on=url)

            # anchors
            for link in dom["links"]:
                self._route(link, url, enqueue)
            for hu in dom["handler_urls"]:
                self._route(hu, url, enqueue)

            # aggressive sweep for URLs the DOM parser missed (item 3)
            self._mine_text(text, url, url, enqueue)

            # resources
            for r in dom["resources"]:
                ru = r["url"]
                if is_javascript(ru):
                    if in_scope(ru, self.domain):
                        js_urls.add(ru)
                    else:
                        self.result.add_endpoint(ru, etype="resource", source="crawler",
                                                 found_on=url, in_scope=False)
                elif is_interesting_file(ru):
                    kind, sub = classify_resource(ru)
                    self.result.add_file(ru, kind=kind, subtype=sub, source="crawler",
                                         found_on=url)
                    self._route(ru, url, enqueue, enqueue_ok=False)
                else:
                    self._route(ru, url, enqueue, enqueue_ok=False)

            for img in dom["images"]:
                if img.get("src"):
                    self.result.add_file(img["src"], kind="image", subtype="image",
                                         source="crawler", found_on=url)

            # inline scripts
            for i, script in enumerate(dom["inline_scripts"]):
                parsed = js_parser.parse(script, f"{url}#inline-{i}")
                for s in parsed["secrets"]:
                    self.result.add_secret(kind=s["type"], match=s["match"],
                                           severity=s["severity"], source_url=url,
                                           context=s.get("context", ""), found_by="js")
                for ep in parsed["endpoints"]:
                    norm = normalize_url(ep, url)
                    if norm:
                        self._route(norm, url, enqueue)
                for rq in parsed["requests"]:
                    norm = normalize_url(rq["url"], url)
                    if not norm:
                        continue
                    scoped = in_scope(norm, self.domain)
                    if scoped:
                        self._register_host(norm)
                    self.result.add_endpoint(norm, method=rq["method"], etype="xhr",
                                             source="js", found_on=url,
                                             in_scope=scoped, fields=_query_fields(norm),
                                             note=f"inline {rq['kind']} call")

        return enqueue, js_urls

    def _route(self, target: str, found_on: str, enqueue: set[str],
               enqueue_ok: bool = True) -> None:
        """Normalise a URL, record it, and enqueue if in-scope. Caller holds lock."""
        norm = normalize_url(target, found_on)
        if not norm:
            return
        if in_scope(norm, self.domain):
            self._register_host(norm)
            self.result.add_endpoint(norm, etype="link", source="crawler",
                                     found_on=found_on, in_scope=True,
                                     fields=_query_fields(norm))
            if enqueue_ok:
                enqueue.add(norm)
        else:
            # Scope rule: log once, never follow.
            self.result.add_endpoint(norm, etype="link", source="crawler",
                                     found_on=found_on, in_scope=False)

    def _register_host(self, url: str) -> None:
        """Any in-scope host we touch while crawling becomes a listed subdomain,
        even if passive enum never reported it (fix list, item 1). Caller holds
        the lock."""
        host = host_of(url)
        if host and host not in self._seen_hosts:
            self._seen_hosts.add(host)
            self.result.add_subdomain(host, source="crawler")

    def _mine_text(self, text: str, base: str, found_on: str, enqueue: set[str]) -> None:
        """Regex-sweep a body for absolute URLs and quoted root-relative paths
        the structured parsers missed. Caller holds the lock."""
        if not text:
            return
        hits = 0
        for m in _ABS_URL_RX.finditer(text):
            self._route(m.group(0).rstrip('.,);"\''), found_on, enqueue)
            hits += 1
            if hits > 4000:
                break
        for m in _REL_PATH_RX.finditer(text):
            self._route(m.group(1), found_on, enqueue)
            hits += 1
            if hits > 4000:
                break

    # ------------------------------------------------------------------ #
    # Per-URL processing
    # ------------------------------------------------------------------ #
    def _process(self, url: str) -> set[str]:
        resp, kind, text = self._fetch(url)
        if resp is None:
            with self.lock:
                self.result.add_endpoint(url, etype="page", source="crawler",
                                         note="request failed / no response")
            return set()

        final = normalize_url(resp.url) or url
        status = resp.status_code
        ct = resp.headers.get("Content-Type", "")
        resp_headers = {k: v for k, v in resp.headers.items()
                        if k.lower() in ("server", "content-type", "content-length",
                                         "location", "set-cookie", "x-powered-by",
                                         "via", "cf-ray", "strict-transport-security",
                                         "content-security-policy")}

        # If a redirect carried us out of scope, log the destination and stop.
        if not in_scope(final, self.domain):
            with self.lock:
                self.result.add_endpoint(url, etype="page", source="crawler",
                                         status=status, content_type=ct,
                                         resp_headers=resp_headers,
                                         note=f"redirects out-of-scope -> {final}")
                self.result.add_endpoint(final, etype="link", source="crawler",
                                         found_on=url, in_scope=False,
                                         note="redirect target")
            return set()

        new: set[str] = set()
        etype = "js" if kind == "js" else ("page" if kind == "page" else "resource")
        req_headers = dict(self.session.headers)

        with self.lock:
            self._register_host(final)
            rec = self.result.add_endpoint(
                final, etype=etype, source="crawler", status=status,
                content_type=ct, resp_headers=resp_headers,
                req_body=None, headers=req_headers,
                resp_body=(text or "")[: config.MAX_BODY_STORE],
                fields=_query_fields(final))
            if kind in _LIGHT_KINDS or is_interesting_file(final, ct):
                k, sub = classify_resource(final, ct)
                # capture request + response so the Files panel can show them (item 10)
                self.result.add_file(
                    final, kind=k, subtype=sub, source="crawler",
                    status=status, size=_content_length(resp),
                    content_type=ct, final_url=final,
                    req_headers=req_headers, resp_headers=resp_headers,
                    resp_body=(text or "")[:4000] if kind not in _LIGHT_KINDS else "")
            # follow same-scope Location/Content-Location redirect targets
            for hk in _LOCATION_HEADERS:
                loc = resp.headers.get(hk)
                if loc:
                    self._route(loc, final, new)

        if text and kind == "js":
            new |= self._handle_js(final, text, found_on=url)
        elif text and is_html(ct):
            enq, js_urls = self._handle_html(final, text)
            new |= enq
            for ju in js_urls:
                if ju not in self.js_done:
                    self.js_done.add(ju)
                    new |= self._fetch_js_now(ju, found_on=final)
        elif text and kind in _TEXT_KINDS:
            # data/config/backup/other textual: mine for endpoints + secrets.
            new |= self._handle_js(final, text, found_on=url)
            with self.lock:
                self._mine_text(text, final, final, new)

        return {u for u in new if u not in self.visited}

    def _fetch_js_now(self, url: str, found_on: str) -> set[str]:
        resp, kind, text = self._fetch(url)
        if resp is None or not text:
            with self.lock:
                self.result.add_js_file(url, source="crawler", found_on=found_on)
            return set()
        with self.lock:
            self.result.add_endpoint(url, etype="js", source="crawler",
                                     status=resp.status_code,
                                     content_type=resp.headers.get("Content-Type"))
        return self._handle_js(url, text, found_on=found_on)

    # ------------------------------------------------------------------ #
    # Map-file seeding (robots.txt / sitemap.xml) — runs before the BFS
    # ------------------------------------------------------------------ #
    def _seed_urls_from_maps(self, roots: list[str]) -> list[str]:
        seeds: list[str] = []
        for root in roots:
            for mp in ("/robots.txt", "/sitemap.xml"):
                url = root + mp
                try:
                    resp = self.session.get(url, timeout=config.HTTP_TIMEOUT)
                except Exception:
                    continue
                if resp.status_code != 200 or not resp.text:
                    continue
                if mp.endswith("robots.txt"):
                    for line in resp.text.splitlines():
                        m = re.match(r"(?:Dis)?[Aa]llow:\s*(\S+)", line.strip())
                        if m:
                            p = m.group(1).split("*")[0].split("?")[0]
                            if p.startswith("/"):
                                full = normalize_url(p, root)
                                if full and in_scope(full, self.domain):
                                    seeds.append(full)
                        sm = re.match(r"[Ss]itemap:\s*(\S+)", line.strip())
                        if sm:
                            seeds += self._urls_from_sitemap(sm.group(1))
                else:
                    seeds += self._urls_from_sitemap(url, body=resp.text)
        return list(dict.fromkeys(seeds))

    def _urls_from_sitemap(self, url: str, body: str | None = None, _depth: int = 0) -> list[str]:
        if _depth > 2:
            return []
        out: list[str] = []
        try:
            if body is None:
                resp = self.session.get(url, timeout=config.HTTP_TIMEOUT)
                if resp.status_code != 200:
                    return []
                body = resp.text
            locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body or "", re.I)
        except Exception:
            return []
        for loc in locs:
            loc = loc.strip()
            if loc.endswith(".xml") and "sitemap" in loc.lower():
                out += self._urls_from_sitemap(loc, _depth=_depth + 1)
            else:
                full = normalize_url(loc)
                if full and in_scope(full, self.domain):
                    out.append(full)
        return out

    # ------------------------------------------------------------------ #
    # BFS driver
    # ------------------------------------------------------------------ #
    def crawl(self, seeds: list[str]) -> None:
        frontier = []
        for s in seeds:
            n = normalize_url(s)
            if n and in_scope(n, self.domain):
                frontier.append(n)
        frontier = list(dict.fromkeys(frontier))

        depth = 0
        while frontier and depth <= self.max_depth:
            batch = []
            for url in frontier:
                if url in self.visited:
                    continue
                host = host_of(url)
                if self.host_pages[host] >= self.max_pages:
                    continue
                self.visited.add(url)
                self.host_pages[host] += 1
                batch.append(url)
            if not batch:
                break
            log.info(f"depth {depth}: crawling {len(batch)} URLs "
                     f"({len(self.visited)} seen)")
            next_frontier: set[str] = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                for new_urls in ex.map(self._process, batch):
                    next_frontier |= new_urls
            frontier = [u for u in next_frontier if u not in self.visited]
            depth += 1

        log.info(f"crawl complete: {len(self.visited)} pages fetched, "
                 f"{len(self.js_done)} JS files parsed")


def _content_length(resp) -> int | None:
    try:
        return int(resp.headers.get("Content-Length"))
    except (TypeError, ValueError):
        return None


def run(result: ScanResult, *, max_pages: int | None = None,
        max_depth: int | None = None, threads: int | None = None,
        extra_seeds: list[str] | None = None) -> None:
    t0 = time.time()
    crawler = Crawler(
        result,
        max_pages=max_pages or config.CRAWL_MAX_PAGES,
        max_depth=max_depth or config.CRAWL_MAX_DEPTH,
        threads=threads or config.CRAWL_THREADS,
    )

    # Seeds: the live root of every resolving subdomain, plus any URLs BBOT/JS
    # already surfaced, plus robots.txt / sitemap.xml / common entry points.
    seeds: list[str] = []
    live_roots: list[str] = []
    for sub in result._subdomains.values():  # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("status") and not http.get("error"):
            scheme = http.get("scheme", "https")
            root = f"{scheme}://{sub['host']}"
            seeds.append(root + "/")
            live_roots.append(root)
    for ep in list(result.iter_endpoints()):
        if ep["in_scope"] and ep["type"] in ("link", "page"):
            seeds.append(ep["url"])
    # aggressiveness: prime every live host with its map files + common paths.
    for root in live_roots:
        for p in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                  "/.well-known/security.txt"):
            seeds.append(root + p)
    seeds += extra_seeds or []
    seeds = crawler._seed_urls_from_maps(live_roots) + seeds

    log.info(f"seeding crawl with {len(set(seeds))} URLs "
             f"(max {crawler.max_pages}/host, depth {crawler.max_depth})")
    crawler.crawl(seeds)

    # Resolve subdomains the crawler discovered so they appear with IPs (item 1).
    _resolve_new_subdomains(result)

    result.mark_module("crawler", "ok",
                       note=f"{len(crawler.visited)} pages, {len(crawler.js_done)} JS files, "
                            f"{len(crawler._seen_hosts)} hosts touched",
                       duration=time.time() - t0)


def _resolve_new_subdomains(result: ScanResult) -> None:
    """DNS-resolve any subdomain that still has no IP (crawler-discovered ones)."""
    from .subdomain import _resolve_many
    unresolved = [r["host"] for r in result._subdomains.values()  # type: ignore[attr-defined]
                  if not r["ips"]]
    if not unresolved:
        return
    log.info(f"resolving {len(unresolved)} newly discovered hosts")
    for host, ips in _resolve_many(unresolved).items():
        if ips:
            rec = result.add_subdomain(host)
            for ip in ips:
                result._link_ip(rec, ip, source="crawler")  # type: ignore[attr-defined]
            rec["resolved"] = True
