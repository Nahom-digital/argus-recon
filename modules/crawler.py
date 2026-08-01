"""
Module 3 · In-scope crawler.

Starts from each live subdomain root (plus whatever the deep-crawl pre-pass
already discovered) and walks the target domain breadth-first, following internal
links, form actions and JS-discovered request URLs until no new in-domain URLs
remain (bounded by page/depth safety caps). It drives the HTML parser (module 4)
and JS parser (module 5) on every page and script.

Transport: the fetch layer is asyncio (`modules.asynchttp`) · one event loop with
a semaphore-bounded pool, so hundreds of requests are in flight at once instead
of one per thread. That matters because every stage around this one is a Go
binary running at that concurrency already; a thread-per-request crawler was the
slowest link in the chain and set the pace for the whole pipeline. If the async
client is unavailable (not installed, or a Tor scan without SOCKS support in it)
the original thread-pool path still runs, so the crawl degrades in speed and
never in capability.

Scope rule (enforced here via util.in_scope): anything pointing outside the
target domain + subdomains is logged exactly once as an out-of-scope endpoint
entry · method, full URL, where it was found · and never fetched or followed.
"""
from __future__ import annotations

import concurrent.futures
import re
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse, parse_qsl

from . import config, html_parser, js_parser
from .asynchttp import AsyncFetcher, Fetched, offload
from .asynchttp import available as async_available
from .asynchttp import run as run_async
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
# response headers worth keeping on the endpoint record
_KEEP_HEADERS = ("server", "content-type", "content-length", "location",
                 "set-cookie", "x-powered-by", "via", "cf-ray",
                 "strict-transport-security", "content-security-policy")


def _query_fields(url: str) -> list[dict]:
    q = urlparse(url).query
    return [{"name": k, "type": "param", "location": "query"}
            for k, _ in parse_qsl(q, keep_blank_values=True) if k]


class Crawler:
    def __init__(self, result: ScanResult, *, max_pages: int, max_depth: int,
                 threads: int, concurrency: int | None = None,
                 host_concurrency: int | None = None):
        self.result = result
        self.domain = result.domain
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.threads = threads
        self.concurrency = concurrency or config.CRAWL_CONCURRENCY
        self.host_concurrency = host_concurrency or config.CRAWL_HOST_CONCURRENCY
        self.session = make_session()          # map files + the synchronous fallback
        self.visited: set[str] = set()
        self.js_done: set[str] = set()
        self.host_pages: dict[str, int] = defaultdict(int)
        self._seen_hosts: set[str] = set()
        # Recording happens on worker threads whenever a body is large enough to
        # be parsed off the event loop, so the shared result stays behind a lock.
        self.lock = threading.Lock()
        self.engine = "async"
        self.stats: dict = {}

    # ------------------------------------------------------------------ #
    # Networking · synchronous fallback path
    # ------------------------------------------------------------------ #
    def _fetch_sync(self, url: str) -> Fetched:
        """GET a URL with the blocking client, normalised to the same result
        object the async path produces."""
        try:
            resp = self.session.get(url, timeout=config.HTTP_TIMEOUT,
                                    allow_redirects=True, stream=True)
        except Exception as exc:
            log.debug(f"fetch failed {url}: {exc}")
            return Fetched(url, error=f"{type(exc).__name__}: {exc}"[:200])
        ct = resp.headers.get("Content-Type", "")
        kind, _sub = classify_resource(resp.url, ct)
        headers = dict(resp.headers)
        clen = _int_or_none(resp.headers.get("Content-Length"))
        if kind in _LIGHT_KINDS:
            resp.close()
            return Fetched(url, final_url=resp.url, status=resp.status_code,
                           headers=headers, kind=kind, content_length=clen)
        cap = config.MAX_JS_BYTES if kind == "js" else _MAX_HTML_BYTES
        text = None
        total = 0
        try:
            chunks = []
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
            text = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            text = None
        finally:
            resp.close()
        return Fetched(url, final_url=resp.url, status=resp.status_code,
                       headers=headers, text=text, kind=kind,
                       content_length=clen if clen is not None else total)

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
            # concrete request calls (fetch/axios/XHR) · the button->request map
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
    # Per-URL recording · shared by both engines, may run on a worker thread
    # ------------------------------------------------------------------ #
    def _record(self, doc: Fetched, is_js: bool = False) -> tuple[set[str], set[str]]:
        """Fold one fetched document into the scan.

        Returns (new_in_scope_urls, js_urls_to_fetch). Pure bookkeeping plus
        parsing · no network · so it is safe to run off the event loop.
        """
        if not doc.ok:
            with self.lock:
                self.result.add_endpoint(doc.url, etype="js" if is_js else "page",
                                         source="crawler",
                                         note=doc.error or "request failed / no response")
                if is_js:
                    self.result.add_js_file(doc.url, source="crawler")
            return set(), set()

        final = normalize_url(doc.final_url) or doc.url
        status = doc.status
        ct = doc.header("Content-Type", "") or ""
        kind = doc.kind or classify_resource(final, ct)[0]
        resp_headers = {k: v for k, v in doc.headers.items()
                        if k.lower() in _KEEP_HEADERS}

        # If a redirect carried us out of scope, log the destination and stop.
        if not in_scope(final, self.domain):
            with self.lock:
                self.result.add_endpoint(doc.url, etype="page", source="crawler",
                                         status=status, content_type=ct,
                                         resp_headers=resp_headers,
                                         note=f"redirects out-of-scope -> {final}")
                self.result.add_endpoint(final, etype="link", source="crawler",
                                         found_on=doc.url, in_scope=False,
                                         note="redirect target")
            return set(), set()

        new: set[str] = set()
        js_urls: set[str] = set()
        text = doc.text
        etype = "js" if kind == "js" else ("page" if kind == "page" else "resource")
        req_headers = dict(self.session.headers)

        with self.lock:
            self._register_host(final)
            self.result.add_endpoint(
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
                    status=status, size=doc.content_length,
                    content_type=ct, final_url=final,
                    req_headers=req_headers, resp_headers=resp_headers,
                    resp_body=(text or "")[:4000] if kind not in _LIGHT_KINDS else "")
            # follow same-scope Location/Content-Location redirect targets
            for hk in _LOCATION_HEADERS:
                loc = doc.header(hk)
                if loc:
                    self._route(loc, final, new)

        if text and kind == "js":
            new |= self._handle_js(final, text, found_on=doc.url)
        elif text and is_html(ct):
            enq, js = self._handle_html(final, text)
            new |= enq
            js_urls |= js
        elif text and kind in _TEXT_KINDS:
            # data/config/backup/other textual: mine for endpoints + secrets.
            new |= self._handle_js(final, text, found_on=doc.url)
            with self.lock:
                self._mine_text(text, final, final, new)

        return new, js_urls

    # ------------------------------------------------------------------ #
    # Frontier bookkeeping (shared by both engines)
    # ------------------------------------------------------------------ #
    def _select(self, urls: set[str], js_urls: set[str]) -> list[tuple[str, bool]]:
        """Claim what may be fetched next, respecting the per-host page cap.

        Scripts are exempt from that cap: a page budget exists to stop the crawl
        drowning in one host's pagination, and refusing to read the bundle that
        names the API would defeat the point of crawling the host at all.
        """
        batch: list[tuple[str, bool]] = []
        for url in urls:
            if url in self.visited:
                continue
            host = host_of(url)
            if self.host_pages[host] >= self.max_pages:
                continue
            self.visited.add(url)
            self.host_pages[host] += 1
            batch.append((url, False))
        for url in js_urls:
            if url in self.visited or url in self.js_done:
                continue
            self.visited.add(url)
            self.js_done.add(url)
            batch.append((url, True))
        return batch

    # ------------------------------------------------------------------ #
    # Async engine
    # ------------------------------------------------------------------ #
    async def _work(self, item: tuple[str, bool], fetcher: AsyncFetcher):
        url, is_js = item
        doc = await fetcher.get(url)
        # Parsing a large body (beautify + a few dozen regex passes over a
        # megabyte bundle) takes long enough to stall every request in flight,
        # so anything sizeable is recorded on a worker thread instead.
        if doc.text and len(doc.text) > config.PARSE_OFFLOAD_BYTES:
            return await offload(self._record, doc, is_js)
        return self._record(doc, is_js)

    async def _crawl_async(self, seeds: list[str]) -> None:
        frontier = _clean(seeds, self.domain)
        js_frontier: set[str] = set()
        depth = 0
        async with AsyncFetcher(concurrency=self.concurrency,
                                host_concurrency=self.host_concurrency,
                                light_kinds=_LIGHT_KINDS) as fetcher:
            while (frontier or js_frontier) and depth <= self.max_depth:
                batch = self._select(set(frontier), js_frontier)
                js_frontier = set()
                if not batch:
                    break
                log.info(f"depth {depth}: fetching {len(batch)} URLs "
                         f"({len(self.visited)} seen, {self.concurrency} in flight)")
                next_urls: set[str] = set()
                next_js: set[str] = set()

                def collect(res):
                    if not res:
                        return
                    urls, js = res
                    next_urls.update(urls)
                    next_js.update(js)

                await fetcher.each(batch, lambda it: self._work(it, fetcher),
                                   on_result=collect)
                frontier = [u for u in next_urls if u not in self.visited]
                js_frontier = {u for u in next_js
                               if u not in self.visited and u not in self.js_done}
                depth += 1
            self.stats = dict(fetcher.stats)

    # ------------------------------------------------------------------ #
    # Synchronous engine (fallback)
    # ------------------------------------------------------------------ #
    def _work_sync(self, item: tuple[str, bool]):
        url, is_js = item
        return self._record(self._fetch_sync(url), is_js)

    def _crawl_sync(self, seeds: list[str]) -> None:
        frontier = _clean(seeds, self.domain)
        js_frontier: set[str] = set()
        depth = 0
        while (frontier or js_frontier) and depth <= self.max_depth:
            batch = self._select(set(frontier), js_frontier)
            js_frontier = set()
            if not batch:
                break
            log.info(f"depth {depth}: fetching {len(batch)} URLs "
                     f"({len(self.visited)} seen, {self.threads} threads)")
            next_urls: set[str] = set()
            next_js: set[str] = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                for res in ex.map(self._work_sync, batch):
                    if not res:
                        continue
                    urls, js = res
                    next_urls |= urls
                    next_js |= js
            frontier = [u for u in next_urls if u not in self.visited]
            js_frontier = {u for u in next_js
                           if u not in self.visited and u not in self.js_done}
            depth += 1

    # ------------------------------------------------------------------ #
    # Map-file seeding (robots.txt / sitemap.xml) · runs before the BFS
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
    # Driver
    # ------------------------------------------------------------------ #
    def crawl(self, seeds: list[str]) -> None:
        usable, why = async_available()
        if usable:
            self.engine = "async"
            run_async(self._crawl_async(seeds))
        else:
            self.engine = "threads"
            log.warning(f"{why} · falling back to the thread-pool crawler "
                        f"({self.threads} threads)")
            self._crawl_sync(seeds)

        log.info(f"crawl complete: {len(self.visited)} URLs fetched, "
                 f"{len(self.js_done)} JS files parsed")


def _clean(seeds: list[str], domain: str) -> list[str]:
    out = []
    for s in seeds:
        n = normalize_url(s)
        if n and in_scope(n, domain):
            out.append(n)
    return list(dict.fromkeys(out))


def _int_or_none(v) -> int | None:
    try:
        return int(v)
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

    # Seeds: the live root of every resolving subdomain, plus any URLs the
    # pre-passes already surfaced, plus robots.txt / sitemap.xml / entry points.
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
                       note=f"{len(crawler.visited)} URLs, {len(crawler.js_done)} JS files, "
                            f"{len(crawler._seen_hosts)} hosts touched "
                            f"({crawler.engine})",
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
