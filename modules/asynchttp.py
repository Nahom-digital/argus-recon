"""
Asynchronous HTTP layer for the crawler and the parsers.

Everything around this module is a Go binary doing hundreds of requests at once
(name enum, mass probe, deep crawl). Our own crawler used to be one blocking
`requests.get` per thread, so it became the pipeline's floor: twelve requests in
flight no matter how fast the target answered. This replaces that with a single
`httpx.AsyncClient` and a semaphore · hundreds of in-flight requests from one
thread, with the fan-out actually bounded by a number instead of by how many
threads the machine tolerates.

Two limits, not one:

  * a global semaphore (`concurrency`) caps total requests in flight,
  * a per-host semaphore (`host_concurrency`) stops a single subdomain from
    absorbing the whole budget · which is also what keeps us from looking like a
    denial-of-service to one box while the rest of the scope idles.

`available()` decides whether the async path can be used at all. Over Tor it also
needs SOCKS support in the client; without it the crawler keeps its synchronous
requests+PySocks path rather than silently leaking traffic around the proxy.

NOTE: the `httpx` here is the Python client library, not the ProjectDiscovery Go
binary of the same name used by modules.probe. Same word, unrelated programs.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable

from . import config
from .util import classify_resource, get_logger

log = get_logger("http")

_MAX_REDIRECTS = 5


def available() -> tuple[bool, str]:
    """(usable, reason). Reason is only meaningful when usable is False."""
    try:
        import httpx  # noqa: F401
    except Exception:
        return False, "the async HTTP client is not installed"
    if config.HTTP_PROXY:
        try:
            import socksio  # noqa: F401
        except Exception:
            return False, "the async client has no SOCKS support (Tor scan)"
    return True, ""


class Fetched:
    """One response, already read and size-capped.

    Deliberately not an httpx object: the connection is released before this is
    handed back, so nothing downstream can hold a socket open while it parses.
    """

    __slots__ = ("url", "final_url", "status", "headers", "text", "kind",
                 "content_length", "error")

    def __init__(self, url: str, *, final_url: str | None = None, status: int | None = None,
                 headers: dict | None = None, text: str | None = None,
                 kind: str | None = None, content_length: int | None = None,
                 error: str | None = None):
        self.url = url
        self.final_url = final_url or url
        self.status = status
        self.headers = headers or {}
        self.text = text
        self.kind = kind
        self.content_length = content_length
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def header(self, name: str, default: str | None = None) -> str | None:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return default


class AsyncFetcher:
    """A bounded, reusable async HTTP client.

    Used as an async context manager:

        async with AsyncFetcher() as f:
            resp = await f.get(url)
    """

    def __init__(self, *, concurrency: int | None = None,
                 host_concurrency: int | None = None,
                 timeout: float | None = None,
                 light_kinds: set[str] | None = None):
        self.concurrency = concurrency or config.CRAWL_CONCURRENCY
        self.host_concurrency = host_concurrency or config.CRAWL_HOST_CONCURRENCY
        self.timeout = timeout or config.HTTP_TIMEOUT
        self.light_kinds = light_kinds or set()
        self._sem: asyncio.Semaphore | None = None
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._client: Any = None
        self.stats = {"requests": 0, "errors": 0, "bytes": 0}

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def __aenter__(self) -> "AsyncFetcher":
        import httpx

        self._sem = asyncio.Semaphore(self.concurrency)
        limits = httpx.Limits(max_connections=self.concurrency,
                              max_keepalive_connections=max(10, self.concurrency // 2),
                              keepalive_expiry=15.0)
        timeout = httpx.Timeout(self.timeout, connect=min(self.timeout, 10.0),
                                pool=self.timeout * 2)
        kwargs: dict[str, Any] = {
            "limits": limits,
            "timeout": timeout,
            "verify": config.VERIFY_TLS,
            "follow_redirects": True,
            "max_redirects": _MAX_REDIRECTS,
            "http2": False,
            "headers": {
                "User-Agent": config.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
            },
            "trust_env": not bool(config.HTTP_PROXY),
        }
        self._client = _client_with_proxy(httpx, kwargs, config.HTTP_PROXY)
        if not config.VERIFY_TLS:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    # ------------------------------------------------------------------ #
    # fetching
    # ------------------------------------------------------------------ #
    def _host_sem(self, host: str) -> asyncio.Semaphore:
        sem = self._host_sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self.host_concurrency)
            self._host_sems[host] = sem
        return sem

    async def get(self, url: str, *, cap: int = 3_000_000,
                  js_cap: int | None = None) -> Fetched:
        """GET one URL. Bodies are read up to `cap` bytes; asset kinds
        (image/font/archive/…) are recorded without downloading a body."""
        from urllib.parse import urlparse
        host = (urlparse(url).netloc or "").lower()
        assert self._sem is not None, "use AsyncFetcher as an async context manager"
        async with self._sem, self._host_sem(host):
            return await self._get(url, cap, js_cap)

    async def _get(self, url: str, cap: int, js_cap: int | None) -> Fetched:
        import httpx

        self.stats["requests"] += 1
        try:
            async with self._client.stream("GET", url) as resp:
                ct = resp.headers.get("Content-Type", "")
                kind, _sub = classify_resource(str(resp.url), ct)
                headers = dict(resp.headers)
                clen = _int_or_none(resp.headers.get("Content-Length"))
                if kind in self.light_kinds:
                    return Fetched(url, final_url=str(resp.url), status=resp.status_code,
                                   headers=headers, kind=kind, content_length=clen)
                limit = (js_cap or config.MAX_JS_BYTES) if kind == "js" else cap
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes(65536):
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= limit:
                        break
                self.stats["bytes"] += total
                raw = b"".join(chunks)
                text = raw.decode(resp.encoding or "utf-8", errors="replace")
                return Fetched(url, final_url=str(resp.url), status=resp.status_code,
                               headers=headers, text=text, kind=kind,
                               content_length=clen if clen is not None else total)
        except httpx.HTTPError as exc:
            self.stats["errors"] += 1
            return Fetched(url, error=f"{type(exc).__name__}: {exc}"[:200])
        except Exception as exc:                      # decoding / protocol oddities
            self.stats["errors"] += 1
            return Fetched(url, error=f"{type(exc).__name__}: {exc}"[:200])

    async def text_of(self, url: str) -> str | None:
        """Body of one URL as text, or None. For small helper fetches
        (robots.txt, sitemaps, calibration probes)."""
        r = await self.get(url, cap=2_000_000)
        return r.text if r.ok else None

    # ------------------------------------------------------------------ #
    # bounded fan-out
    # ------------------------------------------------------------------ #
    async def each(self, items: Iterable[Any],
                   worker: Callable[[Any], Awaitable[Any]],
                   *, on_result: Callable[[Any], None] | None = None) -> list:
        """Run `worker` over every item with the fetcher's concurrency, handing
        each result to `on_result` as it completes (order is arrival order).

        The semaphores inside `get()` already bound the network, so the task set
        is created eagerly · that is what keeps the pipe full instead of walking
        a batch in lock-step.
        """
        results: list = []
        tasks = [asyncio.create_task(_guard(worker, it)) for it in items]
        if not tasks:
            return results
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
            if on_result is not None:
                try:
                    on_result(res)
                except Exception as exc:
                    log.debug(f"result handler failed: {exc}")
        return results


async def _guard(worker: Callable[[Any], Awaitable[Any]], item: Any):
    """A failing worker must not cancel its siblings."""
    try:
        return await worker(item)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.debug(f"worker failed on {item}: {exc}")
        return None


def _client_with_proxy(httpx_mod, kwargs: dict, proxy: str | None):
    """Build the client, tolerating both proxy-argument spellings and both SOCKS
    URL schemes across httpx versions."""
    if not proxy:
        return httpx_mod.AsyncClient(**kwargs)
    # socks5h (resolve at the proxy) is what a Tor scan needs; older httpx builds
    # only register socks5, whose transport also forwards the hostname.
    for candidate in (proxy, proxy.replace("socks5h://", "socks5://")):
        for key in ("proxy", "proxies"):
            try:
                return httpx_mod.AsyncClient(**{**kwargs, key: candidate})
            except (TypeError, ValueError):
                continue
    raise RuntimeError(f"could not configure the async client for proxy {proxy}")


def _int_or_none(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def run(coro):
    """Run one coroutine to completion from synchronous pipeline code."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # A loop is already running (embedded use) · give the work its own.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


async def offload(fn: Callable, *args):
    """Run a CPU-bound parse in a worker thread.

    Beautifying and regex-scanning a multi-megabyte bundle takes long enough that
    doing it inline would stall every in-flight request on the loop thread.
    """
    return await asyncio.to_thread(fn, *args)
