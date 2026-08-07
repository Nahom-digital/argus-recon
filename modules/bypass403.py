"""
Module · access-control bypass probe (source code "x").

When a scan turns up a 401/403 endpoint, the interesting question is whether the
control is real or just a front-door check the app forgot to enforce underneath.
This replays each forbidden URL with the well-known bypass tricks and reports the
ones that turn a 403 into a 200:

  * path manipulation · trailing slash, //, /./, /%2e/, /..;/, %20/%09 suffixes,
    case flips, extension and matrix-parameter tricks
  * bypass headers · X-Forwarded-For / X-Original-URL / X-Rewrite-URL /
    X-Custom-IP-Authorization / X-Forwarded-Host and friends, set to 127.0.0.1
  * safe method switching · HEAD / OPTIONS in place of GET

It is deliberately non-destructive · only GET / HEAD / OPTIONS are ever sent, so
nothing changes state · and it only runs against hosts already in scope. Each
confirmed bypass becomes a high-severity finding carrying the exact technique so
an operator can reproduce it in one request.

The technique catalogue is built from the well-known open-source 403 bypass
repos · iamj0ker/bypass-403 (the "Joker" repo) and nomore403 · implemented
natively so it has no hard dependency and honours the scan's session (Tor proxy,
UA, TLS settings) automatically. When the external `nomore403` binary is present
it is run as an additional, conservative second opinion and its confirmed hits
are merged in (see _run_nomore403).
"""
from __future__ import annotations

import concurrent.futures
import re
import subprocess
import time
from urllib.parse import urlparse, urlunparse, quote

from . import config
from .schema import ScanResult
from .util import get_logger, make_session, in_scope, host_of, resolve_tool

log = get_logger("bypass403")

SRC = config.SOURCE_CODES["bypass"]          # "x"

_LOCAL = "127.0.0.1"
# Headers that a misconfigured proxy trusts to mean "internal / already
# authorised". The catalogue mirrors the well-known open-source 403 bypass tools
# (iamj0ker/bypass-403 · the "Joker" repo · and nomore403), implemented natively
# so it honours the scan session and needs no external binary.
_BYPASS_HEADERS = [
    {"X-Forwarded-For": _LOCAL},
    {"X-Forwarded-For": "127.0.0.1:80"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": _LOCAL},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Port": "80"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Server": _LOCAL},
    {"X-Originating-IP": _LOCAL},
    {"X-Remote-IP": _LOCAL},
    {"X-Remote-Addr": _LOCAL},
    {"X-Client-IP": _LOCAL},
    {"Client-IP": _LOCAL},
    {"True-Client-IP": _LOCAL},
    {"X-Real-IP": _LOCAL},
    {"X-Custom-IP-Authorization": _LOCAL},
    {"X-ProxyUser-Ip": _LOCAL},
    {"X-Host": _LOCAL},
    {"X-Server-IP": _LOCAL},
    {"Forwarded": f"for={_LOCAL};by={_LOCAL};host={_LOCAL}"},
    {"X-HTTP-Method-Override": "GET"},
    {"Content-Length": "0"},
]
_SAFE_METHODS = ["HEAD", "OPTIONS", "TRACE"]


def _path_variants(path: str) -> list[str]:
    """Path rewrites that frequently slip past a prefix-based deny rule."""
    p = path if path.startswith("/") else "/" + path
    seg = p.rstrip("/").rsplit("/", 1)[-1] or ""
    base = p.rstrip("/")
    out = [
        p + "/",
        "/" + p.lstrip("/"),
        p + "//",
        "//" + p.lstrip("/"),
        base + "/.",
        base + "/./",
        base + "/./.",
        p.replace(seg, "%2e" + seg, 1) if seg else p,
        base + "/%2e/",
        base + "/%2e%2e/",
        base + "/..;/",
        base + "/..%2f",
        base + "/%2f",
        base + "%2f",
        base + "/%252e/",          # double-encoded dot
        base + "/%252f",           # double-encoded slash
        base + ";/",
        base + "/;/",
        base + ";foo=bar",         # matrix parameter
        base + "%20",
        base + "%09",
        base + "%00",
        base + "%0a",
        base + "%23",
        base + "?",
        base + "??",
        base + "#",
        base + "/*",
        base + ".json",
        base + ".html",
        base + ".css",
        base + "/~",
        base + "/.randomstring",   # trailing junk a prefix rule may not expect
        p.upper() if p.lower() != p.upper() else p,
        (base[: -len(seg)] + seg.upper()) if seg and seg.lower() != seg.upper() else p,
        (base[: -len(seg)] + seg.capitalize()) if seg and seg[:1].islower() else p,
    ]
    # de-dup, drop the identity
    seen, uniq = {path}, []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def _build_variants(url: str) -> list[tuple[str, str, str, dict]]:
    """(technique, method, url, headers) probes for one forbidden URL."""
    parts = urlparse(url)
    variants: list[tuple[str, str, str, dict]] = []

    for np in _path_variants(parts.path or "/"):
        nu = urlunparse((parts.scheme, parts.netloc, np, parts.params, parts.query, ""))
        variants.append((f"path {np}", "GET", nu, {}))

    for hdr in _BYPASS_HEADERS:
        variants.append((f"header {next(iter(hdr))}", "GET", url, dict(hdr)))

    # X-Original-URL / X-Rewrite-URL · ask the root but smuggle the real path.
    root = urlunparse((parts.scheme, parts.netloc, "/", "", "", ""))
    smuggle = parts.path + (("?" + parts.query) if parts.query else "")
    for h in ("X-Original-URL", "X-Rewrite-URL"):
        variants.append((f"header {h}", "GET", root, {h: smuggle}))

    for m in _SAFE_METHODS:
        variants.append((f"method {m}", m, url, {}))

    return variants


def _forbidden_targets(result: ScanResult) -> list[str]:
    """In-scope URLs the scan saw answer 401/403 · endpoints and files."""
    urls: list[str] = []
    seen: set[str] = set()

    def consider(url: str, status) -> None:
        if status in (401, 403) and url not in seen and in_scope(url, result.domain):
            seen.add(url)
            urls.append(url)

    for e in result.iter_endpoints():
        if e.get("method", "GET") == "GET":
            consider(e.get("url"), e.get("status"))
        if len(urls) >= config.BYPASS_MAX_TARGETS:
            return urls
    for f in result._files.values():              # type: ignore[attr-defined]
        consider(f.get("url"), f.get("status"))
        if len(urls) >= config.BYPASS_MAX_TARGETS:
            break
    return urls


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run_nomore403(url: str) -> list[dict]:
    """Optional second opinion from the external nomore403 binary (the strong
    open-source 403 bypass tool). Best-effort and conservative · only a clear 200
    line that names the path is accepted, so a noisy table never fabricates a
    bypass. Returns extra hits, or [] when the tool is absent or found nothing."""
    binp = resolve_tool(config.NOMORE403_BIN)
    if not binp:
        return []
    try:
        proc = subprocess.run([binp, "-u", url], capture_output=True, text=True,
                              timeout=max(60, config.HTTP_TIMEOUT * 6))
    except Exception:
        return []
    text = _ANSI_RE.sub("", (proc.stdout or "") + "\n" + (proc.stderr or ""))
    path = urlparse(url).path or "/"
    hits: list[dict] = []
    for line in text.splitlines():
        s = line.strip()
        # Accept only lines that clearly report a 200 and reference the target,
        # never the 401/403 baseline lines.
        if re.search(r"\b200\b", s) and ("http" in s.lower() or path in s) \
                and "403" not in s and "401" not in s:
            hits.append({"technique": "external tool (nomore403)", "method": "GET",
                         "url": url, "status": 200, "length": None,
                         "headers": {}, "evidence_line": s[:180]})
        if len(hits) >= 5:
            break
    return hits


def _probe(session, url: str) -> dict | None:
    """Confirm the URL is still forbidden, then try each bypass. Returns a result
    dict or None if the baseline is no longer 401/403 (nothing to bypass)."""
    try:
        base = session.get(url, timeout=config.HTTP_TIMEOUT, allow_redirects=False)
    except Exception:
        return None
    if base.status_code not in (401, 403):
        return None
    base_len = len(base.content or b"")
    hits: list[dict] = []
    for technique, method, vurl, headers in _build_variants(url):
        try:
            resp = session.request(method, vurl, headers=headers or None,
                                   timeout=config.HTTP_TIMEOUT, allow_redirects=False)
        except Exception:
            continue
        sc = resp.status_code
        # A win: a forbidden resource now answers 2xx (or a 3xx to somewhere real).
        if 200 <= sc < 400 and sc not in (403, 401):
            hits.append({"technique": technique, "method": method, "url": vurl,
                         "status": sc, "length": len(resp.content or b""),
                         "headers": headers})
    # Optional external tool · merge its confirmed hits alongside the native ones.
    try:
        hits.extend(_run_nomore403(url))
    except Exception:
        pass
    if not hits:
        return None
    return {"url": url, "baseline": base.status_code, "baseline_len": base_len,
            "hits": hits}


def _emit(result: ScanResult, res: dict) -> None:
    url = res["url"]
    # Prefer a clean 200 hit for the headline; keep the rest as evidence.
    best = min(res["hits"], key=lambda h: (0 if h["status"] == 200 else 1, h["status"]))
    techniques = ", ".join(sorted({h["technique"].split(" ")[0] for h in res["hits"]}))
    evidence = (f"baseline {res['baseline']} · "
                + "; ".join(f"{h['technique']} -> {h['status']}" for h in res["hits"][:8]))
    # A 200 is a strong signal; a 3xx is weaker (could be a generic redirect).
    strong = any(h["status"] == 200 for h in res["hits"])
    result.add_finding(
        title=f"403/401 bypass on {urlparse(url).path or '/'}",
        category="access-control", severity="high" if strong else "medium",
        confidence=80 if strong else 55, source=SRC, target=url,
        evidence=evidence,
        parsed={"baseline": res["baseline"], "best": best, "techniques": techniques,
                "hits": res["hits"][:12]},
        risk=("The access control is enforced only at the front door · a simple "
              "path or header rewrite reaches the protected resource anyway."),
        recommendation=("Enforce authorization in the application for the "
                        "canonical resource, not by URL prefix at the proxy; "
                        "normalise the path before the check."),
        tags=["access-control", "bypass"], signature=f"bypass:{url}")


def run(result: ScanResult) -> None:
    t0 = time.time()
    if not config.BYPASS_ENABLE:
        result.mark_module("bypass", "skip", note="disabled")
        return
    targets = _forbidden_targets(result)
    if not targets:
        log.info("no 401/403 endpoints to test")
        result.mark_module("bypass", "empty", note="no forbidden endpoints", duration=0)
        return

    session = make_session()
    log.info(f"testing {len(targets)} forbidden endpoint"
             f"{'s' if len(targets) != 1 else ''} for access-control bypass")
    found = 0
    workers = max(1, min(config.BYPASS_THREADS, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe, session, url): url for url in targets}
        for fut in concurrent.futures.as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                _emit(result, res)
                found += 1
                log.info(f"  bypass found: {res['url']} "
                         f"({len(res['hits'])} technique(s))")

    log.info(f"bypass probe complete: {found} bypassable "
             f"of {len(targets)} ({time.time() - t0:.1f}s)")
    result.mark_module("bypass", "ok" if found else "empty",
                       note=f"{found}/{len(targets)} bypassable",
                       duration=time.time() - t0)
