"""
Shared collection of injectable request targets for the active vulnerability
scanners (SQL injection, XSS). A target is any request that carries
user-controlled input · a URL with a query string, or a form / XHR endpoint with
named fields · expressed uniformly so sqlmap and dalfox can be pointed at it:

    {"url", "method", "params": [names], "fields": [names],
     "has_query": bool, "type"}

Targets are ranked (forms / XHR and parameter-bearing endpoints first) and
de-duplicated by (method, path, parameter set) so the budget is not spent on
`?id=1` vs `?id=2`, and capped by the caller.
"""
from __future__ import annotations

from urllib.parse import urlsplit, parse_qsl

from .schema import ScanResult


def _url_params(url: str) -> list[str]:
    try:
        q = urlsplit(url).query
    except Exception:
        return []
    return [k for k, _ in parse_qsl(q, keep_blank_values=True) if k]


# Markers that mean a URL was lifted verbatim out of JavaScript source (a template
# literal, a framework binding, a concatenated fragment) rather than being a real,
# resolvable request. Pointing sqlmap / dalfox at one wastes the budget and, on a
# catch-all host that answers 200 for everything, invents a "vulnerability" with no
# real payload behind it. Such URLs stay in the endpoint inventory as references ·
# they are only skipped as active-injection targets.
_JS_ARTIFACTS = ("${", "`", "{{", "}}", "<%", "%>", "[object", "undefined/",
                 "/undefined", "=undefined", ":undefined")


def _is_testable_url(url: str) -> bool:
    """False for a URL that carries an unexpanded template / interpolation marker,
    or a parameter whose name is itself such a fragment · nothing real to inject."""
    low = url.lower()
    if any(tok in low for tok in _JS_ARTIFACTS):
        return False
    # A parameter *name* that is a placeholder (e.g. ?${k}=v) is equally unusable.
    for p in _url_params(url):
        pl = p.lower()
        if "$" in pl or "{" in pl or "}" in pl or "`" in pl:
            return False
    return True


def collect(result: ScanResult, *, limit: int = 40,
            need_params: bool = True) -> list[dict]:
    """Return up to `limit` injectable targets, best first. When `need_params`
    is set (the default) only endpoints that actually carry a parameter are
    returned · nothing to inject into otherwise."""
    ranked: list[tuple[int, dict]] = []
    seen: set[tuple] = set()
    for e in result.iter_endpoints():
        url = e.get("url")
        if not url or not e.get("in_scope"):
            continue
        if not _is_testable_url(url):
            continue
        method = (e.get("method") or "GET").upper()
        field_names = [f.get("name") for f in (e.get("fields") or [])
                       if f.get("name")]
        url_params = _url_params(url)
        params = sorted(set(field_names) | set(url_params))
        if need_params and not params:
            continue
        path = url.split("?", 1)[0]
        key = (method, path, tuple(params))
        if key in seen:
            continue
        seen.add(key)
        score = 0
        if e.get("type") in ("form", "xhr", "fetch"):
            score += 3
        if field_names:
            score += 2
        if url_params:
            score += 2
        if e.get("status") == 200:
            score += 1
        ranked.append((-score, {
            "url": url, "method": method, "params": params,
            "fields": field_names, "has_query": bool(url_params),
            "type": e.get("type"),
        }))
    ranked.sort(key=lambda x: x[0])
    return [t for _, t in ranked[:limit]]
