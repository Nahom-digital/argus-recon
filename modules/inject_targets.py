"""
Shared collection of injectable request targets for the active vulnerability
scanners (SQL injection, XSS). A target is any request that carries
user-controlled input, expressed uniformly so sqlmap and dalfox can be pointed at
every place a value reaches the server, not just the query string:

    {"url", "method", "params": [names], "fields": [names], "has_query": bool,
     "type", "content_type", "body", "is_json", "cookies"}

`params` is the union of query-string keys and captured body/field names · the
scanners inject into each. `body` is the request body actually observed (a JSON
document for an API/XHR call, or a form string), so a JSON login is tested as
JSON. `cookies` is the request's captured Cookie header, so session and
preference cookies are tested too. Anything the browser sent to the server (URL,
body, cookie, and · via the scanner's own level · the common request headers) is
a candidate injection point.

Targets are ranked (forms / XHR and parameter-bearing endpoints first) and
de-duplicated by (method, path, parameter set) so the budget is not spent on
`?id=1` vs `?id=2`, and capped by the caller.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit, parse_qsl

from .schema import ScanResult


def _header(headers: dict, name: str) -> str:
    """Case-insensitive lookup · captured headers keep their original casing."""
    if not isinstance(headers, dict):
        return ""
    low = name.lower()
    for k, v in headers.items():
        if str(k).lower() == low:
            return str(v or "")
    return ""


def _is_jsonish(content_type: str, body: str) -> bool:
    if "json" in (content_type or "").lower():
        return True
    b = (body or "").strip()
    if not b or b[0] not in "{[":
        return False
    try:
        json.loads(b)
        return True
    except Exception:
        return False


def _body_field_names(body: str, is_json: bool) -> list[str]:
    """Top-level input names carried in a captured request body · JSON keys, or
    form `a=1&b=2` keys. Nested JSON keys are left to sqlmap, which walks the
    document itself once it is handed the body."""
    b = (body or "").strip()
    if not b:
        return []
    if is_json:
        try:
            obj = json.loads(b)
            return [str(k) for k in obj] if isinstance(obj, dict) else []
        except Exception:
            return []
    return [k for k, _ in parse_qsl(b, keep_blank_values=True) if k]


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
        headers = e.get("req_headers") or {}
        body = e.get("req_body") or ""
        content_type = (e.get("content_type")
                        or _header(headers, "Content-Type") or "")
        is_json = _is_jsonish(content_type, body)
        cookies = _header(headers, "Cookie")

        field_names = [f.get("name") for f in (e.get("fields") or [])
                       if f.get("name")]
        url_params = _url_params(url)
        body_names = _body_field_names(body, is_json)
        params = sorted(set(field_names) | set(url_params) | set(body_names))
        # A request that carries a body or cookies is worth testing even when its
        # field names were not parsed out · sqlmap / dalfox walk the body itself.
        if need_params and not params and not body and not cookies:
            continue
        path = url.split("?", 1)[0]
        key = (method, path, tuple(params), bool(cookies))
        if key in seen:
            continue
        seen.add(key)
        score = 0
        if e.get("type") in ("form", "xhr", "fetch"):
            score += 3
        if field_names or body_names:
            score += 2
        if url_params:
            score += 2
        if cookies:
            score += 1
        if e.get("status") == 200:
            score += 1
        ranked.append((-score, {
            "url": url, "method": method, "params": params,
            "fields": field_names, "has_query": bool(url_params),
            "type": e.get("type"), "content_type": content_type,
            "body": body, "is_json": is_json, "cookies": cookies,
        }))
    ranked.sort(key=lambda x: x[0])
    return [t for _, t in ranked[:limit]]
