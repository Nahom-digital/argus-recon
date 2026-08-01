"""
Module 5 · JS source parser (combines and exceeds JSluice + LinkFinder).

For any JavaScript body (linked file or inline block) it recovers:

  1. hardcoded endpoints / API paths  (LinkFinder-style extraction)
  2. request logic · fetch / axios / XHR / jQuery / Angular HttpClient /
     WebSocket calls, each with method + URL + the nearest enclosing function
     or click/submit handler, so a button can be traced to the request it fires
  3. exposed secrets, keys and tokens (config.SECRET_PATTERNS)

Minified single-line bundles are beautified first (when not too large) so line
numbers and enclosing-function detection are meaningful.
"""
from __future__ import annotations

import re

from . import config

# --------------------------------------------------------------------------- #
# 1. Endpoint extraction · the well-known LinkFinder pattern, lightly adapted.
# --------------------------------------------------------------------------- #
_ENDPOINT_RX = re.compile(r"""
  (?:"|'|`)
    (
      ((?:[a-zA-Z][a-zA-Z0-9+.\-]{0,9}:)?//[^"'`/][^"'`]{1,})            # scheme://host or //host
      |
      ((?:/|\.\./|\./)[^"'`><,;|*()%$^\\\[\]\s][^"'`><,;|)\s]{1,})        # /path ./path ../path
      |
      ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.[a-zA-Z]{1,5}(?:[?#/][^"'`\s]*|))  # dir/file.ext
      |
      ([a-zA-Z0-9_\-]{2,}\.(?:php|asp|aspx|jsp|do|action|json|xml|ya?ml|txt|graphql)(?:\?[^"'`\s]*|))
    )
  (?:"|'|`)
""", re.VERBOSE)

# Noise we never want to treat as an endpoint.
_ENDPOINT_DENY = re.compile(
    r"^(?://)?(?:[\w.-]*\.(?:png|jpe?g|gif|svg|ico|webp|bmp|css|woff2?|ttf|eot|mp4|webm|map))(?:[?#].*)?$"
    r"|^text/|^application/(?:json|xml|javascript|x-www)|^image/|^\.{1,2}$|^//$|^/$",
    re.I,
)

# --------------------------------------------------------------------------- #
# 2. Request-logic patterns. Each yields (method, url) · method may be None.
# --------------------------------------------------------------------------- #
_REQUEST_PATTERNS = [
    ("fetch", re.compile(
        r"""fetch\(\s*[`'"](?P<u>[^`'"]+)[`'"]"""
        r"""(?:\s*,\s*\{(?P<opts>[^{}]*?)\})?""", re.S)),
    ("axios", re.compile(
        r"""axios\.(?P<m>get|post|put|delete|patch|head)\(\s*[`'"](?P<u>[^`'"]+)[`'"]""", re.I)),
    ("axios", re.compile(
        r"""axios\(\s*\{(?P<opts>[^{}]*?url\s*:\s*[`'"](?P<u>[^`'"]+)[`'"][^{}]*?)\}""", re.S | re.I)),
    ("xhr", re.compile(
        r"""\.open\(\s*[`'"](?P<m>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[`'"]\s*,\s*[`'"](?P<u>[^`'"]+)[`'"]""", re.I)),
    ("jquery", re.compile(
        r"""\$\.(?P<m>get|post|getJSON)\(\s*[`'"](?P<u>[^`'"]+)[`'"]""", re.I)),
    ("jquery", re.compile(
        r"""\$\.ajax\(\s*\{(?P<opts>[^{}]*?url\s*:\s*[`'"](?P<u>[^`'"]+)[`'"][^{}]*?)\}""", re.S | re.I)),
    ("angular", re.compile(
        r"""(?:this\.)?http\.(?P<m>get|post|put|delete|patch)\(\s*[`'"](?P<u>[^`'"]+)[`'"]""", re.I)),
    ("websocket", re.compile(
        r"""new\s+WebSocket\(\s*[`'"](?P<u>[^`'"]+)[`'"]""", re.I)),
]

# Enclosing scope hints, searched backwards from a request match.
_FN_RX = re.compile(
    r"""(?:function\s+([A-Za-z0-9_$]+)\s*\(|"""
    r"""([A-Za-z0-9_$]+)\s*[:=]\s*(?:async\s+)?function|"""
    r"""([A-Za-z0-9_$]+)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>|"""
    r"""addEventListener\(\s*['"](\w+)['"])""")

_METHOD_IN_OPTS = re.compile(r"""method\s*:\s*['"]([A-Za-z]+)['"]""", re.I)


def _beautify(content: str) -> str:
    # Only beautify minified-looking bodies within a sane size budget.
    if len(content) > 800_000:
        return content
    newline_ratio = content.count("\n") / max(len(content), 1)
    if newline_ratio > 0.01:
        return content
    try:
        import jsbeautifier
        return jsbeautifier.beautify(content)
    except Exception:
        return content


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _enclosing(text: str, pos: int) -> str | None:
    window = text[max(0, pos - 400):pos]
    best = None
    for m in _FN_RX.finditer(window):
        best = next((g for g in m.groups() if g), best)
    return best


def _extract_requests(text: str) -> list[dict]:
    reqs: list[dict] = []
    seen = set()
    for kind, rx in _REQUEST_PATTERNS:
        for m in rx.finditer(text):
            gd = m.groupdict()
            url = gd.get("u")
            if not url:
                continue
            method = gd.get("m")
            if not method:
                opts = gd.get("opts") or ""
                mm = _METHOD_IN_OPTS.search(opts)
                method = mm.group(1) if mm else None
            if method is None:
                method = {"fetch": "GET", "websocket": "WS", "jquery": "GET",
                          "axios": "GET", "angular": "GET", "xhr": "GET"}.get(kind, "GET")
            method = method.upper()
            key = (kind, method, url)
            if key in seen:
                continue
            seen.add(key)
            reqs.append({
                "kind": kind,
                "method": method,
                "url": url,
                "line": _line_of(text, m.start()),
                "handler": _enclosing(text, m.start()),
                "snippet": re.sub(r"\s+", " ", m.group(0))[:160],
            })
    return reqs


def _extract_endpoints(text: str) -> list[str]:
    out: list[str] = []
    seen = set()
    for m in _ENDPOINT_RX.finditer(text):
        ep = m.group(1).strip()
        if not ep or len(ep) > 400:
            continue
        if _ENDPOINT_DENY.search(ep):
            continue
        if ep not in seen:
            seen.add(ep)
            out.append(ep)
    return out


def _extract_secrets(text: str, source_url: str) -> list[dict]:
    out: list[dict] = []
    seen = set()
    for name, pattern, severity in config.SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            match = m.group(0)
            if match in seen:
                continue
            seen.add(match)
            start = max(0, m.start() - 30)
            context = re.sub(r"\s+", " ", text[start:m.end() + 30]).strip()
            out.append({
                "type": name,
                "match": match if len(match) <= 80 else match[:77] + "...",
                "severity": severity,
                "line": _line_of(text, m.start()),
                "context": context[:200],
                "source": source_url,
            })
    return out


def parse(content: str, source_url: str) -> dict:
    """Return {endpoints, requests, secrets} for a JS body."""
    if not content:
        return {"endpoints": [], "requests": [], "secrets": []}
    text = _beautify(content)
    return {
        "endpoints": _extract_endpoints(text),
        "requests": _extract_requests(text),
        "secrets": _extract_secrets(text, source_url),
    }
