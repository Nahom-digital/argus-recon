"""
Module 5 · JS source parser (combines and exceeds JSluice + LinkFinder).

For any JavaScript body (linked file or inline block) it recovers:

  1. hardcoded endpoints / API paths  (LinkFinder-style extraction)
  2. request logic · fetch / axios / XHR / jQuery / Angular HttpClient /
     WebSocket calls, each with method + URL + the nearest enclosing function
     or click/submit handler, so a button can be traced to the request it fires
  3. exposed secrets, keys and tokens (config.SECRET_PATTERNS)

and, for a full recon read of the asset, also:

  4. GraphQL endpoints + whether introspection is referenced
  5. WebSocket endpoints (ws:// / wss://)
  6. OAuth / OpenID / SSO authorize + token URLs
  7. source maps (//# sourceMappingURL) · the original source, one fetch away
  8. cloud references · AWS (S3, ARNs, API Gateway, Cognito, CloudFront), Azure
     (blob, webapp, SQL, Key Vault), GCP (GCS, App Engine, Cloud Run/Functions,
     Firebase), DigitalOcean Spaces
  9. Firebase web configuration objects (apiKey / projectId / databaseURL / ...)
 10. internal addresses · RFC1918 IPs and .internal/.corp/.lan/.local hostnames
 11. analytics / tracking IDs · GA, GA4, GTM, AdSense, Meta Pixel, Mixpanel,
     Amplitude, Hotjar, Sentry DSN, Segment, Intercom
 12. TODO / FIXME / HACK / INSECURE code comments (flagged when security-relevant)
 13. parameter names seen in URLs (the app's real query surface)
 14. third-party hosts the asset talks to

Minified single-line bundles are beautified first (when not too large) so line
numbers and enclosing-function detection are meaningful.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl

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


# --------------------------------------------------------------------------- #
# 4+. Deep asset intelligence · everything else worth pulling out of a JS body.
# Each category is a cheap linear scan and its result list is capped so a huge
# bundle cannot blow up the record.
# --------------------------------------------------------------------------- #
_CAP = 200

# Absolute URL string literals · the raw material for oauth / third-party / param.
_URL_LITERAL_RX = re.compile(r"""[`'"](https?://[^`'"\s]{4,400})[`'"]""")

_SOURCEMAP_RX = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"`]+)")

_GRAPHQL_RX = re.compile(r"""[`'"]([^`'"]*?/graphi?ql[\w./-]*)[`'"]""", re.I)
_GQL_INTROSPECT_RX = re.compile(r"IntrospectionQuery|__schema\b|__type\b")

_WS_RX = re.compile(r"\bwss?://[^\s\"'`<>()]+", re.I)

_OAUTH_HINTS = ("oauth", "/authorize", "/oauth2", "openid", "/connect/token",
                "/connect/authorize", "accounts.google.com/o/oauth2",
                "login.microsoftonline.com", "auth0.com", ".okta.com",
                ".onelogin.com", "/.well-known/openid-configuration")

# Cloud references · (provider, kind, regex). The first capture group is the value
# when present, else the whole match.
_CLOUD_PATTERNS = [
    ("aws", "s3-bucket", re.compile(r"\b([a-z0-9][a-z0-9.-]{1,61}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)\b", re.I)),
    ("aws", "s3-bucket", re.compile(r"\bs3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9._-]{2,62})", re.I)),
    ("aws", "s3-uri", re.compile(r"\bs3://([a-z0-9][a-z0-9._-]{2,62})", re.I)),
    ("aws", "arn", re.compile(r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d*:[^\s\"'`]{1,120}")),
    ("aws", "api-gateway", re.compile(r"\b([a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)\b", re.I)),
    ("aws", "cognito", re.compile(r"\b(cognito-idp\.[a-z0-9-]+\.amazonaws\.com)\b", re.I)),
    ("aws", "cloudfront", re.compile(r"\b([a-z0-9]+\.cloudfront\.net)\b", re.I)),
    ("aws", "elb", re.compile(r"\b([a-z0-9][a-z0-9.-]+\.elb\.amazonaws\.com)\b", re.I)),
    ("azure", "blob", re.compile(r"\b([a-z0-9]+\.blob\.core\.windows\.net)\b", re.I)),
    ("azure", "webapp", re.compile(r"\b([a-z0-9][a-z0-9-]+\.azurewebsites\.net)\b", re.I)),
    ("azure", "sql", re.compile(r"\b([a-z0-9][a-z0-9-]+\.database\.windows\.net)\b", re.I)),
    ("azure", "keyvault", re.compile(r"\b([a-z0-9][a-z0-9-]+\.vault\.azure\.net)\b", re.I)),
    ("gcp", "gcs", re.compile(r"\b([a-z0-9][a-z0-9._-]+\.storage\.googleapis\.com)\b", re.I)),
    ("gcp", "gcs", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._-]{2,62})", re.I)),
    ("gcp", "appspot", re.compile(r"\b([a-z0-9][a-z0-9-]+\.appspot\.com)\b", re.I)),
    ("gcp", "cloud-functions", re.compile(r"\b([a-z0-9-]+\.cloudfunctions\.net)\b", re.I)),
    ("gcp", "cloud-run", re.compile(r"\b([a-z0-9-]+\.run\.app)\b", re.I)),
    ("gcp", "firebase-db", re.compile(r"\b([a-z0-9-]+\.firebaseio\.com)\b", re.I)),
    ("gcp", "firebase-app", re.compile(r"\b([a-z0-9-]+\.firebaseapp\.com)\b", re.I)),
    ("digitalocean", "spaces", re.compile(r"\b([a-z0-9][a-z0-9.-]+\.digitaloceanspaces\.com)\b", re.I)),
]

# Firebase web config · a set of these keys near each other is the client SDK init.
_FIREBASE_KV_RX = re.compile(
    r"(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)"
    r"""\s*:\s*[`'"]([^`'"]+)[`'"]""")

_INTERNAL_IP_RX = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b")
_INTERNAL_HOST_RX = re.compile(
    r"\b([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.(?:internal|intranet|corp|lan|local))\b", re.I)

# Analytics / tracking IDs · (provider, regex). Group 1 is the id when captured.
_ANALYTICS_PATTERNS = [
    ("google-analytics", re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")),
    ("google-analytics-4", re.compile(r"\bG-[A-Z0-9]{8,12}\b")),
    ("google-tag-manager", re.compile(r"\bGTM-[A-Z0-9]{6,9}\b")),
    ("google-adsense", re.compile(r"\bca-pub-\d{16}\b")),
    ("meta-pixel", re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{15,16})['"]""")),
    ("mixpanel", re.compile(r"""mixpanel\.init\(\s*['"]([0-9a-f]{32})['"]""", re.I)),
    ("amplitude", re.compile(r"""amplitude[^;\n]{0,40}?\.init\(\s*['"]([0-9a-f]{32})['"]""", re.I)),
    ("hotjar", re.compile(r"hjid\s*[:=]\s*(\d{5,8})")),
    ("sentry", re.compile(r"https://[0-9a-f]{16,}@[a-z0-9.-]*sentry(?:\.io|[.-][a-z0-9.-]+)/\d+", re.I)),
    ("segment", re.compile(r"""analytics\.load\(\s*['"]([A-Za-z0-9]{20,})['"]""")),
    ("intercom", re.compile(r"""app_id\s*:\s*['"]([a-z0-9]{8})['"]""", re.I)),
]

_COMMENT_RX = re.compile(
    r"(?://|/\*+|\*)\s*(TODO|FIXME|HACK|XXX|BUG|WARNING|DEPRECATED|NOTE|INSECURE|REMOVE)"
    r"\b[:\s-]*([^\n\r*]{0,200})", re.I)
_COMMENT_SEC_HINT = re.compile(
    r"pass(word|wd)|secret|api[_-]?key|token|creds?|backdoor|insecure|disable|"
    r"hack|hardcode|temporary|remove before|do not commit|bypass|auth", re.I)


def _dedup_cap(seq, cap: int = _CAP) -> list:
    out, seen = [], set()
    for item in seq:
        key = item if isinstance(item, str) else repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cap:
            break
    return out


def _url_literals(text: str) -> list[str]:
    return [m.group(1) for m in _URL_LITERAL_RX.finditer(text)]


def _extract_source_maps(text: str) -> list[str]:
    return _dedup_cap(m.group(1) for m in _SOURCEMAP_RX.finditer(text))


def _extract_graphql(text: str, endpoints: list[str]) -> tuple[list[str], bool]:
    gql = [m.group(1) for m in _GRAPHQL_RX.finditer(text)]
    gql += [e for e in endpoints
            if "/graphql" in e.lower() or e.lower().rstrip("/").endswith("/gql")]
    return _dedup_cap(gql, 50), bool(_GQL_INTROSPECT_RX.search(text))


def _extract_websockets(text: str, requests: list[dict]) -> list[str]:
    ws = [m.group(0) for m in _WS_RX.finditer(text)]
    ws += [r["url"] for r in requests if r.get("kind") == "websocket"]
    return _dedup_cap(ws, 50)


def _extract_oauth(urls: list[str]) -> list[str]:
    return _dedup_cap((u for u in urls if any(h in u.lower() for h in _OAUTH_HINTS)), 50)


def _extract_cloud(text: str) -> list[dict]:
    out, seen = [], set()
    for provider, kind, rx in _CLOUD_PATTERNS:
        for m in rx.finditer(text):
            val = (m.group(1) if m.groups() else m.group(0)).strip().rstrip("/")
            key = (provider, kind, val.lower())
            if not val or key in seen:
                continue
            seen.add(key)
            out.append({"provider": provider, "type": kind, "value": val})
            if len(out) >= 100:
                return out
    return out


def _extract_firebase(text: str) -> dict | None:
    kv: dict[str, str] = {}
    for m in _FIREBASE_KV_RX.finditer(text):
        kv.setdefault(m.group(1), m.group(2))
    # Three or more of these keys together is a real Firebase init, not a fluke.
    return kv if len(kv) >= 3 else None


def _extract_internal(text: str) -> list[dict]:
    out = [{"type": "ip", "value": m.group(0)} for m in _INTERNAL_IP_RX.finditer(text)]
    out += [{"type": "host", "value": m.group(1)} for m in _INTERNAL_HOST_RX.finditer(text)]
    return _dedup_cap(out, 80)


def _extract_analytics(text: str) -> list[dict]:
    out, seen = [], set()
    for provider, rx in _ANALYTICS_PATTERNS:
        for m in rx.finditer(text):
            ident = (m.group(1) if m.groups() else m.group(0))
            key = (provider, ident)
            if key in seen:
                continue
            seen.add(key)
            out.append({"provider": provider, "id": ident})
            if len(out) >= 60:
                return out
    return out


def _extract_comments(text: str) -> list[dict]:
    out, seen = [], set()
    for m in _COMMENT_RX.finditer(text):
        tag = m.group(1).upper()
        body = re.sub(r"\s+", " ", m.group(2)).strip()
        note = f"{tag} {body}".strip()
        if note in seen or len(note) < 5:
            continue
        seen.add(note)
        out.append({"tag": tag, "text": body[:200], "line": _line_of(text, m.start()),
                    "security": bool(_COMMENT_SEC_HINT.search(note))})
        if len(out) >= 120:
            break
    return out


def _extract_params(endpoints: list[str], requests: list[dict],
                    urls: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for u in endpoints + [r["url"] for r in requests] + urls:
        try:
            q = urlparse(u).query
        except Exception:
            continue
        for name, _ in parse_qsl(q, keep_blank_values=True):
            name = name.strip()
            if name and name not in seen and len(name) <= 64:
                seen.add(name)
                names.append(name)
                if len(names) >= 150:
                    return names
    return names


def _extract_third_party(urls: list[str], source_host: str) -> list[str]:
    src = (source_host or "").lower()
    hosts: list[str] = []
    seen: set[str] = set()
    for u in urls:
        try:
            host = (urlparse(u).hostname or "").lower()
        except Exception:
            continue
        if not host or host in seen:
            continue
        if src and (host == src or host.endswith("." + src)):
            continue
        seen.add(host)
        hosts.append(host)
        if len(hosts) >= 60:
            break
    return hosts


def parse(content: str, source_url: str) -> dict:
    """Return the full asset breakdown for a JS body.

    Backwards compatible: the original {endpoints, requests, secrets} keys are
    untouched, so existing callers keep working; the deep-recon categories are
    added alongside and callers that do not know about them simply ignore them.
    """
    empty = {"endpoints": [], "requests": [], "secrets": [], "graphql": [],
             "graphql_introspection": False, "websockets": [], "oauth": [],
             "source_maps": [], "cloud": [], "firebase": None, "internal_refs": [],
             "analytics": [], "comments": [], "params": [], "third_party": []}
    if not content:
        return empty
    text = _beautify(content)
    endpoints = _extract_endpoints(text)
    requests = _extract_requests(text)
    url_lits = _url_literals(text)
    graphql, introspection = _extract_graphql(text, endpoints)
    try:
        src_host = urlparse(source_url).hostname or ""
    except Exception:
        src_host = ""
    return {
        "endpoints": endpoints,
        "requests": requests,
        "secrets": _extract_secrets(text, source_url),
        "graphql": graphql,
        "graphql_introspection": introspection,
        "websockets": _extract_websockets(text, requests),
        "oauth": _extract_oauth(url_lits),
        "source_maps": _extract_source_maps(text),
        "cloud": _extract_cloud(text),
        "firebase": _extract_firebase(text),
        "internal_refs": _extract_internal(text),
        "analytics": _extract_analytics(text),
        "comments": _extract_comments(text),
        "params": _extract_params(endpoints, requests, url_lits),
        "third_party": _extract_third_party(url_lits, src_host),
    }
