"""
Module · HTTP security review (source code "H").

Every other web stage is after content; this one is after the *response itself*.
For each live root it records and judges the HTTP surface:

  * security headers · HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy
  * cookies · Secure / HttpOnly / SameSite flags on each Set-Cookie
  * CORS · whether an arbitrary Origin is reflected, and with credentials
  * allowed methods · OPTIONS/Allow, plus a non-destructive TRACE check (XST)
  * redirect chain, compression, cache headers, content type
  * server fingerprint (Server / X-Powered-By) and any auth challenge
  * the CDN / WAF the response headers give away (and wafw00f when installed)

Findings are raised for the material problems (missing HSTS/CSP, insecure
cookies, permissive CORS, TRACE enabled, version disclosure); everything is
stored on the subdomain's `http` record so the panel can show the full picture.
Non-destructive throughout · it never sends anything past GET / HEAD / OPTIONS /
TRACE.
"""
from __future__ import annotations

import concurrent.futures
import time
from urllib.parse import urlparse

from . import config
from .schema import ScanResult
from .util import get_logger, make_session, resolve_tool, run_cmd, host_of

log = get_logger("http_analysis")

SRC = config.SOURCE_CODES["http_analysis"]   # "H"

# The security headers we check for, with why each matters and how bad missing is.
_SEC_HEADERS = [
    ("strict-transport-security", "HSTS", "medium",
     "Without HSTS a network attacker can strip TLS and downgrade the connection to HTTP."),
    ("content-security-policy", "Content-Security-Policy", "low",
     "No CSP means no defence-in-depth against cross-site scripting and data injection."),
    ("x-frame-options", "X-Frame-Options", "low",
     "Without frame protection the page can be framed for clickjacking (unless CSP frame-ancestors covers it)."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Missing nosniff lets a browser MIME-sniff responses into an executable type."),
    ("referrer-policy", "Referrer-Policy", "info",
     "Without a referrer policy full URLs (with tokens in the path/query) leak to third parties."),
    ("permissions-policy", "Permissions-Policy", "info",
     "No permissions policy leaves powerful browser features unrestricted."),
]

# CDN / WAF signatures read straight off the response headers · (header, value
# substring or '', provider, kind). An empty value means presence is enough.
_EDGE_SIGNATURES = [
    ("cf-ray", "", "Cloudflare", "cdn"),
    ("server", "cloudflare", "Cloudflare", "cdn"),
    ("x-amz-cf-id", "", "AWS CloudFront", "cdn"),
    ("server", "cloudfront", "AWS CloudFront", "cdn"),
    ("x-sucuri-id", "", "Sucuri", "waf"),
    ("x-sucuri-cache", "", "Sucuri", "waf"),
    ("server", "sucuri", "Sucuri", "waf"),
    ("x-akamai-transformed", "", "Akamai", "cdn"),
    ("server", "akamaighost", "Akamai", "cdn"),
    ("x-fastly-request-id", "", "Fastly", "cdn"),
    ("x-served-by", "cache-", "Fastly", "cdn"),
    ("server", "awselb", "AWS ELB", "lb"),
    ("x-varnish", "", "Varnish", "cache"),
    ("x-cache", "", "CDN cache", "cache"),
    ("server", "imperva", "Imperva", "waf"),
    ("x-iinfo", "", "Imperva Incapsula", "waf"),
    ("x-cdn", "", "Generic CDN", "cdn"),
    ("server", "cloudflarespectrum", "Cloudflare", "cdn"),
    ("x-powered-by-plesk", "", "Plesk", "panel"),
]

_SESSION_COOKIE_HINT = ("session", "sess", "sid", "token", "auth", "jwt",
                        "csrf", "xsrf", "phpsessid", "jsessionid", "connect.sid")


def _roots(result: ScanResult) -> list[str]:
    """Live http(s) roots to review · a host with a good HTTP probe result, on the
    scheme it answered."""
    roots: list[str] = []
    seen: set[str] = set()
    for sub in result._subdomains.values():       # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("status") and not http.get("error"):
            scheme = http.get("scheme", "https")
            root = f"{scheme}://{sub['host']}"
            if root not in seen:
                seen.add(root)
                roots.append(root)
    return roots[: config.HTTP_ANALYSIS_MAX_HOSTS]


def _raw_set_cookie(resp) -> list[str]:
    lines: list[str] = []
    for r in list(getattr(resp, "history", [])) + [resp]:
        raw = getattr(r, "raw", None)
        hdrs = getattr(raw, "headers", None)
        if hdrs is not None and hasattr(hdrs, "getlist"):
            lines += hdrs.getlist("Set-Cookie")
        elif r.headers.get("Set-Cookie"):
            lines.append(r.headers["Set-Cookie"])
    return lines


def _parse_cookie(line: str) -> dict:
    parts = [p.strip() for p in line.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if v else True
    samesite = attrs.get("samesite")
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": samesite if isinstance(samesite, str) else None,
            "session_like": any(h in name.lower() for h in _SESSION_COOKIE_HINT)}


def _detect_edge(headers: dict) -> dict | None:
    low = {k.lower(): (v or "") for k, v in headers.items()}
    for header, needle, provider, kind in _EDGE_SIGNATURES:
        if header in low and (not needle or needle in low[header].lower()):
            return {"name": provider, "kind": kind, "via": header}
    return None


def _wafw00f(root: str) -> str | None:
    binp = resolve_tool(config.WAFW00F_BIN)
    if not binp:
        return None
    proc = run_cmd([binp, "-a", "-o", "-", root], timeout=40, log=log)
    if not proc or not proc.stdout:
        return None
    for line in proc.stdout.splitlines():
        low = line.lower()
        if "is behind" in low:
            # "The site ... is behind <WAF> WAF."
            seg = line.split("is behind", 1)[1].strip()
            return seg.replace(" WAF.", "").replace(" WAF", "").strip(" .")
    return None


def _analyze_one(session, root: str) -> dict:
    out: dict = {"root": root}
    try:
        resp = session.get(root, timeout=config.HTTP_TIMEOUT, allow_redirects=True,
                           headers={"Origin": "https://argus-recon-probe.example"})
    except Exception as exc:
        out["error"] = str(exc)[:160]
        return out
    headers = dict(resp.headers)
    low = {k.lower(): v for k, v in headers.items()}

    out["status"] = resp.status_code
    out["final_url"] = resp.url
    out["redirect_chain"] = [r.url for r in resp.history] + ([resp.url] if resp.history else [])
    out["server"] = low.get("server")
    out["powered_by"] = low.get("x-powered-by")
    out["content_type"] = low.get("content-type")
    out["compression"] = low.get("content-encoding")
    out["cache_control"] = low.get("cache-control")
    out["www_authenticate"] = low.get("www-authenticate")

    # Security headers · which are present, which are missing.
    present, missing = {}, []
    for key, label, sev, why in _SEC_HEADERS:
        if key in low:
            present[key] = low[key][:300]
        else:
            missing.append(key)
    out["security_headers"] = present
    out["missing_headers"] = missing

    # CORS · did we get our probe Origin (or *) reflected, and with credentials?
    acao = low.get("access-control-allow-origin")
    acac = (low.get("access-control-allow-credentials") or "").lower() == "true"
    out["cors"] = {"allow_origin": acao, "allow_credentials": acac,
                   "reflects_origin": acao == "https://argus-recon-probe.example",
                   "wildcard": acao == "*"}

    # Cookies.
    out["cookies"] = [_parse_cookie(l) for l in _raw_set_cookie(resp)]

    # Allowed methods · OPTIONS/Allow + a non-destructive TRACE check.
    if config.HTTP_ANALYSIS_METHODS:
        try:
            opt = session.options(root, timeout=config.HTTP_TIMEOUT, allow_redirects=False)
            allow = opt.headers.get("Allow") or opt.headers.get("allow")
            out["allowed_methods"] = [m.strip().upper() for m in allow.split(",")] if allow else []
        except Exception:
            out["allowed_methods"] = []
        try:
            tr = session.request("TRACE", root, timeout=config.HTTP_TIMEOUT,
                                 allow_redirects=False)
            out["trace_enabled"] = tr.status_code == 200 and "TRACE" in (tr.text[:200].upper())
        except Exception:
            out["trace_enabled"] = False

    # CDN / WAF.
    edge = _detect_edge(headers)
    waf = _wafw00f(root)
    if waf and waf.lower() not in ("none", "no waf", "generic"):
        edge = edge or {}
        edge = {"name": waf, "kind": "waf", "via": "wafw00f"} if not edge.get("name") else edge
        out["waf"] = waf
    out["edge"] = edge
    return out


def _emit_findings(result: ScanResult, host: str, a: dict) -> None:
    add = result.add_finding
    root = a.get("root", host)
    https = root.startswith("https://")

    # Missing security headers.
    for key, label, sev, why in _SEC_HEADERS:
        if key in a.get("missing_headers", []):
            # X-Frame-Options is covered when CSP has frame-ancestors.
            if key == "x-frame-options":
                csp = (a.get("security_headers", {}) or {}).get("content-security-policy", "")
                if "frame-ancestors" in csp:
                    continue
            if key == "strict-transport-security" and not https:
                continue
            add(title=f"Missing {label} header", category="http-header",
                severity=sev, confidence=85, source=SRC, target=root,
                evidence=f"{root} response has no {label} header",
                parsed={"header": label, "host": host},
                risk=why, recommendation=f"Set a {label} response header.",
                tags=["http-header", "hardening"], signature=f"missing-header:{key}:{host}")

    # Cookies.
    for c in a.get("cookies", []):
        if https and not c["secure"]:
            add(title="Cookie set without the Secure flag", category="cookie",
                severity="medium", confidence=80, source=SRC, target=root,
                evidence=f"Set-Cookie {c['name']} has no Secure attribute",
                parsed=c,
                risk="The cookie can be sent over plain HTTP and captured on the wire.",
                recommendation="Add the Secure attribute to every cookie on an HTTPS site.",
                tags=["cookie"], signature=f"cookie-secure:{host}:{c['name']}")
        if c["session_like"] and not c["httponly"]:
            add(title="Session cookie without HttpOnly", category="cookie",
                severity="medium", confidence=78, source=SRC, target=root,
                evidence=f"Set-Cookie {c['name']} has no HttpOnly attribute",
                parsed=c,
                risk="A session cookie readable from JavaScript can be stolen via XSS.",
                recommendation="Add HttpOnly to session/auth cookies.",
                tags=["cookie", "session"], signature=f"cookie-httponly:{host}:{c['name']}")
        if not c["samesite"]:
            add(title="Cookie without SameSite attribute", category="cookie",
                severity="low", confidence=65, source=SRC, target=root,
                evidence=f"Set-Cookie {c['name']} has no SameSite attribute",
                parsed=c,
                risk="Absent SameSite widens exposure to cross-site request forgery.",
                recommendation="Set SameSite=Lax or Strict where possible.",
                tags=["cookie", "csrf"], signature=f"cookie-samesite:{host}:{c['name']}")

    # CORS.
    cors = a.get("cors", {})
    if cors.get("reflects_origin") and cors.get("allow_credentials"):
        add(title="CORS reflects arbitrary origin with credentials",
            category="cors", severity="high", confidence=85, source=SRC, target=root,
            evidence=f"Access-Control-Allow-Origin reflected our probe Origin and "
                     f"Allow-Credentials is true",
            parsed=cors,
            risk="Any site can read authenticated responses from this origin on "
                 "behalf of a logged-in victim.",
            recommendation="Never reflect Origin with credentials · use a strict allow-list.",
            tags=["cors"], signature=f"cors-reflect:{host}")
    elif cors.get("wildcard"):
        add(title="CORS allows any origin (wildcard)", category="cors",
            severity="low", confidence=70, source=SRC, target=root,
            evidence="Access-Control-Allow-Origin: *", parsed=cors,
            risk="Any origin can read non-credentialed responses from this endpoint.",
            recommendation="Restrict Access-Control-Allow-Origin to known origins.",
            tags=["cors"], signature=f"cors-wildcard:{host}")

    # TRACE / XST.
    if a.get("trace_enabled"):
        add(title="HTTP TRACE method enabled", category="http-method",
            severity="medium", confidence=80, source=SRC, target=root,
            evidence="TRACE returned 200 and echoed the request",
            parsed={"method": "TRACE"},
            risk="TRACE enables Cross-Site Tracing, a way to read otherwise "
                 "protected headers/cookies.",
            recommendation="Disable the TRACE method at the web server.",
            tags=["http-method", "xst"], signature=f"trace:{host}")

    # Dangerous methods advertised by OPTIONS.
    dangerous = sorted(set(a.get("allowed_methods", []))
                       & {"PUT", "DELETE", "PATCH", "CONNECT"})
    if dangerous:
        add(title=f"Write methods advertised: {', '.join(dangerous)}",
            category="http-method", severity="low", confidence=55, source=SRC,
            target=root, evidence=f"OPTIONS Allow: {', '.join(a.get('allowed_methods', []))}",
            parsed={"methods": dangerous},
            risk="Write/verb-tunnelling methods may allow unintended state changes "
                 "if not access-controlled.",
            recommendation="Confirm these methods are intended and authenticated; "
                           "disable them otherwise.",
            tags=["http-method"], signature=f"methods:{host}")

    # Version disclosure.
    for field in ("server", "powered_by"):
        val = a.get(field)
        if val and any(ch.isdigit() for ch in val):
            add(title=f"Server version disclosed ({val})", category="info-leak",
                severity="info", confidence=60, source=SRC, target=root,
                evidence=f"{field.replace('_', '-')}: {val}",
                parsed={"header": field, "value": val},
                risk="A precise server/framework version helps an attacker pick "
                     "known exploits.",
                recommendation="Suppress version tokens in Server / X-Powered-By.",
                tags=["info-leak"], signature=f"version:{field}:{host}")

    # CDN / WAF · recorded as context (info) so the findings view reflects it.
    edge = a.get("edge")
    if edge and edge.get("name"):
        add(title=f"{edge['name']} {edge['kind'].upper()} in front of {host}",
            category="edge", severity="info", confidence=75, source=SRC, target=root,
            evidence=f"detected via {edge.get('via')}", parsed=edge,
            risk="Traffic is fronted by an edge/WAF · direct-to-origin access may "
                 "bypass it if the origin IP is exposed.",
            recommendation="Ensure the origin only accepts traffic from the edge.",
            tags=["cdn", "waf", edge["kind"]], signature=f"edge:{host}")


def run(result: ScanResult, *, roots: list[str] | None = None) -> None:
    t0 = time.time()
    roots = roots if roots is not None else _roots(result)
    if not roots:
        log.info("no live roots to review")
        result.mark_module("http_analysis", "empty", note="no live roots", duration=0)
        return

    session = make_session()
    log.info(f"HTTP security review of {len(roots)} host{'s' if len(roots) != 1 else ''}")
    reviewed = 0
    workers = max(1, min(config.CRAWL_THREADS, len(roots)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_analyze_one, session, root): root for root in roots}
        for fut in concurrent.futures.as_completed(futs):
            root = futs[fut]
            try:
                a = fut.result()
            except Exception as exc:
                log.debug(f"{root}: {exc}")
                continue
            if a.get("error"):
                continue
            host = host_of(root)
            sub = result.add_subdomain(host)
            sub["http"].setdefault("scheme", urlparse(root).scheme)
            # Store the full review on the subdomain's http record (additive).
            sub["http"]["review"] = {k: v for k, v in a.items() if k != "root"}
            if a.get("edge"):
                sub["http"]["edge"] = a["edge"]
            _emit_findings(result, host, a)
            reviewed += 1

    log.info(f"HTTP review complete: {reviewed} host{'s' if reviewed != 1 else ''} "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("http_analysis", "ok" if reviewed else "empty",
                       note=f"{reviewed} hosts", duration=time.time() - t0)
