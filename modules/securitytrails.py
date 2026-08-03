"""
Deep DNS source (internal code "s").

Pulls three things the passive engine and the local resolver cannot give on
their own, gated behind an API key + the dashboard's "Deep" toggle:

  * a much larger subdomain set,
  * the *current* DNS record set (A / AAAA / MX / NS / SOA / TXT) with the
    first-seen timestamp for each,
  * the *historical* DNS timeline for each record type · previous IPs, previous
    name servers, old MX, and when each change happened (first_seen / last_seen).

Everything is best-effort: no key, a rate-limit, or a network error degrades to
"nothing added" rather than raising. Records are normalised to a uniform shape:

    {"value": str, "first_seen": str|None, "last_seen": str|None, "organization": str|None, ...}

so the DNS panel in the dashboard renders one way regardless of record type.
"""
from __future__ import annotations

import time

from . import config
from .schema import ScanResult
from .util import get_logger, make_session

log = get_logger("deepdns")

CODE = config.SOURCE_CODES["securitytrails"]   # "s" · no tool name leaks downstream


def available() -> bool:
    return bool(config.SECURITYTRAILS_KEY)


# --------------------------------------------------------------------------- #
# Quota
#
# A key with its monthly allowance spent does not fail loudly · it answers 429
# to every call, and the scan simply comes back with no deep DNS at all after
# having spent minutes pretending to look. So the dashboard asks first, before
# the run starts, and puts the choice in front of the operator: go on without
# deep DNS, or paste a key that still has room.
# --------------------------------------------------------------------------- #
_USAGE_CACHE: dict = {"at": 0.0, "key": None, "value": None}
_USAGE_TTL = 120.0


def run_cost(*, subdomains: bool = True, history: bool = True) -> int:
    """How many API calls one deep-DNS pass spends.

    A monthly allowance on the free tier is small enough that a single run can
    finish it, so the dashboard is told the price before it commits: the host
    list, the domain record set, WHOIS, and one call per history record type."""
    return ((1 if subdomains else 0) + 2
            + (len(config.DNS_HISTORY_TYPES) if history else 0))


def check(*, force: bool = False) -> dict:
    """Where the configured key stands. Never raises.

    state is one of:
      unset       · no key configured (deep DNS simply unavailable)
      ok          · the key works and has allowance left
      low         · what is left will not cover a full deep pass
      exhausted   · the monthly quota is spent
      invalid     · the key was rejected (401/403)
      unreachable · the API did not answer (network, outage)
    """
    key = config.SECURITYTRAILS_KEY
    if not key:
        return {"state": "unset", "ok": False, "available": False,
                "message": "No deep-DNS key is configured."}
    now = time.time()
    if (not force and _USAGE_CACHE["value"] is not None
            and _USAGE_CACHE["key"] == key and now - _USAGE_CACHE["at"] < _USAGE_TTL):
        return _USAGE_CACHE["value"]

    session = make_session()
    url = f"{config.SECURITYTRAILS_BASE}/account/usage"
    try:
        resp = session.get(url, headers={"apikey": key, "Accept": "application/json"},
                           timeout=config.HTTP_TIMEOUT)
    except Exception as exc:
        out = {"state": "unreachable", "ok": False, "available": True,
               "message": f"Could not reach the deep-DNS API ({exc.__class__.__name__}). "
                          "The scan can still run without it."}
        return _cache_usage(key, out, now)

    if resp.status_code in (401, 403):
        out = {"state": "invalid", "ok": False, "available": True,
               "message": "The deep-DNS key was rejected. Enter a valid key, or "
                          "run without deep DNS."}
        return _cache_usage(key, out, now)
    if resp.status_code == 429:
        out = {"state": "exhausted", "ok": False, "available": True,
               "message": "The deep-DNS key has hit its rate limit. Enter another "
                          "key, or run without deep DNS."}
        return _cache_usage(key, out, now)
    if resp.status_code != 200:
        out = {"state": "unreachable", "ok": False, "available": True,
               "message": f"The deep-DNS API answered {resp.status_code}. "
                          "The scan can still run without it."}
        return _cache_usage(key, out, now)

    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    used = _as_int(data.get("current_monthly_usage"))
    limit = _as_int(data.get("allowed_monthly_usage"))
    remaining = (max(0, limit - used) if limit and used is not None else None)
    needed = run_cost()
    if limit and used is not None and used >= limit:
        out = {"state": "exhausted", "ok": False, "available": True,
               "used": used, "limit": limit, "remaining": 0, "needed": needed,
               "message": f"The deep-DNS key has used its full monthly allowance "
                          f"({used}/{limit}). Enter another key, or run without it."}
    elif remaining is not None and remaining < needed:
        # Enough allowance to start, not enough to finish: the pass would stop
        # part way through and the scan would carry half a DNS history without
        # ever saying so. Better to ask now.
        out = {"state": "low", "ok": False, "available": True,
               "used": used, "limit": limit, "remaining": remaining, "needed": needed,
               "message": f"Only {remaining} deep-DNS queries are left this month and a "
                          f"deep pass needs about {needed}. It would run out part way "
                          f"through and return incomplete history."}
    else:
        out = {"state": "ok", "ok": True, "available": True,
               "used": used, "limit": limit, "remaining": remaining, "needed": needed,
               "message": (f"{remaining} of {limit} deep-DNS queries left this month"
                           if remaining is not None else "Deep DNS is ready.")}
    return _cache_usage(key, out, now)


def _cache_usage(key: str, value: dict, at: float) -> dict:
    _USAGE_CACHE.update(at=at, key=key, value=value)
    return value


def _as_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def forget_usage() -> None:
    """Drop the cached quota · called when the key changes."""
    _USAGE_CACHE.update(at=0.0, key=None, value=None)


def _get(session, path: str) -> dict | None:
    if not config.SECURITYTRAILS_KEY:
        return None
    url = f"{config.SECURITYTRAILS_BASE}{path}"
    try:
        resp = session.get(url, headers={"apikey": config.SECURITYTRAILS_KEY,
                                         "Accept": "application/json"},
                           timeout=config.HTTP_TIMEOUT)
    except Exception as exc:
        log.info(f"deep DNS request failed ({path}): {exc}")
        return None
    if resp.status_code == 429:
        log.warning("deep DNS quota/rate limit hit · this key has no allowance "
                    "left, so the rest of the deep-DNS pass will return nothing. "
                    "Add a key with room in the dashboard.")
        time.sleep(1.5)
        return None
    if resp.status_code == 401 or resp.status_code == 403:
        log.warning("deep DNS key rejected (401/403) · check the key in the dashboard")
        return None
    if resp.status_code != 200:
        log.info(f"deep DNS http {resp.status_code} for {path}")
        return None
    try:
        return resp.json()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def _norm_current(rtype: str, block: dict) -> list[dict]:
    """Turn a current_dns block into uniform records (with first_seen)."""
    out: list[dict] = []
    first_seen = block.get("first_seen")
    for v in block.get("values", []) or []:
        rec: dict = {"value": None, "first_seen": first_seen, "last_seen": None}
        if rtype in ("a", "aaaa"):
            rec["value"] = v.get("ip") or v.get("ipv6")
            rec["organization"] = v.get("ip_organization")
        elif rtype == "mx":
            rec["value"] = v.get("hostname")
            rec["priority"] = v.get("priority")
            rec["organization"] = v.get("hostname_organization")
        elif rtype == "ns":
            rec["value"] = v.get("nameserver")
            rec["organization"] = v.get("nameserver_organization")
        elif rtype == "soa":
            rec["value"] = v.get("email")
            rec["ttl"] = v.get("ttl")
        elif rtype == "txt":
            rec["value"] = v.get("value")
        else:
            rec["value"] = v.get("value") or v.get("ip") or v.get("hostname")
        if rec["value"]:
            out.append(rec)
    return out


def _norm_history(rtype: str, data: dict) -> list[dict]:
    """Flatten the history timeline into per-value records with first/last seen."""
    out: list[dict] = []
    for rec in data.get("records", []) or []:
        first_seen = rec.get("first_seen")
        last_seen = rec.get("last_seen")
        orgs = rec.get("organizations") or []
        org = ", ".join(orgs) if isinstance(orgs, list) else str(orgs or "")
        for v in rec.get("values", []) or []:
            if isinstance(v, dict):
                val = (v.get("ip") or v.get("ipv6") or v.get("nameserver")
                       or v.get("hostname") or v.get("email") or v.get("value"))
                extra = {k: v[k] for k in ("priority", "ttl") if v.get(k) is not None}
            else:
                val = str(v)
                extra = {}
            if not val:
                continue
            out.append({"value": val, "first_seen": first_seen,
                        "last_seen": last_seen, "organization": org or None, **extra})
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(result: ScanResult, domain: str, *, history: bool = True,
        subdomains: bool = True) -> int:
    """Enrich `result` with deep subdomains + current & historical DNS.
    Returns the number of new subdomains added. No-op without a key.

    `subdomains=False` keeps the DNS records and the history but skips the host
    list · that is what a single-target scan wants: everything about this one
    host, nothing that widens the scope.
    """
    if not available():
        log.info("deep DNS skipped (no key)")
        return 0
    t0 = time.time()
    session = make_session()
    added = 0

    # 1. Subdomains -------------------------------------------------------- #
    data = _get(session, f"/domain/{domain}/subdomains?children_only=false&include_inactive=true") if subdomains else None
    if data:
        subs = data.get("subdomains", []) or []
        result.dns["subdomain_count"] = data.get("subdomain_count", len(subs))
        for prefix in subs:
            host = f"{prefix}.{domain}".lower().strip(".")
            before = host in result._subdomains          # type: ignore[attr-defined]
            result.add_subdomain(host, source=CODE)
            if not before:
                added += 1
        log.info(f"deep DNS: {len(subs)} subdomains ({added} new)")

    # 2. Current DNS records + WHOIS -------------------------------------- #
    details = _get(session, f"/domain/{domain}")
    if details:
        cur = details.get("current_dns", {}) or {}
        for rtype in ("a", "aaaa", "mx", "ns", "soa", "txt"):
            block = cur.get(rtype)
            if isinstance(block, dict):
                recs = _norm_current(rtype, block)
                if recs:
                    result.set_dns_records(rtype, recs, source=CODE)
                    # A/AAAA current records are real infra · link them.
                    if rtype in ("a", "aaaa"):
                        sub = result.add_subdomain(domain)
                        for r in recs:
                            result._link_ip(sub, r["value"], source=CODE)  # type: ignore[attr-defined]

    who = _get(session, f"/domain/{domain}/whois")
    if who:
        result.dns["whois"] = {
            "registrar": who.get("registrarName") or who.get("registrar"),
            "created": who.get("createdDate"),
            "expires": who.get("expiresDate"),
            "updated": who.get("updatedDate"),
            "name_servers": who.get("nameServers"),
            "contact_email": _first_email(who),
        }

    # 3. Historical DNS timeline ----------------------------------------- #
    if history:
        for rtype in config.DNS_HISTORY_TYPES:
            hist = _get(session, f"/history/{domain}/dns/{rtype}")
            if hist:
                recs = _norm_history(rtype, hist)
                if recs:
                    result.set_dns_history(rtype, recs, source=CODE)
        hcount = sum(len(v) for v in result.dns["history"].values())
        log.info(f"deep DNS: {hcount} historical records across "
                 f"{len(result.dns['history'])} record types")

    result.mark_module("deepdns", "ok",
                       note=f"{added} subdomains, "
                            f"{sum(len(v) for v in result.dns['records'].values())} DNS records",
                       duration=time.time() - t0)
    return added


def _first_email(who: dict) -> str | None:
    for c in who.get("contacts", []) or []:
        if isinstance(c, dict) and c.get("email"):
            return c["email"]
    return None
