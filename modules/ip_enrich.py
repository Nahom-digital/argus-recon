"""
Module 7 · IP enrichment.

For every resolved IP across all subdomains, query ipinfo.io and classify it:
hosting provider / organisation, country, ASN, and a datacenter-vs-residential
verdict inferred from the ASN organisation (ipinfo's explicit privacy/type
fields require a paid token, so we classify by provider keywords as a fallback
and use the token-provided fields when available).
"""
from __future__ import annotations

import concurrent.futures
import re
import time

from . import config
from .schema import ScanResult
from .util import get_logger, make_session

log = get_logger("ip_enrich")

# ASN-org keywords that reliably indicate datacenter / cloud / CDN hosting.
HOSTING_KEYWORDS = [
    "amazon", "aws", "google", "cloudflare", "microsoft", "azure", "digitalocean",
    "linode", "akamai", "fastly", "hetzner", "ovh", "oracle", "vultr", "scaleway",
    "leaseweb", "gcore", "cloud", "hosting", "datacenter", "data center", "server",
    "colo", "vps", "dedicated", "rackspace", "godaddy", "namecheap", "bluehost",
    "hostgator", "digital ocean", "contabo", "upcloud", "aliyun", "alibaba",
    "tencent", "cdn", "netlify", "vercel", "heroku", "fireabase", "cloudfront",
    "wpengine", "kinsta", "flywheel", "equinix", "hostinger", "ionos", "1&1",
]
# Keywords that suggest an ISP / eyeball (residential-ish) network.
ISP_KEYWORDS = [
    "telecom", "telecommunications", "broadband", "cable", "dsl", "fiber",
    "communications", "wireless", "mobile", "cellular", "isp", "internet service",
    "comcast", "verizon", "at&t", "vodafone", "orange", "telefonica", "bt group",
    "deutsche telekom", "spectrum", "cox", "charter", "sky ", "virgin media",
]


def _classify_org(org: str) -> tuple[str, bool]:
    """Return (type, datacenter) from an ASN org string."""
    low = (org or "").lower()
    if any(k in low for k in HOSTING_KEYWORDS):
        return "hosting", True
    if any(k in low for k in ISP_KEYWORDS):
        return "isp", False
    return "unknown", False


def _split_asn_org(org_field: str) -> tuple[str | None, str | None]:
    """ipinfo 'org' is like 'AS13335 Cloudflare, Inc.'."""
    if not org_field:
        return None, None
    m = re.match(r"(AS\d+)\s+(.*)", org_field.strip())
    if m:
        return m.group(1), m.group(2).strip()
    return None, org_field.strip()


def _enrich_one(session, ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}
    try:
        resp = session.get(url, params=params, timeout=config.HTTP_TIMEOUT)
        if resp.status_code != 200:
            return {"ip": ip, "error": f"http {resp.status_code}"}
        return resp.json()
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


def run(result: ScanResult, *, threads: int = 6) -> None:
    t0 = time.time()
    session = make_session()
    ips = list(result._ips.keys())  # type: ignore[attr-defined]
    if not ips:
        log.warning("no IPs to enrich")
        result.mark_module("ip_enrich", "empty", duration=time.time() - t0)
        return

    log.info(f"enriching {len(ips)} IPs via ipinfo.io"
             + ("" if config.IPINFO_TOKEN else " (no token · free tier)"))

    enriched = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_enrich_one, session, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            data = fut.result()
            rec = result.add_ip(ip, source=config.SOURCE_CODES["ipinfo"])
            if data.get("error"):
                rec["enriched"] = False
                rec.setdefault("whois", {})["error"] = data["error"]
                continue
            asn, org = _split_asn_org(data.get("org", ""))
            # ipinfo may also return a structured 'asn' object on paid plans.
            asn_obj = data.get("asn") or {}
            if isinstance(asn_obj, dict) and asn_obj:
                asn = asn_obj.get("asn") or asn
                org = asn_obj.get("name") or org
            ip_type = None
            datacenter = None
            privacy = data.get("privacy") or {}
            if isinstance(privacy, dict) and privacy:
                datacenter = bool(privacy.get("hosting"))
                ip_type = "hosting" if datacenter else "residential"
            if ip_type is None:
                ip_type, datacenter = _classify_org(org or "")
            rec.update({
                "hostname": data.get("hostname") or rec.get("hostname"),
                "city": data.get("city"), "region": data.get("region"),
                "country": data.get("country"), "loc": data.get("loc"),
                "asn": asn or rec.get("asn"),
                "org": org or rec.get("org"),
                "provider": org or rec.get("org"),
                "type": ip_type, "datacenter": datacenter,
                "enriched": True,
            })
            rec["whois"] = {
                "org": org, "asn": asn, "country": data.get("country"),
                "postal": data.get("postal"), "timezone": data.get("timezone"),
                "hostname": data.get("hostname"),
            }
            enriched += 1

    dc = sum(1 for r in result._ips.values() if r.get("datacenter"))  # type: ignore[attr-defined]
    log.info(f"enriched {enriched}/{len(ips)} IPs ({dc} datacenter/hosting)")
    result.mark_module("ip_enrich", "ok",
                       note=f"{enriched} IPs, {dc} hosting", duration=time.time() - t0)
