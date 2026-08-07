"""
Module · Nuclei preparation · smart template / tag selection.

Running every Nuclei template against every host is slow and noisy. This module
is the "understand the target first" step: it collects what the scan already
learned · detected technologies, open ports and services, server software,
CMS/frameworks · and turns it into a focused Nuclei run:

  * the live targets worth scanning (HTTP roots + discovered web ports), and
  * the template *tags* relevant to them · each detected technology maps to its
    Nuclei tag, on top of a small, high-value baseline (exposures,
    misconfiguration, default logins, subdomain takeover, known CVEs for the
    detected stack).

nuclei_scan then runs Nuclei with exactly that selection. Keeping the selection
here (data in, plan out, no subprocess) makes it easy to test and to reason about
what a given scan will actually probe.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .schema import ScanResult

# Detected-technology keyword -> Nuclei template tag(s). Substring match on the
# lowercased tech/product/header string, so "Apache Tomcat/9" matches both
# "apache" and "tomcat".
TECH_TAGS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-plugin"], "woocommerce": ["wordpress"],
    "joomla": ["joomla"], "drupal": ["drupal"], "magento": ["magento"],
    "typo3": ["typo3"], "ghost": ["ghost"], "shopify": ["shopify"],
    "jira": ["jira"], "confluence": ["confluence"], "bitbucket": ["bitbucket"],
    "gitlab": ["gitlab"], "github": ["github"], "gitea": ["gitea"],
    "jenkins": ["jenkins"], "teamcity": ["teamcity"], "bamboo": ["bamboo"],
    "grafana": ["grafana"], "kibana": ["kibana"], "prometheus": ["prometheus"],
    "elasticsearch": ["elastic"], "elastic": ["elastic"], "splunk": ["splunk"],
    "phpmyadmin": ["phpmyadmin"], "adminer": ["adminer"],
    "tomcat": ["tomcat", "apache"], "jboss": ["jboss"], "weblogic": ["weblogic"],
    "websphere": ["websphere"], "coldfusion": ["coldfusion"],
    "spring": ["springboot", "spring"], "springboot": ["springboot"],
    "laravel": ["laravel"], "symfony": ["symfony"], "django": ["django"],
    "flask": ["flask"], "rails": ["rails"], "express": ["nodejs"],
    "nginx": ["nginx"], "apache": ["apache"], "iis": ["iis"],
    "openresty": ["nginx"], "litespeed": ["litespeed"], "caddy": ["caddy"],
    "tomcat/": ["tomcat"], "php": ["php"], "aspnet": ["aspx"], "asp.net": ["aspx"],
    "citrix": ["citrix"], "fortinet": ["fortinet"], "fortigate": ["fortinet"],
    "pulse": ["pulsesecure"], "vpn": ["vpn"], "cisco": ["cisco"],
    "exchange": ["exchange"], "outlook": ["exchange"], "owa": ["exchange"],
    "sharepoint": ["sharepoint"], "rabbitmq": ["rabbitmq"], "kubernetes": ["kubernetes"],
    "docker": ["docker"], "portainer": ["portainer"], "consul": ["consul"],
    "vault": ["vault"], "solr": ["solr"], "zabbix": ["zabbix"], "nagios": ["nagios"],
    "sonarqube": ["sonarqube"], "nexus": ["nexus"], "artifactory": ["artifactory"],
    "keycloak": ["keycloak"], "wso2": ["wso2"], "moodle": ["moodle"],
    "cpanel": ["cpanel"], "plesk": ["plesk"], "webmin": ["webmin"],
    "phpinfo": ["phpinfo"], "swagger": ["swagger", "exposure"], "graphql": ["graphql"],
}

# Small, high-value baseline that is safe to run broadly and catches the issues a
# recon scan most wants surfaced, without pulling in the entire CVE corpus.
BASELINE_TAGS = ["exposure", "misconfig", "default-login", "takeover",
                 "config", "backup", "logs", "debug"]


def _tech_strings(result: ScanResult) -> set[str]:
    out: set[str] = set()
    for sub in result._subdomains.values():          # type: ignore[attr-defined]
        for t in (sub.get("tech") or []):
            if t:
                out.add(str(t).lower())
        http = sub.get("http") or {}
        if http.get("server"):
            out.add(str(http["server"]).lower())
        for comp in (http.get("tech") or http.get("components") or []):
            if comp:
                out.add(str(comp).lower())
    for ip in result._ips.values():                  # type: ignore[attr-defined]
        for p in (ip.get("ports") or []):
            for k in ("service", "product", "version"):
                v = p.get(k)
                if v:
                    out.add(str(v).lower())
            for t in (p.get("tech") or []):
                if t:
                    out.add(str(t).lower())
    return out


def _targets(result: ScanResult) -> list[str]:
    """Live HTTP roots plus discovered web ports, de-duplicated by origin."""
    seen: set[str] = set()
    out: list[str] = []

    def add(url: str) -> None:
        if not url:
            return
        try:
            s = urlsplit(url)
        except Exception:
            return
        if not s.scheme or not s.netloc:
            return
        origin = f"{s.scheme}://{s.netloc}"
        if origin not in seen:
            seen.add(origin)
            out.append(origin)

    for sub in result._subdomains.values():          # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("status") and not http.get("error"):
            add(f"{http.get('scheme', 'https')}://{sub['host']}")
    # Discovered web ports (non-standard admin panels, staging apps).
    for ip in result._ips.values():                  # type: ignore[attr-defined]
        for p in (ip.get("ports") or []):
            svc = (p.get("service") or "").lower()
            port = p.get("port")
            if not isinstance(port, int):
                continue
            if "http" in svc or port in (80, 443, 8080, 8443, 8000, 8888):
                scheme = "https" if ("ssl" in svc or "https" in svc or port in (443, 8443)) else "http"
                add(f"{scheme}://{ip['ip']}:{port}")
    return out


def collect(result: ScanResult) -> dict:
    """Return the focused Nuclei plan: targets, tags, and the tech it was built
    from. Tags = baseline + every tag implied by a detected technology."""
    tech = _tech_strings(result)
    tags: set[str] = set(BASELINE_TAGS)
    matched_tech: set[str] = set()
    for s in tech:
        for keyword, keyword_tags in TECH_TAGS.items():
            if keyword in s:
                tags.update(keyword_tags)
                matched_tech.add(keyword)
    return {
        "targets": _targets(result),
        "tags": sorted(tags),
        "tech": sorted(matched_tech),
        "reason": (f"{len(matched_tech)} technolog"
                   f"{'y' if len(matched_tech) == 1 else 'ies'} detected"),
    }
