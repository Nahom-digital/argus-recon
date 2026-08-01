#!/usr/bin/env python3
"""
Argus Recon · scan engine.

Runs the full single-domain recon pipeline in order and writes one JSON file per
scan into ./scans:

    0. Tor transport (optional)           (modules.tor · before anything else)
    1. subdomain discovery + infra        (modules.subdomain: fast passive → BBOT,
                                           bulk resolver)
    2. mass HTTP probe                    (modules.probe · live hosts + scheme)
    3. tech-stack fingerprinting          (modules.fingerprint, WhatWeb -a 3)
    4. deep crawl pre-pass                (modules.deepcrawl · JS-aware discovery)
    5. crawl -> HTML parse -> JS parse    (modules.crawler, async transport)
    6. smart bruteforce                   (modules.bruteforce, ffuf)
    7. IP enrichment                      (modules.ip_enrich, ipinfo.io)
    8. field-intent classification        (modules.classifier)
    9. storage                            (scans/{domain}_{timestamp}.json)
   10. graph load                         (modules.graph_loader → Neo4j / kuzu)

Two switches change the shape of a run rather than a step of it:

  * `--tor`    establishes a Tor circuit first and routes every request, name
               lookup and external tool through it; if that cannot be done the
               scan aborts instead of falling back to a direct connection.
  * `--single` scans exactly the host it was given: no subdomain enumeration and
               nothing off that host is in scope, anywhere in the pipeline.

This is not a terminal command. Scans are started from the dashboard, which
runs this module as a worker (web.server sets ARGUS_INTERNAL=1 and streams the
output into the job log you can watch in the UI). Running it by hand prints a
pointer to the dashboard and exits.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from modules import config
from modules.schema import ScanResult
from modules.util import (get_logger, registrable_root, registrable_domain,
                          is_subdomain_of, set_single_host)
from modules import (subdomain, fingerprint, crawler, bruteforce, ip_enrich,
                     classifier, graph_loader, securitytrails, tor, probe,
                     deepcrawl, portscan)

log = get_logger("main")

SRC_PORTSCAN = config.SOURCE_CODES["portscan"]

# The stages a scan runs by default and can switch off from the dashboard. The
# port scan is deliberately NOT here: it is opt-in (a toggle, like Tor and deep
# DNS), because it touches the target's infrastructure directly rather than its
# web surface · see --portscan.
ALL_MODULES = ["subdomain", "fingerprint", "crawl", "bruteforce",
               "ip_enrich", "classify", "graph"]


def _refuse_terminal_use() -> int:
    """The engine is driven by the dashboard. Point a human at it and stop."""
    url = f"http://{config.WEB_HOST}:{config.WEB_PORT}"
    print(f"""
  Argus Recon does not scan from the terminal.

  It runs as a service and every scan is started from the dashboard:

      {url}

  Enter the target there and press Run scan · you get the same pipeline,
  a live log, and the result opens in the graph view when it finishes.

      ./argus            is the service live?
      ./argus open       open the dashboard
      ./install.sh       install / register the service
""", file=sys.stderr)
    return 2

BANNER = r"""
   _   _ __ _ _   _ ___    Argus Recon v{ver}
  / \ | '__| '_| | | / __|   single-domain deep recon
 / _ \| |  | (_| |_| \__ \   target: {target}
/_/ \_\_|   \__,_\__,_|___/
""".strip("\n")


def _selected(args) -> set[str]:
    if args.only:
        want = {m.strip() for m in args.only.split(",")}
        return {m for m in ALL_MODULES if m in want}
    skip = {m.strip() for m in args.skip.split(",")} if args.skip else set()
    return {m for m in ALL_MODULES if m not in skip}


def run_pipeline(args) -> ScanResult:
    raw_host = registrable_root(args.domain)
    # A single-target scan is by definition exactly the host it was given.
    exact = bool(args.exact_scope or args.single)
    # If the user handed us a subdomain, pivot the scan to its apex so the rest
    # of the subdomains are enumerated too (item 5). --exact-scope keeps the host.
    domain = raw_host if exact else registrable_domain(raw_host)
    input_host = raw_host if is_subdomain_of(raw_host, domain) else None
    if input_host:
        log.info(f"target {raw_host} is a subdomain · pivoting scope to apex {domain}")

    # Single-target mode: nothing outside this one host is in scope, for every
    # module at once (crawler, parsers, bruteforce, graph).
    set_single_host(bool(args.single))

    result = ScanResult(domain)
    result.meta["scope"] = ("host" if args.single
                            else "exact" if args.exact_scope else "apex")
    run = _selected(args)
    t0 = time.time()

    # The deep-DNS key is managed in the dashboard (Settings / first run), so
    # here it is simply present or it is not.
    deep = bool(args.deep) and securitytrails.available()

    print(BANNER.format(ver="1.0.0", target=domain), file=sys.stderr)
    log.info(f"modules: {', '.join(m for m in ALL_MODULES if m in run)}"
             + ("  · deep DNS" if deep else "")
             + ("  · port scan" if args.portscan else "")
             + ("  · single target" if args.single else "")
             + ("  · over Tor" if tor.active() else ""))
    if args.single:
        log.info(f"scope: {domain} only · no subdomain enumeration, nothing off-host "
                 "is followed")

    # 1. Subdomains + infra
    if "subdomain" in run:
        subdomain.run(result, domain, passive=args.passive,
                      timeout=args.bbot_timeout, use_bbot=not args.no_bbot,
                      deep=deep, input_host=input_host, single=args.single)
    else:
        result.add_subdomain(domain, source="seed")
        subdomain.run(result, domain, passive=True, use_bbot=False,
                      deep=deep, input_host=input_host,
                      single=args.single)  # resolve + DNS only

    # 2. Mass HTTP probe · establishes which hosts are live and on which scheme
    #    for both the fingerprint and the crawl. Runs whenever either of those
    #    stages will (they both start from the live-host list it produces).
    if ("fingerprint" in run or "crawl" in run) and not args.no_probe:
        probe.run(result, timeout=args.tool_timeout)

    # 2a. Port / service scan (opt-in). Placed after the IPs are known but before
    #     the crawl so a web service found on a non-standard port (an admin panel
    #     on :8443, a staging app on :8080) becomes a crawl seed and gets the same
    #     body/form/secret treatment as the rest of the surface.
    port_seeds: list[str] = []
    if args.portscan:
        got = portscan.run(result, timeout=args.portscan_timeout)
        if isinstance(got, list):
            port_seeds = got
        # Name the stack behind each open web port (host:port), not just nmap's
        # "http" · WhatWeb against the exact port, tags folded onto the record.
        portscan.fingerprint_web_ports(result, timeout=args.tool_timeout)

    # 3. Fingerprint
    if "fingerprint" in run:
        fingerprint.run(result, timeout=args.tool_timeout)

    # 4-5. Crawl (HTML + JS parsing happen inside). A JS-aware deep-crawl
    #      pre-pass discovers routes/endpoints the static crawler cannot see and
    #      seeds it with them; the crawler then does the body/form/secret work.
    if "crawl" in run:
        seeds: list[str] = list(port_seeds)
        if not args.no_deepcrawl:
            roots = probe.live_roots(result) or _fallback_roots(result)
            got = deepcrawl.run(result, roots=roots, timeout=args.tool_timeout)
            if got:
                seeds += got
        crawler.run(result, max_pages=args.max_pages, max_depth=args.max_depth,
                    threads=args.threads, extra_seeds=seeds)
    elif args.portscan and port_seeds:
        # crawl disabled but a scan still turned up web ports · record them as
        # confirmed endpoints so they are not silently dropped.
        for seed in port_seeds:
            result.add_endpoint(seed, etype="page", source=SRC_PORTSCAN, in_scope=True)

    # 6. Bruteforce
    if "bruteforce" in run:
        bruteforce.run(result, timeout=args.tool_timeout,
                       maxtime=args.brute_maxtime, max_hosts=args.brute_hosts)

    # 7. IP enrichment
    if "ip_enrich" in run:
        ip_enrich.run(result)

    # 8. Classification
    if "classify" in run:
        classifier.run(result)

    result.meta["elapsed_sec"] = round(time.time() - t0, 1)
    return result


def _fallback_roots(result: ScanResult) -> list[str]:
    """Live roots when the mass probe was skipped: use whatever HTTP metadata is
    already on the subdomain records, else assume https for resolving hosts."""
    roots: list[str] = []
    for sub in result._subdomains.values():          # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("status") and not http.get("error"):
            roots.append(f"{http.get('scheme', 'https')}://{sub['host']}")
        elif sub.get("resolved"):
            roots.append(f"https://{sub['host']}")
    return sorted(set(roots))


def print_summary(result: ScanResult, path) -> None:
    d = result.to_dict()
    s = d["meta"]["stats"]
    print("\n" + "=" * 58, file=sys.stderr)
    print(f"  SCAN COMPLETE  ·  {d['meta']['domain']}", file=sys.stderr)
    print("=" * 58, file=sys.stderr)
    rows = [
        ("Subdomains", s["subdomains"]),
        ("Unique IPs", s["ips"]),
    ]
    if s.get("scanned_ips"):
        rows.append(("Open ports", f"{s.get('open_ports', 0)} across "
                                   f"{s['scanned_ips']} scanned IPs"))
    rows += [
        ("DNS records", s.get("dns_records", 0)),
        ("Historical DNS records", s.get("dns_history", 0)),
        ("Endpoints (in-scope)", s["in_scope_endpoints"]),
        ("Endpoints (out-of-scope, logged)", s["out_of_scope_endpoints"]),
        ("Forms", s["forms"]),
        ("JS files parsed", s["js_files"]),
        ("Discovered files", s["files"]),
        ("Secrets flagged", s["secrets"]),
        ("Classified requests", s["classified_requests"]),
    ]
    for label, val in rows:
        print(f"  {label:<36} {val}", file=sys.stderr)
    if d["meta"].get("scope") == "host":
        print(f"  {'Scope':<36} single target ({d['meta']['domain']} only)", file=sys.stderr)
    t = d["meta"].get("tor") or {}
    if t.get("active") or t.get("exit_ip"):
        print(f"  {'Transport':<36} Tor exit {t.get('exit_ip')}"
              + ("" if t.get("verified") else " (proxied, unverified)"), file=sys.stderr)
    if result.meta.get("classification_summary"):
        print("  Field intents: "
              + ", ".join(f"{k}={v}" for k, v in
                          result.meta["classification_summary"].items()),
              file=sys.stderr)
    print("-" * 58, file=sys.stderr)
    print(f"  Saved: {path}", file=sys.stderr)
    print(f"  View:  http://{config.WEB_HOST}:{config.WEB_PORT}/scan/"
          f"{d['meta']['scan_id']}", file=sys.stderr)
    print("=" * 58 + "\n", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="argus-engine",
        description="Argus Recon scan engine (started by the dashboard)")
    p.add_argument("domain", help="target domain, e.g. example.com")
    p.add_argument("--passive", action="store_true",
                   help="passive enumeration only (faster, non-touching)")
    p.add_argument("--deep", action="store_true",
                   help="deep DNS: extra subdomains + full DNS records + historical DNS "
                        "(needs an API key; prompts on first use)")
    p.add_argument("--exact-scope", action="store_true",
                   help="treat the given host literally; do not pivot a subdomain to its apex")
    p.add_argument("--single", action="store_true",
                   help="single-target scan: this host only · no subdomain "
                        "enumeration, nothing off-host is in scope")
    p.add_argument("--tor", action="store_true",
                   help="route the whole scan through Tor; aborts if a circuit "
                        "cannot be established (never falls back to a direct scan)")
    p.add_argument("--portscan", action="store_true",
                   help="scan every discovered IP for open ports and services "
                        "(off by default: touches infrastructure directly, slow, loud)")
    p.add_argument("--portscan-timeout", type=int, default=config.PORTSCAN_TIMEOUT,
                   help="max seconds per address in the port scan")
    p.add_argument("--no-prompt", action="store_true",
                   help=argparse.SUPPRESS)   # accepted for compatibility; never prompts
    p.add_argument("--no-bbot", action="store_true",
                   help="skip the deep passive enum engine; use the quick pass + "
                        "certificate transparency + DNS brute")
    p.add_argument("--no-probe", action="store_true",
                   help="skip the mass HTTP probe; each stage probes hosts itself (slower)")
    p.add_argument("--no-deepcrawl", action="store_true",
                   help="skip the JS-aware deep-crawl pre-pass; run the built-in crawler alone")
    p.add_argument("--only", help="comma list: run only these modules "
                   f"({','.join(ALL_MODULES)})")
    p.add_argument("--skip", help="comma list: skip these modules")
    p.add_argument("--max-pages", type=int, default=config.CRAWL_MAX_PAGES,
                   help="crawler page cap per host")
    p.add_argument("--max-depth", type=int, default=config.CRAWL_MAX_DEPTH,
                   help="crawler max depth")
    p.add_argument("--threads", type=int, default=config.CRAWL_THREADS,
                   help="crawler / probe threads")
    p.add_argument("--bbot-timeout", type=int, default=900,
                   help="max seconds for the BBOT run")
    p.add_argument("--tool-timeout", type=int, default=600,
                   help="max seconds per WhatWeb/ffuf batch")
    p.add_argument("--brute-maxtime", type=int, default=120,
                   help="ffuf max seconds per host")
    p.add_argument("--brute-hosts", type=int, default=None,
                   help="limit bruteforce to N live hosts")
    p.add_argument("--no-graph", action="store_true",
                   help="do not attempt the Neo4j graph load")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    if args.no_graph and args.only and "graph" in args.only:
        pass
    if args.no_graph:
        args.skip = (args.skip + ",graph") if args.skip else "graph"

    if args.verbose:
        for name in logging.root.manager.loggerDict:
            if name.startswith("argus."):
                logging.getLogger(name).setLevel(logging.DEBUG)

    # 0. Tor, before anything reaches the target. A failure here ends the run:
    #    the operator asked for Tor, so a direct scan is not an acceptable
    #    substitute.
    if args.tor:
        try:
            tor.connect()
        except tor.TorError as exc:
            log.error(f"Tor: {exc}")
            print("\n  Scan aborted · Tor was requested and could not be "
                  "established.\n  Nothing was sent to the target.\n", file=sys.stderr)
            return 3

    try:
        result = run_pipeline(args)
        if args.tor:
            result.meta["tor"] = tor.state()

        # 9. Storage
        path = result.save()

        # 10. Graph. Neo4j is a server, so the engine can load it directly. An
        #     embedded kuzu DB can only be open in one process at a time and the
        #     dashboard owns it · so for kuzu (and when no backend is up) the scan
        #     is queued and the dashboard's worker loads it. Either way a failure
        #     is queued, never lost, and the graph still renders from JSON.
        if "graph" in _selected(args):
            doc = result.to_dict()
            backend = graph_loader.active_backend()
            loaded = False
            if backend == "neo4j":
                loaded = graph_loader.load(doc, backend="neo4j")
                if loaded:
                    log.info("graph loaded into neo4j")
            # Queue for the dashboard to load only when a backend actually exists
            # to load it into (kuzu is owned by the dashboard process; a failed
            # neo4j load is worth retrying). With graph storage off entirely there
            # is nothing to queue · the dashboard still renders it from the JSON.
            if not loaded and backend != "none":
                try:
                    from modules import store
                    store.enqueue_graph(doc["meta"]["scan_id"], doc["meta"]["domain"])
                    if backend == "kuzu":
                        log.info("graph queued for the dashboard's embedded DB")
                except Exception:
                    pass

        print_summary(result, path)
    finally:
        tor.shutdown()
    return 0


if __name__ == "__main__":
    # Only the dashboard's job runner drives the engine (it sets ARGUS_INTERNAL).
    if os.environ.get("ARGUS_INTERNAL") != "1":
        sys.exit(_refuse_terminal_use())
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[interrupted]", file=sys.stderr)
        sys.exit(130)
