#!/usr/bin/env python3
"""
Argus Recon — scan engine.

Runs the full single-domain recon pipeline in order and writes one JSON file per
scan into ./scans:

    1. subdomain discovery + infra        (modules.subdomain, BBOT)
    2. tech-stack fingerprinting          (modules.fingerprint, WhatWeb -a 3)
    3. crawl  -> 4. HTML parse -> 5. JS parse   (modules.crawler)
    6. smart bruteforce                   (modules.bruteforce, ffuf)
    7. IP enrichment                      (modules.ip_enrich, ipinfo.io)
    8. field-intent classification        (modules.classifier)
    9. storage                            (scans/{domain}_{timestamp}.json)
   10. graph load                         (modules.graph_loader, Neo4j)

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
from modules.util import get_logger, registrable_root, registrable_domain, is_subdomain_of
from modules import (subdomain, fingerprint, crawler, bruteforce, ip_enrich,
                     classifier, graph_loader, securitytrails)

log = get_logger("main")

ALL_MODULES = ["subdomain", "fingerprint", "crawl", "bruteforce",
               "ip_enrich", "classify", "graph"]


def _refuse_terminal_use() -> int:
    """The engine is driven by the dashboard. Point a human at it and stop."""
    url = f"http://{config.WEB_HOST}:{config.WEB_PORT}"
    print(f"""
  Argus Recon does not scan from the terminal.

  It runs as a service and every scan is started from the dashboard:

      {url}

  Enter the target there and press Run scan — you get the same pipeline,
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
    # If the user handed us a subdomain, pivot the scan to its apex so the rest
    # of the subdomains are enumerated too (item 5). --exact-scope keeps the host.
    domain = raw_host if args.exact_scope else registrable_domain(raw_host)
    input_host = raw_host if is_subdomain_of(raw_host, domain) else None
    if input_host:
        log.info(f"target {raw_host} is a subdomain — pivoting scope to apex {domain}")

    result = ScanResult(domain)
    run = _selected(args)
    t0 = time.time()

    # The deep-DNS key is managed in the dashboard (Settings / first run), so
    # here it is simply present or it is not.
    deep = bool(args.deep) and securitytrails.available()

    print(BANNER.format(ver="1.0.0", target=domain), file=sys.stderr)
    log.info(f"modules: {', '.join(m for m in ALL_MODULES if m in run)}"
             + ("  · deep DNS" if deep else ""))

    # 1. Subdomains + infra
    if "subdomain" in run:
        subdomain.run(result, domain, passive=args.passive,
                      timeout=args.bbot_timeout, use_bbot=not args.no_bbot,
                      deep=deep, input_host=input_host)
    else:
        result.add_subdomain(domain, source="seed")
        subdomain.run(result, domain, passive=True, use_bbot=False,
                      deep=deep, input_host=input_host)  # resolve + DNS only

    # 2. Fingerprint
    if "fingerprint" in run:
        fingerprint.run(result, timeout=args.tool_timeout)

    # 3-5. Crawl (HTML + JS parsing happen inside)
    if "crawl" in run:
        crawler.run(result, max_pages=args.max_pages, max_depth=args.max_depth,
                    threads=args.threads)

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


def print_summary(result: ScanResult, path) -> None:
    d = result.to_dict()
    s = d["meta"]["stats"]
    print("\n" + "=" * 58, file=sys.stderr)
    print(f"  SCAN COMPLETE  ·  {d['meta']['domain']}", file=sys.stderr)
    print("=" * 58, file=sys.stderr)
    rows = [
        ("Subdomains", s["subdomains"]),
        ("Unique IPs", s["ips"]),
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
    p.add_argument("--no-prompt", action="store_true",
                   help=argparse.SUPPRESS)   # accepted for compatibility; never prompts
    p.add_argument("--no-bbot", action="store_true",
                   help="skip the passive enum engine; use certificate transparency + DNS brute")
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

    result = run_pipeline(args)

    # 9. Storage
    path = result.save()

    # 10. Graph
    if "graph" in _selected(args):
        graph_loader.load(result.to_dict())

    print_summary(result, path)
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
