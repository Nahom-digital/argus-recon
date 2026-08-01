# Argus Recon

Single domain reconnaissance. Point it at one domain and it maps the attack
surface (subdomains, infrastructure, open ports, tech stack, endpoints, files,
secrets), saves one JSON file per scan, and serves a local dashboard with a
graph view.

Only scan targets you are authorized to test.

## Install

Linux with systemd and Python 3.10 or newer.

```bash
cd argus-recon
./install.sh
```

This installs the dependencies, registers the `argus-recon` systemd user
service, and starts the dashboard on http://127.0.0.1:7666. It is safe to run
again at any time. Use `./install.sh --upgrade` to update and restart.

## Use

Open http://127.0.0.1:7666, type a domain, press Run scan. The scan runs in the
background with a live log and opens in the graph view when it finishes. Results
are saved to `scans/`.

Launcher options: deep DNS, passive, via Tor, port scan, scope (apex, host, or
single), crawl limits, and a toggle per pipeline stage.

Port scan is opt in. When on, every discovered IP is scanned for open ports and
services, WhatWeb fingerprints each open web port, and the ports, service
versions, OS guess and tech show up in the Infrastructure panel and in the graph.

## Service

```bash
./argus              status
./argus open         open the dashboard
./argus start|stop|restart
./argus logs         follow the service log
./argus upgrade      pull the latest and restart
```

## Configuration

Set in `.env` or the environment. Full list in `modules/config.py`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECURITYTRAILS_KEY` | none | deep DNS: more subdomains plus full and historical DNS |
| `IPINFO_TOKEN` | none | IP enrichment (provider, ASN, country) |
| `ARGUS_GRAPH_BACKEND` | `auto` | graph store: `auto`, `kuzu`, `neo4j`, or `none` |
| `ARGUS_WEB_HOST` / `ARGUS_WEB_PORT` | `127.0.0.1` / `7666` | dashboard bind |
| `ARGUS_ACCESS_LOG` | `1` | set `0` to disable the dashboard access log |

## Notes

- This tool crawls and bruteforces actively. Get permission first.
- Missing optional tools degrade speed, not capability.
- A JSON access log of dashboard visitors is written under `scans/.access/`.
- Secrets in `.env` are gitignored and never leave the machine.
