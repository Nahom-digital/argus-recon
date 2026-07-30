# Argus Recon

Single-domain deep reconnaissance. Point it at one domain and it maps the whole
attack surface — subdomains, infrastructure, tech stack, every request/endpoint,
discovered files, and classified sensitive fields — writes it all to one JSON
file per scan, and serves an interactive dashboard with a graph view.

Built for authorized security testing / bug-bounty recon. **Only scan targets
you have permission to test.**

```
   _   _ __ _ _   _ ___     subdomains · infra · tech · endpoints
  / \ | '__| '_| | | / __|   requests · files · secrets · field intents
 / _ \| |  | (_| |_| \__ \   → one JSON per scan  +  local graph dashboard
/_/ \_\_|   \__,_\__,_|___/
```

---

## What it does

Everything is scoped to **the target domain and its subdomains**. Any link, form
action, or JS request pointing outside that scope is logged once as an endpoint
(method, full URL, where it was found) and never followed.

| # | Stage | Tool (source code) | Output |
|---|-------|------|--------|
| 1 | Subdomain discovery + infra | **BBOT** (`b`) + **SecurityTrails** deep DNS (`s`) + **crt.sh** (`c`) + DNS resolver (`dns`) | subdomains, resolved IPs, **DNS records** (A/AAAA/MX/NS/CNAME/TXT/SOA), **historical DNS**, WHOIS |
| 2 | Tech fingerprinting | **WhatWeb** `-a 3` (`W`) | per-subdomain tech tags + raw plugin record |
| 3 | Crawler (in-scope, recursive) | custom (`crawler`) | every page, form, link, resource; discovered hosts become subdomains |
| 4 | HTML/DOM parser | custom | forms, buttons/inputs, links, favicon/img, meta, comments |
| 5 | JS source parser | custom (`js`, JSluice + LinkFinder ideas) | endpoints, fetch/axios/XHR request logic, secrets |
| 6 | Smart bruteforce | **ffuf** (`f`, or feroxbuster) | robots/sitemap hints + stack-aware wordlist hits, w/ request+response |
| 7 | IP enrichment | **ipinfo.io** (`i`) | provider, ASN, country, datacenter vs residential |
| 8 | Field-intent classifier | custom | password / token / otp / api_key / redirect / idor … |
| 9 | Storage | — | `scans/{domain}_{timestamp}.json` |
| 10 | Graph | **Neo4j** (optional) | Domain → Subdomain → Endpoint → Request → Field |

**Source codes.** Findings and the dashboard never print the real tool names — each
source is tagged with a short code so a shared scan or screenshot does not disclose
the toolchain. The mapping (documented here only):

| Code | Real source | Code | Real source |
|------|-------------|------|-------------|
| `b` | BBOT (passive subdomain/ASN enum) | `i` | ipinfo.io (IP enrichment) |
| `W` | WhatWeb (`-a 3` fingerprint) | `crawler` | our in-scope crawler |
| `f` | ffuf / feroxbuster (content brute) | `js` | our JS analyser |
| `s` | SecurityTrails (deep DNS + history) | `robots` / `sitemap` | those map files |
| `c` | crt.sh (certificate transparency) | `dns` / `input` / `seed` | resolver / target / apex |

The button-to-request mapping is traceable: the JS parser records each
`fetch`/`axios`/`XHR` call with its method, URL, line, and the enclosing
handler function, and links it to the request node in the graph and the
"Request logic (JS)" block in the dashboard.

**If you point Argus at a subdomain** (e.g. `api.example.com`) it recognises it as a
subdomain, pivots the scan to the registrable apex (`example.com`), enumerates the
*other* subdomains too, and keeps the one you named tagged as the `input` source.
Set **Scope → This host only** in the launcher to disable the pivot and scan just
the host you gave.

---

## Install

Requires Linux with systemd, Python 3.10+, and a few external CLI tools.
One command installs everything and registers the dashboard as a service:

```bash
cd argus-recon
./install.sh
```

That is the whole install. It is fresh-server safe and idempotent:

1. installs the base packages it needs (python venv/pip, pipx, curl, git),
2. installs the external recon engines (whatweb, ffuf/feroxbuster, bbot via pipx),
3. builds the Python venv from `requirements.txt`,
4. writes and enables the **`argus-recon`** systemd *user* service, with linger on
   so it survives logout and reboot,
5. waits until the dashboard actually answers, then prints **LIVE** with the URL,
   pid, uptime and version.

Run it again any time. If the service is already up it says so and stops rather
than installing a second copy:

```
[argus] LIVE  ·  http://127.0.0.1:7666
        service   argus-recon (pid 339379)
        up since  2026-07-29 22:42
        version   967ad05
```

| Command | What it does |
|---------|--------------|
| `./install.sh` | install everything, register the service, start it |
| `./install.sh --upgrade` | fetch + fast-forward from GitHub, refresh deps, restart the service |
| `./install.sh --status` | is it live? (exit 0 when serving) |
| `./install.sh --restart` | bounce the service |
| `./install.sh --force` | reinstall dependencies and the unit over the top |
| `./install.sh --uninstall` | stop and remove the service (scans and `.venv` are kept) |

`--upgrade` stashes local edits before pulling, refreshes the venv, rewrites the
unit, restarts, and waits for the dashboard to answer again before reporting.

Manage the unit directly with `systemctl --user status|restart|stop argus-recon`,
follow logs with `journalctl --user -u argus-recon -f`. (Installs from before the
rename retire their old `argusscanner` unit automatically.)

Two optional extras:

```bash
# Deep DNS: a SecurityTrails API key — a much larger subdomain set plus full and
# historical DNS. The dashboard asks for it on first run and stores it in .env;
# you can also write it yourself:
echo 'SECURITYTRAILS_KEY=your_key_here' >> .env

# Neo4j for the persisted graph — the dashboard graph works fine without it
docker run -d --name argus-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/argusrecon neo4j:5
```

Everything degrades gracefully: no BBOT → certificate transparency + DNS brute;
no deep-DNS key → resolver-only DNS records; no Neo4j → the dashboard builds the
graph straight from the scan JSON. Secrets (`.env`, the SecurityTrails key) are
gitignored and never leave the machine.

---

## Usage

**Scans run in the dashboard.** There is no scanning command: the engine refuses
to run from a terminal, and `./argus` only controls the service. Everything the
old flags did is in the launcher on the home page.

### Start a scan

Open **http://127.0.0.1:7666**, type the target, press **Run scan**. The job
appears with a live log, and the finished scan opens in the graph view.

| Control | Old flag | Meaning |
|---------|----------|---------|
| deep DNS | `--deep` | extra subdomains + full DNS records + historical DNS (needs a key) |
| passive | `--passive` | passive enumeration only |
| Scope: *This host only* | `--exact-scope` | treat the host literally; don't pivot a subdomain to its apex |
| skip passive-enum engine | `--no-bbot` | use certificate transparency + DNS fallback instead |
| Max pages / Max depth | `--max-pages` `--max-depth` | crawler bounds (blank = configured default) |
| Pipeline stages | `--skip a,b` / `--no-graph` | switch off any of subdomains, fingerprint, crawl, bruteforce, IP enrich, classify, graph |

A running scan can be stopped from its job row — that is what replaces Ctrl-C.
Each scan still writes `scans/{domain}_{timestamp}.json`.

### Control the service

```bash
./argus              # is it live?
./argus open         # open the dashboard
./argus start|stop|restart
./argus logs         # follow the service log
./argus upgrade      # pull the latest + restart
```

### The dashboard

- **Home** — the scan launcher (target, the two common toggles, and an **Options**
  panel holding scope, crawl bounds and the pipeline stages, with a badge when
  anything is off-default), running and recent jobs with a live log and a **stop**
  button, and every scan in `./scans` with headline metrics (**delete** by hovering
  a row). The status strip leads with **Live** — service state, uptime and version —
  followed by capability state only (deep unlocked, graph DB, engines); no tool
  names. First launch asks once for the deep-DNS key.
- **Scan view**
  - *left*: subdomains (status + tech + IP + **source**), infrastructure (each IP →
    which subdomains + source), **DNS** (A/AAAA/MX/NS/CNAME/TXT/SOA + history + WHOIS),
    **tech stack** (each fingerprint → the subdomains it was detected on *and* the
    IPs those hosts resolve to — every chip filters), secrets (+ which source found
    each), discovered **files** (expand for source + request + response), module run log
  - *center*: interactive force-directed graph. **Click a node to lock it** — a rich
    card shows every attribute + source, with a **decode** button for any base64 /
    JWT / URL-encoded value; the card stays until you press ×. Large graphs
    **defer layout** behind an *Activate* button so the tab never freezes.
    The **⤢ expand** button hides the graph + table and opens a full-width detail
    report — DNS tables, historical-DNS expandables, subdomains, infra, tech,
    secrets, files — **one table per row, each the full width of the page**, so no
    data set has to be read through a horizontal scrollbar.
  - *bottom*: every captured request; filter by scope / **domain / subdomain** /
    **IP** / type / **status code** / classification / search; expand a row for
    headers, response body, fields, the JS call that fires it, and a decode
    affordance for encoded URLs/bodies. Host and IP filters drive the graph too:
    a host collapses it to that host's subtree, an IP to every host on that address,
    with the domain kept as an anchor.

  **Graph detail layers.** `Endpoint`, `Request`, `Field`, `JS`, `File` and
  `External` are the bulk of a scan — thousands of nodes that only mean anything
  inside one host. They stay hidden, and their legend entry shows a **lock**,
  until a **specific subdomain** is selected; the legend still reports their real
  totals, so the true size of the attack surface is visible the whole time. Pick a
  host and those layers unlock, land around it, and the view frames itself. "All
  hosts" (or an IP filter, which can span several hosts) keeps them locked.

Visual style matches the claude.ai chat interface — warm flat surfaces, one clay
accent, self-hosted Hanken Grotesk + IBM Plex Mono, a Tabler icon set, light/dark.

---

## Configuration

Behaviour is tunable via environment variables (see `modules/config.py`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECURITYTRAILS_KEY` | — | deep-DNS key (subdomains + full/historical DNS); stored in `.env` |
| `IPINFO_TOKEN` | — | ipinfo.io token (free tier works without) |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | `bolt://localhost:7687` / `neo4j` / `argusrecon` | graph DB |
| `ARGUS_CRAWL_MAX_PAGES` / `ARGUS_CRAWL_MAX_DEPTH` / `ARGUS_CRAWL_THREADS` | 600 / 6 / 12 | crawler bounds |
| `ARGUS_HTTP_TIMEOUT` | 12 | per-request timeout (s) |
| `ARGUS_VERIFY_TLS` | 0 | set `1` to enforce TLS verification |
| `ARGUS_WEB_HOST` / `ARGUS_WEB_PORT` | 127.0.0.1 / 7666 | dashboard bind |

Load the scan JSON into Neo4j manually if you skipped it at scan time:

```python
import json
from modules import graph_loader
graph_loader.load(json.load(open("scans/example.com_20260101_120000.json")))
```

---

## Layout

```
argus-recon/
  install.sh              installer + service manager (argus-recon systemd user unit)
  main.py                 scan engine — run by the dashboard, refuses a terminal
  argus                   service control (status / start / stop / logs / upgrade)
  serve                   what the service execs to run the dashboard
  bootstrap.sh            shared venv/dependency bootstrap
  .env                    local secrets (deep-DNS key) — gitignored
  modules/
    config.py             paths, tool commands, pattern libraries, .env loader, source codes
    util.py               logging, HTTP session, scope rule, eTLD+1, tool resolution
    schema.py             ScanResult container + dedup + DNS store + JSON serialisation
    subdomain.py          (1) BBOT + deep DNS + crt.sh/DNS fallback + DNS records + WHOIS
    securitytrails.py     (1) deep DNS: subdomains + current & historical records
    fingerprint.py        (2) WhatWeb -a 3
    crawler.py            (3) in-scope recursive crawler
    html_parser.py        (4) DOM extraction
    js_parser.py          (5) endpoints / request logic / secrets
    bruteforce.py         (6) robots/sitemap + stack wordlist + ffuf
    ip_enrich.py          (7) ipinfo.io
    classifier.py         (8) field-intent classification
    graph_loader.py       (10) graph model + Neo4j loader
  web/
    server.py             Flask app (:7666)
    templates/            base, index, scan
    static/               css, js (incl. custom canvas graph), fonts, icons
  scans/                  {domain}_{timestamp}.json outputs
  wordlists/
```

## Scan JSON shape

```jsonc
{
  "meta":       { "domain", "scan_id", "started_at", "stats", "modules", "domain_whois", … },
  "dns":        { "records":  { "a|aaaa|mx|ns|cname|txt|soa": [ { "value", "first_seen", "priority", "ttl", "organization" } ] },
                  "history":  { "a|ns|mx|…": [ { "value", "first_seen", "last_seen", "organization" } ] },
                  "whois", "subdomain_count", "sources": ["s","dns"] },
  "subdomains": [ { "host", "ips", "sources", "resolved", "http", "tech", "whatweb" } ],
  "infra":      { "ips": [ { "ip", "asn", "org", "country", "type", "datacenter", "subdomains", "sources" } ] },
  "endpoints":  [ { "url", "method", "type", "in_scope", "status", "sources", "fields",
                    "classifications", "req_headers", "resp_headers", "resp_body",
                    "js_origin", "found_on", "dom" } ],
  "files":      [ { "url", "kind", "subtype", "status", "sources", "found_on",
                    "req_headers", "resp_headers", "resp_body" } ],
  "js_files":   [ { "url", "endpoints", "requests", "secrets" } ],
  "secrets":    [ { "type", "match", "severity", "source", "found_by" } ]
}
```

## Notes & limits

- **Authorization is on you.** This tool actively crawls and bruteforces; only
  point it at assets you are permitted to test.
- Deep DNS (subdomains, full records, historical DNS) needs a SecurityTrails key;
  on the free/trial tier its history endpoints are rate-limited, so Argus backs off
  and keeps whatever it retrieved rather than failing. IP-privacy fields likewise
  need an ipinfo token. Without keys those fields are best-effort and left empty
  rather than faked.
- The crawler is static (requests + regex JS analysis), which is what makes the
  button→request mapping traceable without executing pages. It does not render
  SPA client-side routes that only exist after JS execution.
