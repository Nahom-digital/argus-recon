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
| 1 | Subdomain discovery + infra | **subfinder** quick pass (`n`) → **BBOT** deep (`b`) + **SecurityTrails** deep DNS (`s`) + **crt.sh** (`c`), resolved by **dnsx** (`r`) / DNS resolver (`dns`) | subdomains, resolved IPs, **DNS records** (A/AAAA/MX/NS/CNAME/TXT/SOA), **historical DNS**, WHOIS |
| 2 | Mass HTTP probe | **httpx** (`h`) | live hosts + scheme, status/title/server, first tech guess, answering IP + CNAME |
| 3 | Tech fingerprinting | **WhatWeb** `-a 3` (`W`) | per-subdomain tech tags + raw plugin record |
| 4 | Deep-crawl pre-pass | **katana** (`k`) | JS-aware endpoint/route discovery → seeds the crawler |
| 5 | Crawler (in-scope, recursive, async) | custom (`crawler`) | every page, form, link, resource; discovered hosts become subdomains |
| 6 | HTML/DOM parser | custom | forms, buttons/inputs, links, favicon/img, meta, comments |
| 7 | JS source parser | custom (`js`, JSluice + LinkFinder ideas) | endpoints, fetch/axios/XHR request logic, secrets |
| 8 | Smart bruteforce | **ffuf** (`f`, or feroxbuster) | robots/sitemap hints + stack-aware wordlist hits, w/ request+response |
| 9 | IP enrichment | **ipinfo.io** (`i`) | provider, ASN, country, datacenter vs residential |
| 10 | Field-intent classifier | custom | password / token / otp / api_key / redirect / idor … |
| 11 | Storage | SQLite (WAL) cache + `scans/{domain}_{timestamp}.json` | one JSON per scan; a derived cache/queue speeds the dashboard |
| 12 | Graph | **kuzu** (embedded, default) or **Neo4j** | Domain → Subdomain → Endpoint → Request → Field |

**Speed.** The wide, fan-out-heavy passes (name enum, HTTP probing, JS-aware
crawling, bulk resolution) run on Go binaries at high concurrency, and the custom
crawler's own HTTP layer is asyncio (`httpx.AsyncClient` behind a semaphore) so it
keeps pace instead of being the pipeline's floor. Every Go tool is **optional and
validated** — Argus probes each binary's `-version` (some distros ship an unrelated
`httpx`) and falls back to a built-in path when one is missing, so the pipeline
degrades in speed, never in capability.

**Source codes.** Findings and the dashboard never print the real tool names — each
source is tagged with a short code so a shared scan or screenshot does not disclose
the toolchain. The mapping (documented here only):

| Code | Real source | Code | Real source |
|------|-------------|------|-------------|
| `b` | BBOT (passive subdomain/ASN enum) | `i` | ipinfo.io (IP enrichment) |
| `n` | subfinder (quick passive names) | `h` | httpx (mass HTTP probe) |
| `k` | katana (JS-aware deep crawl) | `r` | dnsx (bulk resolver) |
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

**Scope** has three settings in the launcher:

| Scope | Meaning |
|-------|---------|
| Apex + subdomains *(default)* | a subdomain target pivots to its apex; the whole estate is enumerated |
| Host + subdomains | the host is taken literally (no apex pivot); its own subdomains are still enumerated |
| **Single host** | this host and nothing else — no enumeration; anything off-host is logged but never followed |

**Tor.** Turn on **via Tor** and the scan runs through a Tor circuit end to end.
Before anything reaches the target Argus finds a usable SOCKS proxy — reusing a
Tor client already listening on `127.0.0.1:9050`, or starting a private `tor` with
its own throwaway data directory — waits for the circuit to bootstrap, and confirms
the exit really is a Tor node. Only then does the pipeline start. Every request,
every name lookup (switched to DNS-over-HTTPS so no hostname leaks past the proxy),
and every external tool (torsocks-wrapped, or handed the SOCKS proxy natively for
Go tools like ffuf) goes through it. If a circuit cannot be established the scan
**aborts** rather than falling back to a direct connection — the point of the toggle
is that your address never reaches the target. WHOIS (raw port 43) is skipped over
Tor rather than leaked. The toggle is locked when the machine has no `tor` and no
SOCKS dependency; the launcher says which piece is missing.

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
2. installs the external recon engines (whatweb, ffuf/feroxbuster, bbot via pipx,
   tor + torsocks for Tor scans), and — when a Go toolchain is present — the
   ProjectDiscovery speed tools (httpx, katana, subfinder, dnsx) into `~/go/bin`,
3. builds the Python venv from `requirements.txt` (incl. PySocks for Tor, the
   async HTTP client, and the embedded graph DB),
4. writes and enables the **`argus-recon`** systemd *user* service, with linger on
   so it survives logout and reboot,
5. waits until the dashboard actually answers, then prints **LIVE** with the URL,
   pid, uptime and version.

The Go speed tools are optional: without them (or without Go) Argus runs on its
built-in async probe/crawler/resolver — slower, but nothing is lost. Install them
later with `go install github.com/projectdiscovery/{httpx,katana,dnsx}/cmd/...@latest`
and `.../subfinder/v2/cmd/subfinder@latest`, then re-run `./install.sh --force`.

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

# Persisted graph: kuzu (embedded, no server) is the default and ships in
# requirements.txt — nothing to run. To use Neo4j instead, start one and set
# ARGUS_GRAPH_BACKEND=neo4j:
docker run -d --name argus-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/argusrecon neo4j:5
```

**Graph storage.** `ARGUS_GRAPH_BACKEND` selects the backend: `auto` (default —
a reachable Neo4j, else the embedded **kuzu** DB), `kuzu`, `neo4j`, or `none`.
kuzu is an embedded graph database (SQLite's deployment model, Cypher's query
language) that needs no server, so the persisted graph works out of the box. A
scan finished while the backend was down is queued and loaded when it returns.
In the dashboard's graph panel a **1 / 2** switch picks the renderer — **1** the
built-in canvas graph, **2** Cytoscape.js with the fCoSE layout and a switchable
fCoSE / SBGN stylesheet.

A SQLite (WAL) store sits in front of it as a cache + job queue: the home-page
summaries and the per-endpoint index are written once and read back as rows, so a
large scan lists and opens without re-parsing multi-MB JSON on every request.

Everything degrades gracefully: no BBOT → quick passive pass + certificate
transparency + DNS brute; no deep-DNS key → resolver-only DNS records; no graph
backend → the dashboard builds the graph straight from the scan JSON. Secrets
(`.env`, the SecurityTrails key) are gitignored and never leave the machine.

---

## Usage

**Scans run in the dashboard.** There is no scanning command: the engine refuses
to run from a terminal, and `./argus` only controls the service. Everything the
old flags did is in the launcher on the home page.

### Start a scan

Open **http://127.0.0.1:7666**, type the target, press **Run scan**. The job
appears with a live log, and the finished scan opens in the graph view.

| Control | Engine flag | Meaning |
|---------|----------|---------|
| deep DNS | `--deep` | extra subdomains + full DNS records + historical DNS (needs a key) |
| passive | `--passive` | passive enumeration only |
| via Tor | `--tor` | run the whole scan through Tor; aborts if no circuit (never scans direct) |
| Scope: *Host + subdomains* | `--exact-scope` | treat the host literally; don't pivot a subdomain to its apex |
| Scope: *Single host* | `--single` | this host only — no enumeration, nothing off-host is followed |
| skip passive-enum engine | `--no-bbot` | use certificate transparency + DNS fallback instead |
| Max pages / Max depth | `--max-pages` `--max-depth` | crawler bounds (blank = configured default) |
| Pipeline stages | `--skip a,b` / `--no-graph` | switch off any of subdomains, fingerprint, crawl, bruteforce, IP enrich, classify, graph |

The flags are how the dashboard drives the engine internally; they are not a
terminal interface (the engine refuses to run from a terminal).

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
| `ARGUS_GRAPH_BACKEND` | `auto` | graph store: `auto` / `kuzu` / `neo4j` / `none` |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | `bolt://localhost:7687` / `neo4j` / `argusrecon` | Neo4j graph DB |
| `ARGUS_KUZU_DIR` / `ARGUS_STORE_DB` | `scans/.kuzu` / `scans/.argus.db` | embedded graph DB / SQLite cache-queue |
| `ARGUS_STORE` | 1 | set `0` to disable the SQLite cache + graph-load queue |
| `ARGUS_CRAWL_CONCURRENCY` / `ARGUS_CRAWL_HOST_CONCURRENCY` | 80 / 12 | async crawler in-flight requests (total / per host) |
| `ARGUS_CRAWL_MAX_PAGES` / `ARGUS_CRAWL_MAX_DEPTH` / `ARGUS_CRAWL_THREADS` | 600 / 6 / 12 | crawler bounds (threads = sync-fallback pool) |
| `ARGUS_PROBE_THREADS` / `ARGUS_PROBE_RATE` | 150 / 300 | mass HTTP probe concurrency / rate cap |
| `ARGUS_KATANA_DEPTH` / `ARGUS_KATANA_HEADLESS` | 3 / 0 | deep-crawl depth / headless render (`1` = on) |
| `ARGUS_BRUTE_RATE` / `ARGUS_BRUTE_MATCH_ALL` | 180 / 1 | ffuf requests/sec / `-mc all` + noise filters |
| `ARGUS_HTTP_TIMEOUT` | 12 | per-request timeout (s) |
| `ARGUS_VERIFY_TLS` | 0 | set `1` to enforce TLS verification |
| `ARGUS_WEB_HOST` / `ARGUS_WEB_PORT` | 127.0.0.1 / 7666 | dashboard bind |

Load a scan JSON into the graph backend manually if you skipped it at scan time
(picks the active backend — embedded kuzu unless a Neo4j is reachable):

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
    util.py               logging, HTTP session (Tor-aware), scope rule, eTLD+1, tool resolution (Go-tool validation)
    schema.py             ScanResult container + dedup + DNS store + JSON serialisation (+ store index)
    store.py              SQLite (WAL) cache + graph-load queue in front of the graph backend
    asynchttp.py          async HTTP layer (httpx.AsyncClient + semaphore) used by the crawler
    tor.py                (0) Tor transport — proxy discovery, bootstrap, verification
    subdomain.py          (1) subfinder quick pass + BBOT + deep DNS + crt.sh/DNS fallback + dnsx bulk resolve + WHOIS
    securitytrails.py     (1) deep DNS: subdomains + current & historical records
    probe.py              (2) mass HTTP probe (httpx) — live hosts + scheme + first tech guess
    fingerprint.py        (3) WhatWeb -a 3 (reuses the probe's live-host list)
    deepcrawl.py          (4) JS-aware deep-crawl pre-pass (katana) — seeds the crawler
    crawler.py            (5) in-scope recursive crawler — async transport, sync fallback
    html_parser.py        (6) DOM extraction
    js_parser.py          (7) endpoints / request logic / secrets
    bruteforce.py         (8) robots/sitemap + stack wordlist + ffuf (rate-tuned, -mc all + calibration)
    ip_enrich.py          (9) ipinfo.io
    classifier.py         (10) field-intent classification
    graph_loader.py       (12) graph model + kuzu / Neo4j loaders
  web/
    server.py             Flask app (:7666) — store-backed reads, graph-queue drain worker
    templates/            base, index, scan
    static/               css, js (canvas graph + Cytoscape.js engine), js/vendor (cytoscape, fcose, sbgn), fonts, icons
  scans/                  {domain}_{timestamp}.json outputs (+ .argus.db cache, .kuzu graph — gitignored)
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
