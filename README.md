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

This installs the dependencies, asks you to create the administrator account,
registers the `argus-recon` systemd user service, and starts the dashboard on
http://127.0.0.1:7666. It is safe to run again at any time. Use
`./install.sh --upgrade` to update and restart.

## Use

Open http://127.0.0.1:7666, sign in, type a domain, press Run scan. The scan
runs in the background with a live log and opens in the graph view when it
finishes. Results are saved to `scans/`.

## Accounts and access

The dashboard is not open. Once `key.json` exists (the installer creates it),
every page and every API route needs a signed session, including from
localhost.

- **Administrator** · created at install time. Sees every scan, manages
  accounts, reads the access history. Admin area: `/recon/admin`.
- **Operator** · created by an administrator. Sees only their own scans, and
  only gets the scan options the administrator enabled for them.

Accounts live in `key.json` next to the code: passwords as PBKDF2-SHA256
hashes (never plaintext), each account's allowance, and the secret that signs
session tokens. The file is written `0600` and is gitignored. Sessions are
HS256 JWTs in an httpOnly, SameSite=Lax cookie; state-changing requests also
have to echo a CSRF value carried inside the token. Changing a password
invalidates every session already issued for that account.

```bash
./install.sh --admin     create the administrator (turns authentication on)
./install.sh --check     among other things, reports whether auth is configured
```

Lost the admin password? Delete `key.json` and run `./install.sh --admin`.
That resets accounts only; scans are untouched.

### What an administrator can set per account

| Setting | Effect |
|---------|--------|
| Scans per day | Refused past this many starts in a UTC day. `0` = unlimited |
| Scans at once | How many of their scans may run concurrently. `0` = unlimited |
| See every account's scans | Off: the library and every scan URL show only their own runs |
| Delete scans | Whether they may remove a scan from the library |
| Port scan / Tor / web archive / deep DNS | Whether each option is available to them at all |

## The toolchain

Argus is an orchestrator. These are the external tools it drives, and when.
Findings are tagged in the UI with a short source code instead of a tool name,
so an exported scan does not disclose the toolchain; the mapping is here.

| Tool | Code | Stage | What it does | If missing |
|------|------|-------|--------------|------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `n` | 1 · subdomains | Fast passive name enumeration, the first pass | crt.sh + DNS brute cover it |
| [bbot](https://github.com/blacklanternsecurity/bbot) | `b` | 1 · subdomains | The deep passive sweep behind subfinder | quick pass only, fewer hosts |
| crt.sh | `c` | 1 · subdomains | Certificate transparency logs | skipped |
| [SecurityTrails](https://securitytrails.com) | `s` | 1 · subdomains + DNS | Deep DNS: larger host set, full current DNS, historical DNS | option locked (needs a key) |
| [dnsx](https://github.com/projectdiscovery/dnsx) | `r` | 1 · resolve | Bulk resolution of every candidate host | slower Python resolver |
| [httpx](https://github.com/projectdiscovery/httpx) | `h` | 2 · probe | Mass HTTP probe: which hosts are live, on which scheme | each stage probes for itself, slower |
| [nmap](https://nmap.org) | `p` | 2a · port scan | Aggressive service/version, OS guess, default scripts, traceroute, aimed at the discovered open ports | port-scan toggle stays locked |
| [naabu](https://github.com/projectdiscovery/naabu) / [masscan](https://github.com/robertdavidgraham/masscan) | `p` | 2a · port scan | Fast full-range discovery, so nmap version-scans every open port, not just the top 1000 | nmap connect sweep does the discovery |
| [cdncheck](https://github.com/projectdiscovery/cdncheck) | `p` | 2a · port scan | Flags CDN/WAF/cloud edge IPs so their ports read as the edge's, not the origin's | header-based edge detection in the HTTP review |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | `W` | 2a + 3 · fingerprint | Tech stack per host, and per non-standard web port | no tech tags |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | `y` | 2b · web archive | URLs the domain used to serve, from the internet archive | the archive's CDX index over HTTP is used instead |
| [katana](https://github.com/projectdiscovery/katana) | `k` | 4 · deep crawl | JS-aware discovery: bundled routes, lazy chunks, runtime XHR targets | built-in crawler runs alone |
| built-in crawler | `crawler` | 5 · crawl | Fetches bodies, extracts forms and fields, maps buttons to requests | — |
| built-in JS parser | `js` | 5 · crawl | Deep asset read: endpoints, secrets, GraphQL / WebSocket / OAuth, source maps, cloud refs (AWS / Azure / GCP / Firebase), internal IPs, analytics IDs, TODO / FIXME, parameters | — |
| built-in HTTP review | `H` | 3b · http review | Security headers, cookies, CORS, methods (TRACE / OPTIONS), server fingerprint, CDN / WAF from headers | — |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | `H` | 3b · http review | Names the WAF in front of a host | header signatures still detect common edges |
| built-in TLS review | `T` | 3b · tls review | TLS versions, cipher, full certificate (issuer / SAN / expiry), weak-protocol probe | — |
| built-in bypass probe | `x` | 6b · bypass | Replays 401 / 403 with path / header / method tricks to find front-door-only access control | — |
| [arjun](https://github.com/s0md3v/Arjun) | `A` | 6c · params | Hidden query / body parameter discovery on the interesting endpoints | JS-extracted parameters only |
| [ffuf](https://github.com/ffuf/ffuf) or [feroxbuster](https://github.com/epi052/feroxbuster) | `f` | 6 · bruteforce | Content discovery against a calibrated per-host baseline | no bruteforce stage |
| [ipinfo.io](https://ipinfo.io) | `i` | 7 · enrich | Provider, ASN, country, hosting-or-not per IP | IPs stay bare |
| [Shodan](https://www.shodan.io) / [InternetDB](https://internetdb.shodan.io) | `S` | 7b · passive intel | Passive host intel: ports, banners, CVEs, CPEs, TLS / JA3, hashes, org / ASN / geo, tags · merged into the IP records and findings | InternetDB (free, no key) when there is no Shodan key |
| [tor](https://www.torproject.org) + torsocks | — | 0 · transport | Routes the entire scan through Tor | Tor toggle stays locked |
| [kuzu](https://kuzudb.com) (or Neo4j) | — | 10 · graph | Stores the scan graph for querying | graph still renders from the JSON |

`./install.sh` installs all of these. `./install.sh --check` reports which are
present and what degrades without each.

## Scanning settings

Everything below is on the launcher at the top of the dashboard. The four
toggles are in the bar; the rest are behind **Options**.

### Toggles

| Toggle | Default | What it does |
|--------|---------|--------------|
| **deep DNS** | off | Larger subdomain set, full current DNS records, and historical DNS (previous IPs, name servers, MX, with dates). Needs an API key. If the key's monthly allowance is spent, the launcher says so before the scan starts and offers: run without it, or paste another key |
| **passive** | off | Passive enumeration only. Nothing is sent to the target, and passive host intelligence (Shodan with a key, else the free InternetDB) is folded into the results. Rules out the port scan and the active HTTP/TLS/bypass reviews |
| **via Tor** | off | Routes every request, name lookup and external tool through Tor. If a circuit cannot be established the scan aborts rather than falling back to a direct connection |
| **port scan** | off | Scans every discovered IP for open ports and services, fingerprints each open web port, and hands non-standard web ports (`:8080`, `:8443`) to the crawler as seeds. Slow, and it touches infrastructure directly |
| **web archive** | off | Mines the internet archive for URLs this domain used to serve: retired admin panels, old API versions, files published then deleted. Sends nothing to the target. What it finds is re-checked by the crawler |

### Scope

| Scope | What counts as the target |
|-------|---------------------------|
| **Apex + subdomains** (default) | A subdomain target pivots to its apex, so the whole estate is enumerated |
| **Host + subdomains** | The host is taken literally; its own subdomains are still enumerated |
| **Single host** | This host and nothing else. No subdomain enumeration; anything off-host is recorded but never followed |

### Crawl limits

| Setting | Default | Meaning |
|---------|---------|---------|
| Max pages per host | 600 | Cap on pages the crawler fetches per host |
| Max depth | 6 | How far from a seed the crawler will follow links |
| skip passive-enum engine | off | Skip the deep sweep; use the quick pass + certificate transparency + DNS brute. No effect in single-host mode |

### Pipeline stages

Every stage runs by default; switch one off to skip it.

| Stage | What you lose by skipping it |
|-------|------------------------------|
| `subdomains` | Host enumeration. Only the target itself is resolved |
| `fingerprint` | Tech-stack tags on hosts and ports |
| `http_analysis` | The HTTP security review (headers, cookies, CORS, methods, CDN/WAF). Active scans only |
| `tls` | The TLS/certificate review (versions, ciphers, expiry, weak protocols). Active scans only |
| `crawl` | Endpoints, forms, fields, JS analysis, secrets · the bulk of a scan |
| `bruteforce` | Content discovery of unlinked paths and files |
| `bypass` | The 401/403 access-control bypass probe. Active scans only |
| `paramscan` | Hidden-parameter discovery (arjun). Active scans only |
| `ip_enrich` | Provider, ASN, country and hosting classification per IP |
| `shodan` | Passive host intelligence (Shodan / InternetDB) merged into the IP records and findings. Passive scans only |
| `classify` | Field-intent tagging (credentials, PII, tokens, IDOR, SSRF, …) |
| `graph` | The scan is not loaded into the graph database. The graph view still renders from the JSON |

Every stage feeds one ranked **Findings** list: each finding carries a severity,
a confidence score, the raw and parsed evidence, its source, a plain-language
risk and recommendation, and is deduplicated so the same issue seen by two tools
becomes one entry.

## Reading a scan

The left panel is the estate; the graph is its shape; the table is every
request. Each panel section has its own filter: subdomains by response code,
infrastructure by announcing AS, tech stack by fingerprint, secrets by
severity, discovered files by kind and by response code.

The graph shows at most **100 children of one type per parent**. Beyond that a
`+N more` marker appears; clicking it opens the next hundred, and it retires
when the last batch has been loaded. Endpoint, request, field, JS and file
layers stay hidden until a single subdomain is selected · pick one from the
host filter or click it in the graph. Two renderers are available behind the
**1** / **2** switch: the built-in canvas engine, and Cytoscape with the fCoSE
layout.

A large scan's graph is built in the background: the page shows
"Building graph…" and picks it up when it is ready, however long that takes.

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
| `ARGUS_KEY_FILE` | `./key.json` | account store location |
| `ARGUS_TOKEN_TTL` | `43200` | session lifetime in seconds |
| `ARGUS_ACCESS_LOG` | `1` | set `0` to disable the dashboard access log |
| `ARGUS_WAYBACK_MAX_URLS` | `25000` | ceiling on archived URLs ingested per scan |
| `ARGUS_GRAPH_VIEW_NODES` | `6000` | node budget for one graph response |

## Notes

- This tool crawls and bruteforces actively. Get permission first.
- Missing optional tools degrade speed, not capability.
- A JSON access log of dashboard visitors is written under `scans/.access/`,
  naming the account behind each request. The admin area reads it back.
- Secrets in `.env` and accounts in `key.json` are gitignored and never leave
  the machine.
