"""
Central configuration for Argus Recon.

Everything tunable lives here: filesystem paths, network behaviour, the external
tool commands each module shells out to, and the pattern libraries used by the
field-intent classifier and the JS secret scanner. Modules import from here so
there is a single place to adjust behaviour.
"""
from __future__ import annotations

import os
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    """int() an environment value, but treat empty or non-numeric as unset.

    A bare `ARGUS_WEB_PORT=` in .env or a systemd unit (or an exported-but-empty
    variable) used to make `int("")` raise at import time · which takes the whole
    app, and every `import config`, down with it. Tolerate it instead.
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = ROOT / "scans"
WORDLISTS_DIR = ROOT / "wordlists"
WEB_DIR = ROOT / "web"
ENV_FILE = ROOT / ".env"

SCANS_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)

# Built graph payloads are cached here (keyed by the scan file's mtime) so the
# one-off cost of building a huge scan's graph is paid once and survives a
# restart · a later view of the same scan is served straight from disk.
GRAPHCACHE_DIR = SCANS_DIR / ".graphcache"


# --------------------------------------------------------------------------- #
# .env · minimal loader (no external dependency). Keys already present in the
# real environment win; the file only fills what is unset.
# --------------------------------------------------------------------------- #
def load_env(path: Path = ENV_FILE) -> dict:
    values: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            values[key] = val
            os.environ.setdefault(key, val)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return values


def save_env_key(key: str, value: str, path: Path = ENV_FILE) -> None:
    """Write/replace a single KEY=value line in .env, preserving the rest."""
    value = (value or "").strip()
    lines: list[str] = []
    found = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    out: list[str] = []
    for line in lines:
        if line.strip().startswith(f"{key}=") or line.strip().startswith(f"{key} ="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    path.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
    os.environ[key] = value


_ENV = load_env()

# --------------------------------------------------------------------------- #
# External tool commands (overridable via environment)
# --------------------------------------------------------------------------- #
BBOT_BIN = os.environ.get("ARGUS_BBOT", "bbot")
WHATWEB_BIN = os.environ.get("ARGUS_WHATWEB", "whatweb")
FFUF_BIN = os.environ.get("ARGUS_FFUF", "ffuf")
FEROX_BIN = os.environ.get("ARGUS_FEROX", "feroxbuster")
TOR_BIN = os.environ.get("ARGUS_TOR", "tor")
TORSOCKS_BIN = os.environ.get("ARGUS_TORSOCKS", "torsocks")
PORTSCAN_BIN = os.environ.get("ARGUS_PORTSCAN", "nmap")
WAYBACK_BIN = os.environ.get("ARGUS_WAYBACK", "waybackurls")

# --------------------------------------------------------------------------- #
# Go recon binaries. These run the wide, fan-out heavy passes (name enum, mass
# HTTP probing, JS-aware crawling, bulk resolution) that a synchronous Python
# stage cannot keep up with, and each one has a Python fallback so a missing
# binary degrades the pipeline instead of breaking it.
#
# `httpx` is ambiguous on purpose-built boxes: Kali ships python3-httpx, whose
# CLI is also called `httpx` and answers on PATH before anything in ~/go/bin. So
# candidate names are probed *and validated* (util.resolve_recon_tool runs
# `-version` and checks the answer) rather than trusted by name.
# --------------------------------------------------------------------------- #
SUBFINDER_BIN = os.environ.get("ARGUS_SUBFINDER", "subfinder")
HTTPX_BIN = os.environ.get("ARGUS_HTTPX", "httpx")
KATANA_BIN = os.environ.get("ARGUS_KATANA", "katana")
DNSX_BIN = os.environ.get("ARGUS_DNSX", "dnsx")
# Alternative names the same tool is installed under (Kali packages, our own
# installer's collision-free symlink).
TOOL_ALIASES = {
    "httpx": ["httpx-pd", "httpx-toolkit"],
    "subfinder": ["subfinder-pd"],
    "katana": ["katana-pd"],
    "dnsx": ["dnsx-pd"],
}

# --------------------------------------------------------------------------- #
# Port scan (module 7a, source code "p")
#
# Off by default: it is the one stage that touches the target's infrastructure
# rather than its web surface, it is slow, and it is loud. The dashboard exposes
# it as an explicit toggle next to "Via Tor" for exactly that reason.
#
# The aggressive profile is the point of the feature · service/version detection,
# OS inference, the default script set and a traceroute · so PORTSCAN_ARGS is not
# something to trim without also changing what the Infrastructure panel can show.
# --------------------------------------------------------------------------- #
PORTSCAN_ARGS = [a for a in os.environ.get("ARGUS_PORTSCAN_ARGS", "-T4 -A").split() if a]
# Per-target ceiling. An -A scan of one address is minutes, not seconds, and a
# scope with 40 addresses must not turn a scan into an overnight job.
PORTSCAN_TIMEOUT = _int_env("ARGUS_PORTSCAN_TIMEOUT", 600)
# Addresses scanned in one run, most-connected first. 0 = no limit.
PORTSCAN_MAX_TARGETS = _int_env("ARGUS_PORTSCAN_MAX_TARGETS", 25)
# How many addresses are scanned at once.
PORTSCAN_PARALLEL = _int_env("ARGUS_PORTSCAN_PARALLEL", 3)
# Open HTTP(S) ports found off the standard 80/443 are handed to the crawler as
# extra seeds · an admin panel on :8443 is exactly what this stage is for.
PORTSCAN_SEED_CRAWL = os.environ.get("ARGUS_PORTSCAN_SEED_CRAWL", "1") != "0"

# --- mass HTTP probe (httpx) ------------------------------------------------ #
PROBE_THREADS = _int_env("ARGUS_PROBE_THREADS", 150)
PROBE_RATE = _int_env("ARGUS_PROBE_RATE", 300)       # requests/sec cap
PROBE_TIMEOUT = _int_env("ARGUS_PROBE_TIMEOUT", 8)   # per request
PROBE_RETRIES = _int_env("ARGUS_PROBE_RETRIES", 1)
PROBE_MAXTIME = _int_env("ARGUS_PROBE_MAXTIME", 600) # whole batch

# --- deep crawl (katana) --------------------------------------------------- #
KATANA_DEPTH = _int_env("ARGUS_KATANA_DEPTH", 3)
KATANA_CONCURRENCY = _int_env("ARGUS_KATANA_CONCURRENCY", 20)
KATANA_PARALLEL = _int_env("ARGUS_KATANA_PARALLEL", 10)  # hosts at once
KATANA_RATE = _int_env("ARGUS_KATANA_RATE", 150)
KATANA_TIMEOUT = _int_env("ARGUS_KATANA_TIMEOUT", 900)  # whole run
# Headless rendering finds routes a static fetch never sees (SPA routers, lazy
# chunks) but needs a Chromium and far more RAM, so it is opt-in.
KATANA_HEADLESS = os.environ.get("ARGUS_KATANA_HEADLESS", "0") == "1"

# --- bulk resolver (dnsx) -------------------------------------------------- #
DNSX_THREADS = _int_env("ARGUS_DNSX_THREADS", 200)
DNSX_TIMEOUT = _int_env("ARGUS_DNSX_TIMEOUT", 300)

# --------------------------------------------------------------------------- #
# Wayback Machine archive mining (module 3b, source code "y")
#
# Opt-in, like the port scan and Tor: it is a different kind of pass. Nothing is
# sent to the target at all · the URLs come from what the internet archive
# recorded over the years, which is exactly where retired admin panels, old API
# versions and published-then-deleted backups still show up.
#
# Two paths: the `waybackurls` binary when it is installed (it also folds in the
# Common Crawl index), else the archive's CDX API over plain HTTP · so the stage
# always contributes something.
# --------------------------------------------------------------------------- #
WAYBACK_CDX_URL = os.environ.get("ARGUS_WAYBACK_CDX",
                                 "https://web.archive.org/cdx/search/cdx")
WAYBACK_TIMEOUT = _int_env("ARGUS_WAYBACK_TIMEOUT", 300)
# Ceiling on URLs ingested per run. The archive can hold hundreds of thousands
# of rows for a large estate, and every one becomes an endpoint record.
WAYBACK_MAX_URLS = _int_env("ARGUS_WAYBACK_MAX_URLS", 25000)
# Rows requested per CDX query (the API's own `limit`).
WAYBACK_CDX_LIMIT = _int_env("ARGUS_WAYBACK_CDX_LIMIT", 20000)

# --- passive name enum (subfinder) ----------------------------------------- #
SUBFINDER_TIMEOUT = _int_env("ARGUS_SUBFINDER_TIMEOUT", 180)
# -all queries every configured source (slower, wider). Off by default so the
# quick first pass stays quick; BBOT is the deep sweep behind it.
SUBFINDER_ALL = os.environ.get("ARGUS_SUBFINDER_ALL", "0") == "1"

# --------------------------------------------------------------------------- #
# Network behaviour
# --------------------------------------------------------------------------- #
USER_AGENT = os.environ.get(
    "ARGUS_UA",
    "Mozilla/5.0 (X11; Linux x86_64) ArgusRecon/1.0 (+https://localhost)",
)
HTTP_TIMEOUT = _int_env("ARGUS_HTTP_TIMEOUT", 12)
CRAWL_THREADS = _int_env("ARGUS_CRAWL_THREADS", 12)
CRAWL_MAX_PAGES = _int_env("ARGUS_CRAWL_MAX_PAGES", 600)   # per subdomain safety cap
CRAWL_MAX_DEPTH = _int_env("ARGUS_CRAWL_MAX_DEPTH", 6)

# The crawler's HTTP layer is asyncio (modules.asynchttp, an httpx.AsyncClient
# behind a semaphore) rather than one thread per request, so concurrency is
# bounded by these numbers instead of by the thread pool. CRAWL_THREADS stays as
# the fallback pool size for the synchronous path and as the default fan-out for
# other modules.
CRAWL_CONCURRENCY = _int_env("ARGUS_CRAWL_CONCURRENCY", 80)   # in-flight requests
CRAWL_HOST_CONCURRENCY = _int_env("ARGUS_CRAWL_HOST_CONCURRENCY", 12)  # per host
# Parsing is CPU work; bodies above this size are handed to a worker thread so a
# single huge bundle cannot stall the event loop.
PARSE_OFFLOAD_BYTES = _int_env("ARGUS_PARSE_OFFLOAD_BYTES", 60000)
MAX_JS_BYTES = _int_env("ARGUS_MAX_JS_BYTES", 3000000)     # skip huge bundles above this
MAX_BODY_STORE = _int_env("ARGUS_MAX_BODY_STORE", 20000)   # chars of response body kept in JSON

VERIFY_TLS = os.environ.get("ARGUS_VERIFY_TLS", "0") == "1"             # recon targets often have bad certs

# --------------------------------------------------------------------------- #
# Tor transport · set at runtime by modules.tor.connect() and read by
# util.make_session() (HTTP) and subdomain (name resolution). Nothing here is a
# preference: while TOR_ACTIVE is true every request must go through the proxy,
# so the flags live in one place instead of being threaded through call sites.
# --------------------------------------------------------------------------- #
TOR_SOCKS_HOST = os.environ.get("ARGUS_TOR_HOST", "127.0.0.1")
TOR_SOCKS_PORT = _int_env("ARGUS_TOR_PORT", 9050)
TOR_BOOTSTRAP_TIMEOUT = _int_env("ARGUS_TOR_BOOTSTRAP", 180)
TOR_ACTIVE = False          # the scan is running over Tor
HTTP_PROXY: str | None = None   # e.g. "socks5h://127.0.0.1:9050"
# DNS-over-HTTPS resolvers used instead of UDP DNS while Tor is active (a UDP
# resolver would bypass the proxy and leak every hostname we look up).
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]
# Plain resolvers used when Tor is off.
DNS_NAMESERVERS = [s for s in os.environ.get(
    "ARGUS_DNS", "1.1.1.1,8.8.8.8,9.9.9.9").split(",") if s.strip()]

# ipinfo.io token is optional; without one the free tier still returns core fields.
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "").strip()

# --------------------------------------------------------------------------- #
# SecurityTrails · deep DNS / subdomain / historical-DNS source (module "s").
# The key is read from the environment / .env (SECURITYTRAILS_KEY). Without a
# key, "Deep" mode is unavailable and the tool relies on the local resolver +
# the other passive sources only.
# --------------------------------------------------------------------------- #
SECURITYTRAILS_KEY = os.environ.get("SECURITYTRAILS_KEY", "").strip()
SECURITYTRAILS_BASE = os.environ.get("SECURITYTRAILS_BASE",
                                     "https://api.securitytrails.com/v1")
# Historical DNS record types we pull the timeline for (deep mode).
DNS_HISTORY_TYPES = ["a", "aaaa", "mx", "ns", "soa", "txt"]
# Record types resolved locally (always, even without a key) for the DNS panel.
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]

# --------------------------------------------------------------------------- #
# Source codes · findings are tagged with a short code rather than the real tool
# name so the dashboard / exported JSON do not disclose the toolchain. The real
# names live only in the README. (own components keep readable names)
# --------------------------------------------------------------------------- #
SOURCE_CODES = {
    "bbot": "b",            # subdomain / infra engine
    "whatweb": "W",         # tech fingerprint
    "ffuf": "f",            # content bruteforce
    "securitytrails": "s",  # deep DNS / history
    "crtsh": "c",           # certificate transparency
    "ipinfo": "i",          # IP enrichment
    "subfinder": "n",       # fast passive name enum
    "httpx": "h",           # mass HTTP probe
    "katana": "k",          # JS-aware deep crawl engine
    "dnsx": "r",            # bulk resolver
    "portscan": "p",        # port / service scan
    "wayback": "y",         # web archive mining
}
# Human labels for the dashboard legend (still no real tool names).
SOURCE_LABELS = {
    "b": "passive enum",
    "W": "fingerprint",
    "f": "content brute",
    "s": "deep DNS",
    "c": "cert transparency",
    "i": "IP enrichment",
    "n": "passive names",
    "h": "http probe",
    "k": "deep crawl",
    "r": "bulk DNS",
    "p": "port scan",
    "y": "web archive",
    "crawler": "crawler",
    "js": "JS analysis",
    "robots": "robots.txt",
    "sitemap": "sitemap.xml",
    "seed": "seed",
    "input": "target input",
    "dns": "DNS resolver",
    "dns-brute": "DNS brute",
}

# Graph: above this node count the dashboard defers physics until the user
# activates it (module 6 in the fix list).
GRAPH_LAZY_THRESHOLD = _int_env("ARGUS_GRAPH_LAZY", 500)

# --------------------------------------------------------------------------- #
# Graph storage
#
# Neo4j is a server you have to run; for a single-user local tool that is the
# heaviest part of the stack. `kuzu` is an embedded graph database (SQLite's
# deployment model, Cypher's query language) that needs no process at all, so it
# is the default when it is installed.
#
#   ARGUS_GRAPH_BACKEND = auto | neo4j | kuzu | none
#     auto  -> neo4j if it answers, else kuzu if importable, else none
#              (the dashboard graph always renders from the scan JSON regardless)
# --------------------------------------------------------------------------- #
GRAPH_BACKEND = os.environ.get("ARGUS_GRAPH_BACKEND", "auto").strip().lower()

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "argusrecon")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")

# Embedded graph DB directory (kuzu). One database, every scan tagged by scan_id.
KUZU_DIR = Path(os.environ.get("ARGUS_KUZU_DIR", str(ROOT / "scans" / ".kuzu")))

# --------------------------------------------------------------------------- #
# Graph *view* budget
#
# The backend stores every node of a scan; the browser must not be handed every
# node of a scan. A 46k-endpoint scan expands to ~67k nodes / ~218k edges, which
# is a 30 MB response the tab then has to turn into 67k objects, 218k edges and a
# 67k-entry adjacency map before it can paint a single pixel · the page just sits
# there empty. These caps bound what the dashboard is served; the response still
# reports the true totals (stats.totals) so the legend shows the real size of the
# surface, and ?limit= raises the cap for anyone who wants the whole thing.
# --------------------------------------------------------------------------- #
GRAPH_VIEW_NODES = _int_env("ARGUS_GRAPH_VIEW_NODES", 6000)
GRAPH_VIEW_EDGES = _int_env("ARGUS_GRAPH_VIEW_EDGES", 14000)
# Hard ceiling for an explicit ?limit= · past this the browser stalls no matter
# what the caller asked for.
GRAPH_VIEW_MAX = _int_env("ARGUS_GRAPH_VIEW_MAX", 40000)

# When a graph must be built from the scan file itself (no graph DB, no cached
# rows in the store), stop reading the endpoints array after this many records.
# The graph only ever renders GRAPH_VIEW_NODES of them, so reading a million to
# pick a few thousand is pure latency · a bounded prefix keeps the first view of
# a gigabyte scan under a few seconds. stats.totals still reports the real size
# (it comes from meta), and the cut is flagged truncated.
GRAPH_SCAN_CAP = _int_env("ARGUS_GRAPH_SCAN_CAP", 120000)

# --------------------------------------------------------------------------- #
# SQLite job/cache store (modules.store)
#
# Sits in front of the graph backend and the JSON files: stage checkpoints, the
# per-endpoint index the dashboard expands rows from, home-page summaries, and
# the graph-load queue (so a scan finished while Neo4j/kuzu was down is still
# loaded later instead of lost). WAL mode is what lets the engine write while
# the dashboard reads the same file.
# --------------------------------------------------------------------------- #
STORE_DB = Path(os.environ.get("ARGUS_STORE_DB", str(ROOT / "scans" / ".argus.db")))
STORE_ENABLED = os.environ.get("ARGUS_STORE", "1") != "0"

# --------------------------------------------------------------------------- #
# Web dashboard
# --------------------------------------------------------------------------- #
WEB_HOST = os.environ.get("ARGUS_WEB_HOST", "127.0.0.1")
WEB_PORT = _int_env("ARGUS_WEB_PORT", 7666)

# Above this on-disk size a scan document is never parsed whole into the web
# process's heap. json.load() of a gigabyte of JSON builds several gigabytes of
# Python objects, and doing that per request (raw view, home-page summary, an
# expanded row, a graph build) is what let one huge scan exhaust memory and take
# the dashboard down with 502s for everyone. At or above this size the server
# reads only what a view needs straight off disk with a streaming parser
# (modules.scan_stream). 0 disables the guard (always parse in memory).
INMEM_MAX_BYTES = _int_env("ARGUS_INMEM_MAX_MB", 100) * 1024 * 1024

# The scan page renders its request table from the endpoints the /view response
# carries. A deep crawl holds over a million · serialising them all is a ~400 MB
# response no browser can lay out, and is why a big scan's page "never loaded".
# The page is served the highest-priority slice up to this cap (classified
# requests, forms, JS and fielded endpoints first); the response still reports
# the true endpoint total so the header shows the real surface, and the table
# says it is a top-N view. 0 means no cap (old behaviour).
VIEW_ENDPOINT_CAP = _int_env("ARGUS_VIEW_ENDPOINT_CAP", 8000)

# --------------------------------------------------------------------------- #
# Accounts / access control (modules.auth)
#
# The dashboard is no longer implicitly trusted just because it is bound to
# loopback: once it is published behind a proxy, "anyone who can reach the port"
# is the whole internet. `key.json` holds the account store · the admin created
# at install time, any operators they add, each one's scan allowance, and the
# signing secret for the session tokens.
#
# No file, no accounts: the dashboard runs open (a fresh checkout that has not
# been through ./install.sh yet). The moment the file exists, every page and
# every API route requires a signed token.
# --------------------------------------------------------------------------- #
KEY_FILE = Path(os.environ.get("ARGUS_KEY_FILE", str(ROOT / "key.json")))
# How long a session token stays valid. Short enough that a leaked token expires,
# long enough that a running scan does not log you out mid-way.
AUTH_TOKEN_TTL = _int_env("ARGUS_TOKEN_TTL", 12 * 3600)
# Failed sign-ins tolerated per account before it is locked out, and for how long.
AUTH_MAX_FAILURES = _int_env("ARGUS_AUTH_MAX_FAILURES", 8)
AUTH_LOCKOUT_SEC = _int_env("ARGUS_AUTH_LOCKOUT", 900)
# PBKDF2 rounds for stored password hashes.
AUTH_HASH_ROUNDS = _int_env("ARGUS_AUTH_ROUNDS", 240_000)
# Default allowance for a newly created operator account (the admin can change
# it per user). 0 = unlimited.
AUTH_DEFAULT_DAILY_SCANS = _int_env("ARGUS_DEFAULT_DAILY_SCANS", 10)
AUTH_DEFAULT_CONCURRENT = _int_env("ARGUS_DEFAULT_CONCURRENT", 1)

# --------------------------------------------------------------------------- #
# Bruteforce
# --------------------------------------------------------------------------- #
# Standard extension set the spec calls for, always appended to the generated list.
BRUTE_EXTENSIONS = ["xml", "json", "conf", "bak", "env", "sql", "yml"]
BRUTE_THREADS = _int_env("ARGUS_BRUTE_THREADS", 40)
# Requests per second. Unbounded fan-out gets a scanner rate-limited (429s and
# tarpits that look like hits), which costs more time than it saves.
BRUTE_RATE = _int_env("ARGUS_BRUTE_RATE", 180)

# Matching strategy: take *every* status code and subtract the noise instead of
# listing the codes we like. A soft-404 answers 200, so a status allow-list keeps
# it while `-mc all` plus a size/regex filter drops it · the classifier then only
# ever sees responses that differ from the host's own catch-all.
BRUTE_MATCH_ALL = os.environ.get("ARGUS_BRUTE_MATCH_ALL", "1") != "0"
# Codes never worth a row even under -mc all.
BRUTE_STATUS_FILTER = os.environ.get("ARGUS_BRUTE_FC", "404,429,502,503,504")
# Fallback allow-list, used when -mc all is switched off.
BRUTE_STATUS_MATCH = os.environ.get("ARGUS_BRUTE_STATUS", "200,204,301,302,307,401,403,405,500")
# Response sizes to drop, measured per host before the run (the catch-all page)
# and merged with anything set here (comma list, ffuf -fs syntax).
BRUTE_FILTER_SIZES = os.environ.get("ARGUS_BRUTE_FS", "").strip()
# How many random paths are requested to learn a host's catch-all size/body.
BRUTE_CALIBRATE_PROBES = _int_env("ARGUS_BRUTE_CALIBRATE", 3)

# A compact, stack-agnostic base list. Stack-specific paths are added at runtime
# by bruteforce.generate_wordlist() based on the fingerprint.
BASE_WORDS = [
    "admin", "administrator", "login", "logout", "signin", "signup", "register",
    "dashboard", "panel", "api", "api/v1", "api/v2", "graphql", "app", "assets",
    "static", "public", "uploads", "upload", "files", "images", "img", "css", "js",
    "config", "configuration", "settings", "setup", "install", "installer",
    "backup", "backups", "old", "new", "test", "testing", "dev", "development",
    "staging", "stage", "prod", "production", "tmp", "temp", "cache", "logs", "log",
    "debug", "status", "health", "healthz", "metrics", "actuator", "server-status",
    "phpinfo", "info", "server-info", "console", "shell", "cmd", "internal",
    "private", "secret", "secrets", "hidden", "db", "database", "sql", "dump",
    "user", "users", "account", "accounts", "profile", "auth", "oauth", "sso",
    "token", "reset", "forgot", "password", "vendor", "node_modules", "cgi-bin",
    "wp-admin", "wp-content", "wp-login.php", "robots.txt", "sitemap.xml",
    ".git", ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    ".svn", ".htaccess", ".htpasswd", ".DS_Store", "docker-compose.yml",
    "Dockerfile", "package.json", "composer.json", "web.config", "crossdomain.xml",
    ".well-known/security.txt", "swagger", "swagger.json", "swagger-ui",
    "openapi.json", "api-docs", "readme", "README.md", "changelog", "CHANGELOG.md",
]

# Stack-specific paths keyed by tokens that may appear in the WhatWeb fingerprint.
STACK_WORDLISTS = {
    "wordpress": [
        "wp-admin/", "wp-login.php", "wp-content/", "wp-includes/",
        "wp-config.php", "wp-config.php.bak", "wp-json/", "wp-json/wp/v2/users",
        "xmlrpc.php", "wp-cron.php", "wp-content/debug.log",
        "wp-content/uploads/", "wp-admin/install.php", "wp-admin/setup-config.php",
    ],
    "drupal": [
        "user/login", "admin/", "?q=user", "CHANGELOG.txt", "core/CHANGELOG.txt",
        "sites/default/settings.php", "sites/default/files/", "update.php",
        "install.php", "web.config", "core/install.php",
    ],
    "joomla": [
        "administrator/", "configuration.php", "configuration.php-dist",
        "administrator/manifests/files/joomla.xml", "htaccess.txt", "web.config.txt",
    ],
    "laravel": [
        ".env", ".env.example", "storage/logs/laravel.log", "telescope/",
        "_ignition/health-check", "artisan", "vendor/", "public/",
        "storage/framework/", "config/app.php",
    ],
    "symfony": [
        "app_dev.php", "_profiler/", "config.php", "app/config/parameters.yml",
        ".env", "web/app_dev.php", "web/config.php", "bin/console",
    ],
    "django": [
        "admin/", "static/admin/", "__debug__/", "api/", "media/",
        "settings.py", ".env", "manage.py",
    ],
    "flask": [
        "console", "debug", ".env", "config.py", "app.py", "static/",
    ],
    "rails": [
        "rails/info/properties", "rails/info/routes", "config/database.yml",
        "config/secrets.yml", "config/master.key", "assets/", ".env",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/env", "actuator/mappings",
        "actuator/heapdump", "actuator/beans", "actuator/httptrace",
        "swagger-ui.html", "v2/api-docs", "v3/api-docs",
    ],
    "express": [
        "api/", "package.json", ".env", "config.js", "server.js", "app.js",
    ],
    "nginx": ["nginx_status", "status", ".well-known/"],
    "apache": ["server-status", "server-info", ".htaccess", ".htpasswd"],
    "iis": ["web.config", "trace.axd", "elmah.axd", "iisstart.htm"],
    "tomcat": ["manager/html", "host-manager/html", "examples/", "docs/"],
    "php": ["phpinfo.php", "info.php", "test.php", "phpmyadmin/", "adminer.php"],
    "jenkins": ["script", "asynchPeople/", "systemInfo", "credentials/"],
    "gitlab": ["users/sign_in", "help", "api/v4/projects", "explore"],
}

# --------------------------------------------------------------------------- #
# Field-intent classifier (module 8) · name substring -> (category, severity)
# Order matters: the first matching pattern wins for a given field name.
# --------------------------------------------------------------------------- #
FIELD_PATTERNS = [
    # (regex substring, category, human label, severity 1-3)
    (r"pass(word|wd|phrase)?|pwd", "credentials", "Password", 3),
    (r"^user(name|_?name|_?id)?$|^uname$|^login$|^acct$", "identity", "Username / login", 2),
    (r"e?[-_]?mail\b|email", "pii", "Email address", 2),
    (r"\botp\b|one[-_]?time|\btotp\b|\bmfa\b|2fa|verif(y|ication)_?code|\bpin\b", "otp", "OTP / MFA code", 3),
    (r"api[-_]?key|apikey|client[-_]?secret|access[-_]?key|secret[-_]?key|private[-_]?key|\bsecret\b", "secret", "API key / secret", 3),
    (r"csrf|xsrf|authenticity[-_]?token|nonce", "csrf", "CSRF token", 1),
    (r"bearer|access[-_]?token|refresh[-_]?token|id[-_]?token|\bjwt\b|session|\bsid\b|auth[-_]?token", "session", "Session / auth token", 3),
    (r"card[-_]?number|\bcvv\b|\bcvc\b|\bccv\b|credit[-_]?card|\bccnum\b|\biban\b|routing|account[-_]?number", "financial", "Payment data", 3),
    (r"\bssn\b|social[-_]?security|passport|national[-_]?id|tax[-_]?id|\bdob\b|birth", "pii", "Sensitive PII", 3),
    (r"phone|\btel\b|mobile|contact[-_]?number", "pii", "Phone number", 2),
    (r"first[-_]?name|last[-_]?name|full[-_]?name|surname|address|street|city|zip|postal|country", "pii", "Personal detail", 1),
    (r"redirect|return[-_]?(url|to)|\bnext\b|callback|continue|\bdest\b|goto|forward", "open-redirect", "Redirect target", 2),
    (r"\bfile\b|filename|filepath|\bpath\b|upload|download|document|attachment", "file-op", "File / path operand", 2),
    (r"is[-_]?admin|\brole\b|privilege|is[-_]?staff|superuser|\bdebug\b|\btest[-_]?mode\b", "privilege", "Privilege / debug flag", 3),
    (r"(user|account|customer|order|invoice|obj(ect)?)[-_]?id$|^id$|^uid$|^gid$", "idor", "Object identifier", 2),
    (r"^q$|search|query|keyword|term", "search", "Search input", 1),
    (r"amount|price|qty|quantity|balance|total", "value", "Numeric value", 1),
    (r"url|uri|link|endpoint|host|domain|server", "ssrf", "URL / host operand", 2),
]

CLASSIFICATION_SEVERITY = {1: "low", 2: "medium", 3: "high"}

# --------------------------------------------------------------------------- #
# Secret scanner patterns for JS (module 5). (name, regex, severity)
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b", "high"),
    ("AWS Secret Access Key", r"(?i)aws.{0,24}?['\"][0-9a-zA-Z/+]{40}['\"]", "high"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high"),
    ("Google OAuth Client ID", r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "medium"),
    ("Firebase URL", r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b", "medium"),
    ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "high"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+", "high"),
    ("Stripe Secret Key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "high"),
    ("Stripe Publishable Key", r"\bpk_live_[0-9a-zA-Z]{24,}\b", "low"),
    ("Stripe Restricted Key", r"\brk_live_[0-9a-zA-Z]{24,}\b", "high"),
    ("GitHub Token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", "high"),
    ("GitLab PAT", r"\bglpat-[0-9A-Za-z_-]{20,}\b", "high"),
    ("SendGrid API Key", r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b", "high"),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("Mailgun API Key", r"\bkey-[0-9a-zA-Z]{32}\b", "high"),
    ("Square Access Token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", "high"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "medium"),
    ("Private Key Block", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) (?:PRIVATE )?KEY-----", "high"),
    ("Basic Auth in URL", r"\bhttps?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "high"),
    # --- additional providers (module 8: strengthen coverage) --------------- #
    ("GitHub OAuth Secret", r"(?i)github.{0,20}?['\"][0-9a-f]{40}['\"]", "high"),
    ("GitHub App Token", r"\b(?:ghs|ghu)_[0-9A-Za-z]{36,}\b", "high"),
    ("Heroku API Key", r"(?i)heroku.{0,20}?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high"),
    ("Mapbox Token", r"\bpk\.eyJ[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}\b", "medium"),
    ("Algolia API Key", r"(?i)algolia.{0,20}?['\"][a-z0-9]{32}['\"]", "medium"),
    ("Facebook Access Token", r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", "high"),
    ("Facebook App Secret", r"(?i)fb.{0,15}?(?:secret|app).{0,15}?['\"][0-9a-f]{32}['\"]", "high"),
    ("Twitter Bearer Token", r"\bAAAAAAAAAA[0-9A-Za-z%]{40,}\b", "medium"),
    ("Cloudinary URL", r"\bcloudinary://[0-9]{10,}:[0-9A-Za-z_-]+@[0-9a-z-]+\b", "high"),
    ("PayPal Braintree Token", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", "high"),
    ("Discord Bot Token", r"\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", "high"),
    ("Discord Webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_-]+", "medium"),
    ("Telegram Bot Token", r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b", "high"),
    ("OpenAI API Key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b", "high"),
    ("Anthropic API Key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "high"),
    ("npm Access Token", r"\bnpm_[0-9A-Za-z]{36}\b", "high"),
    ("PyPI Upload Token", r"\bpypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}\b", "high"),
    ("Postgres/MySQL URI", r"\b(?:postgres(?:ql)?|mysql)://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "high"),
    ("MongoDB URI", r"\bmongodb(?:\+srv)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "high"),
    ("Redis URI", r"\bredis://[^/\s:@]*:[^/\s:@]+@[^/\s]+", "high"),
    ("AMQP URI", r"\bamqps?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "high"),
    ("Authorization Bearer", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/=-]{16,}", "medium"),
    ("Google Service Account", r'"type"\s*:\s*"service_account"', "high"),
    ("Generic Secret Assignment",
     r"(?i)\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|token|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,80}['\"]",
     "medium"),
]
