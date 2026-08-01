"""
Shared helpers: logging, a hardened HTTP session, and URL/scope utilities.

The scope rule from the spec is enforced here in one place · `in_scope()` · so
every module (crawler, parsers, bruteforce, graph) agrees on what "the target
domain and its subdomains" means.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None

from . import config

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
_LEVEL_COLORS = {
    "DEBUG": "\033[38;5;244m",
    "INFO": "\033[38;5;39m",
    "WARNING": "\033[38;5;214m",
    "ERROR": "\033[38;5;196m",
    "OK": "\033[38;5;41m",
}
_RESET = "\033[0m"


class _Formatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = _LEVEL_COLORS.get(record.levelname, "")
        name = record.name.replace("argus.", "")
        return f"{color}[{record.levelname:<5}]{_RESET} \033[38;5;250m{name:<11}{_RESET} {record.getMessage()}"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"argus.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_Formatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


# --------------------------------------------------------------------------- #
# HTTP session
# --------------------------------------------------------------------------- #
def make_session() -> requests.Session:
    """A requests session with retries, a recon UA, and TLS verification off by
    default (recon targets frequently present broken/self-signed certificates).

    This is also where the Tor transport is applied: with `config.HTTP_PROXY` set
    every module that asks for a session gets a proxied one, so "scan over Tor"
    is one decision made once rather than a flag each module has to remember.
    """
    sess = requests.Session()
    sess.headers.update(
        {
            "User-Agent": config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    sess.verify = config.VERIFY_TLS
    if config.HTTP_PROXY:
        sess.proxies = {"http": config.HTTP_PROXY, "https": config.HTTP_PROXY}
        sess.trust_env = False   # no ambient *_proxy env can redirect us elsewhere
    if Retry is not None:
        retry = Retry(
            total=2, connect=2, read=1, backoff_factor=0.4,
            status_forcelist=(502, 503, 504), allowed_methods=frozenset(["GET", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=config.CRAWL_THREADS * 2,
                              pool_maxsize=config.CRAWL_THREADS * 2)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
    if not config.VERIFY_TLS:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return sess


# --------------------------------------------------------------------------- #
# URL / scope helpers
# --------------------------------------------------------------------------- #
def registrable_root(domain: str) -> str:
    """Lower-cased, stripped bare host (no scheme/port/path). Not reduced to
    eTLD+1 · that's `registrable_domain()`."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split("@")[-1].split(":")[0]
    return domain.strip(".")


# Multi-label public suffixes commonly seen in recon targets. Used by the
# heuristic fallback when the `tldextract` package (bundled PSL) is unavailable.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.kr", "or.kr", "go.kr", "ne.kr", "re.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "gob.ar", "org.ar", "edu.ar",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "gen.in", "firm.in", "ind.in",
    "co.za", "org.za", "gov.za", "ac.za", "net.za", "web.za",
    "com.et", "gov.et", "edu.et", "org.et", "net.et", "biz.et", "name.et",
    "com.ng", "gov.ng", "edu.ng", "org.ng", "net.ng",
    "com.eg", "gov.eg", "edu.eg", "org.eg", "net.eg",
    "com.gh", "gov.gh", "edu.gh", "org.gh",
    "co.ke", "or.ke", "go.ke", "ac.ke", "ne.ke",
    "com.tr", "gov.tr", "edu.tr", "org.tr", "net.tr", "web.tr",
    "com.sa", "gov.sa", "edu.sa", "org.sa", "net.sa",
    "com.sg", "edu.sg", "gov.sg", "org.sg", "net.sg",
    "com.my", "gov.my", "edu.my", "org.my", "net.my",
    "com.hk", "gov.hk", "edu.hk", "org.hk", "net.hk",
    "com.tw", "gov.tw", "edu.tw", "org.tw", "net.tw",
    "com.ua", "gov.ua", "edu.ua", "org.ua", "net.ua", "in.ua",
    "com.pl", "gov.pl", "edu.pl", "org.pl", "net.pl",
    "co.il", "org.il", "gov.il", "ac.il", "net.il",
    "com.pk", "gov.pk", "edu.pk", "org.pk", "net.pk",
    "com.bd", "gov.bd", "edu.bd", "org.bd", "net.bd",
    "com.co", "gov.co", "edu.co", "org.co", "net.co",
    "com.ph", "gov.ph", "edu.ph", "org.ph", "net.ph",
    "com.vn", "gov.vn", "edu.vn", "org.vn", "net.vn",
    "com.gt", "gob.gt", "edu.gt", "org.gt",
    "com.pe", "gob.pe", "edu.pe", "org.pe", "net.pe",
}


_TLD_EXTRACTOR = None
_TLD_TRIED = False


def _tld_extract(host: str) -> str | None:
    """eTLD+1 via tldextract's *bundled* PSL snapshot (no network). Returns None
    if the package is unavailable so the heuristic can take over."""
    global _TLD_EXTRACTOR, _TLD_TRIED
    if _TLD_EXTRACTOR is None and not _TLD_TRIED:
        _TLD_TRIED = True
        try:
            import tldextract
            # suffix_list_urls=() => never fetch; use the snapshot shipped in the wheel.
            _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            _TLD_EXTRACTOR = None
    if _TLD_EXTRACTOR is None:
        return None
    try:
        ext = _TLD_EXTRACTOR(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        return None
    return None


def registrable_domain(host: str) -> str:
    """Reduce a host to its registrable domain (eTLD+1).

    `api.staging.example.co.uk` -> `example.co.uk`. Prefers the `tldextract`
    package (bundled Public Suffix List) when present; otherwise uses a
    heuristic covering the common multi-label ccTLDs above.
    """
    host = registrable_root(host)
    if not host or "." not in host:
        return host
    # An IP address is its own "domain".
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return host
    ext = _tld_extract(host)
    if ext:
        return ext
    labels = host.split(".")
    for n in (3, 2):  # try a 3-label suffix (a.b.c) then 2-label (b.c)
        if len(labels) > n and ".".join(labels[-n:]) in _MULTI_SUFFIXES:
            return ".".join(labels[-(n + 1):])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def is_subdomain_of(host: str, domain: str) -> bool:
    host = registrable_root(host)
    domain = registrable_root(domain)
    return bool(host) and host != domain and host.endswith("." + domain)


def host_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
    except Exception:
        return ""
    return netloc.split("@")[-1].split(":")[0].lower()


# Single-target mode ("scan exactly what I gave you"). Process-wide because one
# engine process runs exactly one scan, and because scope has to mean the same
# thing to every module · the crawler, the parsers, the bruteforcer and the
# graph all decide what to follow through `in_scope()`.
_SINGLE_HOST = False


def set_single_host(on: bool) -> None:
    """Restrict `in_scope()` to the exact target host · no subdomains."""
    global _SINGLE_HOST
    _SINGLE_HOST = bool(on)


def single_host() -> bool:
    return _SINGLE_HOST


def in_scope(url: str, domain: str, *, exact: bool | None = None) -> bool:
    """True iff `url`'s host is in scope for this scan.

    Normally that means the target domain or any of its subdomains. In
    single-host mode it means the target host and nothing else.

    This is the single enforcement point for the spec's scope rule.
    """
    host = host_of(url)
    if not host:
        return False
    domain = registrable_root(domain)
    if _SINGLE_HOST if exact is None else exact:
        return host == domain
    return host == domain or host.endswith("." + domain)


def normalize_url(url: str, base: str | None = None) -> str | None:
    """Resolve `url` against `base`, drop the fragment, and canonicalise.

    Returns None for non-HTTP(S) schemes (mailto:, tel:, javascript:, data:).
    """
    if not url:
        return None
    url = url.strip()
    if url.startswith(("mailto:", "tel:", "javascript:", "data:", "#", "sms:", "ftp:", "blob:")):
        return None
    try:
        if base:
            url = urljoin(base, url)
        url, _ = urldefrag(url)
        parts = urlparse(url)
        if parts.scheme not in ("http", "https"):
            return None
        if not parts.netloc:
            return None
        # Normalise: lowercase host, drop default ports, collapse duplicate slashes in path.
        netloc = parts.netloc.lower()
        if netloc.endswith(":80") and parts.scheme == "http":
            netloc = netloc[:-3]
        if netloc.endswith(":443") and parts.scheme == "https":
            netloc = netloc[:-4]
        path = re.sub(r"/{2,}", "/", parts.path) or "/"
        return urlunparse((parts.scheme, netloc, path, parts.params, parts.query, ""))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Content typing
# --------------------------------------------------------------------------- #
_EXT_MAP = {
    "js": ("js", "javascript"), "mjs": ("js", "javascript"), "jsx": ("js", "javascript"),
    "ts": ("js", "typescript"),
    "css": ("style", "stylesheet"),
    "json": ("data", "json"), "xml": ("data", "xml"), "yml": ("data", "yaml"),
    "yaml": ("data", "yaml"), "csv": ("data", "csv"),
    "png": ("image", "image"), "jpg": ("image", "image"), "jpeg": ("image", "image"),
    "gif": ("image", "image"), "svg": ("image", "image"), "ico": ("image", "image"),
    "webp": ("image", "image"), "bmp": ("image", "image"),
    "woff": ("font", "font"), "woff2": ("font", "font"), "ttf": ("font", "font"),
    "eot": ("font", "font"),
    "pdf": ("document", "pdf"), "doc": ("document", "office"), "docx": ("document", "office"),
    "xls": ("document", "office"), "xlsx": ("document", "office"), "ppt": ("document", "office"),
    "txt": ("document", "text"),
    "zip": ("archive", "archive"), "gz": ("archive", "archive"), "tar": ("archive", "archive"),
    "rar": ("archive", "archive"), "7z": ("archive", "archive"),
    "sql": ("backup", "sql"), "bak": ("backup", "backup"), "old": ("backup", "backup"),
    "swp": ("backup", "backup"), "dump": ("backup", "backup"),
    "env": ("config", "env"), "conf": ("config", "config"), "config": ("config", "config"),
    "ini": ("config", "config"), "cfg": ("config", "config"), "pem": ("config", "key"),
    "key": ("config", "key"), "log": ("data", "log"),
    "html": ("page", "html"), "htm": ("page", "html"), "php": ("page", "html"),
    "asp": ("page", "html"), "aspx": ("page", "html"), "jsp": ("page", "html"),
}

_INTERESTING_FILE_KINDS = {"data", "backup", "config", "document", "archive"}


def path_ext(url: str) -> str:
    path = urlparse(url).path
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        return seg.rsplit(".", 1)[-1].lower()
    return ""


def classify_resource(url: str, content_type: str | None = None) -> tuple[str, str]:
    """Return (kind, subtype) e.g. ('js','javascript'), ('backup','sql')."""
    ext = path_ext(url)
    if ext in _EXT_MAP:
        return _EXT_MAP[ext]
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return ("js", "javascript")
    if "css" in ct:
        return ("style", "stylesheet")
    if "json" in ct:
        return ("data", "json")
    if "xml" in ct:
        return ("data", "xml")
    if ct.startswith("image/"):
        return ("image", "image")
    if ct.startswith("font/") or "font" in ct:
        return ("font", "font")
    if "html" in ct:
        return ("page", "html")
    return ("other", ext or "unknown")


def is_javascript(url: str, content_type: str | None = None) -> bool:
    return classify_resource(url, content_type)[0] == "js"


def is_html(content_type: str | None) -> bool:
    return "html" in (content_type or "").lower()


def is_interesting_file(url: str, content_type: str | None = None) -> bool:
    """Discovered-file candidate: config/backup/data/archive/document resources."""
    return classify_resource(url, content_type)[0] in _INTERESTING_FILE_KINDS


def short_hash(*parts: str) -> str:
    h = hashlib.sha1("||".join(p or "" for p in parts).encode("utf-8", "replace"))
    return h.hexdigest()[:16]


# --------------------------------------------------------------------------- #
# External tools
# --------------------------------------------------------------------------- #
_EXTRA_BIN_DIRS = [
    str(Path.home() / ".local" / "bin"),
    str(Path(os.environ.get("GOBIN") or (Path(os.environ.get("GOPATH") or (Path.home() / "go")) / "bin"))),
    "/usr/local/bin", "/usr/bin", "/bin", "/snap/bin",
]


def resolve_tool(name: str) -> str | None:
    """Find an external binary on PATH, falling back to common install dirs
    (BBOT/ffuf frequently land in ~/.local/bin, Go tools in ~/go/bin, and a venv
    drops both from PATH)."""
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_BIN_DIRS:
        cand = Path(d) / name
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def _candidate_paths(name: str, aliases: list[str]) -> list[str]:
    """Every executable that could be `name`, in preference order, de-duplicated."""
    out: list[str] = []
    for n in [name, *aliases]:
        for d in _EXTRA_BIN_DIRS:
            cand = Path(d) / n
            if cand.exists() and os.access(cand, os.X_OK):
                out.append(str(cand))
        which = shutil.which(n)
        if which:
            out.append(which)
    seen, uniq = set(), []
    for p in out:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


# Validated lookups are cached: each miss costs a subprocess, and a module may
# ask for the same tool once per host.
_TOOL_CACHE: dict[str, str | None] = {}


def resolve_recon_tool(name: str, aliases: list[str] | None = None,
                       marker: str = "projectdiscovery") -> str | None:
    """Find a Go recon binary, proving it is the right program before using it.

    `httpx` is the reason this exists: Kali's python3-httpx package installs a
    CLI of the same name into /usr/bin, ahead of ~/go/bin on PATH. Running a
    subdomain list through *that* httpx does nothing useful and the failure looks
    like the probe finding no live hosts. So every candidate is asked for its
    version and only accepted if the answer looks like the real tool (its own
    name, the vendor's domain, or a bare vX.Y.Z).
    """
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]
    result = None
    for path in _candidate_paths(name, aliases or []):
        try:
            proc = subprocess.run([path, "-version"], capture_output=True, text=True,
                                  timeout=8, errors="replace")
        except Exception:
            continue
        blob = f"{proc.stdout}\n{proc.stderr}".lower()
        # A real Go recon tool answers `-version` with an exit-0 banner carrying
        # the vendor name or a bare version. The name alone is not enough · the
        # collision this guards against (python3-httpx vs ProjectDiscovery httpx)
        # is two different programs sharing the name `httpx`, and the impostor
        # exits non-zero here parsing `-version` as bundled short flags.
        if proc.returncode not in (0, None):
            continue
        if marker in blob or re.search(r"\bv\d+\.\d+\.\d+", blob):
            result = path
            break
    _TOOL_CACHE[name] = result
    return result


def clear_tool_cache() -> None:
    _TOOL_CACHE.clear()
    _FLAG_CACHE.clear()


_FLAG_CACHE: dict[str, set[str]] = {}
_FLAG_RX = re.compile(r"(?<![\w-])-([A-Za-z][A-Za-z0-9-]*)")


def tool_flags(bin_path: str) -> set[str]:
    """Every option the binary lists in its own help output.

    These tools rename and retire flags between releases, and an unrecognised
    flag makes them exit instead of ignoring it · so one bad spelling silently
    turns a whole stage off. Asking the binary what it supports (once, cached)
    and only passing what is there costs a single subprocess and makes the
    integration version-proof.
    """
    if bin_path in _FLAG_CACHE:
        return _FLAG_CACHE[bin_path]
    flags: set[str] = set()
    for args in (["-h"], ["--help"]):
        try:
            proc = subprocess.run([bin_path, *args], capture_output=True, text=True,
                                  timeout=15, errors="replace")
        except Exception:
            continue
        text = f"{proc.stdout}\n{proc.stderr}"
        if text.strip():
            flags = {m.group(1) for m in _FLAG_RX.finditer(text)}
            if flags:
                break
    _FLAG_CACHE[bin_path] = flags
    return flags


def pick_flag(flags: set[str], *candidates: str) -> str | None:
    """First candidate spelling the binary actually supports ('-sc', '-status-code'
    …). Returns None when none of them are, so the caller can drop the option.

    An empty flag set means help could not be read; assume the first spelling
    rather than stripping every option and running a useless command.
    """
    if not flags:
        return f"-{candidates[0]}" if candidates else None
    for c in candidates:
        if c.lstrip("-") in flags:
            return f"-{c.lstrip('-')}"
    return None


def stream_cmd(cmd: list[str], timeout: int, on_line, log: logging.Logger | None = None,
               cwd: str | None = None) -> int:
    """Run a command and hand each stdout line to `on_line` as it arrives.

    The Go tools emit newline-delimited JSON and can run for minutes; reading the
    stream keeps the job log moving (and lets a stage report partial results)
    instead of blocking on a single capture that a timeout would throw away.
    Returns the number of lines consumed. Never raises for the usual failures.
    """
    lines = 0
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1, errors="replace",
                                env=tool_env(), cwd=cwd)
    except FileNotFoundError:
        if log:
            log.warning(f"binary not found: {cmd[0]}")
        return 0
    except Exception as exc:
        if log:
            log.warning(f"command failed ({cmd[0]}): {exc}")
        return 0

    deadline = time.time() + timeout
    try:
        for line in proc.stdout:            # type: ignore[union-attr]
            line = line.strip()
            if line:
                try:
                    on_line(line)
                    lines += 1
                except Exception:
                    pass
            if time.time() > deadline:
                if log:
                    log.warning(f"timeout after {timeout}s: {Path(cmd[0]).name} "
                                f"(keeping {lines} results)")
                break
    finally:
        _terminate(proc)
    return lines


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except Exception:
        pass


def tool_env() -> dict:
    """A copy of the environment with the extra bin dirs guaranteed on PATH."""
    env = dict(os.environ)
    parts = env.get("PATH", "").split(os.pathsep)
    for d in _EXTRA_BIN_DIRS:
        if d not in parts:
            parts.append(d)
    env["PATH"] = os.pathsep.join(parts)
    return env


def run_cmd(cmd: list[str], timeout: int, log: logging.Logger | None = None,
            cwd: str | None = None) -> subprocess.CompletedProcess | None:
    """Run a subprocess, capturing output, with a hard timeout. Returns None on
    timeout/spawn failure (callers degrade gracefully rather than crash)."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=tool_env(), cwd=cwd, errors="replace",
        )
    except subprocess.TimeoutExpired:
        if log:
            log.warning(f"timeout after {timeout}s: {' '.join(cmd[:3])} …")
        return None
    except FileNotFoundError:
        if log:
            log.warning(f"binary not found: {cmd[0]}")
        return None
    except Exception as exc:  # pragma: no cover
        if log:
            log.warning(f"command failed ({cmd[0]}): {exc}")
        return None
