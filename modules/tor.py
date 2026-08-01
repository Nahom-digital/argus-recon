"""
Tor transport · the "Tor scan" option.

When a scan is launched with Tor on this runs *first*, before anything touches
the target: it finds a usable Tor SOCKS proxy (reusing a system tor if one is
already listening, otherwise starting a private tor with its own throwaway data
directory), waits for the circuit to bootstrap, and proves the exit really is a
Tor node. Only then does the pipeline start.

Once connected the proxy is published in `config`, which is what actually routes
the scan:

  * every HTTP request goes through it (util.make_session),
  * name resolution switches to DNS-over-HTTPS through the same proxy, because a
    UDP resolver would bypass Tor and leak every hostname we look up,
  * external tools are wrapped in torsocks, or handed the proxy natively when
    they support SOCKS5 themselves (see the per-module call sites).

If any of that cannot be arranged, `connect()` raises and the engine aborts the
scan. Falling back to a direct connection would be worse than not scanning: the
operator asked for Tor precisely so their address never reaches the target.
"""
from __future__ import annotations

import atexit
import collections
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from . import config
from .util import get_logger, resolve_tool

log = get_logger("tor")

_BOOT_RE = re.compile(r"Bootstrapped (\d+)%")

# Live state, also copied into the scan JSON so a result records how it was taken.
_STATE: dict = {
    "active": False, "proxy": None, "socks": None, "own_process": False,
    "exit_ip": None, "verified": False, "torsocks": False, "bootstrap_sec": None,
}

_PROC: subprocess.Popen | None = None
_DATADIR: Path | None = None
_LOG_TAIL: collections.deque = collections.deque(maxlen=80)
_READY = threading.Event()


class TorError(RuntimeError):
    """Tor could not be brought up · the caller must abort, not fall back."""


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #
def socks_ready(host: str, port: int, timeout: float = 2.5) -> bool:
    """True only if a SOCKS5 server completes the no-auth handshake. An open
    port proves nothing · something else could be sitting on 9050."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")          # SOCKS5, 1 method, "no auth"
            reply = s.recv(2)
    except OSError:
        return False
    return len(reply) == 2 and reply[0:1] == b"\x05" and reply[1:2] == b"\x00"


def socks_lib_available() -> bool:
    """requests needs PySocks to speak socks5h://."""
    try:
        import socks  # noqa: F401  (PySocks)
        return True
    except Exception:
        return False


def availability() -> dict:
    """What the dashboard needs in order to offer (or lock) the Tor toggle."""
    running = socks_ready(config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT, timeout=0.6)
    binary = bool(resolve_tool(config.TOR_BIN))
    lib = socks_lib_available()
    return {
        "available": bool(lib and (running or binary)),
        "running": running,
        "binary": binary,
        "socks_lib": lib,
        "torsocks": bool(resolve_tool(config.TORSOCKS_BIN)),
        "socks": f"{config.TOR_SOCKS_HOST}:{config.TOR_SOCKS_PORT}",
    }


def state() -> dict:
    return dict(_STATE)


def active() -> bool:
    return bool(_STATE["active"])


# --------------------------------------------------------------------------- #
# Private tor instance
# --------------------------------------------------------------------------- #
def _free_port(exclude: set[int] | None = None) -> int:
    exclude = exclude or set()
    for _ in range(20):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in exclude:
            return port
    raise TorError("could not find a free local port for tor")


def _pump(stream) -> None:
    """Drain tor's log forever (a full pipe would stall it) and report progress.
    Each percentage is logged once so the job log shows the bootstrap without
    being buried by it."""
    seen: set[int] = set()
    for line in stream:
        line = line.rstrip()
        if not line:
            continue
        _LOG_TAIL.append(line)
        m = _BOOT_RE.search(line)
        if not m:
            continue
        pct = int(m.group(1))
        if pct not in seen:
            seen.add(pct)
            if pct % 25 == 0 or pct == 100:
                log.info(f"bootstrapping circuit … {pct}%")
        if pct >= 100:
            _READY.set()


def _start_own(bootstrap_timeout: int) -> int:
    """Launch a tor we own and wait for a full bootstrap. Returns the SOCKS port.

    The process deliberately stays in the engine's process group: cancelling a
    scan from the dashboard signals the whole group, and tor has to go with it.
    """
    global _PROC, _DATADIR
    tor_bin = resolve_tool(config.TOR_BIN)
    if not tor_bin:
        raise TorError("tor is not installed · install it (apt install tor) or "
                       "start a Tor client on "
                       f"{config.TOR_SOCKS_HOST}:{config.TOR_SOCKS_PORT}")
    port = _free_port()
    _DATADIR = Path(tempfile.mkdtemp(prefix="argus_tor_"))   # mkdtemp is 0700, as tor requires
    cmd = [
        tor_bin,
        "--SocksPort", str(port),
        "--DataDirectory", str(_DATADIR),
        "--ClientOnly", "1",
        "--AvoidDiskWrites", "1",
        "--CookieAuthentication", "0",
        "--SafeLogging", "1",
        "--Log", "notice stdout",
    ]
    log.info(f"starting a private tor on 127.0.0.1:{port} (data dir {_DATADIR})")
    t0 = time.time()
    _READY.clear()
    _LOG_TAIL.clear()
    try:
        _PROC = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True,
                                 bufsize=1, errors="replace")
    except OSError as exc:
        raise TorError(f"could not start tor: {exc}") from exc
    threading.Thread(target=_pump, args=(_PROC.stdout,), daemon=True).start()

    deadline = time.time() + bootstrap_timeout
    while time.time() < deadline:
        if _READY.wait(0.5):
            break
        if _PROC.poll() is not None:
            raise TorError(f"tor exited with code {_PROC.returncode}: {_tail()}")
    if not _READY.is_set():
        shutdown()
        raise TorError(f"tor did not bootstrap within {bootstrap_timeout}s: {_tail()}")

    _STATE["bootstrap_sec"] = round(time.time() - t0, 1)
    log.info(f"circuit ready in {_STATE['bootstrap_sec']}s")
    return port


def _tail(n: int = 4) -> str:
    return " | ".join(list(_LOG_TAIL)[-n:]) or "(no output)"


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _verify(proxy: str) -> tuple[str | None, bool]:
    """Return (exit_ip, confirmed_tor). Asks the Tor Project's own checker first
    because it answers both questions at once; an exit-IP lookup is the
    fallback when that endpoint is unreachable."""
    import requests
    sess = requests.Session()
    sess.proxies = {"http": proxy, "https": proxy}
    sess.headers.update({"User-Agent": config.USER_AGENT})
    sess.verify = True          # this check is worthless without a verified cert
    try:
        resp = sess.get("https://check.torproject.org/api/ip", timeout=30)
        data = resp.json()
        ip = (data.get("IP") or "").strip() or None
        if ip:
            return ip, bool(data.get("IsTor"))
    except Exception as exc:
        log.info(f"tor checker unreachable ({exc}) · falling back to an exit-IP lookup")
    for url in ("https://api.ipify.org?format=json", "https://ifconfig.co/json"):
        try:
            data = sess.get(url, timeout=25).json()
            ip = (data.get("ip") or "").strip() or None
            if ip:
                return ip, False
        except Exception:
            continue
    return None, False


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def connect(*, bootstrap_timeout: int | None = None) -> dict:
    """Bring Tor up and route the scan through it. Raises TorError on failure."""
    if _STATE["active"]:
        return state()
    if not socks_lib_available():
        raise TorError("SOCKS support for the HTTP client is missing · run "
                       "./install.sh (or pip install -r requirements.txt)")

    host = config.TOR_SOCKS_HOST
    port = config.TOR_SOCKS_PORT
    own = False
    if socks_ready(host, port):
        log.info(f"using the Tor SOCKS proxy already listening on {host}:{port}")
    else:
        log.info(f"nothing answering SOCKS5 on {host}:{port} · starting our own tor")
        port = _start_own(bootstrap_timeout or config.TOR_BOOTSTRAP_TIMEOUT)
        own = True

    # socks5h, not socks5: hostnames are resolved *at the proxy*, so no lookup
    # for a target ever leaves this machine in the clear.
    proxy = f"socks5h://{host}:{port}"
    exit_ip, confirmed = _verify(proxy)
    if not exit_ip:
        shutdown()
        raise TorError("the SOCKS proxy answered but no request completed through "
                       f"it: {_tail() if own else 'check that the Tor client has a circuit'}")
    if confirmed:
        log.info(f"Tor confirmed · traffic exits from {exit_ip}")
    else:
        log.warning(f"proxied through {host}:{port} (exit {exit_ip}) but the Tor "
                    "checker could not confirm it · treating the scan as proxied, "
                    "not verified")

    has_torsocks = bool(resolve_tool(config.TORSOCKS_BIN))
    if not has_torsocks:
        log.warning("torsocks is not installed · external tools that cannot take a "
                    "SOCKS proxy themselves will be skipped instead of run in the clear")

    config.HTTP_PROXY = proxy
    config.TOR_ACTIVE = True
    _STATE.update(active=True, proxy=proxy, socks=f"{host}:{port}", own_process=own,
                  exit_ip=exit_ip, verified=confirmed, torsocks=has_torsocks)
    atexit.register(shutdown)
    return state()


def wrap_cmd(cmd: list[str]) -> list[str] | None:
    """torsocks-wrap a tool that has no SOCKS option of its own.

    Returns None when Tor is on but torsocks is unavailable · the caller must
    then skip the tool rather than run it outside the proxy. Go binaries are the
    exception: they bypass libc, so torsocks cannot cover them and they must be
    given the proxy natively (see `proxy_url`).
    """
    if not _STATE["active"]:
        return cmd
    ts = resolve_tool(config.TORSOCKS_BIN)
    if not ts:
        return None
    host, _, port = (_STATE["socks"] or "").partition(":")
    return [ts, "--address", host, "--port", port, *cmd]


def proxy_url(scheme: str = "socks5") -> str | None:
    """The proxy in a form tools understand (ffuf -x, curl -x): socks5://host:port."""
    if not _STATE["active"]:
        return None
    return f"{scheme}://{_STATE['socks']}"


def shutdown() -> None:
    """Stop a tor we started and drop its data directory. A system tor is left
    alone · we did not start it."""
    global _PROC, _DATADIR
    proc, _PROC = _PROC, None
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        except Exception:
            pass
        log.info("stopped the tor instance we started")
    datadir, _DATADIR = _DATADIR, None
    if datadir:
        shutil.rmtree(datadir, ignore_errors=True)
    # Stop routing through the proxy either way: a system tor keeps running, but
    # this scan is over, and leaving config pointed at it would be a lie.
    _STATE["active"] = False
    config.TOR_ACTIVE = False
    config.HTTP_PROXY = None
