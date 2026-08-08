"""
Module · SQL injection testing (source code "Q").

Drives sqlmap against the parameters the scan discovered · URL query strings and
form / XHR bodies · in fully non-interactive batch mode, exercising every
technique (boolean/error/union/stacked/time/inline) so a real injection is not
missed. Each confirmed injection becomes a finding carrying the endpoint,
parameter, injection type, payload, back-end DBMS, severity and the raw sqlmap
evidence.

Opt-in (the --sqli toggle) and active · it sends crafted requests to the target ·
so it never runs in a passive scan and needs sqlmap installed. Bounded by a
target cap and a wall-clock budget so it cannot turn a scan into an overnight job.
"""
from __future__ import annotations

import re
import time

from . import config, inject_targets, tor
from .schema import ScanResult
from .util import get_logger, resolve_tool, run_cmd

log = get_logger("sqli")

SRC = config.SOURCE_CODES["sqli"]            # "Q"


def available() -> bool:
    return bool(resolve_tool(config.SQLMAP_BIN))


# sqlmap reports each injectable parameter as a block:
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: ...
#       Payload: id=1 AND 1=1
_PARAM_BLOCK_RE = re.compile(
    r"Parameter:\s*(?P<name>.+?)\s*\((?P<place>[A-Za-z]+)\)"
    r"(?P<body>.*?)(?=\nParameter:|\n---|\Z)", re.S)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")


def _parse_sqlmap(text: str) -> list[dict]:
    dbms_m = _DBMS_RE.search(text or "")
    dbms = dbms_m.group(1).strip() if dbms_m else None
    out: list[dict] = []
    for m in _PARAM_BLOCK_RE.finditer(text or ""):
        body = m.group("body")
        types = [t.strip() for t in re.findall(r"Type:\s*(.+)", body)]
        titles = [t.strip() for t in re.findall(r"Title:\s*(.+)", body)]
        payloads = [p.strip() for p in re.findall(r"Payload:\s*(.+)", body)]
        out.append({
            "param": m.group("name").strip(),
            "place": m.group("place").strip(),
            "types": types, "titles": titles, "payloads": payloads,
            "dbms": dbms,
        })
    return out


def _cmd_for(binp: str, target: dict, per_target: int) -> tuple[list[str], str, str]:
    """Build the sqlmap argv for one target. Returns (cmd, url, data)."""
    cmd = [binp, "--batch", "--disable-coloring", "-v", "0",
           "--level", str(config.SQLI_LEVEL), "--risk", str(config.SQLI_RISK),
           "--technique", "BEUSTQ", "--random-agent", "--flush-session",
           "--threads", "4", "--timeout", "15", "--retries", "1"]
    url = target["url"]
    data = ""
    if target["method"] == "POST":
        base = url.split("?", 1)[0]
        data = "&".join(f"{p}=1" for p in target["params"]) or "x=1"
        cmd += ["-u", base, "--data", data]
    else:
        if "?" not in url and target["params"]:
            url = url + "?" + "&".join(f"{p}=1" for p in target["params"])
        cmd += ["-u", url]
    return cmd, url, data


def _emit(result: ScanResult, target: dict, url: str, data: str,
          hits: list[dict]) -> None:
    if data:
        request = f"{url.split('?', 1)[0]} (POST {data})"
        curl = f"curl -sk -X POST '{url.split('?', 1)[0]}' --data '{data}'"
    else:
        request = url
        curl = f"curl -sk '{url}'"
    for h in hits:
        dbms = h.get("dbms") or "unknown"
        payload = (h.get("payloads") or [""])[0]
        types = ", ".join(h.get("types") or []) or "n/a"
        result.add_finding(
            title=f"SQL injection in '{h['param']}' on {url.split('?')[0]}",
            category="sqli", severity="critical", confidence=95, source=SRC,
            target=url,
            evidence=(f"parameter {h['param']} ({h['place']}) · {types}"
                      + (f" · DBMS {dbms}" if dbms != "unknown" else "")
                      + (f" · payload: {payload}" if payload else "")),
            parsed={"parameter": h["param"], "place": h["place"],
                    "types": h.get("types"), "titles": h.get("titles"),
                    "payloads": h.get("payloads"), "dbms": dbms,
                    "method": target["method"], "request": request,
                    "curl": curl, "data": data},
            risk=("The parameter is concatenated into a SQL query · an attacker "
                  "can read or modify the database, and often reach the host."),
            recommendation=("Use parameterised queries / prepared statements for "
                            "this input; never build SQL by string concatenation."),
            tags=["sqli", "injection", dbms.split()[0].lower() if dbms != "unknown" else "sql"],
            refs=["https://owasp.org/www-community/attacks/SQL_Injection"],
            signature=f"sqli:{url.split('?')[0]}:{h['param']}:{target['method']}")


def run(result: ScanResult) -> None:
    t0 = time.time()
    if not config.SQLI_ENABLE:
        result.mark_module("sqli", "skip", note="disabled")
        return
    if tor.active():
        result.mark_module("sqli", "skip", note="not run over Tor")
        return
    binp = resolve_tool(config.SQLMAP_BIN)
    if not binp:
        log.info("sqlmap not installed · skipping SQL injection testing")
        result.mark_module("sqli", "skip", note="sqlmap not installed")
        return
    targets = inject_targets.collect(result, limit=config.SQLI_MAX_TARGETS)
    if not targets:
        log.info("no parameter-bearing endpoints to test for SQLi")
        result.mark_module("sqli", "empty", note="no injectable targets", duration=0)
        return

    per_target = max(90, config.SQLI_TIMEOUT // max(1, len(targets)))
    deadline = t0 + config.SQLI_TIMEOUT
    log.info(f"SQL injection testing {len(targets)} endpoint"
             f"{'s' if len(targets) != 1 else ''} (sqlmap, level {config.SQLI_LEVEL}"
             f"/risk {config.SQLI_RISK})")
    tested = found = 0
    for target in targets:
        if time.time() >= deadline:
            log.info("SQLi budget reached · stopping")
            break
        cmd, url, data = _cmd_for(binp, target, per_target)
        remaining = int(min(per_target, deadline - time.time()))
        if remaining < 30:
            break
        proc = run_cmd(cmd, timeout=remaining, log=log)
        tested += 1
        if not proc or not proc.stdout:
            continue
        hits = _parse_sqlmap(proc.stdout)
        if hits:
            _emit(result, target, url, data, hits)
            found += len(hits)
            log.info(f"  SQLi confirmed: {url.split('?')[0]} "
                     f"({', '.join(h['param'] for h in hits)})")

    log.info(f"SQL injection testing complete: {found} injection(s) across "
             f"{tested} endpoint(s) ({time.time() - t0:.1f}s)")
    result.mark_module("sqli", "ok" if found else "empty",
                       note=f"{found} injection(s) / {tested} tested",
                       duration=time.time() - t0)
