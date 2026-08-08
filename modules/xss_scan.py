"""
Module · XSS testing (source code "X").

Drives dalfox against the parameters the scan discovered · URL query strings and
form / XHR bodies · to find reflected, stored and DOM-based cross-site scripting.
Every proof-of-concept dalfox returns becomes a finding carrying the XSS type
(reflected / stored / DOM), the location, the parameter, the payload, the
evidence and a severity.

Opt-in (the --xss toggle), active (it sends crafted requests to the target), and
bounded by a target cap and a wall-clock budget. Needs dalfox installed. Over Tor
it is handed the SOCKS proxy natively (dalfox speaks --proxy socks5), so it runs
through the circuit rather than standing down · it is only skipped if no proxy
can be resolved, never run in the clear.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from . import config, inject_targets, tor
from .schema import ScanResult
from .util import get_logger, resolve_tool, run_cmd

log = get_logger("xss")

SRC = config.SOURCE_CODES["xss"]             # "X"

_TYPE_LABEL = {"V": "reflected XSS (verified)", "R": "reflected XSS",
               "G": "potential XSS"}
_TYPE_SEV = {"V": "high", "R": "medium", "G": "low"}


def available() -> bool:
    return bool(resolve_tool(config.DALFOX_BIN))


def _classify(poc: dict) -> tuple[str, str]:
    """Map a dalfox PoC to (kind, severity). DOM-based is detected from the
    inject type / message; stored is flagged when dalfox says so."""
    t = (poc.get("type") or "R").upper()
    blob = " ".join(str(poc.get(k) or "") for k in
                    ("inject_type", "message_str", "message", "poc_type")).lower()
    if "dom" in blob:
        return "DOM XSS", _TYPE_SEV.get(t, "medium")
    if "stored" in blob:
        return "stored XSS", "high"
    return _TYPE_LABEL.get(t, "reflected XSS"), _TYPE_SEV.get(t, "medium")


def _parse(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("pocs") or data.get("results") or [data]
        if isinstance(data, list):
            return [p for p in data if isinstance(p, dict)]
    except Exception:
        pass
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _json_body(target: dict) -> str:
    body = (target.get("body") or "").strip()
    if body[:1] in ("{", "["):
        try:
            json.loads(body)
            return body
        except Exception:
            pass
    obj = {p: "1" for p in (target.get("params") or [])} or {"q": "1"}
    return json.dumps(obj)


def _cmd_for(binp: str, target: dict, outfile: Path) -> tuple[list[str], str]:
    """dalfox argv for one target. The request's own channels are reused: its body
    (as JSON when the endpoint speaks JSON, else form), and its Cookie header, so
    reflected input is tested wherever the browser actually put it, not only in the
    query string."""
    cmd = [binp, "url"]
    url = target["url"]
    if target["method"] == "POST" or target.get("body"):
        base = url.split("?", 1)[0]
        if target.get("is_json"):
            data = _json_body(target)
            cmd += [base, "-d", data, "-X", "POST",
                    "-H", "Content-Type: application/json"]
        else:
            data = (target.get("body") or "").strip() \
                or "&".join(f"{p}=1" for p in (target.get("params") or [])) or "x=1"
            cmd += [base, "-d", data, "-X", "POST"]
    else:
        if "?" not in url and target["params"]:
            url = url + "?" + "&".join(f"{p}=1" for p in target["params"])
        cmd += [url]
    cookies = target.get("cookies")
    if cookies:
        cmd += ["-C", cookies]
    # dalfox is a Go binary · torsocks cannot cover it, so it is handed the SOCKS
    # proxy natively when the scan runs over Tor.
    if tor.active():
        proxy = tor.proxy_url("socks5")
        if proxy:
            cmd += ["--proxy", proxy]
    cmd += ["--format", "json", "-o", str(outfile), "--silence", "--no-color",
            "--no-spinner", "--skip-bav", "--worker", "10", "--timeout", "10"]
    return cmd, url


def _poc_request(poc: dict, url: str) -> str:
    """The exact request that carried the payload. dalfox's `data` field is the
    full PoC URL it fired (the payload is already embedded in the query), so it is
    the proof of concept · fall back to the tested URL when dalfox omits it."""
    data = str(poc.get("data") or poc.get("poc") or "").strip()
    if data.startswith("http"):
        return data
    return url


def _curl_for(method: str, request_url: str) -> str:
    """A copy-paste reproduction of the request the scanner sent."""
    if method == "POST":
        base, _, body = request_url.partition("?")
        return f"curl -sk -X POST '{base}'" + (f" --data '{body}'" if body else "")
    return f"curl -sk '{request_url}'"


def _emit(result: ScanResult, target: dict, url: str, pocs: list[dict]) -> None:
    seen: set[str] = set()
    for poc in pocs:
        kind, sev = _classify(poc)
        param = poc.get("param") or poc.get("parameter") or ""
        payload = str(poc.get("payload") or "").strip()
        request = _poc_request(poc, url)
        evidence = poc.get("evidence") or poc.get("message_str") or ""
        # A credible PoC has to carry something an operator can reproduce · a
        # payload, or a payload-bearing request that is not just the bare URL we
        # pointed dalfox at. Without either it is noise (typically a catch-all host
        # echoing the path), so it is not worth a finding.
        if not payload and request == url:
            continue
        curl = _curl_for(target["method"], request)
        param_lbl = param or "query"
        dedup = f"{param_lbl}:{kind}"
        if dedup in seen:
            continue
        seen.add(dedup)
        result.add_finding(
            title=f"{kind} in '{param_lbl}' on {url.split('?')[0]}",
            category="xss", severity=sev, confidence=90 if sev == "high" else 65,
            source=SRC, target=url,
            evidence=(f"parameter {param_lbl} · {kind}"
                      + (f" · payload: {payload[:200]}" if payload else "")
                      + (f" · request: {request[:200]}" if request else "")),
            parsed={"type": kind, "parameter": param_lbl,
                    "method": target["method"], "payload": payload,
                    "request": request, "curl": curl,
                    "evidence": str(evidence)[:400], "cwe": poc.get("cwe")},
            risk=("User input is reflected into the page without correct output "
                  "encoding · an attacker can run script in a victim's session."),
            recommendation=("Context-encode all user input on output and apply a "
                            "strict Content-Security-Policy."),
            tags=["xss", kind.split()[0].lower()],
            refs=["https://owasp.org/www-community/attacks/xss/"],
            signature=f"xss:{url.split('?')[0]}:{param_lbl}:{kind}")


def run(result: ScanResult) -> None:
    t0 = time.time()
    if not config.XSS_ENABLE:
        result.mark_module("xss", "skip", note="disabled")
        return
    # Over Tor, dalfox is handed the SOCKS proxy natively (see _cmd_for) rather
    # than skipped · but only when a proxy can actually be resolved. If Tor is on
    # and no proxy is available, skip: never let the tool reach out in the clear.
    if tor.active() and not tor.proxy_url("socks5"):
        result.mark_module("xss", "skip",
                           note="Tor on but no usable proxy · skipped to avoid a leak")
        return
    binp = resolve_tool(config.DALFOX_BIN)
    if not binp:
        log.info("dalfox not installed · skipping XSS testing")
        result.mark_module("xss", "skip", note="dalfox not installed")
        return
    targets = inject_targets.collect(result, limit=config.XSS_MAX_TARGETS)
    if not targets:
        log.info("no parameter-bearing endpoints to test for XSS")
        result.mark_module("xss", "empty", note="no injectable targets", duration=0)
        return

    per_target = max(60, config.XSS_TIMEOUT // max(1, len(targets)))
    deadline = t0 + config.XSS_TIMEOUT
    log.info(f"XSS testing {len(targets)} endpoint"
             f"{'s' if len(targets) != 1 else ''} (dalfox"
             + (", over Tor" if tor.active() else "") + ")")
    tmpd = Path(tempfile.mkdtemp(prefix="argus-xss-"))
    tested = found = 0
    for i, target in enumerate(targets):
        if time.time() >= deadline:
            log.info("XSS budget reached · stopping")
            break
        outfile = tmpd / f"dalfox-{i}.json"
        cmd, url = _cmd_for(binp, target, outfile)
        remaining = int(min(per_target, deadline - time.time()))
        if remaining < 20:
            break
        proc = run_cmd(cmd, timeout=remaining, log=log)
        tested += 1
        text = ""
        try:
            if outfile.exists():
                text = outfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        if not text and proc is not None:
            text = proc.stdout or ""
        pocs = _parse(text)
        if pocs:
            _emit(result, target, url, pocs)
            found += 1
            log.info(f"  XSS found: {url.split('?')[0]} ({len(pocs)} PoC)")

    log.info(f"XSS testing complete: {found} vulnerable of {tested} tested "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("xss", "ok" if found else "empty",
                       note=f"{found} vulnerable / {tested} tested",
                       duration=time.time() - t0)
