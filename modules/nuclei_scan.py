"""
Module · Nuclei scanning (source code "N").

Runs near the end of the pipeline, once the target is understood. It takes the
focused plan from nuclei_prep (live targets + template tags derived from the
detected stack) and runs Nuclei with exactly that selection · not every template
blindly · then folds each result into the findings list with the template id,
name, severity, matched location, description and references.

Opt-in (the --nuclei toggle), active, bounded by a target cap and a wall-clock
budget. Over Tor it is handed the SOCKS proxy natively (nuclei speaks -proxy
socks5), so it runs through the circuit rather than standing down.
Requires nuclei installed with its templates (install.sh does both).
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from . import config, nuclei_prep, tor
from .schema import ScanResult
from .schema import normalize_severity
from .util import get_logger, resolve_tool, run_cmd

log = get_logger("nuclei")

SRC = config.SOURCE_CODES["nuclei"]          # "N"


def available() -> bool:
    return bool(resolve_tool(config.NUCLEI_BIN))


def _emit(result: ScanResult, rec: dict) -> None:
    info = rec.get("info") or {}
    tid = rec.get("template-id") or rec.get("templateID") or "nuclei"
    name = info.get("name") or tid
    sev = normalize_severity(info.get("severity") or "info")
    matched = (rec.get("matched-at") or rec.get("matched")
               or rec.get("host") or "")
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    # Confidence: a matcher/extractor hit is high; a plain info template lower.
    conf = 85 if sev in ("high", "critical") else (70 if sev == "medium" else 55)
    result.add_finding(
        title=f"{name}",
        category="nuclei", severity=sev, confidence=conf, source=SRC,
        target=matched or (rec.get("host") or ""),
        evidence=(f"template {tid} matched at {matched}"
                  + (f" · {rec.get('matcher-name')}" if rec.get("matcher-name") else "")),
        parsed={"template_id": tid, "name": name,
                "matched_at": matched, "type": rec.get("type"),
                "matcher": rec.get("matcher-name"),
                "extracted": rec.get("extracted-results"),
                "curl": rec.get("curl-command"),
                "tags": tags},
        risk=(info.get("description") or
              "Nuclei matched a template for a known issue on this target."),
        recommendation=("Review the referenced template and remediate the "
                        "identified issue."),
        tags=(["nuclei"] + [t for t in tags[:8]]),
        refs=[r for r in refs if isinstance(r, str)][:6],
        signature=f"nuclei:{tid}:{matched}")


def _parse_jsonl(text: str) -> list[dict]:
    out: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def run(result: ScanResult) -> None:
    t0 = time.time()
    # Over Tor, nuclei is handed the SOCKS proxy natively (it supports -proxy)
    # rather than skipped. Skip only when Tor is on and no proxy resolves, so the
    # scanner never reaches a target in the clear.
    if tor.active() and not tor.proxy_url("socks5"):
        result.mark_module("nuclei", "skip",
                           note="Tor on but no usable proxy · skipped to avoid a leak")
        return
    binp = resolve_tool(config.NUCLEI_BIN)
    if not binp:
        log.info("nuclei not installed · skipping")
        result.mark_module("nuclei", "skip", note="nuclei not installed")
        return

    plan = nuclei_prep.collect(result)
    targets = plan["targets"][: config.NUCLEI_MAX_TARGETS]
    if not targets:
        log.info("no live targets for nuclei")
        result.mark_module("nuclei", "empty", note="no live targets", duration=0)
        return

    tmpd = Path(tempfile.mkdtemp(prefix="argus-nuclei-"))
    lfile, ofile = tmpd / "targets.txt", tmpd / "out.jsonl"
    lfile.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = [binp, "-l", str(lfile), "-jsonl", "-o", str(ofile),
           "-silent", "-no-color", "-disable-update-check",
           "-severity", config.NUCLEI_SEVERITY,
           "-rate-limit", str(config.NUCLEI_RATE),
           "-timeout", "10", "-retries", "1"]
    if plan["tags"]:
        cmd += ["-tags", ",".join(plan["tags"])]
    if config.NUCLEI_TEMPLATES_DIR:
        cmd += ["-t", config.NUCLEI_TEMPLATES_DIR]
    if tor.active():
        proxy = tor.proxy_url("socks5")
        if proxy:
            cmd += ["-proxy", proxy]

    log.info(f"nuclei · {len(targets)} target(s), "
             f"{len(plan['tags'])} tag(s) from {plan['reason']}"
             + (", over Tor" if tor.active() else ""))
    run_cmd(cmd, timeout=config.NUCLEI_TIMEOUT, log=log)

    text = ""
    try:
        if ofile.exists():
            text = ofile.read_text(encoding="utf-8", errors="replace")
    except Exception:
        text = ""
    records = _parse_jsonl(text)
    for rec in records:
        try:
            _emit(result, rec)
        except Exception as exc:
            log.debug(f"nuclei emit failed: {exc}")

    log.info(f"nuclei complete: {len(records)} finding(s) "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("nuclei", "ok" if records else "empty",
                       note=f"{len(records)} finding(s)",
                       duration=time.time() - t0)
