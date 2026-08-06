"""
Module · parameter discovery (source code "A").

Hidden query/body parameters are attack surface the crawler cannot see · a
`?debug=`, `?admin=`, `?redirect=` the page never links to. When arjun is
installed this drives it against the most interesting in-scope endpoints and
folds every discovered parameter back onto the endpoint record (so the field
classifier then judges it like any other input) and into the findings list.

Optional and additive: with no arjun binary the stage records itself unavailable
and the pipeline continues · the JS analyzer's URL-parameter extraction still
contributes the parameters that do appear in code.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from . import config
from .schema import ScanResult
from .util import (get_logger, resolve_tool, run_cmd, tool_flags, pick_flag,
                   in_scope, host_of)

log = get_logger("paramscan")

SRC = config.SOURCE_CODES["param"]           # "A"


def available() -> bool:
    return bool(resolve_tool(config.ARJUN_BIN))


def _targets(result: ScanResult) -> list[str]:
    """The endpoints most worth mining · forms and XHR first, then 200 pages,
    de-duplicated by path so we do not spend the budget on ?id=1 vs ?id=2."""
    ranked: list[tuple[int, str]] = []
    seen_path: set[str] = set()
    for e in result.iter_endpoints():
        url = e.get("url")
        if not url or not e.get("in_scope") or e.get("method", "GET") != "GET":
            continue
        key = url.split("?", 1)[0]
        if key in seen_path:
            continue
        seen_path.add(key)
        score = 0
        if e.get("type") in ("form", "xhr", "fetch"):
            score += 3
        if e.get("fields"):
            score += 2
        if e.get("status") == 200:
            score += 1
        ranked.append((-score, key))
    ranked.sort()
    return [u for _, u in ranked[: config.PARAM_MAX_TARGETS]]


def _parse_output(path: Path) -> dict[str, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    if isinstance(data, dict):
        for url, info in data.items():
            if isinstance(info, dict):
                params = info.get("params") or info.get("parameters") or []
                if isinstance(params, list) and params:
                    out[url] = [str(p) for p in params]
    return out


def run(result: ScanResult) -> None:
    t0 = time.time()
    binp = resolve_tool(config.ARJUN_BIN)
    if not binp:
        log.info("parameter-discovery engine not installed · skipping")
        result.mark_module("paramscan", "skip", note="engine not installed")
        return
    targets = _targets(result)
    if not targets:
        result.mark_module("paramscan", "empty", note="no candidate endpoints", duration=0)
        return

    flags = tool_flags(binp)
    log.info(f"parameter discovery on {len(targets)} endpoint"
             f"{'s' if len(targets) != 1 else ''}")
    tmpd = Path(tempfile.mkdtemp(prefix="argus-arjun-"))
    infile, outfile = tmpd / "urls.txt", tmpd / "out.json"
    infile.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = [binp]
    iflag = pick_flag(flags, "i", "input")
    oflag = pick_flag(flags, "oJ", "o")
    cmd += [iflag or "-i", str(infile), oflag or "-oJ", str(outfile)]
    tflag = pick_flag(flags, "t", "threads")
    if tflag:
        cmd += [tflag, "10"]
    if pick_flag(flags, "q", "quiet"):
        cmd.append(pick_flag(flags, "q", "quiet"))

    run_cmd(cmd, timeout=max(120, 20 * len(targets)), log=log)
    discovered = _parse_output(outfile)

    total = 0
    for url, params in discovered.items():
        if not in_scope(url, result.domain):
            continue
        rec = result.add_endpoint(url, source=SRC,
                                  fields=[{"name": p, "source": "param-discovery"}
                                          for p in params])
        total += len(params)
        result.add_finding(
            title=f"Hidden parameters discovered on {url.split('?')[0]}",
            category="param", severity="low", confidence=70, source=SRC, target=url,
            evidence=f"discovered: {', '.join(params[:12])}",
            parsed={"params": params, "count": len(params)},
            risk=("Undocumented parameters are input the app processes but never "
                  "advertises · a common home for debug flags, IDORs and injection."),
            recommendation="Review each parameter's handling and access control.",
            tags=["param", "discovery"], signature=f"params:{url.split('?')[0]}")

    log.info(f"parameter discovery: {total} parameter"
             f"{'s' if total != 1 else ''} across {len(discovered)} endpoints "
             f"({time.time() - t0:.1f}s)")
    result.mark_module("paramscan", "ok" if total else "empty",
                       note=f"{total} params / {len(discovered)} endpoints",
                       duration=time.time() - t0)
