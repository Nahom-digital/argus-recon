"""
Module · false-positive / soft-404 detection for discovered files.

A catch-all route or SPA fallback answers 200 for paths that do not exist, and
often serves an HTML page (the app shell, or a styled 404) rather than the file
that was requested. ffuf's status/size calibration removes the obvious cases;
this adds the content dimension the spec calls out: a request for
`/home/test.json` that comes back `200 text/html` is not a discovered JSON file,
it is a web page. Such records are re-labelled (verdict "webpage" /
"false_positive"), never silently dropped, so the operator still sees them for
what they are instead of chasing a phantom file.

No network traffic · it re-reads the response bodies the discovery stages have
already captured, so it is safe to run on every scan.
"""
from __future__ import annotations

import hashlib
import re
import time

from .schema import ScanResult
from .util import get_logger, host_of, path_ext

log = get_logger("falsepos")

# Extensions whose content is, by definition, not an HTML document. If one of
# these answered with an HTML page, the "file" was the catch-all, not the file.
NON_HTML_EXTS = {
    "json", "js", "mjs", "cjs", "xml", "txt", "csv", "tsv", "yaml", "yml",
    "toml", "ini", "conf", "config", "cfg", "properties", "env", "sql", "db",
    "sqlite", "dump", "bak", "old", "backup", "log", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "md", "zip", "tar", "gz", "tgz", "bz2",
    "rar", "7z", "war", "jar", "class", "pem", "key", "crt", "cer", "p12",
    "pfx", "jks", "rss", "atom", "map", "wasm", "proto", "lock",
}

# Conservative error-page phrases · only consulted when the response is HTML, so
# a genuine JSON/JS file that merely contains the word "error" is never matched.
_ERROR_RE = re.compile(
    r"(page\s+not\s+found|404\s*[-:–]?\s*(?:not\s+found|error|page)|"
    r"\bnot\s+found\b|403\s*[-:–]?\s*forbidden|\bforbidden\b|"
    r"access\s+denied|does\s+not\s+exist|no\s+longer\s+(?:available|exists)|"
    r"the\s+page\s+you\s+(?:requested|are\s+looking\s+for)|"
    r"could\s+not\s+be\s+found|error\s+404|http\s+404)",
    re.I)

_HTML_RE = re.compile(r"<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]", re.I)


def _looks_html(body: str) -> bool:
    return bool(_HTML_RE.search(body[:2000]))


def classify(url: str, status, content_type: str | None,
             body: str | None) -> tuple[str, str]:
    """Return (verdict, reason). verdict is one of:

       "file"           · a genuine discovered file (the default)
       "webpage"        · an HTML page returned where a file was requested
       "false_positive" · a 200 whose body is an error / not-found page

    Only 200 responses are ever re-labelled; a real 401/403/500 stays a file
    record so the bypass and review stages still see it."""
    try:
        code = int(status) if status is not None else 0
    except (TypeError, ValueError):
        code = 0
    if code and code != 200:
        return "file", ""
    ct = (content_type or "").lower()
    body = body or ""
    is_html = ("html" in ct) or _looks_html(body)
    if not is_html:
        return "file", ""
    head = body[:4000]
    ext = (path_ext(url) or "").lower().lstrip(".")

    # 1. An HTML body that reads as an error / not-found page, served at 200.
    if _ERROR_RE.search(head):
        return "false_positive", "200 response body is an HTML error/not-found page"
    # 2. A non-HTML file that came back as an HTML page · the catch-all / SPA
    #    shell case the spec describes (/home/test.json -> 200 text/html).
    if ext in NON_HTML_EXTS:
        return ("webpage",
                f"requested .{ext} but received an HTML page (likely a catch-all route)")
    return "file", ""


def _sig(body: str) -> str:
    collapsed = re.sub(r"\s+", " ", body[:4000]).strip()
    return hashlib.sha1(collapsed.encode("utf-8", "replace")).hexdigest()


def run(result: ScanResult) -> None:
    """Re-label discovered files in place. Pure post-pass over captured bodies:
    a per-file content check, then a cross-file page-similarity check."""
    t0 = time.time()
    files = list(result._files.values())  # type: ignore[attr-defined]
    if not files:
        result.mark_module("falsepos", "empty", duration=time.time() - t0)
        return

    relabelled = 0
    # Pass 1 · per-file content check.
    for rec in files:
        rec.setdefault("verdict", "file")
        rec.setdefault("fp_reason", "")
        verdict, reason = classify(rec.get("url", ""), rec.get("status"),
                                   rec.get("content_type"), rec.get("resp_body"))
        if verdict != "file":
            rec["verdict"] = verdict
            rec["fp_reason"] = reason
            relabelled += 1

    # Pass 2 · page similarity. If the same 200 body is served for several
    # distinct URLs on one host, that body is a catch-all and every one of those
    # "files" is a false positive · exactly the page-similarity signal the spec
    # asks for, computed from bodies already in hand (no extra requests).
    by_host_sig: dict[tuple[str, str], list[dict]] = {}
    for rec in files:
        body = rec.get("resp_body") or ""
        try:
            code = int(rec.get("status")) if rec.get("status") is not None else 0
        except (TypeError, ValueError):
            code = 0
        if code == 200 and len(body) >= 80:
            key = (rec.get("host") or host_of(rec.get("url", "")), _sig(body))
            by_host_sig.setdefault(key, []).append(rec)
    for (_host, _s), recs in by_host_sig.items():
        if len(recs) >= 3:
            for rec in recs:
                if rec.get("verdict", "file") == "file":
                    relabelled += 1
                rec["verdict"] = "false_positive"
                rec["fp_reason"] = (f"identical body served for {len(recs)} distinct "
                                    "paths on this host · catch-all route")

    genuine = sum(1 for r in files if r.get("verdict", "file") == "file")
    log.info(f"file check · {len(files)} discovered, {relabelled} re-labelled as "
             f"web page / false positive, {genuine} genuine")
    result.mark_module("falsepos", "ok",
                       note=f"{relabelled} of {len(files)} re-labelled",
                       duration=time.time() - t0)
