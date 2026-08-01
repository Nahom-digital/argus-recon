"""
Module 8 · Field intent classifier.

Scans every captured form field and request parameter name against the pattern
library in config.FIELD_PATTERNS (password, username, email, otp, api_key,
token, redirect target, object id, …). Each field gets a classification, and the
owning endpoint is tagged with the set of intents it exposes plus the highest
severity seen · this is what the dashboard renders inline on request rows.
"""
from __future__ import annotations

import re
import time

from . import config
from .schema import ScanResult
from .util import get_logger

log = get_logger("classifier")

_COMPILED = [(re.compile(rx, re.I), cat, label, sev)
             for rx, cat, label, sev in config.FIELD_PATTERNS]


def classify_field(name: str) -> dict | None:
    name = (name or "").strip()
    if not name:
        return None
    for rx, cat, label, sev in _COMPILED:
        if rx.search(name):
            return {"category": cat, "label": label,
                    "severity": config.CLASSIFICATION_SEVERITY[sev], "sev": sev}
    return None


def run(result: ScanResult) -> None:
    t0 = time.time()
    classified_fields = 0
    classified_eps = 0
    category_counts: dict[str, int] = {}

    for ep in result.iter_endpoints():
        tags: dict[str, dict] = {}   # category -> {label,severity,sev,fields}
        for field in ep["fields"]:
            cls = classify_field(field.get("name", ""))
            if not cls:
                continue
            field["classification"] = {"category": cls["category"],
                                       "label": cls["label"],
                                       "severity": cls["severity"]}
            classified_fields += 1
            cat = cls["category"]
            entry = tags.setdefault(cat, {"category": cat, "label": cls["label"],
                                          "severity": cls["severity"],
                                          "sev": cls["sev"], "fields": []})
            if field["name"] not in entry["fields"]:
                entry["fields"].append(field["name"])
            if cls["sev"] > entry["sev"]:
                entry["severity"] = cls["severity"]
                entry["sev"] = cls["sev"]

        if tags:
            ordered = sorted(tags.values(), key=lambda t: -t["sev"])
            ep["classifications"] = [{k: v for k, v in t.items() if k != "sev"}
                                     for t in ordered]
            ep["max_severity"] = config.CLASSIFICATION_SEVERITY[max(t["sev"] for t in tags.values())]
            classified_eps += 1
            for cat in tags:
                category_counts[cat] = category_counts.get(cat, 0) + 1

    result.meta["classification_summary"] = dict(
        sorted(category_counts.items(), key=lambda kv: -kv[1]))
    log.info(f"classified {classified_fields} fields across {classified_eps} requests")
    if category_counts:
        top = ", ".join(f"{k}:{v}" for k, v in
                        list(result.meta["classification_summary"].items())[:6])
        log.info(f"  intents: {top}")
    result.mark_module("classifier", "ok",
                       note=f"{classified_eps} requests tagged", duration=time.time() - t0)
