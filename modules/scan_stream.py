"""
Streaming reader for large scan documents.

A scan JSON grows without bound with the crawl: a deep run can produce a file of
a gigabyte or more, almost all of it the `endpoints` array. Parsing such a file
with json.load() builds a Python object tree several times the file's size in the
web process heap, and doing that per request (the raw-JSON view, a home-page
summary, one expanded row, a graph build) is what let a single huge scan exhaust
memory and take the whole dashboard down · every visitor getting a 502.

This module reads only the parts a view actually needs straight off disk with a
streaming parser (ijson), so peak memory tracks what is returned rather than the
size of the file on disk:

  * meta only            -> home-page summary
  * panel + light rows   -> the scan page (heavy per-endpoint fields dropped)
  * one endpoint by id   -> an expanded row
  * a graph-ready doc    -> the connected graph

Numbers are decoded as float/int (use_float) rather than ijson's default Decimal,
so a streamed document is byte-for-byte what json.load() would have produced and
serialises through Flask's encoder without a custom hook.
"""
from __future__ import annotations

from pathlib import Path

import ijson

_Builder = getattr(ijson, "ObjectBuilder", None) or ijson.common.ObjectBuilder

# Per-endpoint fields that dominate a large scan and that the request *table* and
# the graph never read. Mirrors store._HEAVY / server._ENDPOINT_HEAVY.
HEAVY = ("resp_body", "req_body", "dom", "found_on",
         "req_headers", "resp_headers", "notes", "js_origin")
# The graph builder attaches "found_on" edges, so it keeps that one field; it
# still has no use for bodies, headers, the captured DOM or notes.
GRAPH_DROP = tuple(f for f in HEAVY if f != "found_on")


def stream_meta(path: Path | str) -> dict:
    """Just the top-level `meta` object · everything the home-page summary needs,
    without touching the endpoints array."""
    with open(path, "rb") as fh:
        for meta in ijson.items(fh, "meta", use_float=True):
            return meta
    return {}


def _stream_doc(path: Path | str, drop: tuple) -> dict:
    """One pass over the file: rebuild every top-level field except `endpoints`
    into a panel object, and rebuild each endpoint individually so its heavy
    fields can be dropped before it is kept. Peak memory is the panel plus the
    stripped endpoint list, never the whole file."""
    panel = _Builder()
    endpoints: list[dict] = []
    item: object | None = None
    depth = 0
    with open(path, "rb") as fh:
        for prefix, event, value in ijson.parse(fh, use_float=True):
            # The endpoints array itself and its map-key: never fed to the panel.
            if prefix == "endpoints" and event in ("start_array", "end_array"):
                continue
            if prefix == "" and event == "map_key" and value == "endpoints":
                continue
            # Everything inside the endpoints array: build one endpoint at a time.
            if prefix == "endpoints.item" or prefix.startswith("endpoints.item"):
                if prefix == "endpoints.item" and event == "start_map" and item is None:
                    item = _Builder()
                    depth = 0
                if item is not None:
                    item.event(event, value)
                    if event in ("start_map", "start_array"):
                        depth += 1
                    elif event in ("end_map", "end_array"):
                        depth -= 1
                        if depth == 0:
                            ep = item.value
                            endpoints.append(
                                {k: v for k, v in ep.items() if k not in drop})
                            item = None
                continue
            panel.event(event, value)
    doc = panel.value or {}
    doc["endpoints"] = endpoints
    return doc


def stream_light_doc(path: Path | str) -> dict:
    """The scan-page document: panel data plus table-ready endpoints with the
    heavy per-endpoint fields removed. Identical shape to server._light_scan()."""
    return _stream_doc(path, HEAVY)


def stream_graph_doc(path: Path | str) -> dict:
    """A document graph_loader.graph_from_scan() can consume: panel plus endpoints
    with bodies/headers/DOM dropped but `found_on` kept (the graph needs it)."""
    return _stream_doc(path, GRAPH_DROP)


def find_endpoint(path: Path | str, eid: str) -> dict | None:
    """The full record for one endpoint (bodies, headers, found-on, JS origin),
    located by streaming the array so the other tens of thousands never load."""
    with open(path, "rb") as fh:
        for ep in ijson.items(fh, "endpoints.item", use_float=True):
            if ep.get("id") == eid:
                return ep
    return None
