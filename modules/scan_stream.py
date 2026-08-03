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


def panel_only(path: Path | str) -> dict:
    """Every top-level field of the scan except `endpoints`, built in one pass.

    This is the graph "shell": meta, subdomains, infra, secrets, files · the
    small layers the graph hangs endpoints off. Kept separate from the endpoints
    so the caller can stream those one at a time (iter_graph_endpoints) and keep
    only the few thousand it will actually render, instead of holding the whole
    array in memory the way stream_graph_doc does."""
    panel = _Builder()
    with open(path, "rb") as fh:
        for prefix, event, value in ijson.parse(fh, use_float=True):
            if prefix == "endpoints" and event in ("start_array", "end_array"):
                continue
            if prefix == "" and event == "map_key" and value == "endpoints":
                continue
            if prefix == "endpoints.item" or prefix.startswith("endpoints.item"):
                continue
            panel.event(event, value)
    return panel.value or {}


def iter_graph_endpoints(path: Path | str, cap: int | None = None):
    """Yield each endpoint, one at a time, with the graph-drop fields removed
    (bodies/headers/DOM/notes/js_origin gone, `found_on` kept).

    ijson.items builds each object with the parser's C backend · roughly twice
    the throughput of feeding events to a Python ObjectBuilder · and because it
    is a generator, peak memory is a single endpoint, not the whole array. The
    caller decides what to retain, so a gigabyte scan never materialises its
    endpoints list in the web process at all.

    `cap` stops after that many endpoints. The graph only renders a few thousand
    nodes, so reading a million to choose them is wasted I/O · a bounded prefix
    keeps a from-scratch graph build off a gigabyte file down to a few seconds."""
    n = 0
    with open(path, "rb") as fh:
        for ep in ijson.items(fh, "endpoints.item", use_float=True):
            yield {k: v for k, v in ep.items() if k not in GRAPH_DROP}
            n += 1
            if cap is not None and n >= cap:
                return


def graph_shell(path: Path | str) -> dict:
    """The scan "shell" · every top-level layer except `endpoints` · read by
    stopping the parse the instant the endpoints array begins.

    panel_only() reaches the same result but keeps parsing to end-of-file: even
    skipping the endpoint events, ijson still tokenises every byte of the array,
    so on a gigabyte scan it costs ~20s. This walks the top-level object and
    breaks at the `endpoints` key, so its cost is the size of the shell, not the
    file. With endpoints written last (schema.to_dict) the shell is complete;
    on an older file that put endpoints in the middle the trailing layers
    (files/js_files/secrets) are simply absent here and come from the store
    panel instead."""
    shell: dict = {}
    cur_key: str | None = None
    builder = None
    depth = 0
    with open(path, "rb") as fh:
        for prefix, event, value in ijson.parse(fh, use_float=True):
            if prefix == "" and event == "map_key":
                if value == "endpoints":
                    break
                cur_key, builder, depth = value, None, 0
                continue
            if cur_key is None:
                continue  # the root object's own start_map / end_map
            if builder is None:
                builder = _Builder()
            builder.event(event, value)
            if event in ("start_map", "start_array"):
                depth += 1
            elif event in ("end_map", "end_array"):
                depth -= 1
                if depth == 0:
                    shell[cur_key] = builder.value
                    cur_key, builder = None, None
    return shell


def find_endpoint(path: Path | str, eid: str) -> dict | None:
    """The full record for one endpoint (bodies, headers, found-on, JS origin),
    located by streaming the array so the other tens of thousands never load."""
    with open(path, "rb") as fh:
        for ep in ijson.items(fh, "endpoints.item", use_float=True):
            if ep.get("id") == eid:
                return ep
    return None
