"""
Module 10 — Graph model + graph-database loader.

`graph_from_scan()` turns a scan dict into a connected node/edge graph following
the spec's shape:

    Domain -> Subdomain -> Endpoint -> Request -> Field
    Subdomain -> IP -> ASN,   Subdomain -> File,   JS -> Secret

That pure function is the single source of truth for the graph: the web
dashboard renders it directly (so the view always works), and `load()` pushes
the very same nodes/edges into a graph database for anyone who wants to explore
it there.

Two backends, selected by `config.GRAPH_BACKEND` (auto | neo4j | kuzu | none):

  * neo4j — a server you run; batched MERGE statements, explorable in the Neo4j
    browser,
  * kuzu  — an *embedded* graph DB (SQLite's deployment model, Cypher's query
    language): no server, one file on disk, the sensible default for a
    single-user local tool.

"auto" prefers a reachable Neo4j, else an importable kuzu, else nothing. Either
way the loss of a backend is non-fatal: `load()` returns False (and the scan is
queued for a later retry by modules.store), and the dashboard graph still
renders from the scan JSON.
"""
from __future__ import annotations

import time

from . import config
from .util import get_logger, short_hash, host_of

log = get_logger("graph")

# Node type -> display colour hint (consumed by the dashboard legend).
NODE_TYPES = ["Domain", "Subdomain", "IP", "ASN", "Endpoint", "JS",
              "Request", "Field", "Secret", "File", "External"]


def _ep_node_id(method: str, url: str) -> str:
    return "ep:" + short_hash(method, url)


def graph_from_scan(data: dict, *, max_nodes: int = 4000) -> dict:
    """Build {nodes, edges, stats} from a scan dict."""
    domain = data["meta"]["domain"]
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    def node(nid: str, ntype: str, label: str, **props):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, "props": props}
        return nid

    def edge(src: str, dst: str, rel: str):
        key = (src, dst, rel)
        if key in seen_edges or src not in nodes or dst not in nodes:
            return
        seen_edges.add(key)
        edges.append({"source": src, "target": dst, "type": rel})

    # ---- domain + subdomains + infra ------------------------------------ #
    dom_id = node(f"domain:{domain}", "Domain", domain)
    sub_ids: dict[str, str] = {}
    for sub in data.get("subdomains", []):
        host = sub["host"]
        sid = node(f"sub:{host}", "Subdomain", host,
                   resolved=sub.get("resolved"),
                   tech=", ".join(sub.get("tech", [])[:8]),
                   sources=", ".join(sub.get("sources", [])),
                   ips=", ".join(sub.get("ips", [])[:4]),
                   status=(sub.get("http") or {}).get("status"))
        sub_ids[host] = sid
        edge(dom_id, sid, "HAS_SUBDOMAIN")
        for ip in sub.get("ips", []):
            iid = node(f"ip:{ip}", "IP", ip)
            edge(sid, iid, "RESOLVES_TO")

    for ip in data.get("infra", {}).get("ips", []):
        iid = node(f"ip:{ip['ip']}", "IP", ip["ip"],
                   asn=ip.get("asn"), org=ip.get("org"), country=ip.get("country"),
                   type=ip.get("type"), datacenter=ip.get("datacenter"))
        if ip.get("asn"):
            aid = node(f"asn:{ip['asn']}", "ASN", ip["asn"], org=ip.get("org"))
            edge(iid, aid, "ANNOUNCED_BY")

    def ensure_sub(host: str) -> str | None:
        if not host:
            return None
        if host in sub_ids:
            return sub_ids[host]
        sid = node(f"sub:{host}", "Subdomain", host, resolved=None, tech="")
        edge(dom_id, sid, "HAS_SUBDOMAIN")
        sub_ids[host] = sid
        return sid

    # ---- endpoints / requests / fields ---------------------------------- #
    endpoints = data.get("endpoints", [])
    # Index in-scope GET pages by URL so we can attach "found_on" edges.
    get_index: dict[str, str] = {}
    for ep in endpoints:
        if ep["method"] == "GET":
            get_index[ep["url"]] = _ep_node_id("GET", ep["url"])

    # Prioritise which endpoints to include if we bump into the node cap.
    def priority(ep):
        p = 0
        if ep.get("classifications"):
            p += 4
        if ep["type"] in ("form", "xhr", "fetch"):
            p += 3
        if ep["type"] == "js":
            p += 2
        if ep["fields"]:
            p += 1
        if not ep["in_scope"]:
            p -= 2
        return -p

    for ep in sorted(endpoints, key=priority):
        if len(nodes) >= max_nodes and ep["type"] in ("link", "page") and not ep["fields"]:
            continue
        nid = _ep_node_id(ep["method"], ep["url"])
        srcs = ", ".join(ep.get("sources", []))
        if not ep["in_scope"]:
            node(nid, "External", ep["url"], method=ep["method"],
                 status=ep.get("status"), sources=srcs)
        elif ep["type"] in ("form", "xhr", "fetch"):
            node(nid, "Request", ep["url"], method=ep["method"], type=ep["type"],
                 status=ep.get("status"), sources=srcs,
                 severity=ep.get("max_severity"),
                 intents=", ".join(c["category"] for c in ep.get("classifications", [])))
        elif ep["type"] == "js":
            node(nid, "JS", ep["url"], status=ep.get("status"), sources=srcs)
        else:
            node(nid, "Endpoint", ep["url"], method=ep["method"], type=ep["type"],
                 status=ep.get("status"), sources=srcs)

        # attach in-scope nodes to their subdomain (never promote an
        # out-of-scope host to a Subdomain of the target)
        if nodes[nid]["type"] != "External":
            sid = ensure_sub(ep.get("host") or host_of(ep["url"]))
            rel = "HAS_REQUEST" if nodes[nid]["type"] == "Request" else "HAS_ENDPOINT"
            if sid:
                edge(sid, nid, rel)
        # attach to the page it was found on
        for fo in ep.get("found_on", []):
            pid = get_index.get(fo)
            if pid and pid in nodes and pid != nid:
                edge(pid, nid, "CONTAINS" if nodes[nid]["type"] in ("Request", "External")
                     else "LINKS_TO")
        # fields
        for field in ep.get("fields", []):
            name = field.get("name")
            if not name:
                continue
            cls = field.get("classification")
            fid = node(f"field:{ep['id']}:{name}", "Field", name,
                       category=(cls or {}).get("category"),
                       severity=(cls or {}).get("severity"),
                       location=field.get("location") or field.get("type"))
            edge(nid, fid, "HAS_FIELD")

    # ---- secrets (linked to the JS/page that exposed them) -------------- #
    for sec in data.get("secrets", []):
        sid_node = node("secret:" + short_hash(sec["type"], sec["match"], sec["source"]),
                        "Secret", sec["type"], severity=sec.get("severity"),
                        match=sec.get("match"),
                        sources=", ".join(sec.get("found_by", [])),
                        source_url=sec.get("source"))
        origin = get_index.get(sec["source"])
        if origin and origin in nodes:
            edge(origin, sid_node, "EXPOSES")
        else:
            s = ensure_sub(host_of(sec["source"]))
            if s:
                edge(s, sid_node, "EXPOSES")

    # ---- files ---------------------------------------------------------- #
    for f in data.get("files", []):
        fid = node("file:" + short_hash(f["url"]), "File", f["url"],
                   kind=f.get("kind"), subtype=f.get("subtype"), status=f.get("status"),
                   sources=", ".join(f.get("sources", [])))
        s = ensure_sub(f.get("host") or host_of(f["url"]))
        if s:
            edge(s, fid, "HAS_FILE")

    counts: dict[str, int] = {}
    for n in nodes.values():
        counts[n["type"]] = counts.get(n["type"], 0) + 1

    return {"nodes": list(nodes.values()), "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges), "by_type": counts}}


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #
def _neo4j_importable() -> bool:
    try:
        import neo4j  # noqa: F401
        return True
    except Exception:
        return False


def _kuzu_importable() -> bool:
    try:
        import kuzu  # noqa: F401
        return True
    except Exception:
        return False


_BACKEND_CACHE = {"at": 0.0, "value": None}
_BACKEND_TTL = 15.0


def active_backend() -> str:
    """Which backend a load/fetch will actually use right now: 'neo4j', 'kuzu',
    or 'none'. Honours config.GRAPH_BACKEND; 'auto' prefers a reachable Neo4j,
    then an importable kuzu.

    The result is cached briefly: in 'auto' mode it probes Neo4j connectivity,
    and that socket round-trip should not run on every graph request/status poll.
    """
    now = time.time()
    if _BACKEND_CACHE["value"] is not None and now - _BACKEND_CACHE["at"] < _BACKEND_TTL:
        return _BACKEND_CACHE["value"]
    want = config.GRAPH_BACKEND
    if want == "none":
        result = "none"
    elif want == "neo4j":
        result = "neo4j" if _neo4j_importable() else "none"
    elif want == "kuzu":
        result = "kuzu" if _kuzu_importable() else "none"
    elif _neo4j_importable() and _neo4j_ping():          # auto
        result = "neo4j"
    elif _kuzu_importable():
        result = "kuzu"
    else:
        result = "none"
    _BACKEND_CACHE.update(at=now, value=result)
    return result


def backend_status() -> dict:
    """What the dashboard shows for the graph DB: available? which one?"""
    b = active_backend()
    return {"available": b != "none", "backend": b,
            "neo4j": _neo4j_importable() and _neo4j_ping(),
            "kuzu": _kuzu_importable()}


def ping(**conn) -> bool:
    """Back-compat: is *any* persistent backend available."""
    return active_backend() != "none"


def _prepare(data: dict) -> tuple[dict, str, str]:
    """graph_from_scan + scan metadata stamped onto every node's props."""
    graph = graph_from_scan(data, max_nodes=10_000_000)   # no cap for the DB
    scan_id = data["meta"]["scan_id"]
    domain = data["meta"]["domain"]
    for n in graph["nodes"]:
        n["props"] = {k: v for k, v in n["props"].items() if v is not None}
        n["props"]["scan_id"] = scan_id
        n["props"]["domain"] = domain
        n["props"]["name"] = n["label"]
    return graph, scan_id, domain


def load(data: dict, *, wipe_scan: bool = True, backend: str | None = None, **conn) -> bool:
    """Push the scan graph into the selected backend. Returns True on success,
    False if no backend is available or the write errors (never raises)."""
    b = backend or active_backend()
    if b == "neo4j":
        return _neo4j_load(data, wipe_scan=wipe_scan, **conn)
    if b == "kuzu":
        return _kuzu_load(data, wipe_scan=wipe_scan)
    log.info("no graph backend available — graph renders from JSON; "
             "scan queued for a later load")
    return False


def delete_scan(scan_id: str, **conn) -> bool:
    """Remove a scan's subgraph from whichever backends have it (best-effort)."""
    ok = False
    if _neo4j_importable():
        ok = _neo4j_delete(scan_id, **conn) or ok
    if _kuzu_importable():
        ok = _kuzu_delete(scan_id) or ok
    return ok


def fetch_graph(scan_id: str, backend: str | None = None, **conn) -> dict | None:
    """Read a scan's graph back out of the active backend. None if unavailable."""
    b = backend or active_backend()
    if b == "neo4j":
        return _neo4j_fetch(scan_id, **conn)
    if b == "kuzu":
        return _kuzu_fetch(scan_id)
    return None


# --------------------------------------------------------------------------- #
# Neo4j backend
# --------------------------------------------------------------------------- #
def _driver(uri=None, user=None, password=None):
    from neo4j import GraphDatabase
    return GraphDatabase.driver(uri or config.NEO4J_URI,
                                auth=(user or config.NEO4J_USER,
                                      password or config.NEO4J_PASSWORD))


def _neo4j_ping(uri=None, user=None, password=None) -> bool:
    try:
        drv = _driver(uri, user, password)
        drv.verify_connectivity()
        drv.close()
        return True
    except Exception:
        return False


def _neo4j_load(data: dict, *, wipe_scan: bool = True, **conn) -> bool:
    t0 = time.time()
    graph, scan_id, _domain = _prepare(data)
    try:
        drv = _driver(conn.get("uri"), conn.get("user"), conn.get("password"))
        drv.verify_connectivity()
    except Exception as exc:
        log.warning(f"Neo4j unreachable at {config.NEO4J_URI}: {exc}")
        log.warning("  (graph still renders in the dashboard from JSON)")
        return False

    nodes_by_type: dict[str, list] = {}
    for n in graph["nodes"]:
        nodes_by_type.setdefault(n["type"], []).append(
            {"id": n["id"], "props": n["props"]})
    edges_by_type: dict[str, list] = {}
    for e in graph["edges"]:
        edges_by_type.setdefault(e["type"], []).append(
            {"src": e["source"], "dst": e["target"]})

    try:
        with drv.session(database=config.NEO4J_DATABASE) as sess:
            sess.run("CREATE CONSTRAINT argus_node_id IF NOT EXISTS "
                     "FOR (n:ArgusNode) REQUIRE n.id IS UNIQUE")
            if wipe_scan:
                sess.run("MATCH (n:ArgusNode {scan_id:$sid}) DETACH DELETE n",
                         sid=scan_id)
            for ntype, batch in nodes_by_type.items():
                sess.run(
                    f"UNWIND $rows AS row "
                    f"MERGE (n:ArgusNode {{id: row.id}}) "
                    f"SET n += row.props, n:`{ntype}`",
                    rows=batch)
            for rel, batch in edges_by_type.items():
                sess.run(
                    f"UNWIND $rows AS row "
                    f"MATCH (a:ArgusNode {{id: row.src}}), (b:ArgusNode {{id: row.dst}}) "
                    f"MERGE (a)-[:`{rel}`]->(b)",
                    rows=batch)
        drv.close()
    except Exception as exc:
        log.warning(f"Neo4j load failed: {exc}")
        return False

    log.info(f"loaded {graph['stats']['nodes']} nodes / {graph['stats']['edges']} "
             f"edges into Neo4j ({time.time() - t0:.1f}s)")
    return True


def _neo4j_delete(scan_id: str, **conn) -> bool:
    try:
        drv = _driver(conn.get("uri"), conn.get("user"), conn.get("password"))
        drv.verify_connectivity()
        with drv.session(database=config.NEO4J_DATABASE) as sess:
            sess.run("MATCH (n:ArgusNode {scan_id:$sid}) DETACH DELETE n", sid=scan_id)
        drv.close()
        return True
    except Exception:
        return False


def _neo4j_fetch(scan_id: str, **conn) -> dict | None:
    try:
        drv = _driver(conn.get("uri"), conn.get("user"), conn.get("password"))
        drv.verify_connectivity()
    except Exception:
        return None
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    try:
        with drv.session(database=config.NEO4J_DATABASE) as sess:
            for rec in sess.run(
                    "MATCH (n:ArgusNode {scan_id:$sid}) RETURN n, labels(n) AS labels",
                    sid=scan_id):
                n = rec["n"]
                labels = [l for l in rec["labels"] if l != "ArgusNode"]
                nodes[n["id"]] = {
                    "id": n["id"], "type": labels[0] if labels else "Node",
                    "label": n.get("name", n["id"]),
                    "props": {k: v for k, v in dict(n).items()
                              if k not in ("id", "scan_id", "domain")},
                }
            for rec in sess.run(
                    "MATCH (a:ArgusNode {scan_id:$sid})-[r]->(b:ArgusNode {scan_id:$sid}) "
                    "RETURN a.id AS s, b.id AS t, type(r) AS rel", sid=scan_id):
                edges.append({"source": rec["s"], "target": rec["t"], "type": rec["rel"]})
        drv.close()
    except Exception:
        return None
    if not nodes:
        return None
    return {"nodes": list(nodes.values()), "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges)}, "source": "neo4j"}


# --------------------------------------------------------------------------- #
# Kuzu backend (embedded, no server)
#
# Kuzu wants a declared schema, so the whole property graph is stored in one
# generic node table and one generic relationship table, with the node type,
# label and remaining attributes carried as columns / a JSON blob. That keeps the
# arbitrary Domain/Subdomain/Endpoint/… shape without a table per type, and reads
# back into exactly the {nodes, edges} structure the dashboard already consumes.
# --------------------------------------------------------------------------- #
import json as _json
import threading as _threading

_KUZU_LOCK = _threading.Lock()      # one embedded DB, serialise writers
_KUZU_DB = None


def _kuzu_conn():
    """Open (once) the embedded database and ensure the schema exists."""
    global _KUZU_DB
    import kuzu
    if _KUZU_DB is None:
        config.KUZU_DIR.parent.mkdir(parents=True, exist_ok=True)
        _KUZU_DB = kuzu.Database(str(config.KUZU_DIR))
        conn = kuzu.Connection(_KUZU_DB)
        conn.execute(
            "CREATE NODE TABLE IF NOT EXISTS ArgusNode("
            "id STRING, scan_id STRING, ntype STRING, label STRING, props STRING, "
            "PRIMARY KEY (id))")
        conn.execute(
            "CREATE REL TABLE IF NOT EXISTS REL(FROM ArgusNode TO ArgusNode, "
            "rtype STRING, scan_id STRING)")
        return conn
    return kuzu.Connection(_KUZU_DB)


_KUZU_BATCH = 2000


def _kuzu_load(data: dict, *, wipe_scan: bool = True) -> bool:
    t0 = time.time()
    try:
        graph, scan_id, _domain = _prepare(data)
        node_rows = [{"id": n["id"], "sid": scan_id, "t": n["type"], "lbl": n["label"],
                      "p": _json.dumps({k: v for k, v in n["props"].items()
                                        if k not in ("scan_id", "domain")})}
                     for n in graph["nodes"]]
        edge_rows = [{"s": e["source"], "d": e["target"], "rt": e["type"], "sid": scan_id}
                     for e in graph["edges"]]
        with _KUZU_LOCK:
            conn = _kuzu_conn()
            if wipe_scan:
                _kuzu_delete_locked(conn, scan_id)
            # One UNWIND per batch instead of a query per element — 16k edges as
            # 16k separate MERGE compilations is what made a load take minutes and
            # hold the lock the reader needs.
            for chunk in _chunks(node_rows, _KUZU_BATCH):
                conn.execute(
                    "UNWIND $rows AS row MERGE (n:ArgusNode {id: row.id}) "
                    "SET n.scan_id=row.sid, n.ntype=row.t, n.label=row.lbl, n.props=row.p",
                    {"rows": chunk})
            for chunk in _chunks(edge_rows, _KUZU_BATCH):
                conn.execute(
                    "UNWIND $rows AS row "
                    "MATCH (a:ArgusNode {id: row.s}), (b:ArgusNode {id: row.d}) "
                    "MERGE (a)-[r:REL {rtype: row.rt}]->(b) SET r.scan_id=row.sid",
                    {"rows": chunk})
    except Exception as exc:
        log.warning(f"kuzu load failed: {exc}")
        return False
    log.info(f"loaded {graph['stats']['nodes']} nodes / {graph['stats']['edges']} "
             f"edges into kuzu ({time.time() - t0:.1f}s)")
    return True


def _chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _kuzu_delete_locked(conn, scan_id: str) -> None:
    conn.execute("MATCH (n:ArgusNode {scan_id:$sid}) DETACH DELETE n",
                 {"sid": scan_id})


def _kuzu_delete(scan_id: str) -> bool:
    try:
        with _KUZU_LOCK:
            _kuzu_delete_locked(_kuzu_conn(), scan_id)
        return True
    except Exception:
        return False


def _kuzu_fetch(scan_id: str) -> dict | None:
    try:
        with _KUZU_LOCK:
            conn = _kuzu_conn()
            nodes: dict[str, dict] = {}
            res = conn.execute(
                "MATCH (n:ArgusNode {scan_id:$sid}) "
                "RETURN n.id, n.ntype, n.label, n.props", {"sid": scan_id})
            while res.has_next():
                nid, ntype, label, props = res.get_next()
                try:
                    p = _json.loads(props) if props else {}
                except Exception:
                    p = {}
                p.pop("name", None)
                nodes[nid] = {"id": nid, "type": ntype or "Node",
                              "label": label or nid, "props": p}
            edges: list[dict] = []
            res = conn.execute(
                "MATCH (a:ArgusNode {scan_id:$sid})-[r:REL]->(b:ArgusNode {scan_id:$sid}) "
                "RETURN a.id, b.id, r.rtype", {"sid": scan_id})
            while res.has_next():
                s, t, rel = res.get_next()
                edges.append({"source": s, "target": t, "type": rel})
    except Exception as exc:
        log.debug(f"kuzu fetch failed: {exc}")
        return None
    if not nodes:
        return None
    return {"nodes": list(nodes.values()), "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges)}, "source": "kuzu"}
