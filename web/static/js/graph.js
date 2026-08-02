/* ============================================================================
   Argus Recon · canvas force-directed graph
   Custom, dependency-free renderer for the crawl graph:
     Domain -> Subdomain -> Endpoint -> Request -> Field, IP/ASN, Secret, File.
   Grid-approximated repulsion keeps it smooth for thousands of nodes; the
   layout settles then freezes (no perpetual animation).
   ========================================================================== */
'use strict';

const NODE_TYPES = ['Domain', 'Subdomain', 'IP', 'ASN', 'Port', 'Endpoint', 'JS',
  'Request', 'Field', 'Secret', 'File', 'External'];

/* Per-page detail: these carry the bulk of a scan (thousands of nodes) and are
   only meaningful inside one host. They stay hidden · and their legend entry
   locked · until a specific subdomain is selected, so the "all hosts" view
   stays readable. The legend still reports their real totals, so the true size
   of the surface is always visible even while they are locked. */
const DETAIL_TYPES = new Set(['Endpoint', 'Request', 'Field', 'JS', 'File', 'External']);

function typeColor(t) {
  const key = '--n-' + t.toLowerCase();
  return cssVar(key) || cssVar('--n-endpoint') || '#888';
}

function createGraph(canvas, data, opts) {
  opts = opts || {};
  const wrap = canvas.parentElement;
  const ctx = canvas.getContext('2d');
  let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);

  // ---- model ----
  const nodes = data.nodes.map(n => ({
    ...n, x: 0, y: 0, vx: 0, vy: 0, deg: 0, r: 4,
    color: typeColor(n.type),
  }));
  const byId = new Map(nodes.map(n => [n.id, n]));
  const edges = data.edges.filter(e => byId.has(e.source) && byId.has(e.target))
    .map(e => ({ s: byId.get(e.source), t: byId.get(e.target), type: e.type }));
  edges.forEach(e => { e.s.deg++; e.t.deg++; });
  nodes.forEach(n => { n.r = 3.5 + Math.min(8, Math.sqrt(n.deg) * 1.7) + (n.type === 'Domain' ? 4 : 0); });

  /* ---- paged children ------------------------------------------------------
     A host with 156 subdomains, or a subdomain with 4,000 endpoints, drew every
     one of them at once: an unreadable ball of dots that also had to be laid out
     before the first frame. So a parent only ever shows PAGE_SIZE children of
     any one type. The rest sit behind a single "+N more" node · click it and the
     next hundred appear, click again for the hundred after that, until the last
     partial batch lands and the marker retires itself.

     It is per (parent, child type), so opening the subdomains of a domain does
     not also unpack its IPs, and each layer pages independently. */
  const PAGE_SIZE = window.GRAPH_PAGE_SIZE || 100;
  const pageGroups = [];

  function labelMore(g) {
    const left = g.children.length - g.shown;
    const pages = Math.ceil(g.children.length / PAGE_SIZE);
    const stage = Math.ceil(g.shown / PAGE_SIZE);
    g.more.label = `+${left} more ${g.type}`;
    g.more.props = {
      showing: `${g.shown} of ${g.children.length}`,
      stage: `${stage} of ${pages}`,
      next: `click to add ${Math.min(PAGE_SIZE, left)} more`,
    };
  }

  function buildPages() {
    const byParent = new Map();               // parentId -> Map(childType -> [node])
    for (const e of edges) {
      let g = byParent.get(e.s.id);
      if (!g) byParent.set(e.s.id, g = new Map());
      const list = g.get(e.t.type);
      if (list) list.push(e.t); else g.set(e.t.type, [e.t]);
    }
    const accent = cssVar('--accent') || '#bd5b3d';
    for (const [pid, byType] of byParent) {
      const parent = byId.get(pid);
      if (!parent) continue;
      for (const [type, children] of byType) {
        if (children.length <= PAGE_SIZE) continue;
        // stable order, so the same hundred come back on a reload
        children.sort((a, b) => String(a.label).localeCompare(String(b.label)));
        for (let i = PAGE_SIZE; i < children.length; i++) children[i].pageHidden = true;
        const more = {
          id: `more:${pid}:${type}`, type: 'More', childType: type,
          label: '', props: {}, x: 0, y: 0, vx: 0, vy: 0, deg: 1, r: 9,
          color: accent,
        };
        const group = { parent, type, children, shown: PAGE_SIZE, more };
        more.group = group;
        labelMore(group);
        nodes.push(more);
        byId.set(more.id, more);
        edges.push({ s: parent, t: more, type: 'MORE' });
        pageGroups.push(group);
      }
    }
  }

  /* Reveal the next batch behind a "+N more" marker. */
  function expandGroup(g) {
    if (!g || g.shown >= g.children.length) return false;
    const end = Math.min(g.children.length, g.shown + PAGE_SIZE);
    for (let i = g.shown; i < end; i++) g.children[i].pageHidden = false;
    g.shown = end;
    if (g.shown >= g.children.length) g.more.exhausted = true;
    else labelMore(g);
    if (selected === g.more && g.more.exhausted) {
      selected = null; locked = false; if (card) card.classList.remove('show');
    }
    seedNewlyVisible();
    refreshVis();
    if (legendEl) buildLegend(legendEl);
    wake();
    return true;
  }

  buildPages();

  // adjacency for hover highlight (built after paging so the markers are in it)
  const adj = new Map(nodes.map(n => [n.id, new Set()]));
  edges.forEach(e => { adj.get(e.s.id).add(e.t.id); adj.get(e.t.id).add(e.s.id); });

  // initial layout: domain centered, rest on a spiral
  const domain = nodes.find(n => n.type === 'Domain');
  nodes.forEach((n, i) => {
    const a = i * 2.399963;                // golden angle
    const rad = 30 + Math.sqrt(i) * 24;
    n.x = Math.cos(a) * rad; n.y = Math.sin(a) * rad;
  });
  if (domain) { domain.x = 0; domain.y = 0; domain.fixed = true; }

  // ---- view transform ----
  let k = 1, tx = 0, ty = 0;
  const hidden = new Set();               // hidden node types (legend)
  let hostVisibleIds = null;              // null = all hosts; Set = only these ids
  let detailUnlocked = false;             // DETAIL_TYPES shown only for one host
  let legendEl = null, fitPending = false;
  let hover = null, selected = null, dragging = null, panning = false, locked = false;
  let alpha = 1, running = true, raf = null, started = false, dirty = true;

  function resize() {
    W = wrap.clientWidth; H = wrap.clientHeight;
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * DPR; canvas.height = H * DPR;
    dirty = true;
    canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }

  function visible(n) {
    // A "+N more" marker follows the layer it belongs to: hidden while that
    // layer is locked or toggled off, and gone once its batch is exhausted.
    if (n.type === 'More') {
      if (n.exhausted) return false;
      if (DETAIL_TYPES.has(n.childType) && !detailUnlocked) return false;
      if (hidden.has(n.childType)) return false;
      return !(hostVisibleIds && !hostVisibleIds.has(n.id));
    }
    if (n.pageHidden) return false;              // still behind a "+N more"
    if (DETAIL_TYPES.has(n.type) && !detailUnlocked) return false;
    if (hidden.has(n.type)) return false;
    if (hostVisibleIds && !hostVisibleIds.has(n.id)) return false;
    return true;
  }

  /* Visibility only changes when a filter or a legend toggle changes it · never
     during the simulation. Resolve it once into a flag + a dense list so the
     per-frame loops don't re-test three sets per node and per edge. */
  const visList = [];
  function refreshVis() {
    visList.length = 0;
    for (const n of nodes) { n.vis = visible(n); if (n.vis) visList.push(n); }
  }

  // ---- physics (grid-approximated repulsion + link springs + gravity) ----
  const CELL = 72;
  // A crowded cell (right after a layer is revealed, everything starts stacked)
  // would make repulsion quadratic. Sample a bounded number of neighbours per
  // cell, rotating which ones each tick, and scale the force by what was
  // skipped · the crowd disperses just as fast, at a fixed cost per node.
  const CELL_SAMPLE = 10;
  const GKEY = (cx, cy) => (cx + 8192) * 65536 + (cy + 8192);   // numeric grid key
  let ticks = 0;
  function tick() {
    ticks++;
    const grid = new Map();
    for (const n of visList) {
      const key = GKEY(Math.floor(n.x / CELL), Math.floor(n.y / CELL));
      const cell = grid.get(key);
      if (cell) cell.push(n); else grid.set(key, [n]);
    }
    // repulsion within neighboring cells
    for (const n of visList) {
      if (n.fixed) continue;
      const cx = Math.floor(n.x / CELL), cy = Math.floor(n.y / CELL);
      let fx = 0, fy = 0;
      for (let gx = cx - 1; gx <= cx + 1; gx++)
        for (let gy = cy - 1; gy <= cy + 1; gy++) {
          const cell = grid.get(GKEY(gx, gy));
          if (!cell) continue;
          const len = cell.length;
          const take = len < CELL_SAMPLE ? len : CELL_SAMPLE;
          const w = len / take;                         // weight of the skipped ones
          let idx = take < len ? ticks % len : 0;
          for (let ci = 0; ci < take; ci++) {
            const m = cell[idx];
            if (++idx === len) idx = 0;
            if (m === n) continue;
            let dx = n.x - m.x, dy = n.y - m.y;
            let d2 = dx * dx + dy * dy;
            if (d2 < 0.01) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
            if (d2 > CELL * CELL * 4) continue;
            const f = 480 * w / d2;
            const d = Math.sqrt(d2);
            fx += (dx / d) * f; fy += (dy / d) * f;
          }
        }
      n.vx = (n.vx + fx * alpha) * 0.86;
      n.vy = (n.vy + fy * alpha) * 0.86;
    }
    // link springs
    for (const e of edges) {
      if (!e.s.vis || !e.t.vis) continue;
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const ideal = 38 + e.s.r + e.t.r;
      const f = (d - ideal) * 0.045 * alpha;
      const ox = (dx / d) * f, oy = (dy / d) * f;
      if (!e.s.fixed) { e.s.vx += ox; e.s.vy += oy; }
      if (!e.t.fixed) { e.t.vx -= ox; e.t.vy -= oy; }
    }
    // gravity to center + integrate
    for (const n of visList) {
      if (n.fixed || n === dragging) continue;
      n.vx -= n.x * 0.009 * alpha;
      n.vy -= n.y * 0.009 * alpha;
      n.x += Math.max(-25, Math.min(25, n.vx));
      n.y += Math.max(-25, Math.min(25, n.vy));
    }
    alpha *= 0.975;
    if (alpha < 0.02) {
      alpha = 0; running = false;
      dirty = true;                     // repaint once more, now with the edges
      // a filter change asked to be framed once the layout stopped moving
      if (fitPending && !dragging) { fitPending = false; fit(); }
    }
  }

  // ---- rendering ----
  function worldToScreen(n) { return [n.x * k + tx, n.y * k + ty]; }
  function screenToWorld(px, py) { return [(px - tx) / k, (py - ty) / k]; }

  /* Theme colours are read once per theme change. Reading a CSS variable forces
     a style recalc, so doing it per edge (thousands per frame) is what used to
     make a fully revealed graph crawl. */
  let TH = {};
  function readTheme() {
    const cs = getComputedStyle(document.documentElement);
    const g = key => (cs.getPropertyValue(key) || '').trim();
    const faint = g('--faint') || '#999';
    TH = {
      ink: g('--ink') || '#111', ink2: g('--ink-2') || '#333',
      edge: withAlpha(faint, 0.14), edgeDim: withAlpha(faint, 0.05),
      halo: withAlpha(g('--bg') || '#fff', 0.9),
      labelBg: withAlpha(g('--surface') || '#fff', 0.82),
    };
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const dim = hover || selected;
    const near = dim ? adj.get(dim.id) : null;

    // edges: everything unrelated to the focused node is stroked as one path.
    // On a big graph they are also the bulk of the raster cost, so while the
    // layout is still moving we draw nodes only · the mesh lands the moment it
    // comes to rest.
    const settling = running && visList.length > 600;
    ctx.lineWidth = 1;
    ctx.strokeStyle = dim ? TH.edgeDim : TH.edge;
    const lit = [];
    if (!settling) {
      ctx.beginPath();
      for (const e of edges) {
        if (!e.s.vis || !e.t.vis) continue;
        if (dim && (e.s === dim || e.t === dim)) { lit.push(e); continue; }
        ctx.moveTo(e.s.x * k + tx, e.s.y * k + ty);
        ctx.lineTo(e.t.x * k + tx, e.t.y * k + ty);
      }
      ctx.stroke();
      for (const e of lit) {
        ctx.strokeStyle = withAlpha(e.s === dim ? e.t.color : e.s.color, 0.85);
        ctx.beginPath();
        ctx.moveTo(e.s.x * k + tx, e.s.y * k + ty);
        ctx.lineTo(e.t.x * k + tx, e.t.y * k + ty);
        ctx.stroke();
      }
    }

    // nodes: bucketed by colour so each colour is a single fill
    const rk = Math.min(1.6, Math.max(0.42, k * 0.9));
    const labelZoom = k > 1.15;
    const buckets = new Map(), outlined = [], labelled = [];
    for (const n of visList) {
      const isNear = dim && (n === dim || (near && near.has(n.id)));
      const faded = dim && !isNear;
      const key = (faded ? 'f' : 'n') + n.color;
      let b = buckets.get(key);
      if (!b) buckets.set(key, b = { color: n.color, faded, list: [] });
      b.list.push(n);
      if (n === selected || n === hover) outlined.push(n);
      else if (!faded && (n.type === 'Domain' || n.type === 'Subdomain' || n.type === 'More'))
        outlined.push(n);
      // A "+N more" marker is always labelled · an unlabelled dot is not an
      // affordance, and the count is the whole message.
      if (!faded && (n === dim || n.type === 'Domain' || n.type === 'More'
        || (n.type === 'Subdomain' && (labelZoom || n.deg > 6))
        || (isNear && labelZoom))) labelled.push(n);
    }
    for (const b of buckets.values()) {
      ctx.globalAlpha = b.faded ? 0.18 : 1;
      ctx.fillStyle = b.color;
      ctx.beginPath();
      for (const n of b.list) {
        const x = n.x * k + tx, y = n.y * k + ty, r = n.r * rk;
        ctx.moveTo(x + r, y);
        ctx.arc(x, y, r, 0, 6.2832);
      }
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    // outlines: focused node, plus the halo that lifts hosts off the mesh
    for (const n of outlined) {
      const on = n === selected || n === hover;
      ctx.lineWidth = on ? 2 : 1.5;
      ctx.strokeStyle = on ? TH.ink : TH.halo;
      ctx.beginPath();
      ctx.arc(n.x * k + tx, n.y * k + ty, n.r * rk, 0, 6.2832);
      ctx.stroke();
    }

    // labels for important / hovered nodes
    ctx.textBaseline = 'middle';
    for (const n of labelled) {
      const lbl = shortLabel(n);
      ctx.font = (n.type === 'Domain' ? '600 12px ' : n.type === 'More' ? '600 11px '
        : '500 11px ') + "'Libertinus Serif',Georgia,serif";
      const tw = ctx.measureText(lbl).width;
      const lx = n.x * k + tx + n.r + 4, ly = n.y * k + ty;
      ctx.fillStyle = TH.labelBg;
      ctx.fillRect(lx - 2, ly - 7, tw + 4, 14);
      ctx.fillStyle = n.type === 'More' ? n.color : TH.ink2;
      ctx.fillText(lbl, lx, ly);
    }
  }

  function shortLabel(n) {
    let s = n.label || '';
    if (n.type === 'Subdomain' || n.type === 'IP' || n.type === 'ASN') return s;
    if (/^https?:\/\//.test(s)) { try { const u = new URL(s); s = u.pathname + u.search; } catch (e) {} }
    if (s.length > 30) s = s.slice(0, 29) + '…';
    return s;
  }

  function withAlpha(col, a) {
    col = (col || '').trim();
    if (col.startsWith('#')) {
      let h = col.slice(1);
      if (h.length === 3) h = h.split('').map(c => c + c).join('');
      const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16);
      return `rgba(${r},${g},${b},${a})`;
    }
    return col;
  }

  // ---- loop ----
  function frame() {
    if (running) { tick(); dirty = true; }
    if (dirty) { draw(); dirty = false; }
    raf = requestAnimationFrame(frame);
  }
  function mark() { dirty = true; }        // view changed without the physics

  // ---- hit testing ----
  function nodeAt(px, py) {
    let best = null, bestD = 16 * 16;
    for (const n of visList) {
      const [x, y] = worldToScreen(n);
      const d = (x - px) * (x - px) + (y - py) * (y - py);
      const rr = Math.max(8, n.r * k + 4);
      if (d < rr * rr && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }

  // ---- interaction ----
  let last = null;
  function onMove(ev) {
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    if (dragging) {
      const [wx, wy] = screenToWorld(px, py);
      dragging.x = wx; dragging.y = wy; dragging.vx = dragging.vy = 0;
      wake(); return;
    }
    if (panning && last) {
      tx += px - last.x; ty += py - last.y; last = { x: px, y: py }; mark(); return;
    }
    const n = nodeAt(px, py);
    if (n !== hover) {
      hover = n;
      canvas.style.cursor = n ? 'pointer' : 'grab';
      mark();
      // hover only highlights adjacency · the card is shown on click (and locks)
    }
  }
  function onDown(ev) {
    fitPending = false;                 // the user is framing it themselves now
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    const n = nodeAt(px, py);
    if (n && n.type === 'More') {
      // The marker is a control, not a finding: clicking it loads the next
      // batch instead of opening a card or starting a drag.
      expandGroup(n.group);
      return;
    }
    if (n) {
      dragging = n; n.fixed = true;
      // Lock selection on first click; while locked, clicking a different node
      // does NOT change the card · only the card's × releases it.
      if (!locked) selectNode(n);
    } else {
      panning = true; last = { x: px, y: py }; canvas.classList.add('grabbing');
    }
  }
  function onUp() {
    if (dragging && dragging.type !== 'Domain') dragging.fixed = false;
    dragging = null; panning = false; last = null; canvas.classList.remove('grabbing');
  }
  function onWheel(ev) {
    ev.preventDefault();
    fitPending = false;
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    const [wx, wy] = screenToWorld(px, py);
    const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    k = Math.max(0.04, Math.min(6, k * f));
    tx = px - wx * k; ty = py - wy * k;
    mark();
  }
  function wake() { if (alpha < 0.25) alpha = 0.25; running = true; }

  // ---- node card (rich, all node types, source-aware, decodable) ----
  const card = document.getElementById('nodeCard');
  function propRow(key, val) {
    if (key === 'sources') {
      const chips = String(val).split(',').map(s => s.trim()).filter(Boolean).map(sourceChip).join('');
      return chips ? `<div class="p"><span class="k">source</span><span class="v srcs">${chips}</span></div>` : '';
    }
    if (key === 'status') {
      return `<div class="p"><span class="k">status</span><span class="v"><span class="${statusClass(val)}">${esc(val)}</span></span></div>`;
    }
    if (key === 'severity' && val) {
      return `<div class="p"><span class="k">severity</span><span class="v"><span class="sev ${sevClass(val)}">${esc(val)}</span></span></div>`;
    }
    return `<div class="p"><span class="k">${esc(key)}</span><span class="v">${esc(val)}</span></div>`;
  }
  function showCard(n) {
    if (!card) return;
    const entries = Object.entries(n.props || {}).filter(([, v]) => v != null && v !== '');
    const rows = entries.map(([k, v]) => propRow(k, v)).join('');
    // decode affordance for the label and any encoded-looking prop value
    const decodeSource = [n.label, ...entries.map(([, v]) => v)].join(' ');
    const dec = decodeWidget(decodeSource, 'nc');
    card.innerHTML =
      `<button class="btn icon sm ghost nc-close" aria-label="close" title="release">${icon('x')}</button>
       <span class="nc-type"><span class="dot" style="background:${n.color}"></span>${esc(n.type)}
         <span class="nc-deg" title="connections">${icon('topology-star-3')}${n.deg}</span></span>
       <div class="nc-label">${esc(n.label)}${dec}</div>
       <div class="nc-props">${rows || '<span class="muted" style="font-size:12px">no attributes</span>'}</div>`;
    card.classList.add('show');
    card.querySelector('.nc-close').addEventListener('click', () => {
      card.classList.remove('show'); selected = null; locked = false; mark();
    });
    wireDecode(card);
  }
  function selectNode(n) { selected = n; locked = true; mark(); showCard(n); if (opts.onSelect) opts.onSelect(n); }

  // ---- fit ----
  function fit() {
    const vis = visList;
    if (!vis.length) return;
    let minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    for (const n of vis) { minX = Math.min(minX, n.x); minY = Math.min(minY, n.y); maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y); }
    const gw = Math.max(1, maxX - minX), gh = Math.max(1, maxY - minY);
    k = Math.max(0.04, Math.min(2.2, Math.min(W / (gw + 90), H / (gh + 90))));
    tx = W / 2 - (minX + maxX) / 2 * k;
    ty = H / 2 - (minY + maxY) / 2 * k;
    mark();
  }

  function reheat() { alpha = 1; running = true; }

  // ---- host / IP filter ----------------------------------------------------
  // Restrict the graph to the subtree of one or more hosts: each Subdomain node
  // and everything hanging off it (its endpoints, requests, fields, files, IPs,
  // secrets), keeping the Domain node as an anchor. Sibling subdomains reached
  // through a shared IP are not crossed into. An empty/absent list clears the
  // restriction and shows the whole graph.
  function computeVisible(hosts) {
    if (!hosts || !hosts.length) return null;
    const wanted = new Set(hosts);
    const subNodes = nodes.filter(n => n.type === 'Subdomain' && wanted.has(n.label));
    if (!subNodes.length) return new Set();         // unknown host(s) -> hide all
    const subIds = new Set(subNodes.map(n => n.id));
    const domNode = nodes.find(n => n.type === 'Domain');
    const keep = new Set(subIds);
    if (domNode) keep.add(domNode.id);
    const stack = [...subIds];
    while (stack.length) {
      const id = stack.pop();
      for (const nb of (adj.get(id) || [])) {
        if (keep.has(nb)) continue;
        const m = byId.get(nb);
        if (!m) continue;
        if (m.type === 'Domain') { keep.add(nb); continue; }        // anchor only
        if (m.type === 'Subdomain' && !subIds.has(nb)) continue;    // a sibling host (shared IP) · don't cross into it
        keep.add(nb); stack.push(nb);
      }
    }
    return keep;
  }

  /* A layer that has never been drawn still sits on the initial spiral, far
     from where it belongs. Walk out from the nodes already in place and drop
     each newcomer next to its parent, so unlocking a layer settles in a beat
     instead of flinging nodes across the canvas. */
  function seedNewlyVisible() {
    const queue = nodes.filter(n => n.seeded && visible(n)).map(n => n.id);
    const seen = new Set(queue);
    while (queue.length) {
      const anchor = byId.get(queue.shift());
      for (const nb of (adj.get(anchor.id) || [])) {
        if (seen.has(nb)) continue;
        const m = byId.get(nb);
        if (!m || !visible(m)) continue;
        seen.add(nb);
        if (!m.seeded) {
          // fan the newcomers around their parent instead of stacking them,
          // so the first tick starts from something close to laid out
          const i = anchor.spawn = (anchor.spawn || 0) + 1;
          const a = i * 2.399963;                       // golden angle
          const rad = 26 + Math.sqrt(i) * 16;
          m.x = anchor.x + Math.cos(a) * rad;
          m.y = anchor.y + Math.sin(a) * rad;
          m.vx = m.vy = 0;
          m.seeded = true;
        }
        queue.push(nb);
      }
    }
    for (const n of nodes) if (visible(n)) n.seeded = true;
  }

  /* setFilter({hosts, detail}) · the single entry point the dashboard uses.
     `detail` unlocks DETAIL_TYPES; it is only ever true when exactly one
     subdomain is selected. */
  function setFilter(f) {
    f = f || {};
    const wantDetail = !!f.detail;
    const justUnlocked = wantDetail && !detailUnlocked;
    detailUnlocked = wantDetail;
    // reveal the detail layers on unlock, even if they were toggled off before
    if (justUnlocked) DETAIL_TYPES.forEach(t => hidden.delete(t));
    hostVisibleIds = computeVisible(f.hosts);
    if (selected && !visible(selected)) {
      selected = null; locked = false; if (card) card.classList.remove('show');
    }
    seedNewlyVisible();
    refreshVis();
    if (legendEl) buildLegend(legendEl);
    reheat();                                    // re-cluster the visible set
    // frame it early so the change is legible straight away, then again for
    // real once the layout has come to rest (see tick())
    setTimeout(() => { if (!dragging) fit(); }, 400);
    fitPending = true;
  }

  function filterHost(host) { setFilter({ hosts: host ? [host] : null, detail: !!host }); }

  // ---- legend ----
  // Counts are always the scan's real totals · locked layers still report how
  // much is there, they just are not drawn until a subdomain is picked. When a
  // view budget trimmed a layer the server sends stats.totals alongside what it
  // actually shipped, so the legend keeps reporting the true size of the surface
  // and says how much of it is on screen.
  const TOTALS = (data.stats && data.stats.totals) || null;
  function buildLegend(elm) {
    if (!elm) return;
    legendEl = elm;
    const present = {};
    nodes.forEach(n => present[n.type] = (present[n.type] || 0) + 1);
    const total = t => (TOTALS && TOTALS[t] != null ? TOTALS[t] : present[t]);
    const types = NODE_TYPES.filter(t => present[t] || (TOTALS && TOTALS[t]));
    const anyLocked = types.some(t => DETAIL_TYPES.has(t)) && !detailUnlocked;
    elm.innerHTML = types.map(t => {
      const lock = DETAIL_TYPES.has(t) && !detailUnlocked;
      const off = !lock && hidden.has(t);
      const partial = total(t) > (present[t] || 0);
      const tip = lock ? `${total(t)} ${t} nodes · select a subdomain to activate this layer`
        : partial ? `${total(t)} ${t} nodes in this scan · ${present[t] || 0} drawn (view budget)`
          : `${total(t)} ${t} nodes · click to ${off ? 'show' : 'hide'}`;
      return `<span class="lg${lock ? ' locked' : ''}${off ? ' off' : ''}" data-t="${t}" title="${tip}">
        ${lock ? `<svg class="ic lk" aria-hidden="true"><use href="#i-lock"></use></svg>`
        : `<span class="sw" style="background:${typeColor(t)}"></span>`}
        ${t} <span class="n">${total(t)}${partial ? '*' : ''}</span></span>`;
    }).join('') + (anyLocked
      ? `<span class="lg-hint" id="lgHint"><svg class="ic" aria-hidden="true"><use href="#i-filter"></use></svg>
          select a subdomain to reveal endpoints, files &amp; fields</span>` : '');
    elm.querySelectorAll('.lg').forEach(el => el.addEventListener('click', () => {
      const t = el.getAttribute('data-t');
      if (DETAIL_TYPES.has(t) && !detailUnlocked) return flashHint();
      if (hidden.has(t)) { hidden.delete(t); el.classList.remove('off'); }
      else { hidden.add(t); el.classList.add('off'); }
      refreshVis();
      wake();
    }));
    const hint = elm.querySelector('#lgHint');
    if (hint) hint.addEventListener('click', flashHint);
  }

  /* A locked layer was clicked · point at the control that unlocks it. */
  function flashHint() {
    const hint = legendEl && legendEl.querySelector('#lgHint');
    if (hint) { hint.classList.remove('flash'); void hint.offsetWidth; hint.classList.add('flash'); }
    if (opts.onLocked) opts.onLocked();
  }

  // ---- events ----
  canvas.addEventListener('mousemove', onMove);
  canvas.addEventListener('mousedown', onDown);
  window.addEventListener('mouseup', onUp);
  canvas.addEventListener('wheel', onWheel, { passive: false });
  canvas.addEventListener('mouseleave', () => { if (!selected) card && card.classList.remove('show'); hover = null; mark(); });
  window.addEventListener('themechange', () => {
    readTheme();
    nodes.forEach(n => n.color = typeColor(n.type));
    const lg = document.getElementById('legend'); if (lg) buildLegend(lg);
    mark();                             // repaint the settled graph in the new theme
  });
  const ro = new ResizeObserver(() => resize());
  ro.observe(wrap);

  readTheme();
  refreshVis();
  resize();

  // Chunked warm-up so big graphs (module 6) settle without freezing the tab.
  function activate(onProgress) {
    if (started) return Promise.resolve();
    started = true;
    return new Promise(resolve => {
      let done = 0; const total = 110;
      (function chunk() {
        const end = Math.min(total, done + 10);
        for (; done < end; done++) tick();
        if (onProgress) onProgress(done / total);
        if (done < total) requestAnimationFrame(chunk);
        else { markSeeded(); fit(); frame(); resolve(); }
      })();
    });
  }
  /* whatever was laid out up front is "in place" · later layers are seeded
     relative to it */
  function markSeeded() { for (const n of visList) n.seeded = true; }

  if (opts.autoStart !== false) {
    started = true;
    for (let i = 0; i < 110; i++) tick();   // settle synchronously · small graph
    markSeeded();
    fit();
    frame();
  }

  return {
    fit, reheat, buildLegend, activate, filterHost, setFilter,
    stats: data.stats,
    detailUnlocked: () => detailUnlocked,
    /* What is currently paged and how far each group has been opened. */
    pages: () => pageGroups.map(g => ({
      parent: g.parent.label, type: g.type,
      shown: g.shown, total: g.children.length,
      visible: visible(g.more),
    })),
    /* Open the next batch for a group · the same thing clicking its marker
       does, reachable without a pointer. */
    expandPage(parentLabel, type) {
      const g = pageGroups.find(x => x.parent.label === parentLabel && x.type === type);
      return expandGroup(g);
    },
    focusHost(host) {
      const n = nodes.find(x => x.type === 'Subdomain' && x.label === host);
      if (n) { selected = n; locked = true; showCard(n); k = 1.4; tx = W / 2 - n.x * k; ty = H / 2 - n.y * k; wake(); }
    },
    destroy() { cancelAnimationFrame(raf); ro.disconnect(); },
  };
}

window.createGraph = createGraph;
window.GRAPH_DETAIL_TYPES = DETAIL_TYPES;
