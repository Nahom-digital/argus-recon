/* ============================================================================
   Argus Recon — canvas force-directed graph
   Custom, dependency-free renderer for the crawl graph:
     Domain -> Subdomain -> Endpoint -> Request -> Field, IP/ASN, Secret, File.
   Grid-approximated repulsion keeps it smooth for thousands of nodes; the
   layout settles then freezes (no perpetual animation).
   ========================================================================== */
'use strict';

const NODE_TYPES = ['Domain', 'Subdomain', 'IP', 'ASN', 'Endpoint', 'JS',
  'Request', 'Field', 'Secret', 'File', 'External'];

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

  // adjacency for hover highlight
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
  let hover = null, selected = null, dragging = null, panning = false, locked = false;
  let alpha = 1, running = true, raf = null, started = false;

  function resize() {
    W = wrap.clientWidth; H = wrap.clientHeight;
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * DPR; canvas.height = H * DPR;
    canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }

  function visible(n) { return !hidden.has(n.type); }

  // ---- physics (grid-approximated repulsion + link springs + gravity) ----
  const CELL = 72;
  function tick() {
    const grid = new Map();
    for (const n of nodes) {
      if (!visible(n)) continue;
      const cx = Math.floor(n.x / CELL), cy = Math.floor(n.y / CELL);
      const key = cx + ',' + cy;
      (grid.get(key) || grid.set(key, []).get(key)).push(n);
    }
    // repulsion within neighboring cells
    for (const n of nodes) {
      if (!visible(n) || n.fixed) continue;
      const cx = Math.floor(n.x / CELL), cy = Math.floor(n.y / CELL);
      let fx = 0, fy = 0;
      for (let gx = cx - 1; gx <= cx + 1; gx++)
        for (let gy = cy - 1; gy <= cy + 1; gy++) {
          const cell = grid.get(gx + ',' + gy);
          if (!cell) continue;
          for (const m of cell) {
            if (m === n) continue;
            let dx = n.x - m.x, dy = n.y - m.y;
            let d2 = dx * dx + dy * dy;
            if (d2 < 0.01) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
            if (d2 > CELL * CELL * 4) continue;
            const f = 480 / d2;
            const d = Math.sqrt(d2);
            fx += (dx / d) * f; fy += (dy / d) * f;
          }
        }
      n.vx = (n.vx + fx * alpha) * 0.86;
      n.vy = (n.vy + fy * alpha) * 0.86;
    }
    // link springs
    for (const e of edges) {
      if (!visible(e.s) || !visible(e.t)) continue;
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const ideal = 38 + e.s.r + e.t.r;
      const f = (d - ideal) * 0.045 * alpha;
      const ox = (dx / d) * f, oy = (dy / d) * f;
      if (!e.s.fixed) { e.s.vx += ox; e.s.vy += oy; }
      if (!e.t.fixed) { e.t.vx -= ox; e.t.vy -= oy; }
    }
    // gravity to center + integrate
    for (const n of nodes) {
      if (!visible(n) || n.fixed || n === dragging) continue;
      n.vx -= n.x * 0.009 * alpha;
      n.vy -= n.y * 0.009 * alpha;
      n.x += Math.max(-25, Math.min(25, n.vx));
      n.y += Math.max(-25, Math.min(25, n.vy));
    }
    alpha *= 0.985;
    if (alpha < 0.02) { alpha = 0; running = false; }
  }

  // ---- rendering ----
  function worldToScreen(n) { return [n.x * k + tx, n.y * k + ty]; }
  function screenToWorld(px, py) { return [(px - tx) / k, (py - ty) / k]; }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const dim = hover || selected;
    const near = dim ? adj.get(dim.id) : null;

    // edges
    ctx.lineWidth = 1;
    for (const e of edges) {
      if (!visible(e.s) || !visible(e.t)) continue;
      const active = dim && (e.s === dim || e.t === dim);
      const [x1, y1] = worldToScreen(e.s), [x2, y2] = worldToScreen(e.t);
      ctx.strokeStyle = active
        ? withAlpha(e.s === dim ? e.t.color : e.s.color, 0.85)
        : withAlpha(cssVar('--faint') || '#999', dim ? 0.05 : 0.14);
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    }

    // nodes
    const labelZoom = k > 1.15;
    for (const n of nodes) {
      if (!visible(n)) continue;
      const [x, y] = worldToScreen(n);
      const isNear = dim && (n === dim || (near && near.has(n.id)));
      const faded = dim && !isNear;
      ctx.globalAlpha = faded ? 0.18 : 1;
      ctx.beginPath();
      ctx.arc(x, y, n.r * Math.min(1.6, Math.max(0.8, k * 0.9)), 0, 6.2832);
      ctx.fillStyle = n.color;
      ctx.fill();
      if (n === selected || n === hover) {
        ctx.lineWidth = 2; ctx.strokeStyle = cssVar('--ink'); ctx.stroke();
      } else if (n.type === 'Domain' || n.type === 'Subdomain') {
        ctx.lineWidth = 1.5; ctx.strokeStyle = withAlpha(cssVar('--bg'), 0.9); ctx.stroke();
      }
      // labels for important / hovered nodes
      const showLabel = !faded && (n === dim || n.type === 'Domain'
        || (n.type === 'Subdomain' && (labelZoom || n.deg > 6))
        || (isNear && labelZoom));
      if (showLabel) {
        const lbl = shortLabel(n);
        ctx.globalAlpha = faded ? 0.3 : 1;
        ctx.font = (n.type === 'Domain' ? '600 12px ' : '500 11px ') + "'Hanken Grotesk',sans-serif";
        const tw = ctx.measureText(lbl).width;
        const lx = x + n.r + 4, ly = y;
        ctx.fillStyle = withAlpha(cssVar('--surface'), 0.82);
        ctx.fillRect(lx - 2, ly - 7, tw + 4, 14);
        ctx.fillStyle = cssVar('--ink-2');
        ctx.textBaseline = 'middle';
        ctx.fillText(lbl, lx, ly);
      }
    }
    ctx.globalAlpha = 1;
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
    if (running) tick();
    draw();
    raf = requestAnimationFrame(frame);
  }

  // ---- hit testing ----
  function nodeAt(px, py) {
    let best = null, bestD = 16 * 16;
    for (const n of nodes) {
      if (!visible(n)) continue;
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
      tx += px - last.x; ty += py - last.y; last = { x: px, y: py }; return;
    }
    const n = nodeAt(px, py);
    if (n !== hover) {
      hover = n;
      canvas.style.cursor = n ? 'pointer' : 'grab';
      // hover only highlights adjacency — the card is shown on click (and locks)
    }
  }
  function onDown(ev) {
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    const n = nodeAt(px, py);
    if (n) {
      dragging = n; n.fixed = true;
      // Lock selection on first click; while locked, clicking a different node
      // does NOT change the card — only the card's × releases it.
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
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    const [wx, wy] = screenToWorld(px, py);
    const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    k = Math.max(0.15, Math.min(6, k * f));
    tx = px - wx * k; ty = py - wy * k;
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
      card.classList.remove('show'); selected = null; locked = false;
    });
    wireDecode(card);
  }
  function selectNode(n) { selected = n; locked = true; showCard(n); if (opts.onSelect) opts.onSelect(n); }

  // ---- fit ----
  function fit() {
    const vis = nodes.filter(visible);
    if (!vis.length) return;
    let minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    for (const n of vis) { minX = Math.min(minX, n.x); minY = Math.min(minY, n.y); maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y); }
    const gw = Math.max(1, maxX - minX), gh = Math.max(1, maxY - minY);
    k = Math.max(0.2, Math.min(2.2, Math.min(W / (gw + 90), H / (gh + 90))));
    tx = W / 2 - (minX + maxX) / 2 * k;
    ty = H / 2 - (minY + maxY) / 2 * k;
  }

  function reheat() { alpha = 1; running = true; }

  // ---- legend ----
  function buildLegend(elm) {
    if (!elm) return;
    const present = {};
    nodes.forEach(n => present[n.type] = (present[n.type] || 0) + 1);
    elm.innerHTML = NODE_TYPES.filter(t => present[t]).map(t =>
      `<span class="lg" data-t="${t}"><span class="sw" style="background:${typeColor(t)}"></span>
        ${t} <span class="n">${present[t]}</span></span>`).join('');
    elm.querySelectorAll('.lg').forEach(el => el.addEventListener('click', () => {
      const t = el.getAttribute('data-t');
      if (hidden.has(t)) { hidden.delete(t); el.classList.remove('off'); }
      else { hidden.add(t); el.classList.add('off'); }
      wake();
    }));
  }

  // ---- events ----
  canvas.addEventListener('mousemove', onMove);
  canvas.addEventListener('mousedown', onDown);
  window.addEventListener('mouseup', onUp);
  canvas.addEventListener('wheel', onWheel, { passive: false });
  canvas.addEventListener('mouseleave', () => { if (!selected) card && card.classList.remove('show'); hover = null; });
  window.addEventListener('themechange', () => {
    nodes.forEach(n => n.color = typeColor(n.type));
    const lg = document.getElementById('legend'); if (lg) buildLegend(lg);
  });
  const ro = new ResizeObserver(() => resize());
  ro.observe(wrap);

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
        else { fit(); frame(); resolve(); }
      })();
    });
  }
  if (opts.autoStart !== false) {
    started = true;
    for (let i = 0; i < 110; i++) tick();   // settle synchronously — small graph
    fit();
    frame();
  }

  return {
    fit, reheat, buildLegend, activate,
    stats: data.stats,
    focusHost(host) {
      const n = nodes.find(x => x.type === 'Subdomain' && x.label === host);
      if (n) { selected = n; locked = true; showCard(n); k = 1.4; tx = W / 2 - n.x * k; ty = H / 2 - n.y * k; wake(); }
    },
    destroy() { cancelAnimationFrame(raf); ro.disconnect(); },
  };
}

window.createGraph = createGraph;
