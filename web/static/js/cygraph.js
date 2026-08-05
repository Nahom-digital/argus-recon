/* ============================================================================
   Argus Recon · Cytoscape.js graph engine (alternative to the canvas renderer)

   Same {nodes, edges} model and the same public interface the canvas renderer
   exposes (fit / reheat / buildLegend / activate / setFilter / focusHost /
   destroy), so scan.js can swap one for the other behind a single GRAPH handle.

   Cytoscape is built for exactly this: nodes/edges, click-to-expand, layouts
   that scale. It renders with the fCoSE force layout in the "gene-gene" style:
   solid coloured nodes, curved edges, fast and readable at thousands of nodes.

   The heavy vendor scripts are loaded on demand (loadCyEngine) the first time
   the user selects this engine, so the canvas default costs nothing extra.
   ========================================================================== */
'use strict';

/* Load the vendored cytoscape + fcose bundles once, in dependency order
   (layoutBase -> coseBase -> fcose; cytoscape). Returns a promise that
   resolves when cytoscape is registered and ready. */
let _cyReady = null;
function loadCyEngine(base) {
  if (_cyReady) return _cyReady;
  const v = (f) => `${base}/static/js/vendor/${f}`;
  const chain = [
    'cytoscape.min.js',
    'layout-base.js',
    'cose-base.js',
    'cytoscape-fcose.js',
  ];
  _cyReady = chain.reduce((p, file) => p.then(() => loadScript(v(file))), Promise.resolve())
    .then(() => {
      if (window.cytoscape && window.cytoscapeFcose) {
        try { window.cytoscape.use(window.cytoscapeFcose); } catch (e) {}
      }
      return window.cytoscape;
    });
  return _cyReady;
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-src="${src}"]`);
    if (existing) { existing.dataset.loaded ? resolve() : existing.addEventListener('load', resolve); return; }
    const s = document.createElement('script');
    s.src = src; s.async = false; s.dataset.src = src;
    s.addEventListener('load', () => { s.dataset.loaded = '1'; resolve(); });
    s.addEventListener('error', () => reject(new Error('failed to load ' + src)));
    document.head.appendChild(s);
  });
}

const CY_DETAIL_TYPES = window.GRAPH_DETAIL_TYPES ||
  new Set(['Endpoint', 'Request', 'Field', 'JS', 'File', 'External']);
const CY_TYPE_ORDER = ['Domain', 'Subdomain', 'IP', 'ASN', 'Port', 'Endpoint', 'JS',
  'Request', 'Field', 'Secret', 'File', 'External'];

function cyTypeColor(t) {
  const cs = getComputedStyle(document.documentElement);
  return (cs.getPropertyValue('--n-' + t.toLowerCase()) || '').trim()
    || (cs.getPropertyValue('--n-endpoint') || '').trim() || '#888';
}

function createCyGraph(container, data, opts) {
  opts = opts || {};
  const cytoscape = window.cytoscape;

  // ---- model -> cytoscape elements ----
  const present = {};
  data.nodes.forEach(n => { present[n.type] = (present[n.type] || 0) + 1; });
  const ids = new Set(data.nodes.map(n => n.id));
  const elements = [];
  const deg = {};
  data.edges.forEach(e => { if (ids.has(e.source) && ids.has(e.target)) { deg[e.source] = (deg[e.source] || 0) + 1; deg[e.target] = (deg[e.target] || 0) + 1; } });
  data.nodes.forEach(n => {
    elements.push({
      data: {
        id: n.id, ntype: n.type, label: n.label,
        short: shortCyLabel(n), props: n.props || {},
        deg: deg[n.id] || 0, color: cyTypeColor(n.type),
      },
      classes: n.type,
    });
  });
  data.edges.forEach((e, i) => {
    if (!ids.has(e.source) || !ids.has(e.target)) return;
    elements.push({ data: { id: 'e' + i, source: e.source, target: e.target, rel: e.type } });
  });

  /* ---- paged children (mirrors the canvas engine) --------------------------
     A parent shows at most CY_PAGE_SIZE children of any one type; the rest wait
     behind a single "+N more" node that loads the next batch when tapped. Same
     rule, same batch size, so switching engines does not change what you see. */
  const CY_PAGE_SIZE = window.GRAPH_PAGE_SIZE || 100;
  const byIdRaw = new Map(data.nodes.map(n => [n.id, n]));
  const pageHidden = new Set();          // node ids waiting behind a marker
  const groups = new Map();              // marker id -> {children, shown, type, parent}

  (function buildCyPages() {
    const byParent = new Map();
    data.edges.forEach(e => {
      if (!ids.has(e.source) || !ids.has(e.target)) return;
      let g = byParent.get(e.source);
      if (!g) byParent.set(e.source, g = new Map());
      const t = byIdRaw.get(e.target);
      const list = g.get(t.type);
      if (list) list.push(t); else g.set(t.type, [t]);
    });
    const accent = (getComputedStyle(document.documentElement)
      .getPropertyValue('--accent') || '#bd5b3d').trim();
    byParent.forEach((byType, pid) => {
      byType.forEach((children, type) => {
        if (children.length <= CY_PAGE_SIZE) return;
        children.sort((a, b) => String(a.label).localeCompare(String(b.label)));
        for (let i = CY_PAGE_SIZE; i < children.length; i++) pageHidden.add(children[i].id);
        const mid = `more:${pid}:${type}`;
        const group = { children, shown: CY_PAGE_SIZE, type, parent: pid, id: mid };
        groups.set(mid, group);
        elements.push({
          data: {
            id: mid, ntype: 'More', childType: type, label: moreLabel(group),
            short: moreLabel(group), props: {}, deg: 6, color: accent,
          },
          classes: 'More',
        });
        elements.push({ data: { id: 'e-' + mid, source: pid, target: mid, rel: 'MORE' } });
      });
    });
  })();

  function moreLabel(g) {
    return `+${g.children.length - g.shown} more ${g.type}`;
  }

  const cy = cytoscape({
    container,
    elements,
    wheelSensitivity: 0.25,
    pixelRatio: Math.min(window.devicePixelRatio || 1, 2),
    textureOnViewport: elements.length > 1500,
    hideEdgesOnViewport: elements.length > 2500,
    style: styleFor(),
    layout: { name: 'preset' },        // real layout runs in activate()/reheat()
  });

  // ---- state ----
  let hostVisibleIds = null;           // null = all hosts, else Set of ids to keep
  let detailUnlocked = false;
  const hidden = new Set();            // legend-toggled-off types
  let legendEl = null, selected = null, started = false;

  function isDetailLocked(t) { return CY_DETAIL_TYPES.has(t) && !detailUnlocked; }

  function applyVisibility() {
    cy.batch(() => {
      cy.nodes().forEach(n => {
        const t = n.data('ntype');
        const id = n.id();
        let show;
        if (t === 'More') {
          // the marker follows the layer it pages, and retires when spent
          const ct = n.data('childType');
          const g = groups.get(id);
          show = !!g && g.shown < g.children.length
            && !isDetailLocked(ct) && !hidden.has(ct)
            && (!hostVisibleIds || hostVisibleIds.has(id));
        } else {
          show = !pageHidden.has(id) && !isDetailLocked(t) && !hidden.has(t)
            && (!hostVisibleIds || hostVisibleIds.has(id));
        }
        n.style('display', show ? 'element' : 'none');
      });
    });
  }

  /* Reveal the next batch behind a marker, then re-run the layout so the new
     nodes find room rather than landing on top of their siblings. */
  function expandGroup(id) {
    const g = groups.get(id);
    if (!g || g.shown >= g.children.length) return;
    const end = Math.min(g.children.length, g.shown + CY_PAGE_SIZE);
    for (let i = g.shown; i < end; i++) pageHidden.delete(g.children[i].id);
    g.shown = end;
    const marker = cy.getElementById(id);
    if (marker && marker.length) {
      marker.data('label', moreLabel(g));
      marker.data('short', moreLabel(g));
    }
    applyVisibility();
    runLayout(true);
  }

  // ---- fcose layout ----
  function fcoseOptions(animate) {
    const n = cy.nodes(':visible').length;
    return {
      name: 'fcose',
      quality: n > 1500 ? 'draft' : 'default',
      animate: !!animate && n <= 800,
      animationDuration: 500,
      randomize: true,
      fit: true,
      padding: 30,
      nodeSeparation: 90,
      idealEdgeLength: 70,
      nodeRepulsion: 6500,
      gravity: 0.25,
      gravityRange: 3.2,
      packComponents: true,
    };
  }
  function runLayout(animate) {
    const eles = cy.elements(':visible');
    if (!eles.length) return;
    try { eles.layout(fcoseOptions(animate)).run(); }
    catch (e) { cy.layout({ name: 'cose', animate: false }).run(); }
  }

  // ---- interaction ----
  cy.on('tap', 'node', evt => {
    const n = evt.target;
    if (n.data('ntype') === 'More') { expandGroup(n.id()); return; }
    if (isDetailLocked(n.data('ntype'))) { if (opts.onLocked) opts.onLocked(); return; }
    select(n);
    if (opts.onSelect) opts.onSelect({ type: n.data('ntype'), label: n.data('label') });
  });
  cy.on('tap', evt => { if (evt.target === cy) clearSelect(); });

  // Labels are hidden on the dense detail nodes by default (a crowd of dots
  // stays legible as structure); pointing at a node reveals its name, the way
  // the canvas engine and neo4j do. Domain/Subdomain anchors stay labelled.
  cy.on('mouseover', 'node', evt => evt.target.addClass('hl'));
  cy.on('mouseout', 'node', evt => evt.target.removeClass('hl'));

  function select(n) {
    clearSelect();
    selected = n;
    cy.elements().addClass('faded');
    n.removeClass('faded').addClass('lit');
    n.neighborhood().removeClass('faded');
    n.connectedEdges().removeClass('faded').addClass('lit');
    showCard(n);
  }
  function clearSelect() {
    selected = null;
    cy.elements().removeClass('faded lit');
    const card = document.getElementById('nodeCard');
    if (card) card.classList.remove('show');
  }

  const card = document.getElementById('nodeCard');
  function showCard(n) {
    if (!card) return;
    const props = n.data('props') || {};
    const entries = Object.entries(props).filter(([, v]) => v != null && v !== '');
    const rows = entries.map(([k, v]) => cyPropRow(k, v)).join('');
    const dec = (window.decodeWidget)
      ? decodeWidget([n.data('label'), ...entries.map(([, v]) => v)].join(' '), 'nc') : '';
    card.innerHTML =
      `<button class="btn icon sm ghost nc-close" aria-label="close" title="release">${cyIcon('x')}</button>
       <span class="nc-type"><span class="dot" style="background:${n.data('color')}"></span>${cyEsc(n.data('ntype'))}
         <span class="nc-deg" title="connections">${cyIcon('topology-star-3')}${n.data('deg')}</span></span>
       <div class="nc-label">${cyEsc(n.data('label'))}${dec}</div>
       <div class="nc-props">${rows || '<span class="muted" style="font-size:12px">no attributes</span>'}</div>`;
    card.classList.add('show');
    card.querySelector('.nc-close').addEventListener('click', clearSelect);
    if (window.wireDecode) wireDecode(card);
  }

  // ---- public interface (mirrors the canvas renderer) ----
  function activate(onProgress) {
    if (started) return Promise.resolve();
    started = true;
    applyVisibility();
    return new Promise(resolve => {
      // fcose is synchronous once kicked; report coarse progress around it so
      // the same activation UI works for both engines.
      if (onProgress) onProgress(0.15);
      requestAnimationFrame(() => {
        runLayout(false);
        if (onProgress) onProgress(1);
        cy.fit(undefined, 40);
        resolve();
      });
    });
  }

  function buildLegend(elm) {
    if (!elm) return;
    legendEl = elm;
    const types = CY_TYPE_ORDER.filter(t => present[t]);
    const anyLocked = types.some(t => CY_DETAIL_TYPES.has(t)) && !detailUnlocked;
    elm.innerHTML = types.map(t => {
      const lock = CY_DETAIL_TYPES.has(t) && !detailUnlocked;
      const off = !lock && hidden.has(t);
      const tip = lock ? `${present[t]} ${t} nodes · select a subdomain to activate this layer`
        : `${present[t]} ${t} nodes · click to ${off ? 'show' : 'hide'}`;
      return `<span class="lg${lock ? ' locked' : ''}${off ? ' off' : ''}" data-t="${t}" title="${tip}">
        ${lock ? `<svg class="ic lk" aria-hidden="true"><use href="#i-lock"></use></svg>`
        : `<span class="sw" style="background:${cyTypeColor(t)}"></span>`}
        ${t} <span class="n">${present[t]}</span></span>`;
    }).join('') + (anyLocked
      ? `<span class="lg-hint" id="lgHint"><svg class="ic" aria-hidden="true"><use href="#i-filter"></use></svg>
          select a subdomain to reveal endpoints, files &amp; fields</span>` : '');
    elm.querySelectorAll('.lg').forEach(el => el.addEventListener('click', () => {
      const t = el.getAttribute('data-t');
      if (CY_DETAIL_TYPES.has(t) && !detailUnlocked) { if (opts.onLocked) opts.onLocked(); return; }
      if (hidden.has(t)) { hidden.delete(t); el.classList.remove('off'); }
      else { hidden.add(t); el.classList.add('off'); }
      applyVisibility();
    }));
  }

  function setFilter(f) {
    f = f || {};
    const wantDetail = !!f.detail;
    const justUnlocked = wantDetail && !detailUnlocked;
    detailUnlocked = wantDetail;
    if (justUnlocked) CY_DETAIL_TYPES.forEach(t => hidden.delete(t));
    hostVisibleIds = computeVisible(f.hosts, f.ip || null);
    if (selected && hostVisibleIds && !hostVisibleIds.has(selected.id())) clearSelect();
    applyVisibility();
    if (legendEl) buildLegend(legendEl);
    runLayout(true);
    setTimeout(() => cy.fit(cy.elements(':visible'), 40), 520);
  }

  /* Same subtree rule as the canvas renderer: keep each selected Subdomain and
     everything hanging off it, with the Domain as an anchor; don't cross into a
     sibling subdomain reached only through a shared IP. And, when an address is
     held, keep that address alone at the IP layer · the other addresses go, and
     their Port and ASN nodes (only reachable through an address) go with them. */
  function computeVisible(hosts, ip) {
    const wanted = new Set(hosts || []);
    if (!wanted.size && !ip) return null;
    const subs = cy.nodes().filter(n => n.data('ntype') === 'Subdomain' && wanted.has(n.data('label')));
    const ipNode = ip
      ? cy.nodes().filter(n => n.data('ntype') === 'IP' && n.data('label') === ip)
      : null;
    if (!subs.length && !(ipNode && ipNode.length)) return new Set();
    const subIds = new Set(subs.map(n => n.id()));
    const keep = new Set(subIds);
    const dom = cy.nodes('.Domain'); if (dom.length) keep.add(dom.id());
    const stack = [...subIds];
    if (ipNode && ipNode.length) { keep.add(ipNode[0].id()); stack.push(ipNode[0].id()); }
    while (stack.length) {
      const id = stack.pop();
      cy.getElementById(id).neighborhood('node').forEach(m => {
        const mid = m.id();
        if (keep.has(mid)) return;
        const t = m.data('ntype');
        if (t === 'Domain') { keep.add(mid); return; }
        if (t === 'Subdomain' && !subIds.has(mid)) return;
        if (t === 'IP' && ip && m.data('label') !== ip) return;
        if (t === 'More' && ip && m.data('childType') === 'IP') return;
        keep.add(mid); stack.push(mid);
      });
    }
    return keep;
  }

  function focusHost(host) {
    const n = cy.nodes().filter(x => x.data('ntype') === 'Subdomain' && x.data('label') === host);
    if (n.length) { select(n[0]); cy.animate({ center: { eles: n }, zoom: 1.4 }, { duration: 300 }); }
  }

  // theme repaint: recolour by type
  const onTheme = () => {
    cy.batch(() => cy.nodes().forEach(n => n.data('color', cyTypeColor(n.data('ntype')))));
    cy.style(styleFor());
    if (legendEl) buildLegend(legendEl);
  };
  window.addEventListener('themechange', onTheme);

  return {
    fit: () => cy.fit(cy.elements(':visible'), 40),
    reheat: () => runLayout(true),
    buildLegend, activate, setFilter,
    stats: data.stats,
    detailUnlocked: () => detailUnlocked,
    focusHost,
    /* Same reading as the canvas engine: what the filters left on screen. */
    visibleCounts() {
      const out = {};
      cy.nodes().forEach(n => {
        if (n.style('display') === 'none') return;
        const t = n.data('ntype');
        out[t] = (out[t] || 0) + 1;
      });
      return out;
    },
    /* Same paging surface as the canvas engine, so both behave alike. */
    pages: () => [...groups.entries()].map(([id, g]) => ({
      parent: g.parent, type: g.type, shown: g.shown, total: g.children.length,
      visible: cy.getElementById(id).style('display') === 'element',
    })),
    expandPage(parentId, type) {
      const hit = [...groups.entries()].find(([, g]) => g.parent === parentId && g.type === type);
      if (hit) expandGroup(hit[0]);
      return !!hit;
    },
    destroy() {
      window.removeEventListener('themechange', onTheme);
      try { cy.destroy(); } catch (e) {}
    },
  };
}

/* ---- stylesheet ----------------------------------------------------------- */
/* fCoSE "gene-gene" look: solid coloured discs, curved faint edges.

   Node labels are OFF by default. A large graph packs hundreds of dots close
   together, and drawing every name turns it into an unreadable wall of
   overlapping text. So only the few structural anchors (Domain, Subdomain)
   carry a permanent label; every other node reveals its name on hover (class
   `hl`) or when selected (class `lit`), the same read as the canvas engine and
   neo4j. */
function styleFor() {
  return [
    { selector: 'node', style: {
        'background-color': 'data(color)', 'label': '',
        'width': 'mapData(deg, 0, 40, 14, 46)', 'height': 'mapData(deg, 0, 40, 14, 46)',
        'font-size': 9, 'font-family': 'Libertinus Serif, Georgia, serif',
        'color': cyInk(), 'text-valign': 'center', 'text-halign': 'right',
        'text-margin-x': 3, 'min-zoomed-font-size': 8,
        'text-background-color': cyBg(), 'text-background-opacity': 0.82,
        'text-background-padding': 2, 'text-background-shape': 'roundrectangle', 'border-width': 0 } },
    // structural anchors are few, so they stay labelled at all times
    { selector: 'node.Domain', style: {
        'width': 40, 'height': 40, 'font-size': 12, 'font-weight': 'bold', 'label': 'data(short)' } },
    { selector: 'node.Subdomain', style: { 'shape': 'round-rectangle', 'label': 'data(short)' } },
    // "+N more" markers are controls: always labelled, always legible
    { selector: 'node.More', style: {
        'shape': 'round-rectangle', 'label': 'data(short)', 'width': 18, 'height': 18,
        'font-size': 10, 'font-weight': 'bold', 'text-halign': 'right',
        'text-background-opacity': 0.95, 'z-index': 20 } },
    // hovered node reveals its name and lifts above its neighbours
    { selector: 'node.hl', style: {
        'label': 'data(short)', 'z-index': 30, 'text-background-opacity': 0.95 } },
    { selector: 'edge', style: {
        // line-color carries its own alpha (tuned per theme in app.css), so the
        // edge opacity stays at 1 here · the old flat 0.5 washed the faint stroke
        // out until the mesh was almost invisible on both light and dark.
        'width': 1, 'line-color': cyEdge(), 'curve-style': 'haystack',
        'haystack-radius': 0.4, 'opacity': 1 } },
    { selector: '.faded', style: { 'opacity': 0.12 } },
    // selected node keeps its label and gets an outline
    { selector: 'node.lit', style: {
        'label': 'data(short)', 'z-index': 30, 'border-width': 2, 'border-color': cyInk() } },
    { selector: 'edge.lit', style: { 'line-color': '#e0b341', 'width': 2, 'opacity': 1, 'curve-style': 'bezier' } },
  ];
}

function cyInk() { return (getComputedStyle(document.documentElement).getPropertyValue('--ink') || '#111').trim(); }
function cyBg() { return (getComputedStyle(document.documentElement).getPropertyValue('--surface') || '#fff').trim(); }
function cyEdge() {
  const cs = getComputedStyle(document.documentElement);
  return (cs.getPropertyValue('--graph-edge') || '').trim()
    || (cs.getPropertyValue('--faint') || '#bbb').trim();
}

function shortCyLabel(n) {
  let s = n.label || '';
  if (n.type === 'Subdomain' || n.type === 'IP' || n.type === 'ASN') return s;
  if (/^https?:\/\//.test(s)) { try { const u = new URL(s); s = u.pathname + u.search; } catch (e) {} }
  return s.length > 28 ? s.slice(0, 27) + '…' : s;
}

/* tiny local helpers so this file works whether or not app.js globals exist */
function cyEsc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function cyIcon(name) { return (window.icon ? window.icon(name) : `<svg class="ic"><use href="#i-${name}"></use></svg>`); }
function cyPropRow(key, val) {
  if (window.statusClass && key === 'status')
    return `<div class="p"><span class="k">status</span><span class="v"><span class="${statusClass(val)}">${cyEsc(val)}</span></span></div>`;
  if (window.sevClass && key === 'severity' && val)
    return `<div class="p"><span class="k">severity</span><span class="v"><span class="sev ${sevClass(val)}">${cyEsc(val)}</span></span></div>`;
  if (key === 'sources' && window.sourceChip) {
    const chips = String(val).split(',').map(s => s.trim()).filter(Boolean).map(sourceChip).join('');
    return chips ? `<div class="p"><span class="k">source</span><span class="v srcs">${chips}</span></div>` : '';
  }
  return `<div class="p"><span class="k">${cyEsc(key)}</span><span class="v">${cyEsc(val)}</span></div>`;
}

window.createCyGraph = createCyGraph;
window.loadCyEngine = loadCyEngine;
