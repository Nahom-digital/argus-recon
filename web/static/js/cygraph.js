/* ============================================================================
   Argus Recon — Cytoscape.js graph engine (alternative to the canvas renderer)

   Same {nodes, edges} model and the same public interface the canvas renderer
   exposes (fit / reheat / buildLegend / activate / setFilter / focusHost /
   destroy), so scan.js can swap one for the other behind a single GRAPH handle.

   Cytoscape is built for exactly this — nodes/edges, click-to-expand, layouts
   that scale — and it ships two looks the user can switch between:

     * 'fcose' — the fCoSE force layout in the "gene-gene" style: solid coloured
       nodes, curved edges. Fast and readable at thousands of nodes.
     * 'sbgn'  — the SBGN stylesheet (cytoscape-sbgn-stylesheet): each Argus node
       type is mapped to an SBGN glyph class (macromolecule, simple chemical,
       process, …) and drawn with that notation's shapes, still laid out by fCoSE.

   The heavy vendor scripts are loaded on demand (loadCyEngine) the first time
   the user selects this engine, so the canvas default costs nothing extra.
   ========================================================================== */
'use strict';

/* Argus node type -> SBGN glyph class. SBGN has a fixed vocabulary of shapes;
   this maps the recon graph onto the closest glyphs so the notation is
   meaningful rather than decorative. */
const SBGN_CLASS = {
  Domain: 'compartment',
  Subdomain: 'macromolecule',
  IP: 'simple chemical',
  ASN: 'nucleic acid feature',
  Port: 'simple chemical',
  Endpoint: 'process',
  JS: 'macromolecule multimer',
  Request: 'process',
  Field: 'unspecified entity',
  Secret: 'perturbing agent',
  File: 'nucleic acid feature',
  External: 'source and sink',
};

/* Load the vendored cytoscape + fcose + sbgn bundles once, in dependency order
   (layoutBase -> coseBase -> fcose; cytoscape; sbgn). Returns a promise that
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
    'cytoscape-sbgn-stylesheet.js',
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
  let style = opts.style === 'sbgn' ? 'sbgn' : 'fcose';

  // ---- model -> cytoscape elements ----
  const present = {};
  data.nodes.forEach(n => { present[n.type] = (present[n.type] || 0) + 1; });
  const ids = new Set(data.nodes.map(n => n.id));
  const elements = [];
  const deg = {};
  data.edges.forEach(e => { if (ids.has(e.source) && ids.has(e.target)) { deg[e.source] = (deg[e.source] || 0) + 1; deg[e.target] = (deg[e.target] || 0) + 1; } });
  data.nodes.forEach(n => {
    const glyph = SBGN_CLASS[n.type] || 'unspecified entity';
    elements.push({
      data: {
        id: n.id, ntype: n.type, label: n.label,
        short: shortCyLabel(n), props: n.props || {},
        // `class` is the field the SBGN stylesheet keys its glyph selectors on;
        // `sbgnbbox` gives those glyphs a size to draw into.
        class: glyph, sbgnclass: glyph,
        sbgnbbox: { w: 30, h: 24 },
        deg: deg[n.id] || 0, color: cyTypeColor(n.type),
      },
      classes: n.type,
    });
  });
  data.edges.forEach((e, i) => {
    if (!ids.has(e.source) || !ids.has(e.target)) return;
    elements.push({ data: { id: 'e' + i, source: e.source, target: e.target, rel: e.type } });
  });

  const cy = cytoscape({
    container,
    elements,
    wheelSensitivity: 0.25,
    pixelRatio: Math.min(window.devicePixelRatio || 1, 2),
    textureOnViewport: elements.length > 1500,
    hideEdgesOnViewport: elements.length > 2500,
    style: styleFor(style),
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
        const show = !isDetailLocked(t) && !hidden.has(t)
          && (!hostVisibleIds || hostVisibleIds.has(n.id()));
        n.style('display', show ? 'element' : 'none');
      });
    });
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
    if (isDetailLocked(n.data('ntype'))) { if (opts.onLocked) opts.onLocked(); return; }
    select(n);
    if (opts.onSelect) opts.onSelect({ type: n.data('ntype'), label: n.data('label') });
  });
  cy.on('tap', evt => { if (evt.target === cy) clearSelect(); });

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

  // ---- style modes ----
  function setStyle(mode) {
    style = mode === 'sbgn' ? 'sbgn' : 'fcose';
    cy.style(styleFor(style));
    applyVisibility();
    return style;
  }
  function currentStyle() { return style; }

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
      const tip = lock ? `${present[t]} ${t} nodes — select a subdomain to activate this layer`
        : `${present[t]} ${t} nodes — click to ${off ? 'show' : 'hide'}`;
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
    hostVisibleIds = computeVisible(f.hosts);
    if (selected && hostVisibleIds && !hostVisibleIds.has(selected.id())) clearSelect();
    applyVisibility();
    if (legendEl) buildLegend(legendEl);
    runLayout(true);
    setTimeout(() => cy.fit(cy.elements(':visible'), 40), 520);
  }

  /* Same subtree rule as the canvas renderer: keep each selected Subdomain and
     everything hanging off it, with the Domain as an anchor; don't cross into a
     sibling subdomain reached only through a shared IP. */
  function computeVisible(hosts) {
    if (!hosts || !hosts.length) return null;
    const wanted = new Set(hosts);
    const subs = cy.nodes().filter(n => n.data('ntype') === 'Subdomain' && wanted.has(n.data('label')));
    if (!subs.length) return new Set();
    const subIds = new Set(subs.map(n => n.id()));
    const keep = new Set(subIds);
    const dom = cy.nodes('.Domain'); if (dom.length) keep.add(dom.id());
    const stack = [...subIds];
    while (stack.length) {
      const id = stack.pop();
      cy.getElementById(id).neighborhood('node').forEach(m => {
        const mid = m.id();
        if (keep.has(mid)) return;
        const t = m.data('ntype');
        if (t === 'Domain') { keep.add(mid); return; }
        if (t === 'Subdomain' && !subIds.has(mid)) return;
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
    cy.style(styleFor(style));
    if (legendEl) buildLegend(legendEl);
  };
  window.addEventListener('themechange', onTheme);

  return {
    fit: () => cy.fit(cy.elements(':visible'), 40),
    reheat: () => runLayout(true),
    buildLegend, activate, setFilter, setStyle, currentStyle,
    stats: data.stats,
    detailUnlocked: () => detailUnlocked,
    focusHost,
    destroy() {
      window.removeEventListener('themechange', onTheme);
      try { cy.destroy(); } catch (e) {}
    },
  };
}

/* ---- stylesheets ---------------------------------------------------------- */
function styleFor(mode) {
  if (mode === 'sbgn' && window.cytoscapeSbgnStylesheet) {
    try {
      // Each node's data(class) is an SBGN glyph, so the stylesheet draws the
      // right notation shapes; we overlay per-type colour + our fade/lit states.
      const base = window.cytoscapeSbgnStylesheet(window.cytoscape);
      const overrides = [
        { selector: 'node', style: { 'label': 'data(short)', 'font-size': 9, 'background-color': 'data(color)' } },
        { selector: '.faded', style: { 'opacity': 0.12 } },
        { selector: 'node.lit', style: { 'border-width': 2, 'border-color': cyInk() } },
        { selector: 'edge.lit', style: { 'line-color': '#e0b341', 'width': 2 } },
      ];
      // The library returns either a plain style array or a chainable stylesheet
      // builder, depending on version — support both.
      if (Array.isArray(base)) return base.concat(overrides);
      if (base && typeof base.selector === 'function') {
        overrides.forEach(o => base.selector(o.selector).css(o.style));
        return base;
      }
    } catch (e) { /* fall through to the fcose style */ }
  }
  // fCoSE "gene-gene" look: solid coloured discs, curved faint edges.
  return [
    { selector: 'node', style: {
        'background-color': 'data(color)', 'label': 'data(short)',
        'width': 'mapData(deg, 0, 40, 14, 46)', 'height': 'mapData(deg, 0, 40, 14, 46)',
        'font-size': 9, 'color': cyInk(), 'text-valign': 'center', 'text-halign': 'right',
        'text-margin-x': 3, 'min-zoomed-font-size': 8,
        'text-background-color': cyBg(), 'text-background-opacity': 0.7,
        'text-background-padding': 1, 'border-width': 0 } },
    { selector: 'node.Domain', style: { 'width': 40, 'height': 40, 'font-size': 12, 'font-weight': 'bold' } },
    { selector: 'node.Subdomain', style: { 'shape': 'round-rectangle' } },
    { selector: 'edge', style: {
        'width': 1, 'line-color': cyEdge(), 'curve-style': 'haystack',
        'haystack-radius': 0.4, 'opacity': 0.5 } },
    { selector: '.faded', style: { 'opacity': 0.12 } },
    { selector: 'node.lit', style: { 'border-width': 2, 'border-color': cyInk() } },
    { selector: 'edge.lit', style: { 'line-color': '#e0b341', 'width': 2, 'opacity': 1, 'curve-style': 'bezier' } },
  ];
}

function cyInk() { return (getComputedStyle(document.documentElement).getPropertyValue('--ink') || '#111').trim(); }
function cyBg() { return (getComputedStyle(document.documentElement).getPropertyValue('--surface') || '#fff').trim(); }
function cyEdge() { return (getComputedStyle(document.documentElement).getPropertyValue('--faint') || '#bbb').trim(); }

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
