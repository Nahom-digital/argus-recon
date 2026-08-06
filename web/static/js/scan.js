/* ============================================================================
   Argus Recon · scan detail controller
   ========================================================================== */
'use strict';

const ROW_CAP = 1500;
const GRAPH_LAZY = 500;              // above this, defer physics until activated
let SCAN = null, GRAPH = null, detailMode = false;
const F = {
  search: '', type: '', status: '', source: '', scope: 'in', classifiedOnly: false,
  host: null, ip: null,
  // Section filters · each narrows one section's list, nothing else. The left
  // panel and the full-width detail view read the same state, so a filter set
  // in one is still held when the other is opened.
  subStatus: '', subIp: '', subTech: '',
  asn: '', tech: '', secretSev: '',
  fileType: '', fileStatus: '', fileHost: '', fileIp: '',
};

/* IP <-> host index, built once per scan from both directions (a subdomain
   lists its IPs, an IP record lists the hosts that resolve to it). */
const IP_HOSTS = new Map();          // ip   -> Set(host)
const HOST_IPS = new Map();          // host -> Set(ip)

/* Deep-DNS address timeline · ip -> {first_seen,last_seen,organization,current}.
   Historical A/AAAA records are the only place a scan learns when an address
   started and stopped serving the domain, so the index is built once and read
   by both the infrastructure panel and the detail tables. */
const IP_SEEN = new Map();

document.addEventListener('DOMContentLoaded', init);

let SCAN_ID = null;
/* expanded-row detail is fetched per endpoint and cached so re-opening is free */
const EP_DETAIL = new Map();

async function init() {
  const layout = document.querySelector('.scan-layout');
  const id = layout.dataset.scanId;
  SCAN_ID = id;
  wireSections();
  wireGraphSplitter();
  wireSideSplitter();
  wireSideCollapse();
  wireTableCollapse();
  showLoading();

  // Both requests go out together, but the page does not wait for both before
  // drawing anything. The graph is much the slower of the two on a large scan,
  // and awaiting them as a pair is what left the panel, the table *and* the
  // graph blank until the slowest one had landed · the whole page looked dead.
  // Each half now renders the moment its own response arrives, and one failing
  // no longer blanks the other.
  const viewP = getJSON(withBase(`/api/scan/${encodeURIComponent(id)}/view`));
  const graphP = fetchGraph(id)
    .then(g => ({ g }), e => ({ e }));       // settled either way; never unhandled

  try {
    const scan = await viewP;
    SCAN = scan;
    buildIpIndex(scan);
    buildIpSeenIndex(scan);
    renderPanel(scan);
    buildStatusFilter();
    buildSourceFilter();
    buildHostFilter();
    buildIpFilter();
    renderTable();
    wireTableControls();
  } catch (e) {
    failLoading(e);
    await graphP;                            // consume it; nothing to draw into
    return;
  }

  const { g, e } = await graphP;
  clearGraphLoading();
  if (g) initGraph(g);
  else failGraph(e);
}

/* ---- load / error states --------------------------------------------------
   Without these a slow scan is indistinguishable from a broken one: empty
   panel, empty table, empty graph, no explanation. */
function showLoading() {
  const spin = t => `<div class="loading-mini">${icon('refresh', 'spinning')}<span>${esc(t)}</span></div>`;
  document.getElementById('ovBody').innerHTML = spin('loading scan…');
  document.getElementById('subList').innerHTML = spin('loading…');
  document.getElementById('ipList').innerHTML = spin('loading…');
  document.getElementById('tBody').innerHTML =
    `<div class="empty">${icon('refresh', 'spinning')}<h4>Loading requests…</h4>
     <p>Large scans take a moment to open.</p></div>`;
  const wrap = document.getElementById('graphWrap');
  if (wrap && !wrap.querySelector('.graph-loading'))
    wrap.insertAdjacentHTML('beforeend',
      `<div class="graph-loading"><div class="empty" style="margin:auto">${icon('refresh', 'spinning')}
        <h4>Building graph…</h4></div></div>`);
}

function clearGraphLoading() {
  document.querySelectorAll('.graph-loading').forEach(el => el.remove());
}

/* A graph-loading overlay shown while an engine is (re)built. Switching to the
   Cytoscape engine has to fetch and parse several vendor bundles the first time,
   which used to freeze the tab with no feedback; this shows the switch is
   working rather than stuck. */
function showGraphLoading(text) {
  const wrap = document.getElementById('graphWrap');
  if (!wrap) return;
  clearGraphLoading();
  wrap.insertAdjacentHTML('beforeend',
    `<div class="graph-loading"><div class="empty" style="margin:auto">${icon('refresh', 'spinning')}
      <h4>${esc(text || 'Building graph…')}</h4></div></div>`);
}

function failLoading(err) {
  clearGraphLoading();
  document.querySelector('.main').innerHTML =
    `<div class="empty" style="margin:auto">${icon('alert-triangle')}<h4>Could not load scan</h4>
     <p>${esc(err && err.message ? err.message : String(err))}</p></div>`;
  ['ovBody', 'subList', 'ipList', 'dnsBody', 'techList', 'secretList', 'fileList']
    .forEach(elId => { const el = document.getElementById(elId); if (el) el.innerHTML = emptyMini('unavailable'); });
}

function failGraph(err) {
  const wrap = document.getElementById('graphWrap');
  if (!wrap) return;
  wrap.insertAdjacentHTML('beforeend',
    `<div class="graph-empty"><div class="empty" style="margin:auto">${icon('alert-triangle')}
      <h4>Graph unavailable</h4><p>${esc(err && err.message ? err.message : 'The graph could not be built for this scan.')}</p></div></div>`);
}

/* ---- graph fetch ----------------------------------------------------------
   Building the graph for a large scan takes longer than any proxy will hold a
   connection open, which is exactly what "Graph unavailable 524" was: the
   reverse proxy giving up while the server was still working. The server now
   answers 202 "building" instead of holding the socket, and this waits it out.

   A gateway status (502/504/524, and 408) is treated the same way · it means
   something in front of us timed out, not that the graph failed, so the right
   move is to keep asking rather than to paint an error over a build that is
   still running.

   Progress is reported into the loading overlay so a five-minute build looks
   like work in progress instead of a hung tab. */
const GRAPH_POLL_MS = 2500;
const GRAPH_MAX_WAIT_MS = 15 * 60 * 1000;
const GATEWAY_STATUS = new Set([408, 502, 503, 504, 522, 524]);

async function fetchGraph(id, limit) {
  const url = withBase(`/api/scan/${encodeURIComponent(id)}/graph`)
    + (limit ? `?limit=${encodeURIComponent(limit)}` : '');
  const deadline = Date.now() + GRAPH_MAX_WAIT_MS;

  while (true) {
    let r;
    try {
      r = await apiFetch(url);
    } catch (e) {
      // a dropped connection mid-build is the same story as a gateway timeout
      if (Date.now() > deadline) throw e;
      await graphWait();
      continue;
    }

    if (r.status === 202) {
      const body = await r.json().catch(() => ({}));
      if (Date.now() > deadline)
        throw new Error('the graph is still being built · reload the page to keep waiting');
      noteGraphProgress(body.elapsed_sec);
      await graphWait();
      continue;
    }
    if (GATEWAY_STATUS.has(r.status)) {
      if (Date.now() > deadline)
        throw new Error(`the graph request kept timing out (${r.status})`);
      noteGraphProgress(null);
      await graphWait();
      continue;
    }
    if (!r.ok) {
      const body = await r.json().catch(() => null);
      throw new Error((body && body.error) || `${r.status} ${r.statusText}`);
    }
    return r.json();
  }
}

function graphWait() {
  return new Promise(res => setTimeout(res, GRAPH_POLL_MS));
}

/* Update the "Building graph…" overlay in place · replacing it would restart
   the spinner's animation on every poll. */
function noteGraphProgress(elapsed) {
  const box = document.querySelector('.graph-loading .empty h4');
  if (!box) return;
  box.textContent = elapsed
    ? `Building graph… ${Math.round(elapsed)}s`
    : 'Building graph…';
  let sub = document.querySelector('.graph-loading .empty p');
  if (!sub) {
    const parent = document.querySelector('.graph-loading .empty');
    if (parent) parent.insertAdjacentHTML('beforeend',
      '<p>This scan is large. The rest of the page is ready below.</p>');
  }
}

function buildIpIndex(s) {
  IP_HOSTS.clear(); HOST_IPS.clear();
  const link = (ip, host) => {
    if (!ip || !host) return;
    if (!IP_HOSTS.has(ip)) IP_HOSTS.set(ip, new Set());
    IP_HOSTS.get(ip).add(host);
    if (!HOST_IPS.has(host)) HOST_IPS.set(host, new Set());
    HOST_IPS.get(host).add(ip);
  };
  (s.subdomains || []).forEach(sd => (sd.ips || []).forEach(ip => link(ip, sd.host)));
  ((s.infra && s.infra.ips) || []).forEach(r => (r.subdomains || []).forEach(h => link(r.ip, h)));
}
/* Address timeline from deep DNS: every A/AAAA value ever recorded, with the
   window it was seen in. Current records win over historical ones for the same
   address, so an address still in service is marked as such rather than being
   reported as "last seen" on the day the history snapshot was taken. */
function buildIpSeenIndex(s) {
  IP_SEEN.clear();
  const dns = s.dns || {};
  const put = (r, current) => {
    if (!r || !r.value) return;
    const prev = IP_SEEN.get(r.value);
    if (prev && prev.current && !current) return;
    IP_SEEN.set(r.value, {
      first_seen: r.first_seen || (prev && prev.first_seen) || null,
      last_seen: current ? null : r.last_seen || null,
      organization: r.organization || (prev && prev.organization) || null,
      current: current || (prev ? prev.current : false),
    });
  };
  ['a', 'aaaa'].forEach(t => {
    ((dns.history || {})[t] || []).forEach(r => put(r, false));
    ((dns.records || {})[t] || []).forEach(r => put(r, true));
  });
}

/* One line of provenance for an address: how long it has served, and whether it
   still does. Empty when this scan has no deep DNS behind it. */
function ipSeenText(ip) {
  const s = IP_SEEN.get(ip);
  if (!s || (!s.first_seen && !s.last_seen)) return '';
  const dur = durationOf(s.first_seen, s.last_seen);
  if (s.current) return `since ${s.first_seen ? (yearOf(s.first_seen) || s.first_seen) : '?'}${dur ? ' · ' + dur : ''} · current`;
  return fmtRange(s.first_seen, s.last_seen);
}

const hostsOfIp = ip => [...(IP_HOSTS.get(ip) || [])].sort();
/* every IP behind a set of hosts, de-duplicated (used by the tech stack) */
function ipsOfHosts(hosts) {
  const out = new Set();
  hosts.forEach(h => (HOST_IPS.get(h) || new Set()).forEach(ip => out.add(ip)));
  return [...out].sort();
}

/* ---- left panel ----------------------------------------------------------- */
function renderPanel(s) {
  const m = s.meta || {}, st = m.stats || {};
  document.getElementById('crumbDomain').textContent = m.domain || m.scan_id;

  // overview
  const wh = m.domain_whois || {};
  const kv = (k, v) => v ? `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>` : '';
  const mods = Object.entries(m.modules || {}).map(([name, d]) =>
    `<div class="modline"><span class="dot ${d.status === 'ok' ? 'ok' : d.status === 'empty' ? 'empty' : 'skip'}"></span>
      ${esc(name)}<span class="faint" style="margin-left:auto">${d.note ? esc(d.note) : d.status}${d.duration ? ' · ' + d.duration + 's' : ''}</span></div>`).join('');
  document.getElementById('ovBody').innerHTML = `<div class="ov">
    ${kv('domain', m.domain)}
    ${kv('scanned', m.started_at ? new Date(m.started_at).toLocaleString() : '')}
    ${kv('duration', m.duration_sec != null ? fmtDur(m.duration_sec) : '')}
    ${kv('registrar', wh.registrar)}
    ${kv('created', wh.created)}
    ${kv('name servers', (wh.name_servers || []).slice(0, 2).join(', '))}
    <div style="margin-top:6px">${mods}</div>
  </div>`;

  // Findings · the ranked cross-module conclusions (exposed services, weak TLS,
  // leaked secrets, bypassable controls, known CVEs). Placed first so the scan's
  // headline reads before the raw inventory below. Auto-collapses when clean.
  const findings = s.findings || [];
  setCount('cFindings', findings.length);
  F.findSev = ''; F.findCat = '';
  buildFindingFilter('findingFilter', 'sd');
  renderFindingList();
  document.querySelector('.side-sec[data-sec="findings"]').classList.toggle('collapsed', !findings.length);

  // Each section below carries its own filter, built from what this scan
  // actually contains · a status code nothing returned is never offered.
  const subs = s.subdomains || [];
  setCount('cSubs', subs.length);
  F.subStatus = ''; F.subIp = ''; F.subTech = '';
  buildSubFilter('subFilter', 'sd');
  renderSubList();

  const ips = (s.infra && s.infra.ips) || [];
  setCount('cIps', ips.length);
  F.asn = '';
  buildAsnFilter('asnFilter', 'sd');
  renderIpList();

  // DNS
  renderDns(s.dns || {});

  // tech (per fingerprint -> which subdomains, like secrets)
  F.tech = '';
  buildTechFilter('techFilter', 'sd');
  renderTech();

  const secrets = s.secrets || [];
  setCount('cSecrets', secrets.length);
  F.secretSev = '';
  buildSecretFilter('secretFilter', 'sd');
  renderSecretList();
  document.querySelector('.side-sec[data-sec="secrets"]').classList.toggle('collapsed', !secrets.length);

  const files = s.files || [];
  setCount('cFiles', files.length);
  F.fileType = ''; F.fileStatus = ''; F.fileHost = ''; F.fileIp = '';
  buildFileFilter('fileFilter', 'sd');
  renderFileList();

  wirePanelInteractions();
}

/* ---- section filters ------------------------------------------------------
   One shared builder for every section's filter row, used twice over: once in
   the left panel and once in the full-width detail view. `specs` are the selects
   to draw; any select with nothing to choose between is dropped, and a row with
   no selects left hides itself rather than showing an empty control.

   `prefix` keeps the two copies of a row from sharing element ids, and the
   `data-fkey` on each select is what lets one copy follow the other without
   being rebuilt (see syncPanelSelects). */
function panelFilter(containerId, prefix, specs) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const useful = specs.filter(s => s.options.length > 1);
  if (!useful.length) { el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  el.innerHTML = `<svg class="ic"><use href="#i-filter"></use></svg>`
    + useful.map(s => `<select class="input" id="${esc(prefix + s.id)}" data-fkey="${esc(s.key)}"
        aria-label="${esc(s.aria)}" title="${esc(s.aria)}">${
      s.options.map(([v, label]) =>
        `<option value="${esc(v)}"${v === s.value ? ' selected' : ''}>${esc(label)}</option>`
      ).join('')}</select>`).join('');
  useful.forEach(s => {
    const sel = el.querySelector('#' + CSS.escape(prefix + s.id));
    if (sel) sel.addEventListener('change', () => { F[s.key] = sel.value; s.onChange(); });
  });
}

/* Both copies of a filter row read the same state, so after a change the other
   copy is nudged to the new value instead of being re-rendered · re-rendering
   would drop the open dropdown and the focus ring mid-interaction. */
function syncPanelSelects() {
  document.querySelectorAll('select[data-fkey]').forEach(sel => {
    const want = F[sel.dataset.fkey] || '';
    if (sel.value !== want) sel.value = want;
  });
}

/* Count how many items fall under each value of one facet. `get` returns a
   single value or a list of them (tech is many-per-subdomain). */
function facetCounts(items, get) {
  const counts = new Map();
  items.forEach(x => {
    const v = get(x);
    (Array.isArray(v) ? v : [v]).forEach(one => {
      if (one == null || one === '') return;
      counts.set(one, (counts.get(one) || 0) + 1);
    });
  });
  return counts;
}

/* Facet options, busiest first, each carrying its own count. `noneLabel` adds a
   trailing group for the items the facet says nothing about, so nothing in the
   list is unreachable through the filter. */
function facetOptions(items, get, allLabel, noneLabel) {
  const counts = facetCounts(items, get);
  const opts = [['', `${allLabel} (${items.length})`]];
  [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .forEach(([v, n]) => opts.push([String(v), `${v} (${n})`]));
  if (noneLabel) {
    const none = items.filter(x => {
      const v = get(x);
      return Array.isArray(v) ? !v.length : (v == null || v === '');
    }).length;
    if (none) opts.push(['none', `${noneLabel} (${none})`]);
  }
  return opts;
}

/* "none" is the escape hatch every facet shares: the items the facet has
   nothing to say about. */
function matchesFacet(value, got) {
  if (!value) return true;
  const list = Array.isArray(got) ? got : (got == null || got === '' ? [] : [got]);
  if (value === 'none') return !list.length;
  return list.map(String).includes(value);
}

/* Status options built from the codes actually seen: the classes present
   (2xx/4xx/…), then each exact code, then "no response" when something did not
   answer at all. Same vocabulary as the request table's status filter. */
function statusOptions(items, getStatus, allLabel) {
  const codes = new Map(), classes = new Map();
  let none = 0;
  items.forEach(x => {
    const c = getStatus(x);
    if (c) {
      codes.set(c, (codes.get(c) || 0) + 1);
      const k = Math.floor(c / 100) + 'xx';
      classes.set(k, (classes.get(k) || 0) + 1);
    } else none++;
  });
  const opts = [['', `${allLabel} (${items.length})`]];
  [...classes.keys()].sort().forEach(k => opts.push([k, `${k} (${classes.get(k)})`]));
  [...codes.keys()].sort((a, b) => a - b).forEach(c => opts.push([String(c), `${c} (${codes.get(c)})`]));
  if (none) opts.push(['none', `no response (${none})`]);
  return opts;
}

function matchesStatusFilter(value, code) {
  if (!value) return true;
  if (value === 'none') return !code;
  if (/^\dxx$/.test(value)) return !!code && Math.floor(code / 100) === +value[0];
  return String(code) === value;
}

/* ---- what each section holds once its filter is applied ------------------- */
const allSubs = () => (SCAN && SCAN.subdomains) || [];
const allIps = () => ((SCAN || {}).infra || {}).ips || [];
const allSecrets = () => (SCAN && SCAN.secrets) || [];
const allFiles = () => (SCAN && SCAN.files) || [];

/* Subdomains answer three questions at once: what did it respond with, where is
   it served from, and what is it running. The three filters combine. */
function subMatches(sd) {
  return matchesStatusFilter(F.subStatus, (sd.http || {}).status)
    && matchesFacet(F.subIp, sd.ips || [])
    && matchesFacet(F.subTech, sd.tech || []);
}
const filteredSubs = () => allSubs().filter(subMatches);

function ipMatches(ip) { return matchesFacet(F.asn, ip.asn); }
const filteredIps = () => allIps().filter(ipMatches);

function secretMatches(x) { return !F.secretSev || x.severity === F.secretSev; }
const filteredSecrets = () => allSecrets().filter(secretMatches);

const allFindings = () => (SCAN && SCAN.findings) || [];
function findMatches(f) {
  return (!F.findSev || f.severity === F.findSev) && (!F.findCat || f.category === F.findCat);
}
const filteredFindings = () => allFindings().filter(findMatches);

/* Tech is a derived list (fingerprint -> the hosts carrying it), so it is built
   rather than filtered in place. */
function techEntries() {
  const map = {};
  allSubs().forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  return Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}
const filteredTech = () => techEntries().filter(([t]) => !F.tech || t === F.tech);

/* Subdomains · response code, serving address, fingerprint. */
function buildSubFilter(containerId, prefix) {
  const subs = allSubs();
  panelFilter(containerId, prefix, [
    { key: 'subStatus', id: 'SubStatus', aria: 'Filter subdomains by response code',
      value: F.subStatus, options: statusOptions(subs, sd => (sd.http || {}).status, 'all status'),
      onChange: refreshSubs },
    { key: 'subIp', id: 'SubIp', aria: 'Filter subdomains by resolved IP',
      value: F.subIp, options: facetOptions(subs, sd => sd.ips || [], 'all IPs', 'no IP'),
      onChange: refreshSubs },
    { key: 'subTech', id: 'SubTech', aria: 'Filter subdomains by tech stack',
      value: F.subTech, options: facetOptions(subs, sd => sd.tech || [], 'all tech', 'no fingerprint'),
      onChange: refreshSubs },
  ]);
}

/* Infrastructure · by announcing AS. Addresses with no ASN are their own group
   rather than being silently unreachable through the filter. */
function buildAsnFilter(containerId, prefix) {
  const ips = allIps();
  const orgOf = new Map();
  ips.forEach(ip => {
    if (ip.asn && ip.org && !orgOf.has(ip.asn))
      orgOf.set(ip.asn, String(ip.org).split(/[,(]/)[0].trim());
  });
  const opts = facetOptions(ips, ip => ip.asn, 'all AS', 'no AS recorded')
    .map(([v, label]) => [v, orgOf.get(v) ? label.replace(v, `${v} · ${orgOf.get(v)}`) : label]);
  panelFilter(containerId, prefix, [{
    key: 'asn', id: 'Asn', aria: 'Filter infrastructure by announcing AS',
    value: F.asn, options: opts, onChange: refreshIps,
  }]);
}

/* Tech stack · by fingerprint. */
function buildTechFilter(containerId, prefix) {
  const entries = techEntries();
  const opts = [['', `all tech (${entries.length})`]];
  entries.forEach(([t, hosts]) => opts.push([t, `${t} (${hosts.length})`]));
  panelFilter(containerId, prefix, [{
    key: 'tech', id: 'Tech', aria: 'Filter the tech stack',
    value: F.tech, options: opts, onChange: refreshTech,
  }]);
}

/* Secrets · by severity, worst first. */
function buildSecretFilter(containerId, prefix) {
  const secrets = allSecrets();
  const order = ['high', 'medium', 'low'];
  const counts = facetCounts(secrets, x => x.severity);
  const opts = [['', `all severities (${secrets.length})`]];
  order.filter(s => counts.get(s)).forEach(s => opts.push([s, `${s} (${counts.get(s)})`]));
  [...counts.keys()].filter(s => !order.includes(s)).sort()
    .forEach(s => opts.push([s, `${s} (${counts.get(s)})`]));
  panelFilter(containerId, prefix, [{
    key: 'secretSev', id: 'SecretSev', aria: 'Filter secrets by severity',
    value: F.secretSev, options: opts, onChange: refreshSecrets,
  }]);
}

/* Findings · by severity (worst first) and by type. */
function buildFindingFilter(containerId, prefix) {
  const items = allFindings();
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const sevCounts = facetCounts(items, f => f.severity);
  const sevOpts = [['', `all severities (${items.length})`]];
  order.filter(s => sevCounts.get(s)).forEach(s => sevOpts.push([s, `${s} (${sevCounts.get(s)})`]));
  const catCounts = facetCounts(items, f => f.category);
  const catOpts = [['', `all types (${[...catCounts.keys()].length})`]];
  [...catCounts.entries()].sort((a, b) => b[1] - a[1])
    .forEach(([c, n]) => catOpts.push([c, `${c} (${n})`]));
  panelFilter(containerId, prefix, [
    { key: 'findSev', id: 'FindSev', aria: 'Filter findings by severity',
      value: F.findSev, options: sevOpts, onChange: refreshFindings },
    { key: 'findCat', id: 'FindCat', aria: 'Filter findings by type',
      value: F.findCat, options: catOpts, onChange: refreshFindings },
  ]);
}

/* ---- one refresh per section ----------------------------------------------
   A filter can be moved from the left panel or from the detail view, and both
   are on screen in their own mode, so each refresh redraws whichever of the two
   exists and re-points the other copy of the control at the new value. */
function refreshSubs() {
  renderSubList();
  renderDvBody('subdomains');
  syncPanelSelects();
}
function refreshIps() {
  renderIpList();
  renderDvBody('infra');
  syncPanelSelects();
}
function refreshTech() {
  renderTech();
  renderDvBody('tech');
  syncPanelSelects();
}
function refreshSecrets() {
  renderSecretList();
  renderDvBody('secrets');
  syncPanelSelects();
}
function refreshFindings() {
  renderFindingList();
  renderDvBody('findings');
  syncPanelSelects();
}
function refreshFiles() {
  renderFileList();
  renderDvBody('files');
  syncPanelSelects();
}

function renderSubList() {
  const el = document.getElementById('subList');
  if (!el) return;
  const subs = filteredSubs();
  el.innerHTML = subs.map(subItem).join('')
    || emptyMini(subFiltered() ? 'no subdomains match those filters' : 'no subdomains');
  wirePanelInteractions();
}
const subFiltered = () => !!(F.subStatus || F.subIp || F.subTech);

function renderIpList() {
  const el = document.getElementById('ipList');
  if (!el) return;
  const ips = filteredIps();
  el.innerHTML = ips.map(ipCard).join('')
    || emptyMini(F.asn ? 'no addresses on that AS' : 'no IPs');
  wirePanelInteractions();
}

function renderSecretList() {
  const el = document.getElementById('secretList');
  if (!el) return;
  const secrets = filteredSecrets();
  el.innerHTML = secrets.map(secRow).join('')
    || emptyMini(F.secretSev ? 'none at that severity' : 'none flagged');
}

function renderFindingList() {
  const el = document.getElementById('findingList');
  if (!el) return;
  const items = filteredFindings();
  el.innerHTML = items.map(findRow).join('')
    || emptyMini((F.findSev || F.findCat) ? 'none match those filters'
        : (allFindings().length ? 'none'
           : 'no findings · the surface looks clean, or no active review ran'));
}

/* One finding · summary row (severity, title, confidence) that expands to the
   risk, the fix, the raw evidence, a parsed breakdown, tags and references.
   Same expand vocabulary as the file rows: instant detail, animated chevron. */
function findRow(f) {
  const src = (f.sources || []).map(sc =>
    `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('');
  const host = f.host || (f.target && f.target.includes('://') ? splitUrl(f.target).host : f.target || '');
  const tgtPath = f.target && f.target.includes('://') ? splitUrl(f.target).path : '';
  const conf = typeof f.confidence === 'number' ? f.confidence : null;
  const tags = (f.tags || []).slice(0, 6).map(t => `<span class="tag mono">${esc(t)}</span>`).join('');
  const refs = (f.refs || []).map(r =>
    `<a class="find-ref" href="${esc(r)}" target="_blank" rel="noopener">${icon('external-link')}${esc(splitUrl(r).host || r)}</a>`).join('');
  const parsed = (f.parsed && typeof f.parsed === 'object')
    ? Object.entries(f.parsed)
        .filter(([, v]) => v != null && v !== '' && (!Array.isArray(v) || v.length))
        .slice(0, 8)
        .map(([k, v]) => `<div class="find-kv"><span class="k">${esc(k)}</span><span class="v mono">${
          esc(Array.isArray(v) ? v.join(', ') : (typeof v === 'object' ? JSON.stringify(v) : String(v))).slice(0, 300)
        }</span></div>`).join('')
    : '';
  const det = [
    f.risk ? `<div class="find-block"><span class="find-lbl">Risk</span><p>${esc(f.risk)}</p></div>` : '',
    f.recommendation ? `<div class="find-block"><span class="find-lbl">Fix</span><p>${esc(f.recommendation)}</p></div>` : '',
    f.evidence ? `<div class="find-block"><span class="find-lbl">Evidence</span><pre class="find-ev">${esc(f.evidence)}</pre></div>` : '',
    parsed ? `<div class="find-block"><span class="find-lbl">Detail</span><div class="find-kvs">${parsed}</div></div>` : '',
    tags ? `<div class="find-tags">${tags}</div>` : '',
    refs ? `<div class="find-refs">${refs}</div>` : '',
  ].join('');
  return `<div class="find-row" data-sev="${esc(f.severity)}">
    <button class="find-sum" aria-expanded="false">
      <span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span>
      <span class="find-title">${esc(f.title)}</span>
      ${conf != null ? `<span class="find-conf" title="confidence">${conf}</span>` : ''}
      <svg class="ic find-chev"><use href="#i-chevron-down"></use></svg>
    </button>
    <div class="find-meta">
      ${f.category ? `<span class="find-cat">${esc(f.category)}</span>` : ''}
      ${host ? `<span class="find-host" title="${esc(f.target || host)}">${esc(host)}${esc(tgtPath)}</span>` : ''}
      ${f.occurrences > 1 ? `<span class="faint">seen ${f.occurrences}x</span>` : ''}
      ${src ? `<span class="find-src">${src}</span>` : ''}
    </div>
    ${det ? `<div class="find-det">${det}</div>` : ''}
  </div>`;
}

function subItem(sd) {
  const http = sd.http || {};
  const stCls = statusClass(http.status);
  const ipline = (sd.ips || []).slice(0, 2).join(', ');
  return `<button class="sitem" data-host="${esc(sd.host)}">
    <div class="top">
      <span class="host">${esc(sd.host)}</span>
      ${http.status ? `<span class="st ${stCls}">${http.status}</span>` : (sd.resolved ? '' : `<span class="st status-x">dns</span>`)}
    </div>
    ${(sd.tech && sd.tech.length) ? `<div class="sub">${sd.tech.slice(0, 3).map(t => `<span class="tag mono">${esc(t)}</span>`).join('')}${sd.tech.length > 3 ? `<span class="faint" style="font-size:11px">+${sd.tech.length - 3}</span>` : ''}</div>` : ''}
    ${ipline ? `<div class="ipline">${icon('server-2')} ${esc(ipline)}</div>` : ''}
    ${(sd.sources && sd.sources.length) ? `<div class="ipline">${sd.sources.map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('')}</div>` : ''}
  </button>`;
}

/* Where an address sits, as one line: city, region, country. Empty when the
   enrichment pass had nothing to say about it. */
function ipPlace(ip) {
  return [ip.city, ip.region, ip.country].filter(Boolean).join(', ');
}

/* Infra: each IP lists which subdomains resolve to it + discovery source (item 4) */
function ipCard(ip) {
  const dc = ip.datacenter === true ? 'hosting' : ip.type || 'unknown';
  const meta = [];
  if (ip.asn) meta.push(esc(ip.asn));
  meta.push(esc(dc));
  const place = ipPlace(ip);
  const seen = ipSeenText(ip.ip);
  const placeLine = place
    ? `<div class="ip-place">${icon('map-2')}<span>${esc(place)}</span></div>` : '';
  const seenLine = seen
    ? `<div class="ip-seen" title="from historical DNS · when this address served the domain">${icon('history')}<span>${esc(seen)}</span></div>` : '';
  const hosts = ip.subdomains || [];
  const hostList = hosts.length ? `<div class="ip-hosts">${hosts.slice(0, 10).map(h =>
    `<span class="chip-host" data-host="${esc(h)}" title="${esc(h)}">${esc(h)}</span>`).join('')}${hosts.length > 10 ? `<span class="faint" style="font-size:11px;align-self:center">+${hosts.length - 10}</span>` : ''}</div>` : '';
  const srcs = (ip.sources && ip.sources.length)
    ? `<span class="ip-src">${ip.sources.map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('')}</span>` : '';
  return `<div class="ipcard" data-ip="${esc(ip.ip)}">
    <button class="ipaddr" data-ip="${esc(ip.ip)}" title="filter list and graph by ${esc(ip.ip)}">${icon('server-2')} ${esc(ip.ip)}${srcs}</button>
    ${ip.org ? `<div class="iporg">${esc(ip.org)}</div>` : ''}
    <div class="ipmeta">${meta.map(x => `<span>${x}</span>`).join('<span class="faint">·</span>')}
      <span class="faint">·</span><span>${hosts.length} host${hosts.length === 1 ? '' : 's'}</span></div>
    ${placeLine}${seenLine}
    ${hostList}
    ${portsBlock(ip)}
  </div>`;
}

/* Open ports on one address · the port-scan layer inside Infrastructure. Each
   port is expandable: the summary is port/service/version, the detail is the
   default-script output the scan captured. OS + traceroute, when present, sit
   above the port list. */
function portsBlock(ip) {
  const ports = ip.ports || [];
  const os = ip.os;
  const trace = ip.traceroute || [];
  if (!ports.length && !os && !trace.length) {
    return ip.scanned
      ? `<div class="ip-ports empty"><span class="faint">${icon('shield-check')} no open ports found</span></div>`
      : '';
  }
  const osLine = os && os.name
    ? `<div class="ip-os" title="OS guess${os.accuracy ? ' · ' + os.accuracy + '% match' : ''}">${icon('device-desktop')}
        <span>${esc(os.name)}</span>${os.accuracy ? `<span class="faint">${os.accuracy}%</span>` : ''}</div>` : '';
  const rows = ports.map(portRow).join('');
  const traceLine = trace.length
    ? `<div class="ip-trace"><span class="faint">${icon('route')} ${trace.length} hop${trace.length === 1 ? '' : 's'} to host</span></div>` : '';
  const head = `<div class="ip-ports-h">${icon('plug-connected')} ${ports.length} open port${ports.length === 1 ? '' : 's'}</div>`;
  return `<div class="ip-ports">${osLine}${ports.length ? head + rows : ''}${traceLine}</div>`;
}

function portRow(p) {
  const svc = p.service || '·';
  const ver = [p.product, p.version].filter(Boolean).join(' ');
  const web = /https?/.test(svc) || p.tunnel === 'ssl';
  const scripts = Object.entries(p.scripts || {});
  const tech = p.tech || [];      // WhatWeb fingerprint of the service on this port
  const hasDetail = ver || p.extrainfo || scripts.length || tech.length || p.cpe && p.cpe.length;
  const badge = `<span class="port-num mono">${p.port}<span class="faint">/${esc(p.protocol || 'tcp')}</span></span>`;
  const detail = hasDetail ? `<div class="port-detail">
      ${ver ? `<div class="kv"><span class="k">version</span><span class="v mono">${esc(ver)}</span></div>` : ''}
      ${tech.length ? `<div class="kv"><span class="k">tech</span><span class="v"><span class="port-tech">${tech.map(t => `<span class="tag mono">${esc(t)}</span>`).join('')}</span></span></div>` : ''}
      ${p.extrainfo ? `<div class="kv"><span class="k">info</span><span class="v">${esc(p.extrainfo)}</span></div>` : ''}
      ${(p.cpe || []).length ? `<div class="kv"><span class="k">cpe</span><span class="v mono">${p.cpe.map(esc).join('<br>')}</span></div>` : ''}
      ${scripts.map(([name, out]) => `<div class="port-script"><span class="ps-name mono">${esc(name)}</span><pre class="ps-out">${esc(out)}</pre></div>`).join('')}
    </div>` : '';
  return `<div class="prow${hasDetail ? ' has-detail' : ''}" ${web ? 'data-web="1"' : ''}>
    <button class="psummary"${hasDetail ? '' : ' tabindex="-1"'}>
      ${badge}
      <span class="port-svc">${esc(svc)}${web ? ` <span class="port-web" title="web service · crawled">${icon('world')}</span>` : ''}</span>
      ${ver ? `<span class="port-ver mono faint">${esc(ver)}</span>` : (tech.length ? `<span class="port-ver mono faint">${esc(tech[0])}</span>` : '')}
      ${hasDetail ? `<svg class="ic pchev"><use href="#i-chevron-down"></use></svg>` : ''}
    </button>
    ${detail}
  </div>`;
}

/* Tech: each fingerprint -> the subdomains it was seen on AND the IPs those
   hosts resolve to, so a stack can be traced to the box serving it. Chips are
   click-to-filter (host chip -> host filter, IP chip -> IP filter). */
function renderTech() {
  const el = document.getElementById('techList');
  setCount('cTech', techEntries().length);
  if (!el) return;
  const entries = filteredTech();
  el.innerHTML = entries.map(([t, hosts]) => {
    const ips = ipsOfHosts(hosts);
    return `<div class="techrow">
      <div class="th"><span class="tag mono">${esc(t)}</span>
        <span class="tmeta faint">${hosts.length} host${hosts.length === 1 ? '' : 's'}${
      ips.length ? ` · ${ips.length} IP${ips.length === 1 ? '' : 's'}` : ''}</span></div>
      <div class="tech-hosts">${chipRow(hosts, 4, h =>
      `<span class="chip-host" data-host="${esc(h)}" title="filter by ${esc(h)}">${esc(h)}</span>`)}</div>
      ${ips.length ? `<div class="tech-ips">${chipRow(ips, 4, ip =>
      `<span class="chip-ip" data-ip="${esc(ip)}" title="filter by ${esc(ip)}">${icon('server-2')}${esc(ip)}</span>`)}</div>` : ''}
    </div>`;
  }).join('') || emptyMini('no fingerprints');
}

/* first `n` items rendered by `f`, plus a "+N" remainder marker */
function chipRow(items, n, f) {
  return items.slice(0, n).map(f).join('') +
    (items.length > n ? `<span class="faint" style="font-size:11px;align-self:center">+${items.length - n}</span>` : '');
}

/* DNS panel: current records grouped by type + a compact history preview + WHOIS */
const DNS_ORDER = ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'soa'];
const DNS_LABEL = { a: 'A', aaaa: 'AAAA', cname: 'CNAME', mx: 'MX', ns: 'NS', txt: 'TXT', soa: 'SOA' };

function renderDns(dns) {
  dns = dns || {}; const recs = dns.records || {}, hist = dns.history || {};
  const nRec = Object.values(recs).reduce((a, v) => a + v.length, 0);
  const nHist = Object.values(hist).reduce((a, v) => a + v.length, 0);
  setCount('cDns', nRec + nHist);
  const body = document.getElementById('dnsBody');
  const wh = dns.whois || {};
  const hasWhois = Object.values(wh).some(Boolean);
  if (!nRec && !nHist && !hasWhois) {
    body.innerHTML = emptyMini('no DNS data yet · run with Deep for full records + history');
    document.querySelector('.side-sec[data-sec="dns"]').classList.add('collapsed');
    return;
  }
  document.querySelector('.side-sec[data-sec="dns"]').classList.remove('collapsed');
  let html = '';
  const curTypes = DNS_ORDER.filter(t => recs[t] && recs[t].length);
  if (curTypes.length) {
    html += `<div class="dns-group"><div class="dns-gh">Current records</div>`;
    for (const t of curTypes)
      html += `<div class="dns-type"><span class="dns-t">${DNS_LABEL[t]}</span>
        <div class="dns-vals">${recs[t].map(r => dnsValRow(r)).join('')}</div></div>`;
    html += `</div>`;
  }
  const histTypes = DNS_ORDER.filter(t => hist[t] && hist[t].length);
  if (histTypes.length) {
    html += `<div class="dns-group"><div class="dns-gh">${icon('history')} History
      <span class="faint" style="font-weight:400">· expand view for full tables</span></div>`;
    for (const t of histTypes) {
      const rows = hist[t];
      html += `<div class="dns-type"><span class="dns-t">${DNS_LABEL[t]}</span>
        <div class="dns-vals">${rows.slice(0, 5).map(dnsHistRow).join('')}
        ${rows.length > 5 ? `<div class="faint" style="font-size:11px;padding:3px 0">+${rows.length - 5} earlier</div>` : ''}</div></div>`;
    }
    html += `</div>`;
  }
  const whRows = [['registrar', wh.registrar], ['created', wh.created], ['expires', wh.expires],
    ['contact', wh.contact_email]].filter(r => r[1]);
  if (whRows.length) {
    html += `<div class="dns-group"><div class="dns-gh">WHOIS</div><div class="ov" style="padding-top:6px">${
      whRows.map(([k, v]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div></div>`;
  }
  if (dns.subdomain_count)
    html += `<div class="faint" style="font-size:11px;padding:7px 3px">${fmtNum(dns.subdomain_count)} subdomains known to deep DNS · sources ${(dns.sources || []).join(', ')}</div>`;
  body.innerHTML = html;
}

function dnsValRow(r) {
  const meta = [];
  if (r.priority != null) meta.push('pri ' + r.priority);
  if (r.ttl != null) meta.push('ttl ' + r.ttl);
  if (r.first_seen) meta.push('since ' + (yearOf(r.first_seen) || r.first_seen));
  const org = r.organization ? `<div class="dns-org faint">${esc(r.organization)}</div>` : '';
  return `<div class="dns-row"><span class="dns-v mono">${esc(r.value)}</span>
    ${meta.length ? `<span class="dns-m faint">${esc(meta.join(' · '))}</span>` : ''}${org}</div>`;
}
function dnsHistRow(r) {
  return `<div class="dns-row"><span class="dns-v mono">${esc(r.value)}</span>
    <span class="dns-m faint">${esc(fmtRange(r.first_seen, r.last_seen))}</span></div>`;
}

function secRow(x) {
  const by = (x.found_by || []).map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('');
  return `<div class="srow">
    <div class="st1"><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span>
      <span class="name">${esc(x.type)}</span>${by ? `<span style="margin-left:auto;display:flex;gap:3px">${by}</span>` : ''}</div>
    <div class="match">${esc(x.match)}</div>
    <div class="src" title="${esc(x.source)}">${esc(splitUrl(x.source).host)}${esc(splitUrl(x.source).path)}</div>
  </div>`;
}

/* Files: expandable · source + request + response (item 10) */
function fileRow(f, i) {
  const p = splitUrl(f.url);
  const srcs = (f.sources || []).map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('');
  return `<div class="frow" data-file="${i}">
    <button class="fsummary">
      <span class="tag mono">${esc(f.subtype || f.kind)}</span>
      <span class="name mono" title="${esc(f.url)}">${esc(p.path)}</span>
      ${f.status ? `<span class="st ${statusClass(f.status)}">${f.status}</span>` : ''}
      <svg class="ic fchev"><use href="#i-chevron-down"></use></svg>
    </button>
    <div class="fmeta"><span class="faint">${esc(p.host)}</span>${srcs}</div>
    <div class="fdetail"></div>
  </div>`;
}

/* Discovered-files type filter, built from the kinds actually present in this
   scan (js, json, config, backup, image, ...), plus a synthetic "code" group
   that collects the source / config / data kinds. Client-side; re-renders the
   list without refetching. */
const CODE_FILE_TYPES = new Set(['js', 'ts', 'jsx', 'tsx', 'json', 'config', 'env',
  'source', 'php', 'py', 'rb', 'go', 'java', 'xml', 'yaml', 'yml', 'ini', 'log',
  'backup', 'angular', 'sql']);
function fileTypeOf(f) { return (f.subtype || f.kind || 'other'); }

/* The host a file was served from, and the addresses behind that host. Both are
   derived · a file record carries a URL, not a resolved address. */
const fileHostOf = f => splitUrl(f.url).host;
const fileIpsOf = f => [...(HOST_IPS.get(fileHostOf(f)) || [])];

function buildFileFilter(containerId, prefix) {
  const files = allFiles();
  const types = [...new Set(files.map(fileTypeOf))].sort();
  const codeCount = files.filter(f => CODE_FILE_TYPES.has(fileTypeOf(f))).length;
  const typeOpts = [['', `all types (${files.length})`]];
  if (codeCount && codeCount < files.length)
    typeOpts.push(['__code', `code (${codeCount})`]);
  types.forEach(t => typeOpts.push(
    [t, `${t} (${files.filter(f => fileTypeOf(f) === t).length})`]));

  // Kind, status, host and address answer four different questions ("what is
  // it?", "did it actually serve?", "who served it?", "off which box?"), so all
  // four are offered and they combine.
  panelFilter(containerId, prefix, [
    { key: 'fileType', id: 'FileType', aria: 'Filter discovered files by type',
      value: F.fileType, options: typeOpts, onChange: refreshFiles },
    { key: 'fileStatus', id: 'FileStatus', aria: 'Filter discovered files by response code',
      value: F.fileStatus, options: statusOptions(files, f => f.status, 'all status'),
      onChange: refreshFiles },
    { key: 'fileHost', id: 'FileHost', aria: 'Filter discovered files by host',
      value: F.fileHost, options: facetOptions(files, fileHostOf, 'all hosts'),
      onChange: refreshFiles },
    { key: 'fileIp', id: 'FileIp', aria: 'Filter discovered files by serving IP',
      value: F.fileIp, options: facetOptions(files, fileIpsOf, 'all IPs', 'no IP'),
      onChange: refreshFiles },
  ]);
}

function fileMatches(f) {
  if (!matchesStatusFilter(F.fileStatus, f.status)) return false;
  if (!matchesFacet(F.fileHost, fileHostOf(f))) return false;
  if (!matchesFacet(F.fileIp, fileIpsOf(f))) return false;
  if (!F.fileType) return true;
  if (F.fileType === '__code') return CODE_FILE_TYPES.has(fileTypeOf(f));
  return fileTypeOf(f) === F.fileType;
}
const fileFiltered = () => !!(F.fileType || F.fileStatus || F.fileHost || F.fileIp);
const filteredFiles = () => allFiles().filter(fileMatches);

/* Render (or re-render) the file rows for the active filters. Each row keeps
   its original index into SCAN.files, so expanding still finds the record. */
function renderFileList() {
  const list = document.getElementById('fileList');
  if (!list) return;
  const rows = [];
  allFiles().forEach((f, i) => { if (fileMatches(f)) rows.push(fileRow(f, i)); });
  list.innerHTML = rows.join('') ||
    emptyMini(fileFiltered() ? 'no files match those filters' : 'none');
  list.querySelectorAll('.frow').forEach(r =>
    r.querySelector('.fsummary').addEventListener('click', () => toggleFile(r)));
}

function fileDetail(f) {
  const blocks = [];
  const kvt = (rows) => `<div class="kvtable">${rows.filter(r => r[1] != null && r[1] !== '')
    .map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>`;
  // provenance
  const srcLabels = (f.sources || []).map(sc => `${sc} (${sourceMeta(sc).label})`).join(', ');
  blocks.push(`<div class="fdet-block"><h6>${icon('point-filled')} Source</h6>
    <div class="row wrap" style="gap:5px">${(f.sources || []).map(sourceChip).join('') || '<span class="faint">unknown</span>'}</div>
    ${(f.found_on && f.found_on.length) ? `<div class="faint mono" style="font-size:11px;margin-top:6px">found on: ${esc(f.found_on.slice(0, 2).join('  '))}</div>` : ''}</div>`);
  // request
  const reqRows = [['method', 'GET'], ['url', f.url]];
  const rqh = f.req_headers || {};
  blocks.push(`<div class="fdet-block"><h6>${icon('arrow-left')} Request</h6>${kvt(reqRows)}
    ${Object.keys(rqh).length ? `<div class="hd-mini">${Object.entries(rqh).slice(0, 6).map(([k, v]) => `<span><b>${esc(k)}</b>: ${esc(String(v).slice(0, 80))}</span>`).join('')}</div>` : ''}</div>`);
  // response
  const rsh = f.resp_headers || {};
  const respRows = [['status', f.status], ['content-type', f.content_type], ['size', f.size != null ? fmtBytes(f.size) : null], ['final url', f.final_url && f.final_url !== f.url ? f.final_url : null]];
  blocks.push(`<div class="fdet-block"><h6>${icon('list-details')} Response</h6>${kvt(respRows)}
    ${Object.keys(rsh).length ? `<div class="kvtable" style="margin-top:6px">${Object.entries(rsh).map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>` : ''}</div>`);
  if (f.resp_body) {
    blocks.push(`<div class="fdet-block"><h6>${icon('message-code')} Body preview</h6>
      ${decodeWidget(f.resp_body, 'file' + short(f.url))}
      <div class="codebox">${esc(f.resp_body.slice(0, 4000))}</div></div>`);
  }
  return `<div class="fdet">${blocks.join('')}</div>`;
}
function short(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return Math.abs(h).toString(36); }

function emptyMini(t) { return `<div class="muted" style="padding:8px 10px;font-size:12px">${esc(t)}</div>`; }
function setCount(id, n) { const e = document.getElementById(id); if (e) e.textContent = fmtNum(n); }

/* Wire clickable host / IP chips + port rows after each panel render.
   Scoped to the left panel on purpose: the detail view renders the same chip
   classes and binds its own handler (which leaves detail mode first), so a
   document-wide query here would bind both and the two would cancel each other
   out · the filter would toggle on and straight back off in one click.

   One delegated listener rather than a binding pass per node: a section
   re-renders on every filter change, and re-binding every chip in the panel each
   time used to stack a second handler on the chips that had *not* been redrawn,
   so their next click set a filter and immediately cleared it again. */
let _sideWired = false;
function wirePanelInteractions() {
  const side = document.getElementById('side');
  if (!side || _sideWired) return;
  _sideWired = true;
  side.addEventListener('click', (e) => {
    const ip = e.target.closest('.chip-ip[data-ip], .ipaddr[data-ip]');
    if (ip) { e.stopPropagation(); setIpFilter(ip.dataset.ip); return; }
    const host = e.target.closest('.chip-host[data-host]');
    if (host) { e.stopPropagation(); setHostFilter(host.dataset.host); return; }
    // port rows: expand to reveal version / CPE / script output
    const port = e.target.closest('.prow.has-detail .psummary');
    if (port) { port.closest('.prow').classList.toggle('open'); return; }
    // finding rows: expand to reveal risk / fix / evidence
    const find = e.target.closest('.find-row .find-sum');
    if (find) {
      const row = find.closest('.find-row');
      find.setAttribute('aria-expanded', String(row.classList.toggle('open')));
      return;
    }
    const item = e.target.closest('.sitem[data-host]');
    if (item) setHostFilter(item.dataset.host);
    // file rows are wired by renderFileList, which owns their expanded detail
  });
}
function toggleFile(row) {
  const open = row.classList.toggle('open');
  const det = row.querySelector('.fdetail');
  if (!open) { det.innerHTML = ''; return; }
  const f = (SCAN.files || [])[+row.dataset.file];
  if (!f) return;
  det.innerHTML = fileDetail(f);
  wireDecode(det);
}

/* ---- date helpers (DNS history duration / year) --------------------------- */
function yearOf(d) { const m = String(d || '').match(/^(\d{4})/); return m ? m[1] : null; }
function durationOf(first, last) {
  if (!first) return '';
  const a = new Date(first).getTime(), b = last ? new Date(last).getTime() : Date.now();
  if (isNaN(a) || isNaN(b) || b < a) return '';
  const days = Math.round((b - a) / 86400000);
  if (days < 1) return '<1d';
  if (days < 31) return days + 'd';
  if (days < 365) return Math.round(days / 30) + 'mo';
  const y = days / 365;
  return (y >= 10 ? Math.round(y) : y.toFixed(1).replace(/\.0$/, '')) + 'y';
}
function fmtRange(first, last) {
  const fy = yearOf(first), ly = yearOf(last), dur = durationOf(first, last);
  if (fy && ly && fy !== ly) return `${fy} → ${ly}${dur ? ' · ' + dur : ''}`;
  if (fy && last) return `${fy}${dur ? ' · ' + dur : ''}`;
  if (fy) return `since ${fy}`;
  return last ? 'until ' + (ly || last) : '';
}

/* ---- requests table ------------------------------------------------------- */
function matchType(t) {
  if (!F.type) return true;
  if (F.type === 'xhr') return t === 'xhr' || t === 'fetch';
  return t === F.type;
}
function matchStatus(code) {
  if (!F.status) return true;
  if (F.status === 'none') return !code;
  if (/^\dxx$/.test(F.status)) return code && Math.floor(code / 100) === +F.status[0];
  return String(code) === F.status;
}
/* Which pass found the endpoint · an endpoint can carry several sources, so it
   matches if any of them is the one asked for. "none" is the escape hatch for
   the records that never recorded where they came from. */
function matchSource(sources) {
  if (!F.source) return true;
  const list = sources || [];
  if (F.source === 'none') return !list.length;
  return list.includes(F.source);
}

function filtered() {
  const q = F.search.toLowerCase();
  return (SCAN.endpoints || []).filter(e => {
    if (F.scope === 'in' && !e.in_scope) return false;
    if (F.classifiedOnly && !(e.classifications && e.classifications.length)) return false;
    if (!matchType(e.type)) return false;
    if (!matchStatus(e.status)) return false;
    if (!matchSource(e.sources)) return false;
    if (F.host && e.host !== F.host) return false;
    if (F.ip && !(IP_HOSTS.get(F.ip) || new Set()).has(e.host)) return false;
    if (q) {
      const hay = (e.url + ' ' + e.method + ' ' + (e.sources || []).join(' ') + ' ' + (e.fields || []).map(f => f.name).join(' ')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/* Build the status filter options from the codes actually present (item 9) */
function buildStatusFilter() {
  const sel = document.getElementById('statusFilter');
  if (!sel) return;
  const codes = new Set(), classes = new Set();
  let hasNone = false;
  (SCAN.endpoints || []).forEach(e => {
    if (e.status) { codes.add(e.status); classes.add(Math.floor(e.status / 100) + 'xx'); }
    else hasNone = true;
  });
  const opts = ['<option value="">all status</option>'];
  [...classes].sort().forEach(c => opts.push(`<option value="${c}">${c}</option>`));
  [...codes].sort((a, b) => a - b).forEach(c => opts.push(`<option value="${c}">${c}</option>`));
  if (hasNone) opts.push('<option value="none">no status</option>');
  sel.innerHTML = opts.join('');
}

/* Discovery filter · what actually found each endpoint (crawler, JS analysis,
   wayback, robots, sitemap, deep crawl …). Built from the source codes present
   in this scan, busiest first and spelled out with the label the source chips
   use, so the dropdown reads as findings rather than as one-letter codes.

   An endpoint can be found by more than one pass, so the counts add up to more
   than the endpoint total · each option says how many endpoints that pass
   contributed to, which is the question being asked. */
function buildSourceFilter() {
  const sel = document.getElementById('sourceFilter');
  if (!sel) return;
  const eps = SCAN.endpoints || [];
  const counts = new Map();
  let none = 0;
  eps.forEach(e => {
    const srcs = e.sources || [];
    if (!srcs.length) { none++; return; }
    srcs.forEach(sc => counts.set(sc, (counts.get(sc) || 0) + 1));
  });
  const opts = [`<option value="">all findings (${fmtNum(eps.length)})</option>`];
  [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .forEach(([sc, n]) => {
      const label = sourceMeta(sc).label;
      const text = label && label !== sc ? `${label} · ${sc} (${fmtNum(n)})` : `${sc} (${fmtNum(n)})`;
      opts.push(`<option value="${esc(sc)}">${esc(text)}</option>`);
    });
  if (none) opts.push(`<option value="none">no source recorded (${fmtNum(none)})</option>`);
  sel.innerHTML = opts.join('');
  sel.disabled = !counts.size && !none;
  sel.value = F.source || '';
}

/* Domain / subdomain filter · every host seen in this scan (apex first).

   The host and IP filters are supportive, not exclusive: you can hold a
   subdomain AND an IP at once and the list/graph show their intersection. So
   when an IP is active this dropdown is narrowed to the hosts that resolve to it
   (`constraintIp`) · picking from it can only ever produce a valid combination.
   With no IP held it lists every host. */
function buildHostFilter(constraintIp) {
  const sel = document.getElementById('hostFilter');
  if (!sel) return;
  const domain = (SCAN.meta || {}).domain || '';
  let hosts = [...new Set((SCAN.subdomains || []).map(s => s.host).filter(Boolean))];
  if (constraintIp) {
    const allow = new Set(hostsOfIp(constraintIp));
    hosts = hosts.filter(h => allow.has(h));
  }
  hosts.sort((a, b) => (a === domain ? -1 : b === domain ? 1 : a.localeCompare(b)));
  const label = constraintIp ? `all hosts on ${constraintIp}` : 'all hosts';
  const opts = [`<option value="">${esc(label)}</option>`];
  hosts.forEach(h => opts.push(
    `<option value="${esc(h)}">${esc(h)}${h === domain ? ' (apex)' : ''}</option>`));
  sel.innerHTML = opts.join('');
  if (F.host) sel.value = F.host;
}

/* IP filter · every resolved IP in this scan, busiest first, labelled with how
   many hosts sit on it and who owns it. Supportive with the host filter: when a
   subdomain is held this dropdown is narrowed to just that host's IPs
   (`constraintHost`), so selecting one further scopes to a single address served
   by that host rather than replacing the host selection. With no host held it
   lists every IP. */
function buildIpFilter(constraintHost) {
  const sel = document.getElementById('ipFilter');
  if (!sel) return;
  let recs = ((SCAN.infra && SCAN.infra.ips) || []).slice();
  // any IP seen on a subdomain but missing an infra record still gets an entry
  const known = new Set(recs.map(r => r.ip));
  IP_HOSTS.forEach((_, ip) => { if (!known.has(ip)) recs.push({ ip }); });
  if (constraintHost) {
    const allow = new Set([...(HOST_IPS.get(constraintHost) || [])]);
    recs = recs.filter(r => allow.has(r.ip));
  }
  recs.sort((a, b) => hostsOfIp(b.ip).length - hostsOfIp(a.ip).length || a.ip.localeCompare(b.ip));
  const label = constraintHost ? `all IPs of ${constraintHost}` : 'all IPs';
  const opts = [`<option value="">${esc(label)}</option>`];
  recs.forEach(r => {
    const n = hostsOfIp(r.ip).length;
    const org = (r.org || '').split(/[,(]/)[0].trim();
    const lab = `${r.ip}${n ? ` · ${n} host${n === 1 ? '' : 's'}` : ''}${org ? ` · ${org}` : ''}`;
    opts.push(`<option value="${esc(r.ip)}">${esc(lab)}</option>`);
  });
  sel.innerHTML = opts.join('');
  sel.disabled = recs.length === 0 && !constraintHost;
  if (F.ip) sel.value = F.ip;
}

function renderTable() {
  const body = document.getElementById('tBody');
  const rows = filtered();
  const shown = rows.slice(0, ROW_CAP);
  // On a huge crawl the page holds only the top slice the server sent (see
  // endpoints_capped), not every endpoint · say so, and report the real total
  // from meta so the count never pretends the table is the whole surface.
  const capped = !!(SCAN && SCAN.endpoints_capped);
  const loaded = (SCAN && SCAN.endpoints_shown) || (SCAN.endpoints || []).length;
  const total = (SCAN && SCAN.endpoints_total) || rows.length;
  const tc = document.getElementById('tCount');
  const base = rows.length > ROW_CAP
    ? `showing ${ROW_CAP} of ${fmtNum(rows.length)}`
    : `${fmtNum(rows.length)} request${rows.length === 1 ? '' : 's'}`;
  tc.textContent = capped
    ? `${base} · top ${fmtNum(loaded)} of ${fmtNum(total)} loaded`
    : base;
  tc.title = capped
    ? `This scan has ${fmtNum(total)} endpoints. The highest-priority `
      + `${fmtNum(loaded)} are loaded here (classified requests, forms, JS and `
      + `fielded endpoints first); filters and search apply to those.`
    : '';

  if (!rows.length) {
    body.innerHTML = `<div class="empty" style="padding:40px">${icon('file-search')}
      <h4>No matching requests</h4><p>Adjust the filters above to widen the search.</p></div>`;
    return;
  }
  body.innerHTML = shown.map(rowHtml).join('');
  body.querySelectorAll('.trow').forEach(r => {
    r.querySelector('.tsummary').addEventListener('click', () => toggleRow(r));
  });
}

function rowHtml(e, i) {
  const u = splitUrl(e.url);
  const cls = (e.classifications || []).slice(0, 3).map(c =>
    `<span class="sev ${sevClass(c.severity)}" title="${esc(c.fields.join(', '))}">${esc(c.category)}</span>`).join('');
  const more = (e.classifications || []).length > 3 ? `<span class="faint" style="font-size:11px">+${e.classifications.length - 3}</span>` : '';
  const tags = [];
  if (!e.in_scope) tags.push(`<span class="tag oos-tag">${icon('external-link')} out-of-scope</span>`);
  (e.sources || []).forEach(sc => tags.push(`<span class="src-chip" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`));
  return `<div class="trow ${e.in_scope ? '' : 'oos'}" data-i="${i}" data-eid="${esc(e.id || '')}">
    <div class="tsummary">
      <span><span class="method ${esc(e.method)}">${esc(e.method)}</span></span>
      <div class="c-url">
        <div class="u"><span class="path">${esc(u.path)}</span> <span class="host">${esc(u.host)}</span></div>
        ${tags.length ? `<div class="tags">${tags.join('')}</div>` : ''}
      </div>
      <span class="c-type">${esc(e.type)}</span>
      <span class="c-cls">${cls || '<span class="faint" style="font-size:11px">·</span>'}${more}</span>
      <span class="c-status ${statusClass(e.status)}">${e.status || '·'}</span>
    </div>
    <div class="tdetail"></div>
  </div>`;
}

async function toggleRow(row) {
  const open = row.classList.toggle('open');
  const det = row.querySelector('.tdetail');
  if (!open) { det.innerHTML = ''; return; }
  const i = +row.dataset.i;
  const light = filtered()[i];
  if (!light) return;
  // The list row carries only light fields; the bodies/headers/found-on that the
  // detail shows are fetched per endpoint and merged over the light record.
  const e = await loadEndpointDetail(row.dataset.eid, light, det);
  if (!row.classList.contains('open')) return;   // collapsed again while loading
  det.innerHTML = detailHtml(e);
  det.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => {
    navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy);
    b.innerHTML = icon('circle-check-filled') + ' copied';
    setTimeout(() => b.innerHTML = icon('copy') + ' copy', 1400);
  }));
  wireDecode(det);
}

/* Fetch one endpoint's full record (bodies, headers, found-on, JS origin) and
   merge it over the light row we already have. Cached per endpoint id; falls back
   to the light record if the detail request fails, so a row still opens offline. */
async function loadEndpointDetail(eid, light, det) {
  if (!eid) return light;
  if (EP_DETAIL.has(eid)) return EP_DETAIL.get(eid);
  det.innerHTML = `<div class="det-loading">${icon('loader-2')} loading detail…</div>`;
  try {
    const full = await getJSON(
      withBase(`/api/scan/${encodeURIComponent(SCAN_ID)}/endpoint/${encodeURIComponent(eid)}`));
    const merged = Object.assign({}, light, full);
    EP_DETAIL.set(eid, merged);
    return merged;
  } catch (e) {
    return light;
  }
}

function detailHtml(e) {
  const blocks = [];

  if (e.fields && e.fields.length) {
    blocks.push(`<div class="det-block"><h5>${icon('forms')} Fields (${e.fields.length})</h5>
      <div class="fieldlist">${e.fields.map(f => {
      const c = f.classification;
      return `<div class="fieldrow"><span class="fname">${esc(f.name)}</span>
          <span class="ftype">${esc(f.type || f.location || '')}</span>
          <span class="fcls">${c ? `<span class="sev ${sevClass(c.severity)}" title="${esc(c.category)}">${esc(c.label)}</span>` : ''}</span></div>`;
    }).join('')}</div></div>`);
  }

  if (e.classifications && e.classifications.length) {
    blocks.push(`<div class="det-block"><h5>${icon('shield-half-filled')} Field intents</h5>
      <div class="row wrap">${e.classifications.map(c =>
      `<span class="sev ${sevClass(c.severity)}">${esc(c.category)} · ${esc(c.fields.join(', '))}</span>`).join('')}</div></div>`);
  }

  if (e.js_origin && e.js_origin.length) {
    blocks.push(`<div class="det-block"><h5>${icon('braces')} Request logic (JS)</h5>
      ${e.js_origin.map(o => `<div class="jsorigin">${o.handler ? `<span class="h">${esc(o.handler)}()</span> · ` : ''}${esc(o.kind)} · ${esc(splitUrl(o.file).path)}:${o.line || '?'}
        ${o.snippet ? `<div class="muted" style="margin-top:4px">${esc(o.snippet)}</div>` : ''}</div>`).join('')}</div>`);
  }

  const metaRows = [];
  metaRows.push(['url', e.url]);
  if (e.sources) metaRows.push(['source', e.sources.map(sc => `${sc} · ${sourceMeta(sc).label}`).join('   ')]);
  if (e.content_type) metaRows.push(['content-type', e.content_type]);
  if (e.found_on && e.found_on.length) metaRows.push(['found on', e.found_on.slice(0, 3).join('  ')]);
  if (e.notes && e.notes.length) metaRows.push(['notes', e.notes.join('; ')]);
  blocks.push(`<div class="det-block"><h5>${icon('info-circle')} Request
      <button class="btn sm ghost" style="margin-left:auto;height:22px" data-copy="${esc(e.url)}">${icon('copy')} copy</button></h5>
    <div class="kvtable">${metaRows.map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>
    ${decodeWidget(e.url, 'req' + e.id)}</div>`);

  const rq = e.req_headers || {};
  if (Object.keys(rq).length) {
    blocks.push(`<div class="det-block"><h5>${icon('arrow-left')} Request headers</h5>
      <div class="kvtable">${Object.entries(rq).map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div></div>`);
  }
  const rh = e.resp_headers || {};
  if (Object.keys(rh).length) {
    blocks.push(`<div class="det-block"><h5>${icon('list-details')} Response headers</h5>
      <div class="kvtable">${Object.entries(rh).map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div></div>`);
  }
  if (e.resp_body) {
    blocks.push(`<div class="det-block" style="grid-column:1/-1"><h5>${icon('message-code')} Response body preview</h5>
      ${decodeWidget(e.resp_body, 'body' + e.id)}
      <div class="codebox">${esc(e.resp_body.slice(0, 6000))}</div></div>`);
  }
  return `<div class="det-grid">${blocks.join('')}</div>`;
}

/* ---- filters wiring ------------------------------------------------------- */
function wireTableControls() {
  const search = document.getElementById('tSearch');
  let t;
  search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { F.search = search.value.trim(); renderTable(); }, 160); });

  document.getElementById('typeFilter').addEventListener('change', e => { F.type = e.target.value; renderTable(); });
  document.getElementById('statusFilter').addEventListener('change', e => { F.status = e.target.value; renderTable(); });
  const src = document.getElementById('sourceFilter');
  if (src) src.addEventListener('change', e => { F.source = e.target.value; renderTable(); });

  const host = document.getElementById('hostFilter');
  if (host) host.addEventListener('change', e => setHostFilter(e.target.value));

  const ip = document.getElementById('ipFilter');
  if (ip) ip.addEventListener('change', e => setIpFilter(e.target.value));

  const scope = document.getElementById('scopeToggle');
  scope.addEventListener('click', () => {
    F.scope = F.scope === 'in' ? 'all' : 'in';
    scope.classList.toggle('on', F.scope === 'in');
    document.getElementById('scopeLabel').textContent = F.scope === 'in' ? 'in-scope' : 'all scopes';
    scope.querySelector('use').setAttribute('href', F.scope === 'in' ? '#i-eye' : '#i-eye-off');
    renderTable();
  });

  const clsChip = document.getElementById('clsToggle');
  clsChip.addEventListener('click', () => {
    F.classifiedOnly = !F.classifiedOnly;
    clsChip.classList.toggle('on', F.classifiedOnly);
    renderTable();
  });

  const exp = document.getElementById('gExpand');
  if (exp) exp.addEventListener('click', toggleDetailMode);
}

/* Central host filter · drives the request list AND the graph. Clicking the
   same host again clears it. Selecting one host is also what unlocks the
   graph's endpoint / file / field layers.

   Supportive with the IP filter: a held IP is kept if the new host resolves to
   it, and dropped only when the two would contradict each other. */
function setHostFilter(host) {
  F.host = (F.host === host || !host) ? null : host;
  if (F.host && F.ip && !(HOST_IPS.get(F.host) || new Set()).has(F.ip)) {
    F.ip = null;                       // the held IP does not serve this host
  }
  rebuildFilterOptions();
  syncFilterUI();
  renderTable();
  syncGraphFilter();
}

/* IP filter · same contract; scopes to hosts resolving to that address, and
   combines with a held subdomain rather than replacing it. */
function setIpFilter(ip) {
  F.ip = (F.ip === ip || !ip) ? null : ip;
  if (F.ip && F.host && !(IP_HOSTS.get(F.ip) || new Set()).has(F.host)) {
    F.host = null;                     // the held host is not on this IP
  }
  rebuildFilterOptions();
  syncFilterUI();
  renderTable();
  syncGraphFilter();
}

/* Re-scope each dropdown to what is still selectable given the other filter, so
   the two can only ever form a valid combination. */
function rebuildFilterOptions() {
  buildHostFilter(F.ip || null);
  buildIpFilter(F.host || null);
}

/* keep the dropdowns and the left-panel selection state in step with F */
function syncFilterUI() {
  const hs = document.getElementById('hostFilter');
  if (hs) hs.value = F.host || '';
  const is = document.getElementById('ipFilter');
  if (is) is.value = F.ip || '';
  document.querySelectorAll('.sitem').forEach(s =>
    s.classList.toggle('active', !!F.host && s.dataset.host === F.host));
  document.querySelectorAll('.ipcard').forEach(c =>
    c.classList.toggle('active', !!F.ip && c.dataset.ip === F.ip));
}

/* Graph scope: a held subdomain wins as the anchor (its subtree, detail
   unlocked). An IP alone shows every host on it (detail locked). With both held
   the host is guaranteed to sit on the IP, so the host subtree is the
   intersection.

   The address itself is passed through as well, not just the hosts on it. A host
   usually resolves to several addresses, so scoping by hosts alone still drew
   every one of those addresses · and, hanging off them, their ports and their
   announcing AS. With `ip` set the graph keeps that one address and nothing
   else at that layer, which takes the other addresses' ports and AS nodes out
   with them. */
function syncGraphFilter() {
  if (!GRAPH) return;
  const hosts = F.host ? [F.host] : F.ip ? hostsOfIp(F.ip) : null;
  GRAPH.setFilter({ hosts, ip: F.ip || null, detail: !!F.host });
}

/* ---- side sections collapse ---------------------------------------------- */
function wireSections() {
  document.querySelectorAll('.side-sec .sh').forEach(sh =>
    sh.addEventListener('click', () => sh.parentElement.classList.toggle('collapsed')));
}

/* ---- detail view (item 11): hide graph + table, expand info full-width ----- */
function toggleDetailMode() {
  detailMode = !detailMode;
  document.querySelector('.scan-layout').classList.toggle('detail-mode', detailMode);
  const dv = document.getElementById('detailView');
  dv.hidden = !detailMode;
  const btn = document.getElementById('gExpand');
  if (detailMode) {
    renderDetail();
    if (btn) { btn.querySelector('use').setAttribute('href', '#i-arrows-minimize'); btn.title = 'Back to graph'; }
    dv.scrollTop = 0;
  } else if (btn) {
    btn.querySelector('use').setAttribute('href', '#i-arrows-maximize'); btn.title = 'Expand detail view';
  }
}

/* Every table gets the full width of the page and its own row · nothing sits
   side by side, so no data set has to be read through a horizontal scrollbar.

   Each section here is the same thing the left panel shows, at full size: it
   collapses from its own header, and it carries the same filter row, reading the
   same state. Collapsing one section is how the others get the screen. */
const DV_SECTIONS = [
  { id: 'findings', title: 'Findings', short: 'findings', icon: 'shield-half-filled', filter: buildFindingFilter },
  { id: 'dns', title: 'DNS records & history', short: 'DNS', icon: 'network' },
  { id: 'subdomains', title: 'Subdomains', short: 'subdomains', icon: 'world', filter: buildSubFilter },
  { id: 'infra', title: 'Infrastructure', short: 'IPs', icon: 'server-2', filter: buildAsnFilter },
  { id: 'tech', title: 'Tech stack', short: 'tech', icon: 'fingerprint', filter: buildTechFilter },
  { id: 'secrets', title: 'Secrets', short: 'secrets', icon: 'key', filter: buildSecretFilter },
  { id: 'files', title: 'Discovered files', short: 'files', icon: 'file-code', filter: buildFileFilter },
];
/* which sections the operator has folded away · kept for the session so leaving
   and re-entering the detail view does not undo the arrangement */
const DV_COLLAPSED = new Set();

function renderDetail() {
  const dv = document.getElementById('detailView');
  const m = (SCAN || {}).meta || {};
  const jumps = DV_SECTIONS.map(sec => {
    const n = dvCounts(sec.id).total;
    return n ? `<button class="dv-stat" data-jump="dv-${sec.id}"><b>${fmtNum(n)}</b> ${esc(sec.short)}</button>` : '';
  }).join('');
  dv.innerHTML = `
    <div class="dv-head">
      <div><h2>${esc(m.domain || '')}</h2><div class="dv-substats">${jumps}</div></div>
      <div class="dv-head-actions">
        <button class="btn sm ghost" id="dvFoldAll">${icon('chevron-down')} Collapse all</button>
        <button class="btn sm ghost" id="dvUnfoldAll">${icon('arrows-maximize')} Expand all</button>
        <button class="btn" id="dvCollapse">${icon('arrows-minimize')} Back to graph</button>
      </div>
    </div>
    <div class="dv-grid">${DV_SECTIONS.map(dvShell).join('')}</div>`;

  DV_SECTIONS.forEach(sec => {
    if (sec.filter) sec.filter(`dvFilter-${sec.id}`, 'dv');
    renderDvBody(sec.id);
  });
  syncPanelSelects();

  dv.querySelector('#dvCollapse').addEventListener('click', toggleDetailMode);
  dv.querySelector('#dvFoldAll').addEventListener('click', () => dvFoldAll(true));
  dv.querySelector('#dvUnfoldAll').addEventListener('click', () => dvFoldAll(false));
  dv.querySelectorAll('.dv-ch').forEach(btn =>
    btn.addEventListener('click', () => dvToggleSection(btn.dataset.sec)));
  dv.querySelectorAll('[data-jump]').forEach(b => b.addEventListener('click', () => {
    const el = document.getElementById(b.dataset.jump);
    if (!el) return;
    if (el.classList.contains('collapsed')) dvToggleSection(el.dataset.sec);
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));
}

/* The empty shell of one section · header, filter row, body. The body is filled
   by renderDvBody so a filter change redraws only what it changed. */
function dvShell(sec) {
  const folded = DV_COLLAPSED.has(sec.id);
  return `<section class="dv-card${folded ? ' collapsed' : ''}" id="dv-${sec.id}" data-sec="${sec.id}">
    <button class="dv-ch" data-sec="${sec.id}" aria-expanded="${folded ? 'false' : 'true'}"
            aria-controls="dvWrap-${sec.id}">
      ${icon(sec.icon)}<h3>${esc(sec.title)}</h3>
      <span class="count" id="dvCount-${sec.id}"></span>
      <svg class="ic chev"><use href="#i-chevron-down"></use></svg>
    </button>
    <div class="dv-cwrap" id="dvWrap-${sec.id}">
      ${sec.filter ? `<div class="panel-filter dv-filter" id="dvFilter-${sec.id}" hidden></div>` : ''}
      <div class="dv-slot" id="dvBody-${sec.id}"></div>
    </div>
  </section>`;
}

function dvToggleSection(id) {
  const card = document.getElementById('dv-' + id);
  if (!card) return;
  const folded = card.classList.toggle('collapsed');
  if (folded) DV_COLLAPSED.add(id); else DV_COLLAPSED.delete(id);
  const head = card.querySelector('.dv-ch');
  if (head) head.setAttribute('aria-expanded', folded ? 'false' : 'true');
}

function dvFoldAll(folded) {
  DV_SECTIONS.forEach(sec => {
    const card = document.getElementById('dv-' + sec.id);
    if (!card) return;
    card.classList.toggle('collapsed', folded);
    if (folded) DV_COLLAPSED.add(sec.id); else DV_COLLAPSED.delete(sec.id);
    const head = card.querySelector('.dv-ch');
    if (head) head.setAttribute('aria-expanded', folded ? 'false' : 'true');
  });
}

/* How many rows a section holds, and how many survive its filter · the header
   says "12 of 480" rather than pretending the filtered view is everything. */
function dvCounts(id) {
  switch (id) {
    case 'dns': {
      const dns = (SCAN && SCAN.dns) || {};
      const n = o => Object.values(o || {}).reduce((a, v) => a + v.length, 0);
      const total = n(dns.records) + n(dns.history);
      return { shown: total, total };
    }
    case 'findings': return { shown: filteredFindings().length, total: allFindings().length };
    case 'subdomains': return { shown: filteredSubs().length, total: allSubs().length };
    case 'infra': return { shown: filteredIps().length, total: allIps().length };
    case 'tech': return { shown: filteredTech().length, total: techEntries().length };
    case 'secrets': return { shown: filteredSecrets().length, total: allSecrets().length };
    case 'files': return { shown: filteredFiles().length, total: allFiles().length };
    default: return { shown: 0, total: 0 };
  }
}

/* Redraw one section of the detail view, if it is currently built. Called both
   on first render and on every filter change, from either copy of the row. */
function renderDvBody(id) {
  const slot = document.getElementById('dvBody-' + id);
  if (!slot || !SCAN) return;
  const body = {
    findings: () => dvFindingsBody(filteredFindings()),
    dns: () => dvDnsBody(SCAN.dns || {}),
    subdomains: () => dvSubdomainsBody(filteredSubs()),
    infra: () => dvInfraBody(filteredIps()),
    tech: () => dvTechBody(filteredTech()),
    secrets: () => dvSecretsBody(filteredSecrets()),
    files: () => dvFilesBody(filteredFiles()),
  }[id];
  slot.innerHTML = body ? body() : '';

  const { shown, total } = dvCounts(id);
  const badge = document.getElementById('dvCount-' + id);
  if (badge) {
    badge.textContent = shown === total ? fmtNum(total) : `${fmtNum(shown)} of ${fmtNum(total)}`;
    badge.classList.toggle('filtered', shown !== total);
  }
  wireDvInteractions(slot);
}

/* chips, expandable port rows and decode widgets inside one redrawn section */
function wireDvInteractions(root) {
  root.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', () => { toggleDetailMode(); setHostFilter(el.dataset.host); }));
  root.querySelectorAll('.chip-ip[data-ip]').forEach(el =>
    el.addEventListener('click', () => { toggleDetailMode(); setIpFilter(el.dataset.ip); }));
  root.querySelectorAll('.prow.has-detail .psummary').forEach(btn =>
    btn.addEventListener('click', () => btn.closest('.prow').classList.toggle('open')));
  root.querySelectorAll('.find-row .find-sum').forEach(btn =>
    btn.addEventListener('click', () => {
      const row = btn.closest('.find-row');
      btn.setAttribute('aria-expanded', String(row.classList.toggle('open')));
    }));
  wireDecode(root);
}

function dvEmpty(text, sub) {
  return `<div class="dv-body"><div class="empty" style="padding:26px">${icon('file-search')}
    <h4>${esc(text)}</h4>${sub ? `<p>${esc(sub)}</p>` : ''}</div></div>`;
}

/* DNS · current records, then the deep-DNS address timeline (which address
   served the domain, for how long, and out of whose network), then the full
   per-type history. The timeline is the part a deep scan pays for, so it is
   spelled out here rather than left implicit in a history table. */
function dvDnsBody(dns) {
  const recs = dns.records || {}, hist = dns.history || {};
  const nRec = Object.values(recs).reduce((a, v) => a + v.length, 0);
  const nHist = Object.values(hist).reduce((a, v) => a + v.length, 0);
  if (!nRec && !nHist)
    return dvEmpty('No DNS data', 'Run a Deep scan for full records and historical DNS.');
  let body = '';
  const curTypes = DNS_ORDER.filter(t => recs[t] && recs[t].length);
  if (curTypes.length) {
    body += `<h4 class="dv-sub">Current records</h4><table class="dv-table"><thead><tr>
      <th>Type</th><th>Value</th><th>Detail</th><th>Since</th><th>Held for</th></tr></thead><tbody>`;
    for (const t of curTypes) for (const r of recs[t]) {
      const detail = [r.priority != null ? 'pri ' + r.priority : '', r.ttl != null ? 'ttl ' + r.ttl : '', r.organization || ''].filter(Boolean).join(' · ');
      body += `<tr><td class="dv-rt">${DNS_LABEL[t]}</td><td class="mono">${esc(r.value)}</td>
        <td class="faint">${esc(detail)}</td>
        <td class="mono">${esc(r.first_seen ? yearOf(r.first_seen) || r.first_seen : '')}</td>
        <td class="mono">${esc(durationOf(r.first_seen, null))}</td></tr>`;
    }
    body += `</tbody></table>`;
  }
  body += dvAddressTimeline();
  const histTypes = DNS_ORDER.filter(t => hist[t] && hist[t].length);
  if (histTypes.length) {
    body += `<h4 class="dv-sub">${icon('history')} Historical DNS</h4>
      <p class="faint" style="font-size:12px;margin-bottom:8px">Previous IPs, name servers and MX with when each change happened, and how long each one stood. Click a type to open the full table.</p>`;
    for (const t of histTypes) {
      const rows = hist[t];
      const list = rows.slice(0, 4).map(r => `${esc(r.value)} <span class="faint">(${esc(fmtRange(r.first_seen, r.last_seen))})</span>`).join(' · ');
      body += `<details class="dv-details"><summary><span class="dv-rt">${DNS_LABEL[t]}</span>
        <span class="faint">${rows.length} record${rows.length === 1 ? '' : 's'}</span>
        <span class="dv-sum-list">${list}${rows.length > 4 ? ' …' : ''}</span></summary>
        <table class="dv-table"><thead><tr><th>Value</th><th>First seen</th><th>Last seen</th><th>Duration</th><th>Organization</th></tr></thead><tbody>
        ${rows.map(r => `<tr><td class="mono">${esc(r.value)}</td><td>${esc(r.first_seen || '')}</td><td>${esc(r.last_seen || '')}</td><td class="mono">${esc(durationOf(r.first_seen, r.last_seen))}</td><td class="faint">${esc(r.organization || '')}</td></tr>`).join('')}
        </tbody></table></details>`;
    }
  }
  return `<div class="dv-body">${body}</div>`;
}

/* Every address the domain has ever pointed at, newest window first: where it
   is, who announces it, how long it served, and whether it still does. */
function dvAddressTimeline() {
  if (!IP_SEEN.size) return '';
  const infra = new Map(allIps().map(r => [r.ip, r]));
  const rows = [...IP_SEEN.entries()]
    .sort((a, b) => (b[1].current ? 1 : 0) - (a[1].current ? 1 : 0)
      || String(b[1].first_seen || '').localeCompare(String(a[1].first_seen || '')))
    .map(([ip, s]) => {
      const rec = infra.get(ip) || {};
      const place = ipPlace(rec);
      return `<tr>
        <td class="mono"><span class="chip-ip" data-ip="${esc(ip)}">${icon('server-2')}${esc(ip)}</span></td>
        <td>${s.current ? '<span class="tag accent">current</span>' : '<span class="faint">retired</span>'}</td>
        <td>${esc(s.first_seen || '')}</td>
        <td>${esc(s.current ? '' : s.last_seen || '')}</td>
        <td class="mono">${esc(durationOf(s.first_seen, s.current ? null : s.last_seen))}</td>
        <td>${esc(place || '')}</td>
        <td class="faint">${esc(s.organization || rec.org || '')}</td>
        <td class="mono faint">${esc(rec.asn || '')}</td>
      </tr>`;
    }).join('');
  return `<h4 class="dv-sub">${icon('map-2')} Address timeline</h4>
    <p class="faint" style="font-size:12px;margin-bottom:8px">Where this domain has been hosted over time, from deep DNS: each address, the window it served in, how long that lasted, and the network it sat on.</p>
    <table class="dv-table"><thead><tr><th>IP</th><th>State</th><th>First seen</th><th>Last seen</th>
      <th>Duration</th><th>Location</th><th>Organization</th><th>ASN</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
}

function dvInfraBody(ips) {
  if (!ips.length)
    return dvEmpty(F.asn ? 'No addresses on that AS' : 'No IPs',
      F.asn ? 'Clear the AS filter to see the rest.' : '');
  const rows = ips.map(ip => {
    const hosts = ip.subdomains || [];
    const nports = (ip.ports || []).length;
    const portsCell = nports
      ? `<span class="tag mono" title="open ports · expand the row for services, versions and OS">${nports} open</span>`
      : (ip.scanned ? '<span class="faint">0 open</span>' : '<span class="faint">·</span>');
    const place = ipPlace(ip);
    const kind = ip.datacenter ? 'hosting' : ip.type || '';
    const seen = ipSeenText(ip.ip);
    const main = `<tr>
      <td class="mono"><span class="chip-ip" data-ip="${esc(ip.ip)}">${icon('server-2')}${esc(ip.ip)}</span></td>
      <td>${esc(ip.org || '')}</td>
      <td class="mono">${esc(ip.asn || '')}</td>
      <td>${place ? esc(place) : '<span class="faint">·</span>'}</td>
      <td>${esc(kind)}</td>
      <td class="mono">${seen ? esc(seen) : '<span class="faint">·</span>'}</td>
      <td>${esc((ip.os || {}).name || '')}${(ip.os || {}).accuracy ? ` <span class="faint">${ip.os.accuracy}%</span>` : ''}</td>
      <td>${portsCell}</td>
      <td>${(ip.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
      <td class="mono">${hosts.length}</td>
      <td>${hosts.map(h => `<span class="chip-host" data-host="${esc(h)}">${esc(h)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    </tr>`;
    // A second, full-width row carries the rich port/OS/script detail · the same
    // renderer the left Infrastructure panel uses, so the ports, service versions,
    // WhatWeb tech and default-script output are all "seen" here too.
    const pb = (nports || ip.os || (ip.traceroute || []).length) ? portsBlock(ip) : '';
    const detailRow = pb ? `<tr class="dv-ports-row"><td colspan="11"><div class="dv-ports">${pb}</div></td></tr>` : '';
    return main + detailRow;
  }).join('');
  return `<div class="dv-body"><table class="dv-table"><thead><tr>
    <th>IP</th><th>Org</th><th>ASN</th><th>Location</th><th>Type</th><th>Seen</th><th>OS</th>
    <th>Ports</th><th>Src</th><th>Hosts</th><th>Resolves for</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function dvSubdomainsBody(subs) {
  if (!subs.length)
    return dvEmpty(subFiltered() ? 'No subdomains match those filters' : 'No subdomains',
      subFiltered() ? 'Widen the status, IP or tech filter above.' : '');
  // Where each host's addresses sit, so a subdomain row answers "served from
  // where" without a trip to the infrastructure table.
  const infra = new Map(allIps().map(r => [r.ip, r]));
  const rows = subs.map(sd => {
    const places = [...new Set((sd.ips || []).map(ip => ipPlace(infra.get(ip) || {})).filter(Boolean))];
    return `<tr>
    <td class="mono"><span class="chip-host" data-host="${esc(sd.host)}">${esc(sd.host)}</span></td>
    <td class="${statusClass((sd.http || {}).status)} mono">${(sd.http || {}).status || (sd.resolved ? '·' : 'dns')}</td>
    <td>${(sd.ips || []).map(ip => `<span class="chip-ip" data-ip="${esc(ip)}">${icon('server-2')}${esc(ip)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    <td>${places.length ? esc(places.join(' · ')) : '<span class="faint">·</span>'}</td>
    <td>${(sd.tech || []).map(x => `<span class="tag mono">${esc(x)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    <td>${(sd.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
  </tr>`;
  }).join('');
  return `<div class="dv-body"><table class="dv-table"><thead><tr>
    <th>Host</th><th>Status</th><th>IPs</th><th>Location</th><th>Tech</th><th>Src</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

/* Tech stack: what was detected, on which subdomains, and on which IPs those
   subdomains resolve to · not just a bare list of fingerprints. */
function dvTechBody(entries) {
  if (!entries.length)
    return dvEmpty(F.tech ? 'That fingerprint is not in this scan' : 'No fingerprints');
  const rows = entries.map(([t, hosts]) => {
    const ips = ipsOfHosts(hosts);
    return `<tr>
      <td><span class="tag mono">${esc(t)}</span></td>
      <td class="mono">${hosts.length}</td>
      <td>${hosts.map(h => `<span class="chip-host" data-host="${esc(h)}">${esc(h)}</span>`).join(' ')}</td>
      <td class="mono">${ips.length}</td>
      <td>${ips.map(ip => `<span class="chip-ip" data-ip="${esc(ip)}">${icon('server-2')}${esc(ip)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    </tr>`;
  }).join('');
  return `<div class="dv-body"><table class="dv-table"><thead><tr>
    <th>Technology</th><th>Hosts</th><th>Detected on</th><th>IPs</th><th>Served from</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function dvFindingsBody(items) {
  if (!items.length)
    return dvEmpty((F.findSev || F.findCat) ? 'No findings match those filters' : 'No findings',
      allFindings().length ? '' : 'The surface looks clean, or no active review ran.');
  return `<div class="dv-body"><div class="find-list dv-find">${items.map(findRow).join('')}</div></div>`;
}

function dvSecretsBody(secrets) {
  if (!secrets.length)
    return dvEmpty(F.secretSev ? 'None at that severity' : 'None flagged');
  const rows = secrets.map(x => `<tr>
    <td><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span></td>
    <td>${esc(x.type)}</td><td class="mono wrap">${esc(x.match)}</td>
    <td>${(x.found_by || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    <td class="mono faint wrap">${esc(splitUrl(x.source).host + splitUrl(x.source).path)}</td>
  </tr>`).join('');
  return `<div class="dv-body"><table class="dv-table"><thead><tr>
    <th>Sev</th><th>Type</th><th>Match</th><th>Src</th><th>Location</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function dvFilesBody(files) {
  if (!files.length)
    return dvEmpty(fileFiltered() ? 'No files match those filters' : 'No files',
      fileFiltered() ? 'Widen the type, status, host or IP filter above.' : '');
  const rows = files.map(f => {
    const u = splitUrl(f.url);
    const ips = fileIpsOf(f);
    return `<tr>
      <td><span class="tag mono">${esc(f.subtype || f.kind)}</span></td>
      <td class="mono"><span class="chip-host" data-host="${esc(u.host)}">${esc(u.host)}</span></td>
      <td>${ips.map(ip => `<span class="chip-ip" data-ip="${esc(ip)}">${icon('server-2')}${esc(ip)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
      <td class="mono wrap">${esc(u.path)}</td>
      <td class="${statusClass(f.status)} mono">${f.status || '·'}</td>
      <td class="mono faint">${esc(f.size != null ? fmtBytes(f.size) : '')}</td>
      <td class="faint">${esc((f.content_type || '').split(';')[0])}</td>
      <td>${(f.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    </tr>`;
  }).join('');
  return `<div class="dv-body"><table class="dv-table"><thead><tr>
    <th>Kind</th><th>Host</th><th>IPs</th><th>Path</th><th>Status</th><th>Size</th><th>Type</th><th>Src</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}

/* ---- graph / table split -------------------------------------------------- */
/* The graph used to take a fixed ~half of the viewport, leaving the request
   table a cramped sliver. It is now user-sized: drag the handle, double-click to
   reset, or collapse the graph entirely to give the table the full height. The
   choice is remembered per browser. */
const GRAPH_H_KEY = 'argus-graph-h';
const GRAPH_COLLAPSED_KEY = 'argus-graph-collapsed';
const GRAPH_H_DEFAULT = Math.round(Math.min(window.innerHeight * 0.40, 460));

function graphHBounds() {
  const main = document.querySelector('.main');
  const avail = main ? main.clientHeight : window.innerHeight;
  // keep at least a usable table below and always leave the graph controls reachable
  return { min: 120, max: Math.max(200, Math.round(avail - 160)) };
}
function setGraphH(px, persist) {
  const { min, max } = graphHBounds();
  const v = Math.max(min, Math.min(max, Math.round(px)));
  document.querySelector('.main').style.setProperty('--graph-h', v + 'px');
  if (persist) { try { localStorage.setItem(GRAPH_H_KEY, String(v)); } catch (e) {} }
  return v;
}
function setCollapsed(on, persist) {
  const main = document.querySelector('.main');
  // the graph and the endpoint list share the column · folding one away brings
  // the other back rather than leaving an empty page
  if (on && main.classList.contains('table-collapsed')) setTableCollapsed(false, persist);
  main.classList.toggle('graph-collapsed', on);
  document.getElementById('graphRestore').hidden = !on;
  const btn = document.getElementById('gCollapse');
  if (btn) btn.setAttribute('title', on ? 'Show graph' : 'Collapse graph · give the table the full height');
  if (persist) { try { localStorage.setItem(GRAPH_COLLAPSED_KEY, on ? '1' : '0'); } catch (e) {} }
  if (!on) refitGraph();
}

/* Re-frame the graph after a pane has been folded away or brought back. The
   renderer only learns its new size from a ResizeObserver, so a single frame is
   not always enough · frame it now, and again once the resize has landed. */
function refitGraph() {
  if (!GRAPH) return;
  requestAnimationFrame(() => { if (GRAPH) GRAPH.fit(); });
  setTimeout(() => { if (GRAPH) GRAPH.fit(); }, 240);
}

function wireGraphSplitter() {
  const main = document.querySelector('.main');
  const handle = document.getElementById('graphResize');
  if (!main || !handle) return;

  let saved = null, collapsed = false;
  try { saved = parseInt(localStorage.getItem(GRAPH_H_KEY) || '', 10); } catch (e) {}
  try { collapsed = localStorage.getItem(GRAPH_COLLAPSED_KEY) === '1'; } catch (e) {}
  setGraphH(Number.isFinite(saved) && saved > 0 ? saved : GRAPH_H_DEFAULT, false);
  if (collapsed) setCollapsed(true, false);

  let startY = 0, startH = 0, dragging = false;
  const onMove = (e) => {
    if (!dragging) return;
    const y = (e.touches ? e.touches[0].clientY : e.clientY);
    setGraphH(startH + (y - startY), false);
  };
  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.style.userSelect = '';
    const cur = parseInt(getComputedStyle(main).getPropertyValue('--graph-h'), 10);
    if (Number.isFinite(cur)) { try { localStorage.setItem(GRAPH_H_KEY, String(cur)); } catch (e) {} }
    if (GRAPH) GRAPH.fit();
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
  };
  const onDown = (e) => {
    dragging = true;
    startY = (e.touches ? e.touches[0].clientY : e.clientY);
    startH = document.getElementById('graphWrap').getBoundingClientRect().height;
    handle.classList.add('dragging');
    document.body.style.userSelect = 'none';
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    e.preventDefault();
  };
  handle.addEventListener('pointerdown', onDown);
  handle.addEventListener('dblclick', () => { setGraphH(GRAPH_H_DEFAULT, true); if (GRAPH) GRAPH.fit(); });
  // keyboard: the handle is a focusable separator
  handle.addEventListener('keydown', (e) => {
    const cur = document.getElementById('graphWrap').getBoundingClientRect().height;
    if (e.key === 'ArrowUp') { setGraphH(cur - 24, true); e.preventDefault(); if (GRAPH) GRAPH.fit(); }
    else if (e.key === 'ArrowDown') { setGraphH(cur + 24, true); e.preventDefault(); if (GRAPH) GRAPH.fit(); }
  });

  const collapseBtn = document.getElementById('gCollapse');
  if (collapseBtn) collapseBtn.addEventListener('click', () =>
    setCollapsed(!main.classList.contains('graph-collapsed'), true));
  const restore = document.getElementById('graphRestore');
  if (restore) restore.addEventListener('click', () => setCollapsed(false, true));
}

/* ---- left panel width -----------------------------------------------------
   The left panel was a fixed 336px column: the graph/table split could be
   dragged but the panel could not, so a long host or IP list had no way to get
   more room. It is now user-sized with the same handle vocabulary as the graph
   splitter (drag, double-click to reset, arrow keys), remembered per browser. */
const SIDE_W_KEY = 'argus-side-w';
const SIDE_W_DEFAULT = 336;

function sideWBounds() {
  // keep the panel usable and always leave the main column the larger half
  return { min: 240, max: Math.max(300, Math.round(window.innerWidth * 0.5)) };
}
function setSideW(px, persist) {
  const { min, max } = sideWBounds();
  const v = Math.max(min, Math.min(max, Math.round(px)));
  const layout = document.querySelector('.scan-layout');
  if (layout) layout.style.setProperty('--side-w', v + 'px');
  if (persist) { try { localStorage.setItem(SIDE_W_KEY, String(v)); } catch (e) {} }
  return v;
}

function wireSideSplitter() {
  const layout = document.querySelector('.scan-layout');
  const handle = document.getElementById('sideResize');
  if (!layout || !handle) return;

  let saved = null;
  try { saved = parseInt(localStorage.getItem(SIDE_W_KEY) || '', 10); } catch (e) {}
  setSideW(Number.isFinite(saved) && saved > 0 ? saved : SIDE_W_DEFAULT, false);

  let startX = 0, startW = 0, dragging = false;
  const onMove = (e) => {
    if (!dragging) return;
    const x = (e.touches ? e.touches[0].clientX : e.clientX);
    setSideW(startW + (x - startX), false);
  };
  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.style.userSelect = '';
    const cur = parseInt(getComputedStyle(layout).getPropertyValue('--side-w'), 10);
    if (Number.isFinite(cur)) { try { localStorage.setItem(SIDE_W_KEY, String(cur)); } catch (e) {} }
    if (GRAPH) GRAPH.fit();
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
  };
  const onDown = (e) => {
    dragging = true;
    startX = (e.touches ? e.touches[0].clientX : e.clientX);
    startW = document.getElementById('side').getBoundingClientRect().width;
    handle.classList.add('dragging');
    document.body.style.userSelect = 'none';
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    e.preventDefault();
  };
  handle.addEventListener('pointerdown', onDown);
  handle.addEventListener('dblclick', () => { setSideW(SIDE_W_DEFAULT, true); if (GRAPH) GRAPH.fit(); });
  handle.addEventListener('keydown', (e) => {
    const cur = document.getElementById('side').getBoundingClientRect().width;
    if (e.key === 'ArrowLeft') { setSideW(cur - 24, true); e.preventDefault(); if (GRAPH) GRAPH.fit(); }
    else if (e.key === 'ArrowRight') { setSideW(cur + 24, true); e.preventDefault(); if (GRAPH) GRAPH.fit(); }
  });
}

/* ---- fold the left panel away ---------------------------------------------
   The panel can be narrowed by dragging, but a wide graph wants the whole page.
   The header's left chevron takes the panel out of the layout entirely; the rail
   it leaves on the viewport's left edge (a right chevron) brings it back. The
   choice is remembered per browser, like the two splitters. */
const SIDE_COLLAPSED_KEY = 'argus-side-collapsed';

function setSideCollapsed(on, persist) {
  const layout = document.querySelector('.scan-layout');
  if (!layout) return;
  layout.classList.toggle('side-collapsed', on);
  const restore = document.getElementById('sideRestore');
  if (restore) { restore.hidden = !on; restore.setAttribute('aria-expanded', on ? 'false' : 'true'); }
  const btn = document.getElementById('sideCollapse');
  if (btn) btn.setAttribute('aria-expanded', on ? 'false' : 'true');
  if (persist) { try { localStorage.setItem(SIDE_COLLAPSED_KEY, on ? '1' : '0'); } catch (e) {} }
  refitGraph();
}

function wireSideCollapse() {
  let saved = false;
  try { saved = localStorage.getItem(SIDE_COLLAPSED_KEY) === '1'; } catch (e) {}
  setSideCollapsed(saved, false);
  const btn = document.getElementById('sideCollapse');
  if (btn) btn.addEventListener('click', () => setSideCollapsed(true, true));
  const restore = document.getElementById('sideRestore');
  if (restore) restore.addEventListener('click', () => setSideCollapsed(false, true));
}

/* ---- fold the endpoint list away ------------------------------------------
   Same bargain the graph's own collapse makes, in the other direction: the down
   chevron in the filter bar minimises the list and hands its height to the
   graph, and the strip left behind (an up chevron) restores it. With the left
   panel folded away too, the graph has the whole viewport. */
const TABLE_COLLAPSED_KEY = 'argus-table-collapsed';

function setTableCollapsed(on, persist) {
  const main = document.querySelector('.main');
  if (!main) return;
  if (on && main.classList.contains('graph-collapsed')) setCollapsed(false, persist);
  main.classList.toggle('table-collapsed', on);
  const restore = document.getElementById('tableRestore');
  if (restore) restore.hidden = !on;
  const btn = document.getElementById('tCollapse');
  if (btn) btn.setAttribute('aria-expanded', on ? 'false' : 'true');
  if (persist) { try { localStorage.setItem(TABLE_COLLAPSED_KEY, on ? '1' : '0'); } catch (e) {} }
  refitGraph();
}

function wireTableCollapse() {
  let saved = false;
  try { saved = localStorage.getItem(TABLE_COLLAPSED_KEY) === '1'; } catch (e) {}
  if (saved) setTableCollapsed(true, false);
  const btn = document.getElementById('tCollapse');
  if (btn) btn.addEventListener('click', () => setTableCollapsed(true, true));
  const restore = document.getElementById('tableRestore');
  if (restore) restore.addEventListener('click', () => setTableCollapsed(false, true));
}

/* ---- graph ----------------------------------------------------------------

   Two interchangeable engines behind one GRAPH handle:
     'canvas' is the built-in dependency-free renderer (default, engine "1").
     'cy' is Cytoscape.js with the fCoSE layout (engine "2"; its vendor bundles
     load on first use).
   Both expose the same {fit, reheat, buildLegend, activate, setFilter} surface,
   so switching is: tear the old one down, show the other container, rebuild, and
   re-apply the current host/IP filter. */
let GRAPH_DATA = null;
let ENGINE = 'canvas';

function initGraph(graph) {
  GRAPH_DATA = graph;
  const st = graph.stats || {};
  const n = st.nodes;
  const total = st.total_nodes || n;
  // Say plainly when the view is a bounded slice of a bigger graph, rather than
  // quietly reporting the slice as if it were the whole scan.
  const badge = document.getElementById('graphSource');
  badge.textContent =
    (graph.source === 'neo4j' ? 'neo4j' : graph.source === 'kuzu' ? 'kuzu' : 'json')
    + (st.truncated ? ` · ${fmtNum(n)} of ${fmtNum(total)} nodes` : ` · ${fmtNum(n)} nodes`);
  if (st.truncated)
    badge.title = `This scan's graph has ${fmtNum(total)} nodes. `
      + `${fmtNum(n)} are drawn · the structure in full, plus as much per-page `
      + `detail as the view budget allows. Add ?limit=N to the URL to raise it.`;
  wireGraphEngineControls();
  if (!graph.nodes.length) {
    document.getElementById('graphWrap').insertAdjacentHTML('beforeend',
      `<div class="graph-empty"><div class="empty" style="margin:auto">${icon('topology-star-3')}
        <h4>No graph data</h4><p>This scan captured no in-scope structure to graph.</p></div></div>`);
    return;
  }
  startGraph(graph, /*reapplyFilter=*/false);
}

/* Node-cap gate + build for the current engine. `reapplyFilter` restores the
   host/IP selection after an engine switch. */
function startGraph(graph, reapplyFilter) {
  const detail = window.GRAPH_DETAIL_TYPES || new Set();
  const upfront = graph.nodes.reduce((a, x) => a + (detail.has(x.type) ? 0 : 1), 0);
  const done = () => { clearGraphLoading(); if (reapplyFilter) syncGraphFilter(); };
  if (upfront > GRAPH_LAZY) {
    // large graph: the activation overlay is its own progress UI
    showActivate(graph, upfront, done);
  } else {
    // small graph builds and lays out immediately, but the Cytoscape engine
    // still has to load its vendor bundles, so show a loading state until it is
    // on screen instead of a frozen tab
    if (ENGINE === 'cy') showGraphLoading('Loading graph engine…');
    buildGraph(graph, true).then(done, (err) => { clearGraphLoading(); failGraph(err); });
  }
}

const GRAPH_OPTS = {
  onSelect(node) {
    // Clicking a subdomain scopes everything to it; an IP scopes to its hosts.
    if (node.type === 'Subdomain') setHostFilter(node.label);
    else if (node.type === 'IP') setIpFilter(node.label);
  },
  // a locked legend layer was clicked · send the user to the control that unlocks it
  onLocked() {
    const sel = document.getElementById('hostFilter');
    if (sel) { sel.focus(); sel.classList.add('nudge'); setTimeout(() => sel.classList.remove('nudge'), 900); }
  },
};

/* Build the active engine. Returns a promise that resolves once it is ready to
   activate (the canvas engine is synchronous; the Cytoscape engine first loads
   its vendored bundles). `autoStart` lays a small graph out immediately. */
function buildGraph(graph, autoStart) {
  if (ENGINE === 'cy') return buildCyGraph(graph, autoStart);
  const canvas = document.getElementById('graph');
  GRAPH = createGraph(canvas, graph, { autoStart, ...GRAPH_OPTS });
  GRAPH.buildLegend(document.getElementById('legend'));
  return Promise.resolve(GRAPH);
}

function buildCyGraph(graph, autoStart) {
  const host = document.getElementById('cyGraph');
  return loadCyEngine(BASE).then(() => {
    GRAPH = createCyGraph(host, graph, { ...GRAPH_OPTS });
    GRAPH.buildLegend(document.getElementById('legend'));
    if (autoStart) return GRAPH.activate().then(() => GRAPH);
    return GRAPH;
  });
}

/* Fit / reheat are wired once and always act on whichever engine is current. */
let _graphBtnsWired = false;
function wireGraphButtonsOnce() {
  if (_graphBtnsWired) return; _graphBtnsWired = true;
  document.getElementById('gFit').addEventListener('click', () => GRAPH && GRAPH.fit());
  document.getElementById('gReheat').addEventListener('click', () => GRAPH && GRAPH.reheat());
}

/* Engine (1/2) switch. */
function wireGraphEngineControls() {
  wireGraphButtonsOnce();
  const engSwitch = document.getElementById('engineSwitch');
  if (engSwitch) engSwitch.querySelectorAll('.gseg-btn').forEach(btn =>
    btn.addEventListener('click', () => switchEngine(btn.dataset.engine)));
}

function switchEngine(engine) {
  if (engine === ENGINE || !GRAPH_DATA) return;
  ENGINE = engine;
  // reflect the choice on the segmented control
  document.querySelectorAll('#engineSwitch .gseg-btn').forEach(b => {
    const on = b.dataset.engine === engine;
    b.classList.toggle('on', on); b.setAttribute('aria-checked', on ? 'true' : 'false');
  });

  // tear the old engine down and reset the shared overlay bits
  if (GRAPH && GRAPH.destroy) { try { GRAPH.destroy(); } catch (e) {} }
  GRAPH = null;
  const nc = document.getElementById('nodeCard'); if (nc) nc.classList.remove('show');
  document.querySelectorAll('.graph-activate').forEach(el => el.remove());
  // swap the visible container
  document.getElementById('graph').hidden = engine !== 'canvas';
  document.getElementById('cyGraph').hidden = engine !== 'cy';

  document.getElementById('graphSource').textContent =
    (ENGINE === 'cy' ? 'cytoscape' : (GRAPH_DATA.source || 'json'))
    + ` · ${GRAPH_DATA.stats.nodes} nodes`;
  startGraph(GRAPH_DATA, /*reapplyFilter=*/true);
}

/* Large graph: don't freeze the tab. Let the user activate and show progress.
   `onDone` fires once layout has settled (used to re-apply a filter after an
   engine switch). */
function showActivate(graph, n, onDone) {
  const wrap = document.getElementById('graphWrap');
  const ov = h('div', { class: 'graph-activate' });
  ov.innerHTML = `<div class="ga-inner">${icon('topology-star-3')}
    <h4>${fmtNum(n)} nodes</h4>
    <p>This graph is large. Activate it to lay it out · the rest of the scan is ready below.</p>
    <button class="btn primary" id="gaBtn">${icon('topology-star-3')} Activate graph</button>
    <div class="ga-prog" hidden><div class="ga-bar"><span></span></div><div class="ga-pct faint">laying out… 0%</div></div>
  </div>`;
  wrap.appendChild(ov);
  ov.querySelector('#gaBtn').addEventListener('click', () => {
    const btn = ov.querySelector('#gaBtn'), prog = ov.querySelector('.ga-prog');
    btn.disabled = true; btn.style.display = 'none'; prog.hidden = false;
    const bar = ov.querySelector('.ga-bar span'), pct = ov.querySelector('.ga-pct');
    const progress = p => {
      const v = Math.round(p * 100); bar.style.transform = `scaleX(${p})`; pct.textContent = `laying out… ${v}%`;
    };
    buildGraph(graph, false).then(() =>
      // let the DOM paint the progress UI before the (chunked) warm-up begins
      requestAnimationFrame(() => GRAPH.activate(progress).then(() => {
        ov.classList.add('done'); setTimeout(() => ov.remove(), 260);
        if (onDone) onDone();
      })));
  });
}
