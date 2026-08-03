/* ============================================================================
   Argus Recon · scan detail controller
   ========================================================================== */
'use strict';

const ROW_CAP = 1500;
const GRAPH_LAZY = 500;              // above this, defer physics until activated
let SCAN = null, GRAPH = null, detailMode = false;
const F = {
  search: '', type: '', status: '', scope: 'in', classifiedOnly: false,
  host: null, ip: null,
  // left-panel filters · each narrows one section's list, nothing else
  fileType: '', fileStatus: '', subStatus: '', asn: '', tech: '', secretSev: '',
};

/* IP <-> host index, built once per scan from both directions (a subdomain
   lists its IPs, an IP record lists the hosts that resolve to it). */
const IP_HOSTS = new Map();          // ip   -> Set(host)
const HOST_IPS = new Map();          // host -> Set(ip)

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
    renderPanel(scan);
    buildStatusFilter();
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

  // Each section below carries its own filter, built from what this scan
  // actually contains · a status code nothing returned is never offered.
  const subs = s.subdomains || [];
  setCount('cSubs', subs.length);
  F.subStatus = '';
  buildSubFilter(subs);
  renderSubList();

  const ips = (s.infra && s.infra.ips) || [];
  setCount('cIps', ips.length);
  F.asn = '';
  buildAsnFilter(ips);
  renderIpList();

  // DNS
  renderDns(s.dns || {});

  // tech (per fingerprint -> which subdomains, like secrets)
  F.tech = '';
  buildTechFilter(subs);
  renderTech(subs);

  const secrets = s.secrets || [];
  setCount('cSecrets', secrets.length);
  F.secretSev = '';
  buildSecretFilter(secrets);
  renderSecretList();
  document.querySelector('.side-sec[data-sec="secrets"]').classList.toggle('collapsed', !secrets.length);

  const files = s.files || [];
  setCount('cFiles', files.length);
  F.fileType = ''; F.fileStatus = '';
  buildFileFilter(files);
  renderFileList();

  wirePanelInteractions();
}

/* ---- left-panel filters ---------------------------------------------------
   One shared builder for every section's filter row. `specs` are the selects to
   draw; any select with nothing to choose between is dropped, and a row with no
   selects left hides itself rather than showing an empty control. */
function panelFilter(containerId, specs) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const useful = specs.filter(s => s.options.length > 1);
  if (!useful.length) { el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  el.innerHTML = `<svg class="ic"><use href="#i-filter"></use></svg>`
    + useful.map(s => `<select class="input" id="${esc(s.id)}" aria-label="${esc(s.aria)}">${
      s.options.map(([v, label]) =>
        `<option value="${esc(v)}"${v === s.value ? ' selected' : ''}>${esc(label)}</option>`
      ).join('')}</select>`).join('');
  useful.forEach(s => {
    const sel = el.querySelector('#' + s.id);
    if (sel) sel.addEventListener('change', () => s.onChange(sel.value));
  });
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

/* Subdomains · by the status their host answered with. */
function buildSubFilter(subs) {
  panelFilter('subFilter', [{
    id: 'subStatusFilter', aria: 'Filter subdomains by response code',
    value: F.subStatus,
    options: statusOptions(subs, sd => (sd.http || {}).status, 'all status'),
    onChange: v => { F.subStatus = v; renderSubList(); },
  }]);
}

function renderSubList() {
  const subs = ((SCAN && SCAN.subdomains) || [])
    .filter(sd => matchesStatusFilter(F.subStatus, (sd.http || {}).status));
  document.getElementById('subList').innerHTML = subs.map(subItem).join('')
    || emptyMini(F.subStatus ? 'no subdomains with that status' : 'no subdomains');
  wirePanelInteractions();
}

/* Infrastructure · by announcing AS. Addresses with no ASN are their own group
   rather than being silently unreachable through the filter. */
function buildAsnFilter(ips) {
  const seen = new Map();          // asn -> {n, org}
  let none = 0;
  ips.forEach(ip => {
    if (!ip.asn) { none++; return; }
    const rec = seen.get(ip.asn) || { n: 0, org: '' };
    rec.n++;
    if (!rec.org && ip.org) rec.org = String(ip.org).split(/[,(]/)[0].trim();
    seen.set(ip.asn, rec);
  });
  const opts = [['', `all AS (${ips.length})`]];
  [...seen.entries()]
    .sort((a, b) => b[1].n - a[1].n || String(a[0]).localeCompare(String(b[0])))
    .forEach(([asn, r]) => opts.push([asn, `${asn}${r.org ? ' · ' + r.org : ''} (${r.n})`]));
  if (none) opts.push(['none', `no AS recorded (${none})`]);
  panelFilter('asnFilter', [{
    id: 'asnSelect', aria: 'Filter infrastructure by announcing AS',
    value: F.asn, options: opts,
    onChange: v => { F.asn = v; renderIpList(); },
  }]);
}

function renderIpList() {
  const ips = (((SCAN || {}).infra || {}).ips || []).filter(ip =>
    !F.asn || (F.asn === 'none' ? !ip.asn : ip.asn === F.asn));
  document.getElementById('ipList').innerHTML = ips.map(ipCard).join('')
    || emptyMini(F.asn ? 'no addresses on that AS' : 'no IPs');
  wirePanelInteractions();
}

/* Tech stack · by fingerprint. */
function buildTechFilter(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { map[t] = (map[t] || 0) + 1; }));
  const entries = Object.entries(map)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const opts = [['', `all tech (${entries.length})`]];
  entries.forEach(([t, n]) => opts.push([t, `${t} (${n})`]));
  panelFilter('techFilter', [{
    id: 'techSelect', aria: 'Filter the tech stack',
    value: F.tech, options: opts,
    onChange: v => { F.tech = v; renderTech((SCAN && SCAN.subdomains) || []); },
  }]);
}

/* Secrets · by severity. */
function buildSecretFilter(secrets) {
  const order = ['high', 'medium', 'low'];
  const counts = {};
  secrets.forEach(x => { counts[x.severity] = (counts[x.severity] || 0) + 1; });
  const opts = [['', `all severities (${secrets.length})`]];
  order.filter(s => counts[s]).forEach(s => opts.push([s, `${s} (${counts[s]})`]));
  Object.keys(counts).filter(s => !order.includes(s)).sort()
    .forEach(s => opts.push([s, `${s} (${counts[s]})`]));
  panelFilter('secretFilter', [{
    id: 'secretSevSelect', aria: 'Filter secrets by severity',
    value: F.secretSev, options: opts,
    onChange: v => { F.secretSev = v; renderSecretList(); },
  }]);
}

function renderSecretList() {
  const secrets = ((SCAN && SCAN.secrets) || [])
    .filter(x => !F.secretSev || x.severity === F.secretSev);
  document.getElementById('secretList').innerHTML = secrets.map(secRow).join('')
    || emptyMini(F.secretSev ? 'none at that severity' : 'none flagged');
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

/* Infra: each IP lists which subdomains resolve to it + discovery source (item 4) */
function ipCard(ip) {
  const dc = ip.datacenter === true ? 'hosting' : ip.type || 'unknown';
  const meta = [];
  if (ip.asn) meta.push(esc(ip.asn));
  if (ip.country) meta.push(esc(ip.country));
  meta.push(esc(dc));
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
function renderTech(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  let entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  setCount('cTech', entries.length);
  if (F.tech) entries = entries.filter(([t]) => t === F.tech);
  document.getElementById('techList').innerHTML = entries.map(([t, hosts]) => {
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

function buildFileFilter(files) {
  const types = [...new Set(files.map(fileTypeOf))].sort();
  const codeCount = files.filter(f => CODE_FILE_TYPES.has(fileTypeOf(f))).length;
  const typeOpts = [['', `all types (${files.length})`]];
  if (codeCount && codeCount < files.length)
    typeOpts.push(['__code', `code (${codeCount})`]);
  types.forEach(t => typeOpts.push(
    [t, `${t} (${files.filter(f => fileTypeOf(f) === t).length})`]));

  // Kind and status answer different questions ("what is it?" vs "did it
  // actually serve?"), so both are offered and they combine.
  panelFilter('fileFilter', [
    { id: 'fileTypeFilter', aria: 'Filter discovered files by type',
      value: F.fileType, options: typeOpts,
      onChange: v => { F.fileType = v; renderFileList(); } },
    { id: 'fileStatusFilter', aria: 'Filter discovered files by response code',
      value: F.fileStatus, options: statusOptions(files, f => f.status, 'all status'),
      onChange: v => { F.fileStatus = v; renderFileList(); } },
  ]);
}

function fileMatches(f) {
  if (!matchesStatusFilter(F.fileStatus, f.status)) return false;
  if (!F.fileType) return true;
  if (F.fileType === '__code') return CODE_FILE_TYPES.has(fileTypeOf(f));
  return fileTypeOf(f) === F.fileType;
}

/* Render (or re-render) the file rows for the active type filter. Each row keeps
   its original index into SCAN.files, so expanding still finds the record. */
function renderFileList() {
  const list = document.getElementById('fileList');
  if (!list) return;
  const files = (SCAN && SCAN.files) || [];
  const rows = [];
  files.forEach((f, i) => { if (fileMatches(f)) rows.push(fileRow(f, i)); });
  list.innerHTML = rows.join('') ||
    emptyMini(F.fileType || F.fileStatus ? 'no files match those filters' : 'none');
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

/* wire clickable host / IP chips + file rows after each panel render */
function wirePanelInteractions() {
  document.querySelectorAll('.sitem[data-host]').forEach(el =>
    el.addEventListener('click', () => setHostFilter(el.dataset.host)));
  document.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', (e) => { e.stopPropagation(); setHostFilter(el.dataset.host); }));
  document.querySelectorAll('.chip-ip[data-ip], .ipaddr[data-ip]').forEach(el =>
    el.addEventListener('click', (e) => { e.stopPropagation(); setIpFilter(el.dataset.ip); }));
  // file rows are wired by renderFileList (they re-render when the type filter changes)
  // port rows: expand to reveal version / CPE / script output
  document.querySelectorAll('.prow.has-detail .psummary').forEach(btn =>
    btn.addEventListener('click', () => btn.closest('.prow').classList.toggle('open')));
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

function filtered() {
  const q = F.search.toLowerCase();
  return (SCAN.endpoints || []).filter(e => {
    if (F.scope === 'in' && !e.in_scope) return false;
    if (F.classifiedOnly && !(e.classifications && e.classifications.length)) return false;
    if (!matchType(e.type)) return false;
    if (!matchStatus(e.status)) return false;
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
   intersection. */
function syncGraphFilter() {
  if (!GRAPH) return;
  const hosts = F.host ? [F.host] : F.ip ? hostsOfIp(F.ip) : null;
  GRAPH.setFilter({ hosts, detail: !!F.host });
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
   side by side, so no data set has to be read through a horizontal scrollbar. */
function renderDetail() {
  const dv = document.getElementById('detailView');
  const s = SCAN, m = s.meta || {}, st = m.stats || {};
  const techCount = new Set((s.subdomains || []).flatMap(sd => sd.tech || [])).size;
  const jumps = [
    ['dns', 'DNS', (st.dns_records || 0) + (st.dns_history || 0)],
    ['subdomains', 'subdomains', st.subdomains],
    ['infra', 'IPs', st.ips],
    ['tech', 'tech', techCount],
    ['secrets', 'secrets', st.secrets],
    ['files', 'files', st.files],
  ].filter(j => j[2] == null || j[2]).map(([id, label, n]) =>
    `<button class="dv-stat" data-jump="dv-${id}">${n != null ? `<b>${fmtNum(n)}</b> ` : ''}${label}</button>`).join('');
  dv.innerHTML = `
    <div class="dv-head">
      <div><h2>${esc(m.domain || '')}</h2><div class="dv-substats">${jumps}</div></div>
      <button class="btn" id="dvCollapse">${icon('arrows-minimize')} Back to graph</button>
    </div>
    <div class="dv-grid">
      ${dvDnsCard(s.dns || {})}
      ${dvSubdomainsCard(s.subdomains || [])}
      ${dvInfraCard((s.infra && s.infra.ips) || [])}
      ${dvTechCard(s.subdomains || [])}
      ${dvSecretsCard(s.secrets || [])}
      ${dvFilesCard(s.files || [])}
    </div>`;
  dv.querySelector('#dvCollapse').addEventListener('click', toggleDetailMode);
  dv.querySelectorAll('[data-jump]').forEach(b => b.addEventListener('click', () => {
    const el = document.getElementById(b.dataset.jump);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));
  dv.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', () => { toggleDetailMode(); setHostFilter(el.dataset.host); }));
  dv.querySelectorAll('.chip-ip[data-ip]').forEach(el =>
    el.addEventListener('click', () => { toggleDetailMode(); setIpFilter(el.dataset.ip); }));
  // port rows inside the infra card expand to their service / version / script detail
  dv.querySelectorAll('.prow.has-detail .psummary').forEach(btn =>
    btn.addEventListener('click', () => btn.closest('.prow').classList.toggle('open')));
  wireDecode(dv);
}

function dvCard(title, ic, count, body, id) {
  return `<section class="dv-card"${id ? ` id="dv-${id}"` : ''}><div class="dv-ch">${icon(ic)}<h3>${esc(title)}</h3>
    ${count != null ? `<span class="count">${fmtNum(count)}</span>` : ''}</div>${body}</section>`;
}

function dvDnsCard(dns) {
  const recs = dns.records || {}, hist = dns.history || {};
  const nRec = Object.values(recs).reduce((a, v) => a + v.length, 0);
  const nHist = Object.values(hist).reduce((a, v) => a + v.length, 0);
  if (!nRec && !nHist) return dvCard('DNS', 'network', 0,
    `<div class="empty" style="padding:24px">${icon('network')}<h4>No DNS data</h4><p>Run a Deep scan for full records and historical DNS.</p></div>`, 'dns');
  let body = '';
  const curTypes = DNS_ORDER.filter(t => recs[t] && recs[t].length);
  if (curTypes.length) {
    body += `<h4 class="dv-sub">Current records</h4><table class="dv-table"><thead><tr><th>Type</th><th>Value</th><th>Detail</th><th>Since</th></tr></thead><tbody>`;
    for (const t of curTypes) for (const r of recs[t]) {
      const detail = [r.priority != null ? 'pri ' + r.priority : '', r.ttl != null ? 'ttl ' + r.ttl : '', r.organization || ''].filter(Boolean).join(' · ');
      body += `<tr><td class="dv-rt">${DNS_LABEL[t]}</td><td class="mono">${esc(r.value)}</td><td class="faint">${esc(detail)}</td><td class="mono">${esc(r.first_seen ? yearOf(r.first_seen) || r.first_seen : '')}</td></tr>`;
    }
    body += `</tbody></table>`;
  }
  const histTypes = DNS_ORDER.filter(t => hist[t] && hist[t].length);
  if (histTypes.length) {
    body += `<h4 class="dv-sub">${icon('history')} Historical DNS</h4>
      <p class="faint" style="font-size:12px;margin-bottom:8px">Previous IPs, name servers and MX with when each change happened. Click a type to open the full table.</p>`;
    for (const t of histTypes) {
      const rows = hist[t];
      const list = rows.slice(0, 4).map(r => `${esc(r.value)} <span class="faint">(${esc(fmtRange(r.first_seen, r.last_seen))})</span>`).join(' · ');
      body += `<details class="dv-details"><summary><span class="dv-rt">${DNS_LABEL[t]}</span>
        <span class="faint">${rows.length} record${rows.length === 1 ? '' : 's'}</span>
        <span class="dv-sum-list">${list}${rows.length > 4 ? ' …' : ''}</span></summary>
        <table class="dv-table"><thead><tr><th>Value</th><th>First seen</th><th>Last seen</th><th>Duration</th><th>Organization</th></tr></thead><tbody>
        ${rows.map(r => `<tr><td class="mono">${esc(r.value)}</td><td>${esc(r.first_seen || '')}</td><td>${esc(r.last_seen || '')}</td><td>${esc(durationOf(r.first_seen, r.last_seen))}</td><td class="faint">${esc(r.organization || '')}</td></tr>`).join('')}
        </tbody></table></details>`;
    }
  }
  return dvCard('DNS records & history', 'network', nRec + nHist, `<div class="dv-body">${body}</div>`, 'dns');
}

function dvInfraCard(ips) {
  if (!ips.length) return dvCard('Infrastructure', 'server-2', 0, `<div class="dv-body faint" style="padding:16px">No IPs.</div>`, 'infra');
  const rows = ips.map(ip => {
    const hosts = ip.subdomains || [];
    const nports = (ip.ports || []).length;
    const portsCell = nports
      ? `<span class="tag mono" title="open ports · expand the row for services, versions and OS">${nports} open</span>`
      : (ip.scanned ? '<span class="faint">0 open</span>' : '<span class="faint">·</span>');
    const main = `<tr>
      <td class="mono"><span class="chip-ip" data-ip="${esc(ip.ip)}">${icon('server-2')}${esc(ip.ip)}</span></td>
      <td>${esc(ip.org || '')}</td>
      <td class="mono">${esc(ip.asn || '')}</td>
      <td>${esc(ip.country || '')} ${ip.datacenter ? '· hosting' : ip.type ? '· ' + esc(ip.type) : ''}</td>
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
    const detailRow = pb ? `<tr class="dv-ports-row"><td colspan="9"><div class="dv-ports">${pb}</div></td></tr>` : '';
    return main + detailRow;
  }).join('');
  return dvCard('Infrastructure', 'server-2', ips.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>IP</th><th>Org</th><th>ASN</th><th>Type</th><th>OS</th><th>Ports</th><th>Src</th><th>Hosts</th><th>Resolves for</th></tr></thead><tbody>${rows}</tbody></table></div>`,
    'infra');
}

function dvSubdomainsCard(subs) {
  if (!subs.length) return dvCard('Subdomains', 'world', 0, `<div class="dv-body faint" style="padding:16px">None.</div>`, 'subdomains');
  const rows = subs.map(sd => `<tr>
    <td class="mono"><span class="chip-host" data-host="${esc(sd.host)}">${esc(sd.host)}</span></td>
    <td class="${statusClass((sd.http || {}).status)} mono">${(sd.http || {}).status || (sd.resolved ? '·' : 'dns')}</td>
    <td>${(sd.ips || []).map(ip => `<span class="chip-ip" data-ip="${esc(ip)}">${icon('server-2')}${esc(ip)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    <td>${(sd.tech || []).map(x => `<span class="tag mono">${esc(x)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    <td>${(sd.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
  </tr>`).join('');
  return dvCard('Subdomains', 'world', subs.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Host</th><th>Status</th><th>IPs</th><th>Tech</th><th>Src</th></tr></thead><tbody>${rows}</tbody></table></div>`,
    'subdomains');
}

/* Tech stack: what was detected, on which subdomains, and on which IPs those
   subdomains resolve to · not just a bare list of fingerprints. */
function dvTechCard(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  const entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  if (!entries.length) return dvCard('Tech stack', 'fingerprint', 0, `<div class="dv-body faint" style="padding:16px">No fingerprints.</div>`, 'tech');
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
  return dvCard('Tech stack', 'fingerprint', entries.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Technology</th><th>Hosts</th><th>Detected on</th><th>IPs</th><th>Served from</th></tr></thead><tbody>${rows}</tbody></table></div>`,
    'tech');
}

function dvSecretsCard(secrets) {
  if (!secrets.length) return dvCard('Secrets', 'key', 0, `<div class="dv-body faint" style="padding:16px">None flagged.</div>`, 'secrets');
  const rows = secrets.map(x => `<tr>
    <td><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span></td>
    <td>${esc(x.type)}</td><td class="mono wrap">${esc(x.match)}</td>
    <td>${(x.found_by || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    <td class="mono faint wrap">${esc(splitUrl(x.source).host + splitUrl(x.source).path)}</td>
  </tr>`).join('');
  return dvCard('Secrets', 'key', secrets.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Sev</th><th>Type</th><th>Match</th><th>Src</th><th>Location</th></tr></thead><tbody>${rows}</tbody></table></div>`,
    'secrets');
}

function dvFilesCard(files) {
  if (!files.length) return dvCard('Discovered files', 'file-code', 0, `<div class="dv-body faint" style="padding:16px">None.</div>`, 'files');
  const rows = files.map(f => {
    const u = splitUrl(f.url);
    return `<tr>
      <td><span class="tag mono">${esc(f.subtype || f.kind)}</span></td>
      <td class="mono"><span class="chip-host" data-host="${esc(u.host)}">${esc(u.host)}</span></td>
      <td class="mono wrap">${esc(u.path)}</td>
      <td class="${statusClass(f.status)} mono">${f.status || '·'}</td>
      <td class="mono faint">${esc(f.size != null ? fmtBytes(f.size) : '')}</td>
      <td class="faint">${esc((f.content_type || '').split(';')[0])}</td>
      <td>${(f.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    </tr>`;
  }).join('');
  return dvCard('Discovered files', 'file-code', files.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Kind</th><th>Host</th><th>Path</th><th>Status</th><th>Size</th><th>Type</th><th>Src</th></tr></thead><tbody>${rows}</tbody></table></div>`,
    'files');
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
  document.querySelector('.main').classList.toggle('graph-collapsed', on);
  document.getElementById('graphRestore').hidden = !on;
  const btn = document.getElementById('gCollapse');
  if (btn) btn.setAttribute('title', on ? 'Show graph' : 'Collapse graph · give the table the full height');
  if (persist) { try { localStorage.setItem(GRAPH_COLLAPSED_KEY, on ? '1' : '0'); } catch (e) {} }
  if (!on && GRAPH) requestAnimationFrame(() => GRAPH.fit());
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
