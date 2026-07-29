/* ============================================================================
   Argus Recon — scan detail controller
   ========================================================================== */
'use strict';

const ROW_CAP = 1500;
const GRAPH_LAZY = 500;              // above this, defer physics until activated
let SCAN = null, GRAPH = null, detailMode = false;
const F = { search: '', type: '', status: '', scope: 'in', classifiedOnly: false, host: null };

document.addEventListener('DOMContentLoaded', init);

async function init() {
  const layout = document.querySelector('.scan-layout');
  const id = layout.dataset.scanId;
  wireSections();
  try {
    const [scan, graph] = await Promise.all([
      getJSON(`/api/scan/${encodeURIComponent(id)}`),
      getJSON(`/api/scan/${encodeURIComponent(id)}/graph`).catch(() => null),
    ]);
    SCAN = scan;
    renderPanel(scan);
    buildStatusFilter();
    buildHostFilter();
    renderTable();
    wireTableControls();
    if (graph) initGraph(graph);
  } catch (e) {
    document.querySelector('.main').innerHTML =
      `<div class="empty" style="margin:auto">${icon('alert-triangle')}<h4>Could not load scan</h4><p>${esc(e.message)}</p></div>`;
  }
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

  // subdomains
  const subs = s.subdomains || [];
  setCount('cSubs', subs.length);
  document.getElementById('subList').innerHTML = subs.map(subItem).join('') ||
    emptyMini('no subdomains');

  // infra
  const ips = (s.infra && s.infra.ips) || [];
  setCount('cIps', ips.length);
  document.getElementById('ipList').innerHTML = ips.map(ipCard).join('') || emptyMini('no IPs');

  // DNS
  renderDns(s.dns || {});

  // tech (per fingerprint -> which subdomains, like secrets)
  renderTech(subs);

  // secrets
  const secrets = s.secrets || [];
  setCount('cSecrets', secrets.length);
  document.getElementById('secretList').innerHTML = secrets.map(secRow).join('') ||
    emptyMini('none flagged');
  document.querySelector('.side-sec[data-sec="secrets"]').classList.toggle('collapsed', !secrets.length);

  // files
  const files = s.files || [];
  setCount('cFiles', files.length);
  document.getElementById('fileList').innerHTML = files.map((f, i) => fileRow(f, i)).join('') || emptyMini('none');

  wirePanelInteractions();
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
    ? `<div class="ip-src">${ip.sources.map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('')}</div>` : '';
  return `<div class="ipcard">
    <div class="ipaddr">${icon('server-2')} ${esc(ip.ip)}${srcs}</div>
    ${ip.org ? `<div class="iporg">${esc(ip.org)}</div>` : ''}
    <div class="ipmeta">${meta.map(x => `<span>${x}</span>`).join('<span class="faint">·</span>')}
      <span class="faint">·</span><span>${hosts.length} host${hosts.length === 1 ? '' : 's'}</span></div>
    ${hostList}
  </div>`;
}

/* Tech: each fingerprint -> which subdomains it was seen on (item 4) */
function renderTech(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  const entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  setCount('cTech', entries.length);
  document.getElementById('techList').innerHTML = entries.map(([t, hosts]) =>
    `<div class="techrow"><span class="tag mono">${esc(t)}</span>
      <span class="tech-hosts">${hosts.slice(0, 3).map(h =>
      `<span class="chip-host" data-host="${esc(h)}" title="${esc(h)}">${esc(h)}</span>`).join('')}${hosts.length > 3 ? `<span class="faint" style="font-size:11px">+${hosts.length - 3}</span>` : ''}</span>
    </div>`).join('') || emptyMini('no fingerprints');
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
    body.innerHTML = emptyMini('no DNS data yet — run with Deep for full records + history');
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

/* Files: expandable — source + request + response (item 10) */
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

/* wire clickable host chips + file rows after each panel render */
function wirePanelInteractions() {
  document.querySelectorAll('.sitem[data-host]').forEach(el =>
    el.addEventListener('click', () => setHostFilter(el.dataset.host, el)));
  document.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', (e) => { e.stopPropagation(); setHostFilter(el.dataset.host, null); }));
  document.querySelectorAll('.frow').forEach(r => {
    r.querySelector('.fsummary').addEventListener('click', () => toggleFile(r));
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

function filtered() {
  const q = F.search.toLowerCase();
  return (SCAN.endpoints || []).filter(e => {
    if (F.scope === 'in' && !e.in_scope) return false;
    if (F.classifiedOnly && !(e.classifications && e.classifications.length)) return false;
    if (!matchType(e.type)) return false;
    if (!matchStatus(e.status)) return false;
    if (F.host && e.host !== F.host) return false;
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

/* Domain / subdomain filter — every host seen in this scan (apex first). */
function buildHostFilter() {
  const sel = document.getElementById('hostFilter');
  if (!sel) return;
  const domain = (SCAN.meta || {}).domain || '';
  const hosts = [...new Set((SCAN.subdomains || []).map(s => s.host).filter(Boolean))]
    .sort((a, b) => (a === domain ? -1 : b === domain ? 1 : a.localeCompare(b)));
  const opts = ['<option value="">all hosts</option>'];
  hosts.forEach(h => opts.push(
    `<option value="${esc(h)}">${esc(h)}${h === domain ? ' (apex)' : ''}</option>`));
  sel.innerHTML = opts.join('');
}

function renderTable() {
  const body = document.getElementById('tBody');
  const rows = filtered();
  const shown = rows.slice(0, ROW_CAP);
  document.getElementById('tCount').textContent =
    rows.length > ROW_CAP ? `showing ${ROW_CAP} of ${fmtNum(rows.length)}` : `${fmtNum(rows.length)} request${rows.length === 1 ? '' : 's'}`;

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
  return `<div class="trow ${e.in_scope ? '' : 'oos'}" data-i="${i}">
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

function toggleRow(row) {
  const open = row.classList.toggle('open');
  const det = row.querySelector('.tdetail');
  if (!open) { det.innerHTML = ''; return; }
  const i = +row.dataset.i;
  const e = filtered()[i];
  if (!e) return;
  det.innerHTML = detailHtml(e);
  det.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => {
    navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy);
    b.innerHTML = icon('circle-check-filled') + ' copied';
    setTimeout(() => b.innerHTML = icon('copy') + ' copy', 1400);
  }));
  wireDecode(det);
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
  if (host) host.addEventListener('change', e => setHostFilter(e.target.value, null));

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

/* Central host filter — drives the request list AND the graph.
   opts.filterGraph=false lets a graph node click sync the list/dropdown
   without yanking the graph layout out from under the click. */
function setHostFilter(host, el, opts) {
  opts = opts || {};
  const same = F.host === host;
  F.host = (same || !host) ? null : host;
  const sel = document.getElementById('hostFilter');
  if (sel) sel.value = F.host || '';
  document.querySelectorAll('.sitem').forEach(s =>
    s.classList.toggle('active', !!F.host && s.dataset.host === F.host));
  renderTable();
  if (GRAPH && opts.filterGraph !== false) GRAPH.filterHost(F.host);
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

function renderDetail() {
  const dv = document.getElementById('detailView');
  const s = SCAN, m = s.meta || {}, st = m.stats || {};
  const chips = [
    ['subdomains', st.subdomains], ['IPs', st.ips], ['DNS records', st.dns_records],
    ['history', st.dns_history], ['endpoints', st.in_scope_endpoints],
    ['files', st.files], ['secrets', st.secrets],
  ].filter(c => c[1]).map(c => `<span class="dv-stat"><b>${fmtNum(c[1])}</b> ${c[0]}</span>`).join('');
  dv.innerHTML = `
    <div class="dv-head">
      <div><h2>${esc(m.domain || '')}</h2><div class="dv-substats">${chips}</div></div>
      <button class="btn" id="dvCollapse">${icon('arrows-minimize')} Back to graph</button>
    </div>
    <div class="dv-grid">
      ${dvDnsCard(s.dns || {})}
      ${dvInfraCard((s.infra && s.infra.ips) || [])}
      ${dvSubdomainsCard(s.subdomains || [])}
      ${dvTechCard(s.subdomains || [])}
      ${dvSecretsCard(s.secrets || [])}
      ${dvFilesCard(s.files || [])}
    </div>`;
  dv.querySelector('#dvCollapse').addEventListener('click', toggleDetailMode);
  dv.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', () => { toggleDetailMode(); setHostFilter(el.dataset.host, null); }));
  wireDecode(dv);
}

function dvCard(title, ic, count, body) {
  return `<section class="dv-card"><div class="dv-ch">${icon(ic)}<h3>${esc(title)}</h3>
    ${count != null ? `<span class="count">${fmtNum(count)}</span>` : ''}</div>${body}</section>`;
}

function dvDnsCard(dns) {
  const recs = dns.records || {}, hist = dns.history || {};
  const nRec = Object.values(recs).reduce((a, v) => a + v.length, 0);
  const nHist = Object.values(hist).reduce((a, v) => a + v.length, 0);
  if (!nRec && !nHist) return dvCard('DNS', 'network', 0,
    `<div class="empty" style="padding:24px">${icon('network')}<h4>No DNS data</h4><p>Run a Deep scan for full records and historical DNS.</p></div>`);
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
  return dvCard('DNS records & history', 'network', nRec + nHist, `<div class="dv-body">${body}</div>`);
}

function dvInfraCard(ips) {
  if (!ips.length) return dvCard('Infrastructure', 'server-2', 0, `<div class="dv-body faint" style="padding:16px">No IPs.</div>`);
  const rows = ips.map(ip => `<tr>
    <td class="mono">${esc(ip.ip)}</td>
    <td>${esc(ip.org || '')}</td>
    <td class="mono">${esc(ip.asn || '')}</td>
    <td>${esc(ip.country || '')} ${ip.datacenter ? '· hosting' : ip.type ? '· ' + esc(ip.type) : ''}</td>
    <td>${(ip.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    <td>${(ip.subdomains || []).map(h => `<span class="chip-host" data-host="${esc(h)}">${esc(h)}</span>`).join(' ')}</td>
  </tr>`).join('');
  return dvCard('Infrastructure', 'server-2', ips.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>IP</th><th>Org</th><th>ASN</th><th>Type</th><th>Src</th><th>Resolves for</th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

function dvSubdomainsCard(subs) {
  if (!subs.length) return dvCard('Subdomains', 'world', 0, `<div class="dv-body faint" style="padding:16px">None.</div>`);
  const rows = subs.map(sd => `<tr>
    <td class="mono"><span class="chip-host" data-host="${esc(sd.host)}">${esc(sd.host)}</span></td>
    <td class="${statusClass((sd.http || {}).status)} mono">${(sd.http || {}).status || (sd.resolved ? '·' : 'dns')}</td>
    <td class="mono faint">${esc((sd.ips || []).join(', '))}</td>
    <td>${(sd.tech || []).slice(0, 5).map(x => `<span class="tag mono">${esc(x)}</span>`).join(' ')}</td>
    <td>${(sd.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
  </tr>`).join('');
  return dvCard('Subdomains', 'world', subs.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Host</th><th>Status</th><th>IPs</th><th>Tech</th><th>Src</th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

function dvTechCard(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  const entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length);
  if (!entries.length) return dvCard('Tech stack', 'fingerprint', 0, `<div class="dv-body faint" style="padding:16px">No fingerprints.</div>`);
  const rows = entries.map(([t, hosts]) => `<tr>
    <td><span class="tag mono">${esc(t)}</span></td><td class="mono">${hosts.length}</td>
    <td>${hosts.slice(0, 12).map(h => `<span class="chip-host" data-host="${esc(h)}">${esc(h)}</span>`).join(' ')}${hosts.length > 12 ? ` <span class="faint">+${hosts.length - 12}</span>` : ''}</td>
  </tr>`).join('');
  return dvCard('Tech stack', 'fingerprint', entries.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Technology</th><th>Hosts</th><th>Seen on</th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

function dvSecretsCard(secrets) {
  if (!secrets.length) return dvCard('Secrets', 'key', 0, `<div class="dv-body faint" style="padding:16px">None flagged.</div>`);
  const rows = secrets.map(x => `<tr>
    <td><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span></td>
    <td>${esc(x.type)}</td><td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis">${esc(x.match)}</td>
    <td>${(x.found_by || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
    <td class="mono faint">${esc(splitUrl(x.source).host + splitUrl(x.source).path)}</td>
  </tr>`).join('');
  return dvCard('Secrets', 'key', secrets.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Sev</th><th>Type</th><th>Match</th><th>Src</th><th>Location</th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

function dvFilesCard(files) {
  if (!files.length) return dvCard('Discovered files', 'file-code', 0, `<div class="dv-body faint" style="padding:16px">None.</div>`);
  const rows = files.map(f => `<tr>
    <td><span class="tag mono">${esc(f.subtype || f.kind)}</span></td>
    <td class="mono">${esc(splitUrl(f.url).host)}${esc(splitUrl(f.url).path)}</td>
    <td class="${statusClass(f.status)} mono">${f.status || '·'}</td>
    <td>${(f.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
  </tr>`).join('');
  return dvCard('Discovered files', 'file-code', files.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>Kind</th><th>URL</th><th>Status</th><th>Src</th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

/* ---- graph ---------------------------------------------------------------- */
function initGraph(graph) {
  const canvas = document.getElementById('graph');
  const n = graph.stats.nodes;
  document.getElementById('graphSource').textContent =
    (graph.source === 'neo4j' ? 'neo4j' : 'json') + ` · ${n} nodes`;
  if (!graph.nodes.length) {
    document.getElementById('graphWrap').insertAdjacentHTML('beforeend',
      `<div class="graph-empty"><div class="empty" style="margin:auto">${icon('topology-star-3')}
        <h4>No graph data</h4><p>This scan captured no in-scope structure to graph.</p></div></div>`);
    return;
  }
  if (n > GRAPH_LAZY) showActivate(graph, n);
  else buildGraph(graph, true);
}

function buildGraph(graph, autoStart) {
  const canvas = document.getElementById('graph');
  GRAPH = createGraph(canvas, graph, {
    autoStart,
    onSelect(node) {
      if (node.type === 'Subdomain') {
        const el = document.querySelector(`.sitem[data-host="${CSS.escape(node.label)}"]`);
        // inspect: sync the list + dropdown, but don't collapse the graph
        // under the click — use the dropdown / left panel to filter the graph.
        setHostFilter(node.label, el, { filterGraph: false });
      }
    },
  });
  GRAPH.buildLegend(document.getElementById('legend'));
  document.getElementById('gFit').addEventListener('click', () => GRAPH.fit());
  document.getElementById('gReheat').addEventListener('click', () => GRAPH.reheat());
  return GRAPH;
}

/* Large graph: don't freeze the tab — let the user activate + show progress (item 6) */
function showActivate(graph, n) {
  const wrap = document.getElementById('graphWrap');
  const ov = h('div', { class: 'graph-activate' });
  ov.innerHTML = `<div class="ga-inner">${icon('topology-star-3')}
    <h4>${fmtNum(n)} nodes</h4>
    <p>This graph is large. Activate it to lay it out — the rest of the scan is ready below.</p>
    <button class="btn primary" id="gaBtn">${icon('topology-star-3')} Activate graph</button>
    <div class="ga-prog" hidden><div class="ga-bar"><span></span></div><div class="ga-pct faint">laying out… 0%</div></div>
  </div>`;
  wrap.appendChild(ov);
  ov.querySelector('#gaBtn').addEventListener('click', () => {
    const btn = ov.querySelector('#gaBtn'), prog = ov.querySelector('.ga-prog');
    btn.disabled = true; btn.style.display = 'none'; prog.hidden = false;
    const bar = ov.querySelector('.ga-bar span'), pct = ov.querySelector('.ga-pct');
    buildGraph(graph, false);
    // let the DOM paint the progress UI before the (chunked) warm-up begins
    requestAnimationFrame(() => GRAPH.activate(p => {
      const v = Math.round(p * 100); bar.style.transform = `scaleX(${p})`; pct.textContent = `laying out… ${v}%`;
    }).then(() => { ov.classList.add('done'); setTimeout(() => ov.remove(), 260); }));
  });
}
