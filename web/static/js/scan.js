/* ============================================================================
   Argus Recon — scan detail controller
   ========================================================================== */
'use strict';

const ROW_CAP = 1500;
const GRAPH_LAZY = 500;              // above this, defer physics until activated
let SCAN = null, GRAPH = null, detailMode = false;
const F = { search: '', type: '', status: '', scope: 'in', classifiedOnly: false, host: null, ip: null };

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
  try {
    // The list view omits response bodies / DOM / headers — those are the bulk
    // of a large scan and are fetched per endpoint only when a row is expanded.
    const [scan, graph] = await Promise.all([
      getJSON(withBase(`/api/scan/${encodeURIComponent(id)}/view`)),
      getJSON(withBase(`/api/scan/${encodeURIComponent(id)}/graph`)).catch(() => null),
    ]);
    SCAN = scan;
    buildIpIndex(scan);
    renderPanel(scan);
    buildStatusFilter();
    buildHostFilter();
    buildIpFilter();
    renderTable();
    wireTableControls();
    if (graph) initGraph(graph);
  } catch (e) {
    document.querySelector('.main').innerHTML =
      `<div class="empty" style="margin:auto">${icon('alert-triangle')}<h4>Could not load scan</h4><p>${esc(e.message)}</p></div>`;
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
    ? `<span class="ip-src">${ip.sources.map(sc => `<span class="src-chip mini" title="${esc(sourceMeta(sc).label)}">${esc(sc)}</span>`).join('')}</span>` : '';
  return `<div class="ipcard" data-ip="${esc(ip.ip)}">
    <button class="ipaddr" data-ip="${esc(ip.ip)}" title="filter list and graph by ${esc(ip.ip)}">${icon('server-2')} ${esc(ip.ip)}${srcs}</button>
    ${ip.org ? `<div class="iporg">${esc(ip.org)}</div>` : ''}
    <div class="ipmeta">${meta.map(x => `<span>${x}</span>`).join('<span class="faint">·</span>')}
      <span class="faint">·</span><span>${hosts.length} host${hosts.length === 1 ? '' : 's'}</span></div>
    ${hostList}
  </div>`;
}

/* Tech: each fingerprint -> the subdomains it was seen on AND the IPs those
   hosts resolve to, so a stack can be traced to the box serving it. Chips are
   click-to-filter (host chip -> host filter, IP chip -> IP filter). */
function renderTech(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  const entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  setCount('cTech', entries.length);
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

/* wire clickable host / IP chips + file rows after each panel render */
function wirePanelInteractions() {
  document.querySelectorAll('.sitem[data-host]').forEach(el =>
    el.addEventListener('click', () => setHostFilter(el.dataset.host)));
  document.querySelectorAll('.chip-host[data-host]').forEach(el =>
    el.addEventListener('click', (e) => { e.stopPropagation(); setHostFilter(el.dataset.host); }));
  document.querySelectorAll('.chip-ip[data-ip], .ipaddr[data-ip]').forEach(el =>
    el.addEventListener('click', (e) => { e.stopPropagation(); setIpFilter(el.dataset.ip); }));
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

/* IP filter — every resolved IP in this scan, busiest first, labelled with how
   many hosts sit on it and who owns it. Selecting one narrows the request list
   and the graph to everything served from that address. */
function buildIpFilter() {
  const sel = document.getElementById('ipFilter');
  if (!sel) return;
  const recs = ((SCAN.infra && SCAN.infra.ips) || []).slice();
  // any IP seen on a subdomain but missing an infra record still gets an entry
  const known = new Set(recs.map(r => r.ip));
  IP_HOSTS.forEach((_, ip) => { if (!known.has(ip)) recs.push({ ip }); });
  recs.sort((a, b) => hostsOfIp(b.ip).length - hostsOfIp(a.ip).length || a.ip.localeCompare(b.ip));
  const opts = ['<option value="">all IPs</option>'];
  recs.forEach(r => {
    const n = hostsOfIp(r.ip).length;
    const org = (r.org || '').split(/[,(]/)[0].trim();
    const label = `${r.ip}${n ? ` · ${n} host${n === 1 ? '' : 's'}` : ''}${org ? ` · ${org}` : ''}`;
    opts.push(`<option value="${esc(r.ip)}">${esc(label)}</option>`);
  });
  sel.innerHTML = opts.join('');
  sel.disabled = recs.length === 0;
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

/* Central host filter — drives the request list AND the graph. Clicking the
   same host again clears it. Selecting one host is also what unlocks the
   graph's endpoint / file / field layers. */
function setHostFilter(host) {
  F.host = (F.host === host || !host) ? null : host;
  if (F.host) F.ip = null;             // host is the narrower of the two
  syncFilterUI();
  renderTable();
  syncGraphFilter();
}

/* IP filter — same contract, scoped to every host resolving to that address. */
function setIpFilter(ip) {
  F.ip = (F.ip === ip || !ip) ? null : ip;
  if (F.ip) F.host = null;
  syncFilterUI();
  renderTable();
  syncGraphFilter();
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

/* Graph scope: one host -> that subtree with detail unlocked; one IP -> every
   host on it, detail still locked (only a single subdomain unlocks it). */
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

/* Every table gets the full width of the page and its own row — nothing sits
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
    return `<tr>
      <td class="mono"><span class="chip-ip" data-ip="${esc(ip.ip)}">${icon('server-2')}${esc(ip.ip)}</span></td>
      <td>${esc(ip.org || '')}</td>
      <td class="mono">${esc(ip.asn || '')}</td>
      <td>${esc(ip.country || '')} ${ip.datacenter ? '· hosting' : ip.type ? '· ' + esc(ip.type) : ''}</td>
      <td>${(ip.sources || []).map(sc => `<span class="src-chip mini">${esc(sc)}</span>`).join('')}</td>
      <td class="mono">${hosts.length}</td>
      <td>${hosts.map(h => `<span class="chip-host" data-host="${esc(h)}">${esc(h)}</span>`).join(' ') || '<span class="faint">·</span>'}</td>
    </tr>`;
  }).join('');
  return dvCard('Infrastructure', 'server-2', ips.length,
    `<div class="dv-body"><table class="dv-table"><thead><tr><th>IP</th><th>Org</th><th>ASN</th><th>Type</th><th>Src</th><th>Hosts</th><th>Resolves for</th></tr></thead><tbody>${rows}</tbody></table></div>`,
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
   subdomains resolve to — not just a bare list of fingerprints. */
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
  if (btn) btn.setAttribute('title', on ? 'Show graph' : 'Collapse graph — give the table the full height');
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

/* ---- graph ---------------------------------------------------------------- */
function initGraph(graph) {
  const n = graph.stats.nodes;
  document.getElementById('graphSource').textContent =
    (graph.source === 'neo4j' ? 'neo4j' : 'json') + ` · ${n} nodes`;
  if (!graph.nodes.length) {
    document.getElementById('graphWrap').insertAdjacentHTML('beforeend',
      `<div class="graph-empty"><div class="empty" style="margin:auto">${icon('topology-star-3')}
        <h4>No graph data</h4><p>This scan captured no in-scope structure to graph.</p></div></div>`);
    return;
  }
  // Only the layers drawn up front decide whether we need the activation gate —
  // endpoints/files/fields stay locked until a subdomain is picked.
  const detail = window.GRAPH_DETAIL_TYPES || new Set();
  const upfront = graph.nodes.reduce((a, x) => a + (detail.has(x.type) ? 0 : 1), 0);
  if (upfront > GRAPH_LAZY) showActivate(graph, upfront);
  else buildGraph(graph, true);
}

function buildGraph(graph, autoStart) {
  const canvas = document.getElementById('graph');
  GRAPH = createGraph(canvas, graph, {
    autoStart,
    onSelect(node) {
      // Clicking a subdomain scopes everything to it — list, dropdown and the
      // graph's detail layers.
      if (node.type === 'Subdomain') {
        setHostFilter(node.label);
      } else if (node.type === 'IP') {
        setIpFilter(node.label);
      }
    },
    // a locked legend layer was clicked — send the user to the control that
    // unlocks it
    onLocked() {
      const sel = document.getElementById('hostFilter');
      if (sel) { sel.focus(); sel.classList.add('nudge'); setTimeout(() => sel.classList.remove('nudge'), 900); }
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
