/* ============================================================================
   Argus Recon · printable scan report
   ---------------------------------------------------------------------------
   Builds one self-contained document out of the scan the page is already
   holding, and hands it to the browser's print dialog · "Save as PDF" there
   produces the file. Nothing is uploaded and no library is pulled in: the data
   is already in the tab, and the print engine is already a PDF writer.

   The running header (mark + "Argus Recon" + the domain) lives in the <thead> of
   the sheet table. A table header group is the one construct every print engine
   repeats on every page, so the brand sits at the top right of page 1 and of
   page 40 alike · position:fixed only manages that in some browsers.
   ========================================================================== */
'use strict';

/* How much of an unbounded list one report carries. A deep crawl holds more
   rows than anyone prints; each table says what it left out rather than
   silently ending. */
const REPORT_CAPS = { subdomains: 3000, files: 3000, requests: 600, secrets: 2000 };

/* Where this page's static assets live, taken from a tag that is already on it,
   so the report works under any mount prefix. */
function staticBase() {
  const link = document.querySelector('link[href*="css/app.css"]');
  const href = link ? link.getAttribute('href') : '/static/css/app.css';
  return new URL(href, document.baseURI).href.split('/css/app.css')[0];
}

/* The brand mark, lifted out of the sprite that is already inlined in the page
   so the report carries the same glyph the dashboard shows. */
function markSvg() {
  const sym = document.getElementById('i-radar-2');
  const inner = sym ? sym.innerHTML : '';
  return `<svg class="rmark" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
}

function wireReportButton() {
  const btn = document.getElementById('pdfBtn');
  if (!btn) return;
  btn.addEventListener('click', () => {
    if (!SCAN) return;
    const label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> building';
    // Let the button paint its busy state before the (synchronous) build. A
    // timer rather than requestAnimationFrame: rAF is starved in a background
    // tab, and a report started just before switching away would never build.
    setTimeout(() => {
      try { openReport(); }
      finally { btn.disabled = false; btn.innerHTML = label; }
    }, 30);
  });
}

/* Build the document into an off-screen same-origin frame and print it. The
   frame is kept until the dialog closes · removing it early cancels the job in
   Safari · and torn down on the print-done signal. */
function openReport() {
  const old = document.getElementById('reportFrame');
  if (old) old.remove();
  const frame = document.createElement('iframe');
  frame.id = 'reportFrame';
  frame.setAttribute('aria-hidden', 'true');
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden';
  document.body.appendChild(frame);

  const doc = frame.contentWindow.document;
  doc.open();
  doc.write(reportHtml());
  doc.close();

  const go = () => {
    frame.contentWindow.focus();
    frame.contentWindow.print();
  };
  // fonts settle first, otherwise the first page can lay out against a fallback
  const fonts = doc.fonts && doc.fonts.ready ? doc.fonts.ready : Promise.resolve();
  fonts.then(() => setTimeout(go, 60), () => setTimeout(go, 60));
  frame.contentWindow.addEventListener('afterprint', () => setTimeout(() => frame.remove(), 400));
}

/* --------------------------------------------------------------------------
   Document
   -------------------------------------------------------------------------- */
function reportHtml() {
  const s = SCAN || {};
  const m = s.meta || {};
  const domain = m.domain || m.scan_id || '';
  const sections = [
    reportSummary(s, m),
    reportModules(m),
    reportDns(s.dns || {}),
    reportSubdomains(s.subdomains || []),
    reportInfra(((s.infra || {}).ips) || []),
    reportTech(s.subdomains || []),
    reportSecrets(s.secrets || []),
    reportFiles(s.files || []),
    reportRequests(s),
  ].filter(Boolean).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
    <title>Argus Recon · ${esc(domain)}</title>
    <style>${reportCss()}</style></head>
    <body>
      <table class="sheet">
        <thead><tr><td>
          <div class="runhead">
            <div class="rh-scan"><b>${esc(domain)}</b><span>${esc(m.scan_id || '')}</span></div>
            <div class="rh-brand">${markSvg()}<span>Argus Recon</span></div>
          </div>
        </td></tr></thead>
        <tbody><tr><td class="sheet-body">${sections}</td></tr></tbody>
      </table>
    </body></html>`;
}

function reportCss() {
  const fonts = staticBase() + '/fonts';
  // The report is its own document: one light theme, print colours, no reliance
  // on the dashboard's tokens or on the reader's theme choice.
  return `
@font-face{font-family:'Oswald';font-weight:200 700;font-display:block;src:url(${fonts}/oswald-latin.woff2) format('woff2')}
@font-face{font-family:'Hanken Grotesk';font-weight:400;font-display:block;src:url(${fonts}/hanken-400.woff2) format('woff2')}
@font-face{font-family:'Hanken Grotesk';font-weight:600;font-display:block;src:url(${fonts}/hanken-600.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Mono';font-weight:400;font-display:block;src:url(${fonts}/plexmono-400.woff2) format('woff2')}
@page{size:A4;margin:12mm 11mm}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:#fff;color:#23221e;
  font-family:'Hanken Grotesk',system-ui,sans-serif;font-size:9.5pt;line-height:1.45;
  -webkit-print-color-adjust:exact;print-color-adjust:exact}
.sheet{width:100%;border-collapse:collapse}
.sheet > thead{display:table-header-group}
.sheet > thead td{padding:0 0 8pt}
.sheet-body{padding:0;vertical-align:top}
.runhead{display:flex;align-items:flex-start;justify-content:space-between;gap:16pt;
  padding-bottom:5pt;border-bottom:.6pt solid #d5d0c1}
.rh-scan{font-size:8pt;color:#736e62;display:flex;flex-direction:column;gap:1pt}
.rh-scan b{font-size:9.5pt;color:#23221e;font-weight:600}
.rh-brand{display:flex;align-items:center;gap:6pt;font-family:'Oswald',sans-serif;
  font-weight:500;font-size:13pt;letter-spacing:.02em;color:#23221e;white-space:nowrap}
.rmark{width:15pt;height:15pt;color:#bd5b3d}
h1{font-family:'Oswald',sans-serif;font-weight:500;font-size:22pt;letter-spacing:.01em;margin:6pt 0 2pt}
h2{font-family:'Oswald',sans-serif;font-weight:500;font-size:13pt;letter-spacing:.02em;
  margin:0 0 6pt;padding-bottom:3pt;border-bottom:.6pt solid #e4e1d5}
h3{font-size:9.5pt;font-weight:600;margin:9pt 0 4pt;color:#4a473f}
p{margin:0 0 5pt}
section{margin-bottom:13pt;break-inside:auto}
section > h2{break-after:avoid}
.lede{color:#736e62;font-size:9pt;margin-bottom:8pt}
.mono{font-family:'IBM Plex Mono',monospace;font-size:8pt}
.faint{color:#8a8375}
table.t{width:100%;border-collapse:collapse;font-size:8pt;table-layout:fixed}
table.t th{text-align:left;font-size:7pt;text-transform:uppercase;letter-spacing:.05em;color:#736e62;
  font-weight:600;padding:3pt 4pt;border-bottom:.6pt solid #d5d0c1;background:#f4f3ed}
table.t thead{display:table-header-group}
table.t td{padding:3pt 4pt;border-bottom:.4pt solid #e4e1d5;vertical-align:top;
  word-break:break-word;overflow-wrap:anywhere}
table.t tr{break-inside:avoid}
.kvgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:3pt 18pt;margin-bottom:8pt}
.kvgrid .r{display:flex;gap:8pt;font-size:8.5pt;border-bottom:.4pt dotted #e4e1d5;padding-bottom:2pt}
.kvgrid .k{color:#736e62;min-width:74pt}
.kvgrid .v{font-family:'IBM Plex Mono',monospace;font-size:8pt;word-break:break-word}
.stats{display:flex;flex-wrap:wrap;gap:5pt;margin:6pt 0 10pt}
.stat{border:.6pt solid #e4e1d5;border-radius:4pt;padding:4pt 8pt;min-width:64pt}
.stat b{display:block;font-family:'Oswald',sans-serif;font-size:14pt;font-weight:500;line-height:1.1}
.stat span{font-size:7.5pt;color:#736e62;text-transform:uppercase;letter-spacing:.04em}
.sev{font-weight:600}
.sev.high{color:#a63a28}.sev.medium{color:#8a5e12}.sev.low{color:#5c6a4c}
.s2{color:#3f7d52}.s3{color:#9a6a16}.s4,.s5{color:#b4402e}.sx{color:#8a8375}
.tag{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:7pt;padding:0 3pt;
  border:.4pt solid #e4e1d5;border-radius:3pt;margin:0 2pt 2pt 0;color:#4a473f}
.note{font-size:8pt;color:#736e62;margin-top:4pt;font-style:italic}
.dot{display:inline-block;width:5pt;height:5pt;border-radius:50%;margin-right:4pt}
.dot.ok{background:#3f7d52}.dot.empty{background:#a39c8c}.dot.skip{background:#d5d0c1}
`;
}

/* --------------------------------------------------------------------------
   Sections
   -------------------------------------------------------------------------- */
function rTable(cols, rows, widths) {
  if (!rows.length) return '<p class="faint">Nothing recorded.</p>';
  const cg = widths ? `<colgroup>${widths.map(w => `<col style="width:${w}">`).join('')}</colgroup>` : '';
  return `<table class="t">${cg}<thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('')}</tbody></table>`;
}

function capNote(total, cap, what) {
  return total > cap
    ? `<p class="note">Showing the first ${fmtNum(cap)} of ${fmtNum(total)} ${what}. The full set is in the scan JSON.</p>`
    : '';
}

function reportSummary(s, m) {
  const st = m.stats || {};
  const wh = m.domain_whois || (s.dns || {}).whois || {};
  const kv = (k, v) => v ? `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>` : '';
  const stat = (n, label) => n == null ? '' :
    `<div class="stat"><b>${fmtNum(n)}</b><span>${esc(label)}</span></div>`;
  const techCount = new Set((s.subdomains || []).flatMap(sd => sd.tech || [])).size;
  const ports = ((s.infra || {}).ips || []).reduce((a, ip) => a + (ip.ports || []).length, 0);
  return `<section>
    <h1>${esc(m.domain || m.scan_id || 'Scan report')}</h1>
    <p class="lede">Reconnaissance report generated ${esc(new Date().toLocaleString())} from scan
      ${esc(m.scan_id || '')}.</p>
    <div class="stats">
      ${stat(st.subdomains != null ? st.subdomains : (s.subdomains || []).length, 'subdomains')}
      ${stat(st.ips != null ? st.ips : ((s.infra || {}).ips || []).length, 'IPs')}
      ${stat(ports || null, 'open ports')}
      ${stat(techCount || null, 'tech')}
      ${stat(st.endpoints != null ? st.endpoints : (s.endpoints || []).length, 'requests')}
      ${stat(st.files != null ? st.files : (s.files || []).length, 'files')}
      ${stat(st.secrets != null ? st.secrets : (s.secrets || []).length, 'secrets')}
    </div>
    <div class="kvgrid">
      ${kv('domain', m.domain)}
      ${kv('scan id', m.scan_id)}
      ${kv('started', m.started_at ? new Date(m.started_at).toLocaleString() : '')}
      ${kv('duration', m.duration_sec != null ? fmtDur(m.duration_sec) : '')}
      ${kv('registrar', wh.registrar)}
      ${kv('domain created', wh.created)}
      ${kv('domain expires', wh.expires)}
      ${kv('name servers', (wh.name_servers || []).slice(0, 3).join(', '))}
    </div>
  </section>`;
}

function reportModules(m) {
  const mods = Object.entries(m.modules || {});
  if (!mods.length) return '';
  const rows = mods.map(([name, d]) => `<tr>
    <td><span class="dot ${d.status === 'ok' ? 'ok' : d.status === 'empty' ? 'empty' : 'skip'}"></span>${esc(name)}</td>
    <td>${esc(d.status || '')}</td>
    <td class="mono">${d.duration != null ? esc(d.duration + 's') : ''}</td>
    <td class="faint">${esc(d.note || '')}</td></tr>`);
  return `<section><h2>Pipeline</h2>
    ${rTable(['Module', 'Status', 'Time', 'Note'], rows, ['22%', '12%', '10%', '56%'])}</section>`;
}

/* DNS: current records, the deep-DNS address timeline (where the domain has
   been hosted and for how long), then the full per-type history. */
function reportDns(dns) {
  const recs = dns.records || {}, hist = dns.history || {};
  const nRec = Object.values(recs).reduce((a, v) => a + v.length, 0);
  const nHist = Object.values(hist).reduce((a, v) => a + v.length, 0);
  if (!nRec && !nHist) return '';
  let out = '<section><h2>DNS</h2>';

  const cur = DNS_ORDER.filter(t => (recs[t] || []).length);
  if (cur.length) {
    const rows = [];
    cur.forEach(t => (recs[t] || []).forEach(r => {
      const detail = [r.priority != null ? 'pri ' + r.priority : '', r.ttl != null ? 'ttl ' + r.ttl : '',
        r.organization || ''].filter(Boolean).join(' · ');
      rows.push(`<tr><td>${DNS_LABEL[t]}</td><td class="mono">${esc(r.value)}</td>
        <td class="faint">${esc(detail)}</td><td class="mono">${esc(r.first_seen || '')}</td>
        <td class="mono">${esc(durationOf(r.first_seen, null))}</td></tr>`);
    }));
    out += `<h3>Current records</h3>
      ${rTable(['Type', 'Value', 'Detail', 'First seen', 'Held for'], rows, ['8%', '32%', '26%', '20%', '14%'])}`;
  }

  if (IP_SEEN.size) {
    const infra = new Map((((SCAN || {}).infra || {}).ips || []).map(r => [r.ip, r]));
    const rows = [...IP_SEEN.entries()]
      .sort((a, b) => (b[1].current ? 1 : 0) - (a[1].current ? 1 : 0)
        || String(b[1].first_seen || '').localeCompare(String(a[1].first_seen || '')))
      .map(([ip, seen]) => {
        const rec = infra.get(ip) || {};
        return `<tr><td class="mono">${esc(ip)}</td>
          <td>${seen.current ? 'current' : 'retired'}</td>
          <td class="mono">${esc(seen.first_seen || '')}</td>
          <td class="mono">${esc(seen.current ? '' : seen.last_seen || '')}</td>
          <td class="mono">${esc(durationOf(seen.first_seen, seen.current ? null : seen.last_seen))}</td>
          <td>${esc(ipPlace(rec))}</td>
          <td class="faint">${esc(seen.organization || rec.org || '')}</td></tr>`;
      });
    out += `<h3>Address timeline</h3>
      <p class="faint">Every address this domain has resolved to, the window it served in, and how long that lasted.</p>
      ${rTable(['IP', 'State', 'First seen', 'Last seen', 'Duration', 'Location', 'Organization'],
        rows, ['16%', '9%', '15%', '15%', '10%', '17%', '18%'])}`;
  }

  const histTypes = DNS_ORDER.filter(t => (hist[t] || []).length);
  histTypes.forEach(t => {
    const rows = (hist[t] || []).map(r => `<tr><td class="mono">${esc(r.value)}</td>
      <td class="mono">${esc(r.first_seen || '')}</td><td class="mono">${esc(r.last_seen || '')}</td>
      <td class="mono">${esc(durationOf(r.first_seen, r.last_seen))}</td>
      <td class="faint">${esc(r.organization || '')}</td></tr>`);
    out += `<h3>History · ${DNS_LABEL[t]}</h3>
      ${rTable(['Value', 'First seen', 'Last seen', 'Duration', 'Organization'],
        rows, ['30%', '17%', '17%', '12%', '24%'])}`;
  });
  return out + '</section>';
}

function reportSubdomains(subs) {
  if (!subs.length) return '';
  const infra = new Map((((SCAN || {}).infra || {}).ips || []).map(r => [r.ip, r]));
  const rows = subs.slice(0, REPORT_CAPS.subdomains).map(sd => {
    const http = sd.http || {};
    const places = [...new Set((sd.ips || []).map(ip => ipPlace(infra.get(ip) || {})).filter(Boolean))];
    return `<tr><td class="mono">${esc(sd.host)}</td>
      <td class="mono ${statusClass(http.status).replace('status-', 's')}">${http.status || (sd.resolved ? '' : 'dns')}</td>
      <td class="mono">${esc((sd.ips || []).join(' '))}</td>
      <td>${esc(places.join(' · '))}</td>
      <td>${(sd.tech || []).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</td>
      <td class="faint mono">${esc((sd.sources || []).join(' '))}</td></tr>`;
  });
  return `<section><h2>Subdomains</h2>
    ${rTable(['Host', 'Status', 'IPs', 'Location', 'Tech', 'Src'], rows,
      ['26%', '8%', '18%', '18%', '22%', '8%'])}
    ${capNote(subs.length, REPORT_CAPS.subdomains, 'subdomains')}</section>`;
}

function reportInfra(ips) {
  if (!ips.length) return '';
  const rows = ips.map(ip => {
    const seen = ipSeenText(ip.ip);
    return `<tr><td class="mono">${esc(ip.ip)}</td>
      <td>${esc(ip.org || '')}</td><td class="mono">${esc(ip.asn || '')}</td>
      <td>${esc(ipPlace(ip))}</td>
      <td>${esc(ip.datacenter ? 'hosting' : ip.type || '')}</td>
      <td class="mono">${esc(seen)}</td>
      <td>${esc((ip.os || {}).name || '')}</td>
      <td class="mono">${(ip.ports || []).length || (ip.scanned ? '0' : '')}</td>
      <td class="mono">${(ip.subdomains || []).length}</td></tr>`;
  });
  // Open services get their own table: port, service, version and the tech the
  // fingerprinter saw on it, per address.
  const portRows = [];
  ips.forEach(ip => (ip.ports || []).forEach(p => portRows.push(
    `<tr><td class="mono">${esc(ip.ip)}</td>
      <td class="mono">${p.port}/${esc(p.protocol || 'tcp')}</td>
      <td>${esc(p.service || '')}</td>
      <td>${esc([p.product, p.version].filter(Boolean).join(' '))}</td>
      <td>${(p.tech || []).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</td>
      <td class="faint">${esc(p.extrainfo || '')}</td></tr>`)));
  return `<section><h2>Infrastructure</h2>
    ${rTable(['IP', 'Org', 'ASN', 'Location', 'Type', 'Seen', 'OS', 'Ports', 'Hosts'], rows,
      ['14%', '17%', '9%', '15%', '8%', '15%', '10%', '6%', '6%'])}
    ${portRows.length ? `<h3>Open services</h3>${rTable(
      ['IP', 'Port', 'Service', 'Version', 'Tech', 'Info'], portRows,
      ['15%', '9%', '12%', '20%', '26%', '18%'])}` : ''}</section>`;
}

function reportTech(subs) {
  const map = {};
  subs.forEach(sd => (sd.tech || []).forEach(t => { (map[t] = map[t] || []).push(sd.host); }));
  const entries = Object.entries(map).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  if (!entries.length) return '';
  const rows = entries.map(([t, hosts]) => {
    const ips = ipsOfHosts(hosts);
    return `<tr><td>${esc(t)}</td><td class="mono">${hosts.length}</td>
      <td class="mono">${esc(hosts.slice(0, 24).join(' '))}${hosts.length > 24 ? ` +${hosts.length - 24}` : ''}</td>
      <td class="mono">${esc(ips.slice(0, 12).join(' '))}${ips.length > 12 ? ` +${ips.length - 12}` : ''}</td></tr>`;
  });
  return `<section><h2>Tech stack</h2>
    ${rTable(['Technology', 'Hosts', 'Detected on', 'Served from'], rows,
      ['20%', '7%', '43%', '30%'])}</section>`;
}

function reportSecrets(secrets) {
  if (!secrets.length) return '';
  const rows = secrets.slice(0, REPORT_CAPS.secrets).map(x => {
    const u = splitUrl(x.source);
    return `<tr><td class="sev ${sevClass(x.severity)}">${esc(x.severity)}</td>
      <td>${esc(x.type)}</td><td class="mono">${esc(x.match)}</td>
      <td class="mono faint">${esc(u.host + u.path)}</td>
      <td class="faint mono">${esc((x.found_by || []).join(' '))}</td></tr>`;
  });
  return `<section><h2>Secrets</h2>
    ${rTable(['Sev', 'Type', 'Match', 'Location', 'Src'], rows,
      ['8%', '17%', '31%', '36%', '8%'])}
    ${capNote(secrets.length, REPORT_CAPS.secrets, 'findings')}</section>`;
}

function reportFiles(files) {
  if (!files.length) return '';
  const rows = files.slice(0, REPORT_CAPS.files).map(f => {
    const u = splitUrl(f.url);
    return `<tr><td>${esc(f.subtype || f.kind || '')}</td>
      <td class="mono">${esc(u.host)}</td>
      <td class="mono">${esc(u.path)}</td>
      <td class="mono ${statusClass(f.status).replace('status-', 's')}">${f.status || ''}</td>
      <td class="mono faint">${esc(f.size != null ? fmtBytes(f.size) : '')}</td>
      <td class="faint">${esc((f.content_type || '').split(';')[0])}</td></tr>`;
  });
  return `<section><h2>Discovered files</h2>
    ${rTable(['Kind', 'Host', 'Path', 'Status', 'Size', 'Type'], rows,
      ['10%', '21%', '39%', '8%', '9%', '13%'])}
    ${capNote(files.length, REPORT_CAPS.files, 'files')}</section>`;
}

/* Requests: the classified and in-scope ones first · a printed report is read
   for what matters, not for a million-row crawl dump. */
function reportRequests(s) {
  const eps = s.endpoints || [];
  if (!eps.length) return '';
  const score = e => (e.classifications && e.classifications.length ? 2 : 0)
    + (e.in_scope ? 1 : 0) + (e.fields && e.fields.length ? 1 : 0);
  const ranked = eps.slice().sort((a, b) => score(b) - score(a));
  const rows = ranked.slice(0, REPORT_CAPS.requests).map(e => {
    const u = splitUrl(e.url);
    const cls = (e.classifications || []).map(c =>
      `<span class="sev ${sevClass(c.severity)}">${esc(c.category)}</span>`).join(', ');
    return `<tr><td class="mono">${esc(e.method)}</td>
      <td class="mono">${esc(u.host)}${esc(u.path)}</td>
      <td>${esc(e.type || '')}</td>
      <td>${cls}</td>
      <td class="mono ${statusClass(e.status).replace('status-', 's')}">${e.status || ''}</td></tr>`;
  });
  const total = s.endpoints_total || eps.length;
  return `<section><h2>Requests</h2>
    <p class="faint">Highest-value first: classified requests, then in-scope and fielded ones.</p>
    ${rTable(['Method', 'URL', 'Type', 'Classification', 'Status'], rows,
      ['8%', '48%', '10%', '26%', '8%'])}
    ${capNote(total, REPORT_CAPS.requests, 'requests')}</section>`;
}

document.addEventListener('DOMContentLoaded', wireReportButton);
