/* ============================================================================
   Home — scan library, launch + track scans, deep-DNS key, delete
   ========================================================================== */
'use strict';

let DEEP_AVAILABLE = false;

async function loadStatus() {
  const bar = document.getElementById('statusbar');
  try {
    const s = await getJSON('/api/status');
    DEEP_AVAILABLE = !!s.deep_available;
    reflectDeep();
    // No recon-tool names on the home page — only capability state (see README).
    const chip = (dot, label, val) =>
      `<span class="st"><span class="dot ${dot ? 'on' : 'off'}"></span><b>${esc(label)}</b> ${esc(val)}</span>`;
    const chips = [
      chip(s.deep_available, 'deep DNS', s.deep_available ? 'unlocked' : 'locked'),
      chip(s.graph_db, 'graph db', s.graph_db ? 'connected' : 'offline · renders from JSON'),
      chip(s.engines_ready, 'engines', s.engines_ready ? 'ready' : 'incomplete'),
    ];
    if (!s.deep_available)
      chips.push(`<button class="st st-btn" id="setKeyBtn">${icon('settings')} add deep-DNS key</button>`);
    bar.innerHTML = chips.join('');
    const kb = document.getElementById('setKeyBtn');
    if (kb) kb.addEventListener('click', () => openKeyModal());
  } catch (e) { bar.innerHTML = ''; }
}

function reflectDeep() {
  const chk = document.getElementById('deepChk');
  const box = document.getElementById('optDeep');
  if (!chk) return;
  chk.classList.toggle('locked', !DEEP_AVAILABLE);
  chk.title = DEEP_AVAILABLE
    ? 'Extra subdomains + full DNS records + historical DNS'
    : 'Deep DNS is locked — click to add an API key';
  if (!DEEP_AVAILABLE && box) box.checked = false;
}

function scanRow(s) {
  const st = s.stats || {};
  const meta = [];
  if (s.started_at) meta.push(icon('clock') + ' ' + timeAgo(s.started_at));
  if (s.duration_sec != null) meta.push(fmtDur(s.duration_sec));
  meta.push(fmtBytes(s.size));
  const metric = (n, l, accent) =>
    `<div class="metric ${accent ? 'accent' : ''}"><div class="n">${fmtNum(n)}</div><div class="l">${l}</div></div>`;
  return `<div class="scan-row-wrap">
    <a class="scan-row" href="/scan/${encodeURIComponent(s.scan_id)}">
      <div class="id">
        <div class="dom">${icon('world')}<span class="truncate">${esc(s.domain)}</span></div>
        <div class="meta">${meta.map(m => `<span>${m}</span>`).join('')}</div>
      </div>
      <div class="metrics">
        ${metric(st.subdomains || 0, 'subdomains')}
        ${metric(st.in_scope_endpoints || 0, 'endpoints')}
        ${metric(st.classified_requests || 0, 'classified', true)}
        ${metric(st.secrets || 0, 'secrets')}
        <span class="go">${icon('chevron-right')}</span>
      </div>
    </a>
    <button class="row-del" data-del="${esc(s.scan_id)}" title="Delete scan" aria-label="Delete scan">${icon('trash')}</button>
  </div>`;
}

async function loadScans() {
  const wrap = document.getElementById('scanList');
  try {
    const scans = await getJSON('/api/scans');
    if (!scans.length) {
      wrap.innerHTML = `<div class="panel"><div class="empty">
        ${icon('radar-2')}<h4>No scans yet</h4>
        <p>Run your first scan above. Results are saved to <code>./scans</code> and appear here.</p>
      </div></div>`;
      return;
    }
    wrap.innerHTML = `<div class="scan-list">${scans.map(scanRow).join('')}</div>`;
    wrap.querySelectorAll('.row-del').forEach(b =>
      b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); deleteScan(b.dataset.del, b); }));
  } catch (e) {
    wrap.innerHTML = `<div class="panel"><div class="empty">${icon('alert-triangle')}
      <h4>Could not load scans</h4><p>${esc(e.message)}</p></div></div>`;
  }
}

async function deleteScan(id, btn) {
  const wrap = btn.closest('.scan-row-wrap');
  if (wrap.classList.contains('confirm')) {
    btn.innerHTML = '<span class="spin"></span>';
    try {
      const r = await fetch(`/api/scan/${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(await r.text());
      wrap.classList.add('removing');
      setTimeout(loadScans, 200);
    } catch (e) { btn.innerHTML = icon('trash'); wrap.classList.remove('confirm'); }
    return;
  }
  wrap.classList.add('confirm');
  btn.innerHTML = icon('trash') + ' confirm';
  const reset = () => { wrap.classList.remove('confirm'); btn.innerHTML = icon('trash'); };
  const t = setTimeout(reset, 3000);
  btn.addEventListener('mouseleave', () => { clearTimeout(t); }, { once: true });
}

/* ---- deep-DNS key modal --------------------------------------------------- */
function openKeyModal() {
  const m = document.getElementById('keyModal');
  m.hidden = false;
  const input = document.getElementById('keyInput');
  input.value = ''; setTimeout(() => input.focus(), 30);
}
function closeKeyModal() { document.getElementById('keyModal').hidden = true; }

function wireKeyModal() {
  const modal = document.getElementById('keyModal');
  if (!modal) return;
  document.getElementById('keySkip').addEventListener('click', () => {
    try { localStorage.setItem('argus-key-dismissed', '1'); } catch (e) {}
    closeKeyModal();
  });
  document.getElementById('keySave').addEventListener('click', saveKey);
  document.getElementById('keyInput').addEventListener('keydown', e => { if (e.key === 'Enter') saveKey(); });
  modal.addEventListener('click', e => { if (e.target === modal) closeKeyModal(); });
  // clicking the (locked) deep option opens the key modal instead of ticking it
  const deepChk = document.getElementById('deepChk');
  if (deepChk) deepChk.addEventListener('click', e => {
    if (!DEEP_AVAILABLE) { e.preventDefault(); openKeyModal(); }
  });
  // first run: no key set and not dismissed -> prompt once
  let dismissed = false;
  try { dismissed = localStorage.getItem('argus-key-dismissed') === '1'; } catch (e) {}
  setTimeout(() => { if (!DEEP_AVAILABLE && !dismissed) openKeyModal(); }, 700);
}

async function saveKey() {
  const input = document.getElementById('keyInput');
  const key = input.value.trim();
  const btn = document.getElementById('keySave');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> saving';
  try {
    const r = await fetch('/api/config/key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key }),
    });
    const d = await r.json();
    DEEP_AVAILABLE = !!d.deep_available;
    reflectDeep();
    try { localStorage.setItem('argus-key-dismissed', '1'); } catch (e) {}
    closeKeyModal();
    loadStatus();
  } finally {
    btn.disabled = false; btn.innerHTML = `${icon('key')} Save & enable`;
  }
}

/* ---- jobs (running scans) ------------------------------------------------- */
let jobTimer = null;
const openLogs = new Set();

async function loadJobs() {
  const wrap = document.getElementById('jobsWrap');
  let jobs = [];
  try { jobs = await getJSON('/api/jobs'); } catch (e) { return; }
  const active = jobs.filter(j => ['queued', 'running'].includes(j.status));
  const recent = jobs.filter(j => ['done', 'failed'].includes(j.status)).slice(0, 3);
  const show = [...active, ...recent];
  if (!show.length) { wrap.innerHTML = ''; return; }

  wrap.innerHTML = '<div class="section-label">Running &amp; recent jobs</div><div class="jobs">' +
    show.map(j => {
      const running = j.status === 'running' || j.status === 'queued';
      const ind = running ? '<span class="spin"></span>'
        : j.status === 'done' ? icon('circle-check-filled')
        : icon('alert-triangle');
      return `<div class="job" data-job="${j.id}">
        <span class="jdom">${esc(j.domain)}</span>
        <span class="jstat">${ind} ${esc(j.status)}${j.status === 'done' ? ' · <a href="#" data-reload="1">view</a>' : ''}
          <button class="btn sm ghost" data-toggle-log="${j.id}">${icon('terminal-2')} log</button></span>
        <div class="job-log ${openLogs.has(j.id) ? 'open' : ''}" id="log-${j.id}"></div>
      </div>`;
    }).join('') + '</div>';

  openLogs.forEach(id => refreshLog(id));

  wrap.querySelectorAll('[data-toggle-log]').forEach(b => b.addEventListener('click', () => {
    const id = b.getAttribute('data-toggle-log');
    const box = document.getElementById('log-' + id);
    if (openLogs.has(id)) { openLogs.delete(id); box.classList.remove('open'); }
    else { openLogs.add(id); box.classList.add('open'); refreshLog(id); }
  }));
  wrap.querySelectorAll('[data-reload]').forEach(a => a.addEventListener('click', e => {
    e.preventDefault(); loadScans();
  }));

  if (active.length) {
    if (!jobTimer) jobTimer = setInterval(pollJobs, 2500);
  } else if (jobTimer) { clearInterval(jobTimer); jobTimer = null; loadScans(); }
}

async function refreshLog(id) {
  try {
    const d = await getJSON(`/api/jobs/${id}/log`);
    const box = document.getElementById('log-' + id);
    if (box) { box.textContent = d.log || '(waiting for output…)'; box.scrollTop = box.scrollHeight; }
  } catch (e) {}
}
function pollJobs() { loadJobs(); }

/* ---- launch --------------------------------------------------------------- */
function wireNewScan() {
  const form = document.getElementById('newscan');
  const input = document.getElementById('domainInput');
  const btn = document.getElementById('scanBtn');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9.\-]+\.[a-z]{2,}$/.test(domain)) {
      input.focus(); input.style.borderColor = 'var(--danger)';
      setTimeout(() => input.style.borderColor = '', 1200);
      return;
    }
    const wantDeep = document.getElementById('optDeep').checked;
    if (wantDeep && !DEEP_AVAILABLE) { openKeyModal(); return; }
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> starting…';
    try {
      await fetch('/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          passive: document.getElementById('optPassive').checked,
          deep: wantDeep,
          no_graph: document.getElementById('optNoGraph').checked,
        }),
      });
      input.value = '';
      await loadJobs();
    } finally {
      btn.disabled = false; btn.innerHTML = `${icon('radar-2')} Run scan`;
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadScans();
  loadJobs();
  wireNewScan();
  wireKeyModal();
});
