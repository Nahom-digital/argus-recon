/* ============================================================================
   Home — scan library, launch + track scans, deep-DNS key, delete
   ========================================================================== */
'use strict';

let DEEP_AVAILABLE = false;
let TOR = { available: false };
const STAGES = [
  ['subdomain', 'subdomains'], ['fingerprint', 'fingerprint'], ['crawl', 'crawl'],
  ['bruteforce', 'bruteforce'], ['ip_enrich', 'IP enrich'], ['classify', 'classify'],
  ['graph', 'graph'],
];

/* uptime for the Live chip: minutes up to an hour, then hours, then days */
function fmtUptime(sec) {
  sec = Math.max(0, Math.round(sec || 0));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  if (sec < 86400) {
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
    return h + 'h' + (m ? ' ' + m + 'm' : '');
  }
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600);
  return d + 'd' + (h ? ' ' + h + 'h' : '');
}

async function loadStatus() {
  const bar = document.getElementById('statusbar');
  try {
    const s = await getJSON(withBase('/api/status'));
    DEEP_AVAILABLE = !!s.deep_available;
    TOR = s.tor || { available: false };
    reflectDeep();
    reflectTor();
    applyDefaults(s.defaults || {});

    // Service state first: the dashboard is the product now, so whether it is
    // actually registered and serving is the headline, not a footnote.
    const svc = s.service || {};
    const detail = [
      svc.uptime_sec != null ? 'up ' + fmtUptime(svc.uptime_sec) : '',
      svc.version || '',
    ].filter(Boolean).join(' · ');
    const live = svc.managed
      ? `<span class="st live"><span class="dot on"></span><b>Live</b> ${esc(detail)}</span>`
      : `<span class="st live unmanaged" title="Running, but not registered as a service — run ./install.sh so it survives logout and reboot"><span class="dot warn"></span><b>Running</b> not a service${detail ? ' · ' + esc(detail) : ''}</span>`;

    // No recon-tool names on the home page — only capability state (see README).
    const chip = (dot, label, val) =>
      `<span class="st"><span class="dot ${dot ? 'on' : 'off'}"></span><b>${esc(label)}</b> ${esc(val)}</span>`;
    const chips = [
      live,
      chip(s.deep_available, 'deep DNS', s.deep_available ? 'unlocked' : 'locked'),
      chip(s.graph_db, 'graph db', s.graph_db ? 'connected' : 'offline · renders from JSON'),
      chip(s.engines_ready, 'engines', s.engines_ready ? 'ready' : 'incomplete'),
    ];
    if (!s.deep_available)
      chips.push(`<button class="st st-btn" id="setKeyBtn">${icon('settings')} add deep-DNS key</button>`);
    bar.innerHTML = chips.join('');
    const kb = document.getElementById('setKeyBtn');
    if (kb) kb.addEventListener('click', () => openKeyModal());
    maybePromptForKey();
  } catch (e) {
    bar.innerHTML = `<span class="st live unmanaged"><span class="dot off"></span><b>Offline</b> the dashboard service is not answering</span>`;
  }
}

/* show the server's real crawl defaults as placeholders (never invented numbers) */
function applyDefaults(d) {
  const p = document.getElementById('optMaxPages');
  const q = document.getElementById('optMaxDepth');
  if (p && d.max_pages) p.placeholder = String(d.max_pages);
  if (q && d.max_depth) q.placeholder = String(d.max_depth);
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

/* Tor is a machine capability, not a setting: it needs a tor client (or a live
   SOCKS proxy) and the Python SOCKS dependency. Lock the toggle when the server
   says it cannot honour it, and say which piece is missing rather than letting
   the scan fail at its first step. */
function torReason() {
  if (TOR.available) {
    return TOR.running
      ? 'Route the whole scan through the Tor proxy already running on ' + (TOR.socks || 'this machine')
      : 'Route the whole scan through Tor. A private tor is started for the run and stopped after it.';
  }
  if (!TOR.socks_lib) return 'Tor needs the SOCKS dependency — run ./install.sh to add it';
  if (!TOR.binary) return 'Tor is not installed on this machine — install tor, or start a Tor client';
  return 'Tor is unavailable on this machine';
}

function reflectTor() {
  const chk = document.getElementById('torChk');
  const box = document.getElementById('optTor');
  if (!chk) return;
  chk.classList.toggle('locked', !TOR.available);
  chk.title = torReason();
  if (!TOR.available && box) box.checked = false;
}

function scanRow(s) {
  const st = s.stats || {};
  const meta = [];
  if (s.started_at) meta.push(icon('clock') + ' ' + timeAgo(s.started_at));
  if (s.duration_sec != null) meta.push(fmtDur(s.duration_sec));
  meta.push(fmtBytes(s.size));
  // a single-target or Tor run must not look identical to a full direct one
  if (s.scope === 'host')
    meta.push(`<span class="how">${icon('point-filled')} single host</span>`);
  if (s.tor && s.tor.exit_ip)
    meta.push(`<span class="how" title="Exit node ${esc(s.tor.exit_ip)}${
      s.tor.verified ? '' : ' (proxied, unverified)'}">${icon('shield-half-filled')} via Tor</span>`);
  const metric = (n, l, accent) =>
    `<div class="metric ${accent ? 'accent' : ''}"><div class="n">${fmtNum(n)}</div><div class="l">${l}</div></div>`;
  return `<div class="scan-row-wrap">
    <a class="scan-row" href="${withBase('/scan/' + encodeURIComponent(s.scan_id))}">
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
    const scans = await getJSON(withBase('/api/scans'));
    if (!scans.length) {
      wrap.innerHTML = `<div class="panel"><div class="empty">
        ${icon('radar-2')}<h4>No scans yet</h4>
        <p>Enter a domain in the field above and press Run scan. It runs here in the
           dashboard, streams a live log, and lands in this library when it finishes.</p>
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
      const r = await fetch(withBase(`/api/scan/${encodeURIComponent(id)}`), { method: 'DELETE' });
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
}

/* First run: no key set and not dismissed -> prompt once. Driven by the status
   response, not a timer, so a slow status call can't pop the modal over a
   dashboard that already has a key. */
let keyPromptShown = false;
function maybePromptForKey() {
  if (keyPromptShown || DEEP_AVAILABLE) return;
  keyPromptShown = true;
  let dismissed = false;
  try { dismissed = localStorage.getItem('argus-key-dismissed') === '1'; } catch (e) {}
  if (!dismissed) openKeyModal();
}

async function saveKey() {
  const input = document.getElementById('keyInput');
  const key = input.value.trim();
  const btn = document.getElementById('keySave');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> saving';
  try {
    const r = await fetch(withBase('/api/config/key'), {
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

const JOB_ACTIVE = ['queued', 'running', 'stopping'];

/* what the run was launched with — this is the only place it is visible now
   that there is no command line to read it off */
function jobOpts(j) {
  const o = j.options || {};
  const label = Object.fromEntries(STAGES);
  const tags = [];
  if (o.tor) tags.push('via Tor');
  if (o.single) tags.push('single host');
  if (o.passive) tags.push('passive');
  if (o.deep) tags.push('deep DNS');
  if (o.exact_scope) tags.push('exact host');
  (o.skipped || []).forEach(s => tags.push('no ' + (label[s] || s)));
  return tags.length
    ? `<span class="jopts">${tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</span>` : '';
}

async function loadJobs() {
  const wrap = document.getElementById('jobsWrap');
  let jobs = [];
  try { jobs = await getJSON(withBase('/api/jobs')); } catch (e) { return; }
  const active = jobs.filter(j => JOB_ACTIVE.includes(j.status));
  const recent = jobs.filter(j => !JOB_ACTIVE.includes(j.status)).slice(0, 3);
  const show = [...active, ...recent];
  if (!show.length) { wrap.innerHTML = ''; return; }

  wrap.innerHTML = '<div class="section-label">Running &amp; recent jobs</div><div class="jobs">' +
    show.map(j => {
      const running = JOB_ACTIVE.includes(j.status);
      const ind = running ? '<span class="spin"></span>'
        : j.status === 'done' ? icon('circle-check-filled')
        : j.status === 'stopped' ? icon('x')
        : icon('alert-triangle');
      const stop = j.status === 'running' || j.status === 'queued'
        ? `<button class="btn sm ghost jstop" data-stop="${j.id}">${icon('x')} stop</button>` : '';
      return `<div class="job ${running ? 'on' : ''}" data-job="${j.id}">
        <span class="jdom">${esc(j.domain)}</span>
        ${jobOpts(j)}
        <span class="jstat"><span class="jstate ${esc(j.status)}">${ind} ${esc(j.status)}</span>${
        j.status === 'done' ? ' <a href="#" data-reload="1">view result</a>' : ''}
          ${stop}
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
  wrap.querySelectorAll('[data-stop]').forEach(b =>
    b.addEventListener('click', () => stopJob(b.dataset.stop, b)));
  wrap.querySelectorAll('[data-reload]').forEach(a => a.addEventListener('click', e => {
    e.preventDefault(); loadScans();
  }));

  if (active.length) {
    if (!jobTimer) jobTimer = setInterval(pollJobs, 2500);
  } else if (jobTimer) { clearInterval(jobTimer); jobTimer = null; loadScans(); }
}

/* Cancel a run. With no terminal there is nothing else to interrupt, so this
   is the only way out of a scan that is taking too long. */
async function stopJob(id, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> stopping';
  try {
    await fetch(withBase(`/api/jobs/${encodeURIComponent(id)}/stop`), { method: 'POST' });
  } catch (e) { /* the poll below reports the real state */ }
  loadJobs();
}

async function refreshLog(id) {
  try {
    const d = await getJSON(withBase(`/api/jobs/${id}/log`));
    const box = document.getElementById('log-' + id);
    if (box) { box.textContent = d.log || '(waiting for output…)'; box.scrollTop = box.scrollHeight; }
  } catch (e) {}
}
function pollJobs() { loadJobs(); }

/* ---- advanced options ----------------------------------------------------- */
/* The engine no longer runs from a terminal, so every pipeline flag has to be
   reachable here. The common three stay in the bar; the rest live one click
   away, with a badge so a non-default setup is never invisible. */
function renderStages() {
  const wrap = document.getElementById('stageChips');
  if (!wrap) return;
  wrap.innerHTML = STAGES.map(([id, label]) =>
    `<label class="stage"><input type="checkbox" data-stage="${id}" checked>
      <span>${esc(label)}</span></label>`).join('');
}

/* Each scope answers "what counts as the target?", so the help line states the
   consequence of the current choice instead of describing all three at once. */
const SCOPE_HELP = {
  apex: 'A subdomain target pivots to its apex, so the rest of the estate is enumerated too.',
  exact: 'The host is taken literally. Its own subdomains are still enumerated and in scope.',
  single: 'This host and nothing else. No subdomain enumeration, and anything off-host is recorded but never followed.',
};

function currentScope() {
  return (document.querySelector('input[name=scope]:checked') || {}).value || 'apex';
}

function reflectScope() {
  const scope = currentScope();
  const help = document.getElementById('scopeHelp');
  if (help) help.textContent = SCOPE_HELP[scope] || SCOPE_HELP.apex;
  // Nothing is enumerated in single-host mode, so the enum-engine switch has
  // nothing to act on. Disabled and explained, rather than silently ignored.
  const box = document.getElementById('optNoBbot');
  const label = document.getElementById('noBbotChk');
  if (!box || !label) return;
  const na = scope === 'single';
  box.disabled = na;
  if (na) box.checked = false;
  label.classList.toggle('na', na);
  label.title = na ? 'No host enumeration runs in single-host mode' : '';
}

function scanOptions() {
  const num = (id) => {
    const v = (document.getElementById(id).value || '').trim();
    const n = parseInt(v, 10);
    return v && Number.isFinite(n) && n > 0 ? n : null;
  };
  const skip = [...document.querySelectorAll('[data-stage]')]
    .filter(c => !c.checked).map(c => c.dataset.stage);
  const scope = currentScope();
  return {
    passive: document.getElementById('optPassive').checked,
    deep: document.getElementById('optDeep').checked,
    tor: document.getElementById('optTor').checked,
    single: scope === 'single',
    exact_scope: scope === 'exact',
    no_bbot: document.getElementById('optNoBbot').checked,
    max_pages: num('optMaxPages'),
    max_depth: num('optMaxDepth'),
    skip,
  };
}

/* how many advanced options differ from the defaults */
function countAdvanced(o) {
  return (o.exact_scope ? 1 : 0) + (o.single ? 1 : 0) + (o.no_bbot ? 1 : 0) +
    (o.max_pages ? 1 : 0) + (o.max_depth ? 1 : 0) + o.skip.length;
}

function reflectOptionCount() {
  const badge = document.getElementById('optsCount');
  if (!badge) return;
  const n = countAdvanced(scanOptions());
  badge.hidden = n === 0;
  badge.textContent = n;
}

function wireOptions() {
  renderStages();
  reflectScope();
  document.querySelectorAll('input[name=scope]').forEach(r =>
    r.addEventListener('change', reflectScope));
  // a locked Tor toggle has nothing to open — say what is missing, in place
  const torChk = document.getElementById('torChk');
  if (torChk) torChk.addEventListener('click', e => {
    if (!TOR.available) { e.preventDefault(); formError(null, torReason()); }
  });
  const btn = document.getElementById('optsToggle');
  const panel = document.getElementById('scanOpts');
  if (!btn || !panel) return;
  btn.addEventListener('click', () => {
    const open = !panel.classList.contains('open');
    panel.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', String(open));
    // keep clipped controls out of the tab order while collapsed
    if (open) panel.removeAttribute('inert'); else panel.setAttribute('inert', '');
    if (open) setTimeout(() => panel.querySelector('input')?.focus(), 160);
  });
  document.getElementById('newscan').addEventListener('change', reflectOptionCount);
  document.getElementById('newscan').addEventListener('input', reflectOptionCount);
}

/* ---- launch --------------------------------------------------------------- */
function wireNewScan() {
  const form = document.getElementById('newscan');
  const input = document.getElementById('domainInput');
  const btn = document.getElementById('scanBtn');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9.\-]+\.[a-z]{2,}$/.test(domain)) return formError(input, 'Enter a domain like example.com');
    const opts = scanOptions();
    if (opts.deep && !DEEP_AVAILABLE) { openKeyModal(); return; }
    if (opts.tor && !TOR.available) return formError(null, torReason());
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> starting…';
    try {
      const r = await fetch(withBase('/api/scan'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, ...opts }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        return formError(input, d.error || `could not start the scan (${r.status})`);
      }
      input.value = '';
      await loadJobs();
    } catch (err) {
      formError(input, 'the dashboard service did not respond');
    } finally {
      btn.disabled = false; btn.innerHTML = `${icon('radar-2')} Run scan`;
    }
  });
}

/* inline, next to the field that caused it — no toast, no modal. `input` is
   optional: a blocked option (Tor unavailable) is not the domain field's fault,
   so nothing gets marked invalid in that case. */
function formError(input, msg) {
  const form = document.getElementById('newscan');
  let el = form.querySelector('.ns-error');
  if (!el) {
    el = h('p', { class: 'ns-error', role: 'alert' });
    form.querySelector('.ns-main').insertAdjacentElement('afterend', el);
  }
  el.innerHTML = `${icon('alert-triangle')} ${esc(msg)}`;
  if (input) { input.classList.add('invalid'); input.focus(); }
  clearTimeout(formError._t);
  formError._t = setTimeout(() => {
    el.remove();
    if (input) input.classList.remove('invalid');
  }, 5000);
}

document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadScans();
  loadJobs();
  wireOptions();
  wireNewScan();
  wireKeyModal();
  // keep the Live chip's uptime honest while the tab stays open
  setInterval(loadStatus, 60000);
});
