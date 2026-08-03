/* ============================================================================
   Home · scan library, launch + track scans, deep-DNS key, delete
   ========================================================================== */
'use strict';

let DEEP_AVAILABLE = false;
let TOR = { available: false };
let PORTSCAN_AVAILABLE = false;
let WAYBACK = { available: true, engine: false };
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
    PORTSCAN_AVAILABLE = !!s.portscan_available;
    WAYBACK = { available: s.wayback_available !== false, engine: !!s.wayback_engine };
    reflectDeep();
    reflectTor();
    reflectPortscan();
    reflectWayback();
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
      : `<span class="st live unmanaged" title="Running, but not registered as a service · run ./install.sh so it survives logout and reboot"><span class="dot warn"></span><b>Running</b> not a service${detail ? ' · ' + esc(detail) : ''}</span>`;

    // No recon-tool names on the home page · only capability state (see README).
    const chip = (dot, label, val) =>
      `<span class="st"><span class="dot ${dot ? 'on' : 'off'}"></span><b>${esc(label)}</b> ${esc(val)}</span>`;
    const chips = [
      live,
      `<span class="st" id="deepChip"><span class="dot ${s.deep_available ? 'on' : 'off'}"></span>
        <b>deep DNS</b> ${s.deep_available ? 'unlocked' : 'locked'}</span>`,
      chip(s.graph_db, 'graph db', s.graph_db ? 'connected' : 'offline · renders from JSON'),
      chip(s.engines_ready, 'engines', s.engines_ready ? 'ready' : 'incomplete'),
    ];
    if (!s.deep_available)
      chips.push(`<button class="st st-btn" id="setKeyBtn">${icon('settings')} add deep-DNS key</button>`);
    bar.innerHTML = chips.join('');
    const kb = document.getElementById('setKeyBtn');
    if (kb) kb.addEventListener('click', () => openKeyModal());
    refreshQuotaChip(((s.auth || {}).user || {}).quota);
    if (s.deep_available) showDeepAllowance();
    maybePromptForKey();
  } catch (e) {
    bar.innerHTML = `<span class="st live unmanaged"><span class="dot off"></span><b>Offline</b> the dashboard service is not answering</span>`;
  }
}

/* What is left of the deep-DNS allowance, on the status chip. The allowance is
   small and monthly, so "how much is left" belongs next to the toggle that
   spends it rather than in the dialog that appears once it is already gone. The
   server caches this, so asking on every page load is cheap. */
async function showDeepAllowance() {
  const el = document.getElementById('deepChip');
  if (!el) return;
  let q;
  try { q = await getJSON(withBase('/api/config/key/check')); }
  catch (e) { return; }                       // chip keeps its plain "unlocked"
  if (!q || q.remaining == null) return;
  const dot = q.state === 'ok' ? 'on' : 'warn';
  el.innerHTML = `<span class="dot ${dot}"></span><b>deep DNS</b> ${
    fmtNum(q.remaining)} of ${fmtNum(q.limit)} queries left`;
  el.title = q.message || '';
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
    : 'Deep DNS is locked · click to add an API key';
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
  if (!TOR.socks_lib) return 'Tor needs the SOCKS dependency · run ./install.sh to add it';
  if (!TOR.binary) return 'Tor is not installed on this machine · install tor, or start a Tor client';
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

/* Port scan, like Tor, is a machine capability: it needs the scan engine
   installed. Lock the toggle when the server reports it missing, and never let a
   passive run (which sends nothing to the target) also ask for an active scan. */
function reflectPortscan() {
  const chk = document.getElementById('portscanChk');
  const box = document.getElementById('optPortscan');
  const passive = document.getElementById('optPassive');
  if (!chk) return;
  const passiveOn = passive && passive.checked;
  const locked = !PORTSCAN_AVAILABLE || passiveOn;
  chk.classList.toggle('locked', locked);
  chk.title = !PORTSCAN_AVAILABLE
    ? 'Port-scan engine is not installed · run ./install.sh to add it'
    : passiveOn
      ? 'Port scan is an active probe · turn off “passive” to use it'
      : 'Scan every discovered IP for open ports & services (slow, and it touches the target directly)';
  if (locked && box) box.checked = false;
  if (box) box.disabled = locked;
}

/* The archive pass always has a path that works · the index over plain HTTP
   when the dedicated engine is not installed · so this toggle is never locked.
   Say which of the two it will use, since the engine is meaningfully wider. */
function reflectWayback() {
  const chk = document.getElementById('waybackChk');
  if (!chk) return;
  chk.title = WAYBACK.engine
    ? 'Mine the web archive for URLs this domain used to serve · nothing is sent to the target'
    : 'Mine the web archive for URLs this domain used to serve (via the archive index · '
      + 'run ./install.sh to add the faster engine). Nothing is sent to the target.';
}

/* The account's remaining allowance, shown next to the launcher so a limit is
   visible before it is hit rather than as a refusal afterwards. */
function refreshQuotaChip(q) {
  const el = document.getElementById('quotaChip');
  if (!el) return;
  if (!q || !q.daily_scans) { el.hidden = true; return; }
  el.hidden = false;
  el.className = 'quota-chip' + (q.remaining === 0 ? ' out' : '');
  el.innerHTML = `${icon('radar-2')} ${fmtNum(q.remaining)} of ${fmtNum(q.daily_scans)} scans left today`;
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
      await sendJSON(withBase(`/api/scan/${encodeURIComponent(id)}`), 'DELETE');
      wrap.classList.add('removing');
      setTimeout(loadScans, 200);
    } catch (e) {
      btn.innerHTML = icon('trash');
      wrap.classList.remove('confirm');
      formError(null, e.message);
    }
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
  const persist = !document.getElementById('keySession') ||
    !document.getElementById('keySession').checked;
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> saving';
  try {
    const d = await sendJSON(withBase('/api/config/key'), 'POST', { key, persist });
    DEEP_AVAILABLE = !!d.deep_available;
    reflectDeep();
    try { localStorage.setItem('argus-key-dismissed', '1'); } catch (e) {}
    // A key that is already spent is worth saying now rather than at the start
    // of the next scan · the modal stays open with the reason on it.
    const q = d.quota;
    if (key && q && !q.ok) {
      showKeyNote(q.message || 'this key cannot be used');
      return;
    }
    closeKeyModal();
    loadStatus();
  } catch (e) {
    showKeyNote(e.message);
  } finally {
    btn.disabled = false; btn.innerHTML = `${icon('key')} Save & enable`;
  }
}

function showKeyNote(text, ok) {
  const modal = document.querySelector('#keyModal .modal');
  if (!modal) return;
  let el = modal.querySelector('.key-note');
  if (!el) {
    el = h('p', { class: 'key-note' });
    modal.querySelector('#keyInput').insertAdjacentElement('afterend', el);
  }
  el.className = 'key-note' + (ok ? ' ok' : '');
  el.innerHTML = `${icon(ok ? 'circle-check-filled' : 'alert-triangle')} ${esc(text)}`;
}

/* ---- deep-DNS allowance ---------------------------------------------------
   A key whose monthly allowance is spent does not fail loudly · it answers 429
   to everything, so the deep-DNS stage runs for minutes and contributes
   nothing. The launcher therefore asks the server where the key stands *before*
   committing to a run, and puts the choice in front of the operator: go on
   without deep DNS, or paste a key that still has room (for this run only, or
   saved for future ones).

   The same dialog covers the allowance that is nearly gone ("low"): a pass costs
   a known number of calls, so a run that would run dry part way through is worth
   stopping on too · with the extra option of spending what is left anyway. */
function keyStateModal(quota) {
  return new Promise(resolve => {
    const low = quota.state === 'low';
    const scrim = h('div', { class: 'modal-scrim' });
    scrim.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="qTitle">
      <div class="modal-head">${icon('alert-triangle')}<h3 id="qTitle">${
      low ? 'Deep DNS is nearly out of allowance' : 'Deep DNS is not usable'}</h3></div>
      <p class="modal-body">${esc(quota.message || 'The deep-DNS key cannot be used.')}
        ${quota.limit ? `<br><span class="faint">Used ${fmtNum(quota.used)} of ${fmtNum(quota.limit)} this month${
      quota.needed ? `, and this run needs about ${fmtNum(quota.needed)}` : ''}.</span>` : ''}
      </p>
      <label class="field"><span class="faint" style="font-size:12px">Use a different key</span>
        <input class="input mono" id="qKey" type="password" placeholder="paste another API key"
               spellcheck="false" autocomplete="off"></label>
      <label class="chk" style="font-size:13px"><input type="checkbox" id="qSession" checked>
        this session only · do not save it to disk</label>
      <p class="key-note" id="qNote" hidden></p>
      <div class="modal-actions">
        <button class="btn ghost" id="qCancel">Cancel the scan</button>
        <button class="btn" id="qWithout">Run without deep DNS</button>
        ${low ? `<button class="btn" id="qAnyway">Use what is left</button>` : ''}
        <button class="btn primary" id="qUse">${icon('key')} Use this key</button>
      </div>
    </div>`;
    document.body.appendChild(scrim);
    const done = (value) => { scrim.remove(); resolve(value); };
    const note = (msg) => {
      const el = scrim.querySelector('#qNote');
      el.innerHTML = `${icon('alert-triangle')} ${esc(msg)}`;
      el.hidden = false;
    };

    scrim.querySelector('#qCancel').addEventListener('click', () => done('cancel'));
    scrim.querySelector('#qWithout').addEventListener('click', () => done('without'));
    const anyway = scrim.querySelector('#qAnyway');
    if (anyway) anyway.addEventListener('click', () => done('deep'));
    scrim.addEventListener('click', e => { if (e.target === scrim) done('cancel'); });
    scrim.querySelector('#qUse').addEventListener('click', async () => {
      const key = scrim.querySelector('#qKey').value.trim();
      if (!key) return note('paste a key, or choose one of the other two options');
      const btn = scrim.querySelector('#qUse');
      btn.disabled = true;
      btn.innerHTML = '<span class="spin"></span> checking';
      try {
        const d = await sendJSON(withBase('/api/config/key'), 'POST',
          { key, persist: !scrim.querySelector('#qSession').checked });
        if (d.quota && !d.quota.ok) {
          btn.disabled = false;
          btn.innerHTML = `${icon('key')} Use this key`;
          return note(d.quota.message || 'that key cannot be used either');
        }
        DEEP_AVAILABLE = !!d.deep_available;
        reflectDeep();
        done('deep');
      } catch (e) {
        btn.disabled = false;
        btn.innerHTML = `${icon('key')} Use this key`;
        note(e.message);
      }
    });
    setTimeout(() => scrim.querySelector('#qKey').focus(), 40);
  });
}

/* Returns 'deep' (go ahead with deep DNS), 'without' (drop it and scan anyway)
   or 'cancel'. Anything other than a definite problem passes straight through
   without a dialog. */
async function resolveDeepDns() {
  let q;
  try { q = await getJSON(withBase('/api/config/key/check')); }
  catch (e) { return 'deep'; }             // cannot tell · do not block the scan
  if (!q || q.ok || q.state === 'unset') return 'deep';
  if (q.state === 'unreachable') return 'deep';   // transient · let the run try
  return keyStateModal(q);
}

/* ---- jobs (running scans) ------------------------------------------------- */
let jobTimer = null;
const openLogs = new Set();

const JOB_ACTIVE = ['queued', 'running', 'stopping'];

/* what the run was launched with · this is the only place it is visible now
   that there is no command line to read it off */
function jobOpts(j) {
  const o = j.options || {};
  const label = Object.fromEntries(STAGES);
  const tags = [];
  if (o.tor) tags.push('via Tor');
  if (o.portscan) tags.push('port scan');
  if (o.wayback) tags.push('web archive');
  if (o.single) tags.push('single host');
  if (o.passive) tags.push('passive');
  if (o.deep) tags.push('deep DNS');
  if (o.exact_scope) tags.push('exact host');
  (o.skipped || []).forEach(s => tags.push('no ' + (label[s] || s)));
  return tags.length
    ? `<span class="jopts">${tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</span>` : '';
}

/* The job list is polled every 2.5s while something is running. It used to be
   re-rendered wholesale on every poll, which threw away and rebuilt the open
   terminal each time · the log blinked out and back, lost its scroll position,
   and re-ran its open animation, four times a minute.

   So the list is now reconciled instead of rebuilt: the container is only
   regenerated when the *set* of jobs changes, and an existing row has just its
   status, buttons and log text updated in place. The <div class="job-log">
   element survives the whole run, which is what makes the terminal stable. */
let jobsSignature = '';

function jobIndicator(j) {
  const running = JOB_ACTIVE.includes(j.status);
  return running ? '<span class="spin"></span>'
    : j.status === 'done' ? icon('circle-check-filled')
    : j.status === 'stopped' ? icon('x')
    : icon('alert-triangle');
}

function jobStatusHtml(j) {
  const stop = j.status === 'running' || j.status === 'queued'
    ? `<button class="btn sm ghost jstop" data-stop="${esc(j.id)}">${icon('x')} stop</button>` : '';
  return `<span class="jstate ${esc(j.status)}">${jobIndicator(j)} ${esc(j.status)}</span>`
    + (j.status === 'done' ? ' <a href="#" data-reload="1">view result</a>' : '')
    + stop
    + `<button class="btn sm ghost" data-toggle-log="${esc(j.id)}">${icon('terminal-2')} log</button>`;
}

function jobRowHtml(j) {
  const running = JOB_ACTIVE.includes(j.status);
  return `<div class="job ${running ? 'on' : ''}" data-job="${esc(j.id)}">
    <span class="jdom">${esc(j.domain)}</span>
    ${jobOpts(j)}
    <span class="jstat">${jobStatusHtml(j)}</span>
    <div class="job-log ${openLogs.has(j.id) ? 'open' : ''}" id="log-${esc(j.id)}"></div>
  </div>`;
}

async function loadJobs() {
  const wrap = document.getElementById('jobsWrap');
  let jobs = [];
  try { jobs = await getJSON(withBase('/api/jobs')); } catch (e) { return; }
  const active = jobs.filter(j => JOB_ACTIVE.includes(j.status));
  const recent = jobs.filter(j => !JOB_ACTIVE.includes(j.status)).slice(0, 3);
  const show = [...active, ...recent];

  if (!show.length) {
    if (wrap.innerHTML) { wrap.innerHTML = ''; jobsSignature = ''; }
    stopPolling(false);
    return;
  }

  // Rebuild only when the rows themselves change (a job appeared or dropped
  // out of the window). Everything else is an in-place update.
  const sig = show.map(j => j.id).join(',');
  if (sig !== jobsSignature) {
    jobsSignature = sig;
    wrap.innerHTML = '<div class="section-label">Running &amp; recent jobs</div>'
      + `<div class="jobs">${show.map(jobRowHtml).join('')}</div>`;
    wireJobRow(wrap);
  } else {
    show.forEach(j => {
      const row = wrap.querySelector(`.job[data-job="${CSS.escape(j.id)}"]`);
      if (!row) return;
      row.classList.toggle('on', JOB_ACTIVE.includes(j.status));
      const stat = row.querySelector('.jstat');
      const next = jobStatusHtml(j);
      if (stat.dataset.html !== next) {      // only touch the DOM on a real change
        stat.innerHTML = next;
        stat.dataset.html = next;
        wireJobRow(stat);
      }
    });
  }

  openLogs.forEach(id => refreshLog(id));

  if (active.length) {
    if (!jobTimer) jobTimer = setInterval(pollJobs, 2500);
  } else {
    stopPolling(true);
  }
}

function stopPolling(reloadLibrary) {
  if (!jobTimer) return;
  clearInterval(jobTimer);
  jobTimer = null;
  if (reloadLibrary) loadScans();
}

/* Delegate-free wiring for a row (or just its status cell after an update). */
function wireJobRow(root) {
  root.querySelectorAll('[data-toggle-log]').forEach(b => {
    if (b._wired) return; b._wired = true;
    b.addEventListener('click', () => {
      const id = b.getAttribute('data-toggle-log');
      const box = document.getElementById('log-' + id);
      if (!box) return;
      if (openLogs.has(id)) { openLogs.delete(id); box.classList.remove('open'); }
      else { openLogs.add(id); box.classList.add('open'); refreshLog(id); }
    });
  });
  root.querySelectorAll('[data-stop]').forEach(b => {
    if (b._wired) return; b._wired = true;
    b.addEventListener('click', () => stopJob(b.dataset.stop, b));
  });
  root.querySelectorAll('[data-reload]').forEach(a => {
    if (a._wired) return; a._wired = true;
    a.addEventListener('click', e => { e.preventDefault(); loadScans(); });
  });
}

/* Cancel a run. With no terminal there is nothing else to interrupt, so this
   is the only way out of a scan that is taking too long. */
async function stopJob(id, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> stopping';
  try {
    await sendJSON(withBase(`/api/jobs/${encodeURIComponent(id)}/stop`), 'POST', {});
  } catch (e) { /* the poll below reports the real state */ }
  jobsSignature = '';            // force a rebuild so the row's buttons refresh
  loadJobs();
}

/* Refresh one open terminal.

   Two things keep it steady rather than twitchy: the text is only written when
   it actually changed, and the view is only pulled back to the bottom if it was
   already there. Scrolling up to read something no longer yanks you back to the
   tail two seconds later. */
async function refreshLog(id) {
  const box = document.getElementById('log-' + id);
  if (!box || !box.classList.contains('open')) return;
  let d;
  try { d = await getJSON(withBase(`/api/jobs/${encodeURIComponent(id)}/log`)); }
  catch (e) { return; }
  const text = d.log || '(waiting for output…)';
  if (box.textContent === text) return;
  // "pinned" = the reader is at the tail and wants to follow the output
  const pinned = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.textContent = text;
  if (pinned) box.scrollTop = box.scrollHeight;
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
    portscan: document.getElementById('optPortscan').checked,
    wayback: document.getElementById('optWayback').checked,
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
  // a locked Tor toggle has nothing to open · say what is missing, in place
  const torChk = document.getElementById('torChk');
  if (torChk) torChk.addEventListener('click', e => {
    if (!TOR.available) { e.preventDefault(); formError(null, torReason()); }
  });
  // port scan: locked while unavailable or while passive is on; keep the two in sync
  const portscanChk = document.getElementById('portscanChk');
  if (portscanChk) portscanChk.addEventListener('click', e => {
    const box = document.getElementById('optPortscan');
    if (box && box.disabled) { e.preventDefault(); formError(null, portscanChk.title); }
  });
  const passiveBox = document.getElementById('optPassive');
  if (passiveBox) passiveBox.addEventListener('change', reflectPortscan);
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

    // Deep DNS asked for: make sure the key can actually answer before the run
    // commits several minutes to a stage that would return nothing.
    if (opts.deep) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spin"></span> checking key…';
      const choice = await resolveDeepDns();
      btn.disabled = false;
      btn.innerHTML = `${icon('radar-2')} Run scan`;
      if (choice === 'cancel') return;
      if (choice === 'without') {
        opts.deep = false;
        const box = document.getElementById('optDeep');
        if (box) box.checked = false;
      }
    }

    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> starting…';
    try {
      const d = await sendJSON(withBase('/api/scan'), 'POST', { domain, ...opts });
      input.value = '';
      jobsSignature = '';                  // a new row · rebuild the job list
      await loadJobs();
      if (d && d.quota) refreshQuotaChip(d.quota);
    } catch (err) {
      formError(input, err.message || 'the dashboard service did not respond');
    } finally {
      btn.disabled = false; btn.innerHTML = `${icon('radar-2')} Run scan`;
    }
  });
}

/* inline, next to the field that caused it · no toast, no modal. `input` is
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
