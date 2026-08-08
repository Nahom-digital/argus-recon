/* ============================================================================
   Home · scan library, launch + track scans, deep-DNS key, delete
   ========================================================================== */
'use strict';

let DEEP_AVAILABLE = false;
let TOR = { available: false };
let PORTSCAN_AVAILABLE = false;
let WAYBACK = { available: true, engine: false };
let TOOLS_AVAIL = {};                 // per-tool "installed?" map from /api/status
const STAGES = [
  ['subdomain', 'subdomains'], ['fingerprint', 'fingerprint'], ['crawl', 'crawl'],
  ['bruteforce', 'bruteforce'], ['ip_enrich', 'IP enrich'], ['classify', 'classify'],
  ['graph', 'graph'],
];

/* Every recon tool the engine can run, grouped the way an operator thinks about
   them, so even inside "deep" or "passive" a single tool can be switched off.
   One table drives the whole panel; each entry says how turning it off maps onto
   the scan options the server understands:
     kind 'stage'  · a pipeline stage · off adds it to `skip`
     kind 'flag'   · an on-by-default tool behind a --no-x flag · off sets the flag
     kind 'enable' · an off-by-default extra that mirrors a top-bar toggle
   avail  · key in the server tool map; when false the tool is locked (not installed)
   needs  · another tool id this one rides on (off/na when that one is off) */
const TOOLS = [
  // passive & discovery
  { id: 'subdomain', group: 'passive', kind: 'stage', name: 'Subdomain enum',
    tool: 'crt.sh · dnsx', desc: 'Cert transparency + DNS brute' },
  { id: 'bbot', group: 'passive', kind: 'flag', flag: 'no_bbot', name: 'BBOT',
    tool: 'bbot', avail: 'bbot', noSingle: true, desc: 'Deep passive subdomain sweep' },
  { id: 'deep', group: 'passive', kind: 'enable', mirror: 'optDeep', name: 'Deep DNS',
    tool: 'SecurityTrails', avail: 'securitytrails', deep: true,
    desc: 'Extra subdomains + full & historical DNS' },
  { id: 'wayback', group: 'passive', kind: 'enable', mirror: 'optWayback',
    name: 'Web archive', tool: 'waybackurls', desc: 'URLs the domain used to serve' },
  // active scan
  { id: 'probe', group: 'active', kind: 'flag', flag: 'no_probe', name: 'HTTP probe',
    tool: 'httpx', desc: 'Which hosts are live, on which scheme' },
  { id: 'fingerprint', group: 'active', kind: 'stage', name: 'Fingerprint',
    tool: 'WhatWeb', avail: 'whatweb', desc: 'Name the stack behind each host' },
  { id: 'deepcrawl', group: 'active', kind: 'flag', flag: 'no_deepcrawl',
    name: 'Deep crawl', tool: 'katana', avail: 'katana', needs: 'crawl',
    desc: 'JS-aware route & endpoint discovery' },
  { id: 'crawl', group: 'active', kind: 'stage', name: 'Crawler', tool: 'built in',
    desc: 'Fetch pages, forms, bodies, secrets' },
  { id: 'bruteforce', group: 'active', kind: 'stage', name: 'Content brute',
    tool: 'ffuf', avail: 'ffuf', desc: 'Guess unlinked paths & files' },
  { id: 'portscan', group: 'active', kind: 'enable', mirror: 'optPortscan',
    name: 'Port scan', tool: 'nmap', avail: 'nmap',
    desc: 'Open ports & services on every IP' },
  // processing
  { id: 'ip_enrich', group: 'process', kind: 'stage', name: 'IP enrich',
    tool: 'ipinfo', desc: 'ASN, org & geo per address' },
  { id: 'classify', group: 'process', kind: 'stage', name: 'Classify',
    tool: 'built in', desc: 'Label sensitive fields' },
  { id: 'graph', group: 'process', kind: 'stage', name: 'Graph', tool: 'built in',
    desc: 'Build the relationship graph' },
];
const TOOL_BY_ID = Object.fromEntries(TOOLS.map(t => [t.id, t]));

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
    TOOLS_AVAIL = s.tools || {};
    reflectDeep();
    reflectTor();
    reflectPortscan();
    reflectWayback();
    reflectTools();
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

/* Push a top-bar toggle's state down onto its mirrored tool row (deep, port scan,
   web archive appear in both places · the top bar owns them). */
function syncToolRow(id, { checked, locked = false, na = false, disabled = false, reason = '' }) {
  const row = document.querySelector(`.tool[data-tool="${id}"]`);
  const box = document.getElementById('tool-' + id);
  if (!row || !box) return;
  box.checked = !!checked;
  box.disabled = !!disabled;
  row.classList.toggle('locked', !!locked);
  row.classList.toggle('na', !!na);
  if (reason) row.title = reason;
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
  syncToolRow('deep', {
    checked: box && box.checked, locked: !DEEP_AVAILABLE, disabled: !DEEP_AVAILABLE,
    reason: chk.title });
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
  syncToolRow('portscan', {
    checked: box && box.checked, disabled: locked,
    locked: !PORTSCAN_AVAILABLE, na: PORTSCAN_AVAILABLE && passiveOn,
    reason: chk.title });
}

/* The active vulnerability scanners (XSS, SQLi, Nuclei) send crafted requests to
   the target, so they cannot run in a passive scan · lock them while passive is on,
   mirroring the port-scan rule. */
const ACTIVE_SCANNERS = {
  xssChk:    ['optXss',    'Test discovered parameters for XSS (active)'],
  sqliChk:   ['optSqli',   'Test discovered parameters for SQL injection (active)'],
  nucleiChk: ['optNuclei', 'Run Nuclei with templates chosen from the detected stack (active)'],
};
function reflectActiveScanners() {
  const passive = document.getElementById('optPassive');
  const passiveOn = !!(passive && passive.checked);
  Object.entries(ACTIVE_SCANNERS).forEach(([chkId, [boxId, activeTitle]]) => {
    const chk = document.getElementById(chkId);
    const box = document.getElementById(boxId);
    if (!chk || !box) return;
    chk.classList.toggle('locked', passiveOn);
    if (passiveOn) box.checked = false;
    box.disabled = passiveOn;
    chk.title = passiveOn ? 'Active probe · turn off “passive” to use it' : activeTitle;
  });
}

/* The archive pass always has a path that works · the index over plain HTTP
   when the dedicated engine is not installed · so this toggle is never locked.
   Say which of the two it will use, since the engine is meaningfully wider. */
function reflectWayback() {
  const chk = document.getElementById('waybackChk');
  const box = document.getElementById('optWayback');
  if (!chk) return;
  chk.title = WAYBACK.engine
    ? 'Mine the web archive for URLs this domain used to serve · nothing is sent to the target'
    : 'Mine the web archive for URLs this domain used to serve (via the archive index · '
      + 'run ./install.sh to add the faster engine). Nothing is sent to the target.';
  syncToolRow('wayback', { checked: box && box.checked, reason: chk.title });
}

/* Lock, grey out, and label every non-mirror tool against what this machine can
   actually run and the scope in play. The three mirror tools (deep, port scan,
   web archive) are owned by their reflect* above; this handles the rest. */
function reflectTools() {
  const scope = currentScope();
  TOOLS.forEach(t => {
    if (t.kind === 'enable') return;              // mirror tools handled elsewhere
    const row = document.querySelector(`.tool[data-tool="${t.id}"]`);
    const box = document.getElementById('tool-' + t.id);
    if (!row || !box) return;
    let locked = false, na = false, reason = t.desc;
    if (t.avail && TOOLS_AVAIL[t.avail] === false) {
      locked = true;
      reason = `${t.tool} is not installed on this machine · run ./install.sh to add it`;
    } else if (t.noSingle && scope === 'single') {
      na = true;
      reason = 'No host enumeration runs in single-host mode';
    } else if (t.needs) {
      const dep = document.getElementById('tool-' + t.needs);
      if (dep && !dep.checked) {
        na = true;
        reason = `Runs inside the ${(TOOL_BY_ID[t.needs] || {}).name || t.needs} · turn that on first`;
      }
    }
    row.classList.toggle('locked', locked);
    row.classList.toggle('na', na);
    row.title = reason;
    const block = locked || na;
    box.disabled = block;
    if (block) box.checked = false;
  });
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
  // Scanner version this run was produced by (see modules.config.SCANNER_VERSION).
  if (s.version) meta.push(`<span class="ver" title="Scanner version">${esc(s.version)}</span>`);
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
  if (o.xss) tags.push('XSS');
  if (o.sqli) tags.push('SQLi');
  if (o.nuclei) tags.push('Nuclei');
  if (o.single) tags.push('single host');
  if (o.passive) tags.push('passive');
  if (o.deep) tags.push('deep DNS');
  if (o.exact_scope) tags.push('exact host');
  (o.off_tools || []).forEach(t => tags.push(t));
  (o.skipped || []).forEach(s => tags.push('no ' + (label[s] || s)));
  return tags.length
    ? `<span class="jopts">${tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</span>` : '';
}

/* A finished-but-failed or interrupted run carries a plain reason · show it as an
   inline alert on the row, not only buried in the terminal log. A run that
   completed with a tool failure gets the softer warning treatment. */
function jobAlert(j) {
  if ((j.status === 'failed' || j.status === 'interrupted') && j.error)
    return `<div class="job-alert err" role="alert">${icon('alert-triangle')}<span>${esc(j.error)}</span></div>`;
  if (j.status === 'done' && j.warning)
    return `<div class="job-alert warn" role="status">${icon('alert-triangle')}<span>${esc(j.warning)}</span></div>`;
  return '';
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
  const active = JOB_ACTIVE.includes(j.status);
  const stop = j.status === 'running' || j.status === 'queued'
    ? `<button class="btn sm ghost jstop" data-stop="${esc(j.id)}">${icon('x')} stop</button>` : '';
  // A finished run can be cleared from this list. It only forgets the job row and
  // its log · the saved scan it produced stays in the library, so this is never a
  // way to lose a result. Active runs must be stopped first, so no button here.
  const del = active ? ''
    : `<button class="btn sm ghost jdel" data-del-job="${esc(j.id)}"
         title="Remove from this list · the saved scan is kept"
         aria-label="Remove this job from the list">${icon('trash')}</button>`;
  return `<span class="jstate ${esc(j.status)}">${jobIndicator(j)} ${esc(j.status)}</span>`
    + (j.status === 'done' ? ' <a href="#" data-reload="1">view result</a>' : '')
    + stop
    + `<button class="btn sm ghost" data-toggle-log="${esc(j.id)}">${icon('terminal-2')} log</button>`
    + del;
}

function jobRowHtml(j) {
  const running = JOB_ACTIVE.includes(j.status);
  return `<div class="job ${running ? 'on' : ''}" data-job="${esc(j.id)}">
    <span class="jdom">${esc(j.domain)}</span>
    ${jobOpts(j)}
    <span class="jstat">${jobStatusHtml(j)}</span>
    <div class="jalert-slot" data-alert>${jobAlert(j)}</div>
    <div class="job-log ${openLogs.has(j.id) ? 'open' : ''}" id="log-${esc(j.id)}"></div>
  </div>`;
}

/* A Tor scan whose exit was blocked · the operator is told once, as a popup, so a
   thin result over Tor is never mistaken for a clean target. Shown per job id. */
const torPopupShown = new Set();
function maybeTorBlockedPopup(jobs) {
  for (const j of jobs) {
    if (j.tor_blocked && !torPopupShown.has(j.id)) {
      torPopupShown.add(j.id);
      showTorBlockedPopup(j);
    }
  }
}

function showTorBlockedPopup(j) {
  const scrim = h('div', { class: 'modal-scrim' });
  scrim.innerHTML = `<div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="tbTitle">
    <div class="modal-head">${icon('alert-triangle')}<h3 id="tbTitle">Tor exit nodes are being blocked</h3></div>
    <p class="modal-body">${esc(j.tor_blocked)}
      <br><span class="faint">Your address was not exposed · the scan stayed on Tor
      throughout. Results for ${esc(j.domain)} may be incomplete because the target
      refused the Tor exit. Re-running picks a fresh circuit, or scan without Tor if
      the target is known to block it.</span></p>
    <div class="modal-actions">
      <button class="btn primary" id="tbOk">Understood</button>
    </div>
  </div>`;
  document.body.appendChild(scrim);
  const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey); };
  function onKey(e) { if (e.key === 'Escape') close(); }
  scrim.querySelector('#tbOk').addEventListener('click', close);
  scrim.addEventListener('click', e => { if (e.target === scrim) close(); });
  document.addEventListener('keydown', onKey);
}

async function loadJobs() {
  const wrap = document.getElementById('jobsWrap');
  let jobs = [];
  try { jobs = await getJSON(withBase('/api/jobs')); } catch (e) { return; }
  maybeTorBlockedPopup(jobs);
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
      const slot = row.querySelector('[data-alert]');
      if (slot) {
        const alert = jobAlert(j);
        if (slot.dataset.html !== alert) { slot.innerHTML = alert; slot.dataset.html = alert; }
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
  root.querySelectorAll('[data-del-job]').forEach(b => {
    if (b._wired) return; b._wired = true;
    b.addEventListener('click', () => deleteJob(b.dataset.delJob, b));
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

/* Remove a finished job from the Running & recent list. Two steps · the first
   click arms the button ("remove?"), the second does it, so a stray click never
   clears a row. It forgets only the job record and its streamed log; the saved
   scan the run produced stays in the library, reachable from Recent Scans. */
async function deleteJob(id, btn) {
  if (btn.dataset.armed !== '1') {
    btn.dataset.armed = '1';
    btn.classList.add('confirm');
    btn.innerHTML = icon('trash') + '<span>remove?</span>';
    setTimeout(() => {
      if (!btn.isConnected || btn.dataset.armed !== '1') return;
      btn.dataset.armed = '';
      btn.classList.remove('confirm');
      btn.innerHTML = icon('trash');
    }, 3000);
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>';
  try {
    await sendJSON(withBase(`/api/jobs/${encodeURIComponent(id)}`), 'DELETE');
  } catch (e) {
    btn.disabled = false;
    btn.dataset.armed = '';
    btn.classList.remove('confirm');
    btn.innerHTML = icon('trash');
    formError(null, e.message);
    return;
  }
  openLogs.delete(id);
  const row = document.querySelector(`.job[data-job="${CSS.escape(id)}"]`);
  jobsSignature = '';            // force a rebuild so the window refills next poll
  if (row) {
    row.classList.add('removing');
    setTimeout(() => { row.remove(); loadJobs(); }, 180);
  } else {
    loadJobs();
  }
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
/* The engine no longer runs from a terminal, so every tool has to be reachable
   here. The common toggles stay in the bar; the full per-tool list lives one
   click away (grouped passive / active / processing), with a badge so a
   non-default setup is never invisible. */
function renderTools() {
  const rowHtml = (t) => {
    const on = t.kind !== 'enable';         // extras start off · everything else on
    return `<label class="tool" data-tool="${esc(t.id)}">
      <input type="checkbox" id="tool-${esc(t.id)}" data-tool-box="${esc(t.id)}"${on ? ' checked' : ''}>
      <span class="tool-body">
        <span class="tool-top"><span class="tool-name">${esc(t.name)}</span>
          <span class="tool-tool">${esc(t.tool)}</span></span>
        <span class="tool-desc">${esc(t.desc)}</span>
      </span>
    </label>`;
  };
  const fill = (elId, group) => {
    const wrap = document.getElementById(elId);
    if (wrap) wrap.innerHTML = TOOLS.filter(t => t.group === group).map(rowHtml).join('');
  };
  fill('toolsPassive', 'passive');
  fill('toolsActive', 'active');
  fill('toolsProcess', 'process');
}

/* A locked tool cannot run (not installed) · an N/A tool has no meaning under the
   current choices (BBOT in single-host mode, deep crawl when the crawler is off).
   Either way, a click explains why rather than silently doing nothing. */
function onToolClick(e) {
  const row = e.currentTarget;
  const t = TOOL_BY_ID[row.dataset.tool];
  if (!t) return;
  const locked = row.classList.contains('locked');
  const na = row.classList.contains('na');
  if (t.deep && locked) { e.preventDefault(); openKeyModal(); return; }
  if (locked || na) { e.preventDefault(); formError(null, row.title || 'this tool is not available'); }
}

/* A mirror tool (deep, port scan, web archive) writes back to its top-bar twin;
   every change re-checks the relations (turning the crawler off makes deep crawl
   N/A) and the options badge. */
function onToolChange(e) {
  const t = TOOL_BY_ID[e.target.dataset.toolBox];
  if (t && t.kind === 'enable' && t.mirror) {
    const top = document.getElementById(t.mirror);
    if (top) top.checked = e.target.checked;
    if (t.id === 'deep') reflectDeep();
    else if (t.id === 'portscan') reflectPortscan();
    else if (t.id === 'wayback') reflectWayback();
  }
  reflectTools();
  reflectOptionCount();
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
  reflectTools();       // single-host mode makes BBOT N/A (no enumeration runs)
}

function scanOptions() {
  const num = (id) => {
    const v = (document.getElementById(id).value || '').trim();
    const n = parseInt(v, 10);
    return v && Number.isFinite(n) && n > 0 ? n : null;
  };
  // a tool with no rendered box defaults to "on" · a stage that is skipped or a
  // --no-x flag both read off the tool's own checkbox
  const on = (id) => {
    const el = document.getElementById('tool-' + id);
    return el ? el.checked : true;
  };
  const STAGE_IDS = ['subdomain', 'fingerprint', 'crawl', 'bruteforce',
                     'ip_enrich', 'classify', 'graph'];
  const skip = STAGE_IDS.filter(id => !on(id));
  const scope = currentScope();
  return {
    passive: document.getElementById('optPassive').checked,
    deep: document.getElementById('optDeep').checked,
    tor: document.getElementById('optTor').checked,
    portscan: document.getElementById('optPortscan').checked,
    wayback: document.getElementById('optWayback').checked,
    xss: document.getElementById('optXss').checked,
    sqli: document.getElementById('optSqli').checked,
    nuclei: document.getElementById('optNuclei').checked,
    single: scope === 'single',
    exact_scope: scope === 'exact',
    no_bbot: !on('bbot'),
    no_probe: !on('probe'),
    no_deepcrawl: !on('deepcrawl'),
    max_pages: num('optMaxPages'),
    max_depth: num('optMaxDepth'),
    skip,
  };
}

/* how many advanced options differ from the defaults · consequences of a choice
   already counted elsewhere (BBOT off because scope is single) are not re-counted */
function countAdvanced(o) {
  let n = (o.exact_scope ? 1 : 0) + (o.single ? 1 : 0) +
    (o.max_pages ? 1 : 0) + (o.max_depth ? 1 : 0) + o.skip.length;
  if (o.no_bbot && !o.single) n += 1;
  if (o.no_probe) n += 1;
  if (o.no_deepcrawl && !o.skip.includes('crawl')) n += 1;
  return n;
}

function reflectOptionCount() {
  const badge = document.getElementById('optsCount');
  if (!badge) return;
  const n = countAdvanced(scanOptions());
  badge.hidden = n === 0;
  badge.textContent = n;
}

function wireOptions() {
  renderTools();
  reflectScope();
  document.querySelectorAll('[data-tool-box]').forEach(box =>
    box.addEventListener('change', onToolChange));
  document.querySelectorAll('.tool').forEach(row =>
    row.addEventListener('click', onToolClick));
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
  if (passiveBox) passiveBox.addEventListener('change', () => {
    reflectPortscan();
    reflectActiveScanners();
  });
  // The active scanners lock while passive is on · explain in place if clicked.
  Object.keys(ACTIVE_SCANNERS).forEach(chkId => {
    const chk = document.getElementById(chkId);
    if (chk) chk.addEventListener('click', e => {
      const box = document.getElementById(ACTIVE_SCANNERS[chkId][0]);
      if (box && box.disabled) { e.preventDefault(); formError(null, chk.title); }
    });
  });
  reflectActiveScanners();
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
