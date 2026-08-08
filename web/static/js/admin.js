/* ============================================================================
   Argus Recon · administration
   Accounts, per-account scan allowances, access history, scan ownership.
   Every call here is admin-only server side (web/server.py · _require_admin),
   so this file is the interface to those routes, never the authority on them.
   ========================================================================== */
'use strict';

let USERS = [];
let DEFAULT_LIMITS = {};
let EDITING = null;                 // username being edited, or null = new

const PERMS = [
  ['umSeeAll', 'see_all'], ['umDelete', 'delete'], ['umPortscan', 'portscan'],
  ['umTor', 'tor'], ['umWayback', 'wayback'], ['umDeep', 'deep'],
  ['umXss', 'xss'], ['umSqli', 'sqli'], ['umNuclei', 'nuclei'],
];

document.addEventListener('DOMContentLoaded', () => {
  wireTabs();
  wireUserModal();
  wirePasswordForm();
  wireAccessFilters();
  const vr = document.getElementById('versionRefresh');
  if (vr) vr.addEventListener('click', loadVersion);
  loadOverview();
  loadUsers();
});

/* ---- tabs ----------------------------------------------------------------- */
function wireTabs() {
  document.querySelectorAll('.atab').forEach(btn => btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.atab').forEach(b => {
      const on = b === btn;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.atab-panel').forEach(p => {
      p.hidden = p.id !== 'tab-' + tab;
      p.classList.toggle('on', p.id === 'tab-' + tab);
    });
    if (tab === 'access') loadAccess();
    if (tab === 'scans') loadOverview();
    if (tab === 'integrations') loadIntegrations();
    if (tab === 'version') loadVersion();
  }));
}

/* ---- integrations (external API keys) ------------------------------------- */
async function loadIntegrations() {
  const host = document.getElementById('integrationList');
  if (!host) return;
  let d;
  try { d = await getJSON(withBase('/api/admin/integrations')); }
  catch (e) { host.innerHTML = `<div class="empty" style="padding:22px">${icon('alert-triangle')}<h4>Could not load integrations</h4></div>`; return; }
  const items = d.integrations || [];
  document.getElementById('integrationCount').textContent = items.length;
  host.innerHTML = `<div class="intg-rows">${items.map(intgRow).join('')}</div>`;
  host.querySelectorAll('.intg-save').forEach(btn =>
    btn.addEventListener('click', () => saveIntegration(btn.dataset.id)));
  host.querySelectorAll('.intg-test').forEach(btn =>
    btn.addEventListener('click', () => testIntegration(btn.dataset.id)));
  host.querySelectorAll('.intg-field .toggle-eye').forEach(btn =>
    btn.addEventListener('click', () => {
      const inp = btn.parentElement.querySelector('input');
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      btn.innerHTML = icon(show ? 'eye-off' : 'eye');
    }));
}

function intgRow(i) {
  const set = i.configured;
  return `<div class="intg-row" data-id="${esc(i.id)}">
    <div class="intg-info">
      <div class="intg-head">
        <span class="intg-name">${icon('api-app')}${esc(i.label)}</span>
        <span class="intg-status ${set ? 'on' : 'off'}">${icon(set ? 'circle-check-filled' : 'point-filled')}${set ? 'configured' : 'not set'}</span>
        <span class="intg-unlocks tag">${esc(i.unlocks)}</span>
      </div>
      <p class="intg-desc">${esc(i.desc)}${i.get_url ? ` <a href="${esc(i.get_url)}" target="_blank" rel="noopener">get a key ${icon('external-link')}</a>` : ''}</p>
    </div>
    <div class="intg-set">
      <div class="intg-field">
        <input class="input" type="password" id="intg-${esc(i.id)}" spellcheck="false"
               autocomplete="off" autocapitalize="none"
               placeholder="${set ? 'saved · enter a new key to replace' : 'paste the API key'}">
        <button class="toggle-eye" type="button" title="Show or hide" aria-label="Show or hide">${icon('eye')}</button>
      </div>
      <button class="btn primary sm intg-save" data-id="${esc(i.id)}">${icon('key')}Save</button>
      ${['shodan', 'securitytrails'].includes(i.id)
        ? `<button class="btn sm intg-test" data-id="${esc(i.id)}" title="Test the connection">${icon('refresh')}Test</button>`
        : ''}
    </div>
    <p class="form-msg intg-msg" role="alert" hidden></p>
  </div>`;
}

function intgTestNote(d) {
  if (d.shodan) {
    const s = d.shodan;
    if (s.mode === 'internetdb') return { ok: true, text: s.detail || 'No key · using the free InternetDB.' };
    if (s.ok) return { ok: true, text: `Connected · plan ${s.plan || 'n/a'}, ${fmtNum(s.query_credits || 0)} query credits.` };
    return { ok: false, text: `Shodan test failed: ${s.error || 'unknown error'}` };
  }
  if (d.quota) return { ok: true, text: `Connected · ${fmtNum(d.quota.remaining ?? 0)} deep-DNS lookups left.` };
  if (d.error) return { ok: false, text: d.error };
  return { ok: true, text: 'Connected.' };
}

async function saveIntegration(id) {
  const row = document.querySelector(`.intg-row[data-id="${CSS.escape(id)}"]`);
  if (!row) return;
  const input = row.querySelector('input');
  const msg = row.querySelector('.intg-msg');
  const btn = row.querySelector('.intg-save');
  const value = input.value;
  btn.disabled = true;
  msg.hidden = true; msg.classList.remove('ok', 'err');
  try {
    const d = await sendJSON(withBase('/api/admin/integrations/' + encodeURIComponent(id)), 'POST', { value });
    input.value = '';
    let note = value.trim() ? 'Saved.' : 'Cleared.';
    let bad = false;
    if (d.quota_error) { note = `Saved, but the key check failed: ${d.quota_error}`; bad = true; }
    else if (d.shodan_error) { note = `Saved, but the connection test failed: ${d.shodan_error}`; bad = true; }
    else if (d.shodan || d.quota) { const t = intgTestNote(d); note = `Saved · ${t.text}`; bad = !t.ok; }
    msg.textContent = note;
    msg.classList.add(bad ? 'err' : 'ok');
    msg.hidden = false;
    loadIntegrations();
  } catch (e) {
    msg.textContent = e.message || 'Could not save the key.';
    msg.classList.add('err'); msg.hidden = false;
  } finally { btn.disabled = false; }
}

async function testIntegration(id) {
  const row = document.querySelector(`.intg-row[data-id="${CSS.escape(id)}"]`);
  if (!row) return;
  const msg = row.querySelector('.intg-msg');
  const btn = row.querySelector('.intg-test');
  btn.disabled = true;
  msg.hidden = true; msg.classList.remove('ok', 'err');
  try {
    const d = await getJSON(withBase(`/api/admin/integrations/${encodeURIComponent(id)}/test`));
    const t = intgTestNote(d);
    msg.textContent = t.text;
    msg.classList.add(t.ok ? 'ok' : 'err');
    msg.hidden = false;
  } catch (e) {
    msg.textContent = e.message || 'Connection test failed.';
    msg.classList.add('err'); msg.hidden = false;
  } finally { btn.disabled = false; }
}

/* ---- version management (view + downgrade) -------------------------------- */
let VERSION_POLL = null;

async function loadVersion() {
  const cur = document.getElementById('versionCurrent');
  const body = document.getElementById('versionBody');
  if (!cur || !body) return;
  cur.textContent = 'Loading…';
  let d;
  try { d = await getJSON(withBase('/api/admin/version')); }
  catch (e) {
    cur.innerHTML = `<span class="err">Could not read version info: ${esc(e.message || '')}</span>`;
    return;
  }
  const c = d.current || {};
  cur.innerHTML = `<span class="ver-badge">${esc(c.version || '?')}</span>
    <span class="ver-commit mono">${esc(c.commit || '')}</span>
    <span class="faint">${esc(c.branch || '')}${c.subject ? ' · ' + esc(c.subject) : ''}</span>`;
  const rows = [];
  (d.tags || []).forEach(t => rows.push(verRow(t.ref, t.date, t.subject, t.ref, true)));
  (d.commits || []).forEach(cm => rows.push(
    verRow(cm.short, (cm.date || '').slice(0, 10), cm.subject, cm.commit, false, cm.current)));
  body.innerHTML = rows.join('') ||
    `<tr><td colspan="4" class="faint" style="padding:14px">No other versions found on GitHub.</td></tr>`;
  body.querySelectorAll('.ver-go').forEach(btn =>
    btn.addEventListener('click', () => downgrade(btn.dataset.ref, btn.dataset.label)));
  loadVersionStatus();
  loadVersionHistory();
}

function verRow(label, date, subject, ref, isTag, isCurrent) {
  return `<tr>
    <td>${isTag ? icon('tag') : ''}<span class="mono">${esc(label)}</span>${
      isCurrent ? ' <span class="tag">current</span>' : ''}</td>
    <td class="faint">${esc(date || '')}</td>
    <td class="truncate" title="${esc(subject || '')}">${esc(subject || '')}</td>
    <td>${isCurrent ? '' :
      `<button class="btn sm ver-go" data-ref="${esc(ref)}" data-label="${esc(label)}"
        title="Downgrade to this version">${icon('download')} use</button>`}</td>
  </tr>`;
}

async function downgrade(ref, label) {
  if (!confirm(`Downgrade the dashboard to ${label}?\n\nThe current version is backed `
    + `up first and restored automatically if anything fails. The dashboard will `
    + `restart, so it may be briefly unavailable.`)) return;
  const box = document.getElementById('versionStatus');
  box.hidden = false;
  box.className = 'ver-status running';
  box.textContent = `Starting downgrade to ${label}…`;
  try {
    await sendJSON(withBase('/api/admin/version/downgrade'), 'POST', { target: ref });
  } catch (e) {
    box.className = 'ver-status err';
    box.textContent = e.message || 'Could not start the downgrade.';
    return;
  }
  // Poll status · the service will restart under us, so tolerate fetch failures.
  if (VERSION_POLL) clearInterval(VERSION_POLL);
  VERSION_POLL = setInterval(loadVersionStatus, 3000);
}

async function loadVersionStatus() {
  const box = document.getElementById('versionStatus');
  if (!box) return;
  let d;
  try { d = await getJSON(withBase('/api/admin/version/status')); }
  catch (e) { return; }   // server may be mid-restart · keep polling
  const st = d.status || {};
  if (!st.status || st.status === 'idle') { if (!VERSION_POLL) box.hidden = true; return; }
  box.hidden = false;
  const map = {
    starting: ['running', 'Preparing downgrade…'],
    running: ['running', 'Downgrade in progress · backing up, checking out, verifying…'],
    success: ['ok', `Downgraded to ${st.target || ''} (was ${st.previous || ''}). Backup: ${st.backup || 'n/a'}.`],
    rolled_back: ['err', `Downgrade failed and was rolled back: ${st.error || ''}. The dashboard is back on its previous version.`],
    failed: ['err', `Downgrade failed: ${st.error || ''}.`],
  };
  const [cls, text] = map[st.status] || ['running', st.status];
  box.className = 'ver-status ' + cls;
  box.textContent = text;
  if (st.status === 'success' || st.status === 'rolled_back' || st.status === 'failed') {
    if (VERSION_POLL) { clearInterval(VERSION_POLL); VERSION_POLL = null; }
    loadVersionHistory();
  }
}

async function loadVersionHistory() {
  const host = document.getElementById('versionHistory');
  if (!host) return;
  let d;
  try { d = await getJSON(withBase('/api/admin/version/status')); }
  catch (e) { return; }
  const h = d.history || [];
  if (!h.length) { host.innerHTML = `<p class="faint" style="padding:10px 2px">No downgrades recorded.</p>`; return; }
  host.innerHTML = `<div class="atable-wrap"><table class="atable"><thead><tr>
    <th>When</th><th>User</th><th>From</th><th>To</th><th>Status</th></tr></thead><tbody>${
    h.map(e => `<tr>
      <td class="faint">${esc((e.time || '').replace('T', ' ').slice(0, 19))}</td>
      <td>${esc(e.user || '?')}</td>
      <td class="mono faint">${esc(e.previous_commit || e.previous_version || '')}</td>
      <td class="mono">${esc(e.target || '')}</td>
      <td>${esc(e.status || '')}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

/* ---- overview ------------------------------------------------------------- */
async function loadOverview() {
  let d;
  try { d = await getJSON(withBase('/api/admin/overview')); }
  catch (e) { return; }

  const stat = (n, l) => `<div class="astat"><div class="n">${fmtNum(n)}</div><div class="l">${esc(l)}</div></div>`;
  document.getElementById('adminStats').innerHTML =
    stat(d.users, 'accounts') + stat(d.scans, 'scans') +
    stat((d.running || []).length, 'running');
  const kf = document.getElementById('keyFilePath');
  if (kf && d.key_file) kf.textContent = d.key_file;

  // scans per owner
  const owners = Object.entries(d.scans_by_owner || {})
    .sort((a, b) => b[1] - a[1]);
  document.getElementById('scanOwners').innerHTML = owners.length
    ? `<div class="owner-rows">${owners.map(([who, n]) => `
        <div class="owner-row">
          <span class="who-name">${icon('point-filled')}
            ${esc(who === 'unassigned' ? 'before accounts existed' : who)}</span>
          <span class="owner-bar"><span style="width:${Math.round(100 * n / owners[0][1])}%"></span></span>
          <span class="mono">${fmtNum(n)}</span>
        </div>`).join('')}</div>`
    : `<div class="empty" style="padding:26px">${icon('radar-2')}<h4>No scans yet</h4></div>`;

  // recent scans, with who ran them
  const recent = d.recent_scans || [];
  if (recent.length) {
    document.getElementById('scanOwners').insertAdjacentHTML('beforeend', `
      <div class="atable-wrap"><table class="atable"><thead><tr>
        <th>Domain</th><th>Account</th><th>Started</th><th>Size</th><th></th>
      </tr></thead><tbody>${recent.map(s => `<tr>
        <td class="mono">${esc(s.domain)}</td>
        <td>${s.owner ? `<span class="tag">${esc(s.owner)}</span>`
          : '<span class="faint">unassigned</span>'}</td>
        <td class="faint">${esc(timeAgo(s.started_at))}</td>
        <td class="mono faint">${esc(fmtBytes(s.size))}</td>
        <td><a class="btn sm ghost" href="${withBase('/scan/' + encodeURIComponent(s.scan_id))}">open</a></td>
      </tr>`).join('')}</tbody></table></div>`);
  }

  const running = d.running || [];
  document.getElementById('runningScans').innerHTML = running.length
    ? `<div class="atable-wrap"><table class="atable"><thead><tr>
        <th>Domain</th><th>Account</th><th>Status</th><th>Started</th>
      </tr></thead><tbody>${running.map(j => `<tr>
        <td class="mono">${esc(j.domain)}</td>
        <td>${j.owner ? esc(j.owner) : '<span class="faint">·</span>'}</td>
        <td><span class="tag">${esc(j.status)}</span></td>
        <td class="faint">${esc(j.started ? timeAgo(new Date(j.started * 1000).toISOString()) : '')}</td>
      </tr>`).join('')}</tbody></table></div>`
    : `<div class="empty" style="padding:26px">${icon('clock')}<h4>Nothing running</h4>
       <p>Scans started from the dashboard show up here while they run.</p></div>`;
}

/* ---- accounts ------------------------------------------------------------- */
async function loadUsers() {
  const list = document.getElementById('userList');
  try {
    const d = await getJSON(withBase('/api/admin/users'));
    USERS = d.users || [];
    DEFAULT_LIMITS = d.defaults || {};
  } catch (e) {
    list.innerHTML = `<div class="empty" style="padding:30px">${icon('alert-triangle')}
      <h4>Could not load accounts</h4><p>${esc(e.message)}</p></div>`;
    return;
  }
  document.getElementById('userCount').textContent = fmtNum(USERS.length);
  list.innerHTML = `<div class="user-rows">${USERS.map(userRow).join('')}</div>`;
  wireUserRows();
}

function permChips(u) {
  const l = u.limits || {};
  const chips = [];
  if (l.see_all) chips.push('sees all scans');
  if (l.delete) chips.push('can delete');
  if (l.portscan) chips.push('port scan');
  if (l.tor) chips.push('Tor');
  if (l.wayback) chips.push('web archive');
  if (l.deep) chips.push('deep DNS');
  return chips.map(c => `<span class="tag">${esc(c)}</span>`).join('');
}

function userRow(u) {
  const l = u.limits || {};
  const daily = l.daily_scans ? `${u.scans_today}/${l.daily_scans} today` : 'unlimited';
  const conc = l.concurrent ? `${l.concurrent} at once` : 'no concurrency limit';
  return `<div class="user-row${u.enabled ? '' : ' off'}" data-user="${esc(u.username)}">
    <div class="u-id">
      <div class="u-name">
        ${icon(u.role === 'admin' ? 'shield-half-filled' : 'point-filled')}
        <b>${esc(u.username)}</b>
        <span class="u-role ${esc(u.role)}">${esc(u.role === 'admin' ? 'administrator' : 'operator')}</span>
        ${u.enabled ? '' : '<span class="tag u-off">disabled</span>'}
        ${u.locked ? '<span class="tag u-locked">locked out</span>' : ''}
      </div>
      <div class="u-meta">
        <span>${esc(daily)}</span><span class="faint">·</span><span>${esc(conc)}</span>
        <span class="faint">·</span><span>${fmtNum(u.total_scans)} scans total</span>
        ${u.last_login ? `<span class="faint">·</span><span>last in ${esc(timeAgo(u.last_login))}</span>`
          : '<span class="faint">·</span><span class="faint">never signed in</span>'}
      </div>
      <div class="u-perms">${permChips(u)}</div>
    </div>
    <div class="u-actions">
      ${u.locked ? `<button class="btn sm" data-unlock="${esc(u.username)}"
          title="Clear the failed-sign-in lockout">${icon('lock')} unlock</button>` : ''}
      <button class="btn sm" data-toggle="${esc(u.username)}">
        ${icon(u.enabled ? 'eye-off' : 'eye')} ${u.enabled ? 'disable' : 'enable'}</button>
      <button class="btn sm" data-pw="${esc(u.username)}">${icon('key')} password</button>
      <button class="btn sm" data-edit="${esc(u.username)}">${icon('settings')} edit</button>
      <button class="btn sm ghost u-del" data-del="${esc(u.username)}"
        title="Delete this account">${icon('trash')}</button>
    </div>
  </div>`;
}

function wireUserRows() {
  const on = (attr, fn) => document.querySelectorAll(`[data-${attr}]`).forEach(b =>
    b.addEventListener('click', () => fn(b.getAttribute('data-' + attr), b)));

  on('edit', (name) => openUserModal(USERS.find(u => u.username === name)));
  on('unlock', (name) => patchUser(name, { unlock: true }));
  on('toggle', (name) => {
    const u = USERS.find(x => x.username === name);
    patchUser(name, { enabled: !u.enabled });
  });
  on('pw', (name) => resetPassword(name));
  on('del', (name, btn) => deleteUser(name, btn));
}

async function patchUser(name, body) {
  try {
    await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(name)}`), 'POST', body);
    await loadUsers();
  } catch (e) { toast(e.message, true); }
}

async function resetPassword(name) {
  const pw = prompt(`New password for "${name}" (at least 8 characters).\n\n`
    + 'They stay signed out of every existing session until they use it.');
  if (pw === null) return;
  try {
    await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(name)}/password`),
      'POST', { new_password: pw });
    toast(`password changed for ${name}`);
    loadUsers();
  } catch (e) { toast(e.message, true); }
}

async function deleteUser(name, btn) {
  const row = btn.closest('.user-row');
  if (!row.classList.contains('confirm')) {
    row.classList.add('confirm');
    btn.innerHTML = icon('trash') + ' confirm';
    setTimeout(() => {
      row.classList.remove('confirm');
      btn.innerHTML = icon('trash');
    }, 3500);
    return;
  }
  try {
    await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(name)}`), 'DELETE');
    toast(`${name} removed`);
    loadUsers();
    loadOverview();
  } catch (e) { toast(e.message, true); }
}

/* ---- new / edit account modal --------------------------------------------- */
function openUserModal(user) {
  EDITING = user ? user.username : null;
  const l = (user && user.limits) || DEFAULT_LIMITS || {};
  document.getElementById('umTitle').textContent = user ? `Edit ${user.username}` : 'New account';
  document.getElementById('umUser').value = user ? user.username : '';
  document.getElementById('umUser').disabled = !!user;
  document.getElementById('umPass').value = '';
  document.getElementById('umPass').required = !user;
  document.getElementById('umPassLabel').textContent = user
    ? 'Password (leave blank to keep)' : 'Password';
  document.getElementById('umRole').value = user ? user.role : 'user';
  document.getElementById('umDaily').value = l.daily_scans != null ? l.daily_scans : 10;
  document.getElementById('umConcurrent').value = l.concurrent != null ? l.concurrent : 1;
  const credits = user && user.credits != null ? user.credits : 0;
  const cr = document.getElementById('umCredits');
  cr.value = credits; cr.dataset.current = credits;
  PERMS.forEach(([id, key]) => { document.getElementById(id).checked = !!l[key]; });
  document.getElementById('umSave').textContent = user ? 'Save changes' : 'Create account';
  document.getElementById('umMsg').hidden = true;
  // View-this-account's-assets · only meaningful for an existing account.
  const assets = document.getElementById('umAssets');
  assets.hidden = !user; assets.innerHTML = '';
  if (user) {
    assets.innerHTML = `<button class="btn sm" type="button" id="umViewAssets">`
      + `${icon('radar-2')} View ${esc(user.username)}'s scans & findings</button>`
      + `<div id="umAssetsBody"></div>`;
    document.getElementById('umViewAssets').addEventListener('click',
      () => loadUserAssets(user.username));
  }
  document.getElementById('userModal').hidden = false;
  setTimeout(() => document.getElementById(user ? 'umDaily' : 'umUser').focus(), 30);
}

async function loadUserAssets(username) {
  const body = document.getElementById('umAssetsBody');
  if (!body) return;
  body.innerHTML = `<p class="faint" style="padding:8px 0">Loading…</p>`;
  let d;
  try { d = await getJSON(withBase(`/api/admin/user/${encodeURIComponent(username)}/assets`)); }
  catch (e) { body.innerHTML = `<p class="form-msg err" style="display:block">${esc(e.message || 'Could not load assets.')}</p>`; return; }
  const sev = d.findings_by_severity || {};
  const q = d.quota || {};
  const domains = d.domains || [];
  const sevTags = ['critical', 'high', 'medium', 'low', 'info']
    .filter(s => sev[s]).map(s => `<span class="tag">${s}: ${fmtNum(sev[s])}</span>`).join('');
  body.innerHTML = `
    <div class="um-assets-stats">
      <span>${fmtNum(d.scan_count || 0)} scans</span>
      <span>${fmtNum(d.findings_total || 0)} findings</span>
      <span>${fmtNum(domains.length)} domains</span>
      ${q.daily_scans != null
        ? `<span>${q.remaining == null ? '∞' : fmtNum(q.remaining)} scans left today${q.credits ? ` (+${fmtNum(q.credits)} credits)` : ''}</span>`
        : ''}
    </div>
    <div class="um-tags">${sevTags || '<span class="faint">no findings</span>'}</div>
    <div class="um-tags">${domains.slice(0, 24).map(([dom, n]) =>
      `<span class="tag">${esc(dom)} · ${fmtNum(n)}</span>`).join('') || ''}</div>
    <div class="atable-wrap"><table class="atable"><thead><tr>
      <th>Scan</th><th>Findings</th><th>Version</th><th>When</th></tr></thead><tbody>${
      (d.scans || []).slice(0, 60).map(s => `<tr>
        <td><a href="${withBase('/scan/' + encodeURIComponent(s.scan_id))}">${esc(s.domain)}</a></td>
        <td>${fmtNum((s.stats || {}).findings || 0)}</td>
        <td class="mono faint">${esc(s.version || '')}</td>
        <td class="faint">${esc((s.started_at || '').replace('T', ' ').slice(0, 16))}</td>
      </tr>`).join('') || '<tr><td colspan="4" class="faint">no scans</td></tr>'}</tbody></table></div>`;
}

function closeUserModal() { document.getElementById('userModal').hidden = true; }

function wireUserModal() {
  document.getElementById('newUserBtn').addEventListener('click', () => openUserModal(null));
  document.getElementById('umCancel').addEventListener('click', closeUserModal);
  document.getElementById('userModal').addEventListener('click', e => {
    if (e.target.id === 'userModal') closeUserModal();
  });
  // The role picker drives what the permission boxes even mean: an admin has
  // every permission by definition, so show that rather than letting someone
  // untick a box that the server will ignore.
  document.getElementById('umRole').addEventListener('change', reflectRole);

  document.getElementById('userForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = document.getElementById('umMsg');
    const save = document.getElementById('umSave');
    msg.hidden = true;
    save.disabled = true;

    const num = id => {
      const n = parseInt(document.getElementById(id).value, 10);
      return Number.isFinite(n) && n >= 0 ? n : 0;
    };
    const limits = { daily_scans: num('umDaily'), concurrent: num('umConcurrent') };
    PERMS.forEach(([id, key]) => { limits[key] = document.getElementById(id).checked; });
    const role = document.getElementById('umRole').value;
    const password = document.getElementById('umPass').value;

    const wantCredits = num('umCredits');
    try {
      if (EDITING) {
        await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(EDITING)}`),
          'POST', { role, limits });
        if (password)
          await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(EDITING)}/password`),
            'POST', { new_password: password });
        // Credits are a running balance · grant the delta to reach the entered total.
        const curCredits = parseInt(document.getElementById('umCredits').dataset.current || '0', 10) || 0;
        if (wantCredits !== curCredits)
          await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(EDITING)}/credits`),
            'POST', { credits: wantCredits - curCredits });
        toast(`${EDITING} updated`);
      } else {
        const name = document.getElementById('umUser').value.trim().toLowerCase();
        await sendJSON(withBase('/api/admin/users'), 'POST',
          { username: name, password, role, limits });
        if (wantCredits > 0)
          await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(name)}/credits`),
            'POST', { credits: wantCredits });
        toast(`${name} created`);
      }
      closeUserModal();
      loadUsers();
      loadOverview();
    } catch (err) {
      msg.textContent = err.message;
      msg.hidden = false;
    } finally {
      save.disabled = false;
    }
  });
  reflectRole();
}

function reflectRole() {
  const admin = document.getElementById('umRole').value === 'admin';
  const fs = document.querySelector('.um-perms');
  fs.classList.toggle('na', admin);
  fs.title = admin ? 'An administrator has every permission and no scan limit' : '';
  PERMS.forEach(([id]) => {
    const box = document.getElementById(id);
    box.disabled = admin;
    if (admin) box.checked = true;
  });
  ['umDaily', 'umConcurrent', 'umCredits'].forEach(id => {
    const el = document.getElementById(id);
    el.disabled = admin;
    if (admin) el.value = 0;
  });
}

/* ---- access history ------------------------------------------------------- */
async function loadAccess() {
  const body = document.getElementById('accessBody');
  body.innerHTML = `<tr><td colspan="8" class="faint" style="padding:14px">loading…</td></tr>`;
  const params = new URLSearchParams();
  const day = document.getElementById('accessDay').value;
  const who = document.getElementById('accessUser').value;
  const q = document.getElementById('accessQ').value.trim();
  if (day) params.set('day', day);
  if (who) params.set('user', who);
  if (q) params.set('q', q);
  params.set('limit', '400');

  let d;
  try { d = await getJSON(withBase('/api/admin/access?' + params.toString())); }
  catch (e) {
    body.innerHTML = `<tr><td colspan="8" class="faint" style="padding:14px">${esc(e.message)}</td></tr>`;
    return;
  }

  fillOptions('accessDay', d.days || [], 'all days', day);
  const users = Object.keys((d.summary || {}).per_user || {}).sort();
  fillOptions('accessUser', users, 'all accounts', who);

  const per = (d.summary || {}).per_user || {};
  document.getElementById('accessUsers').innerHTML = Object.entries(per)
    .sort((a, b) => b[1] - a[1])
    .map(([u, n]) => `<button class="tag au-chip${u === who ? ' on' : ''}" data-au="${esc(u)}">
      ${esc(u)} <b>${fmtNum(n)}</b></button>`).join('');
  document.querySelectorAll('[data-au]').forEach(b => b.addEventListener('click', () => {
    const v = b.getAttribute('data-au');
    const sel = document.getElementById('accessUser');
    sel.value = sel.value === v ? '' : v;      // clicking the active chip clears it
    loadAccess();
  }));

  const rows = d.records || [];
  document.getElementById('accessCount').textContent = fmtNum(rows.length);
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="8" class="faint" style="padding:14px">${
      d.enabled ? 'nothing matches those filters' :
        'the access log is switched off (ARGUS_ACCESS_LOG=0)'}</td></tr>`;
    return;
  }
  // Group the flat log into sessions · one account, one browser, one sitting ·
  // each a collapsible header with its requests folded away underneath.
  const sessions = groupSessions(rows);
  body.innerHTML = sessions.map((s, i) =>
    sessionHeadHtml(s, i) + s.rows.map(r => accessRowHtml(r, i)).join('')).join('');
  reflectExpandAll();
}

/* A session is consecutive activity by one account from one browser. Records come
   newest-first; a gap longer than SESSION_GAP starts a fresh session. Grouping on
   account + user-agent (not IP) keeps one sitting together even when a CDN spreads
   it across a couple of edge addresses. */
const SESSION_GAP_MS = 30 * 60 * 1000;

function groupSessions(rows) {
  const openByKey = new Map();
  const sessions = [];
  for (const r of rows) {                    // newest-first
    const key = (r.user || 'anonymous') + '\n' + (r.ua || '');
    const t = Date.parse(r.ts || '') || 0;
    const s = openByKey.get(key);
    if (s && (s.startT - t) <= SESSION_GAP_MS) {
      s.rows.push(r);
      s.startT = Math.min(s.startT, t);
    } else {
      const ns = { user: r.user || '', ua: r.ua || '', rows: [r], startT: t };
      openByKey.set(key, ns);
      sessions.push(ns);
    }
  }
  return sessions;
}

function sessionHeadHtml(s, i) {
  const ipCounts = {};
  s.rows.forEach(r => { const ip = r.ip || '?'; ipCounts[ip] = (ipCounts[ip] || 0) + 1; });
  const ips = Object.keys(ipCounts).sort((a, b) => ipCounts[b] - ipCounts[a]);
  const ipLabel = esc(ips[0]) + (ips.length > 1 ? ` <span class="faint">+${ips.length - 1}</span>` : '');
  const errs = s.rows.filter(r => r.status && r.status >= 400).length;
  const endTs = s.rows[0].ts, startTs = s.rows[s.rows.length - 1].ts;
  const range = esc(shortTime(startTs)) + (startTs !== endTs ? ' <span class="faint">to</span> ' + esc(shortTime(endTs)) : '');
  const n = s.rows.length;
  return `<tr class="asess-head" data-sess="${i}" tabindex="0" role="button" aria-expanded="false">
    <td colspan="8">
      <div class="asess-sum">
        <svg class="ic chev"><use href="#i-chevron-right"></use></svg>
        <span class="asess-when mono">${range}</span>
        <span class="asess-who">${s.user ? `<span class="tag">${esc(s.user)}</span>`
          : '<span class="faint">anonymous</span>'}</span>
        <span class="asess-ip mono">${ipLabel}</span>
        <span class="asess-ua faint" title="${esc(s.ua)}">${esc(shortAgent(s.ua))}</span>
        <span class="asess-spacer"></span>
        ${errs ? `<span class="asess-errs">${errs} error${errs > 1 ? 's' : ''}</span>` : ''}
        <span class="asess-count">${fmtNum(n)} request${n > 1 ? 's' : ''}</span>
      </div>
    </td>
  </tr>`;
}

function accessRowHtml(r, i) {
  return `<tr class="arow" data-parent="${i}" hidden>
    <td class="mono nowrap">${esc(shortTime(r.ts))}</td>
    <td>${r.user ? `<span class="tag">${esc(r.user)}</span>`
      : '<span class="faint">anonymous</span>'}</td>
    <td class="mono">${esc(r.ip || '')}</td>
    <td><span class="method ${esc(r.method || 'GET')}">${esc(r.method || '')}</span></td>
    <td class="mono wrap">${esc(r.path || '')}${r.query ? `<span class="faint">?${esc(String(r.query).slice(0, 90))}</span>` : ''}</td>
    <td class="mono ${statusClass(r.status)}">${esc(r.status == null ? '·' : r.status)}</td>
    <td class="mono faint">${r.ms != null ? esc(Math.round(r.ms) + 'ms') : ''}</td>
    <td class="faint agent" title="${esc(r.ua || '')}">${esc(shortAgent(r.ua))}</td>
  </tr>`;
}

/* open / close one session's requests */
function toggleSession(head, force) {
  const i = head.dataset.sess;
  const open = force == null ? !head.classList.contains('open') : force;
  head.classList.toggle('open', open);
  head.setAttribute('aria-expanded', String(open));
  document.querySelectorAll(`#accessBody .arow[data-parent="${i}"]`)
    .forEach(r => { r.hidden = !open; });
}

let accessAllOpen = false;
function reflectExpandAll() {
  const btn = document.getElementById('accessExpand');
  if (btn) btn.textContent = accessAllOpen ? 'collapse all' : 'expand all';
}

function fillOptions(id, values, allLabel, current) {
  const sel = document.getElementById(id);
  if (!sel) return;
  const want = current || '';
  sel.innerHTML = `<option value="">${esc(allLabel)}</option>`
    + values.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
  sel.value = want;
}

function wireAccessFilters() {
  ['accessDay', 'accessUser'].forEach(id =>
    document.getElementById(id).addEventListener('change', loadAccess));
  document.getElementById('accessRefresh').addEventListener('click', loadAccess);
  let t;
  document.getElementById('accessQ').addEventListener('input', () => {
    clearTimeout(t); t = setTimeout(loadAccess, 220);
  });
  // one delegated handler · the body is re-rendered on every load
  const body = document.getElementById('accessBody');
  body.addEventListener('click', e => {
    const head = e.target.closest('.asess-head');
    if (head) toggleSession(head);
  });
  body.addEventListener('keydown', e => {
    const head = e.target.closest && e.target.closest('.asess-head');
    if (head && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggleSession(head); }
  });
  const expand = document.getElementById('accessExpand');
  if (expand) expand.addEventListener('click', () => {
    accessAllOpen = !accessAllOpen;
    document.querySelectorAll('#accessBody .asess-head')
      .forEach(h => toggleSession(h, accessAllOpen));
    reflectExpandAll();
  });
}

function shortTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString([], { month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/* The full UA string is 150 characters of build metadata; the browser name is
   what a human is actually scanning the column for. Full text stays in the
   title attribute. */
function shortAgent(ua) {
  ua = String(ua || '');
  if (!ua) return '';
  if (/curl\//i.test(ua)) return 'curl';
  if (/python-requests|httpx|urllib/i.test(ua)) return 'script';
  if (/ArgusRecon/i.test(ua)) return 'argus';
  const m = ua.match(/(Firefox|Edg|OPR|Chrome|Safari)\/[\d.]+/);
  const os = /Android/i.test(ua) ? 'Android' : /iPhone|iPad/i.test(ua) ? 'iOS'
    : /Windows/i.test(ua) ? 'Windows' : /Mac OS/i.test(ua) ? 'macOS'
      : /Linux/i.test(ua) ? 'Linux' : '';
  const name = m ? m[1].replace('Edg', 'Edge').replace('OPR', 'Opera') : 'other';
  return os ? `${name} · ${os}` : name;
}

/* ---- my password ---------------------------------------------------------- */
function wirePasswordForm() {
  const form = document.getElementById('pwForm');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = document.getElementById('pwMsg');
    const btn = document.getElementById('pwSave');
    const next = document.getElementById('pwNew').value;
    msg.hidden = true;
    if (next !== document.getElementById('pwRepeat').value) {
      msg.textContent = 'the two new passwords do not match';
      msg.hidden = false;
      return;
    }
    btn.disabled = true;
    try {
      const d = await sendJSON(withBase('/api/me/password'), 'POST', {
        current_password: document.getElementById('pwCurrent').value,
        new_password: next,
      });
      if (d && d.csrf) AUTH.csrf = d.csrf;     // the old token was just retired
      form.reset();
      msg.textContent = 'password changed · other sessions have been signed out';
      msg.classList.add('ok');
      msg.hidden = false;
    } catch (err) {
      msg.classList.remove('ok');
      msg.textContent = err.message;
      msg.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });
}

/* ---- toast ---------------------------------------------------------------- */
function toast(text, bad) {
  let el = document.getElementById('adminToast');
  if (!el) {
    el = h('div', { class: 'admin-toast', id: 'adminToast' });
    document.body.appendChild(el);
  }
  el.className = 'admin-toast show' + (bad ? ' bad' : '');
  el.innerHTML = `${icon(bad ? 'alert-triangle' : 'circle-check-filled')} ${esc(text)}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 3400);
}
