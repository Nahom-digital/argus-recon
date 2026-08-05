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
];

document.addEventListener('DOMContentLoaded', () => {
  wireTabs();
  wireUserModal();
  wirePasswordForm();
  wireAccessFilters();
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
    </div>
    <p class="form-msg intg-msg" role="alert" hidden></p>
  </div>`;
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
    if (d.quota_error) note = `Saved, but the key check failed: ${d.quota_error}`;
    else if (d.quota && d.quota.remaining != null) note = `Saved · ${fmtNum(d.quota.remaining)} deep-DNS lookups left.`;
    msg.textContent = note;
    msg.classList.add(d.quota_error ? 'err' : 'ok');
    msg.hidden = false;
    loadIntegrations();
  } catch (e) {
    msg.textContent = e.message || 'Could not save the key.';
    msg.classList.add('err'); msg.hidden = false;
  } finally { btn.disabled = false; }
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
  PERMS.forEach(([id, key]) => { document.getElementById(id).checked = !!l[key]; });
  document.getElementById('umSave').textContent = user ? 'Save changes' : 'Create account';
  document.getElementById('umMsg').hidden = true;
  document.getElementById('userModal').hidden = false;
  setTimeout(() => document.getElementById(user ? 'umDaily' : 'umUser').focus(), 30);
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

    try {
      if (EDITING) {
        await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(EDITING)}`),
          'POST', { role, limits });
        if (password)
          await sendJSON(withBase(`/api/admin/users/${encodeURIComponent(EDITING)}/password`),
            'POST', { new_password: password });
        toast(`${EDITING} updated`);
      } else {
        const name = document.getElementById('umUser').value.trim().toLowerCase();
        await sendJSON(withBase('/api/admin/users'), 'POST',
          { username: name, password, role, limits });
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
  ['umDaily', 'umConcurrent'].forEach(id => {
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
