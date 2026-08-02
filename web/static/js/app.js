/* ============================================================================
   Argus Recon · shared client helpers
   ========================================================================== */
'use strict';

/* icon(name) -> inline SVG referencing the sprite injected into the page */
function icon(name, cls) {
  return `<svg class="ic ${cls || ''}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
}

/* withBase(path) -> path rewritten for wherever the app is mounted. A proxy can
   serve the dashboard under a prefix (nginx: /scanner/ -> 127.0.0.1:7666), which
   Flask learns from X-Forwarded-Prefix and hands back as request.script_root on
   <body data-base>. Root-absolute '/api/…' would leave the app and 404, so every
   fetch and every generated link goes through here. Empty base = served at root. */
const BASE = (document.body.dataset.base || '').replace(/\/+$/, '');
const withBase = (path) => BASE + path;

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function h(tag, attrs, html) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === 'class') e.className = attrs[k];
    else if (k === 'dataset') Object.assign(e.dataset, attrs[k]);
    else if (k.startsWith('on') && typeof attrs[k] === 'function') e.addEventListener(k.slice(2), attrs[k]);
    else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
  }
  if (html != null) e.innerHTML = html;
  return e;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ---- session --------------------------------------------------------------
   The dashboard requires a sign-in the moment an account store exists (see
   modules/auth.py). Two things follow for every page:

     * a 401 from any API call means the session is gone · send the browser to
       the login page rather than rendering an empty screen with a stack of
       "could not load" panels,
     * every state-changing call has to echo the CSRF value carried inside the
       signed session token. AUTH.csrf holds it; apiFetch attaches it.

   With no accounts configured, AUTH.required stays false and none of this is in
   the way. */
const AUTH = { required: false, user: null, csrf: '' };

function goToLogin() {
  if (/\/login(\?|$)/.test(location.pathname)) return;
  const next = encodeURIComponent(location.pathname + location.search);
  location.href = `${BASE}/login?next=${next}`;
}

/* One fetch for everything, so the session rules are applied in exactly one
   place. `method`/`body` behave like fetch's; a plain object body is JSON. */
async function apiFetch(url, opts) {
  opts = opts || {};
  const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
  let body = opts.body;
  if (body && typeof body === 'object' && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const method = (opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && AUTH.csrf) headers['X-Argus-CSRF'] = AUTH.csrf;
  const r = await fetch(url, { ...opts, method, headers, body, credentials: 'same-origin' });
  if (r.status === 401) { goToLogin(); throw new Error('signed out'); }
  return r;
}

async function getJSON(url) {
  const r = await apiFetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

/* POST/DELETE that returns the parsed body and throws the server's own message
   (rather than a bare status) so callers can show something useful. */
async function sendJSON(url, method, body) {
  const r = await apiFetch(url, { method, body });
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) {
    const err = new Error((data && data.error) || `${r.status} ${r.statusText}`);
    err.status = r.status;
    err.data = data;
    throw err;
  }
  return data;
}

/* Read the session once per page load and paint the account chip in the top
   bar. Never throws: a dashboard with no accounts simply has no chip. */
async function loadSession() {
  try {
    const s = await (await fetch(withBase('/api/auth/state'),
      { headers: { Accept: 'application/json' }, credentials: 'same-origin' })).json();
    AUTH.required = !!s.required;
    AUTH.user = s.user || null;
    AUTH.csrf = (s.user && s.user.csrf) || '';
    renderSession();
    return s;
  } catch (e) { return null; }
}

function renderSession() {
  const box = document.getElementById('sessionBox');
  if (!box) return;
  if (!AUTH.required || !AUTH.user) { box.innerHTML = ''; return; }
  const u = AUTH.user;
  const q = u.quota || {};
  const left = (q.daily_scans && q.remaining != null)
    ? `${q.remaining} of ${q.daily_scans} scans left today` : 'unlimited scans';
  // Labels collapse to their icons on a narrow screen (see .session in
  // admin.css) · the top bar has to stay on one line at phone widths.
  box.innerHTML = `
    <span class="who" title="${esc(u.username)} · ${esc(u.role)} · ${esc(left)}">
      ${icon(u.role === 'admin' ? 'shield-half-filled' : 'point-filled')}
      <b>${esc(u.username)}</b><span class="who-role">${esc(u.role)}</span>
    </span>
    ${u.role === 'admin' ? `<a class="btn sm ghost" href="${withBase('/recon/admin')}"
        title="Accounts, allowances and access history">${icon('settings')}<span class="lbl">Admin</span></a>` : ''}
    <button class="btn sm ghost" id="signOutBtn" title="Sign out">${icon('x')}<span class="lbl">Sign out</span></button>`;
  const out = document.getElementById('signOutBtn');
  if (out) out.addEventListener('click', async () => {
    try { await sendJSON(withBase('/api/auth/logout'), 'POST', {}); } catch (e) {}
    goToLogin();
  });
}

/* ---- formatting ----------------------------------------------------------- */
function fmtNum(n) {
  n = Number(n || 0);
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
  return String(n);
}
function fmtBytes(b) {
  if (b == null) return '';
  b = Number(b);
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
function timeAgo(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return iso;
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 604800) return Math.floor(s / 86400) + 'd ago';
  return new Date(t).toLocaleDateString();
}
function fmtDur(sec) {
  if (sec == null) return '';
  sec = Math.round(sec);
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60), s = sec % 60;
  return m + 'm' + (s ? ' ' + s + 's' : '');
}
function statusClass(code) {
  if (!code) return 'status-x';
  const c = Math.floor(code / 100);
  return c >= 2 && c <= 5 ? 'status-' + c : 'status-x';
}
function splitUrl(url) {
  try {
    const u = new URL(url);
    return { host: u.host, path: (u.pathname || '/') + (u.search || '') };
  } catch (e) { return { host: '', path: url }; }
}
function sevClass(s) { return s === 'high' ? 'high' : s === 'medium' ? 'medium' : 'low'; }

/* ---- source provenance (anonymized codes -> label + icon) ----------------- */
const SOURCE_META = {
  b: { label: 'passive enum', icon: 'radar-2' },
  W: { label: 'fingerprint', icon: 'fingerprint' },
  f: { label: 'content brute', icon: 'search' },
  s: { label: 'deep DNS', icon: 'network' },
  c: { label: 'cert transparency', icon: 'lock' },
  i: { label: 'IP enrichment', icon: 'server-2' },
  n: { label: 'passive names', icon: 'radar-2' },
  h: { label: 'http probe', icon: 'server-2' },
  k: { label: 'deep crawl', icon: 'topology-star-3' },
  r: { label: 'bulk DNS', icon: 'network' },
  crawler: { label: 'crawler', icon: 'topology-star-3' },
  js: { label: 'JS analysis', icon: 'braces' },
  robots: { label: 'robots.txt', icon: 'list-details' },
  sitemap: { label: 'sitemap.xml', icon: 'map-2' },
  seed: { label: 'seed', icon: 'point-filled' },
  input: { label: 'target input', icon: 'point-filled' },
  dns: { label: 'DNS resolver', icon: 'network' },
  'dns-brute': { label: 'DNS brute', icon: 'network' },
};
function sourceMeta(code) { return SOURCE_META[code] || { label: code, icon: 'point-filled' }; }
function sourceChip(code) {
  const m = sourceMeta(code);
  return `<span class="tag src-chip" title="source: ${esc(m.label)}">${icon(m.icon)}<b>${esc(code)}</b> ${esc(m.label)}</span>`;
}
function sourceChips(arr) { return (arr || []).map(sourceChip).join(''); }

/* ---- decode helpers (base64 / base64url / JWT / URL-encoded) --------------- */
function b64decode(str) {
  try {
    let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
  } catch (e) { return null; }
}
function looksMeaningful(s) {
  if (!s || s.length < 3) return false;
  if (/[\x00-\x08\x0e-\x1f\x7f]/.test(s)) return false;     // control chars => binary
  const printable = (s.match(/[\x20-\x7e]/g) || []).length / s.length;
  if (printable < 0.9) return false;
  return /[:/{}="'.@\s]/.test(s) || /[aeiou]/i.test(s);      // delimiter or word-like
}
function prettyJson(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return null; }
}
/* Return [{kind, token, decoded}] for encoded fragments found in `text`. */
function decodeCandidates(text) {
  const out = [];
  if (!text) return out;
  text = String(text);
  const jwt = text.match(/eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+)?/);
  if (jwt) {
    const p = jwt[0].split('.');
    const head = b64decode(p[0]), pay = b64decode(p[1]);
    if (head && pay) out.push({ kind: 'JWT', token: jwt[0],
      decoded: (prettyJson(head) || head) + '\n·\n' + (prettyJson(pay) || pay) });
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) {
    try { const d = decodeURIComponent(text.replace(/\+/g, ' ')); if (d !== text) out.push({ kind: 'URL-encoded', token: text, decoded: d }); } catch (e) {}
  }
  const seen = new Set();
  for (const t of (text.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) || []).slice(0, 8)) {
    if (seen.has(t) || (jwt && jwt[0].includes(t))) continue;
    seen.add(t);
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) continue;
    const d = b64decode(t);
    if (d && d !== t && looksMeaningful(d)) out.push({ kind: 'base64', token: t, decoded: prettyJson(d) || d });
  }
  return out;
}
/* Build a small inline "decode" affordance for a string, or '' if nothing to decode. */
function decodeWidget(text, id) {
  const cands = decodeCandidates(text);
  if (!cands.length) return '';
  const body = cands.map(c =>
    `<div class="dec-item"><span class="dec-kind">${esc(c.kind)}</span>
       <div class="dec-out mono">${esc(c.decoded)}</div></div>`).join('');
  return `<span class="decode-wrap">
    <button class="btn sm ghost decode-btn" type="button" data-decode="${id}">${icon('binary')} decode</button>
    <span class="decode-out" id="dec-${id}" hidden>${body}</span></span>`;
}
/* Delegated: wire any [data-decode] buttons inside `root`. */
function wireDecode(root) {
  (root || document).querySelectorAll('[data-decode]').forEach(b => {
    if (b._wired) return; b._wired = true;
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      const box = document.getElementById('dec-' + b.dataset.decode);
      if (box) { const open = box.hasAttribute('hidden'); box.toggleAttribute('hidden', !open); }
    });
  });
}

/* ---- theme ---------------------------------------------------------------- */
(function theme() {
  const root = document.documentElement;
  function current() {
    const set = root.getAttribute('data-theme');
    if (set) return set;
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('themeToggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
      const next = current() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('argus-theme', next); } catch (e) {}
      window.dispatchEvent(new CustomEvent('themechange', { detail: next }));
    });
  });
  window.currentTheme = current;
})();

/* read a CSS custom property (used by the canvas graph for themed colors) */
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/* Session is read on every page. It resolves long before any state-changing
   call can happen (those all need a click), so nothing waits on it. */
document.addEventListener('DOMContentLoaded', () => { loadSession(); });
