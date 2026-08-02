/* ============================================================================
   Argus Recon · sign in
   ========================================================================== */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  const user = document.getElementById('loginUser');
  const pass = document.getElementById('loginPass');
  const btn = document.getElementById('loginBtn');
  const err = document.getElementById('loginError');
  if (!form) return;

  setTimeout(() => user.focus(), 30);

  const fail = (msg) => {
    err.textContent = msg;
    err.hidden = false;
    pass.value = '';
    pass.focus();
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.hidden = true;
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> signing in';
    try {
      const r = await fetch(withBase('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username: user.value.trim(), password: pass.value }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return fail(data.error || `sign-in failed (${r.status})`);
      // Only same-origin paths are followed · a ?next= pointing anywhere else
      // would turn the login page into an open redirect.
      const next = new URLSearchParams(location.search).get('next') || '';
      const safe = /^\/[^/\\]/.test(next) ? next : '/';
      location.href = BASE + safe;
    } catch (e2) {
      fail('the dashboard did not respond');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `${icon('lock')} Sign in`;
    }
  });
});
