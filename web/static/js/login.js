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
      // safeInApp strips the mount prefix (so BASE is not applied twice ·
      // /scanner/scanner/…) and rejects anything that is not a clean same-origin
      // in-app path, so a ?next= pointing off-site cannot turn this into an open
      // redirect. BASE is prepended exactly once.
      const next = new URLSearchParams(location.search).get('next') || '';
      location.href = BASE + safeInApp(next);
    } catch (e2) {
      fail('the dashboard did not respond');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `${icon('lock')} Sign in`;
    }
  });
});
