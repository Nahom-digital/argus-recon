/* ============================================================================
   Argus Recon · build watcher (cache-busting live reload)

   Every static asset URL carries ?v=<token>, where the token is a hash of the
   CSS/JS on disk (see web/server.asset_version). This watcher holds the token
   the page was rendered with (base.html writes it to <body data-asset-v>) and
   asks the server for the current one. When they differ a new build has shipped,
   so it reloads once · because the links are versioned, the reload pulls the new
   CSS/JS instead of the browser's cached copies.

   Loads after app.js, so withBase() is available. Fails closed: any error just
   skips a check, it never blocks the page.
   ========================================================================== */
'use strict';

(function buildWatcher() {
  const loaded = (document.body && document.body.dataset.assetV) || '';
  if (!loaded) return;                       // nothing to compare against

  const POLL_MS = 45000;                     // steady background cadence
  let reloading = false;

  async function currentVersion() {
    const r = await fetch(withBase('/api/version'), {
      headers: { Accept: 'application/json' },
      cache: 'no-store',                     // the check itself must never be cached
    });
    if (!r.ok) throw new Error(r.status);
    return (await r.json()).version || '';
  }

  async function check() {
    if (reloading) return;
    let server;
    try { server = await currentVersion(); }
    catch (e) { return; }                     // offline / restarting · try again later
    if (server && server !== loaded) {
      reloading = true;
      // after the reload the page is rendered with the new token, so loaded will
      // equal server and this cannot loop
      location.reload();
    }
  }

  // Check on a steady interval, and opportunistically whenever the tab regains
  // focus · that is exactly when someone returns to a tab left open across a
  // deploy and would otherwise be staring at the old UI.
  setInterval(check, POLL_MS);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') check();
  });
  window.addEventListener('focus', check);
})();
