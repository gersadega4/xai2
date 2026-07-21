// turnstilePatch — reduce automation fingerprints for Cloudflare Turnstile
// Runs at document_start in MAIN world (all frames)

(function () {
  'use strict';

  // 1) Hide webdriver
  try {
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
      configurable: true,
    });
  } catch (_) {}

  // 2) Fake chrome runtime if missing
  try {
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) window.chrome.runtime = {};
  } catch (_) {}

  // 3) Realistic plugins length
  try {
    Object.defineProperty(navigator, 'plugins', {
      get: () => {
        const arr = [
          { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
          { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
          { name: 'Native Client', filename: 'internal-nacl-plugin' },
        ];
        arr.length = 3;
        return arr;
      },
    });
  } catch (_) {}

  // 4) Languages
  try {
    Object.defineProperty(navigator, 'languages', {
      get: () => ['en-US', 'en'],
    });
  } catch (_) {}

  // 5) MouseEvent screen coords (original patch — helps some Turnstile builds)
  function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  try {
    const screenX = getRandomInt(800, 1600);
    const screenY = getRandomInt(200, 800);
    Object.defineProperty(MouseEvent.prototype, 'screenX', { get: function () { return screenX + (this.clientX || 0); } });
    Object.defineProperty(MouseEvent.prototype, 'screenY', { get: function () { return screenY + (this.clientY || 0); } });
  } catch (_) {}

  // 6) permissions.query spoof (notifications)
  try {
    const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
    if (originalQuery) {
      window.navigator.permissions.query = (parameters) =>
        parameters && parameters.name === 'notifications'
          ? Promise.resolve({ state: Notification.permission })
          : originalQuery(parameters);
    }
  } catch (_) {}

  // 7) Remove Playwright / automation globals if present
  try {
    delete window.__playwright;
    delete window.__pw_manual;
    delete window.__PW_inspect;
  } catch (_) {}
})();
