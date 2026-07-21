#!/usr/bin/env python3
"""grok-signup-playwright-gmail.py — Playwright + Gmail IMAP version.

Combines:
- Playwright browser automation (from grok-signup.py)
- Gmail IMAP OTP polling (from grok-signup-nodriver.py)
- turnstilePatch extension for Turnstile bypass
- Same capabilities: infinite loop, batch, auto-add, retries
"""
import json
import os
import random
import re
import shutil
import string
import sys
import time
import tempfile
import imaplib
from email import message_from_bytes
from pathlib import Path

from playwright.sync_api import sync_playwright
import curl_cffi.requests as creq

# ── Config ────────────────────────────────────────────────────
_env = {}
_envfile = Path(__file__).parent / '.env'
if _envfile.exists():
    for line in _envfile.read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            _env[k.strip()] = v.strip()

def _env_or(key, default): return os.environ.get(key, _env.get(key, default))

PASSWORD = _env_or('PASSWORD', 'change-me')
GMAIL_USER = _env_or('GMAIL_USER', '')
GMAIL_APP_PASSWORD = _env_or('GMAIL_APP_PASSWORD', '')
GMAIL_DOMAINS = _env_or('GMAIL_DOMAINS', 'example.com').split(',')
ROUTER9 = _env_or('ROUTER9_URL', 'https://your-9router.example')
ROUTER9_PASS = _env_or('ROUTER9_PASS', 'change-me')

# Optional SCTG Turnstile solver (fallback when extension yields no token)
# Get key from https://sctg.xyz — set in .env: SCTG_API_KEY=...
SCTG_API_KEY = _env_or('SCTG_API_KEY', '') or _env_or('CAPTCHA_API_KEY', '')
SCTG_IN = _env_or('SCTG_IN', 'https://sctg.xyz/in.php')
SCTG_RES = _env_or('SCTG_RES', 'https://sctg.xyz/res.php')
TURNSTILE_SITEKEY = _env_or('TURNSTILE_SITEKEY', '0x4AAAAAAAhr9JGVDZbrZOo0')
TURNSTILE_PAGEURL = _env_or('TURNSTILE_PAGEURL', 'https://accounts.x.ai/sign-up')
# if true: skip waiting for extension token, go straight to SCTG
SCTG_FIRST = _env_or('SCTG_FIRST', 'false').lower() in ('1', 'true', 'yes')
# Per-attempt SCTG poll budget (short). Prefer retries over long single wait.
SCTG_TIMEOUT = int(_env_or('SCTG_TIMEOUT', '45'))
# How many create+poll attempts before giving up
SCTG_RETRIES = max(1, int(_env_or('SCTG_RETRIES', '3')))
# Quiet inject logs (true = short one-liner)
SCTG_QUIET = _env_or('SCTG_QUIET', 'true').lower() in ('1', 'true', 'yes')

# VPS/GHA: never fall back to direct when proxies configured
REQUIRE_PROXY = _env_or('REQUIRE_PROXY', 'false').lower() in ('1', 'true', 'yes')
PROXY_FAIL_SOFT = _env_or('PROXY_FAIL_SOFT', 'true').lower() in ('1', 'true', 'yes')

# ── Proxy Pool Manager ───────────────────────────────────────
class ProxyPool:
    """Proxy pool with auth support + soft/hard failure tracking.

    Supports:
      - host:port
      - http://host:port
      - http://user:pass@host:port
      - user:pass@host:port
    get_random_proxy() → Playwright dict {server, username?, password?, _key}
    """
    def __init__(self, proxies: list):
        self._proxies = {}  # key -> {server, username?, password?, fails}

        for proxy in proxies:
            proxy = proxy.strip()
            if not proxy:
                continue
            cfg = self._parse(proxy)
            if cfg:
                key = (cfg.get('username', '') + '@' + cfg['server']) if cfg.get('username') else cfg['server']
                cfg['fails'] = 0
                self._proxies[key] = cfg

    @staticmethod
    def _parse(proxy: str):
        p = proxy.strip()
        if ' ' in p and '://' not in p and '@' not in p:
            p = p.split()[0]
        if not p.startswith('http://') and not p.startswith('https://') and not p.startswith('socks'):
            p = 'http://' + p
        m = re.match(r'^(https?|socks5?)://([^:/@]+):([^@/]+)@([^:/]+):(\d+)', p)
        if m:
            scheme, user, pwd, host, port = m.groups()
            return {'server': f'{scheme}://{host}:{port}', 'username': user, 'password': pwd}
        m = re.match(r'^(https?|socks5?)://([^:/]+):(\d+)', p)
        if m:
            scheme, host, port = m.groups()
            return {'server': f'{scheme}://{host}:{port}'}
        m = re.match(r'^([\d\.a-zA-Z\-]+):(\d+)$', proxy.strip().split()[0])
        if m:
            return {'server': f'http://{m.group(1)}:{m.group(2)}'}
        return None

    def get_random_proxy(self):
        available = [k for k, c in self._proxies.items() if c.get('fails', 0) < 3]
        if not available:
            # last resort: still return a configured proxy (avoid bare direct on GHA/VPS)
            if self._proxies:
                key = random.choice(list(self._proxies.keys()))
            else:
                return None
        else:
            key = random.choice(available)
        cfg = self._proxies[key]
        out = {'server': cfg['server'], '_key': key}
        if cfg.get('username'):
            out['username'] = cfg['username']
            out['password'] = cfg.get('password', '')
        return out

    def report_failure(self, proxy, soft=False):
        if soft and PROXY_FAIL_SOFT:
            return
        key = proxy.get('_key') if isinstance(proxy, dict) else proxy
        if not key or key not in self._proxies:
            return
        self._proxies[key]['fails'] = self._proxies[key].get('fails', 0) + 1

    def report_success(self, proxy):
        key = proxy.get('_key') if isinstance(proxy, dict) else proxy
        if key and key in self._proxies:
            self._proxies[key]['fails'] = 0

    def get_stats(self):
        total = len(self._proxies)
        blacklisted = sum(1 for c in self._proxies.values() if c.get('fails', 0) >= 3)
        return {'total': total, 'available': total - blacklisted, 'blacklisted': blacklisted}


def _is_soft_proxy_error(err) -> bool:
    msg = str(err or '').lower()
    soft_markers = (
        'oauth', 'authorization_pending', 'poll failed', 'allow button',
        'turnstile', 'sctg', 'otp', 'email form', 'verification failed',
        'identity', 'blocked', 'invalid action', 'set-cookie',
        'cloudflare', 'abusive traffic', 'you have been blocked',
        'timeout waiting', 'locator.', 'page.',
    )
    return any(m in msg for m in soft_markers)

# Load proxy pool
PROXY_LIST_RAW = _env_or('PROXIES', '')
PROXY_POOL = None
if PROXY_LIST_RAW:
    proxy_lines = [line.strip() for line in PROXY_LIST_RAW.split(',') if line.strip()]
    if proxy_lines:
        PROXY_POOL = ProxyPool(proxy_lines)

# Auto-detect Chrome binary
def _detect_chrome():
    candidates = [
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        None,  # Let Playwright use bundled Chrome
    ]
    env_chrome = _env_or('CHROME_BIN', '')
    if env_chrome:
        return env_chrome

    import shutil
    for path in candidates:
        if path is None:
            return None
        if shutil.which(path) or Path(path).exists():
            return path
    return None

CHROME_BIN = _detect_chrome()
TS_DIR = Path('turnstilePatch').resolve()
SIGNUP = 'https://accounts.x.ai/sign-up?redirect=grok-com'
OUT = Path('sso.txt')

MAX_ACCOUNTS = int(_env_or('MAX_ACCOUNTS', '1'))    # <= 0 = infinite
BATCH_SIZE = max(1, int(_env_or('BATCH_SIZE', '1')))
PAUSE_SECONDS = int(_env_or('PAUSE_SECONDS', '10'))
DELAY_SECONDS = int(_env_or('DELAY_SECONDS', '5'))
MAX_ACCOUNT_RETRIES = max(1, int(_env_or('MAX_ACCOUNT_RETRIES', '3')))
AUTO_ADD = os.environ.get('AUTO_ADD', 'false').lower() in ('1','true','yes')

# Headless mode (default OFF — headed is proven for Turnstile/OAuth)
# true/1/yes = headless; false = headed (visible browser)
# HEADLESS_MODE=new → modern Chrome headless (better than old headless)
HEADLESS = _env_or('HEADLESS', 'false').lower() in ('1', 'true', 'yes')
HEADLESS_MODE = (_env_or('HEADLESS_MODE', 'new') or 'new').strip().lower()  # new | old

def _browser_launch_flags(ext_path=None, extra=None):
    """Shared Chrome flags for headed/headless."""
    args = [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
        '--use-fake-ui-for-media-stream',
        '--use-fake-device-for-media-stream',
        '--disable-webgl',
        '--disable-webgl2',
    ]
    if ext_path:
        args = [
            f'--disable-extensions-except={ext_path}',
            f'--load-extension={ext_path}',
        ] + args
    if HEADLESS:
        # "new" headless is less bot-flagged than legacy --headless
        if HEADLESS_MODE in ('old', 'legacy', 'classic'):
            args.append('--headless')
        else:
            args.append('--headless=new')
        args.extend([
            '--window-size=1920,1080',
            '--hide-scrollbars',
            '--mute-audio',
            '--disable-gpu',
        ])
    if extra:
        args.extend(extra)
    return args

def _launch_headless_value():
    """Playwright headless kwarg: False when headed; True or 'new' when headless."""
    if not HEADLESS:
        return False
    if HEADLESS_MODE in ('old', 'legacy', 'classic'):
        return True
    return True  # + --headless=new in args for Chromium


# ── Temp Chrome profile cleanup (prevents disk spam: grok-pw-*/grok-router-*) ──
PROFILE_PREFIXES = ('grok-pw-', 'grok-router-')


def _temp_root() -> Path:
    return Path(tempfile.gettempdir())


def make_browser_profile_dir(prefix: str = 'grok-pw') -> str:
    """Create unique temp profile dir under system temp (Windows: %TEMP%)."""
    d = _temp_root() / f'{prefix}-{int(time.time() * 1000)}-{random.randint(1000, 9999)}'
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def cleanup_profile_dir(path, quiet: bool = True):
    """Best-effort remove one Chrome user-data-dir after browser close."""
    if not path:
        return
    p = Path(path)
    try:
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            # second pass for locked files on Windows
            if p.exists():
                time.sleep(0.3)
                shutil.rmtree(p, ignore_errors=True)
            if p.exists():
                if not quiet:
                    log_no(f"profile still locked: {p.name}")
            else:
                if not quiet:
                    log_ok(f"cleaned profile: {p.name}")
    except Exception as e:
        if not quiet:
            log_no(f"profile cleanup: {e}")


def cleanup_stale_profiles(max_age_sec: int = 3600, quiet: bool = False):
    """Delete leftover grok-pw-* / grok-router-* folders older than max_age_sec."""
    root = _temp_root()
    now = time.time()
    removed = 0
    freed = 0
    try:
        for child in root.iterdir():
            try:
                name = child.name
                if not any(name.startswith(p) for p in PROFILE_PREFIXES):
                    continue
                if not child.is_dir():
                    continue
                age = now - child.stat().st_mtime
                if age < max_age_sec:
                    continue
                # rough size before delete
                size = 0
                for f in child.rglob('*'):
                    try:
                        if f.is_file():
                            size += f.stat().st_size
                    except Exception:
                        pass
                shutil.rmtree(child, ignore_errors=True)
                if not child.exists():
                    removed += 1
                    freed += size
            except Exception:
                continue
    except Exception:
        pass
    if removed and not quiet:
        mb = freed / (1024 * 1024)
        log_ok(f"cleaned {removed} stale temp profile(s) (~{mb:.1f} MB)")
    return removed

_used_addrs = set()
GRN, RED, YEL, CYN, RST, BOLD = '\033[32m', '\033[31m', '\033[33m', '\033[36m', '\033[0m', '\033[1m'

def log_ok(msg): print(f"  {GRN}✓{RST} {msg}", flush=True)
def log_no(msg): print(f"  {RED}✗{RST} {msg}", flush=True)
def log_wait(msg): print(f"  {YEL}→{RST} {msg}", flush=True)

class TurnstileRetry(Exception):
    """Raised when Turnstile fails but account data can be reused for retry."""
    def __init__(self, mail, code):
        super().__init__('Turnstile retry needed')
        self.mail = mail
        self.code = code

def unique_addr():
    for _ in range(20):
        local = (
            ''.join(random.choices(string.ascii_lowercase, k=5)) + '.'
            + ''.join(random.choices(string.ascii_lowercase, k=5)) + '.'
            + ''.join(random.choices('0123456789abcdef', k=4))
        )
        dom = random.choice(GMAIL_DOMAINS)
        addr = f'{local}@{dom}'
        if addr not in _used_addrs:
            _used_addrs.add(addr)
            return addr
    raise RuntimeError('could not generate unique email')

def unlock_turnstile():
    """Return path to turnstilePatch directory."""
    if not (TS_DIR / 'script.js').exists() or not (TS_DIR / 'manifest.json').exists():
        raise RuntimeError(f"missing turnstilePatch/script.js or manifest.json in {TS_DIR}")
    return str(TS_DIR)


def solve_turnstile_sctg(pageurl=None, sitekey=None, timeout=None, retries=None):
    """Solve Cloudflare Turnstile via SCTG with short timeout + multi-retry.

    Instead of waiting 120–150s on one stuck task, create a new task and retry.
    Env:
      SCTG_TIMEOUT=45   # seconds per attempt (default 45)
      SCTG_RETRIES=3    # attempts (default 3)
    """
    if not SCTG_API_KEY:
        raise RuntimeError('SCTG_API_KEY not set in .env')
    pageurl = pageurl or TURNSTILE_PAGEURL
    sitekey = sitekey or TURNSTILE_SITEKEY
    timeout = int(timeout if timeout is not None else SCTG_TIMEOUT)
    retries = int(retries if retries is not None else SCTG_RETRIES)
    last_err = None

    for attempt in range(1, retries + 1):
        try:
            log_wait(f"SCTG attempt {attempt}/{retries} sitekey={sitekey[:16]}... (≤{timeout}s)")
            r = creq.post(SCTG_IN, data={
                'key': SCTG_API_KEY,
                'method': 'turnstile',
                'pageurl': pageurl,
                'sitekey': sitekey,
            }, timeout=30)
            res = (r.text or '').strip()
            if not res.startswith('OK|'):
                # create fail — retry next attempt
                last_err = f'create fail: {res[:160]}'
                log_no(f"SCTG {last_err}")
                if attempt < retries:
                    time.sleep(2 + attempt)
                continue

            task_id = res.split('|', 1)[1]
            t0 = time.time()
            last_log = 0
            while time.time() - t0 < timeout:
                time.sleep(2.5)
                r = creq.get(
                    SCTG_RES,
                    params={'key': SCTG_API_KEY, 'action': 'get', 'id': task_id},
                    timeout=30,
                )
                res = (r.text or '').strip()
                if res.startswith('OK|'):
                    token = res[3:]
                    log_ok(f"SCTG ok len={len(token)} in {int(time.time()-t0)}s (try {attempt}/{retries})")
                    return token
                if res in ('CAPCHA_NOT_READY', 'CAPTCHA_NOT_READY', 'NOT_READY', 'PROCESSING'):
                    elapsed = int(time.time() - t0)
                    # log every ~10s, less spam
                    if elapsed - last_log >= 10:
                        log_wait(f"SCTG wait {elapsed}/{timeout}s (try {attempt}/{retries})")
                        last_log = elapsed
                    continue
                # hard poll error — break this attempt, retry new task
                last_err = f'poll fail: {res[:160]}'
                log_no(f"SCTG {last_err}")
                break
            else:
                # while exhausted = timeout this attempt
                last_err = f'timeout {timeout}s (task {task_id})'
                log_no(f"SCTG {last_err} — retry new task...")
                if attempt < retries:
                    time.sleep(1.5)
                continue

            # poll fail path
            if attempt < retries:
                time.sleep(2 + attempt)
                continue
        except Exception as e:
            last_err = str(e)
            log_no(f"SCTG error: {e}")
            if attempt < retries:
                time.sleep(2 + attempt)
                continue

    raise RuntimeError(f'SCTG failed after {retries} attempts: {last_err}')


# Installed via context.add_init_script BEFORE navigation — captures turnstile.render callbacks
TURNSTILE_HOOK_JS = r"""
(() => {
  if (window.__tsHookInstalled) return;
  window.__tsHookInstalled = true;
  window.__tsCallbacks = window.__tsCallbacks || [];
  window.__cfToken = window.__cfToken || null;

  const patch = () => {
    if (!window.turnstile || window.turnstile.__tsPatched) return !!window.turnstile;
    try {
      const ts = window.turnstile;
      const origRender = ts.render && ts.render.bind(ts);
      const origGet = ts.getResponse && ts.getResponse.bind(ts);

      ts.render = function (el, opts) {
        try {
          if (opts && typeof opts.callback === 'function') {
            window.__tsCallbacks.push(opts.callback);
            window.__tsCb = opts.callback;
          }
          const node = typeof el === 'string' ? document.querySelector(el) : el;
          if (node) {
            const name = node.getAttribute && node.getAttribute('data-callback');
            if (name && typeof window[name] === 'function') {
              window.__tsCallbacks.push(window[name].bind(window));
            }
          }
          // auto-fire if token already solved
          if (window.__cfToken && opts && typeof opts.callback === 'function') {
            setTimeout(() => { try { opts.callback(window.__cfToken); } catch (e) {} }, 50);
          }
        } catch (e) {}
        return origRender ? origRender(el, opts) : undefined;
      };

      ts.getResponse = function (widgetId) {
        if (window.__cfToken) return window.__cfToken;
        return origGet ? origGet(widgetId) : undefined;
      };

      ts.__tsPatched = true;
      return true;
    } catch (e) {
      return false;
    }
  };

  // patch now + poll until turnstile loads
  patch();
  const iv = setInterval(() => { if (patch()) clearInterval(iv); }, 200);
  setTimeout(() => clearInterval(iv), 30000);
})();
"""


def install_turnstile_hook(context):
    """Must be called on browser context BEFORE any page.goto."""
    try:
        context.add_init_script(TURNSTILE_HOOK_JS)
        log_ok("turnstile render-hook installed")
    except Exception as e:
        log_no(f"turnstile hook install failed: {e}")


def inject_turnstile_token(page, token, quiet=None):
    """Deep inject — ported from bot_oke.js (native value setter + callbacks + getResponse)."""
    report = page.evaluate(
        """(tok) => {
            const report = { inputs: 0, callbacks: 0, methods: [], ok: false, tokenLen: 0 };

            const setNative = (el, value) => {
              if (!el) return;
              try {
                const proto = el.tagName === 'TEXTAREA'
                  ? window.HTMLTextAreaElement.prototype
                  : window.HTMLInputElement.prototype;
                const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                if (desc && desc.set) desc.set.call(el, value);
                else el.value = value;
              } catch (e) {
                el.value = value;
              }
              try { el.setAttribute('value', value); } catch (e) {}
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              report.inputs++;
            };

            // 1) all response fields
            document.querySelectorAll(
              'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"], input[name="g-recaptcha-response"], textarea[name="g-recaptcha-response"]'
            ).forEach((el) => setNative(el, tok));

            // ensure at least one hidden input
            let primary = document.querySelector('input[name="cf-turnstile-response"]');
            if (!primary) {
              primary = document.createElement('input');
              primary.type = 'hidden';
              primary.name = 'cf-turnstile-response';
              const host =
                document.querySelector('.cf-turnstile') ||
                document.querySelector('[data-sitekey]') ||
                document.querySelector('form') ||
                document.body;
              host.appendChild(primary);
              report.methods.push('created-input');
            }
            setNative(primary, tok);

            // 2) data-callback on widget
            const widgets = document.querySelectorAll('.cf-turnstile, [data-sitekey], [class*="turnstile"]');
            widgets.forEach((w) => {
              const cbName = w.getAttribute('data-callback') || (w.dataset && w.dataset.callback);
              if (cbName && typeof window[cbName] === 'function') {
                try {
                  window[cbName](tok);
                  report.callbacks++;
                  report.methods.push('data-callback:' + cbName);
                } catch (e) {}
              }
              w.querySelectorAll('input, textarea').forEach((el) => {
                if (/turnstile|captcha|cf-/i.test(el.name || el.id || '')) setNative(el, tok);
              });
            });

            // 3) callbacks captured by render hook
            const cbs = window.__tsCallbacks || [];
            cbs.forEach((fn, i) => {
              if (typeof fn === 'function') {
                try {
                  fn(tok);
                  report.callbacks++;
                  report.methods.push('hook-cb-' + i);
                } catch (e) {}
              }
            });
            if (typeof window.__tsCb === 'function') {
              try {
                window.__tsCb(tok);
                report.callbacks++;
                report.methods.push('__tsCb');
              } catch (e) {}
            }

            // 4) turnstile API patches
            try {
              window.__cfToken = tok;
              if (window.turnstile) {
                try {
                  window.turnstile.getResponse = () => tok;
                  report.methods.push('getResponse-patch');
                } catch (e) {}
              }
            } catch (e) {}

            // 5) postMessage to iframes
            document.querySelectorAll('iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]').forEach((f) => {
              try {
                f.contentWindow && f.contentWindow.postMessage({ event: 'complete', token: tok }, '*');
                report.methods.push('postMessage');
              } catch (e) {}
            });

            // 6) custom events
            try {
              document.dispatchEvent(new CustomEvent('cf-turnstile-callback', { detail: tok }));
              window.dispatchEvent(new CustomEvent('turnstile-success', { detail: tok }));
            } catch (e) {}

            // 7) cosmetic widget state
            widgets.forEach((w) => {
              try {
                w.setAttribute('data-state', 'solved');
              } catch (e) {}
            });

            const finalVal = document.querySelector('input[name="cf-turnstile-response"]')?.value || '';
            report.ok = finalVal.length > 20;
            report.tokenLen = finalVal.length;
            return report;
        }""",
        token,
    )
    if quiet is None:
        quiet = 'short' if SCTG_QUIET else 'full'
    elif quiet is True:
        quiet = 'none'  # re-inject silent
    elif quiet is False:
        quiet = 'full'
    if quiet == 'short':
        if report.get('ok'):
            log_ok(f"token injected (cb={report.get('callbacks')})")
        else:
            log_no("token inject failed")
    elif quiet == 'full':
        log_ok(
            f"inject: ok={report.get('ok')} in={report.get('inputs')} "
            f"cb={report.get('callbacks')} len={report.get('tokenLen')}"
        )
        if not report.get('ok'):
            log_no("inject may have failed — token field empty/short")
    # quiet == 'none' → no log
    return report


def extract_sitekey(page):
    """Best-effort sitekey from DOM / HTML; fallback env default."""
    try:
        sk = page.evaluate(
            """() => {
                const el = document.querySelector('[data-sitekey]');
                if (el) return el.getAttribute('data-sitekey');
                const iframe = document.querySelector('iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]');
                if (iframe && iframe.src) {
                    const m = iframe.src.match(/[?&]sitekey=([^&]+)/);
                    if (m) return decodeURIComponent(m[1]);
                }
                const html = document.documentElement.innerHTML;
                const m2 = html.match(/data-sitekey=["']([^"']+)["']/)
                  || html.match(/sitekey["']?\\s*[:=]\\s*["']([0-9a-zA-Z_-]{20,})["']/);
                return m2 ? m2[1] : null;
            }"""
        )
        if sk:
            log_ok(f"sitekey from DOM: {sk[:20]}...")
            return sk
    except Exception:
        pass
    return TURNSTILE_SITEKEY


def page_has_verification_failed(page):
    try:
        return page.evaluate(
            "() => /verification failed/i.test(document.body ? document.body.innerText : '')"
        )
    except Exception:
        return False

# ── Gmail IMAP ────────────────────────────────────────────────
class GmailIMAP:
    def __init__(self):
        self.mail = None
        self.addr = None
        self._seen_ids = set()

    def create(self):
        self.addr = unique_addr()
        self.mail = imaplib.IMAP4_SSL('imap.gmail.com')
        self.mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        self.mail.select('inbox')
        return self.addr

    @staticmethod
    def _extract_code(text):
        patterns = [
            r'code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})',  # "code: ZS8-UTP" or "code U5R-4UC"
            r'code[:\s]+([A-Z0-9]{6})',              # "code: ZS8UTP" or "code ZS8UTP"
            r'\b([A-Z0-9]{3}-[A-Z0-9]{3})\b',        # word boundary "U5R-4UC"
            r'\b([A-Z0-9]{6})\b',                    # word boundary "U5R4UC"
        ]
        for pat in patterns:
            m = re.search(pat, text, re.I)
            if m:
                code = m.group(1).replace('-', '')
                if len(code) == 6 and code.isalnum() and code.isupper():
                    return code
        return None

    def _body_text(self, msg):
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode('utf-8', errors='ignore'))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode('utf-8', errors='ignore'))
        return '\n'.join(parts)

    def peek_code(self):
        try:
            self.mail.noop()
            _, search_data = self.mail.search(None, f'TO "{self.addr}"')
            msg_ids = search_data[0].split()

            # Debug: log email count
            if msg_ids:
                log_wait(f"found {len(msg_ids)} emails for {self.addr}")

            for mid in msg_ids:
                if mid in self._seen_ids:
                    continue
                _, fetched = self.mail.fetch(mid, '(RFC822)')
                raw = fetched[0][1]
                msg = message_from_bytes(raw)

                # Debug: log email details (FULL subject, not truncated)
                subj = msg.get('Subject', '')
                from_addr = msg.get('From', '')
                log_wait(f"Email: From={from_addr[:50]}, Subject={subj}")

                # Try extract from SUBJECT FIRST (more reliable than HTML body)
                code = self._extract_code(subj)
                if code:
                    log_ok(f"✓ Extracted OTP: {code} from SUBJECT")
                    self._seen_ids.add(mid)
                    # Delete the email after extracting OTP
                    self.mail.store(mid, '+FLAGS', '\\Deleted')
                    self.mail.expunge()
                    log_ok(f"deleted OTP email")
                    return code

                # Fallback: try body
                text = self._body_text(msg)
                if text:
                    log_wait(f"Body snippet: {text[:100]}")
                    code = self._extract_code(text)
                    if code:
                        log_ok(f"✓ Extracted OTP: {code} from BODY")
                        self._seen_ids.add(mid)
                        # Delete the email after extracting OTP
                        self.mail.store(mid, '+FLAGS', '\\Deleted')
                        self.mail.expunge()
                        log_ok(f"deleted OTP email")
                        return code

                log_wait(f"No OTP match in this email")
                self._seen_ids.add(mid)
        except Exception as e:
            log_no(f"Gmail peek error: {e}")
        return None

    def logout(self):
        try:
            self.mail.close()
            self.mail.logout()
        except Exception:
            pass

def wait_for_otp(mail: GmailIMAP, timeout: int = 120):
    """Poll Gmail IMAP for OTP code."""
    t = time.time()
    while time.time() - t < timeout:
        code = mail.peek_code()
        if code:
            return code
        time.sleep(0.5)
    return None

# ── 9Router helper ─────────────────────────────────────────────
class Router9:
    def __init__(self):
        self.s = creq.Session()
        self.s.headers.update({'Accept':'application/json','Content-Type':'application/json'})
        self.auth_token = None

    def login(self):
        r = self.s.post(f'{ROUTER9}/api/auth/login', json={'password':ROUTER9_PASS}, timeout=15)
        # Extract auth_token from Set-Cookie header
        if 'Set-Cookie' in r.headers:
            cookies = r.headers['Set-Cookie']
            match = re.search(r'auth_token=([^;]+)', cookies)
            if match:
                self.auth_token = match.group(1)
                self.s.cookies.set('auth_token', self.auth_token)
        return r.json().get('success', False)

    def device_code(self):
        r = self.s.get(f'{ROUTER9}/api/oauth/grok-cli/device-code', timeout=60)
        return r.json()

    def poll(self, device_code, code_verifier):
        r = self.s.post(f'{ROUTER9}/api/oauth/grok-cli/poll',
                        json={'deviceCode': device_code, 'codeVerifier': code_verifier}, timeout=60)
        return r.json()

    def list_providers(self):
        r = self.s.get(f'{ROUTER9}/api/providers', timeout=15)
        conns = r.json().get('connections', [])
        return [c for c in conns if c.get('provider') == 'grok-cli']

def add_to_router_single(acc):
    """Add single account to 9Router (for parallel execution)."""
    try:
        r9 = Router9()
        if not r9.login():
            log_no("9router login failed")
            return False

        existing = {c.get('email') for c in r9.list_providers()}
        email = acc.get('email', '')

        if email in existing:
            log_wait(f"{email} already exists"); return False
    except Exception as e:
        log_no(f"9router API error: {e}")
        return False


    # Pick proxy from pool (Playwright dict with optional username/password)
    proxy_config = None
    proxy_key = None
    if PROXY_POOL:
        proxy_config = PROXY_POOL.get_random_proxy()
        if proxy_config:
            proxy_key = proxy_config.get('_key')
            log_ok(f"using proxy: {proxy_config.get('server')} auth={'yes' if proxy_config.get('username') else 'no'}")
        else:
            if REQUIRE_PROXY:
                raise RuntimeError("REQUIRE_PROXY=true but no proxy available")
            log_no("all proxies blacklisted - using direct connection")
    elif REQUIRE_PROXY:
        raise RuntimeError("REQUIRE_PROXY=true but PROXIES not set")

    # Generate random user agent
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    ]
    user_agent = random.choice(user_agents)

    try:
        with sync_playwright() as p:
            profile_dir = make_browser_profile_dir('grok-router')
            launch_kwargs = {
                'user_data_dir': profile_dir,
                'headless': _launch_headless_value(),
                'no_viewport': not HEADLESS,
                'executable_path': CHROME_BIN,
                'user_agent': user_agent,
                'args': _browser_launch_flags(extra=[f'--user-agent={user_agent}']),
                'ignore_default_args': ['--enable-automation'],
            }
            if HEADLESS:
                launch_kwargs['viewport'] = {'width': 1920, 'height': 1080}
            if proxy_config:
                launch_kwargs['proxy'] = {k: v for k, v in proxy_config.items() if k != '_key'}

            log_wait(f"launching browser (proxy: {(proxy_config or {}).get('server') or 'none'}, headless={HEADLESS})")
            ctx = p.chromium.launch_persistent_context(**launch_kwargs)
            try:
                ctx.clear_cookies()
                cookies = acc.get('sso_cookies', [])
                if cookies:
                    safe = []
                    for c in cookies:
                        cc = dict(c)
                        if not cc.get('domain'):
                            continue
                        ss = cc.get('sameSite','Lax')
                        if ss not in ('Strict','Lax','None'):
                            ss = 'Lax'
                        cc['sameSite'] = ss
                        safe.append(cc)
                    ctx.add_cookies(safe)

                d = r9.device_code()
                verify_url = d['verification_uri_complete']

                page = ctx.new_page()
                page.goto(verify_url, wait_until='domcontentloaded', timeout=45000)
                time.sleep(3)

                has_login = page.evaluate("!!document.querySelector('input[type=email], input[type=password]')")
                if has_login:
                    log_no(f"{email} SSO expired"); page.close(); ctx.close(); cleanup_profile_dir(profile_dir); return False

                try:
                    page.get_by_role('button', name=re.compile(r'Continue', re.I)).click(timeout=5000)
                    time.sleep(3)
                except:
                    pass

                try:
                    page.get_by_role('button', name=re.compile(r'Allow', re.I)).click(timeout=8000)
                    time.sleep(2)
                except:
                    log_no(f"{email} Allow button not found"); page.close(); ctx.close(); cleanup_profile_dir(profile_dir); return False

                time.sleep(3); page.close()

                for _ in range(60):
                    res = r9.poll(d['device_code'], d['code_verifier'])
                    if res.get('success'):
                        log_ok(f"{email} added ✓")
                        ctx.close()
                        cleanup_profile_dir(profile_dir)
                        # Report proxy success
                        if PROXY_POOL and proxy_key:
                            PROXY_POOL.report_success({'_key': proxy_key})
                            log_ok(f"proxy success: {proxy_key}")
                        return True
                    if not res.get('pending'):
                        log_no(f"{email} poll error")
                        ctx.close()
                        cleanup_profile_dir(profile_dir)
                        # Report proxy failure
                        if PROXY_POOL and proxy_key:
                            soft = _is_soft_proxy_error(e) if "e" in dir() else False
                            PROXY_POOL.report_failure({'_key': proxy_key}, soft=soft)
                            if not soft:
                                fails = PROXY_POOL._proxies.get(proxy_key, {}).get('fails', 0)
                                log_no(f"proxy hard-fail: {proxy_key} ({fails}/3)")
                            else:
                                log_wait(f"proxy soft-fail (not blacklisted): {proxy_key}")
                        return False
                    time.sleep(5)

                log_no(f"{email} poll timeout")
                ctx.close()
                cleanup_profile_dir(profile_dir)
                # Report proxy failure on timeout
                if PROXY_POOL and proxy_key:
                    PROXY_POOL.report_failure({'_key': proxy_key}, soft=True)
                return False
            except Exception as e:
                log_no(f"{email} error: {e}")
                try:
                    ctx.close()
                except Exception:
                    pass
                cleanup_profile_dir(profile_dir)
                # Report proxy failure on exception
                if PROXY_POOL and proxy_key:
                    PROXY_POOL.report_failure({'_key': proxy_key}, soft=True)
                return False
    except Exception as outer_e:
        # Report proxy failure on outer exception
        if PROXY_POOL and proxy_key:
            PROXY_POOL.report_failure({'_key': proxy_key}, soft=True)
        return False

# ── Main signup flow ──────────────────────────────────────────
def signup_one(email_code_pair=None):
    """Register one Grok account. Returns account dict or raises exception."""
    # Step 1: Get device code from 9router
    r9 = Router9()
    if not r9.login():
        raise RuntimeError("9router login failed")

    device_data = r9.device_code()
    device_code = device_data.get('device_code')
    code_verifier = device_data.get('codeVerifier')
    user_code = device_data.get('user_code')
    verification_uri_complete = device_data.get('verification_uri_complete')

    if not device_code or not code_verifier or not user_code:
        raise RuntimeError(f"invalid device_code response: {device_data}")

    log_ok(f"device code: {user_code}")

    # Build signup URL with OAuth redirect
    import urllib.parse
    return_to = urllib.parse.quote(f'/oauth2/device?user_code={user_code}')
    signup_url = f'https://accounts.x.ai/sign-up?redirect=oauth2-provider&return_to={return_to}'
    log_ok(f"signup URL: {signup_url}")

    ext_path = unlock_turnstile()


    # Pick proxy from pool (Playwright dict with optional username/password)
    proxy_config = None
    proxy_key = None
    if PROXY_POOL:
        proxy_config = PROXY_POOL.get_random_proxy()
        if proxy_config:
            proxy_key = proxy_config.get('_key')
            log_ok(f"using proxy: {proxy_config.get('server')} auth={'yes' if proxy_config.get('username') else 'no'}")
        else:
            if REQUIRE_PROXY:
                raise RuntimeError("REQUIRE_PROXY=true but no proxy available")
            log_no("all proxies blacklisted - using direct connection")
    elif REQUIRE_PROXY:
        raise RuntimeError("REQUIRE_PROXY=true but PROXIES not set")

    # Prefer real OS user-agent (avoid Mac UA on Windows — flags bots)
    import platform
    if platform.system().lower() == 'windows':
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
        ]
    else:
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        ]
    env_ua = _env_or('USER_AGENT', '').strip()
    user_agent = env_ua or random.choice(user_agents)
    log_ok(f"user agent: {user_agent[:50]}...")

    signup_success = False
    profile_dir = None
    try:
        with sync_playwright() as p:
            profile_dir = make_browser_profile_dir('grok-pw')
            launch_args = {
                'user_data_dir': profile_dir,
                'headless': _launch_headless_value(),
                'no_viewport': not HEADLESS,
                'user_agent': user_agent,
                'args': _browser_launch_flags(ext_path=ext_path, extra=[f'--user-agent={user_agent}']),
                'ignore_default_args': ['--enable-automation'],
            }
            if HEADLESS:
                launch_args['viewport'] = {'width': 1920, 'height': 1080}
            if CHROME_BIN:
                launch_args['executable_path'] = CHROME_BIN
            if proxy_config:
                launch_args['proxy'] = {k: v for k, v in proxy_config.items() if k != '_key'}

            mode = f"headless={HEADLESS_MODE}" if HEADLESS else "headed"
            log_wait(f"launching browser ({mode})...")
            log_wait(f"  Chrome: {CHROME_BIN or 'bundled'}")
            log_wait(f"  Extension: {ext_path}")
            log_wait(f"  Proxy: {(proxy_config or {}).get('server') or 'none'}")
            log_wait(f"  User-Agent: {user_agent[:60]}...")
            log_wait(f"  Profile: {Path(profile_dir).name}")

            ctx = p.chromium.launch_persistent_context(**launch_args)
            install_turnstile_hook(ctx)

            page = ctx.new_page()
            page.goto(signup_url, wait_until='domcontentloaded', timeout=60000)
            time.sleep(4)
            log_ok("page loaded")

            # Cookie banner
            try:
                page.get_by_role('button', name='Accept All Cookies').click(timeout=3000)
                time.sleep(0.5)
            except:
                pass

            try:
                page.get_by_text('Sign up with email', exact=False).click(timeout=15000)
                page.wait_for_selector('input[type=email]', timeout=8000)
                time.sleep(2)
                log_ok("email form")
            except Exception as e:
                ctx.close(); cleanup_profile_dir(profile_dir)
                raise RuntimeError(f"email form: {e}")

            # Reuse existing mail+code if retrying
            if email_code_pair:
                mail = email_code_pair[0]
                addr = mail.addr
                code = email_code_pair[1]
                log_wait(f"retrying {addr}")
            else:
                mail = GmailIMAP()
                addr = mail.create()
                code = None
            log_wait(addr)

            page.locator('input[type=email]').fill(addr)
            page.locator('input[type=email]').press('Enter')

            # Wait for OTP input, with fallback to click 'Sign up' button
            try:
                page.wait_for_selector('input[name=code]', timeout=20000)
            except:
                page.get_by_role('button', name='Sign up').click(timeout=3000)
                page.wait_for_selector('input[name=code]', timeout=15000)
            log_ok("email submitted")

            if not code:
                code = wait_for_otp(mail, timeout=120)
                if not code:
                    mail.logout(); ctx.close(); cleanup_profile_dir(profile_dir)
                    raise RuntimeError("OTP timeout 120s")
            log_ok(f"OTP: {code}")

            code_input = page.locator('input[name=code]').first
            code_input.fill(code, timeout=15000)
            time.sleep(0.3)
            log_wait("submitting OTP...")
            page.keyboard.press('Enter')
            page.wait_for_selector('input[name=givenName]', timeout=20000)
            log_ok("OTP verified")

            local = addr.split('@')[0]
            parts = re.split(r'[._\-]', local)
            given = parts[0].capitalize()
            family = (parts[1] if len(parts) > 1 else 'Xyz').capitalize()

            page.locator('input[name=givenName]').fill(given)
            page.locator('input[name=familyName]').fill(family)
            page.locator('input[name=password]').fill(PASSWORD)
            log_ok("form filled")

            # Turnstile: SCTG with internal short-timeout retries (not one long 150s wait)
            turnstile_success = False
            sctg_token = None
            # Outer form retries (Go back + new OTP) — keep small; SCTG already retries
            max_ts = 2 if SCTG_API_KEY else 3
            for ts_attempt in range(1, max_ts + 1):
                log_wait(f"turnstile ({ts_attempt}/{max_ts})...")
                token = ''

                # Prefer SCTG when configured (iframes often 0)
                if SCTG_API_KEY and (SCTG_FIRST or ts_attempt >= 1):
                    try:
                        sitekey = extract_sitekey(page)
                        token = solve_turnstile_sctg(
                            pageurl=page.url or TURNSTILE_PAGEURL,
                            sitekey=sitekey,
                            # short per-attempt; retries handled inside solve_turnstile_sctg
                            timeout=SCTG_TIMEOUT,
                            retries=SCTG_RETRIES,
                        )
                        sctg_token = token
                        inject_turnstile_token(page, token)
                    except Exception as e:
                        log_no(f"SCTG: {e}")
                        token = ''

                # Extension path only if no SCTG key
                if not token and not SCTG_API_KEY:
                    for i in range(12):
                        token = page.evaluate(
                            "document.querySelector('input[name=cf-turnstile-response]')?.value || ''"
                        )
                        if token:
                            log_ok("turnstile token from page")
                            break
                        time.sleep(1)

                if token:
                    sctg_token = token
                    turnstile_success = True
                    break

                log_no(f"turnstile fail {ts_attempt}/{max_ts}")
                if ts_attempt < max_ts:
                    retry_delay = random.randint(3, 8)
                    log_wait(f"form retry in {retry_delay}s...")
                    time.sleep(retry_delay)
                    try:
                        page.get_by_role('button', name=re.compile(r'Go back', re.I)).click(timeout=5000)
                        log_ok("Go back")
                        time.sleep(2)
                        page.wait_for_selector('input[type=email]', timeout=8000)
                        page.locator('input[type=email]').fill(addr)
                        page.locator('input[type=email]').press('Enter')
                        try:
                            page.wait_for_selector('input[name=code]', timeout=20000)
                        except:
                            page.get_by_role('button', name='Sign up').click(timeout=3000)
                            page.wait_for_selector('input[name=code]', timeout=15000)
                        mail._seen_ids.clear()
                        new_code = wait_for_otp(mail, timeout=120)
                        if not new_code:
                            mail.logout(); ctx.close(); cleanup_profile_dir(profile_dir)
                            raise RuntimeError("OTP timeout on retry")
                        log_ok(f"OTP: {new_code}")
                        code_input = page.locator('input[name=code]').first
                        code_input.fill(new_code, timeout=15000)
                        time.sleep(0.3)
                        page.keyboard.press('Enter')
                        page.wait_for_selector('input[name=givenName]', timeout=20000)
                        page.locator('input[name=givenName]').fill(given)
                        page.locator('input[name=familyName]').fill(family)
                        page.locator('input[name=password]').fill(PASSWORD)
                        log_ok("form re-filled")
                    except Exception as e:
                        log_no(f"retry failed: {e}")
                        break

            if not turnstile_success:
                mail.logout(); ctx.close(); cleanup_profile_dir(profile_dir)
                hint = " (set SCTG_API_KEY)" if not SCTG_API_KEY else ""
                raise RuntimeError("turnstile failed" + hint)

            # Quiet re-inject before submit
            use_tok = sctg_token if (sctg_token and len(sctg_token) > 20) else page.evaluate(
                "document.querySelector('input[name=cf-turnstile-response]')?.value || ''"
            )
            if use_tok and len(use_tok) > 20:
                inject_turnstile_token(page, use_tok, quiet=True)  # no second spam log
                time.sleep(0.4)
            else:
                log_no("token missing before submit")

            page.get_by_role('button', name='Complete sign up').click()
            log_ok("submitted")
            time.sleep(2)

            if page_has_verification_failed(page):
                mail.logout(); ctx.close(); cleanup_profile_dir(profile_dir)
                raise RuntimeError("Turnstile Verification failed after submit")

            log_wait("waiting for OAuth...")
            try:
                page.wait_for_selector('button:has-text("Continue"), button:has-text("Allow")', timeout=20000)
                log_ok("OAuth page loaded")
            except:
                log_wait(f"OAuth timeout url={page.url}")
            time.sleep(1)

            # Accept cookies if banner appears after redirect
            try:
                page.get_by_role('button', name='Accept All Cookies').click(timeout=2000)
                log_ok("accepted cookies")
                time.sleep(0.5)
            except:
                pass

            # Click Continue button (if present - may auto-continue)
            try:
                page.get_by_role('button', name=re.compile(r'Continue', re.I)).click(timeout=5000)
                log_ok("clicked Continue")
                time.sleep(1)
            except Exception:
                log_wait("Continue button not found or auto-continued")

            # Click Allow button
            try:
                page.get_by_role('button', name=re.compile(r'Allow', re.I)).click(timeout=8000)
                log_ok("clicked Allow")
                time.sleep(1)
            except Exception as e:
                mail.logout(); ctx.close(); cleanup_profile_dir(profile_dir)
                raise RuntimeError(f"Allow button not found: {e}")

            # Close browser immediately after Allow
            log_ok("closing browser...")
            try:
                mail.logout()
            except Exception:
                pass
            try:
                ctx.close()
            except Exception:
                pass
            cleanup_profile_dir(profile_dir)

            # Poll 9router with retry mechanism (guaranteed delivery)
            log_wait("polling 9router (guaranteed retry)...")
            poll_success = False
            max_poll_attempts = 20  # 20 attempts × 5s = 100s max

            for attempt in range(1, max_poll_attempts + 1):
                try:
                    res = r9.poll(device_code, code_verifier)
                    if res.get('success'):
                        log_ok(f"✓ 9router import success (attempt {attempt}/{max_poll_attempts})")
                        poll_success = True
                        break
                    if not res.get('pending'):
                        # Not pending but not success = error, retry anyway
                        log_wait(f"poll error (attempt {attempt}/{max_poll_attempts}): {res.get('error', 'unknown')}, retrying...")
                        time.sleep(5)
                        continue
                    # Still pending, keep polling
                    if attempt % 5 == 0:
                        log_wait(f"still polling... (attempt {attempt}/{max_poll_attempts})")
                    time.sleep(5)
                except Exception as poll_err:
                    log_wait(f"poll exception (attempt {attempt}/{max_poll_attempts}): {poll_err}, retrying...")
                    time.sleep(5)
                    continue

            if not poll_success:
                raise RuntimeError(f"9router poll failed after {max_poll_attempts} attempts - account created but not imported!")

            # Collect cookies (browser already closed, use empty list)
            sso_cookies = []

            # Check if we have JWT token (skip - browser closed)
            jwt_found = False

            data = {
                'email': addr,
                'password': PASSWORD,
                'code': code,
                'sso_cookies': sso_cookies,
                'final_url': '',
                'timestamp': int(time.time()),
            }

            # Save to sso.txt (JSON lines)
            OUT.parent.mkdir(parents=True, exist_ok=True)
            with open(OUT, 'a') as f:
                f.write(json.dumps(data) + '\n')
            log_ok(f"saved → {OUT}")

            # Save to ~/.grok/auth.json (Grok CLI format)
            grok_dir = Path.home() / '.grok'
            grok_auth = grok_dir / 'auth.json'
            grok_dir.mkdir(parents=True, exist_ok=True)

            # Extract JWT token from sso cookie (.x.ai domain)
            jwt_token = None
            for c in sso_cookies:
                if c['name'] == 'sso' and '.x.ai' in c.get('domain', ''):
                    jwt_token = c['value']
                    break

            # Load existing auth or create new
            if grok_auth.exists():
                try:
                    grok_data = json.loads(grok_auth.read_text())
                except:
                    grok_data = {'accounts': []}
            else:
                grok_data = {'accounts': []}

            # Add account (avoid duplicates)
            existing_emails = {acc.get('email') for acc in grok_data.get('accounts', [])}
            if addr not in existing_emails:
                grok_data['accounts'].append({
                    'email': addr,
                    'token': jwt_token,
                })
                grok_auth.write_text(json.dumps(grok_data, indent=2))
                log_ok(f"saved → {grok_auth}")

        # Report proxy success
        if PROXY_POOL and proxy_key:
            PROXY_POOL.report_success({'_key': proxy_key})
            log_ok(f"proxy success: {proxy_key}")

        return data

    except Exception as e:
        # Ensure browser profile is removed even on failure
        try:
            cleanup_profile_dir(profile_dir)
        except Exception:
            pass
        # Report proxy failure
        if PROXY_POOL and proxy_key:
            soft = _is_soft_proxy_error(e) if "e" in dir() else False
            PROXY_POOL.report_failure({'_key': proxy_key}, soft=soft)
            if not soft:
                fails = PROXY_POOL._proxies.get(proxy_key, {}).get('fails', 0)
                log_no(f"proxy hard-fail: {proxy_key} ({fails}/3)")
            else:
                log_wait(f"proxy soft-fail (not blacklisted): {proxy_key}")
        raise

# ── Infinite runner ───────────────────────────────────────────
def run_accounts():
    """Run infinite or bounded account creation loop."""
    # Wipe leftover temp profiles from previous runs (disk spam fix)
    cleanup_stale_profiles(max_age_sec=0, quiet=False)

    auto_add = AUTO_ADD or '--auto-add' in sys.argv
    max_accounts = MAX_ACCOUNTS
    total = ok_n = fail_n = 0
    total_imported = 0  # Track successful 9router imports
    successful_accounts = []

    print(f"\n{CYN}{'='*74}{RST}")
    print(f"{CYN}║{RST} {BOLD}GROK SIGNUP + 9ROUTER AUTO-IMPORT{RST}")
    print(f"{CYN}{'='*74}{RST}")
    print(f"{CYN}║{RST} Mode: {'INFINITE' if max_accounts <= 0 else f'{max_accounts} accounts'}")
    print(f"{CYN}║{RST} Batch Size: {BATCH_SIZE}")
    print(f"{CYN}║{RST} Chrome: {CHROME_BIN or 'bundled'}")
    print(f"{CYN}║{RST} Mode UI: {'HEADLESS (' + HEADLESS_MODE + ')' if HEADLESS else 'HEADED (visible)'}")
    print(f"{CYN}║{RST} Auto-Import: {'YES' if auto_add else 'NO'}")
    print(f"{CYN}║{RST} Temp dir: {_temp_root()}")

    # Proxy pool stats
    if PROXY_POOL:
        stats = PROXY_POOL.get_stats()
        print(f"{CYN}║{RST} Proxy Pool: {stats['total']} total, {stats['available']} available")
    else:
        print(f"{YEL}║{RST} Proxy Pool: disabled (PROXIES env not set)")

    print(f"{CYN}║{RST} Extension: {TS_DIR}")
    print(f"{CYN}║{RST} SCTG: {'YES key set' if SCTG_API_KEY else 'NO (extension only)'}")
    if SCTG_API_KEY:
        print(f"{CYN}║{RST} SCTG mode: timeout={SCTG_TIMEOUT}s × retries={SCTG_RETRIES}")
    print(f"{CYN}║{RST} Account Retries: {MAX_ACCOUNT_RETRIES}")
    print(f"{CYN}║{RST} Delay Between Accounts: {DELAY_SECONDS}s")
    print(f"{CYN}║{RST} Pause Between Batches: {PAUSE_SECONDS}s")

    # Diagnostic: check extension files
    if (TS_DIR / 'manifest.json').exists():
        print(f"{GRN}║{RST} ✓ turnstilePatch extension found")
    else:
        print(f"{RED}║{RST} ✗ turnstilePatch extension MISSING")

    print(f"{CYN}{'='*74}{RST}\n")

    while max_accounts <= 0 or total < max_accounts:
        batch_target = min(BATCH_SIZE, (max_accounts - total) if max_accounts > 0 else BATCH_SIZE)
        batch_imported = 0  # Track imports in this batch

        print(f"\n{CYN}┌─ BATCH #{(total // BATCH_SIZE) + 1} ─{'─'*58}{RST}")

        for i in range(batch_target):
            total += 1
            t0 = time.time()
            email_code_pair = None
            last_ex = None

            print(f"{CYN}│{RST} [{total}] Starting account creation...")

            for attempt in range(1, MAX_ACCOUNT_RETRIES + 1):
                try:
                    acc = signup_one(email_code_pair)
                    ok_n += 1
                    elapsed = time.time() - t0
                    print(f"{GRN}│ ✓{RST} [{total}] {acc['email']} → imported in {elapsed:.1f}s")
                    total_imported += 1
                    batch_imported += 1

                    if auto_add:
                        successful_accounts.append(acc)
                    break
                except TurnstileRetry as e:
                    email_code_pair = (e.mail, e.code)
                    last_ex = e
                    log_no(f"[{total}] Turnstile retry {attempt}/{MAX_ACCOUNT_RETRIES}")
                except Exception as e:
                    last_ex = e
                    fail_n += 1
                    print(f"{RED}│ ✗{RST} [{total}] Failed: {e}")
                    break
            else:
                # Retries exhausted
                fail_n += 1
                print(f"{RED}│ ✗{RST} [{total}] Failed after {MAX_ACCOUNT_RETRIES} retries")

            if i < batch_target - 1:
                print(f"{CYN}│{RST} Delaying {DELAY_SECONDS}s before next account...")
                time.sleep(DELAY_SECONDS)

        # Batch summary
        print(f"{CYN}└─{'─'*70}{RST}")
        print(f"\n{GRN}■{RST} Batch Summary:")
        print(f"  ├─ Imported: {batch_imported}/{batch_target}")
        print(f"  ├─ Failed: {batch_target - batch_imported}")
        print(f"  └─ Total Imported (all batches): {GRN}{total_imported}{RST}")

        # Proxy pool stats
        if PROXY_POOL:
            stats = PROXY_POOL.get_stats()
            print(f"\n{CYN}■{RST} Proxy Pool Stats:")
            print(f"  ├─ Available: {GRN}{stats['available']}{RST}/{stats['total']}")
            print(f"  └─ Blacklisted: {RED}{stats['blacklisted']}{RST}")

        print(f"\n{CYN}■{RST} Overall Stats:")
        print(f"  ├─ Total Attempts: {total}")
        print(f"  ├─ Successful: {GRN}{ok_n}{RST}")
        print(f"  ├─ Failed: {RED}{fail_n}{RST}")
        print(f"  └─ Success Rate: {int(ok_n/total*100) if total else 0}%")

        if max_accounts > 0 and total >= max_accounts:
            break

        if max_accounts <= 0 or total < max_accounts:
            print(f"\n{YEL}→{RST} Sleeping {PAUSE_SECONDS}s before next batch...\n")
            time.sleep(PAUSE_SECONDS)

    print(f"\n{CYN}{'='*74}{RST}")
    print(f"{CYN}║{RST} {BOLD}FINAL REPORT{RST}")
    print(f"{CYN}{'='*74}{RST}")
    print(f"{GRN}║{RST} Total Imported to 9router: {GRN}{BOLD}{total_imported}{RST}")
    print(f"{GRN}║{RST} Success: {ok_n}  |  {RED}Failed: {fail_n}{RST}  |  Total: {total}")
    print(f"{CYN}{'='*74}{RST}\n")

# ── CLI ───────────────────────────────────────────────────────
if __name__ == '__main__':
    try:
        # Optional: python ... --clean-temp  → only wipe stale profiles then exit
        if '--clean-temp' in sys.argv:
            n = cleanup_stale_profiles(max_age_sec=0, quiet=False)
            print(f"cleaned {n} profile folder(s) under {_temp_root()}")
            sys.exit(0)
        run_accounts()
    except KeyboardInterrupt:
        print(f"\n{YEL}stopped by user{RST}")
        # best-effort wipe any leftover profiles from this session
        try:
            cleanup_stale_profiles(max_age_sec=0, quiet=False)
        except Exception:
            pass
