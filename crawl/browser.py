"""Playwright session, network-layer scope lock, fetch + expand paths.

Security posture (ADR 0001): scope is enforced at the *network layer* — a
route interceptor on the browser context aborts every page request whose
(scheme, host, port) is not the target triple, so Basic Auth credentials
physically cannot leave the target host during rendering. During Tier 2
interaction the interceptor additionally aborts non-GET requests (logged as
`blocked_mutation`).

Defense in depth: the *fetch* path (`context.request.get`) is NOT covered by
`context.route`, so `fetch()` re-checks scope itself before issuing the
request — credentials cannot leak even if the frontier has a bug.

Fetch vs. expand (design §3/§6):
- fetch: obtain a resource's bytes via the API request context — never
  browser-rendered, so Chromium's synthetic wrapper documents cannot pollute
  the edge graph. Every in-scope resource is fetched.
- expand: render a 2xx HTML page in a real browser page and run discovery
  tiers (Tier 0 DOM harvest, Tier 1 passive observation). Only 2xx HTML is
  expanded.

Fetch discipline (design §6/§11): GET-only, serial, 250–500ms politeness
delay, identifying User-Agent. 4xx is terminal immediately (the server
answered); timeouts, 5xx, and connection resets get exactly one retry,
attempted after the queue drains.
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field

from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from .normalize import ScopeTriple, canon_key, in_scope, resolve

log = logging.getLogger("crawl.browser")

TRANSIENT_STATUSES = {500, 502, 503, 504}

# Milliseconds to wait for networkidle after domcontentloaded before
# proceeding anyway and flagging `idle_timeout` (design: canonical snapshot
# moment, ~3–5s bounded wait).
IDLE_TIMEOUT_MS = 4_000

# Init script installed before page scripts run (Tier 1 + tripwires).
# - patches navigation APIs to record intended URLs (js_navigation edges)
# - hard navigations are recorded then swallowed (window.open returns a dummy)
# - same-document history mutations are passed through
# - patches attachShadow to record closed roots at attach time
# - installs a MutationObserver logging post-snapshot mutations
INIT_SCRIPT = r"""
(() => {
  window.__navIntents = [];
  window.__closedShadowRoots = 0;
  window.__lateMutations = 0;
  window.__snapshotTaken = false;

  const record = (kind, url) => {
    try { window.__navIntents.push({kind, url: String(url)}); } catch (e) {}
  };

  const origAssign = location.assign.bind(location);
  const origReplace = location.replace.bind(location);
  try {
    location.assign = (u) => { record('assign', u); };
    location.replace = (u) => { record('replace', u); };
  } catch (e) {}
  const origOpen = window.open.bind(window);
  window.open = (u, ...rest) => { record('open', u); return { closed: true, close(){}, focus(){}, blur(){} }; };
  const origPush = history.pushState.bind(history);
  const origReplaceState = history.replaceState.bind(history);
  history.pushState = (s, t, u) => { if (u) record('pushState', u); return origPush(s, t, u); };
  history.replaceState = (s, t, u) => { if (u) record('replaceState', u); return origReplaceState(s, t, u); };

  const origAttach = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function(init) {
    if (init && init.mode === 'closed') window.__closedShadowRoots++;
    return origAttach.call(this, init);
  };

  // Service worker registration (ADR 0002): record the call site as a
  // discovery intent. The worker is registered for real — it's in-scope,
  // and blocking it would be a crawl-visible behavior change — but the
  // precache inventory is read out of sw.js source text, never executed.
  try {
    const origReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register = (u, ...rest) => { record('sw_register', u); return origReg(u, ...rest); };
  } catch (e) {}

  const mo = new MutationObserver(() => {
    if (window.__snapshotTaken) window.__lateMutations++;
  });
  mo.observe(document.documentElement, {childList: true, subtree: true, attributes: true, characterData: true});
})();
"""


@dataclass
class FetchResult:
    ok: bool
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    final_url: str = ""
    error: str = ""  # reason when ok=False
    transient: bool = False  # eligible for the single retry


@dataclass
class DiscoveredURL:
    verbatim: str  # absolute URL as discovered (never fabricated)
    how: str  # discovery mechanism (design §5 edge vocabulary)
    hint: str = ""  # anchor text / alt text / selector / key path


@dataclass
class ExpandResult:
    ok: bool
    rendered_html: bytes = b""
    discovered: list[DiscoveredURL] = field(default_factory=list)
    idle_timeout: bool = False
    late_mutations: int = 0
    closed_shadow_roots: int = 0
    shadow_root_count: int = 0
    unexplained_interactives: int = 0
    base_href: str = ""  # document base actually used for resolution
    error: str = ""


class CrawlBrowser:
    def __init__(
        self,
        scope: ScopeTriple,
        username: str,
        password: str,
        *,
        user_agent: str = "visualping-challenge-crawler/1.0 (research; +https://visualping.io)",
        delay_range: tuple[float, float] = (0.25, 0.5),
        get_only: bool = True,
        timeout_ms: int = 30_000,
    ):
        self.scope = scope
        self.username = username
        self.password = password
        self.user_agent = user_agent
        self.delay_range = delay_range
        self.get_only = get_only
        self.timeout_ms = timeout_ms

        self.blocked_out_of_scope: list[str] = []
        self.blocked_mutations: list[dict] = []  # Tier 2 findings

        self._pw = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None

    # -- lifecycle -----------------------------------------------------------

    def __enter__(self) -> "CrawlBrowser":
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._context = self._browser.new_context(
            user_agent=self.user_agent,
            http_credentials={"username": self.username, "password": self.password},
            ignore_https_errors=False,
        )
        self._context.route("**/*", self._intercept)
        self._context.add_init_script(INIT_SCRIPT)
        return self

    def __exit__(self, *exc) -> None:
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._pw:
            self._pw.stop()

    # -- network-layer scope lock (ADR 0001) ---------------------------------

    def _intercept(self, route) -> None:
        request = route.request
        url = request.url
        if not in_scope(url, self.scope):
            self.blocked_out_of_scope.append(url)
            log.debug("network-layer blocked out-of-scope: %s", url)
            route.abort()
            return
        if self.get_only and request.method != "GET":
            self.blocked_mutations.append({"url": url, "method": request.method})
            log.warning("network-layer blocked non-GET %s %s (blocked_mutation)",
                        request.method, url)
            route.abort()
            return
        route.continue_()

    # -- fetch path (API request context; no rendering) ----------------------

    def fetch(self, url: str) -> FetchResult:
        """One GET through the API request context. The verbatim URL goes on
        the wire. Scope is re-checked here because context.route does NOT
        cover the API request context — defense in depth for ADR 0001."""
        if not in_scope(url, self.scope):
            return FetchResult(ok=False, error="out_of_scope (refused at harness)")
        self._polite_delay()
        assert self._context is not None
        try:
            response = self._context.request.get(url, timeout=self.timeout_ms)
        except Exception as e:  # timeouts, connection resets — transient class
            return FetchResult(ok=False, error=f"{type(e).__name__}: {e}", transient=True)
        body = response.body()
        status = response.status
        final_url = response.url
        headers = {k.lower(): v for k, v in response.headers.items()}
        if status in TRANSIENT_STATUSES:
            return FetchResult(
                ok=False, status=status, headers=headers, body=body,
                final_url=final_url, error=f"HTTP {status}", transient=True,
            )
        return FetchResult(
            ok=True, status=status, headers=headers, body=body, final_url=final_url
        )

    # -- expand path (real page render; Tier 0 + Tier 1) ---------------------

    def expand(self, url: str) -> ExpandResult:
        """Render a 2xx HTML page in a fresh page and run discovery tiers.

        Canonical snapshot moment: domcontentloaded, then a bounded wait for
        networkidle (IDLE_TIMEOUT_MS); on timeout harvest anyway and flag
        `idle_timeout`. Immediately after the harvest the rendered DOM is
        serialized (returned as `rendered_html`) and the MutationObserver
        tripwire starts counting late mutations.
        """
        if not in_scope(url, self.scope):
            return ExpandResult(ok=False, error="out_of_scope (refused at harness)")
        assert self._context is not None
        self._polite_delay()
        page = self._context.new_page()
        result = ExpandResult(ok=True)
        xhr_urls: list[str] = []

        def on_response(response) -> None:
            try:
                rtype = response.request.resource_type
            except Exception:
                rtype = ""
            if rtype in ("xhr", "fetch") or (
                response.url != url and rtype not in
                ("document", "stylesheet", "image", "script", "font", "media")
            ):
                if response.url and response.url != url:
                    xhr_urls.append(response.url)

        page.on("response", on_response)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=IDLE_TIMEOUT_MS)
            except Exception:
                result.idle_timeout = True

            harvest = page.evaluate(TIER0_HARVEST_JS)
            result.base_href = harvest.get("base") or page.url
            result.shadow_root_count = harvest.get("shadowRoots", 0)
            result.unexplained_interactives = harvest.get("interactives", 0)
            raw = harvest.get("urls", [])

            # Snapshot the rendered DOM, then arm the late-mutation tripwire.
            result.rendered_html = page.content().encode("utf-8")
            page.evaluate("() => { window.__snapshotTaken = true; }")

            nav_intents = page.evaluate("() => window.__navIntents || []")
            result.closed_shadow_roots = page.evaluate("() => window.__closedShadowRoots || 0")
            result.late_mutations = page.evaluate("() => window.__lateMutations || 0")

            base = result.base_href
            for item in raw:
                ref, how, hint = item.get("ref", ""), item.get("how", ""), item.get("hint", "")
                absolute = resolve(base, ref)
                if absolute is None:
                    continue
                result.discovered.append(DiscoveredURL(absolute, how, hint))
            for intent in nav_intents:
                absolute = resolve(base, intent.get("url", ""))
                if absolute is not None:
                    result.discovered.append(
                        DiscoveredURL(absolute, "js_navigation", intent.get("kind", ""))
                    )
            for x in xhr_urls:
                result.discovered.append(DiscoveredURL(x, "xhr", "page.on(response)"))
        except Exception as e:
            result.ok = False
            result.error = f"{type(e).__name__}: {e}"
        finally:
            page.close()
        return result

    def _polite_delay(self) -> None:
        time.sleep(random.uniform(*self.delay_range))


# Tier 0 DOM harvest — one pass over the rendered DOM at the canonical
# snapshot moment. Recursively descends OPEN shadow roots. Collects
# <base href> first, then every URL-bearing attribute. Returns plain data;
# resolution against the base happens on the Python side.
TIER0_HARVEST_JS = r"""
() => {
  const out = {base: null, urls: [], shadowRoots: 0, interactives: 0};
  const baseEl = document.querySelector('base[href]');
  if (baseEl) out.base = baseEl.getAttribute('href');

  const ATTRS = [
    ['href', 'a_href'], ['src', 'img_src'], ['srcset', 'srcset'],
    ['action', 'form_action'], ['data', 'object_data'], ['poster', 'poster'],
  ];
  const TAGHOW = {A:'a_href', AREA:'area_href', IMG:'img_src', SCRIPT:'script_src',
                  IFRAME:'iframe_src', EMBED:'embed_src', OBJECT:'object_data',
                  LINK:'link_rel', SOURCE:'picture_source', FORM:'form_action',
                  TRACK:'track_src', VIDEO:'video_src', AUDIO:'audio_src'};

  const push = (ref, how, hint) => { if (ref) out.urls.push({ref, how, hint}); };

  const walk = (root) => {
    const els = root.querySelectorAll('*');
    for (const el of els) {
      if (el.shadowRoot) { out.shadowRoots++; walk(el.shadowRoot); }
      const tag = el.tagName;
      if (tag === 'BASE') continue;  // the base itself is context, not a reference
      for (const [attr, how] of ATTRS) {
        const v = el.getAttribute(attr);
        if (!v) continue;
        if (attr === 'srcset') {
          // Candidates are comma-separated "url descriptor" pairs.
          for (const cand of v.split(',')) {
            const u = cand.trim().split(/\s+/)[0];
            push(u, 'srcset', (el.getAttribute('alt') || '').slice(0, 80));
          }
          continue;
        }
        const useHow = (attr === 'src' || attr === 'href' || attr === 'data') && TAGHOW[tag] ? TAGHOW[tag] : how;
        // <link> has no text content; the rel value IS the hint — rel=alternate
        // vs rel=icon is exactly the distinction the report should show.
        const hint = tag === 'LINK' ? (el.getAttribute('rel') || '')
                                    : (el.textContent || '').trim().slice(0, 80);
        push(v, useHow, hint);
      }
      const style = el.getAttribute('style');
      if (style && /url\s*\(/.test(style)) {
        for (const m of style.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)) {
          push(m[1], 'css_url', 'inline style');
        }
      }
      for (const attr of el.attributes) {
        if (attr.name.startsWith('data-') && /^[./\w-]+\/[\w./-]+$/.test(attr.value)) {
          push(attr.value, 'data_attr', attr.name);
        }
      }
    }
    // meta refresh
    for (const m of root.querySelectorAll('meta[http-equiv="refresh" i]')) {
      const c = m.getAttribute('content') || '';
      const um = c.match(/url\s*=\s*([^;]+)/i);
      if (um) push(um[1].trim(), 'meta_refresh', c.slice(0, 80));
    }
  };
  walk(document);

  // Unexplained interactives: clickable-looking elements (Tier 2 trigger).
  const clickable = document.querySelectorAll('[role="button"], [onclick]');
  out.interactives = clickable.length + (function(){
    let n = 0;
    for (const el of document.querySelectorAll('*')) {
      try { if (getComputedStyle(el).cursor === 'pointer') n++; } catch (e) {}
    }
    return n;
  })();

  return out;
}
"""
