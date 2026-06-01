"""
Ajax Spider — headless Chromium crawler for JavaScript-heavy SPAs.
Uses Playwright if available; gracefully disabled if not installed.

Captures:
- All pages navigated to (multi-tab concurrent crawling)
- All form inputs (rendered by JS, not just HTML)
- XHR / fetch network requests → additional InputSurface objects
- Links discovered after JS execution
- WebSocket endpoints (ws:// / wss://)

Multi-tab: 3 concurrent Playwright instances via producer-consumer queue.
Each tab runs its own sync_playwright() (thread-safe per Playwright Python docs).

To install: pip install playwright && playwright install chromium
"""
from __future__ import annotations

import base64
import json
import logging
import queue as _queue
import re
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .crawler import InputSurface, SiteMap
from .scope import ScopeManager
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout


def _launch_browser(pw, headless: bool = True):
    """Launch Chromium with Firefox and Webkit fallbacks.

    Tries Chromium first (fastest, most compatible).
    Falls back to Firefox if Chromium is not installed.
    Falls back to Webkit (Safari engine) as a last resort.

    Returns:
        playwright Browser instance.
    Raises:
        RuntimeError if all three browsers fail to launch.
    """
    import logging as _logging
    _log = _logging.getLogger("dast.browser")

    # --no-sandbox + --disable-dev-shm-usage are required when Chromium runs
    # inside a forked process (gunicorn gthread workers) or a container.
    # Without them, Chromium's sandbox kills the worker with SIGSEGV.
    _chromium_args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--ignore-certificate-errors",
    ]

    for browser_type, name in [
        (pw.chromium, "chromium"),
        (pw.firefox,  "firefox"),
        (pw.webkit,   "webkit"),
    ]:
        try:
            launch_kwargs = {"headless": headless}
            if name == "chromium":
                launch_kwargs["args"] = _chromium_args
            b = browser_type.launch(**launch_kwargs)
            if name != "chromium":
                _log.info("[Browser] Chromium unavailable — using %s fallback", name)
            return b
        except Exception as exc:
            _log.debug("[Browser] %s launch failed: %s", name, exc)
            continue

    raise RuntimeError(
        "No Playwright browser available. "
        "Run: playwright install chromium  (or firefox / webkit)"
    )
PLAYWRIGHT_AVAILABLE = True


# ── Reusable JS snippets ──────────────────────────────────────────────────────

_JS_FORMS = """() => {
    return Array.from(document.querySelectorAll('form')).map(f => ({
        action: f.action || window.location.href,
        method: (f.method || 'get').toUpperCase(),
        inputs: Array.from(f.querySelectorAll(
            'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]),' +
            ' select, textarea'
        )).map(i => ({
            name:  i.name  || i.id || '',
            type:  i.type  || 'text',
            value: i.value || ''
        })).filter(i => i.name)
    }));
}"""

_JS_LINKS = """() => {
    const urls = new Set();
    // Anchor tags
    for (const el of document.querySelectorAll('a[href], area[href]')) {
        if (el.href && el.href.startsWith('http')) urls.add(el.href);
    }
    // data-href / data-url on any element
    for (const el of document.querySelectorAll('[data-href],[data-url],[data-link],[data-endpoint]')) {
        const v = el.getAttribute('data-href') || el.getAttribute('data-url') ||
                  el.getAttribute('data-link') || el.getAttribute('data-endpoint') || '';
        if (v.startsWith('http') || v.startsWith('/')) urls.add(v);
    }
    // button[formaction] overrides enclosing form action
    for (const el of document.querySelectorAll('button[formaction], input[formaction]')) {
        const fa = el.getAttribute('formaction') || '';
        try { if (fa) urls.add(new URL(fa, location.href).href); } catch(e) {}
    }
    // onclick / ng-click / v-on (extract URL-like strings)
    for (const el of document.querySelectorAll('[onclick],[ng-click],[v-on\\\\:click],[@click]')) {
        const attr = el.getAttribute('onclick') || el.getAttribute('ng-click') || '';
        const m = attr.match(/['"](\\/[^'"]{2,80})['"]|href\s*=\s*['"]([^'"]{4,80})['"]/);
        if (m) { try { urls.add(new URL(m[1]||m[2], location.href).href); } catch(e) {} }
    }
    return Array.from(urls).filter(u => u.startsWith('http'));
}"""

# ── Sprint 4: Full SPA crawling JS snippets ──────────────────────────────────

_JS_CLICKABLES = """() => {
    const seen = new Set();
    const results = [];
    const sels = [
        'button:not([type=submit]):not([type=reset])',
        '[role="button"]', '[role="tab"]', '[role="menuitem"]',
        '[role="link"]', '[ng-click]', '[v-on\\\\:click]', '[@click]',
        '[data-toggle]', '[data-bs-toggle]', '[onclick]',
        '.nav-link', '.tab', '.accordion-header', '.expandable',
        '[aria-haspopup]', '[aria-expanded]',
        'details > summary',
    ];
    for (const sel of sels) {
        try {
            for (const el of document.querySelectorAll(sel)) {
                if (!el.offsetParent && el.offsetWidth === 0) continue;
                const sig = el.tagName + '|' + (el.id || '') + '|' +
                    (el.className || '').toString().slice(0, 60) + '|' +
                    (el.textContent || '').trim().slice(0, 30);
                if (seen.has(sig)) continue;
                seen.add(sig);
                results.push({
                    selector: el.id ? '#' + el.id :
                        (el.getAttribute('data-testid') ? '[data-testid="' + el.getAttribute('data-testid') + '"]' :
                        null),
                    tag: el.tagName,
                    text: (el.textContent || '').trim().slice(0, 40),
                    sig: sig,
                    index: results.length
                });
            }
        } catch(e) {}
    }
    return results.slice(0, 20);
}"""

_JS_SHADOW_DOM = """() => {
    const results = {links: [], forms: []};
    function walk(root) {
        for (const el of root.querySelectorAll('*')) {
            if (el.shadowRoot) {
                for (const a of el.shadowRoot.querySelectorAll('a[href]')) {
                    if (a.href && a.href.startsWith('http')) results.links.push(a.href);
                }
                for (const f of el.shadowRoot.querySelectorAll('form')) {
                    results.forms.push({
                        action: f.action || window.location.href,
                        method: (f.method || 'get').toUpperCase(),
                        inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                            .map(i => ({name: i.name||i.id||'', type: i.type||'text'}))
                            .filter(i => i.name)
                    });
                }
                walk(el.shadowRoot);
            }
        }
    }
    walk(document);
    return results;
}"""

_JS_EXTRACT_ROUTES = r"""() => {
    const routes = new Set();
    const patterns = [
        /path\s*:\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
        /component\s*:\s*\w+.*?path\s*:\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
        /['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]\s*:\s*\{.*?component/g,
        /Route\s+.*?path=["'](\/?[a-zA-Z0-9\/:_-]{2,60})["']/g,
        /router\.(get|post|put|delete)\s*\(\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
        /navigate\s*\(\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
        /this\.\$router\.push\s*\(\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
        /href:\s*['"](\/?[a-zA-Z0-9\/:_-]{2,60})['"]/g,
    ];
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        if (text.length < 20 || text.length > 500000) continue;
        for (const pat of patterns) {
            pat.lastIndex = 0;
            let m;
            while ((m = pat.exec(text)) !== null) {
                const route = m[m.length > 2 ? 2 : 1];
                if (route && !route.includes('{{') && !route.startsWith('//'))
                    routes.add(route);
            }
        }
    }
    return Array.from(routes).slice(0, 50);
}"""

_JS_HASH_LINKS = """() => {
    const hashes = new Set();
    // 1. Anchor tags with hash routes (broad: any # followed by / or ! or word chars)
    for (const a of document.querySelectorAll('a[href*="#"]')) {
        const h = a.getAttribute('href') || '';
        const frag = h.split('#')[1] || '';
        if (frag.startsWith('/') || frag.startsWith('!') ||
            /^[a-z][-a-z0-9]*[=/]/.test(frag)) {
            hashes.add(h);
        }
    }
    // 2. Current location hash
    const loc = window.location;
    if (loc.hash && loc.hash.length > 2) hashes.add(loc.href);

    // 3. Programmatic hash routes in inline JS (Angular, Ember, Backbone, etc.)
    const hashPats = [
        /location\.hash\s*=\s*['"`](#?\/?[a-zA-Z][-a-zA-Z0-9/.:_=&?]*?)['"`]/g,
        /window\.location\s*=\s*['"`]([^'"`]*#\/?[a-zA-Z][-a-zA-Z0-9/.:_=&?]*)['"`]/g,
        /\$location\.path\s*\(\s*['"`](\/?[a-zA-Z][-a-zA-Z0-9/:_]*)['"`]/g,
        /router\.navigate\s*\(\s*\[?\s*['"`](\/?[a-zA-Z][-a-zA-Z0-9/:_]*)['"`]/g,
        /this\.\$router\.push\s*\(\s*['"`](\/?[a-zA-Z][-a-zA-Z0-9/:_]*)['"`]/g,
        /Backbone\.history\.navigate\s*\(\s*['"`]([a-zA-Z][-a-zA-Z0-9/:_]*)['"`]/g,
        /['"`](#\/?[a-zA-Z][-a-zA-Z0-9/.:_=&?]{2,60})['"`]/g,
    ];
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        if (text.length < 20 || text.length > 300000) continue;
        for (const pat of hashPats) {
            pat.lastIndex = 0;
            let m;
            while ((m = pat.exec(text)) !== null) {
                const route = m[1];
                if (route && !route.includes('{{') && !route.includes('${'))
                    hashes.add(route.startsWith('#') ? route : '#/' + route);
            }
        }
    }
    // 4. data-* attributes with hash routes
    for (const el of document.querySelectorAll('[data-route],[data-page],[data-view],[data-state]')) {
        const val = el.getAttribute('data-route') || el.getAttribute('data-page') ||
                    el.getAttribute('data-view') || el.getAttribute('data-state') || '';
        if (val) hashes.add(val.startsWith('#') ? val : '#/' + val);
    }
    return Array.from(hashes).slice(0, 50);
}"""

_JS_HISTORY_INTERCEPT = """() => {
    // Intercept pushState/replaceState to capture SPA navigations
    const captured = [];
    if (!window.__dast_history_hooked) {
        const origPush = history.pushState;
        const origReplace = history.replaceState;
        window.__dast_captured_routes = [];
        history.pushState = function(state, title, url) {
            if (url) window.__dast_captured_routes.push(String(url));
            return origPush.apply(this, arguments);
        };
        history.replaceState = function(state, title, url) {
            if (url) window.__dast_captured_routes.push(String(url));
            return origReplace.apply(this, arguments);
        };
        window.__dast_history_hooked = true;
    }
    const routes = [...(window.__dast_captured_routes || [])];
    window.__dast_captured_routes = [];
    return routes;
}"""

_JS_STORAGE = """() => {
    const data = {localStorage: {}, sessionStorage: {}};
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            data.localStorage[k] = localStorage.getItem(k).slice(0, 500);
        }
    } catch(e) {}
    try {
        for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            data.sessionStorage[k] = sessionStorage.getItem(k).slice(0, 500);
        }
    } catch(e) {}
    return data;
}"""

_JS_DOM_SIGNATURE = """() => {
    return document.querySelectorAll('a[href],form,button,input,select,textarea,[role]').length
        + '|' + (document.body ? document.body.innerHTML.length : 0);
}"""

# Patterns that suggest sensitive data in browser storage
_STORAGE_SENSITIVE_RE = re.compile(
    r"(?:token|jwt|session|auth|secret|api.?key|password|credential|bearer)",
    re.IGNORECASE,
)

# ── Sprint 5: Beyond Burp/ZAP — unique capabilities ──────────────────────────

_JS_API_ENDPOINTS = r"""() => {
    // Returns [{url, method}] tuples with inferred HTTP method
    const apis = new Map();  // url -> method
    const add = (url, method) => {
        if (!url || url.length < 4 || url.length > 300) return;
        if (url.includes('{{') || url.includes('${')) return;
        // Exclusion filter: skip CDN assets, analytics, fonts, images
        if (/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp[34]|wasm)(\?|$)/i.test(url)) return;
        if (/google[_-]?analytics|googletagmanager|gtag\/|facebook\.net|fbevents|hotjar|segment\.(io|com)|mixpanel|amplitude|sentry\.io|newrelic|cloudflare-static/i.test(url)) return;
        if (!apis.has(url)) apis.set(url, method || 'GET');
    };

    // ── Pattern groups: [regex, captureGroup, method] ──
    const patterns = [
        // 1. fetch() — detect method from options if present
        [/fetch\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]\s*,\s*\{[^}]*method\s*:\s*['"](\w+)['"]/g, 1, null, 2],
        [/fetch\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 2. axios methods
        [/axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        [/axios\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`\s$]{5,200})['"`][^}]*method\s*:\s*['"](\w+)['"]/g, 1, null, 2],
        [/axios\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 3. jQuery AJAX
        [/\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`\s$]{5,200})['"`][^}]*(?:type|method)\s*:\s*['"](\w+)['"]/g, 1, null, 2],
        [/\$\.(get|post|getJSON|put)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 4. XMLHttpRequest
        [/\.open\s*\(\s*['"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 5. Angular HttpClient
        [/(?:this\.)?(?:http|_http|httpClient)\s*\.\s*(get|post|put|patch|delete|head|options)\s*(?:<[^>]*>)?\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 6. Vue $http / $resource
        [/(?:this\.)?\$http\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        [/\$resource\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 7. superagent
        [/superagent\s*\.\s*(get|post|put|patch|del(?:ete)?)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 8. ky library
        [/ky\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 9. got library (sometimes bundled in frontend)
        [/got\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 2, null, 1],
        // 10. SWR / React Query / TanStack query hooks
        [/use(?:SWR|Query|InfiniteQuery)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        [/useMutation\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'POST'],
        // 11. RTK Query / createApi endpoints
        [/query\s*:\s*(?:\([^)]*\)\s*=>|function)\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        [/mutation\s*:\s*(?:\([^)]*\)\s*=>|function)\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'POST'],
        // 12. API/endpoint/base URL variable assignments
        [/(?:api|endpoint|base|server|backend)\s*(?:Url|URL|_url|Uri|URI|Path|_path|_endpoint|_base|Host|_host)\s*[:=]\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 13. Config object patterns
        [/(?:config|env|environment|settings)\s*\.\s*(?:api|endpoint|base|server|backend)\s*(?:Url|URL|_url|Uri|Path|Base|Host)?\s*[:=]\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 14. href/src/action pointing to /api/
        [/(?:href|src|action|url)\s*[:=]\s*['"`](\/api\/[^'"`\s$]{3,200})['"`]/g, 1, 'GET'],
        // 15. new URL / new Request
        [/new\s+(?:URL|Request)\s*\(\s*['"`]([^'"`\s$]{5,200})['"`]/g, 1, 'GET'],
        // 16. Relative API paths (api/v1/..., api/v2/..., rest/...)
        [/['"`]((?:api|rest|graphql|v[1-9])\/[a-zA-Z0-9/_-]{3,120})['"`]/g, 1, 'GET'],
        // 17. Express/Koa/Hapi route definitions (server-side in SSR bundles)
        [/(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`\s$]{3,200})['"`]/g, 2, null, 1],
        // 18. WebSocket URL patterns
        [/new\s+WebSocket\s*\(\s*['"`](wss?:\/\/[^'"`\s$]{5,200})['"`]/g, 1, 'WS'],
        // 19. Base URL + path concatenation: baseUrl + '/users'
        [/(?:base|api|server|endpoint|backend)(?:Url|URL|_url|Uri|Path|Host)?\s*\+\s*['"`](\/[^'"`\s$]{2,120})['"`]/g, 1, 'GET'],
        // 20. Template literal concatenation: `${baseUrl}/users`
        [/`\$\{[^}]+\}(\/[a-zA-Z0-9/_-]{2,120})`/g, 1, 'GET'],
    ];

    // Scan a text block with all patterns
    function scanText(text) {
        if (!text || text.length < 10 || text.length > 1000000) return;
        for (const spec of patterns) {
            const pat = spec[0];
            const urlGroup = spec[1];
            const defaultMethod = spec[2];
            const methodGroup = spec[3] || 0;
            pat.lastIndex = 0;
            let m;
            while ((m = pat.exec(text)) !== null) {
                const ep = m[urlGroup];
                const method = methodGroup && m[methodGroup]
                    ? m[methodGroup].toUpperCase()
                    : (defaultMethod || 'GET');
                add(ep, method === 'DEL' ? 'DELETE' : method);
            }
        }
    }

    // 1. Scan inline scripts
    for (const script of document.querySelectorAll('script:not([src])')) {
        scanText(script.textContent);
    }

    // 2. Scan external same-origin scripts (async fetch with sync result via cache)
    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src)
        .filter(s => {
            try { return new URL(s).origin === location.origin; } catch(e) { return false; }
        })
        .slice(0, 30);  // cap external scripts to avoid slowdown

    for (const src of scriptSrcs) {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', src, false);  // synchronous — same-origin only
            xhr.send();
            if (xhr.status === 200) scanText(xhr.responseText);
        } catch(e) {}
    }

    // 3. Scan window.__NEXT_DATA__ / __NUXT__ / __APP_CONFIG__ for API URLs
    for (const globalKey of ['__NEXT_DATA__', '__NUXT__', '__APP_CONFIG__', '__remixContext']) {
        try {
            const obj = window[globalKey];
            if (obj) {
                const json = JSON.stringify(obj).slice(0, 200000);
                const urlPat = /(?:https?:\/\/[^\s"'`,}{]{5,200}|\/api\/[^\s"'`,}{]{3,150})/g;
                let m;
                while ((m = urlPat.exec(json)) !== null) {
                    add(m[0], 'GET');
                }
            }
        } catch(e) {}
    }

    // Convert to array of {url, method} objects
    const result = [];
    for (const [url, method] of apis) {
        result.push({url, method});
    }
    return result.slice(0, 200);
}"""

_JS_SERVICE_WORKERS = """() => {
    const urls = [];
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
        urls.push(navigator.serviceWorker.controller.scriptURL);
    }
    for (const link of document.querySelectorAll('link[rel="serviceworker"]')) {
        if (link.href) urls.push(link.href);
    }
    const swPatterns = /(?:navigator\.serviceWorker\.register|ServiceWorkerContainer\.register)\s*\(\s*['"`]([^'"`]+)['"`]/g;
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        let m;
        while ((m = swPatterns.exec(text)) !== null) {
            urls.push(new URL(m[1], window.location.origin).href);
        }
    }
    return [...new Set(urls)].slice(0, 10);
}"""

_JS_EVENT_LISTENERS = """() => {
    const listeners = [];
    const interesting = ['message', 'postMessage', 'hashchange', 'popstate', 'storage'];
    try {
        const entries = getEventListeners ? getEventListeners(window) : {};
        for (const [type, handlers] of Object.entries(entries)) {
            if (interesting.includes(type)) {
                listeners.push({type, count: handlers.length});
            }
        }
    } catch(e) {}
    // Fallback: check for addEventListener calls in inline scripts
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        for (const evt of interesting) {
            if (text.includes("'" + evt + "'") || text.includes('"' + evt + '"')) {
                listeners.push({type: evt, count: 1, source: 'inline'});
            }
        }
    }
    return listeners;
}"""

_JS_DATA_ATTRIBUTES = """() => {
    const urls = new Set();
    const attrs = ['data-api', 'data-url', 'data-endpoint', 'data-href',
                   'data-src', 'data-action', 'data-fetch', 'data-resource',
                   'data-ajax', 'data-remote', 'data-link', 'data-target-url'];
    for (const attr of attrs) {
        for (const el of document.querySelectorAll('[' + attr + ']')) {
            const val = el.getAttribute(attr);
            if (val && val.length > 3 && (val.startsWith('/') || val.startsWith('http')))
                urls.add(val);
        }
    }
    return Array.from(urls).slice(0, 40);
}"""

_JS_PREFETCH_LINKS = """() => {
    const urls = [];
    for (const link of document.querySelectorAll(
        'link[rel="prefetch"], link[rel="preload"], link[rel="preconnect"], link[rel="dns-prefetch"], link[rel="modulepreload"]'
    )) {
        if (link.href) urls.push({url: link.href, rel: link.rel, as: link.getAttribute('as') || ''});
    }
    return urls;
}"""

_JS_META_REDIRECTS = """() => {
    const results = [];
    for (const meta of document.querySelectorAll('meta[http-equiv="refresh"]')) {
        const content = meta.getAttribute('content') || '';
        const m = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
        if (m) results.push(m[1]);
    }
    return results;
}"""

_JS_POSTMESSAGE_LISTENERS = """() => {
    const info = {hasListener: false, handlers: []};
    // Check inline scripts for message event handlers
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        if (/addEventListener\s*\(\s*['"]message['"]/.test(text)) {
            info.hasListener = true;
            // Try to extract origin check
            const originCheck = /event\.origin\s*[!=]==?\s*['"]([^'"]+)['"]/g;
            let m;
            while ((m = originCheck.exec(text)) !== null) {
                info.handlers.push({origin: m[1]});
            }
            if (info.handlers.length === 0 && /\.data/.test(text)) {
                info.handlers.push({origin: '*', note: 'no origin validation detected'});
            }
        }
    }
    return info;
}"""

_JS_GRAPHQL_DETECT = """() => {
    const endpoints = new Set();
    // Check script content for GraphQL endpoint URLs
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        const patterns = [
            /['"`]((?:https?:)?\/\/[^'"`\s]*graphql[^'"`\s]*)['"`]/gi,
            /['"`](\/graphql\b[^'"`\s]*)['"`]/gi,
            /['"`](\/gql\b[^'"`\s]*)['"`]/gi,
        ];
        for (const pat of patterns) {
            pat.lastIndex = 0;
            let m;
            while ((m = pat.exec(text)) !== null) endpoints.add(m[1]);
        }
    }
    // Check network for graphql in URL
    return Array.from(endpoints).slice(0, 10);
}"""

_JS_WS_URLS = """() => {
    const urls = new Set();
    for (const script of document.querySelectorAll('script:not([src])')) {
        const text = script.textContent || '';
        const m = text.matchAll(/new\s+WebSocket\s*\(\s*['"`](wss?:\/\/[^'"`\s]+)['"`]/g);
        for (const match of m) urls.add(match[1]);
    }
    return Array.from(urls);
}"""

# ── Sprint 3: Session refresh + Smart form fill ───────────────────────────────

_LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign[_\-]in|auth(?:enticate)?|sso|session/new|account/login"
    r"|user/login|users/sign_in|wp-login\.php)",
    re.IGNORECASE,
)

# (compiled pattern, test value) — matched against field name/id
_SMART_FILL: list = [
    (re.compile(r"e?mail",                         re.I), "test@example.com"),
    (re.compile(r"user(?:name)?|login|acct|handle", re.I), "testuser"),
    (re.compile(r"pass(?:word)?|pwd|secret",        re.I), "Test@1234"),
    (re.compile(r"phone|tel(?:ephone)?|mobile|cell",re.I), "5555555555"),
    (re.compile(r"(?:full.?|first.?|last.?)?name",  re.I), "Test User"),
    (re.compile(r"\bsearch\b|query|\bq\b",          re.I), "test"),
    (re.compile(r"\bage\b|\byear\b",                re.I), "25"),
    (re.compile(r"zip|postal",                      re.I), "12345"),
    (re.compile(r"url|website|link|href|site",      re.I), "https://example.com"),
    (re.compile(r"message|body|comment|description|note|content", re.I), "test message"),
    (re.compile(r"address|street|addr",             re.I), "123 Test St"),
    (re.compile(r"\bcity\b",                        re.I), "Testville"),
    (re.compile(r"state|province|region",           re.I), "CA"),
    (re.compile(r"country",                         re.I), "US"),
    (re.compile(r"number|num|count|qty|quantity|amount", re.I), "1"),
    (re.compile(r"date|birthday|dob",               re.I), "2000-01-01"),
    (re.compile(r"title|subject|topic|heading",     re.I), "Test"),
    (re.compile(r"company|org(?:anization)?|firm",  re.I), "TestCorp"),
]

_SMART_TYPE_DEFAULTS: dict = {
    "number":   "1",
    "email":    "test@example.com",
    "tel":      "5555555555",
    "url":      "https://example.com",
    "date":     "2000-01-01",
    "color":    "#000000",
    "range":    "50",
    "search":   "test",
}

_llm_log = logging.getLogger("dast.ajax_spider.llm")


def _generate_semantic_form_values(form_html: str, llm_provider) -> dict[str, str]:
    """Generate semantically valid form field values using LLM.

    Based on CrawlMLLM (MDPI 2025): semantic form inputs increase real-world
    vulnerability discovery by 3.3x vs random/generic values.

    Args:
        form_html: The raw HTML of the form element
        llm_provider: LLMProvider instance (or None for random fallback)

    Returns:
        Dict mapping field name -> value. Empty dict on failure.
    """
    if not llm_provider or not getattr(llm_provider, 'is_available', False):
        return {}

    prompt = (
        "Analyze this HTML form and generate realistic, valid test input values for each field. "
        "Return ONLY a JSON object mapping field name to value. "
        "Use realistic values: real dates for date fields, valid emails for email fields, "
        "numbers for numeric fields, realistic strings for text fields. "
        "Do not use test/dummy/placeholder values.\n\n"
        f"Form HTML:\n{form_html[:2000]}"
    )

    try:
        raw = llm_provider.chat([
            {"role": "system", "content": "You are a web application tester. Generate realistic form inputs. Return only valid JSON object, no explanation."},
            {"role": "user", "content": prompt},
        ])
        # Strip markdown fences
        raw = re.sub(r'```(?:json)?\s*', '', raw).strip().rstrip('`')
        result = json.loads(raw)
        if isinstance(result, dict):
            return {str(k): str(v) for k, v in result.items()}
        return {}
    except Exception:
        return {}


def _analyze_page_state(screenshot_b64: str, page_html: str, llm_provider) -> dict:
    """Analyze page using MLLM (screenshot + HTML) to understand state and navigation.

    Based on CrawlMLLM (MDPI 2025): MLLM-guided crawling achieves 163% avg code
    coverage improvement and 3.3x more vulnerability discoveries vs best baseline.

    Args:
        screenshot_b64: Base64-encoded PNG screenshot of current page
        page_html: Current page HTML (truncated to 3000 chars)
        llm_provider: LLMProvider instance

    Returns:
        Dict with keys: 'page_type', 'state_description', 'interactive_elements',
        'recommended_actions', 'requires_auth'
    """
    if not llm_provider or not getattr(llm_provider, 'is_available', False):
        return {}

    # Use text-only if no multimodal support, screenshot if available
    html_snippet = page_html[:3000]

    prompt = (
        "Analyze this web page and return a JSON object with:\n"
        "- page_type: string (login/dashboard/form/listing/detail/other)\n"
        "- state_description: string (what state the app is in)\n"
        "- interactive_elements: list of {type, name, action} objects for buttons/forms/links\n"
        "- recommended_actions: list of strings describing next navigation steps\n"
        "- requires_auth: boolean\n\n"
        f"Page HTML snippet:\n{html_snippet}"
    )

    messages = [
        {"role": "system", "content": "You are a web crawler analyzing page structure for security testing. Return only valid JSON, no explanation."},
        {"role": "user", "content": prompt},
    ]

    # If LLM supports vision (Anthropic claude models support image in content)
    if screenshot_b64:
        try:
            messages[-1]["content"] = [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": screenshot_b64,
                    }
                },
                {"type": "text", "text": prompt}
            ]
        except Exception:
            pass  # Fall back to text-only

    try:
        raw = llm_provider.chat(messages)
        raw = re.sub(r'```(?:json)?\s*', '', raw).strip().rstrip('`')
        result = json.loads(raw)
        if isinstance(result, dict):
            return result
        return {}
    except Exception:
        return {}


class AjaxSpider:
    """
    Headless Chromium spider. Handles JS rendering, SPAs, dynamic forms,
    captures XHR/fetch network traffic, and WebSocket endpoints.

    Uses a producer-consumer queue with `max_tabs` concurrent Playwright
    instances for faster crawling. Falls back gracefully if Playwright
    is not installed.
    """

    def __init__(
        self,
        target:       str,
        scope:        "ScopeManager | None" = None,   # defaults to ScopeManager(target)
        max_pages:    int = 50,
        max_depth:    int = 3,
        page_timeout: int = 20_000,   # ms for page navigation (raised: SPAs need longer)
        idle_wait:    int = 2_000,    # ms to wait for JS after navigation (raised)
        headless:     bool = True,
        cookies:      list[dict] | None = None,  # [{name, value, domain, path}]
        headers:      dict       | None = None,
        stop_event:   threading.Event | None = None,
        callback      = None,         # called with (url, status) on each page
        max_tabs:     int = 3,        # concurrent browser instances (1-5)
        # Sprint 3 additions
        auth_config:  dict | None = None,  # {login_url, username, password, user_field, pass_field}
        smart_fill:   bool = True,         # submit forms with smart test values

        # Traffic visibility — passive scan browser traffic
        traffic_log   = None,              # modules.traffic.TrafficLog
        passive_scanner_instance = None,   # modules.passive.PassiveScanner
        # Feature 8 & 12: LLM-powered crawling
        llm_provider  = None,              # LLMProvider instance for semantic form fill + MLLM
        mllm_crawl:   bool = False,        # Enable MLLM state-machine crawling
    ):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed.\n"
                "Install: pip install playwright && playwright install chromium"
            )
        self.target       = target
        self.scope        = scope if scope is not None else ScopeManager(target)
        self.max_pages    = max_pages
        self.max_depth    = max_depth
        self.page_timeout = page_timeout
        self.idle_wait    = idle_wait
        self.headless     = headless
        self.cookies      = cookies or []
        self.headers      = headers or {}
        self.stop_event   = stop_event or threading.Event()
        self.callback     = callback
        self.max_tabs     = max(1, min(max_tabs, 5))
        self.auth_config  = auth_config or {}
        self.smart_fill   = smart_fill
        self._traffic_log = traffic_log
        self._passive_scanner = passive_scanner_instance
        self.llm_provider = llm_provider
        self.mllm_crawl = mllm_crawl

        self.sitemap         = SiteMap()
        self._visited: set[str] = set()
        self._network_reqs: list[dict] = []
        self._ws_endpoints: list[dict] = []
        self._browser_findings: list[dict] = []  # passive findings from browser traffic

        # Thread-safety locks
        self._net_lock     = threading.Lock()
        self._sitemap_lock = threading.Lock()
        self._visited_lock = threading.Lock()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def get_browser_findings(self) -> list[dict]:
        """Return passive findings captured from browser traffic."""
        with self._net_lock:
            return list(self._browser_findings)

    def crawl(self) -> "SiteMap":
        """Launch multi-tab Playwright workers, crawl target, return SiteMap."""
        # Producer-consumer: master feeds work_q, workers put results in result_q
        work_q:   _queue.Queue = _queue.Queue()
        result_q: _queue.Queue = _queue.Queue()

        # Seed queue with the start URL (preserve hash routes)
        start_url = self.target if self._is_hash_route(self.target) else self.target.split("#")[0]
        with self._visited_lock:
            self._visited.add(start_url)
        work_q.put((start_url, 0))
        pending = 1  # number of URLs currently in flight / queued

        stop_tabs = threading.Event()

        # Spawn N tab workers
        workers = []
        for tab_id in range(self.max_tabs):
            t = threading.Thread(
                target=self._tab_worker,
                args=(work_q, result_q, stop_tabs, tab_id),
                daemon=True,
                name=f"ajax-tab-{tab_id}",
            )
            t.start()
            workers.append(t)

        # Master loop: route results → feed new URLs back into work_q
        _last_result_t = time.time()
        _MAX_STALL_SEC = 60  # bail if no result received for 60 s (all workers hung/crashed)
        while pending > 0 and not self.stop_event.is_set():
            try:
                result = result_q.get(timeout=3)
            except _queue.Empty:
                if time.time() - _last_result_t > _MAX_STALL_SEC:
                    log.warning("[AjaxSpider] No results for %ds with %d pending — "
                                "breaking stall (workers may have crashed)", _MAX_STALL_SEC, pending)
                    break
                continue

            _last_result_t = time.time()
            pending -= 1
            new_urls = result.get("new_urls", [])

            with self._visited_lock:
                for href, depth in new_urls:
                    if (href not in self._visited
                            and len(self._visited) < self.max_pages
                            and depth <= self.max_depth):
                        self._visited.add(href)
                        work_q.put((href, depth))
                        pending += 1

        # Signal all workers to stop and wait
        stop_tabs.set()
        for t in workers:
            t.join(timeout=10)

        # Post-process: convert network captures to surfaces + add WS pages
        self._extract_network_surfaces()
        self._add_network_and_ws_pages()

        return self.sitemap

    # ─────────────────────────────────────────────────────────────────────────
    # Tab worker (each runs its own Playwright instance)
    # ─────────────────────────────────────────────────────────────────────────

    def _tab_worker(
        self,
        work_q:   _queue.Queue,
        result_q: _queue.Queue,
        stop_tabs: threading.Event,
        tab_id:   int,
    ):
        """Each tab owns its own sync_playwright() context (thread-safe)."""
        _url_in_flight: str | None = None
        try:
            with sync_playwright() as pw:
                browser = _launch_browser(pw, headless=self.headless)
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=self.headers,
                    user_agent="Mozilla/5.0 (DAST-AjaxSpider/2.0)",
                )
                if self.cookies:
                    ctx.add_cookies(self.cookies)

                # Sprint 5: Headless detection evasion
                self._apply_stealth(ctx)

                page = ctx.new_page()

                # ── Hook pushState/replaceState to capture SPA routes ────
                try:
                    page.evaluate(_JS_HISTORY_INTERCEPT)
                except Exception:
                    pass

                # ── Network capture ───────────────────────────────────────
                # Deduplicate in-flight by (url, method) to cap memory on busy SPAs
                _net_seen: set[tuple] = set()

                def _on_request(req):
                    try:
                        if not self.scope.in_scope(req.url):
                            return
                        key = (req.url.split("?")[0], req.method)
                        with self._net_lock:
                            if key in _net_seen:
                                return
                            _net_seen.add(key)
                            self._network_reqs.append({
                                "url":       req.url,
                                "method":    req.method,
                                "headers":   dict(req.headers),
                                "post_data": req.post_data or "",
                            })
                    except Exception:
                        pass

                # ── WebSocket capture ─────────────────────────────────────
                def _on_websocket(ws):
                    try:
                        ws_url = ws.url
                        with self._net_lock:
                            self._ws_endpoints.append({
                                "url":          ws_url,
                                "source":       "websocket",
                                "status":       101,
                                "content_type": "websocket",
                                "title":        "[WebSocket]",
                            })
                    except Exception:
                        pass

                # ── Response capture (traffic log + passive scan) ────────
                def _on_response(resp):
                    try:
                        if not self.scope.in_scope(resp.url):
                            return
                        status = resp.status
                        headers = dict(resp.headers)
                        ct = headers.get("content-type", "")
                        cl = int(headers.get("content-length", 0))

                        # Capture body for text responses (skip binary, cap at 32KB)
                        body = ""
                        if ct and not any(ct.startswith(b) for b in
                                          ("image/", "audio/", "video/", "font/",
                                           "application/octet-stream", "application/pdf",
                                           "application/zip", "application/gzip",
                                           "application/wasm")):
                            try:
                                body = resp.text()[:32_768]
                            except Exception:
                                pass

                        # Find matching request for method + post_data
                        req = resp.request
                        method = req.method if req else "GET"
                        post_data = ""
                        req_headers = {}
                        if req:
                            try:
                                post_data = req.post_data or ""
                                req_headers = dict(req.headers)
                            except Exception:
                                pass

                        # Feed traffic log
                        if self._traffic_log:
                            self._traffic_log.record(
                                method=method, url=resp.url,
                                status_code=status,
                                request_headers=req_headers,
                                request_body=post_data[:16_384] if post_data else "",
                                response_headers=headers,
                                response_body=body,
                                content_type=ct, content_length=cl,
                                elapsed_ms=0.0,  # Playwright doesn't expose timing
                                source="browser",
                            )

                        # Mine JSON API responses for embedded URL/path patterns
                        if body and "json" in ct and status < 400:
                            try:
                                _resp_url_pat = re.compile(
                                    r'["\'](?:href|url|uri|link|endpoint|path|action|src)'
                                    r'["\']:\s*["\'](\/?(?:api|v\d+|rest|gql|graphql|admin|internal)'
                                    r'[a-zA-Z0-9/_.-]{3,100})["\']',
                                    re.I,
                                )
                                for _m in _resp_url_pat.finditer(body[:30_000]):
                                    _ep = _m.group(1)
                                    if _ep.startswith("/"):
                                        _resp_parsed = urlparse(resp.url)
                                        _full = f"{_resp_parsed.scheme}://{_resp_parsed.netloc}{_ep}"
                                        if self.scope.in_scope(_full):
                                            with self._net_lock:
                                                _rk = (_full.split("?")[0], "GET")
                                                if _rk not in _net_seen:
                                                    _net_seen.add(_rk)
                                                    self._network_reqs.append({
                                                        "url": _full, "method": "GET",
                                                        "headers": {}, "post_data": "",
                                                    })
                            except Exception:
                                pass

                        # Run passive scanner on response
                        if self._passive_scanner and body and status < 400:
                            try:
                                pf = self._passive_scanner.scan(
                                    url=resp.url, status_code=status,
                                    resp_headers=headers, resp_body=body[:8000],
                                    cookies={}, request_headers=req_headers,
                                )
                                if pf:
                                    with self._net_lock:
                                        for f in pf:
                                            self._browser_findings.append(
                                                {**f.to_dict(), "phase": "passive_browser"}
                                            )
                            except Exception:
                                pass
                    except Exception:
                        pass  # Never interfere with browser navigation

                page.on("request", _on_request)
                page.on("response", _on_response)
                page.on("websocket", _on_websocket)

                # Sprint 4: Auto-dismiss dialogs + capture console errors
                self._setup_dialog_handler(page)
                self._setup_console_capture(page)

                # ── Work loop ─────────────────────────────────────────────
                while not self.stop_event.is_set() and not stop_tabs.is_set():
                    try:
                        url, depth = work_q.get(timeout=1)
                    except _queue.Empty:
                        continue

                    _url_in_flight = url
                    try:
                        new_urls = self._navigate(page, url, depth)
                    except Exception as _nav_exc:
                        log.warning("[AjaxSpider] tab-%d navigate failed %s: %s",
                                    tab_id, url, _nav_exc)
                        new_urls = []
                    result_q.put({"new_urls": new_urls})
                    _url_in_flight = None

                try:
                    page.close()
                    browser.close()
                except Exception:
                    pass

        except Exception as _tab_exc:
            log.warning("[AjaxSpider] tab-%d crashed: %s", tab_id, _tab_exc)
            # If a URL was in-flight when the tab crashed, drain it so master
            # loop's pending counter can reach zero instead of spinning forever.
            if _url_in_flight is not None:
                result_q.put({"new_urls": []})

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 3.1 — Session refresh helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _is_login_page(self, url: str, resp, page) -> bool:
        """Return True when we appear to have been redirected to a login page."""
        if _LOGIN_PATH_RE.search(url):
            return True
        if resp and resp.status in (401, 403):
            return True
        try:
            title = page.title().lower()
            if any(w in title for w in ("login", "sign in", "sign-in", "log in",
                                        "authenticate", "authentication")):
                return True
        except Exception:
            pass
        return False

    def _reauth(self, page) -> bool:
        """Navigate to the login URL, fill credentials, submit.  Returns True on success."""
        cfg = self.auth_config
        login_url = cfg.get("login_url", "")
        username  = cfg.get("username", "")
        password  = cfg.get("password", "")
        if not (login_url and username and password):
            return False

        try:
            page.goto(login_url, timeout=self.page_timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(800)

            # ── Fill username ──────────────────────────────────────────────
            user_field = cfg.get("user_field", "")
            user_selectors = (
                [f'[name="{user_field}"]', f'#{user_field}'] if user_field else []
            ) + [
                '[name="username"]', '[name="email"]', '[name="user"]',
                '[name="login"]', '[id="username"]', '[id="email"]',
                '[type="email"]',
                'input[placeholder*="user" i]', 'input[placeholder*="email" i]',
                'input[placeholder*="login" i]',
            ]
            user_filled = False
            for sel in user_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible() and el.is_enabled():
                        el.fill(username)
                        user_filled = True
                        break
                except Exception:
                    pass

            # ── Fill password ──────────────────────────────────────────────
            pass_field = cfg.get("pass_field", "")
            pass_selectors = (
                [f'[name="{pass_field}"]', f'#{pass_field}'] if pass_field else []
            ) + [
                '[name="password"]', '[name="pass"]', '[name="pwd"]',
                '[id="password"]', '[type="password"]',
                'input[placeholder*="pass" i]', 'input[placeholder*="secret" i]',
            ]
            pass_filled = False
            for sel in pass_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible() and el.is_enabled():
                        el.fill(password)
                        pass_filled = True
                        break
                except Exception:
                    pass

            if not (user_filled and pass_filled):
                return False

            # ── Submit ────────────────────────────────────────────────────
            submitted = False
            for sel in ['[type="submit"]', 'button[type="submit"]',
                        'button:not([type="button"]):not([type="reset"])']:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        el.click()
                        submitted = True
                        break
                except Exception:
                    pass
            if not submitted:
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass

            try:
                page.wait_for_load_state("load", timeout=6_000)
            except Exception:
                pass
            page.wait_for_timeout(500)
            return True

        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 3.2 — Smart form submission
    # ─────────────────────────────────────────────────────────────────────────

    def _smart_value(self, name: str, itype: str) -> str:
        """Return a context-appropriate test value for a form field."""
        for pattern, val in _SMART_FILL:
            if pattern.search(name):
                return val
        return _SMART_TYPE_DEFAULTS.get(itype, "test")

    def _fill_and_submit_forms(self, page, url: str, depth: int) -> list:
        """
        Fill every form on `url` with smart test values and submit.
        Returns list of (newly_discovered_url, depth+1) from submission redirects.
        """
        new_urls: list = []
        try:
            forms = page.evaluate(_JS_FORMS)
        except Exception:
            return new_urls

        for form_idx, form in enumerate(forms[:4]):   # cap at 4 forms per page
            if self.stop_event.is_set():
                break
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            try:
                # Re-navigate for every form after the first (fresh DOM state)
                if form_idx > 0:
                    page.goto(url, timeout=self.page_timeout, wait_until="domcontentloaded")
                    page.wait_for_timeout(500)

                # Feature 8: LLM semantic form values (opt-in via llm_provider)
                llm_values: dict[str, str] = {}
                if self.llm_provider:
                    try:
                        form_html = page.evaluate(
                            f"() => {{ const f = document.querySelectorAll('form')[{form_idx}]; return f ? f.outerHTML : ''; }}"
                        )
                        if form_html:
                            llm_values = _generate_semantic_form_values(form_html, self.llm_provider)
                            if llm_values:
                                _llm_log.debug("LLM semantic values for %s: %s", url, list(llm_values.keys()))
                    except Exception:
                        pass

                # Fill each input via smart value (LLM values take priority when available)
                for inp in inputs:
                    name  = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if not name:
                        continue
                    # Use LLM-generated value if available, otherwise fall back to smart value
                    val = llm_values.get(name) if llm_values else None
                    if val is None:
                        val = self._smart_value(name, itype)
                    for sel in [f'[name="{name}"]', f'#{name}']:
                        try:
                            el = page.query_selector(sel)
                            if el and el.is_visible() and el.is_enabled():
                                if itype in ("checkbox", "radio"):
                                    el.check()
                                elif itype in ("select", "select-one"):
                                    opts = page.eval_on_selector(
                                        sel,
                                        "el => Array.from(el.options).map(o=>o.value).filter(v=>v)"
                                    )
                                    if opts:
                                        el.select_option(opts[0])
                                else:
                                    el.fill(val)
                                break
                        except Exception:
                            pass

                pre_url = self._scope_base(page.url)

                # Click submit — try scoped selectors first, then global
                submitted = False
                for sel in [
                    '[type="submit"]', 'button[type="submit"]',
                    'button:not([type="button"]):not([type="reset"])',
                    'input[type="image"]',
                ]:
                    try:
                        el = page.query_selector(sel)
                        if el and el.is_visible():
                            el.click()
                            submitted = True
                            break
                    except Exception:
                        pass
                if not submitted:
                    try:
                        page.keyboard.press("Enter")
                        submitted = True
                    except Exception:
                        pass
                if not submitted:
                    continue

                try:
                    page.wait_for_load_state("load", timeout=4_000)
                except Exception:
                    pass
                page.wait_for_timeout(400)

                post_url = self._scope_base(page.url)
                if post_url != pre_url and self.scope.in_scope(post_url):
                    with self._visited_lock:
                        already = post_url in self._visited
                    if not already:
                        try:
                            title = page.title()
                        except Exception:
                            title = ""
                        with self._sitemap_lock:
                            self.sitemap.add_page(
                                post_url, 200, "", {}, f"[Form-Submit] {title}"
                            )
                        new_urls.append((post_url, depth + 1))
                        if self.callback:
                            self.callback(post_url, 200)

            except Exception:
                pass

        # Leave page at the original URL so the tab can continue cleanly
        if forms:
            try:
                page.goto(url, timeout=self.page_timeout, wait_until="domcontentloaded")
                page.wait_for_timeout(800)
            except Exception:
                pass

        return new_urls

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 4: Full SPA crawling capabilities
    # ─────────────────────────────────────────────────────────────────────────

    def _explore_clickables(self, page, url: str, depth: int) -> list:
        """
        Click interactive elements (buttons, tabs, menus) and detect DOM changes
        to discover new content/routes. Returns list of (url, depth+1).
        Bounded: max 15 elements per page, 2s per click.
        """
        new_urls: list = []
        try:
            clickables = page.evaluate(_JS_CLICKABLES)
        except Exception:
            return new_urls

        if not clickables:
            return new_urls

        # Snapshot DOM state before clicking
        try:
            pre_sig = page.evaluate(_JS_DOM_SIGNATURE)
        except Exception:
            pre_sig = ""

        clicked_sigs: set = set()

        for item in clickables[:15]:
            if self.stop_event.is_set():
                break

            sig = item.get("sig", "")
            if sig in clicked_sigs:
                continue
            clicked_sigs.add(sig)

            try:
                # Try to locate element by selector or by index
                el = None
                sel = item.get("selector")
                if sel:
                    try:
                        el = page.query_selector(sel)
                    except Exception:
                        pass

                if not el:
                    # Fallback: re-query clickables and use index
                    tag = item.get("tag", "").lower()
                    text = item.get("text", "")
                    if text:
                        try:
                            el = page.query_selector(f'{tag}:has-text("{text[:20]}")')
                        except Exception:
                            pass

                if not el:
                    continue

                try:
                    if not el.is_visible() or not el.is_enabled():
                        continue
                except Exception:
                    continue

                pre_url = page.url

                # Click with short timeout
                try:
                    el.click(timeout=2000)
                except Exception:
                    continue

                # Brief wait for SPA routing/DOM update
                try:
                    page.wait_for_timeout(800)
                except Exception:
                    pass

                post_url = page.url

                # Check if URL changed (SPA navigation)
                if post_url != pre_url:
                    clean_url = self._strip_fragment(post_url)
                    if self.scope.in_scope(self._scope_base(clean_url)):
                        with self._visited_lock:
                            if clean_url not in self._visited:
                                new_urls.append((clean_url, depth + 1))

                    # Navigate back to continue exploring
                    try:
                        page.go_back(timeout=3000)
                        page.wait_for_timeout(500)
                    except Exception:
                        # If back doesn't work, re-navigate
                        try:
                            page.goto(url, timeout=self.page_timeout, wait_until="domcontentloaded")
                            page.wait_for_timeout(500)
                        except Exception:
                            break
                else:
                    # URL didn't change — check DOM mutation
                    try:
                        post_sig = page.evaluate(_JS_DOM_SIGNATURE)
                        if post_sig != pre_sig:
                            # DOM changed — extract new links/forms
                            self._extract_post_click_content(page, url, depth, new_urls)
                    except Exception:
                        pass

            except Exception:
                continue

        return new_urls

    def _extract_post_click_content(self, page, url: str, depth: int, new_urls: list):
        """After a click that changed the DOM, extract any new links/forms."""
        try:
            hrefs = page.evaluate(_JS_LINKS)
            with self._visited_lock:
                visited_snap = set(self._visited)
            for href in hrefs:
                href = self._strip_fragment(href)
                if href not in visited_snap and self.scope.in_scope(self._scope_base(href)):
                    new_urls.append((href, depth + 1))
        except Exception:
            pass

        try:
            forms = page.evaluate(_JS_FORMS)
            for form in forms:
                action = form.get("action", url)
                method = form.get("method", "GET").upper()
                for inp in form.get("inputs", []):
                    if inp.get("name"):
                        with self._sitemap_lock:
                            self.sitemap.add_surface(InputSurface(
                                url=action, method=method,
                                param=inp["name"], param_type="form",
                                original_value=inp.get("value", ""),
                                content_type="application/x-www-form-urlencoded",
                            ))
        except Exception:
            pass

    def _scroll_for_lazy_content(self, page) -> int:
        """
        Scroll page progressively to trigger lazy loading / infinite scroll.
        Returns number of new elements detected.
        """
        try:
            pre_count = page.evaluate("() => document.querySelectorAll('a[href],form,img,[data-src]').length")
        except Exception:
            return 0

        scroll_steps = 5
        for _ in range(scroll_steps):
            if self.stop_event.is_set():
                break
            try:
                page.evaluate("() => window.scrollBy(0, window.innerHeight)")
                page.wait_for_timeout(400)
            except Exception:
                break

        try:
            post_count = page.evaluate("() => document.querySelectorAll('a[href],form,img,[data-src]').length")
            return max(0, post_count - pre_count)
        except Exception:
            return 0

    def _extract_shadow_dom(self, page, url: str, depth: int) -> list:
        """Traverse shadow DOM roots to find links and forms inside web components."""
        new_urls: list = []
        try:
            shadow = page.evaluate(_JS_SHADOW_DOM)
        except Exception:
            return new_urls

        with self._visited_lock:
            visited_snap = set(self._visited)

        for href in shadow.get("links", []):
            href = self._strip_fragment(href)
            if href not in visited_snap and self.scope.in_scope(self._scope_base(href)):
                new_urls.append((href, depth + 1))

        for form in shadow.get("forms", []):
            action = form.get("action", url)
            method = form.get("method", "GET").upper()
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=action, method=method,
                            param=inp["name"], param_type="form",
                            original_value="",
                            content_type="application/x-www-form-urlencoded",
                        ))

        return new_urls

    def _extract_js_routes(self, page, url: str, depth: int) -> list:
        """Extract client-side routes from inline JavaScript (Angular/React/Vue)."""
        new_urls: list = []
        try:
            routes = page.evaluate(_JS_EXTRACT_ROUTES)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with self._visited_lock:
            visited_snap = set(self._visited)

        for route in routes:
            if not route:
                continue
            # Skip parameterized routes like /user/:id
            if ":" in route or "{" in route:
                continue
            full_url = base + (route if route.startswith("/") else "/" + route)
            if full_url not in visited_snap and self.scope.in_scope(full_url):
                new_urls.append((full_url, depth + 1))

        return new_urls

    def _is_hash_route(self, url: str) -> bool:
        """Return True if URL uses hash-based routing (#/, #!/, #route=, etc)."""
        parsed = urlparse(url)
        frag = parsed.fragment
        if not frag:
            return False
        # Classic hash routes: #/ #!/ #!
        if frag.startswith("/") or frag.startswith("!/") or frag.startswith("!"):
            return True
        # Named routes: #route=X, #page=X, #view/X
        if re.match(r'^[a-z][-a-z0-9]*[=/]', frag, re.I):
            return True
        return False

    def _strip_fragment(self, url: str) -> str:
        """Strip fragment from URL, but preserve it if it's a hash route."""
        if self._is_hash_route(url):
            return url
        return url.split("#")[0]

    def _scope_base(self, url: str) -> str:
        """Return the base URL (no fragment) for scope checking."""
        return url.split("#")[0]

    def _extract_hash_params(self, url: str):
        """Extract input surfaces from hash route parameters.

        Handles patterns like:
          #/user/123         → param 'id' (path segment)
          #/search?q=test    → param 'q' (query)
          #route=dashboard   → param 'route' (key-value)
          #!/products/42     → param 'id' (path segment)
        """
        parsed = urlparse(url)
        frag = parsed.fragment
        if not frag:
            return

        # Strip leading !/ or / or !
        route = re.sub(r'^[!/]+', '', frag)

        # Key-value style: #route=X or #page=dashboard
        kv_match = re.match(r'^([a-zA-Z][-\w]*)=(.+)', route)
        if kv_match:
            with self._sitemap_lock:
                self.sitemap.add_surface(InputSurface(
                    url=url, method="GET", param=kv_match.group(1),
                    param_type="hash_param",
                    original_value=kv_match.group(2),
                ))
            return

        # Query params in hash: #/search?q=test&page=1
        if "?" in route:
            path_part, qs = route.split("?", 1)
            for param, vals in parse_qs(qs).items():
                with self._sitemap_lock:
                    self.sitemap.add_surface(InputSurface(
                        url=url, method="GET", param=param,
                        param_type="hash_query",
                        original_value=vals[0] if vals else "",
                    ))

        # Numeric path segments: #/user/123 → param guessed from path
        parts = [p for p in route.split("?")[0].split("/") if p]
        for i, part in enumerate(parts):
            if re.match(r'^\d+$', part) and i > 0:
                param_name = parts[i - 1].rstrip("s")  # /users/123 → "user"
                with self._sitemap_lock:
                    self.sitemap.add_surface(InputSurface(
                        url=url, method="GET", param=param_name + "_id",
                        param_type="hash_path",
                        original_value=part,
                    ))

    def _crawl_hash_routes(self, page, url: str, depth: int) -> list:
        """Discover hash-based SPA routes, then actually navigate them.

        Uses page.evaluate('location.hash = ...') instead of page.goto()
        so that hashchange events fire and SPA routers respond properly.
        """
        new_urls: list = []
        try:
            hashes = page.evaluate(_JS_HASH_LINKS)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        with self._visited_lock:
            visited_snap = set(self._visited)

        navigated = 0
        max_hash_nav = 15  # cap per-page hash navigations

        for h in hashes:
            if self.stop_event.is_set():
                break
            # Resolve relative hash links
            if h.startswith("#"):
                full_url = base + h
                hash_val = h
            elif h.startswith("http"):
                full_url = h
                hp = urlparse(h)
                hash_val = "#" + hp.fragment if hp.fragment else None
            else:
                continue

            if not hash_val:
                continue

            if full_url in visited_snap:
                continue

            if not self.scope.in_scope(self._scope_base(full_url)):
                continue

            # Mark visited
            with self._visited_lock:
                if full_url in self._visited:
                    continue
                self._visited.add(full_url)

            # Actually navigate by setting location.hash (triggers hashchange)
            if navigated < max_hash_nav:
                try:
                    pre_sig = page.evaluate(_JS_DOM_SIGNATURE)
                    page.evaluate(f"() => {{ location.hash = {json.dumps(hash_val)}; }}")
                    page.wait_for_timeout(500)

                    # Capture page state after hash navigation
                    try:
                        title = page.title()
                    except Exception:
                        title = ""
                    with self._sitemap_lock:
                        self.sitemap.add_page(full_url, 200, "text/html", {},
                                              f"[Ajax-hash] {title}")

                    # Extract hash route parameters as input surfaces
                    self._extract_hash_params(full_url)

                    # Check if DOM changed — if so, extract new links/forms
                    post_sig = page.evaluate(_JS_DOM_SIGNATURE)
                    if post_sig != pre_sig:
                        self._extract_post_click_content(page, full_url, depth, new_urls)

                    navigated += 1
                except Exception:
                    pass

            new_urls.append((full_url, depth + 1))

        # Collect any routes captured by history intercept
        try:
            history_routes = page.evaluate(_JS_HISTORY_INTERCEPT)
            for route in history_routes:
                if route.startswith("http"):
                    rurl = route
                elif route.startswith("/"):
                    rurl = f"{parsed.scheme}://{parsed.netloc}{route}"
                elif route.startswith("#"):
                    rurl = base + route
                else:
                    continue
                rurl = self._strip_fragment(rurl)
                with self._visited_lock:
                    if rurl in self._visited:
                        continue
                if self.scope.in_scope(self._scope_base(rurl)):
                    new_urls.append((rurl, depth + 1))
        except Exception:
            pass

        return new_urls

    def _capture_storage(self, page, url: str):
        """Dump localStorage/sessionStorage and flag sensitive entries."""
        try:
            storage = page.evaluate(_JS_STORAGE)
        except Exception:
            return

        for store_name in ("localStorage", "sessionStorage"):
            entries = storage.get(store_name, {})
            for key, val in entries.items():
                if _STORAGE_SENSITIVE_RE.search(key) or _STORAGE_SENSITIVE_RE.search(val[:100]):
                    with self._net_lock:
                        self._browser_findings.append({
                            "url": url,
                            "category": "browser_storage",
                            "finding": f"Sensitive data in {store_name}: key='{key}'",
                            "severity": "Medium",
                            "evidence": f"{key}={val[:80]}",
                            "remediation": "Avoid storing tokens/secrets in browser storage — use httpOnly cookies",
                            "cwe": "CWE-922",
                            "phase": "passive_browser",
                        })

    def _setup_console_capture(self, page):
        """Wire up console error/warning capture on a page."""
        def _on_console(msg):
            if msg.type in ("error", "warning"):
                text = msg.text[:200]
                # Only capture potentially security-relevant messages
                if any(w in text.lower() for w in (
                    "cors", "csp", "mixed content", "insecure", "blocked",
                    "denied", "forbidden", "unauthorized", "token", "auth",
                    "certificate", "ssl", "tls", "refused", "security",
                    "xss", "injection", "sanitize",
                )):
                    with self._net_lock:
                        self._browser_findings.append({
                            "url": page.url,
                            "category": "console_error",
                            "finding": f"Browser console {msg.type}: {text[:120]}",
                            "severity": "Info",
                            "evidence": text,
                            "remediation": "Review browser console errors for security misconfigurations",
                            "cwe": "CWE-200",
                            "phase": "passive_browser",
                        })
        page.on("console", _on_console)

    def _setup_dialog_handler(self, page):
        """Auto-dismiss alert/confirm/prompt dialogs to prevent navigation blocking."""
        def _on_dialog(dialog):
            try:
                dialog.dismiss()
            except Exception:
                pass
        page.on("dialog", _on_dialog)

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 5: Beyond Burp/ZAP — unique differentiator capabilities
    # ─────────────────────────────────────────────────────────────────────────

    def _mine_api_endpoints(self, page, url: str, depth: int) -> list:
        """
        Parse fetch()/axios/$.ajax/XHR/Angular/Vue/superagent/SWR calls in inline
        AND external JS to discover API endpoints without triggering them.
        Returns {url, method} tuples with inferred HTTP method.
        UNIQUE — neither Burp nor ZAP does static JS API mining.
        """
        new_urls: list = []
        try:
            endpoints = page.evaluate(_JS_API_ENDPOINTS)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with self._visited_lock:
            visited_snap = set(self._visited)

        for ep_obj in endpoints:
            # Support both old format (string) and new format ({url, method})
            if isinstance(ep_obj, str):
                ep = ep_obj
                method = "GET"
            else:
                ep = ep_obj.get("url", "")
                method = ep_obj.get("method", "GET").upper()

            if ep.startswith("http"):
                full = ep
            elif ep.startswith("/"):
                full = base + ep
            elif ep.startswith("api/") or ep.startswith("rest/") or ep.startswith("v1/") or ep.startswith("v2/"):
                full = base + "/" + ep
            else:
                continue

            clean = full.split("?")[0].split("#")[0]
            if clean not in visited_snap and self.scope.in_scope(clean):
                new_urls.append((clean, depth + 1))
                # Record as input surface with inferred HTTP method
                ep_parsed = urlparse(full)
                if ep_parsed.query:
                    for param, vals in parse_qs(ep_parsed.query).items():
                        with self._sitemap_lock:
                            self.sitemap.add_surface(InputSurface(
                                url=clean, method=method, param=param,
                                param_type="query",
                                original_value=vals[0] if vals else "",
                            ))
                # For POST/PUT/PATCH, add a generic body param surface
                if method in ("POST", "PUT", "PATCH"):
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method=method, param="body",
                            param_type="json",
                            original_value="{}",
                            content_type="application/json",
                        ))

        return new_urls

    def _detect_graphql_endpoints(self, page, url: str, depth: int) -> list:
        """Detect GraphQL endpoints from JS source and add for introspection testing."""
        new_urls: list = []
        try:
            gql_eps = page.evaluate(_JS_GRAPHQL_DETECT)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for ep in gql_eps:
            full = ep if ep.startswith("http") else base + ep
            clean = full.split("?")[0]
            if self.scope.in_scope(clean):
                with self._visited_lock:
                    if clean not in self._visited:
                        new_urls.append((clean, depth + 1))
                # Record GraphQL endpoint as attack surface
                with self._sitemap_lock:
                    self.sitemap.add_surface(InputSurface(
                        url=clean, method="POST", param="query",
                        param_type="json",
                        original_value='{"query":"{__typename}"}',
                        content_type="application/json",
                    ))

        return new_urls

    def _detect_service_workers(self, page, url: str):
        """Find and record service worker scripts for analysis."""
        try:
            sw_urls = page.evaluate(_JS_SERVICE_WORKERS)
        except Exception:
            return

        for sw_url in sw_urls:
            if not sw_url:
                continue
            with self._net_lock:
                self._browser_findings.append({
                    "url": url,
                    "category": "attack_surface",
                    "finding": f"Service Worker registered: {sw_url}",
                    "severity": "Info",
                    "evidence": sw_url[:120],
                    "remediation": "Review service worker for sensitive caching and fetch interception",
                    "cwe": "CWE-200",
                    "phase": "passive_browser",
                })
            # Add SW script URL as a page to crawl
            if self.scope.in_scope(sw_url):
                with self._sitemap_lock:
                    self.sitemap.add_page(sw_url, 0, "application/javascript", {},
                                          "[ServiceWorker]")

    def _detect_event_listeners(self, page, url: str):
        """Enumerate security-interesting event listeners (message, hashchange, etc)."""
        try:
            listeners = page.evaluate(_JS_EVENT_LISTENERS)
        except Exception:
            return

        for listener in listeners:
            evt_type = listener.get("type", "")
            if evt_type == "message":
                with self._net_lock:
                    self._browser_findings.append({
                        "url": url,
                        "category": "attack_surface",
                        "finding": "postMessage listener detected — test for DOM XSS via cross-origin messages",
                        "severity": "Medium",
                        "evidence": f"window.addEventListener('message') found",
                        "remediation": "Validate event.origin in all postMessage handlers",
                        "cwe": "CWE-79",
                        "phase": "passive_browser",
                    })
            elif evt_type in ("hashchange", "popstate"):
                with self._net_lock:
                    self._browser_findings.append({
                        "url": url,
                        "category": "attack_surface",
                        "finding": f"{evt_type} listener detected — SPA routing via URL manipulation",
                        "severity": "Info",
                        "evidence": f"window.addEventListener('{evt_type}')",
                        "remediation": "Ensure URL-controlled routing does not enable open redirect or DOM XSS",
                        "cwe": "CWE-79",
                        "phase": "passive_browser",
                    })

    def _extract_data_attributes(self, page, url: str, depth: int) -> list:
        """Extract URLs from data-api, data-url, data-endpoint and similar attributes."""
        new_urls: list = []
        try:
            urls = page.evaluate(_JS_DATA_ATTRIBUTES)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with self._visited_lock:
            visited_snap = set(self._visited)

        for u in urls:
            full = u if u.startswith("http") else base + u
            clean = self._strip_fragment(full)
            if clean not in visited_snap and self.scope.in_scope(self._scope_base(clean)):
                new_urls.append((clean, depth + 1))

        return new_urls

    def _extract_prefetch_links(self, page, url: str, depth: int) -> list:
        """Discover targets from <link rel=prefetch/preload/preconnect>."""
        new_urls: list = []
        try:
            links = page.evaluate(_JS_PREFETCH_LINKS)
        except Exception:
            return new_urls

        with self._visited_lock:
            visited_snap = set(self._visited)

        for link in links:
            href = link.get("url", "")
            if not href or not href.startswith("http"):
                continue
            clean = self._strip_fragment(href)
            if clean not in visited_snap and self.scope.in_scope(self._scope_base(clean)):
                new_urls.append((clean, depth + 1))

        return new_urls

    def _follow_meta_redirects(self, page, url: str, depth: int) -> list:
        """Follow <meta http-equiv=refresh> redirects that Playwright may not auto-follow."""
        new_urls: list = []
        try:
            redirects = page.evaluate(_JS_META_REDIRECTS)
        except Exception:
            return new_urls

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for redir in redirects:
            full = redir if redir.startswith("http") else base + (redir if redir.startswith("/") else "/" + redir)
            clean = self._strip_fragment(full)
            if self.scope.in_scope(self._scope_base(clean)):
                with self._visited_lock:
                    if clean not in self._visited:
                        new_urls.append((clean, depth + 1))

        return new_urls

    def _detect_postmessage_handlers(self, page, url: str):
        """Detect postMessage listeners and flag missing origin validation."""
        try:
            info = page.evaluate(_JS_POSTMESSAGE_LISTENERS)
        except Exception:
            return

        if not info.get("hasListener"):
            return

        for handler in info.get("handlers", []):
            origin = handler.get("origin", "")
            note = handler.get("note", "")
            if origin == "*" or "no origin validation" in note:
                with self._net_lock:
                    self._browser_findings.append({
                        "url": url,
                        "category": "xss_indicator",
                        "finding": "postMessage handler without origin validation — DOM XSS risk",
                        "severity": "High",
                        "evidence": "addEventListener('message') with no event.origin check",
                        "remediation": "Always validate event.origin against a whitelist in message handlers",
                        "cwe": "CWE-79",
                        "phase": "passive_browser",
                    })
            elif origin:
                with self._net_lock:
                    self._browser_findings.append({
                        "url": url,
                        "category": "attack_surface",
                        "finding": f"postMessage handler validates origin: {origin}",
                        "severity": "Info",
                        "evidence": f"event.origin === '{origin}'",
                        "remediation": "Verify origin whitelist is not overly permissive",
                        "cwe": "CWE-346",
                        "phase": "passive_browser",
                    })

    def _extract_websocket_urls(self, page, url: str):
        """Find WebSocket URLs in inline JS (new WebSocket('wss://...'))."""
        try:
            ws_urls = page.evaluate(_JS_WS_URLS)
        except Exception:
            return

        for ws_url in ws_urls:
            if not ws_url:
                continue
            with self._net_lock:
                already = any(w["url"] == ws_url for w in self._ws_endpoints)
                if not already:
                    self._ws_endpoints.append({
                        "url": ws_url,
                        "source": "js_parse",
                        "status": 101,
                        "content_type": "websocket",
                        "title": "[WebSocket-JS]",
                    })

    def _extract_cookie_surfaces(self, page, url: str):
        """
        After each page load, collect all browser cookies for the current
        domain and register them as cookie-type input surfaces.
        Skips httpOnly cookies (can't be read via JS anyway — but Playwright
        exposes them via context.cookies() so we can still register them).
        Skips __Secure- / __Host- prefixed cookies (HTTPS-only, low FP value).
        """
        try:
            ctx = page.context
            cookies = ctx.cookies()
        except Exception:
            return

        for ck in cookies:
            name  = ck.get("name", "")
            value = ck.get("value", "")
            if not name or name.startswith("__Secure-") or name.startswith("__Host-"):
                continue
            # Typical tracking/analytics cookies — low security value, skip to
            # avoid bloating the surface map with GA/GTM noise
            if re.match(r'^(_ga|_gid|_gat|_fbp|_fbc|JSESSIONID_|csrftoken|_csrf)$',
                        name, re.I):
                # Still register JSESSIONID and csrf as they ARE interesting
                if not re.match(r'^(jsessionid|csrf)', name, re.I):
                    continue
            with self._sitemap_lock:
                self.sitemap.add_surface(InputSurface(
                    url=url.split("?")[0], method="GET",
                    param=name, param_type="cookie",
                    original_value=value[:200],
                ))

    def _apply_stealth(self, ctx):
        """
        Apply headless detection evasion — override navigator properties
        that bot detectors check. UNIQUE — no DAST tool does this.
        """
        stealth_js = """
        () => {
            Object.defineProperty(navigator, 'webdriver', {get: () => false});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
            Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 4});
            Object.defineProperty(screen, 'width',  {get: () => 1920});
            Object.defineProperty(screen, 'height', {get: () => 1080});
            Object.defineProperty(screen, 'colorDepth', {get: () => 24});
            window.chrome = {runtime: {}, loadTimes: () => ({}), csi: () => ({})};
            const origQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (params) =>
                params.name === 'notifications'
                    ? Promise.resolve({state: Notification.permission})
                    : origQuery(params);
        }
        """
        ctx.add_init_script(stealth_js)

    # ─────────────────────────────────────────────────────────────────────────
    # Single page navigation (called by each tab worker)
    # ─────────────────────────────────────────────────────────────────────────

    def _navigate(self, page, url: str, depth: int) -> list:
        """Navigate `page` to `url`, extract data, return list of (href, depth+1)."""
        new_urls = []
        try:
            # Use "domcontentloaded" instead of "networkidle" — SPAs with background
            # polling (heartbeat XHR, analytics) cause networkidle to never fire,
            # killing the whole crawl tab. domcontentloaded fires when HTML is parsed;
            # we then wait idle_wait ms for JS rendering to settle.
            resp = page.goto(
                url,
                timeout=self.page_timeout,
                wait_until="domcontentloaded",
            )
            page.wait_for_timeout(self.idle_wait)

            # ── Sprint 3.1: Session expiry detection → re-authenticate ────
            final_url = self._scope_base(page.url)
            if self.auth_config and self._is_login_page(final_url, resp, page):
                if self._reauth(page):
                    # Retry original URL with fresh session
                    resp = page.goto(url, timeout=self.page_timeout,
                                     wait_until="domcontentloaded")
                    page.wait_for_timeout(self.idle_wait)

            status = resp.status if resp else 0
            ct     = (resp.headers.get("content-type", "") if resp else "")
            title  = ""
            try:
                title = page.title()
            except Exception:
                pass

            # Feature 12: MLLM state-machine analysis (opt-in)
            mllm_state: dict = {}
            if self.mllm_crawl and self.llm_provider:
                try:
                    screenshot_bytes = page.screenshot()
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
                    html = page.content()
                    mllm_state = _analyze_page_state(screenshot_b64, html, self.llm_provider)
                    if mllm_state:
                        _llm_log.debug(
                            "MLLM state for %s: type=%s, actions=%d",
                            url,
                            mllm_state.get("page_type", "unknown"),
                            len(mllm_state.get("recommended_actions", [])),
                        )
                except Exception:
                    pass

            with self._sitemap_lock:
                self.sitemap.add_page(url, status, ct, {}, f"[Ajax] {title}")

            if self.callback:
                self.callback(url, status)

            # ── URL query params ──────────────────────────────────────────
            parsed = urlparse(url)
            if parsed.query:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param, vals in parse_qs(parsed.query).items():
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method="GET", param=param,
                            param_type="query",
                            original_value=vals[0] if vals else "",
                        ))

            # ── Forms via JS evaluation ───────────────────────────────────
            if depth < self.max_depth:
                try:
                    forms = page.evaluate(_JS_FORMS)
                    for form in forms:
                        action = form.get("action", url)
                        method = form.get("method", "GET").upper()
                        for inp in form.get("inputs", []):
                            if inp.get("name"):
                                with self._sitemap_lock:
                                    self.sitemap.add_surface(InputSurface(
                                        url=action, method=method,
                                        param=inp["name"],
                                        param_type="form",
                                        original_value=inp.get("value", ""),
                                        content_type="application/x-www-form-urlencoded",
                                    ))
                except Exception:
                    pass

            # ── Links for BFS queue ───────────────────────────────────────
            if depth < self.max_depth:
                try:
                    hrefs = page.evaluate(_JS_LINKS)
                    with self._visited_lock:
                        visited_snap = set(self._visited)
                    for href in hrefs:
                        href = self._strip_fragment(href)
                        if href not in visited_snap and self.scope.in_scope(
                            self._scope_base(href)
                        ):
                            new_urls.append((href, depth + 1))
                except Exception:
                    pass

            # ── Sprint 3.2: Smart form submission ─────────────────────────
            if self.smart_fill and depth < self.max_depth:
                form_urls = self._fill_and_submit_forms(page, url, depth)
                new_urls.extend(form_urls)

            # ── Sprint 4: Full SPA crawling ────────────────────────────
            if depth < self.max_depth:
                # 4.1 Scroll for lazy-loaded content
                self._scroll_for_lazy_content(page)

                # 4.2 Re-extract links after scroll (new content may have loaded)
                try:
                    hrefs = page.evaluate(_JS_LINKS)
                    with self._visited_lock:
                        visited_snap = set(self._visited)
                    for href in hrefs:
                        href = self._strip_fragment(href)
                        if href not in visited_snap and self.scope.in_scope(
                            self._scope_base(href)
                        ):
                            new_urls.append((href, depth + 1))
                except Exception:
                    pass

                # 4.3 Explore clickable elements (buttons, tabs, menus)
                click_urls = self._explore_clickables(page, url, depth)
                new_urls.extend(click_urls)

                # 4.4 Shadow DOM traversal
                shadow_urls = self._extract_shadow_dom(page, url, depth)
                new_urls.extend(shadow_urls)

                # 4.5 Extract routes from inline JS (Angular/React/Vue)
                route_urls = self._extract_js_routes(page, url, depth)
                new_urls.extend(route_urls)

                # 4.6 Hash-based SPA routes (actually navigates them)
                hash_urls = self._crawl_hash_routes(page, url, depth)
                new_urls.extend(hash_urls)

            # 4.7 Capture browser storage (always, regardless of depth)
            self._capture_storage(page, url)

            # 4.8 Extract browser cookies as attack surfaces
            self._extract_cookie_surfaces(page, url)

            # ── Sprint 5: Beyond Burp/ZAP ──────────────────────────────
            if depth < self.max_depth:
                # 5.1 Mine API endpoints from JS source
                api_urls = self._mine_api_endpoints(page, url, depth)
                new_urls.extend(api_urls)

                # 5.2 Detect GraphQL endpoints
                gql_urls = self._detect_graphql_endpoints(page, url, depth)
                new_urls.extend(gql_urls)

                # 5.3 Extract URLs from data-* attributes
                data_urls = self._extract_data_attributes(page, url, depth)
                new_urls.extend(data_urls)

                # 5.4 Prefetch/preload link discovery
                prefetch_urls = self._extract_prefetch_links(page, url, depth)
                new_urls.extend(prefetch_urls)

                # 5.5 Meta redirect following
                meta_urls = self._follow_meta_redirects(page, url, depth)
                new_urls.extend(meta_urls)

            # 5.6 Service worker detection (always)
            self._detect_service_workers(page, url)

            # 5.7 Event listener enumeration
            self._detect_event_listeners(page, url)

            # 5.8 PostMessage handler analysis
            self._detect_postmessage_handlers(page, url)

            # 5.9 WebSocket URL extraction from JS
            self._extract_websocket_urls(page, url)

            # ── Feature 12: MLLM-guided navigation ────────────────────────
            if mllm_state and depth < self.max_depth:
                parsed_base = urlparse(url)
                base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
                for action_desc in mllm_state.get("recommended_actions", [])[:5]:
                    # Try to extract actionable selectors or URLs from recommendations
                    if not isinstance(action_desc, str):
                        continue
                    # Look for URLs in the action description
                    url_match = re.search(r'(https?://\S+|/\S+)', action_desc)
                    if url_match:
                        action_url = url_match.group(1)
                        if action_url.startswith("/"):
                            action_url = base_url + action_url
                        action_clean = self._strip_fragment(action_url.split("?")[0].rstrip("/.,;"))
                        if self.scope.in_scope(self._scope_base(action_clean)):
                            with self._visited_lock:
                                if action_clean not in self._visited:
                                    new_urls.append((action_clean, depth + 1))
                                    _llm_log.debug("MLLM recommended URL: %s", action_clean)

        except PlaywrightTimeout:
            with self._sitemap_lock:
                self.sitemap.add_page(url, 0, "timeout", {}, "[Ajax] Timeout")
        except Exception:
            pass

        return new_urls

    # ─────────────────────────────────────────────────────────────────────────
    # Post-processing
    # ─────────────────────────────────────────────────────────────────────────

    def _add_network_and_ws_pages(self):
        """Add captured XHR and WebSocket URLs as sitemap pages."""
        seen_pages = set(self.sitemap.pages.keys())

        with self._net_lock:
            for nr in self._network_reqs:
                nurl = nr["url"].split("#")[0]
                if nurl not in seen_pages and self.scope.in_scope(nurl):
                    with self._sitemap_lock:
                        self.sitemap.add_page(nurl, 0, "xhr/network", {}, "[Ajax-net]")
                    seen_pages.add(nurl)

            for ws in self._ws_endpoints:
                ws_url = ws["url"]
                if ws_url not in seen_pages:
                    with self._sitemap_lock:
                        self.sitemap.add_page(ws_url, 101, "websocket", {}, "[WebSocket]")
                    seen_pages.add(ws_url)

    def _extract_network_surfaces(self):
        """Convert captured XHR/fetch requests into InputSurface objects."""
        seen: set[tuple] = set()

        for req in self._network_reqs:
            url    = req["url"]
            method = req["method"]
            key    = (url, method)
            if key in seen:
                continue
            seen.add(key)

            parsed = urlparse(url)
            clean  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Query params from URL
            if parsed.query:
                for param, vals in parse_qs(parsed.query).items():
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method=method, param=param,
                            param_type="query",
                            original_value=vals[0] if vals else "",
                        ))
            else:
                # GET/HEAD with no query params — add a `path` surface so the fuzzer
                # can test the URL segment for injection. e.g. GET /api/v1/users →
                # param_type="path", param="path"
                if method in ("GET", "HEAD") and parsed.path and parsed.path != "/":
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method=method, param="path",
                            param_type="path", original_value=clean,
                        ))

            # POST body
            post_data = req.get("post_data", "")
            ct = req.get("headers", {}).get("content-type", "")

            # GraphQL detection from actual network traffic
            if post_data:
                is_graphql = (
                    "graphql" in url.lower()
                    or "graphql" in ct.lower()
                    or ('"query"' in post_data[:500] and
                        any(op in post_data[:500] for op in
                            ('"mutation"', '"subscription"', '__typename', 'query {', 'mutation {')))
                )
                if is_graphql:
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method="POST", param="query",
                            param_type="json",
                            original_value='{"query":"{__typename}"}',
                            content_type="application/json",
                        ))

            if not post_data:
                continue

            if "application/json" in ct or "application/graphql" in ct:
                try:
                    body = json.loads(post_data)
                    if isinstance(body, dict):
                        for k, v in list(body.items())[:20]:
                            with self._sitemap_lock:
                                self.sitemap.add_surface(InputSurface(
                                    url=url, method=method, param=k,
                                    param_type="json",
                                    original_value=str(v),
                                    content_type="application/json",
                                ))
                except Exception:
                    pass

            elif "form" in ct or "urlencoded" in ct:
                for pair in post_data.split("&"):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        if k:
                            with self._sitemap_lock:
                                self.sitemap.add_surface(InputSurface(
                                    url=url, method=method, param=k,
                                    param_type="form", original_value=v,
                                    content_type="application/x-www-form-urlencoded",
                                ))

            elif "multipart/form-data" in ct:
                # Parse multipart field names from Content-Disposition headers in body
                for m in re.finditer(
                    r'Content-Disposition:\s*form-data;\s*name="([^"]+)"', post_data, re.I
                ):
                    fname = m.group(1)
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=url, method=method, param=fname,
                            param_type="form", original_value="",
                            content_type="multipart/form-data",
                        ))
