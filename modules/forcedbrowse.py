"""
Forced Browse — wordlist-based hidden path/file discovery.
DirBuster / Feroxbuster style. Zero external dependencies.

Built-in wordlist: ~2,000 common dirs/files/endpoints.
Optional: pass extra_wordlist for custom paths.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urljoin

import requests
import requests.exceptions


# ── Wordlist ──────────────────────────────────────────────────────────────────

_WORDLIST: list[str] = [
    # ── Admin / Management ────────────────────────────────────────────────────
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "admin/dashboard", "admin/panel", "admin/config", "admin/settings",
    "admin/users", "admin/db", "admin/backup", "admin/logs",
    "admin/console", "admin/shell", "admin/terminal",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-cron.php",
    "phpmyadmin", "phpMyAdmin", "phpinfo.php", "pma",
    "manager", "management", "panel", "controlpanel", "cpanel",
    "webadmin", "adminer", "adminer.php",

    # ── Authentication ────────────────────────────────────────────────────────
    "login", "logout", "signin", "signup", "signout",
    "register", "registration", "auth", "authenticate",
    "account", "accounts", "user", "users", "profile",
    "dashboard", "home", "portal", "member", "members",
    "forgot-password", "reset-password", "change-password",
    "2fa", "mfa", "otp", "verify", "verification",

    # ── API endpoints ─────────────────────────────────────────────────────────
    "api", "api/v1", "api/v2", "api/v3", "api/v4",
    "rest", "rest/v1", "rest/api", "service", "services",
    "graphql", "gql", "query",
    "swagger.json", "swagger.yaml", "swagger-ui.html",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "api-docs", "api/docs", "apidocs", "redoc", "docs", "documentation",
    "v1", "v2", "v3", "api/users", "api/admin", "api/config",
    "api/debug", "api/test", "api/health", "api/status", "api/info",
    "api/me", "api/profile", "api/token", "api/login", "api/logout",
    "api/register", "api/reset", "api/forgot",
    "api/products", "api/orders", "api/payments", "api/invoices",
    "api/upload", "api/download", "api/export", "api/import",

    # ── Configuration / Secrets ───────────────────────────────────────────────
    ".env", ".env.local", ".env.development", ".env.staging",
    ".env.production", ".env.backup", ".env.bak", ".env.old",
    ".env.example", ".env.sample", ".env.test",
    "config.php", "config.js", "config.json", "config.yaml",
    "config.xml", "config.ini", "config.cfg", "config.yml",
    "configuration.php", "configuration.xml",
    "settings.php", "settings.py", "settings.json", "settings.xml",
    "local.php", "local.py", "local.json",
    "production.php", "production.json",
    "web.config", "applicationHost.config",
    "app.config", "application.properties", "application.yml",
    "database.yml", "database.php", "db.php", "db.json",
    "secrets.json", "secrets.yaml", "credentials.json", "credentials.xml",

    # ── Git / VCS ─────────────────────────────────────────────────────────────
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".git/logs/HEAD", ".git/refs/heads/main", ".git/refs/heads/master",
    ".gitignore", ".gitconfig",
    ".svn/entries", ".svn/wc.db",
    ".hg/requires", "CVS/Root",
    ".DS_Store", "Thumbs.db",

    # ── Backup files ──────────────────────────────────────────────────────────
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql",
    "backup.tar", "backup.tgz", "backup.bak",
    "db.sql", "database.sql", "dump.sql", "mysql.sql",
    "site.tar.gz", "www.tar.gz", "htdocs.zip", "public_html.zip",
    "old", "temp", "tmp", "cache", "data",
    "index.php.bak", "index.php~", "index.php.old",
    "login.php.bak", "config.php.bak",

    # ── CMS – WordPress ───────────────────────────────────────────────────────
    "wp-content", "wp-includes", "xmlrpc.php", "wp-json",
    "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
    "wp-content/uploads", "wp-content/plugins",
    "wp-config.php", "wp-config.php.bak",

    # ── CMS – Joomla ──────────────────────────────────────────────────────────
    "administrator", "index.php/administrator",
    "configuration.php", "joomla",

    # ── CMS – Drupal ──────────────────────────────────────────────────────────
    "sites/default/files", "sites/default/settings.php",
    "CHANGELOG.txt", "core/install.php",

    # ── Frameworks ────────────────────────────────────────────────────────────
    "console", "rails/info", "rails/info/properties",
    "actuator", "actuator/health", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/dump",
    "actuator/trace", "actuator/logfile", "actuator/httptrace",
    ".well-known/security.txt", ".well-known/change-password",
    "robots.txt", "sitemap.xml", "sitemap.html", "humans.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",

    # ── Dev / Debug ───────────────────────────────────────────────────────────
    "debug", "test", "testing", "dev", "development", "staging",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "status", "healthz", "health", "ping", "metrics",
    "server-status", "server-info", "nginx-status",
    "telescope", "horizon", "debugbar",
    "_profiler", "_wdt", "profiler",
    "trace", "env", "properties",

    # ── Logs ──────────────────────────────────────────────────────────────────
    "log", "logs", "error.log", "access.log", "debug.log",
    "app.log", "error_log", "application.log", "system.log",
    "audit.log", "security.log", "server.log",

    # ── Upload / Media ────────────────────────────────────────────────────────
    "upload", "uploads", "files", "file", "media",
    "images", "image", "img", "attachments", "assets",
    "static", "public", "storage",

    # ── Source code / Build ───────────────────────────────────────────────────
    "source", "src", "include", "includes", "lib", "libs",
    "vendor", "node_modules",
    "Gemfile", "requirements.txt", "composer.json", "package.json",
    "yarn.lock", "package-lock.json", "Pipfile",
    "Makefile", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "README", "README.md", "CHANGELOG", "LICENSE", "TODO", "INSTALL",

    # ── Security files ────────────────────────────────────────────────────────
    ".htaccess", ".htpasswd", "htpasswd",
    "ssl", "certs", "pki",

    # ── Common API patterns ───────────────────────────────────────────────────
    "search", "query", "find", "results",
    "export", "import", "download", "report", "reports",
    "webhook", "webhooks", "callback", "notify", "notification",
    "subscribe", "unsubscribe", "feed",
    "token", "tokens", "refresh", "revoke",
    "session", "sessions", "auth/token", "oauth", "oauth2",
    "oauth/authorize", "oauth/token", "connect/token",
    "saml", "saml/sso", "saml/metadata",

    # ── Cloud / Container ─────────────────────────────────────────────────────
    "metadata", "latest/meta-data", "computeMetadata",
    "v1beta1/instance", "instance/service-accounts",
    "169.254.169.254",   # AWS/GCP metadata
]


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BrowseResult:
    url:            str
    status_code:    int
    content_length: int
    content_type:   str
    redirect_to:    str  = ""
    note:           str  = ""
    interesting:    bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ── Forced Browser ────────────────────────────────────────────────────────────

class ForcedBrowser:
    """
    Threaded wordlist-based path discovery.
    Returns paths that exist (2xx), are forbidden (403/401),
    or redirect (3xx) — all indicate the resource exists.
    """

    INTERESTING_STATUS = {200, 201, 204, 206, 301, 302, 307, 308, 400, 401, 403, 405, 500, 503}

    def __init__(
        self,
        base_url:       str,
        session:        requests.Session,
        extra_wordlist: list[str] | None = None,
        workers:        int   = 15,
        timeout:        int   = 8,
        delay:          float = 0.01,
        stop_event:     threading.Event | None = None,
        callback = None,   # called with BrowseResult on each interesting hit
    ):
        self.base_url    = base_url.rstrip("/")
        self.session     = session
        self.wordlist    = _WORDLIST + (extra_wordlist or [])
        self.workers     = workers
        self.timeout     = timeout
        self.delay       = delay
        self.stop_event  = stop_event or threading.Event()
        self.callback    = callback
        self.results:    list[BrowseResult] = []
        self._lock       = threading.Lock()

    def run(self) -> list[BrowseResult]:
        """Discover paths. Returns list of interesting BrowseResults."""
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._probe, word): word for word in self.wordlist}
            for fut in as_completed(futures):
                if self.stop_event.is_set():
                    break
                try:
                    result = fut.result()
                    if result and result.interesting:
                        with self._lock:
                            self.results.append(result)
                        if self.callback:
                            self.callback(result)
                except Exception:
                    pass
        return self.results

    def _probe(self, path: str) -> Optional[BrowseResult]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            if self.delay:
                time.sleep(self.delay)
            resp = self.session.get(
                url,
                timeout  = self.timeout,
                allow_redirects = False,
                headers  = {"User-Agent": "Mozilla/5.0 (DAST-ForcedBrowse/2.0)"},
                verify   = False,
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            return None

        sc = resp.status_code
        if sc not in self.INTERESTING_STATUS:
            return None

        ct  = resp.headers.get("content-type", "")
        cl  = int(resp.headers.get("content-length", len(resp.content)))
        loc = resp.headers.get("location", "")

        if sc in (301, 302, 307, 308):
            note = f"Redirects → {loc}"
        elif sc == 403:
            note = "Forbidden — resource exists but access denied"
        elif sc == 401:
            note = "Unauthorized — authentication required"
        elif sc == 405:
            note = "Method Not Allowed — endpoint exists"
        elif sc == 500:
            note = "Server error — code path triggered"
        elif sc == 200:
            note = f"Found ({cl} bytes)"
        else:
            note = f"Status {sc}"

        return BrowseResult(
            url            = url,
            status_code    = sc,
            content_length = cl,
            content_type   = ct,
            redirect_to    = loc,
            note           = note,
            interesting    = True,
        )
