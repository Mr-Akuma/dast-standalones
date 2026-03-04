"""
Forced Browse — wordlist-based hidden path/file discovery.
DirBuster / Feroxbuster style. Zero external dependencies.

Wordlists loaded from wordlists/ directory (30,000+ paths).
Supports: common.txt (full), or category-specific lists.
Fallback: minimal built-in list if files not found.
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
import requests.exceptions


# ── Wordlist Loading ─────────────────────────────────────────────────────────

_MODULE_DIR = Path(__file__).resolve().parent
_WORDLISTS_DIR = _MODULE_DIR.parent / "wordlists"

# Minimal fallback if wordlist files are missing
_FALLBACK_WORDLIST: list[str] = [
    "admin", "login", "api", "api/v1", "swagger.json", ".env", ".git/HEAD",
    "backup", "config", "debug", "test", "phpinfo.php", "robots.txt",
    "sitemap.xml", "wp-admin", "wp-login.php", ".htaccess", "server-status",
    "actuator/health", "graphql", "health", "status", "metrics",
]

# Available category wordlists (loaded on demand)
WORDLIST_CATEGORIES: dict[str, str] = {
    "common":       "common.txt",          # Full combined list (41K+)
    "admin":        "admin-panels.txt",
    "api":          "api-endpoints.txt",
    "auth":         "auth-session.txt",
    "backup":       "backup-files.txt",
    "cloud":        "cloud-infra.txt",
    "cms":          "cms-platforms.txt",
    "config":       "config-secrets.txt",
    "database":     "database-tools.txt",
    "debug":        "dev-debug.txt",
    "dirs":         "common-dirs.txt",
    "extended":     "extended-paths.txt",
    "files":        "common-files.txt",
    "frameworks":   "frameworks.txt",
    "security":     "security-scanpaths.txt",
    "vcs":          "vcs-cicd.txt",
}


def load_wordlist(name: str = "common", wordlist_dir: Path | None = None) -> list[str]:
    """Load a wordlist by category name or file path.

    Args:
        name: Category name (e.g. "common", "admin", "api") or absolute file path.
              Empty string returns empty list (useful when only extra_wordlist is wanted).
        wordlist_dir: Override directory to search for wordlist files.

    Returns:
        List of unique paths from the wordlist file.
    """
    if not name:
        return []

    wdir = wordlist_dir or _WORDLISTS_DIR

    # Direct file path
    if os.path.isabs(name) and os.path.isfile(name):
        return _read_wordlist_file(Path(name))

    # Category lookup
    filename = WORDLIST_CATEGORIES.get(name, name)
    filepath = wdir / filename

    # Try with .txt extension if not found
    if not filepath.exists() and not filename.endswith(".txt"):
        filepath = wdir / f"{filename}.txt"

    if filepath.exists():
        return _read_wordlist_file(filepath)

    # Fallback
    return list(_FALLBACK_WORDLIST)


def load_multiple_wordlists(*names: str, wordlist_dir: Path | None = None) -> list[str]:
    """Load and merge multiple wordlists, deduplicating paths.

    Args:
        *names: Category names or file paths to load.
        wordlist_dir: Override directory.

    Returns:
        Merged, deduplicated list of paths.
    """
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        for path in load_wordlist(name, wordlist_dir):
            if path not in seen:
                seen.add(path)
                result.append(path)
    return result


def available_wordlists(wordlist_dir: Path | None = None) -> dict[str, int]:
    """List available wordlists with their line counts.

    Returns:
        Dict of {category_name: line_count} for all available wordlist files.
    """
    wdir = wordlist_dir or _WORDLISTS_DIR
    available: dict[str, int] = {}
    if not wdir.exists():
        return available
    for name, filename in WORDLIST_CATEGORIES.items():
        fp = wdir / filename
        if fp.exists():
            with open(fp, "r") as f:
                available[name] = sum(1 for line in f if line.strip())
    return available


def _read_wordlist_file(filepath: Path) -> list[str]:
    """Read a wordlist file, returning unique non-empty lines."""
    seen: set[str] = set()
    result: list[str] = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            path = line.strip()
            if path and not path.startswith("#") and path not in seen:
                seen.add(path)
                result.append(path)
    return result


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
        wordlist_name:  str = "common",
        wordlist_path:  str | None = None,
        workers:        int   = 15,
        timeout:        int   = 8,
        delay:          float = 0.01,
        stop_event:     threading.Event | None = None,
        callback = None,   # called with BrowseResult on each interesting hit
    ):
        self.base_url    = base_url.rstrip("/")
        self.session     = session

        # Load wordlist from file, with optional extras appended
        if wordlist_path:
            base_words = load_wordlist(wordlist_path)
        else:
            base_words = load_wordlist(wordlist_name)

        if extra_wordlist:
            seen = set(base_words)
            for w in extra_wordlist:
                if w not in seen:
                    base_words.append(w)
                    seen.add(w)

        self.wordlist    = base_words
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
