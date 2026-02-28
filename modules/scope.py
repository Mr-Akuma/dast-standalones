"""
Scope Manager — enforces in-scope URL boundaries for all DAST operations.
All crawler and fuzzer requests are validated here before execution.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse


class ScopeManager:
    def __init__(self, target: str, extra_domains: list[str] | None = None,
                 excluded_paths: list[str] | None = None):
        parsed       = urlparse(target)
        self.base_domain   = parsed.netloc or target
        self.scheme        = parsed.scheme or "http"
        self.base_url      = f"{self.scheme}://{self.base_domain}"
        self.allowed_domains: set[str] = {self.base_domain}
        if extra_domains:
            self.allowed_domains.update(extra_domains)
        self.excluded_paths: list[str] = excluded_paths or [
            "/logout", "/signout", "/log-out", "/sign-out",
            "/delete", "/remove", "/destroy",
            "/admin/delete", "/api/delete",
        ]
        self.excluded_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
            ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".pdf",
            ".zip", ".tar", ".gz", ".exe", ".dmg",
        }

    def in_scope(self, url: str) -> bool:
        """Return True if URL is within scan scope."""
        try:
            p = urlparse(url)
            if p.netloc and p.netloc not in self.allowed_domains:
                return False
            path = p.path.lower()
            # Excluded extensions
            for ext in self.excluded_extensions:
                if path.endswith(ext):
                    return False
            # Excluded paths
            for ep in self.excluded_paths:
                if path.startswith(ep.lower()):
                    return False
            return True
        except Exception:
            return False

    def normalise(self, url: str, base: str = "") -> str:
        """Resolve relative URL against base, return absolute."""
        if url.startswith("http://") or url.startswith("https://"):
            return url
        if url.startswith("//"):
            return f"{self.scheme}:{url}"
        if url.startswith("/"):
            return f"{self.base_url}{url}"
        if base:
            # relative path
            base_path = "/".join(urlparse(base).path.split("/")[:-1])
            return f"{self.base_url}{base_path}/{url}"
        return f"{self.base_url}/{url}"

    def same_host(self, url: str) -> bool:
        p = urlparse(url)
        return p.netloc == self.base_domain or not p.netloc
