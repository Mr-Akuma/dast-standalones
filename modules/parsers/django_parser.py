from __future__ import annotations
import re
import os
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Patterns to match:
# path('api/users/', views.user_list)
# path('api/users/<int:pk>/', views.user_detail)
# re_path(r'^api/items/(?P<id>\d+)/$', views.item_detail)
# url(r'^api/old/', views.old_endpoint)   (Django 1.x)
# include('app.urls')                      (note the prefix)

_PATH_RE = re.compile(
    r"""path\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_RE_PATH_RE = re.compile(
    r"""re_path\(\s*r?["']([^"']+)["']""",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"""url\(\s*r?["']([^"']+)["']""",
    re.IGNORECASE,
)

# include('app.urls') — capture the prefix from the surrounding path/url call
_INCLUDE_RE = re.compile(
    r"""(?:path|url)\(\s*r?["']([^"']*?)["']\s*,\s*include\(""",
    re.IGNORECASE,
)

# Django path converters: <int:pk>, <slug:title>, <pk>
_DJANGO_PARAM_RE = re.compile(r'<(?:\w+:)?(\w+)>')

# Regex named groups: (?P<id>\d+)
_REGEX_PARAM_RE = re.compile(r'\(\?P<(\w+)>')

# View name hints for HTTP method inference
_METHOD_HINTS = {
    'create': 'POST',
    'add':    'POST',
    'new':    'POST',
    'store':  'POST',
    'update': 'PUT',
    'edit':   'PUT',
    'modify': 'PUT',
    'delete': 'DELETE',
    'remove': 'DELETE',
    'destroy': 'DELETE',
}

_SKIP_DIRS = frozenset((
    'node_modules', '__pycache__', '.venv', 'venv', '.git', 'migrations',
))


def _clean_regex_path(path: str) -> str:
    """Convert regex route path to a cleaner form for scanning."""
    # Strip leading ^ and trailing $
    path = path.lstrip('^').rstrip('$')
    # Replace (?P<name>...) with <name>
    path = _REGEX_PARAM_RE.sub(r'<\1>', path)
    # Remove leftover regex artifacts like \d+, [^/]+, etc.
    path = re.sub(r'[(\[\]\\dw+?*^$)]+', '', path)
    # Collapse multiple slashes
    path = re.sub(r'/+', '/', path)
    return path


def _infer_method(view_text: str) -> str:
    """Infer HTTP method from view function/class name."""
    lower = view_text.lower()
    for hint, method in _METHOD_HINTS.items():
        if hint in lower:
            return method
    return 'GET'


class DjangoParser:
    """Parse Django urlpatterns from urls.py files."""

    def parse(self, source_path: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []

        for filepath in Path(source_path).rglob('urls.py'):
            # Skip unwanted directories
            if any(skip in filepath.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = filepath.read_text(errors='ignore')
                endpoints.extend(self._parse_file(str(filepath), content))
            except Exception as e:
                log.debug("[DjangoParser] Error reading %s: %s", filepath, e)

        return endpoints

    def _parse_file(self, filepath: str, content: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []
        lines = content.split('\n')

        # First pass: collect include prefixes so we know them but don't emit them
        # as standalone endpoints (they are just namespace prefixes).
        include_prefixes: set[str] = set()
        for line in lines:
            m = _INCLUDE_RE.search(line)
            if m:
                include_prefixes.add(m.group(1))

        for i, line in enumerate(lines, 1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith('#'):
                continue

            # --- path() ---
            for match in _PATH_RE.finditer(line):
                raw_path = match.group(1)
                # Skip if this is an include() line — it's a prefix, not a route
                if 'include(' in line:
                    continue
                params = _DJANGO_PARAM_RE.findall(raw_path)
                # Get the remainder of the line to extract view name for method hint
                rest_of_line = line[match.end():]
                method = _infer_method(rest_of_line)
                endpoints.append(DiscoveredEndpoint(
                    path='/' + raw_path.lstrip('/'),
                    method=method,
                    framework='django',
                    source_file=filepath,
                    params=params,
                    param_type='path' if params else 'query',
                    line_number=i,
                ))

            # --- re_path() ---
            for match in _RE_PATH_RE.finditer(line):
                raw_path = match.group(1)
                if 'include(' in line:
                    continue
                # Extract named groups before cleaning
                params = _REGEX_PARAM_RE.findall(raw_path)
                clean = _clean_regex_path(raw_path)
                rest_of_line = line[match.end():]
                method = _infer_method(rest_of_line)
                endpoints.append(DiscoveredEndpoint(
                    path='/' + clean.lstrip('/'),
                    method=method,
                    framework='django',
                    source_file=filepath,
                    params=params,
                    param_type='path' if params else 'query',
                    line_number=i,
                ))

            # --- url() (Django 1.x) ---
            for match in _URL_RE.finditer(line):
                # Avoid double-matching re_path or path lines
                preceding = line[:match.start()]
                if 're_path' in preceding or 'path(' in preceding:
                    continue
                raw_path = match.group(1)
                if 'include(' in line:
                    continue
                params = _REGEX_PARAM_RE.findall(raw_path)
                clean = _clean_regex_path(raw_path)
                rest_of_line = line[match.end():]
                method = _infer_method(rest_of_line)
                endpoints.append(DiscoveredEndpoint(
                    path='/' + clean.lstrip('/'),
                    method=method,
                    framework='django',
                    source_file=filepath,
                    params=params,
                    param_type='path' if params else 'query',
                    line_number=i,
                ))

        return endpoints
