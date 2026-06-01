from __future__ import annotations
import re
import os
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Patterns to match:
# router.get('/api/users', ...)
# app.post('/api/users/:id', ...)
# router.use('/api', subRouter)
# app.route('/path').get(...).post(...)
# Express: get, post, put, delete, patch, options, head, all
# Koa: router.get, router.post, etc.

_ROUTE_RE = re.compile(
    r"""(?:app|router|server|route)\s*\.\s*(get|post|put|delete|patch|options|head|all|use)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE
)

# app.route('/path') pattern
_ROUTE_CHAIN_RE = re.compile(
    r"""\.route\s*\(\s*["'`]([^"'`]+)["'`]\s*\)""",
    re.IGNORECASE
)

# Extract path params like :id, :userId
_PATH_PARAM_RE = re.compile(r':(\w+)')


class ExpressParser:
    """Parse Express.js and Koa route definitions."""

    def parse(self, source_path: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []

        # Find all JS/TS files
        for ext in ('*.js', '*.ts', '*.mjs', '*.cjs'):
            for filepath in Path(source_path).rglob(ext):
                # Skip node_modules, dist, build
                parts = filepath.parts
                if any(skip in parts for skip in ('node_modules', 'dist', 'build', '.next', 'coverage')):
                    continue
                try:
                    content = filepath.read_text(errors='ignore')
                    endpoints.extend(self._parse_file(str(filepath), content))
                except Exception as e:
                    log.debug("[ExpressParser] Error reading %s: %s", filepath, e)

        return endpoints

    def _parse_file(self, filepath: str, content: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            for match in _ROUTE_RE.finditer(line):
                method = match.group(1).upper()
                path = match.group(2)

                if method == 'USE':
                    method = 'GET'  # middleware prefix — treat as GET
                if method == 'ALL':
                    # Create entries for common methods
                    for m in ('GET', 'POST', 'PUT', 'DELETE'):
                        params = _PATH_PARAM_RE.findall(path)
                        endpoints.append(DiscoveredEndpoint(
                            path=path, method=m, framework="express",
                            source_file=filepath, params=params,
                            param_type="path" if params else "query",
                            line_number=i,
                        ))
                    continue

                params = _PATH_PARAM_RE.findall(path)
                endpoints.append(DiscoveredEndpoint(
                    path=path, method=method, framework="express",
                    source_file=filepath, params=params,
                    param_type="path" if params else "query",
                    line_number=i,
                ))

            # Route chain pattern
            for match in _ROUTE_CHAIN_RE.finditer(line):
                path = match.group(1)
                params = _PATH_PARAM_RE.findall(path)
                # Look for chained methods in surrounding lines
                context = '\n'.join(lines[max(0,i-1):min(len(lines),i+5)])
                for m in ('get', 'post', 'put', 'delete', 'patch'):
                    if re.search(rf'\.{m}\s*\(', context, re.I):
                        endpoints.append(DiscoveredEndpoint(
                            path=path, method=m.upper(), framework="express",
                            source_file=filepath, params=params,
                            param_type="path" if params else "query",
                            line_number=i,
                        ))

        return endpoints
