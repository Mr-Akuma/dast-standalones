from __future__ import annotations
import re
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# FastAPI / Flask method decorators:
#   @app.get("/users/{user_id}")
#   @router.post("/items")
#   @app.put("/x"), @app.delete("/x"), @app.patch("/x"), @app.options("/x"), @app.head("/x")
#   Flask 2.0+ shorthand: @app.get("/users"), @app.post("/users")
_METHOD_DECORATOR_RE = re.compile(
    r"""@\w+\.(get|post|put|delete|patch|options|head)\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Flask @app.route / @blueprint.route with explicit methods list:
#   @app.route("/users", methods=["GET", "POST"])
_ROUTE_METHODS_RE = re.compile(
    r"""@\w+\.route\s*\(\s*["']([^"']+)["'].*?methods\s*=\s*\[([^\]]+)\]""",
    re.IGNORECASE,
)

# Flask @app.route / @blueprint.route without methods (defaults to GET):
#   @app.route("/users")
_ROUTE_DEFAULT_RE = re.compile(
    r"""@\w+\.route\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Extract path params: FastAPI {param}, Flask <type:param> or <param>
_FASTAPI_PARAM_RE = re.compile(r'\{(\w+)\}')
_FLASK_PARAM_RE = re.compile(r'<(?:\w+:)?(\w+)>')

# Directories to skip during traversal
_SKIP_DIRS = frozenset(('__pycache__', '.venv', 'venv', '.git', 'node_modules', 'migrations'))

# Framework detection from imports
_FASTAPI_IMPORT_RE = re.compile(r'(?:from\s+fastapi|import\s+fastapi)', re.IGNORECASE)
_FLASK_IMPORT_RE = re.compile(r'(?:from\s+flask|import\s+flask)', re.IGNORECASE)


def _extract_params(path: str) -> list[str]:
    """Extract path parameters from both FastAPI and Flask path styles."""
    params = _FASTAPI_PARAM_RE.findall(path)
    params.extend(_FLASK_PARAM_RE.findall(path))
    return params


def _detect_framework(content: str) -> str:
    """Detect framework from import statements. Defaults to 'fastapi'."""
    if _FLASK_IMPORT_RE.search(content):
        return "flask"
    if _FASTAPI_IMPORT_RE.search(content):
        return "fastapi"
    # Heuristic: if we see Flask-style angle-bracket params, assume flask
    if _FLASK_PARAM_RE.search(content):
        return "flask"
    return "fastapi"


class PythonWebParser:
    """Parse FastAPI and Flask route definitions from Python source files."""

    def parse(self, source_path: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints: list[DiscoveredEndpoint] = []

        for filepath in Path(source_path).rglob('*.py'):
            # Skip ignored directories
            if _SKIP_DIRS & set(filepath.parts):
                continue
            try:
                content = filepath.read_text(errors='ignore')
                endpoints.extend(self._parse_file(str(filepath), content))
            except Exception as e:
                log.debug("[PythonWebParser] Error reading %s: %s", filepath, e)

        return endpoints

    def _parse_file(self, filepath: str, content: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints: list[DiscoveredEndpoint] = []
        framework = _detect_framework(content)
        lines = content.split('\n')

        # Track which lines we've already matched to avoid duplicates
        matched_lines: set[tuple[str, str]] = set()

        for i, line in enumerate(lines, 1):
            # 1) Method decorators: @app.get("/path"), @router.post("/path")
            for match in _METHOD_DECORATOR_RE.finditer(line):
                method = match.group(1).upper()
                path = match.group(2)
                key = (path, method)
                if key not in matched_lines:
                    matched_lines.add(key)
                    params = _extract_params(path)
                    endpoints.append(DiscoveredEndpoint(
                        path=path, method=method, framework=framework,
                        source_file=filepath, params=params,
                        param_type="path" if params else "query",
                        line_number=i,
                    ))

            # 2) Route with explicit methods: @app.route("/path", methods=["GET", "POST"])
            for match in _ROUTE_METHODS_RE.finditer(line):
                path = match.group(1)
                methods_raw = match.group(2)
                # Parse method names from the list, e.g. "GET", "POST"
                methods = re.findall(r'["\'](\w+)["\']', methods_raw)
                for method in methods:
                    method = method.upper()
                    key = (path, method)
                    if key not in matched_lines:
                        matched_lines.add(key)
                        params = _extract_params(path)
                        endpoints.append(DiscoveredEndpoint(
                            path=path, method=method, framework=framework,
                            source_file=filepath, params=params,
                            param_type="path" if params else "query",
                            line_number=i,
                        ))

            # 3) Route without methods (default GET): @app.route("/path")
            #    Only if not already matched by the methods variant above
            for match in _ROUTE_DEFAULT_RE.finditer(line):
                path = match.group(1)
                # Skip if this line was already handled by _ROUTE_METHODS_RE
                if _ROUTE_METHODS_RE.search(line):
                    continue
                # Skip if this line was already handled by _METHOD_DECORATOR_RE
                if _METHOD_DECORATOR_RE.search(line):
                    continue
                key = (path, "GET")
                if key not in matched_lines:
                    matched_lines.add(key)
                    params = _extract_params(path)
                    endpoints.append(DiscoveredEndpoint(
                        path=path, method="GET", framework=framework,
                        source_file=filepath, params=params,
                        param_type="path" if params else "query",
                        line_number=i,
                    ))

        return endpoints
