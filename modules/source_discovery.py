from __future__ import annotations
import os
import logging
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    """An API endpoint discovered from source code analysis."""
    path: str              # e.g., "/api/users/:id"
    method: str            # GET, POST, PUT, DELETE, PATCH
    framework: str         # express, django, spring, rails, fastapi, flask, aspnet
    source_file: str       # file it was found in
    params: list[str] = field(default_factory=list)  # discovered parameter names
    param_type: str = "query"  # likely param type
    line_number: int = 0

    def to_input_surface(self, base_url: str):
        """Convert to InputSurface for the scanner queue."""
        from .crawler import InputSurface
        # Normalize path: replace :param, {param}, <param> with placeholder
        import re
        url_path = re.sub(r'[:{}](\w+)[}]?', r'\1', self.path)
        # Handle <type:param> Django/Flask patterns
        url_path = re.sub(r'<(?:\w+:)?(\w+)>', r'\1', url_path)
        full_url = base_url.rstrip('/') + '/' + url_path.lstrip('/')

        surfaces = []
        if self.params:
            for param in self.params:
                surfaces.append(InputSurface(
                    url=full_url,
                    method=self.method.upper(),
                    param=param,
                    param_type=self.param_type,
                ))
        else:
            # No params discovered — create surface with empty param for forced browse
            surfaces.append(InputSurface(
                url=full_url,
                method=self.method.upper(),
                param="",
                param_type="path",
            ))
        return surfaces


# Framework detection signatures
_FRAMEWORK_SIGNATURES = {
    "express": [
        ("package.json", r'"express"|"koa"'),
        ("*.js", r'require\(["\']express["\']\)|from ["\']express["\']'),
        ("*.ts", r'from ["\']express["\']|import.*express'),
    ],
    "django": [
        ("manage.py", r'django'),
        ("**/urls.py", r'urlpatterns'),
        ("settings.py", r'INSTALLED_APPS'),
    ],
    "spring": [
        ("pom.xml", r'spring-boot'),
        ("build.gradle", r'spring-boot'),
        ("**/*.java", r'@SpringBootApplication|@RestController'),
    ],
    "rails": [
        ("Gemfile", r'rails'),
        ("config/routes.rb", r'\.routes\.draw'),
    ],
    "fastapi": [
        ("*.py", r'from fastapi|import fastapi|FastAPI\(\)'),
        ("requirements.txt", r'fastapi'),
    ],
    "flask": [
        ("*.py", r'from flask|import flask|Flask\(__name__\)'),
        ("requirements.txt", r'flask'),
    ],
    "aspnet": [
        ("*.csproj", r'Microsoft\.AspNetCore'),
        ("**/*.cs", r'\[ApiController\]|\[HttpGet\]'),
    ],
}


class SourceDiscovery:
    """
    Discovers API endpoints from source code by detecting the framework
    and running the appropriate parser.
    """

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self._endpoints: list[DiscoveredEndpoint] = []

    def discover(self, source_path: str) -> list[DiscoveredEndpoint]:
        """
        Main entry point: detect framework(s) in source tree and parse routes.
        Returns list of DiscoveredEndpoint.
        """
        source_path = os.path.abspath(source_path)
        if not os.path.isdir(source_path):
            log.warning("[SourceDiscovery] Not a directory: %s", source_path)
            return []

        frameworks = self.detect_frameworks(source_path)
        log.info("[SourceDiscovery] Detected frameworks: %s", frameworks)

        endpoints = []

        for fw in frameworks:
            try:
                parser_endpoints = self._run_parser(fw, source_path)
                endpoints.extend(parser_endpoints)
                log.info("[SourceDiscovery] %s parser found %d endpoints", fw, len(parser_endpoints))
            except Exception as e:
                log.warning("[SourceDiscovery] %s parser failed: %s", fw, e)

        # Also try Noir if available
        try:
            from .parsers.noir_runner import NoirRunner
            noir = NoirRunner()
            noir_endpoints = noir.run(source_path)
            # Merge — avoid duplicates by path+method
            existing = {(e.path, e.method) for e in endpoints}
            for ne in noir_endpoints:
                if (ne.path, ne.method) not in existing:
                    endpoints.append(ne)
            if noir_endpoints:
                log.info("[SourceDiscovery] Noir found %d additional endpoints",
                        len([e for e in noir_endpoints if (e.path, e.method) not in existing]))
        except Exception as e:
            log.debug("[SourceDiscovery] Noir not available: %s", e)

        self._endpoints = endpoints
        return endpoints

    def to_input_surfaces(self, base_url: str = "") -> list:
        """Convert all discovered endpoints to InputSurface objects."""
        url = base_url or self.base_url
        surfaces = []
        for ep in self._endpoints:
            surfaces.extend(ep.to_input_surface(url))
        return surfaces

    def detect_frameworks(self, source_path: str) -> list[str]:
        """Detect which frameworks are present in the source tree."""
        import re
        detected = []

        for fw, signatures in _FRAMEWORK_SIGNATURES.items():
            for glob_pattern, regex in signatures:
                # Search for matching files
                matches = list(Path(source_path).rglob(glob_pattern))
                for match in matches[:5]:  # Cap file reads per signature
                    try:
                        content = match.read_text(errors='ignore')[:10000]
                        if re.search(regex, content):
                            if fw not in detected:
                                detected.append(fw)
                            break
                    except Exception:
                        continue
                if fw in detected:
                    break

        return detected

    def _run_parser(self, framework: str, source_path: str) -> list[DiscoveredEndpoint]:
        """Run the appropriate parser for a detected framework."""
        parsers = {
            "express": (".parsers.express_parser", "ExpressParser"),
            "django":  (".parsers.django_parser", "DjangoParser"),
            "spring":  (".parsers.spring_parser", "SpringParser"),
            "rails":   (".parsers.rails_parser", "RailsParser"),
            "fastapi": (".parsers.python_web_parser", "PythonWebParser"),
            "flask":   (".parsers.python_web_parser", "PythonWebParser"),
            "aspnet":  (".parsers.aspnet_parser", "AspNetParser"),
        }

        if framework not in parsers:
            return []

        module_path, class_name = parsers[framework]
        import importlib
        mod = importlib.import_module(module_path, package="modules")
        parser_class = getattr(mod, class_name)
        parser = parser_class()
        return parser.parse(source_path)

    def summary(self) -> dict:
        """Return discovery summary."""
        by_framework = {}
        for ep in self._endpoints:
            by_framework.setdefault(ep.framework, 0)
            by_framework[ep.framework] += 1
        return {
            "total_endpoints": len(self._endpoints),
            "by_framework": by_framework,
        }


def extract_webpack_endpoints(js_content: str) -> list[str]:
    """Extract API endpoint paths from Webpack-bundled JavaScript.

    Based on Microsoft MSRC Scaling DAST (2025): dynamic endpoint discovery
    from runtime artifacts dramatically improves attack surface coverage.

    Parses:
    - fetch("/api/...", ...) calls
    - axios.get("/api/..."), axios.post(...)
    - Template literal API paths: `/api/${id}/resource`
    - String literal routes: "/api/users", "/v1/orders"
    - Angular/React router definitions: path: '/users/:id'
    - Express-style route definitions: app.get('/api/...', ...)

    Returns:
        Deduplicated list of discovered endpoint paths (strings starting with / or http)
    """
    import re
    endpoints = set()

    # fetch() and axios calls
    patterns = [
        r'fetch\s*\(\s*[`"\']([/a-zA-Z0-9_\-\.{}:$]+)[`"\']',
        r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`"\']([/a-zA-Z0-9_\-\.{}:$]+)[`"\']',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*[`"\']([/a-zA-Z][/a-zA-Z0-9_\-\.{}:$]*)[`"\']',
        # String literals that look like API paths
        r'[`"\'](/api/[a-zA-Z0-9_\-/\.{}:$]+)[`"\']',
        r'[`"\'](/v[0-9]+/[a-zA-Z0-9_\-/\.{}:$]+)[`"\']',
        # Router definitions
        r'path\s*:\s*[`"\']([/a-zA-Z0-9_\-/:]+)[`"\']',
        r'route\s*:\s*[`"\']([/a-zA-Z0-9_\-/:]+)[`"\']',
        # Express-style
        r'app\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*[`"\']([/a-zA-Z0-9_\-/:]+)[`"\']',
        r'router\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`"\']([/a-zA-Z0-9_\-/:]+)[`"\']',
        # URL assignments
        r'url\s*[=:]\s*[`"\']([/a-zA-Z][/a-zA-Z0-9_\-\.{}:$]+)[`"\']',
        r'endpoint\s*[=:]\s*[`"\']([/a-zA-Z][/a-zA-Z0-9_\-\.{}:$]+)[`"\']',
        r'baseURL\s*[=:]\s*[`"\']([/a-zA-Z][/a-zA-Z0-9_\-\.{}:$]+)[`"\']',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, js_content):
            path = match.group(1)
            # Filter: must look like a real path
            if len(path) >= 3 and path.startswith('/') and not path.startswith('//'):
                # Exclude common false positives
                if not any(fp in path for fp in ['.js', '.css', '.png', '.svg', '.ico', '{{', '${{']):
                    endpoints.add(path)

    return sorted(endpoints)


def extract_service_worker_routes(sw_content: str) -> list[str]:
    """Extract fetch-intercepted routes from a service worker script.

    Service workers' fetch event handlers reveal all routes the app intercepts,
    including API endpoints that may not appear in normal crawling.
    """
    import re
    routes = set()

    # event.request.url patterns
    patterns = [
        r'url\.includes\s*\(\s*[`"\']([/a-zA-Z0-9_\-/\.]+)[`"\']',
        r'url\.startsWith\s*\(\s*[`"\']([/a-zA-Z][/a-zA-Z0-9_\-/\.]+)[`"\']',
        r'url\.pathname\s*===?\s*[`"\']([/a-zA-Z0-9_\-/\.]+)[`"\']',
        r'cacheName\s*[=:]\s*[`"\']([a-zA-Z0-9_\-]+)[`"\']',  # Cache names hint at route groups
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, sw_content):
            path = match.group(1)
            if path.startswith('/') and len(path) >= 2:
                routes.add(path)

    return sorted(routes)
