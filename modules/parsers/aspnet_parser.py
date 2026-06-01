from __future__ import annotations
import re
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Class-level [Route("api/[controller]")] or [Route("custom/path")]
_CLASS_ROUTE_RE = re.compile(
    r'\[Route\(\s*"([^"]+)"\s*\)\]',
)

# [ApiController] attribute
_API_CONTROLLER_RE = re.compile(r'\[ApiController\]')

# Class declaration: public class UsersController : ControllerBase
_CLASS_DECL_RE = re.compile(
    r'(?:public\s+)?class\s+(\w+)\s*(?::\s*[\w.<>,\s]+)?'
)

# Method-level HTTP attributes: [HttpGet], [HttpGet("path")], [HttpPost("path")], etc.
_HTTP_METHOD_RE = re.compile(
    r'\[(Http(?:Get|Post|Put|Delete|Patch))(?:\(\s*"([^"]*)"\s*\))?\]'
)

# Method-level [Route("...")] for explicit route overrides
_METHOD_ROUTE_RE = re.compile(
    r'\[Route\(\s*"([^"]+)"\s*\)\]'
)

# Path parameters like {id}, {userId}
_PATH_PARAM_RE = re.compile(r'\{(\w+)\}')

# Directories to skip
_SKIP_DIRS = frozenset(('bin', 'obj', 'node_modules', '.git'))

# Map attribute name -> HTTP method
_METHOD_MAP = {
    'HttpGet': 'GET',
    'HttpPost': 'POST',
    'HttpPut': 'PUT',
    'HttpDelete': 'DELETE',
    'HttpPatch': 'PATCH',
}


class AspNetParser:
    """Parse ASP.NET Core controller route definitions from C# source files."""

    def parse(self, source_path: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []

        for filepath in Path(source_path).rglob('*.cs'):
            # Skip excluded directories
            if any(skip in filepath.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = filepath.read_text(errors='ignore')
                # Only parse files with controller markers
                if not (_API_CONTROLLER_RE.search(content) or _CLASS_ROUTE_RE.search(content)):
                    continue
                endpoints.extend(self._parse_file(str(filepath), content))
            except Exception as e:
                log.debug("[AspNetParser] Error reading %s: %s", filepath, e)

        return endpoints

    def _parse_file(self, filepath: str, content: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []
        lines = content.split('\n')

        # Pass 1: find the class-level route and controller name
        base_route = ''
        controller_name = ''

        for i, line in enumerate(lines):
            # Look for class-level [Route(...)]
            route_match = _CLASS_ROUTE_RE.search(line)
            if route_match and not base_route:
                # Only set base_route if we haven't found a class declaration yet,
                # or this precedes a class declaration (attribute on class)
                candidate_base = route_match.group(1)
                # Check next few lines for class declaration to confirm it's class-level
                lookahead = '\n'.join(lines[i:min(len(lines), i + 5)])
                class_match = _CLASS_DECL_RE.search(lookahead)
                if class_match:
                    base_route = candidate_base
                    controller_name = class_match.group(1)

            # Direct class declaration (if route was on a prior line)
            if not controller_name:
                class_match = _CLASS_DECL_RE.search(line)
                if class_match and 'Controller' in class_match.group(1):
                    controller_name = class_match.group(1)

        # Replace [controller] placeholder with actual controller name (minus "Controller" suffix)
        if controller_name and controller_name.endswith('Controller'):
            short_name = controller_name[:-len('Controller')].lower()
        else:
            short_name = controller_name.lower() if controller_name else ''

        base_route = base_route.replace('[controller]', short_name)

        # Normalize base route
        base_route = base_route.strip('/')

        # Pass 2: find method-level HTTP attributes
        pending_route = ''
        for i, line in enumerate(lines):
            stripped = line.strip()

            # Capture method-level [Route("...")] that may precede an Http attribute
            method_route_match = _METHOD_ROUTE_RE.search(stripped)
            # Only treat as method-level route if no Http attribute on same line
            # and this isn't the class-level route
            if method_route_match and not _HTTP_METHOD_RE.search(stripped):
                # Check if this could be the class-level route (near class decl)
                lookahead = '\n'.join(lines[i:min(len(lines), i + 5)])
                if not _CLASS_DECL_RE.search(lookahead):
                    pending_route = method_route_match.group(1)

            http_match = _HTTP_METHOD_RE.search(stripped)
            if not http_match:
                continue

            attr_name = http_match.group(1)  # e.g. "HttpGet"
            method_path = http_match.group(2) or ''  # e.g. "users/{id}" or empty
            http_method = _METHOD_MAP.get(attr_name, 'GET')

            # If there was a pending [Route(...)] just before this, use it
            if pending_route and not method_path:
                method_path = pending_route

            # Build full path
            parts = []
            if base_route:
                parts.append(base_route)
            if method_path:
                parts.append(method_path.strip('/'))

            full_path = '/' + '/'.join(parts) if parts else '/'

            # Extract path parameters
            params = _PATH_PARAM_RE.findall(full_path)

            endpoints.append(DiscoveredEndpoint(
                path=full_path,
                method=http_method,
                framework='aspnet',
                source_file=filepath,
                params=params,
                param_type='path' if params else 'query',
                line_number=i + 1,
            ))

            # Reset pending route after consuming
            pending_route = ''

        return endpoints
