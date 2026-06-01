from __future__ import annotations
import re
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Method-specific mapping annotations -> HTTP method
_METHOD_MAPPINGS = {
    'GetMapping':    'GET',
    'PostMapping':   'POST',
    'PutMapping':    'PUT',
    'DeleteMapping': 'DELETE',
    'PatchMapping':  'PATCH',
}

# @RequestMapping("/path") or @RequestMapping(value="/path", method=RequestMethod.GET)
_REQUEST_MAPPING_RE = re.compile(
    r'@RequestMapping\s*\(\s*'
    r'(?:'
    r'(?:value\s*=\s*)?["\']([^"\']+)["\']'   # simple path or value="path"
    r'|'
    r'[^)]*value\s*=\s*["\']([^"\']+)["\']'    # value= anywhere in args
    r')'
    r'(?:.*?method\s*=\s*RequestMethod\.(\w+))?'  # optional method
    r'[^)]*\)'
)

# @GetMapping("/path"), @PostMapping({"/a", "/b"}), @DeleteMapping, etc.
_SPECIFIC_MAPPING_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch)Mapping\s*'
    r'(?:\(\s*'
    r'(?:'
    r'(?:value\s*=\s*)?["\']([^"\']+)["\']'   # single path
    r'|'
    r'(?:value\s*=\s*)?\{([^}]*)\}'           # array of paths {"/a", "/b"}
    r')?'
    r'[^)]*\))?'
)

# Class-level @RequestMapping for base prefix
_CLASS_MAPPING_RE = re.compile(
    r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']\s*[^)]*\)\s*'
    r'(?:\n\s*)?(?:public\s+)?(?:abstract\s+)?class\s',
    re.MULTILINE
)

# Extract {param} path variables
_PATH_PARAM_RE = re.compile(r'\{(\w+)\}')

# Extract multiple quoted strings from array syntax like {"/a", "/b"}
_ARRAY_PATH_RE = re.compile(r'["\']([^"\']+)["\']')

# Directories to skip
_SKIP_DIRS = ('target', 'build', '.gradle', 'node_modules', '.idea', '.mvn', 'bin', 'out')


class SpringParser:
    """Parse Spring Boot / Spring MVC route definitions from Java and Kotlin files."""

    def parse(self, source_path: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []

        for ext in ('*.java', '*.kt'):
            for filepath in Path(source_path).rglob(ext):
                parts = filepath.parts
                if any(skip in parts for skip in _SKIP_DIRS):
                    continue
                try:
                    content = filepath.read_text(errors='ignore')
                    endpoints.extend(self._parse_file(str(filepath), content))
                except Exception as e:
                    log.debug("[SpringParser] Error reading %s: %s", filepath, e)

        return endpoints

    def _parse_file(self, filepath: str, content: str) -> list:
        from ..source_discovery import DiscoveredEndpoint
        endpoints = []

        # 1. Detect class-level @RequestMapping prefix
        base_path = ''
        class_match = _CLASS_MAPPING_RE.search(content)
        if class_match:
            base_path = class_match.group(1).rstrip('/')

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # 2. Check method-specific annotations: @GetMapping, @PostMapping, etc.
            for match in _SPECIFIC_MAPPING_RE.finditer(stripped):
                method_prefix = match.group(1)  # Get, Post, Put, Delete, Patch
                http_method = _METHOD_MAPPINGS[method_prefix + 'Mapping']

                # Extract path(s)
                single_path = match.group(2)  # single quoted path
                array_paths = match.group(3)  # array syntax content

                paths = []
                if single_path:
                    paths.append(single_path)
                elif array_paths:
                    paths = _ARRAY_PATH_RE.findall(array_paths)
                else:
                    # Bare annotation like @GetMapping with no path -> root
                    paths.append('')

                for path in paths:
                    full_path = self._combine_paths(base_path, path)
                    params = _PATH_PARAM_RE.findall(full_path)
                    endpoints.append(DiscoveredEndpoint(
                        path=full_path,
                        method=http_method,
                        framework='spring',
                        source_file=filepath,
                        params=params,
                        param_type='path' if params else 'query',
                        line_number=i,
                    ))

            # 3. Check @RequestMapping on methods (not class-level)
            if '@RequestMapping' in stripped and 'class ' not in stripped:
                # Skip if already matched as class-level
                if class_match and i <= content[:class_match.end()].count('\n') + 1:
                    continue

                for match in _REQUEST_MAPPING_RE.finditer(stripped):
                    path = match.group(1) or match.group(2) or ''
                    method_str = match.group(3)

                    if method_str:
                        methods = [method_str.upper()]
                    else:
                        # No method specified -> defaults to all, treat as GET
                        methods = ['GET']

                    full_path = self._combine_paths(base_path, path)
                    params = _PATH_PARAM_RE.findall(full_path)

                    for method in methods:
                        endpoints.append(DiscoveredEndpoint(
                            path=full_path,
                            method=method,
                            framework='spring',
                            source_file=filepath,
                            params=params,
                            param_type='path' if params else 'query',
                            line_number=i,
                        ))

        return endpoints

    @staticmethod
    def _combine_paths(base: str, path: str) -> str:
        """Combine a base path prefix with a method-level path."""
        base = base.rstrip('/')
        path = path.strip('/')
        if not base and not path:
            return '/'
        if not path:
            return base or '/'
        if not base:
            return '/' + path
        return base + '/' + path
