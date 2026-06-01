"""
Attack surface model for the DAST scanner.

Builds a topology of the target web application: auth boundaries,
trust zones, data flows between zones, and attack prioritisation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
import re


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

STATIC_EXTENSIONS = frozenset(
    [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".map"]
)

ADMIN_PATTERNS = re.compile(r"/(admin|dashboard|manage)(/|$|\?)", re.IGNORECASE)


@dataclass
class EndpointNode:
    url: str
    method: str
    auth_required: bool = False
    auth_level: str = "unknown"          # public | authenticated | admin | unknown
    content_type: str = ""
    is_static: bool = False
    params: list[str] = field(default_factory=list)
    linked_to: list[str] = field(default_factory=list)
    linked_from: list[str] = field(default_factory=list)
    finding_count: int = 0


@dataclass
class TrustZone:
    name: str                             # public | authenticated | admin | api | internal
    endpoints: list[str] = field(default_factory=list)
    boundary_type: str = "none"           # auth_cookie | bearer_token | api_key | ip_restrict | none


# ---------------------------------------------------------------------------
# Surface model
# ---------------------------------------------------------------------------

class SurfaceModel:
    """Maintains a live topology of discovered endpoints and their trust relationships."""

    def __init__(self) -> None:
        self._endpoints: dict[str, EndpointNode] = {}
        self._zones: list[TrustZone] = []

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _key(url: str, method: str) -> str:
        return f"{method.upper()}::{url}"

    @staticmethod
    def _is_static_url(url: str) -> bool:
        path = urlparse(url).path
        dot = path.rfind(".")
        if dot == -1:
            return False
        return path[dot:].lower() in STATIC_EXTENSIONS

    @staticmethod
    def _infer_auth_level(url: str, status_code: int, auth_used: bool) -> str:
        if ADMIN_PATTERNS.search(url):
            return "admin"
        if status_code in (401, 403) and not auth_used:
            return "authenticated"
        if status_code < 400 and not auth_used:
            return "public"
        if auth_used and status_code < 400:
            return "authenticated"
        return "unknown"

    @staticmethod
    def _is_api(url: str) -> bool:
        path = urlparse(url).path.lower()
        return "/api/" in path or path.startswith("/api")

    # -- mutators ---------------------------------------------------------

    def add_endpoint(
        self,
        url: str,
        method: str,
        status_code: int,
        headers: Optional[dict] = None,
        params: Optional[list] = None,
        auth_used: bool = False,
    ) -> EndpointNode:
        """Create or update an EndpointNode from an observed request/response."""
        headers = headers or {}
        params = params or []

        key = self._key(url, method)
        node = self._endpoints.get(key)

        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        is_static = self._is_static_url(url)
        auth_required = status_code in (401, 403) and not auth_used
        auth_level = self._infer_auth_level(url, status_code, auth_used)

        if node is None:
            node = EndpointNode(
                url=url,
                method=method.upper(),
                auth_required=auth_required,
                auth_level=auth_level,
                content_type=content_type,
                is_static=is_static,
                params=list(params),
            )
            self._endpoints[key] = node
        else:
            # Merge — keep the most restrictive auth info we've seen
            if auth_required:
                node.auth_required = True
            if node.auth_level == "unknown":
                node.auth_level = auth_level
            if content_type:
                node.content_type = content_type
            for p in params:
                if p not in node.params:
                    node.params.append(p)

        return node

    def add_link(self, from_url: str, to_url: str) -> None:
        """Record a data-flow / navigation edge between two URLs."""
        for key, node in self._endpoints.items():
            if node.url == from_url and to_url not in node.linked_to:
                node.linked_to.append(to_url)
            if node.url == to_url and from_url not in node.linked_from:
                node.linked_from.append(from_url)

    def observe_finding(self, url: str, method: str) -> None:
        """Increment finding count for the given endpoint."""
        key = self._key(url, method)
        node = self._endpoints.get(key)
        if node:
            node.finding_count += 1

    # -- zone construction ------------------------------------------------

    def build_zones(self) -> list[TrustZone]:
        """Cluster endpoints into trust zones based on auth level, path prefix, and boundary patterns."""
        buckets: dict[str, list[str]] = {
            "public": [],
            "authenticated": [],
            "admin": [],
            "api": [],
            "internal": [],
        }

        for key, node in self._endpoints.items():
            url = node.url
            if self._is_api(url):
                buckets["api"].append(url)
            elif node.auth_level == "admin":
                buckets["admin"].append(url)
            elif node.auth_level == "authenticated":
                buckets["authenticated"].append(url)
            elif node.auth_level == "public":
                buckets["public"].append(url)
            else:
                buckets["internal"].append(url)

        self._zones = []
        for name, urls in buckets.items():
            if not urls:
                continue
            boundary = self._infer_boundary(name, urls)
            self._zones.append(
                TrustZone(name=name, endpoints=urls, boundary_type=boundary)
            )

        return list(self._zones)

    def _infer_boundary(self, zone_name: str, urls: list[str]) -> str:
        """Heuristic: guess what kind of auth boundary guards a zone."""
        if zone_name == "public":
            return "none"
        if zone_name == "api":
            # Look for bearer / api-key patterns in the endpoints we recorded
            for key, node in self._endpoints.items():
                if node.url in urls:
                    ct = node.content_type.lower()
                    if "json" in ct:
                        return "bearer_token"
            return "api_key"
        if zone_name in ("authenticated", "admin"):
            return "auth_cookie"
        return "none"

    # -- queries ----------------------------------------------------------

    def get_attack_priorities(self) -> list[dict]:
        """Return endpoints ranked by testing priority (1 = highest)."""
        results: list[dict] = []

        boundary_urls = {n.url for n in self.get_boundary_endpoints()}

        for node in self._endpoints.values():
            if node.is_static:
                results.append(self._prio(node, 10, "Static resource — low value"))
                continue

            if node.url in boundary_urls:
                results.append(self._prio(node, 1, "Auth boundary transition"))
                continue

            if node.finding_count > 0:
                results.append(
                    self._prio(node, 2, f"Has {node.finding_count} existing finding(s) — expand testing")
                )
                continue

            if node.auth_level == "admin":
                results.append(self._prio(node, 3, "Admin endpoint — high value target"))
                continue

            if self._is_api(node.url) and node.params:
                results.append(
                    self._prio(node, 4, "API endpoint with parameters — likely data access")
                )
                continue

            if self._is_api(node.url):
                results.append(self._prio(node, 5, "API endpoint"))
                continue

            if node.auth_level == "authenticated":
                results.append(self._prio(node, 5, "Authenticated endpoint"))
                continue

            if node.params:
                results.append(self._prio(node, 6, "Dynamic endpoint with parameters"))
                continue

            results.append(self._prio(node, 7, "Standard endpoint"))

        results.sort(key=lambda r: r["priority"])
        return results

    @staticmethod
    def _prio(node: EndpointNode, priority: int, reason: str) -> dict:
        return {
            "url": node.url,
            "method": node.method,
            "priority": priority,
            "reason": reason,
        }

    def get_data_flows(self) -> list[dict]:
        """Return edges showing data flow between trust zones."""
        if not self._zones:
            self.build_zones()

        url_zone: dict[str, str] = {}
        for zone in self._zones:
            for url in zone.endpoints:
                url_zone[url] = zone.name

        flows: list[dict] = []
        seen: set[tuple[str, str, str, str]] = set()

        for node in self._endpoints.values():
            src_zone = url_zone.get(node.url, "unknown")
            for target_url in node.linked_to:
                dst_zone = url_zone.get(target_url, "unknown")
                edge = (node.url, target_url, src_zone, dst_zone)
                if edge not in seen:
                    seen.add(edge)
                    flows.append({
                        "from_url": node.url,
                        "to_url": target_url,
                        "from_zone": src_zone,
                        "to_zone": dst_zone,
                        "cross_boundary": src_zone != dst_zone,
                    })

        # Cross-boundary flows first
        flows.sort(key=lambda f: (not f["cross_boundary"], f["from_zone"]))
        return flows

    def get_boundary_endpoints(self) -> list[EndpointNode]:
        """Endpoints sitting at trust-zone boundaries — most interesting for testing."""
        if not self._zones:
            self.build_zones()

        url_zone: dict[str, str] = {}
        for zone in self._zones:
            for url in zone.endpoints:
                url_zone[url] = zone.name

        boundary: list[EndpointNode] = []
        for node in self._endpoints.values():
            node_zone = url_zone.get(node.url, "unknown")
            # Linked from a different zone?
            for src_url in node.linked_from:
                src_zone = url_zone.get(src_url, "unknown")
                if src_zone != node_zone:
                    boundary.append(node)
                    break
            else:
                # Also treat auth-required endpoints that neighbour public ones
                if node.auth_required and node_zone != "public":
                    # Check if any public endpoint links here
                    for src_url in node.linked_from:
                        if url_zone.get(src_url) == "public":
                            boundary.append(node)
                            break

        return boundary

    def summary(self) -> dict:
        """Aggregate statistics about the discovered attack surface."""
        total = len(self._endpoints)
        static = sum(1 for n in self._endpoints.values() if n.is_static)
        dynamic = total - static

        by_auth: dict[str, int] = {}
        for node in self._endpoints.values():
            by_auth[node.auth_level] = by_auth.get(node.auth_level, 0) + 1

        if not self._zones:
            self.build_zones()

        by_zone: dict[str, int] = {z.name: len(z.endpoints) for z in self._zones}

        total_findings = sum(n.finding_count for n in self._endpoints.values())
        finding_density = (total_findings / dynamic) if dynamic else 0.0

        return {
            "total_endpoints": total,
            "static": static,
            "dynamic": dynamic,
            "by_auth_level": by_auth,
            "by_zone": by_zone,
            "total_findings": total_findings,
            "finding_density": round(finding_density, 3),
            "boundary_endpoints": len(self.get_boundary_endpoints()),
        }
