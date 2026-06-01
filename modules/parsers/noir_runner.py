from __future__ import annotations
import json
import logging
import shutil
import subprocess
from typing import Any

log = logging.getLogger(__name__)


class NoirRunner:
    """
    Runs the Noir (https://github.com/noir-cr/noir) binary for endpoint extraction.
    Noir supports 30+ frameworks and outputs JSON.
    Gracefully handles missing binary.
    """

    def __init__(self, binary: str = "noir"):
        self._binary = shutil.which(binary)

    @property
    def available(self) -> bool:
        return self._binary is not None

    def run(self, source_path: str, timeout: int = 120) -> list:
        """
        Run Noir on source tree. Returns list of DiscoveredEndpoint.
        Returns empty list if Noir is not installed or fails.
        """
        from ..source_discovery import DiscoveredEndpoint

        if not self.available:
            log.debug("[Noir] Binary not found — skipping")
            return []

        try:
            result = subprocess.run(
                [self._binary, "-b", source_path, "-f", "json", "--no-color"],
                capture_output=True, text=True, timeout=timeout,
            )

            if result.returncode != 0:
                log.warning("[Noir] Exit code %d: %s", result.returncode, result.stderr[:200])
                return []

            data = json.loads(result.stdout)
            endpoints = []

            for entry in data if isinstance(data, list) else data.get("endpoints", []):
                path = entry.get("url", entry.get("path", ""))
                method = entry.get("method", "GET").upper()
                params = []

                # Noir may include params
                for p in entry.get("params", []):
                    if isinstance(p, dict):
                        params.append(p.get("name", ""))
                    elif isinstance(p, str):
                        params.append(p)

                if path:
                    endpoints.append(DiscoveredEndpoint(
                        path=path,
                        method=method,
                        framework="noir",
                        source_file=entry.get("file", ""),
                        params=[p for p in params if p],
                        param_type="json" if method in ("POST", "PUT", "PATCH") else "query",
                        line_number=entry.get("line", 0),
                    ))

            log.info("[Noir] Extracted %d endpoints", len(endpoints))
            return endpoints

        except FileNotFoundError:
            log.debug("[Noir] Binary not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning("[Noir] Timed out after %ds", timeout)
            return []
        except json.JSONDecodeError as e:
            log.warning("[Noir] Invalid JSON output: %s", e)
            return []
        except Exception as e:
            log.warning("[Noir] Unexpected error: %s", e)
            return []
