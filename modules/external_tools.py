"""
External security tool integrations — hybrid subprocess wrappers.

Each runner checks if the binary is available (shutil.which). If not installed,
run() returns an empty list and the scan continues with built-in checks only.

Supported tools:
  - sqlmap   → deep SQL injection testing
  - nuclei   → 8000+ community vulnerability templates
  - nmap     → port/service enumeration and NSE scripts
  - gobuster → wordlist-based directory/path discovery (dir mode)
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse, urlencode

from .event_bus import safe_publish, EXTERNAL_TOOL_DONE

# Wordlists directory — absolute path relative to this module file
_WORDLISTS_DIR = (Path(__file__).parent.parent / "wordlists").resolve()

log = logging.getLogger("dast.external_tools")

_LOG_LEVEL_RE = re.compile(r"^\[.*?\]\s*")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _severity_map(sev: str) -> str:
    """Normalise severity strings to our standard: Critical/High/Medium/Low/Info."""
    s = sev.strip().lower()
    return {
        "critical": "Critical", "high": "High", "medium": "Medium",
        "low": "Low", "info": "Info", "informational": "Info",
        "unknown": "Info",
    }.get(s, "Info")


# ═════════════════════════════════════════════════════════════════════════════
#  SQLMAP
# ═════════════════════════════════════════════════════════════════════════════

class SqlmapRunner:
    """Wrapper around the real sqlmap binary."""

    TIMEOUT = 180  # 3 minutes per URL / group

    # Tamper scripts by WAF product — use only universally-installed sqlmap tampers
    _WAF_TAMPER_MAP: dict[str, str] = {
        "Cloudflare":          "space2comment,between,charencode,randomcase",
        "ModSecurity":         "space2comment,between,charencode",
        "AWS WAF":             "space2comment,between,hex2char",
        "Imperva":             "space2comment,between,charencode,equaltolike",
        "Akamai":              "space2comment,between,charencode",
        "Sucuri":              "space2comment,between",
        "F5 BIG-IP ASM":       "space2comment,between,charencode",
        "Barracuda":           "space2comment,between",
    }
    _DEFAULT_TAMPER = "space2comment,between"

    _SURFACE_SKIP_TYPES = frozenset(
        ("header", "path", "path_filename", "request_line", "xml", "multipart")
    )

    @classmethod
    def available(cls) -> bool:
        return shutil.which("sqlmap") is not None

    @classmethod
    def tamper_for_waf(cls, waf_name: str | None) -> str:
        """Return tamper script string for detected WAF, or default if unknown."""
        if not waf_name:
            return cls._DEFAULT_TAMPER
        for key, tamper in cls._WAF_TAMPER_MAP.items():
            if key.lower() in waf_name.lower():
                return tamper
        return cls._DEFAULT_TAMPER

    @classmethod
    def run(
        cls,
        target: str,
        urls_with_params: list[str] | None = None,
        dbms: str | None = None,
        tamper: str | None = None,
        stop_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[dict]:
        """
        Run sqlmap against target URLs.

        Args:
            target: Base target URL (used if urls_with_params is empty)
            urls_with_params: Specific URLs with query params to test.
                              If empty, sqlmap crawls from target with --forms --crawl=2.
            stop_event: Threading event to check for cancellation.
            on_progress: Callback for status updates.

        Returns:
            List of finding dicts matching the _findings schema.
        """
        if not cls.available():
            log.info("[sqlmap] Binary not found, skipping")
            return []

        findings = []
        tmpdir = tempfile.mkdtemp(prefix="dast_sqlmap_")

        try:
            # Determine URLs to scan
            test_urls = urls_with_params or [target]

            for i, url in enumerate(test_urls):
                if stop_event and stop_event.is_set():
                    break

                if on_progress:
                    on_progress(f"sqlmap: testing URL {i+1}/{len(test_urls)}")

                output_dir = os.path.join(tmpdir, f"target_{i}")
                cmd = [
                    "sqlmap",
                    "-u", url,
                    "--batch",           # non-interactive
                    "--level=3",
                    "--risk=2",
                    "--forms",           # auto-detect forms
                    "--crawl=2",         # crawl depth 2
                    "--threads=4",
                    "--output-dir", output_dir,
                    "--flush-session",
                    "--disable-coloring",
                ]
                if dbms:
                    cmd.extend(["--dbms", dbms])
                if tamper:
                    cmd.extend(["--tamper", tamper])

                log.info("[sqlmap] Running: %s", " ".join(cmd))

                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=cls.TIMEOUT,
                    )
                    stdout = result.stdout or ""

                    raw = cls._parse_output(url, stdout)
                    raw += cls._parse_output_dir(url, output_dir)
                    findings.extend(cls._dedup_findings(raw))

                except subprocess.TimeoutExpired:
                    log.warning("[sqlmap] Timed out after %ds on %s", cls.TIMEOUT, url)
                    findings.append({
                        "agent": "sqlmap",
                        "severity": "Info",
                        "type": "sqli_timeout",
                        "finding": f"sqlmap timed out after {cls.TIMEOUT}s — target may need longer scan",
                        "url": url,
                    })
                except Exception as e:
                    log.error("[sqlmap] Error on %s: %s", url, e)

        finally:
            # Clean up temp dir
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

        return findings

    @classmethod
    def run_surfaces(
        cls,
        surfaces,
        dbms: str | None = None,
        tamper: str | None = None,
        stop_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[dict]:
        """
        Run sqlmap with full BEUST technique coverage, targeting specific crawler surfaces.

        Groups surfaces by (url, method, param_type) and builds one targeted sqlmap
        command per group — passing -p param1,param2 and proper --data/--cookie flags.
        Groups run in parallel (ThreadPoolExecutor, max 4 workers).
        Skips surface types sqlmap cannot meaningfully target (headers, path segments).
        """
        if not cls.available() or not surfaces:
            return []

        groups: dict[tuple, list] = {}
        for surf in surfaces:
            if surf.param_type in cls._SURFACE_SKIP_TYPES:
                continue
            groups.setdefault((surf.url, surf.method, surf.param_type), []).append(surf)

        if not groups:
            return []

        tmpdir = tempfile.mkdtemp(prefix="dast_sqlmap_")
        total = len(groups)

        def _build_cmd(url, method, param_type, grp, output_dir):
            p_flag = ",".join(s.param for s in grp)
            base = [
                "--batch", "--technique=BEUST", "--level=3", "--risk=2",
                "--threads=4", "--output-dir", output_dir,
                "--flush-session", "--disable-coloring", "-p", p_flag,
            ]
            if dbms:
                base.extend(["--dbms", dbms])
            if tamper:
                base.extend(["--tamper", tamper])
            if param_type == "query":
                qs = urlencode({s.param: s.original_value or "1" for s in grp})
                return ["sqlmap", "-u", f"{url}?{qs}"] + base

            body = next((s.body_template for s in grp if s.body_template), None)
            if param_type == "form":
                if not body:
                    body = urlencode({s.param: s.original_value or "test" for s in grp})
                cmd = ["sqlmap", "-u", url, "--data", body] + base
            elif param_type == "json":
                if not body:
                    body = json.dumps({s.param: s.original_value or "1" for s in grp})
                cmd = ["sqlmap", "-u", url, "--data", body,
                       "--headers", "Content-Type: application/json"] + base
            elif param_type == "cookie":
                cookie_str = "; ".join(f"{s.param}={s.original_value or '1'}" for s in grp)
                return ["sqlmap", "-u", url, "--cookie", cookie_str] + base
            else:
                return ["sqlmap", "-u", url] + base

            if method not in ("GET", ""):
                cmd.extend(["--method", method])
            return cmd

        def _run_group(idx, url, method, param_type, grp):
            if stop_event and stop_event.is_set():
                return []
            p_flag = ",".join(s.param for s in grp)
            if on_progress:
                on_progress(f"sqlmap: {idx+1}/{total} {method} {url} -p {p_flag}")
            output_dir = os.path.join(tmpdir, f"g{idx}")
            cmd = _build_cmd(url, method, param_type, grp, output_dir)
            log.info("[sqlmap] run_surfaces: %s", " ".join(cmd))
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=cls.TIMEOUT)
                raw = cls._parse_output(url, result.stdout or "")
                raw += cls._parse_output_dir(url, output_dir)
                return cls._dedup_findings(raw)
            except subprocess.TimeoutExpired:
                log.warning("[sqlmap] timed out: %s -p %s", url, p_flag)
            except Exception as exc:
                log.error("[sqlmap] error %s: %s", url, exc)
            return []

        from concurrent.futures import ThreadPoolExecutor, as_completed
        findings = []
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                futs = {
                    pool.submit(_run_group, idx, url, method, pt, grp): (url, pt)
                    for idx, ((url, method, pt), grp) in enumerate(groups.items())
                }
                for fut in as_completed(futs):
                    if stop_event and stop_event.is_set():
                        break
                    try:
                        findings.extend(fut.result())
                    except Exception as exc:
                        log.error("[sqlmap] group thread error: %s", exc)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return findings

    @classmethod
    def _parse_output(cls, url: str, stdout: str, log_file: bool = False) -> list[dict]:
        """Parse sqlmap stdout (or log file content) for injection confirmations.

        Captures Type/Title/Payload/Vector per technique block and useful WARNING lines.
        """
        findings: list[dict] = []
        current_param: str | None = None
        current_http_method: str | None = None
        pending: list[tuple[str, str, str, str]] = []  # (type, title, payload, vector)
        cur_type: str | None = None
        cur_title: str | None = None
        cur_payload: str | None = None
        cur_vector: str | None = None

        def _commit_technique():
            nonlocal cur_type, cur_title, cur_payload, cur_vector
            if cur_type:
                pending.append((cur_type, cur_title or "", cur_payload or "", cur_vector or ""))
            cur_type = cur_title = cur_payload = cur_vector = None

        def _commit_param():
            nonlocal current_param, current_http_method
            for (inj_type, title, payload, vector) in pending:
                text = f"SQL injection confirmed — param '{current_param}'"
                if current_http_method:
                    text += f" ({current_http_method})"
                if title:
                    text += f": {title}"
                f: dict = {
                    "agent": "sqlmap",
                    "severity": "Critical",
                    "type": "sqli_confirmed",
                    "finding": text,
                    "url": url,
                    "param": current_param,
                    "technique": inj_type,
                    "tool_detail": inj_type,
                }
                if payload:
                    f["payload"] = payload
                if vector:
                    f["vector"] = vector
                if log_file:
                    f["log_file"] = True
                findings.append(f)
            pending.clear()
            current_param = None
            current_http_method = None

        for line in stdout.splitlines():
            stripped = line.strip()

            param_match = re.search(r"Parameter:\s+(\S+)\s+\((\w+)\)", stripped)
            if param_match:
                _commit_technique()
                if current_param:
                    _commit_param()
                current_param = param_match.group(1)
                current_http_method = param_match.group(2)
                continue

            if current_param:
                m = re.match(r"Type:\s+(.+)", stripped)
                if m:
                    _commit_technique()
                    cur_type = m.group(1).strip()
                    continue
                m = re.match(r"Title:\s+(.+)", stripped)
                if m:
                    cur_title = m.group(1).strip()
                    continue
                m = re.match(r"Payload:\s+(.+)", stripped)
                if m:
                    cur_payload = m.group(1).strip()
                    continue
                m = re.match(r"Vector:\s+(.+)", stripped)
                if m:
                    cur_vector = m.group(1).strip()
                    continue

            if "[CRITICAL]" in stripped and "injectable" in stripped.lower():
                f = {
                    "agent": "sqlmap",
                    "severity": "Critical",
                    "type": "sqli_confirmed",
                    "finding": _LOG_LEVEL_RE.sub("", stripped),
                    "url": url,
                }
                if log_file:
                    f["log_file"] = True
                findings.append(f)

            if "[WARNING]" in stripped and any(kw in stripped.lower() for kw in (
                "heuristic", "filter", "waf", "protected", "injectable", "might be",
            )):
                f = {
                    "agent": "sqlmap",
                    "severity": "Info",
                    "type": "sqli_warning",
                    "finding": _LOG_LEVEL_RE.sub("", stripped),
                    "url": url,
                }
                if log_file:
                    f["log_file"] = True
                findings.append(f)

        _commit_technique()
        if current_param:
            _commit_param()

        dbms_match = re.search(r"back-end DBMS:\s+(.+)", stdout)
        if dbms_match:
            findings.append({
                "agent": "sqlmap",
                "severity": "Info",
                "type": "dbms_fingerprint",
                "finding": f"Database identified: {dbms_match.group(1).strip()}",
                "url": url,
            })

        return findings

    @classmethod
    def _parse_output_dir(cls, url: str, output_dir: str) -> list[dict]:
        """Parse sqlmap output directory log files using the full _parse_output parser."""
        findings = []
        if not os.path.isdir(output_dir):
            return findings

        for root, _dirs, files in os.walk(output_dir):
            for fname in files:
                if fname == "log":
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r") as f:
                            content = f.read()
                        findings.extend(cls._parse_output(url, content, log_file=True))
                    except Exception:
                        pass
        return findings

    @staticmethod
    def _dedup_findings(findings: list[dict]) -> list[dict]:
        """Deduplicate findings from stdout + log file by (url, param, technique, type)."""
        seen: set[tuple] = set()
        out: list[dict] = []
        for f in findings:
            key = (
                f.get("url", ""),
                f.get("param", ""),
                f.get("technique", ""),
                f.get("type", ""),
                f.get("payload", ""),
            )
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out


_DBMS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"mysql|mariadb",                   re.I), "MySQL"),
    (re.compile(r"postgresql|postgres",             re.I), "PostgreSQL"),
    (re.compile(r"microsoft sql server|mssql|sqlserver", re.I), "Microsoft SQL Server"),
    (re.compile(r"oracle",                          re.I), "Oracle"),
    (re.compile(r"sqlite",                          re.I), "SQLite"),
]


def extract_dbms_hint(findings: list[dict]) -> str | None:
    """Scan findings for sqli_error/dbms_fingerprint and return DBMS name for --dbms flag."""
    for f in findings:
        if f.get("type") in ("sqli_error", "dbms_fingerprint"):
            text = f.get("finding", "") + " " + f.get("tool_detail", "")
            for pattern, dbms in _DBMS_PATTERNS:
                if pattern.search(text):
                    return dbms
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  NUCLEI
# ═════════════════════════════════════════════════════════════════════════════

class NucleiRunner:
    """Wrapper around the real nuclei binary."""

    PER_FOLDER_TIMEOUT = 900  # 15 min per subfolder

    # Hardcoded local templates root — each subfolder is run as a separate nuclei process
    LOCAL_TEMPLATES_ROOT = "/Users/akshay.jain/Desktop/templates/"

    @classmethod
    def available(cls) -> bool:
        return shutil.which("nuclei") is not None

    @classmethod
    def _get_template_dirs(cls) -> list[str]:
        """Return list of immediate subdirectories under LOCAL_TEMPLATES_ROOT."""
        root = cls.LOCAL_TEMPLATES_ROOT
        if not os.path.isdir(root):
            return []
        return sorted(
            os.path.join(root, d)
            for d in os.listdir(root)
            if os.path.isdir(os.path.join(root, d))
        )

    @classmethod
    def run(
        cls,
        target: str,
        severity_filter: str = "low,medium,high,critical",
        template_tags: str | None = None,
        stop_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
        urls: list[str] | None = None,
    ) -> list[dict]:
        """
        Run nuclei against target using all local template subfolders.

        Each subfolder under LOCAL_TEMPLATES_ROOT is run as a separate nuclei
        process in parallel to avoid choking on 3.4M+ templates at once.

        When `urls` is provided, nuclei uses -list <tempfile> instead of -u <target>
        so every URL discovered by the AJAX spider and forced browse gets scanned.
        """
        if not cls.available():
            log.info("[nuclei] Binary not found, skipping")
            return []

        template_dirs = cls._get_template_dirs()
        if not template_dirs:
            log.warning("[nuclei] No template subdirectories found in %s", cls.LOCAL_TEMPLATES_ROOT)
            return []

        # Build URL list file when sitemap pages are available — nuclei -list
        # scans every discovered URL, not just the base target.
        _url_list_file: str | None = None
        all_urls = list(dict.fromkeys([target] + [u for u in (urls or []) if u.startswith("http")]))
        if len(all_urls) > 1:
            try:
                fd, _url_list_file = tempfile.mkstemp(prefix="dast_nuclei_urls_", suffix=".txt")
                with os.fdopen(fd, "w") as _f:
                    _f.write("\n".join(all_urls))
                log.info("[nuclei] URL list: %d URLs (base + %d discovered)", len(all_urls), len(all_urls) - 1)
            except Exception as _e:
                log.warning("[nuclei] Could not write URL list file: %s — falling back to -u", _e)
                _url_list_file = None

        if on_progress:
            on_progress(f"nuclei: scanning with {len(template_dirs)} template folders")

        all_findings: list[dict] = []
        lock = threading.Lock()
        _done_count = [0]  # mutable counter for completed folders

        def _run_folder(tpl_dir: str, idx: int):
            folder_name = os.path.basename(tpl_dir)
            if stop_event and stop_event.is_set():
                return

            if on_progress:
                on_progress(f"nuclei: scanning [{idx+1}/{len(template_dirs)}] {folder_name}")

            output_file = tempfile.mktemp(prefix=f"dast_nuclei_{folder_name}_", suffix=".jsonl")
            findings: list[dict] = []

            try:
                if _url_list_file:
                    cmd = [
                        "nuclei",
                        "-list", _url_list_file,
                        "-t", tpl_dir,
                        "-jsonl",
                        "-o", output_file,
                        "-severity", severity_filter,
                        "-silent",
                        "-nc",
                    ]
                else:
                    cmd = [
                        "nuclei",
                        "-u", target,
                        "-t", tpl_dir,
                        "-jsonl",
                        "-o", output_file,
                        "-severity", severity_filter,
                        "-silent",
                        "-nc",
                    ]

                if template_tags:
                    cmd.extend(["-tags", template_tags])

                log.info("[nuclei] Running folder %s: %s", folder_name, " ".join(cmd))

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=cls.PER_FOLDER_TIMEOUT,
                )

                # Parse JSONL output file
                if os.path.isfile(output_file):
                    with open(output_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                findings.append(cls._entry_to_finding(entry))
                            except json.JSONDecodeError:
                                continue

                # Also parse stdout
                for line in (result.stdout or "").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append(cls._entry_to_finding(entry))
                    except (json.JSONDecodeError, ValueError):
                        continue

                log.info("[nuclei] Folder %s done — %d findings", folder_name, len(findings))

            except subprocess.TimeoutExpired:
                log.warning("[nuclei] Folder %s timed out after %ds", folder_name, cls.PER_FOLDER_TIMEOUT)
                findings.append({
                    "agent": "nuclei",
                    "severity": "Info",
                    "type": "nuclei_timeout",
                    "finding": f"Nuclei timed out on {folder_name} after {cls.PER_FOLDER_TIMEOUT}s",
                    "url": target,
                })
            except Exception as e:
                log.error("[nuclei] Error on folder %s: %s", folder_name, e)
            finally:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

            with lock:
                all_findings.extend(findings)
                _done_count[0] += 1
                if on_progress:
                    on_progress(f"nuclei: folder_done {_done_count[0]}/{len(template_dirs)} {folder_name} ({len(findings)} findings)")

        # Run all template folders in parallel threads
        threads: list[threading.Thread] = []
        for idx, tpl_dir in enumerate(template_dirs):
            t = threading.Thread(
                target=_run_folder, args=(tpl_dir, idx),
                daemon=True, name=f"nuclei-{os.path.basename(tpl_dir)}",
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if _url_list_file:
            try:
                os.unlink(_url_list_file)
            except Exception:
                pass

        if on_progress:
            on_progress(f"nuclei: all folders done — {len(all_findings)} total findings")

        # Deduplicate by template-id + matched-at
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("type", ""), f.get("finding", ""), f.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        safe_publish(EXTERNAL_TOOL_DONE, {"tool_name": "nuclei", "finding_count": len(deduped), "url": target})
        return deduped

    @classmethod
    def _entry_to_finding(cls, entry: dict) -> dict:
        """Convert a nuclei JSONL entry to our finding format."""
        info = entry.get("info") or {}
        template_id = entry.get("template-id", entry.get("templateID", "unknown"))
        matched_at = entry.get("matched-at", entry.get("matched", ""))
        severity = info.get("severity", "info")
        name = info.get("name", template_id)
        description = info.get("description", "")
        matcher_name = entry.get("matcher-name", entry.get("matcher_name", ""))

        # Build CWE/CVE from tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        cve = ""
        cwe = ""
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                cve = tag.upper()
            elif tag.upper().startswith("CWE-"):
                cwe = tag.upper()

        # Extract reference URLs
        refs = info.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]

        finding_text = name
        if description:
            finding_text += f" — {description[:200]}"
        if matcher_name:
            finding_text += f" (matcher: {matcher_name})"

        return {
            "agent": "nuclei",
            "severity": _severity_map(severity),
            "type": f"nuclei_{template_id}",
            "finding": finding_text,
            "url": matched_at,
            "template_id": template_id,
            "cve": cve,
            "cwe": cwe,
            "references": refs[:5],
            "tags": tags,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  NMAP
# ═════════════════════════════════════════════════════════════════════════════

class NmapRunner:
    """Wrapper around the real nmap binary."""

    TIMEOUT = 120  # 2 minutes

    @classmethod
    def available(cls) -> bool:
        return shutil.which("nmap") is not None

    @classmethod
    def run(
        cls,
        target: str,
        top_ports: int = 1000,
        scripts: bool = True,
        stop_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[dict]:
        """
        Run nmap port/service scan against target host.

        Args:
            target: URL or hostname.
            top_ports: Number of top ports to scan.
            scripts: Whether to run default NSE scripts (-sC).
            stop_event: Threading event to check for cancellation.
            on_progress: Callback for status updates.

        Returns:
            List of finding dicts.
        """
        if not cls.available():
            log.info("[nmap] Binary not found, skipping")
            return []

        if on_progress:
            on_progress("nmap: starting port/service scan")

        # Extract hostname from URL
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port

        findings = []
        output_file = tempfile.mktemp(prefix="dast_nmap_", suffix=".xml")

        try:
            cmd = [
                "nmap",
                "-sV",                   # service/version detection
                "--top-ports", str(top_ports),
                "-oX", output_file,       # XML output
                "--no-stylesheet",
                host,
            ]

            if scripts:
                cmd.insert(2, "-sC")  # default scripts

            log.info("[nmap] Running: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=cls.TIMEOUT,
            )

            if on_progress:
                on_progress("nmap: parsing results")

            # Parse XML output
            if os.path.isfile(output_file):
                findings.extend(cls._parse_xml(target, output_file))

        except subprocess.TimeoutExpired:
            log.warning("[nmap] Timed out after %ds", cls.TIMEOUT)
            findings.append({
                "agent": "nmap",
                "severity": "Info",
                "type": "nmap_timeout",
                "finding": f"Nmap scan timed out after {cls.TIMEOUT}s",
                "url": target,
            })
        except Exception as e:
            log.error("[nmap] Error: %s", e)
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass

        return findings

    @classmethod
    def _parse_xml(cls, target: str, xml_path: str) -> list[dict]:
        """Parse nmap XML output into findings."""
        findings = []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host_el in root.findall(".//host"):
                addr_el = host_el.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""

                # Open ports
                for port_el in host_el.findall(".//port"):
                    port_id = port_el.get("portid", "")
                    protocol = port_el.get("protocol", "tcp")

                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""

                    service_el = port_el.find("service")
                    service_name = service_el.get("name", "") if service_el is not None else ""
                    service_product = service_el.get("product", "") if service_el is not None else ""
                    service_version = service_el.get("version", "") if service_el is not None else ""

                    if state != "open":
                        continue

                    svc_str = service_name
                    if service_product:
                        svc_str += f" ({service_product}"
                        if service_version:
                            svc_str += f" {service_version}"
                        svc_str += ")"

                    findings.append({
                        "agent": "nmap",
                        "severity": "Info",
                        "type": "open_port",
                        "finding": f"Port {port_id}/{protocol} open — {svc_str}",
                        "url": target,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "version": f"{service_product} {service_version}".strip(),
                    })

                    # Check for NSE script output (vulns, default scripts)
                    for script_el in port_el.findall(".//script"):
                        script_id = script_el.get("id", "")
                        script_output = script_el.get("output", "")

                        # Flag known vulnerability scripts
                        sev = "Info"
                        if "vuln" in script_id.lower():
                            sev = "High"
                        elif "ssl" in script_id.lower() or "tls" in script_id.lower():
                            sev = "Medium"

                        if script_output.strip():
                            findings.append({
                                "agent": "nmap",
                                "severity": sev,
                                "type": f"nmap_script_{script_id}",
                                "finding": f"NSE {script_id} on port {port_id}: {script_output[:300]}",
                                "url": target,
                                "port": port_id,
                                "script": script_id,
                            })

                # Host-level scripts
                for script_el in host_el.findall("hostscript/script"):
                    script_id = script_el.get("id", "")
                    script_output = script_el.get("output", "")

                    sev = "Medium" if "vuln" in script_id.lower() else "Info"
                    if script_output.strip():
                        findings.append({
                            "agent": "nmap",
                            "severity": sev,
                            "type": f"nmap_host_{script_id}",
                            "finding": f"NSE (host) {script_id}: {script_output[:300]}",
                            "url": target,
                            "script": script_id,
                        })

        except ET.ParseError as e:
            log.error("[nmap] XML parse error: %s", e)

        return findings


# ═════════════════════════════════════════════════════════════════════════════
#  GOBUSTER
# ═════════════════════════════════════════════════════════════════════════════

class GobusterRunner:
    """
    Wrapper around gobuster for wordlist-based directory/path discovery.

    Uses 'gobuster dir' mode with the curated wordlists in wordlists/.
    Default wordlist: dirbuster-medium (220k paths).
    Fast option:      olfa-micro (37k curated high-signal paths).
    """

    TIMEOUT = 600  # 10 minutes max

    # Interesting HTTP status codes to report
    _INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 503}

    # Severity by status code
    _SEVERITY = {
        200: "Medium",   # Exposed path
        201: "Medium",
        204: "Low",
        401: "Low",      # Auth-required — path exists
        403: "Low",      # Forbidden — path exists
        405: "Low",
        301: "Info",
        302: "Info",
        307: "Info",
        308: "Info",
        500: "High",     # Server error — potential misconfig/vuln
        503: "Info",
    }

    # High-value path patterns → escalate to High severity
    _HIGH_VALUE = re.compile(
        r"(?:admin|backup|config|\.git|\.env|swagger|openapi|phpinfo|phpmyadmin|"
        r"\.aws|credentials|\.ssh|id_rsa|secret|token|debug|console|shell|"
        r"\.sql|\.bak|\.old|upload|grafana|kibana|actuator|metrics|heapdump)",
        re.I,
    )

    @classmethod
    def available(cls) -> bool:
        return shutil.which("gobuster") is not None

    @classmethod
    def _wordlist_path(cls, name: str) -> str | None:
        """Resolve a wordlist category name to an absolute file path."""
        # Map of category name → filename (mirrors forcedbrowse.py WORDLIST_CATEGORIES)
        _CATEGORIES = {
            "common":           "common.txt",
            "olfa-micro":       "onelistforall-micro.txt",
            "dirbuster-medium": "dirbuster-medium.txt",
            "dirbuster-small":  "dirbuster-small.txt",
            "proviesec-full":   "proviesec-full.txt",
            "proviesec-best":   "proviesec-best.txt",
            "proviesec-admin":  "proviesec-admin.txt",
            "swagger":          "proviesec-swagger.txt",
            "git":              "proviesec-git.txt",
            "docker":           "proviesec-docker.txt",
            "grafana":          "proviesec-grafana.txt",
            "log":              "proviesec-log.txt",
            "phpinfo":          "proviesec-phpinfo.txt",
            "phpmyadmin":       "proviesec-phpmyadmin.txt",
            "stats":            "proviesec-stats.txt",
            "backup":           "backup-files.txt",
            "config":           "config-secrets.txt",
            "api":              "api-endpoints.txt",
            "admin":            "admin-panels.txt",
        }
        filename = _CATEGORIES.get(name, name)
        path = _WORDLISTS_DIR / filename
        return str(path) if path.exists() else None

    @classmethod
    def run(
        cls,
        target: str,
        wordlist_name: str = "dirbuster-medium",
        threads: int = 50,
        stop_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[dict]:
        """
        Run gobuster dir against target.

        Args:
            target: Base URL (e.g. https://example.com)
            wordlist_name: Category name from wordlists/ dir. Default: dirbuster-medium (220k).
                           Use 'olfa-micro' for fast (37k curated) coverage.
            threads: Gobuster concurrency (-t). Default 50.
            stop_event: Cancel event — terminates the gobuster subprocess.
            on_progress: Status callback.

        Returns:
            List of finding dicts with type="path_found".
        """
        if not cls.available():
            log.info("[gobuster] Binary not found, skipping")
            return []

        wordlist_path = cls._wordlist_path(wordlist_name)
        if not wordlist_path:
            log.warning("[gobuster] Wordlist '%s' not found, falling back to olfa-micro", wordlist_name)
            wordlist_path = cls._wordlist_path("olfa-micro")
        if not wordlist_path:
            log.error("[gobuster] No wordlist available, skipping")
            return []

        if on_progress:
            on_progress(f"gobuster: starting dir scan against {target} ({wordlist_name})")

        findings: list[dict] = []
        proc = None

        try:
            cmd = [
                "gobuster", "dir",
                "-u", target,
                "-w", wordlist_path,
                "-t", str(threads),
                "--no-error",          # suppress DNS/connection errors from output
                "--no-color",          # clean text output
                "-q",                  # quiet: only found paths
                "--timeout", "10s",
            ]

            log.info("[gobuster] Running: %s", " ".join(cmd))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            found_count = 0
            for line in proc.stdout:
                if stop_event and stop_event.is_set():
                    proc.terminate()
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse gobuster dir output:
                # /path                 (Status: 302) [Size: 0] [--> /redirect/]
                m = re.match(
                    r"^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[-->\s*(.+?)\])?",
                    line,
                )
                if not m:
                    continue

                path, status_str, size_str, redirect = (
                    m.group(1), m.group(2), m.group(3), m.group(4) or "",
                )
                status = int(status_str)

                if status not in cls._INTERESTING:
                    continue

                found_count += 1
                full_url = target.rstrip("/") + path
                sev = cls._SEVERITY.get(status, "Info")

                # Escalate high-value paths
                if sev in ("Low", "Info") and cls._HIGH_VALUE.search(path):
                    sev = "High"
                elif sev == "Medium" and cls._HIGH_VALUE.search(path):
                    sev = "High"

                desc = f"Path discovered: {path} (HTTP {status}, {size_str}B)"
                if redirect:
                    desc += f" → {redirect}"

                findings.append({
                    "agent":    "gobuster",
                    "severity": sev,
                    "type":     "path_found",
                    "finding":  desc,
                    "url":      full_url,
                    "path":     path,
                    "status":   status,
                    "size":     int(size_str),
                    "redirect": redirect,
                })

                if on_progress and found_count % 10 == 0:
                    on_progress(f"gobuster: {found_count} paths found so far")

            proc.wait()
            if on_progress:
                on_progress(f"gobuster: complete — {len(findings)} paths discovered")

        except Exception as e:
            log.error("[gobuster] Error: %s", e)
            if on_progress:
                on_progress(f"gobuster: error — {e}")
        finally:
            if proc and proc.poll() is None:
                proc.terminate()

        safe_publish(EXTERNAL_TOOL_DONE, {"tool_name": "gobuster", "finding_count": len(findings), "url": target})
        return findings


# ═════════════════════════════════════════════════════════════════════════════
#  Unified runner — run all available tools in parallel
# ═════════════════════════════════════════════════════════════════════════════

def run_all_external_tools(
    target: str,
    sqli_urls: list[str] | None = None,
    surfaces=None,
    dbms: str | None = None,
    tamper: str | None = None,
    stop_event: threading.Event | None = None,
    on_progress: Callable[[str], None] | None = None,
    urls: list[str] | None = None,
) -> dict[str, list[dict]]:
    """
    Run all available external tools in parallel.

    Args:
        target: Base URL.
        sqli_urls: Fallback — bare URLs for sqlmap when surfaces not available.
        surfaces: InputSurface list from crawler; when provided, sqlmap uses
                  run_surfaces() for surface-aware BEUST targeting.
        stop_event: Cancellation event.
        on_progress: Status callback.

    Returns:
        Dict mapping tool name to list of findings:
        {"sqlmap": [...], "nuclei": [...], "nmap": [...]}
    """
    results: dict[str, list[dict]] = {"sqlmap": [], "nuclei": [], "nmap": [], "gobuster": []}
    threads: list[threading.Thread] = []

    def _run_sqlmap():
        if surfaces:
            results["sqlmap"] = SqlmapRunner.run_surfaces(
                surfaces, dbms=dbms, tamper=tamper,
                stop_event=stop_event, on_progress=on_progress,
            )
        else:
            results["sqlmap"] = SqlmapRunner.run(
                target, urls_with_params=sqli_urls, dbms=dbms, tamper=tamper,
                stop_event=stop_event, on_progress=on_progress,
            )

    def _run_nuclei():
        results["nuclei"] = NucleiRunner.run(
            target, stop_event=stop_event, on_progress=on_progress, urls=urls,
        )

    def _run_nmap():
        results["nmap"] = NmapRunner.run(
            target, stop_event=stop_event, on_progress=on_progress,
        )

    def _run_gobuster():
        results["gobuster"] = GobusterRunner.run(
            target, wordlist_name="dirbuster-medium",
            stop_event=stop_event, on_progress=on_progress,
        )

    # Launch available tools in parallel
    for name, runner_cls, fn in [
        ("sqlmap",    SqlmapRunner,    _run_sqlmap),
        ("nuclei",    NucleiRunner,    _run_nuclei),
        ("nmap",      NmapRunner,      _run_nmap),
        ("gobuster",  GobusterRunner,  _run_gobuster),
    ]:
        if runner_cls.available():
            log.info("[external] Launching %s", name)
            t = threading.Thread(target=fn, daemon=True, name=f"ext-{name}")
            t.start()
            threads.append(t)
        else:
            log.info("[external] %s not installed, skipping", name)

    # Wait for all to finish
    for t in threads:
        t.join()

    return results


def get_available_tools() -> dict[str, bool]:
    """Return which external tools are installed."""
    return {
        "sqlmap":   SqlmapRunner.available(),
        "nuclei":   NucleiRunner.available(),
        "nmap":     NmapRunner.available(),
        "gobuster": GobusterRunner.available(),
    }
