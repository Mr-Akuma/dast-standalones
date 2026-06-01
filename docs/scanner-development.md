# Adding New Scanner Checks

## Step-by-Step Guide

### 1. Choose a `vuln_type` key

Pick a unique snake_case key: `xpath_injection`, `shellshock`, `mass_assignment`, etc.

### 2. Add to mapping dictionaries

In `modules/scanner.py`, add entries to all 4 dicts near the top of the file:

```python
# _OWASP — maps vuln_type to OWASP Top 10 category
"xpath_injection": "A03:2025 Injection",

# _CWE — maps vuln_type to CWE identifier
"xpath_injection": "CWE-643",

# _REMEDIATION — maps vuln_type to remediation guidance
"xpath_injection": "Use parameterized XPath queries...",

# _SEV — maps vuln_type to default severity
"xpath_injection": "high",
```

### 3. Write the `_check_*` method

Add your method to `VulnerabilityScanner`. Follow this pattern:

```python
def _check_my_vuln(self, sitemap) -> list[ScanFinding]:
    """One-line description of what this checks."""
    findings = []
    for url in islice(sitemap.pages.keys(), 10):
        if self.stop_event.is_set():
            break
        try:
            time.sleep(self.rate_limit)
            resp = self._req("GET", url, headers={"X-Test": "payload"})
            if not resp:
                continue
            body = resp.text[:5000]
            if "vulnerability_marker" in body:
                findings.append(self._make_finding(
                    url=url,
                    method="GET",
                    param="X-Test",
                    param_type="header",  # query, header, body, cookie, path, json
                    vuln_type="my_vuln",
                    finding=f"Description [{url}]",
                    severity="high",
                    proof=f"Evidence: {body[:200]}",
                    payload="the payload sent",
                    status_code=resp.status_code,
                ))
        except Exception:
            continue
    return findings
```

Key patterns:
- **`islice(sitemap.pages.keys(), N)`** — iterate first N URLs without materializing full list
- **`self.stop_event.is_set()`** — check for scan cancellation
- **`time.sleep(self.rate_limit)`** — respect rate limiting
- **`self._req(method, url, ...)`** — HTTP request helper with timeout
- **`self._make_finding(...)`** — create ScanFinding with automatic OWASP/CWE mapping
- **`body[:5000]`** — truncate response body for string matching

### 4. Wire into `scan()` method

Add your check to the `_phase3_checks` list in `scan()`:

```python
_phase3_checks = [
    # ... existing checks ...
    self._check_my_vuln,
]
```

Checks in this list run in parallel via ThreadPoolExecutor.

### 5. Test

Run the scanner against a test target and verify:
- Your check produces findings on vulnerable targets
- No false positives on clean targets
- `stop_event` is respected (scan cancellation works)

## ScanFinding Fields

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Target URL |
| `method` | str | HTTP method (GET, POST, etc.) |
| `param` | str | Parameter or header name tested |
| `param_type` | str | query, header, body, cookie, path, json |
| `vuln_type` | str | Vulnerability type key |
| `finding` | str | Human-readable description |
| `severity` | str | critical, high, medium, low, info |
| `proof` | str | Evidence/proof of vulnerability |
| `payload` | str | Payload that triggered the finding |
| `status_code` | int | HTTP response status code |
| `owasp_category` | str | Auto-populated from `_OWASP` dict |
| `cwe` | str | Auto-populated from `_CWE` dict |
| `remediation` | str | Auto-populated from `_REMEDIATION` dict |

## Passive Checks vs Active Checks

**Passive checks** (in `passive.py`):
- Analyze existing HTTP responses — no new requests
- Return `PassiveFinding` dataclass
- Called on every crawled page automatically
- Method signature: `_check_name(self, url, body/headers, status_code)`

**Active checks** (in `scanner.py`):
- Send attack payloads to the target
- Return `ScanFinding` dataclass
- Called once with full sitemap after crawling
- Method signature: `_check_name(self, sitemap) -> list[ScanFinding]`
