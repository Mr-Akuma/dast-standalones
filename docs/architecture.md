# DAST Scanner Architecture

## Overview

A standalone Dynamic Application Security Testing (DAST) scanner built in Python. It crawls web applications, analyzes responses passively, actively fuzzes for vulnerabilities, and runs specialized security checks. Results are output as SARIF, HTML, or PDF reports.

## Scan Phases

The scanner executes in 5 phases:

1. **Crawl** — Spider the target site, building a sitemap of pages and input surfaces (forms, API endpoints, query params). Supports AJAX crawling and forced browsing.

2. **Passive Analysis** — Analyze every HTTP response for security issues without sending attack payloads: missing headers, cookie misconfigurations, information leakage, PII exposure, dangerous JS functions.

3. **Active Fuzzing & Specialized Checks** — Inject payloads (SQLi, XSS, SSRF, SSTI, etc.) into discovered input surfaces. Run 60+ specialized checks: JWT attacks, CORS abuse, HTTP smuggling, cache deception, Shellshock, Struts RCE, etc. Runs parallelized via ThreadPoolExecutor.

4. **Chain Analysis** — Correlate individual findings into attack chains (e.g., XSS + CSRF = account takeover). VulnChainer identifies multi-step exploitation paths.

5. **Deduplication** — Remove duplicate findings using (normalized_path, param, vuln_type) fingerprinting. Keeps highest-confidence instance.

## Dual Orchestration

Two execution paths exist:

### `modules/scan_engine.py` — ScanEngine class
- Policy-driven via `ScanPolicy` dataclass
- 5 pre-built policies: `quick`, `standard`, `full`, `api`, `stealth`
- Phase plan built from policy flags (`enable_fuzz`, `enable_active_scan`, etc.)
- Used by CLI mode (`cli.py`, `main.py`)

### `app.py` — `_engine_scan_worker()`
- Profile-driven via `_phases_enabled` dict
- Manual module orchestration with progress tracking
- Used by Flask web UI
- Includes additional features: OAST server, auth session management, external tool integration

Both paths produce the same `ScanFinding`-compatible dicts and apply deduplication before final output.

## Scan Policies

| Policy | Pages | Depth | Fuzz | Active | Forced Browse | GraphQL | WebSocket | Workers |
|--------|-------|-------|------|--------|---------------|---------|-----------|---------|
| quick | 20 | 3 | No | No | No | No | No | 5 |
| standard | 100 | 5 | Yes | Yes | No | No | No | 10 |
| full | 500 | 8 | Yes | Yes | Yes | Yes | Yes | 15 |
| api | 0 | 0 | Yes | Yes | No | Yes | Yes | 10 |
| stealth | 30 | 3 | No | Yes | No | No | No | 3 |

## Module Inventory

### Core Engine
- `scan_engine.py` — ScanEngine class, ScanPolicy, ScanPhase enum, phase planning
- `scanner.py` — VulnerabilityScanner with 60+ _check_* methods
- `passive.py` — PassiveScanner with 40+ response analysis checks
- `fuzzer.py` — Active fuzzer with SQLi, XSS, SSRF, SSTI, XXE, etc. payloads
- `crawler.py` — Web crawler with sitemap building
- `scope.py` — URL scope management (include/exclude patterns)

### Specialized Scanners
- `ajax_spider.py` — JavaScript-aware crawling
- `graphql.py` — GraphQL introspection and injection testing
- `websocket.py` — WebSocket security testing
- `grpc_scanner.py` — gRPC service scanning
- `soap_scanner.py` — SOAP/XML web service testing
- `wasm_scanner.py` — WebAssembly binary analysis
- `tls_analyzer.py` — TLS/SSL configuration analysis
- `crypto_scanner.py` — Cryptographic weakness detection
- `http2_smuggler.py` — HTTP/2 request smuggling
- `dom_xss_active.py` — DOM-based XSS with headless browser

### Attack Modules
- `forcedbrowse.py` — Directory/file brute forcing
- `intruder.py` — Burp Intruder-style batch attacks
- `race_condition.py` — Race condition exploitation
- `biz_logic.py` — Business logic flaw testing
- `llm_fuzzer.py` — LLM-powered intelligent fuzzing
- `ua_diff.py` — User-Agent behavioral diffing
- `attack_orchestrator.py` — Multi-step attack chain execution

### Support Modules
- `dedup.py` — Finding deduplication with persistence
- `reporting.py` — SARIF, HTML, PDF report generation
- `evidence.py` — Evidence store for findings
- `oast.py` — Out-of-band Application Security Testing server
- `auth.py` — Authentication session management
- `session_replay.py` — Login macro replay
- `waf_detector.py` — WAF detection and fingerprinting
- `fingerprint.py` — Technology stack fingerprinting
- `config_schema.py` — YAML configuration loader/validator

### Discovery & Analysis
- `api_discovery.py` — API endpoint discovery
- `openapi.py` — OpenAPI/Swagger spec parsing
- `param_digger.py` — Hidden parameter discovery
- `param_analyzer.py` — Parameter behavior analysis
- `surface_model.py` — Input surface modeling
- `source_discovery.py` — Source code/backup file discovery
- `id_harvester.py` — ID/token harvesting from responses

### Nuclei Integration
- `nuclei_tokens.py` — Token/secret pattern matching
- `nuclei_exposures.py` — Sensitive exposure detection
- `nuclei_misconfig.py` — Misconfiguration detection
- `nuclei_dast.py` — DAST-specific nuclei checks
- `js_library_scanner.py` — JavaScript library vulnerability scanning

### Quality & Confidence
- `confidence.py` — Finding confidence scoring
- `anomaly_scorer.py` — Response anomaly detection
- `proof_validator.py` — Finding proof validation
- `finding_correlator.py` — Cross-finding correlation
- `vuln_chainer.py` — Vulnerability chain analysis
- `cvss_owasp.py` — CVSS scoring and OWASP mapping

## Data Flow

```
Target URL
    |
    v
Crawler --> Sitemap (pages + surfaces)
    |
    v
PassiveScanner --> PassiveFinding[]
    |
    v
Fuzzer --> FuzzResult[] --> ScanFinding[]
    |
    v
VulnerabilityScanner._check_*() --> ScanFinding[]
    |
    v
VulnChainer.analyze_and_annotate()
    |
    v
FindingDeduplicator.deduplicate()
    |
    v
SarifReport / HtmlReport / PdfReport
```
