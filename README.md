# DAST Standalones

An extensible Dynamic Application Security Testing platform for authorized security testing. It combines crawling, active checks, passive analysis, API discovery, authentication-aware scanning, evidence capture, and an assurance layer for coverage and replay.

> Use only on systems you own or have explicit permission to test.

## What It Includes

- Web UI and API for launching and reviewing scans
- Crawl, AJAX spidering, forced browsing, OpenAPI, GraphQL, SOAP, gRPC, and shadow API discovery
- Active checks for injection, access control, business logic, race conditions, WebSocket, cache poisoning, TLS, crypto, client-side, and misconfiguration issues
- Industry pattern packs for CVE-style detections, framework fingerprints, payload safety, and proof validation
- OAST support for blind callback-style verification
- Finding correlation, deduplication, severity ranking, CVSS/OWASP mapping, and reporting helpers
- Resumable scan state, evidence replay, browser security checks, OAuth/OIDC checks, API exposure diffing, and false-positive review support

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:REVELIO_SECRET = "replace-with-a-long-random-secret"
python main.py --port 5002
```

Open:

```text
http://127.0.0.1:5002
```

## CLI Example

```powershell
python cli.py scan --url http://127.0.0.1:5002 --profile balanced
```

## Configuration

Start from `config-template.yml`, then tune scan depth, authentication, OAST, safety limits, and pattern packs for your environment. Keep real credentials and target-specific secrets out of source control.

## Tests

```powershell
pytest
```

## Repository Hygiene

Runtime databases, reports, scan state, logs, local agent memory, and fuzzing leftovers are ignored by default so public releases do not publish target data or local artifacts.
