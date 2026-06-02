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
$env:DAST_ADMIN_USER = "admin"
$env:DAST_ADMIN_PASSWORD = "replace-with-a-local-dev-password"
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

## Internal EC2 Deployment

For an internal EC2 deployment, keep the dashboard private and set real secrets before startup:

```bash
cp .env.example .env
python -c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass('Dashboard password: ')))"
docker compose up -d --build
```

Minimum EC2 controls:

- Security group allows the dashboard only from VPN, bastion, or internal CIDR.
- Use ALB/Nginx with TLS for browser access; set `DAST_COOKIE_SECURE=1` when using HTTPS.
- Keep `DAST_ALLOW_DEFAULT_LOGIN=0`; use `DAST_ADMIN_PASSWORD_HASH`.
- Use RDS/PostgreSQL or hardened Postgres with backups; never use the old default DB password.
- Require IMDSv2 on the EC2 instance and block scanner egress to `169.254.169.254` unless you are intentionally testing metadata exposure in a controlled lab.
- Store `.env` outside git, rotate credentials, and restrict shell access to the EC2 host.

## Tests

```powershell
pytest
```

## Repository Hygiene

Runtime databases, reports, scan state, logs, local agent memory, and fuzzing leftovers are ignored by default so public releases do not publish target data or local artifacts.
