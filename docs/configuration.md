# Configuration Reference

## YAML Configuration File

Copy `config-template.yml` and customize for your target:

```bash
cp config-template.yml my-scan.yml
# Edit my-scan.yml
```

### Scan Settings

```yaml
scan:
  policy: standard    # quick|standard|full|api|stealth
  timeout: 10         # HTTP request timeout (1-120 seconds)
  max_pages: 100      # Maximum pages to crawl (0=unlimited)
  max_depth: 5        # Maximum crawl depth
  workers: 10         # Concurrent fuzzing workers (1-50)
  # Default false. Keep active fuzzing away from logout, payment, refund,
  # transfer, password reset, role, and account-changing endpoints.
  allow_dangerous_endpoints: false
```

### Per-Check Enable/Disable

```yaml
checks:
  # Skip specific checks by vuln_type key
  disable:
    - shellshock
    - jetty_leak

  # OR run only specific checks (overrides disable)
  enable_only:
    - sqli_error
    - xss_reflected
    - ssrf
```

### Scope Control

```yaml
scope:
  include:
    - "https://example.com/api/*"
  exclude:
    - "/logout"
    - "/admin/*"
    - "*.pdf"
  exclude_extensions:
    - ".jpg"
    - ".png"
    - ".css"
```

### Authentication

**Bearer Token:**
```yaml
auth:
  type: bearer
  token: "eyJhbGciOiJIUzI1NiIs..."
```

**Cookie Auth:**
```yaml
auth:
  type: cookie
  cookie_name: "session_id"
  cookie_value: "abc123def456"
```

**Basic Auth:**
```yaml
auth:
  type: basic
  username: "admin"
  password: "secretpass"
```

**Custom Header:**
```yaml
auth:
  type: header
  header_name: "X-API-Key"
  header_value: "your-api-key-here"
```

### Custom Wordlists

```yaml
wordlists:
  forced_browse: "/path/to/dirs.txt"
  passwords: "/path/to/passwords.txt"
  usernames: "/path/to/users.txt"
```

### Real-World DAST Extensions

External pattern packs let you add payloads, detectors, parameter rules, upload probes, token regexes, hidden API paths, and LLM/API discovery paths without editing Python code.

```bash
python main.py --headless --target https://example.com \
  --pattern-pack examples/pattern-pack.json
```

For blind SSRF/XXE/CMDi/Log4Shell testing against non-local targets, expose the OAST listener through a reachable reverse proxy or tunnel and pass its public base URL:

```bash
python main.py --headless --target https://example.com \
  --oast-public-base-url https://oast.example.net/callbacks
```

Active fuzzing blocks sensitive business endpoints by default. Only enable this
in an explicit test environment with seeded data and approval:

```bash
python main.py --headless --target https://staging.example.com \
  --allow-dangerous-endpoints
```

### Reporting

```yaml
reporting:
  format:
    - html
    - sarif
    - pdf
  output_dir: ./reports
  fail_on: high    # CI exit code threshold: low|medium|high|critical
```

JSON reports include a `post_processing` section with raw finding count,
deduplicated count, duplicates removed, confidence summary, and severity
summary. Each finding is annotated with `confidence_score`,
`confidence_level`, and Burp-style `audit_confidence`.

## Scan Policies

| Policy | Use Case | Pages | Fuzz | Active Checks | Speed |
|--------|----------|-------|------|---------------|-------|
| `quick` | Smoke test, CI pipeline | 20 | No | No | Fast |
| `standard` | Regular scanning | 100 | Yes | Yes | Medium |
| `full` | Comprehensive assessment | 500 | Yes | Yes + all modules | Slow |
| `api` | API-only (no crawling) | 0 | Yes | Yes + GraphQL | Medium |
| `stealth` | Low-noise recon | 30 | No | Yes (minimal) | Slow |

## CI Exit Codes

- `0` — Pass: no findings at or above threshold
- `1` — Fail: findings at or above threshold
- `2` — Warn: findings below threshold but above medium
