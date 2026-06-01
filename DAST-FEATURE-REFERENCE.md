# Production DAST Scanner Feature Reference

> Comprehensive feature analysis of OWASP ZAP, Burp Suite Pro, and Nuclei.
> Classification: **[M]** = Must-have for parity, **[N]** = Nice-to-have / differentiator

---

## 1. OWASP ZAP (Zaproxy) -- Complete Feature List

### 1.1 Scanner Types

| Feature | Description | Priority |
|---------|-------------|----------|
| **Passive Scanner** | Analyzes proxied traffic without sending additional requests; checks headers, cookies, response bodies for known vulnerability indicators | **[M]** |
| **Active Scanner** | Sends crafted attack payloads to discovered endpoints; tests for injection, XSS, etc. | **[M]** |
| **AJAX Spider** | Uses embedded browser (Crawljax) to execute JavaScript and discover dynamically-generated content, SPAs, client-side routes | **[M]** |
| **Traditional Spider** | HTML parser-based crawler that follows links, extracts form actions, discovers static content tree | **[M]** |
| **Forced Browse** | Dictionary-based directory/file discovery (DirBuster/RAFT integration) | **[M]** |
| **Fuzzer** | Payload-based fuzzing of any request parameter; supports built-in wordlists, community payloads, and custom lists | **[M]** |
| **DOM XSS Scanner** | Specifically targets DOM-based XSS by analyzing client-side JavaScript execution | **[M]** |
| **API Scanner** | Imports OpenAPI/Swagger, GraphQL, or SOAP/WSDL definitions and scans API endpoints | **[M]** |
| **Baseline Scan** | Quick passive-only scan via Docker; runs spider + passive rules, no active attacks | **[M]** |
| **Full Scan** | Docker-based: spider + ajax spider + full active scan with all policies | **[M]** |

### 1.2 Spider / Crawl Modes

| Feature | Description | Priority |
|---------|-------------|----------|
| **Traditional HTML Spider** | Parses HTML for links, forms, comments, robots.txt, sitemap.xml | **[M]** |
| **AJAX Spider (Crawljax)** | Headless browser crawling; clicks elements, fills forms, discovers JS-rendered content | **[M]** |
| **Spider Scope Control** | Regex-based scope inclusion/exclusion; restrict to specific domains/paths | **[M]** |
| **Spider Depth Control** | Configurable max depth, max children, max duration | **[M]** |
| **Form Auto-Fill** | Configurable default values for form fields during spidering | **[N]** |
| **Spider Subtree Only** | Restrict crawling to a specific subtree of the site | **[N]** |

### 1.3 Active Scan Rules (Release -- Stable)

| Rule Category | Specific Checks | Priority |
|---------------|-----------------|----------|
| **SQL Injection** | Error-based, boolean-based blind, time-based blind, UNION-based; MySQL, PostgreSQL, Oracle, MSSQL, SQLite, HypersonicSQL | **[M]** |
| **Cross-Site Scripting (XSS)** | Reflected XSS, Stored/Persistent XSS, DOM-based XSS | **[M]** |
| **OS Command Injection** | Blind command injection (timing), error-based command injection; Unix and Windows payloads | **[M]** |
| **Path Traversal** | Directory traversal / file inclusion via ../ sequences and encoding variants | **[M]** |
| **Remote File Inclusion** | Attempts to include remote files via URL parameters | **[M]** |
| **Local File Inclusion** | Attempts to include local server files (/etc/passwd, etc.) | **[M]** |
| **Server-Side Include (SSI)** | SSI injection detection | **[M]** |
| **LDAP Injection** | LDAP query manipulation testing | **[M]** |
| **XPath Injection** | XPath query injection detection | **[N]** |
| **XML External Entity (XXE)** | XXE injection via XML parsing | **[M]** |
| **CRLF Injection** | HTTP response splitting via CRLF characters | **[M]** |
| **Parameter Tampering** | Modifying parameter values to find unexpected behavior | **[M]** |
| **Buffer Overflow** | Sending oversized inputs to detect buffer handling issues | **[N]** |
| **Format String** | Format string vulnerability detection | **[N]** |
| **Integer Overflow** | Integer boundary testing | **[N]** |
| **NoSQL Injection** | Boolean-based, error-based, and time-based NoSQL injection (MongoDB, etc.) | **[M]** |
| **CSRF Testing** | Anti-CSRF token analysis and bypass testing | **[M]** |
| **CORS Misconfiguration** | Cross-Origin Resource Sharing misconfiguration detection | **[M]** |
| **Source Code Disclosure** | SVN, Git, CVS metadata exposure; backup file detection | **[M]** |
| **Remote Code Execution** | CVE-specific checks (Log4Shell CVE-2021-44228, Spring4Shell, etc.) | **[M]** |
| **Server-Side Template Injection (SSTI)** | Template injection in various engines | **[M]** |
| **Heartbleed** | OpenSSL Heartbleed (CVE-2014-0160) | **[N]** |
| **Padding Oracle** | Padding oracle attack detection | **[N]** |
| **HTTP Parameter Pollution** | HPP detection across various technologies | **[N]** |
| **ELMAH Information Leak** | .NET ELMAH error log exposure | **[N]** |
| **.htaccess Information Leak** | Apache configuration exposure | **[N]** |
| **Trace.axd Information Leak** | .NET trace information exposure | **[N]** |
| **Hidden File Discovery** | Discovery of backup files, config files, IDE files | **[M]** |
| **Cloud Metadata Attack** | AWS/GCP/Azure metadata endpoint access (SSRF to 169.254.169.254) | **[M]** |
| **SSRF (Server-Side Request Forgery)** | Internal network access via SSRF | **[M]** |

### 1.4 Active Scan Rules (Beta)

| Rule | Priority |
|------|----------|
| **Expression Language Injection** | **[N]** |
| **Spring Actuator Detection** | **[M]** |
| **Cookie Slack Detector** | **[N]** |
| **Insecure HTTP Method** | **[M]** |
| **HTTP Only Site** | **[N]** |
| **Relative Path Confusion** | **[N]** |
| **Out-of-Band XSS** | **[M]** |
| **XSLT Injection** | **[N]** |
| **GraphQL Injection** | **[M]** |
| **Web Cache Deception** | **[M]** |
| **Text4Shell (CVE-2022-42889)** | **[N]** |
| **Exponential Entity Expansion (Billion Laughs)** | **[N]** |
| **SOAP Action Spoofing** | **[N]** |
| **Server-Side Request Forgery (SSRF)** | **[M]** |

### 1.5 Active Scan Rules (Alpha)

| Rule | Priority |
|------|----------|
| **MongoDB Injection** | **[N]** |
| **LDAP Injection** | **[N]** |
| **.env File Detection** | **[M]** |
| **Cookie Same-Site Attribute** | **[N]** |
| **Nginx Alias Traversal** | **[N]** |
| **Fetch Metadata Check** | **[N]** |
| **Forbidden Bypass** | **[N]** |
| **Web Cache Poisoning** | **[M]** |
| **HTTP Request Smuggling** | **[M]** |

### 1.6 Passive Scan Rules

| Rule Category | Specific Checks | Priority |
|---------------|-----------------|----------|
| **Security Headers** | Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, Referrer-Policy, X-XSS-Protection (deprecated check) | **[M]** |
| **Cookie Security** | Missing HttpOnly, Secure, SameSite flags; cookie without path; loosely scoped cookies | **[M]** |
| **Information Disclosure** | Debug error messages, sensitive info in URL, info in referrer header, server banner leaks, X-Powered-By, X-Debug-Token | **[M]** |
| **Technology Detection** | Wappalyzer-based technology fingerprinting (frameworks, languages, servers, CMS) | **[M]** |
| **Anti-CSRF Token Detection** | Absence of anti-CSRF tokens in forms | **[M]** |
| **Mixed Content** | HTTP resources loaded on HTTPS pages | **[M]** |
| **Application Error Detection** | HTTP 500 errors, stack traces, known error strings | **[M]** |
| **Private IP Disclosure** | Internal/private IP addresses in responses | **[M]** |
| **Content-Type Mismatch** | Response Content-Type vs actual content | **[N]** |
| **Charset Mismatch** | Character set inconsistency | **[N]** |
| **Viewstate Analysis** | ASP.NET ViewState analysis, MAC validation | **[N]** |
| **Cache Control** | Insecure caching directives on sensitive pages | **[M]** |
| **Timestamp Disclosure** | Unix timestamps in responses | **[N]** |
| **Hash Disclosure** | Password hashes in responses | **[M]** |
| **Session ID in URL** | Session tokens passed via URL parameters | **[M]** |
| **Insecure Form Action** | Forms posting to HTTP from HTTPS | **[M]** |
| **Insecure Form Password Autocomplete** | Password fields with autocomplete enabled | **[N]** |
| **Modern App Detection** | Single Page Application detection | **[N]** |
| **JS Source Map Disclosure** | JavaScript source map file exposure | **[M]** |
| **Sub-Resource Integrity** | Missing SRI on external resources | **[N]** |
| **Dangerous JS Functions** | eval(), innerHTML, document.write() usage | **[M]** |
| **Big Redirect** | Unusually large redirect responses (may indicate open redirect) | **[N]** |
| **User-Controlled Open Redirect** | Redirect URL controlled by user input | **[M]** |
| **Reverse Tabnabbing** | Links with target=_blank missing rel=noopener | **[N]** |
| **PII Disclosure** | Credit card numbers, SSN patterns in responses | **[M]** |
| **Retrieved from Cache** | Sensitive data served from cache | **[N]** |

### 1.7 Authentication Methods

| Method | Description | Priority |
|--------|-------------|----------|
| **Form-Based Authentication** | Standard HTML form login with POST parameters | **[M]** |
| **JSON-Based Authentication** | JSON payload authentication for APIs | **[M]** |
| **HTTP/NTLM Authentication** | HTTP Basic, Digest, and NTLM auth via headers | **[M]** |
| **Script-Based Authentication** | Custom scripts for complex auth flows (OAuth, token exchange) | **[M]** |
| **Browser-Based Authentication** | Headless browser login for JavaScript-heavy apps, SSO, MFA | **[M]** |
| **Manual Authentication** | Proxy-based manual login with session capture | **[N]** |
| **Auto-Detection** | Automatic login page and method detection | **[N]** |
| **Session Management** | Cookie-based, HTTP header-based, and script-based session handling | **[M]** |
| **Verification Strategies** | URL-based, response-based, poll-based login verification | **[M]** |
| **Forced User Mode** | Forces all requests to use a specific user's session | **[N]** |

### 1.8 Scripting Engine

| Feature | Description | Priority |
|---------|-------------|----------|
| **Script Types: Standalone** | Manually invoked scripts with custom functionality | **[N]** |
| **Script Types: Targeted** | Scripts that run against specific URLs/subtrees | **[N]** |
| **Script Types: Proxy** | Intercept and modify proxied requests/responses | **[M]** |
| **Script Types: HTTP Sender** | Process all requests/responses (not just proxied) | **[M]** |
| **Script Types: Active Scan Rule** | Custom active scan checks as scripts | **[M]** |
| **Script Types: Passive Scan Rule** | Custom passive scan checks as scripts | **[M]** |
| **Script Types: Authentication** | Custom authentication logic | **[M]** |
| **Script Types: Session Management** | Custom session handling logic | **[N]** |
| **Script Types: Payload Generator** | Custom fuzzing payload generation | **[N]** |
| **Script Types: Input Vector** | Custom input vector definition for scanning | **[N]** |
| **Script Types: Extender** | Extend ZAP's core functionality | **[N]** |
| **Zest (Domain-Specific Language)** | Visual/recorded security test scripts in JSON format | **[N]** |
| **GraalVM JavaScript** | Modern JS engine for scripting | **[N]** |
| **JSR 223 Language Support** | Python, Ruby, Groovy, Kotlin via JSR 223 | **[N]** |

### 1.9 Add-ons / Marketplace

| Add-on Category | Examples | Priority |
|-----------------|----------|----------|
| **Active Scan Rules (Beta/Alpha)** | Additional vulnerability checks beyond stable release | **[M]** |
| **Passive Scan Rules (Beta/Alpha)** | Additional passive analysis rules | **[M]** |
| **Report Generation** | HTML, XML, JSON, PDF, SARIF, Markdown templates | **[M]** |
| **OpenAPI/Swagger Support** | Import and scan OpenAPI definitions | **[M]** |
| **GraphQL Support** | Import and scan GraphQL schemas/endpoints | **[M]** |
| **SOAP Scanner** | WSDL import and SOAP endpoint scanning | **[N]** |
| **WebSocket Passive Scanner** | Passive analysis of WebSocket messages | **[M]** |
| **Access Control Testing** | Test authorization rules between user roles | **[M]** |
| **Sequence Scanner** | Multi-step request sequence testing for business logic | **[M]** |
| **Automation Framework** | YAML-based automation for CI/CD pipelines | **[M]** |
| **Requester** | Manual request crafting and replay | **[N]** |
| **Retire.js** | Known vulnerable JavaScript library detection | **[M]** |
| **FuzzDB** | Comprehensive fuzzing payload database | **[N]** |
| **Token Generator** | CSRF token analysis and generation testing | **[N]** |
| **WAPPALYZER (Technology Detection)** | Technology stack fingerprinting | **[M]** |
| **Linux WebSwing** | Web-based ZAP UI delivery | **[N]** |
| **Tips and Tricks** | Context-sensitive help and guidance | **[N]** |
| **Custom Payloads** | Community-contributed payload databases | **[N]** |

### 1.10 Automation & CI/CD

| Feature | Description | Priority |
|---------|-------------|----------|
| **Automation Framework** | YAML-based scan configuration; define contexts, environments, jobs | **[M]** |
| **Docker Images** | Pre-built stable, weekly, and bare images | **[M]** |
| **Command-Line Interface** | Full CLI for headless execution | **[M]** |
| **Packaged Scans** | Baseline, Full, API scan scripts in Docker | **[M]** |
| **API** | REST API for programmatic control (JSON, XML, HTML responses) | **[M]** |
| **GitHub Actions Integration** | Official GitHub Action for pipeline integration | **[M]** |
| **Jenkins Plugin** | Official Jenkins ZAP plugin | **[N]** |
| **GitLab CI Templates** | CI/CD template configuration examples | **[N]** |
| **Hook Scripts** | Pre/post-scan hook scripts for pipeline customization | **[N]** |
| **Scan Policy Import/Export** | Shareable scan policy configurations | **[M]** |

---

## 2. Burp Suite Pro -- Complete Feature List

### 2.1 Scanner Engine

| Feature | Description | Priority |
|---------|-------------|----------|
| **Crawl Engine** | Chromium-embedded browser crawler; handles CSRF tokens, stateful navigation, JS rendering | **[M]** |
| **Active Audit** | Sends crafted payloads to discovered insertion points; tests for injection, XSS, etc. | **[M]** |
| **Passive Audit** | Analyzes all proxied traffic for vulnerabilities without additional requests | **[M]** |
| **JavaScript Analysis (SAST+DAST)** | Static + dynamic analysis of client-side JavaScript for DOM XSS, prototype pollution, etc. | **[M]** |
| **Live Passive Crawl** | Builds site map from passively observed traffic as user browses | **[M]** |
| **Scheduled Scans** | Time-based scan scheduling | **[N]** |
| **Scan Queue Management** | Pause, resume, reorder scan tasks | **[N]** |

### 2.2 Crawl Strategies & Configuration

| Feature | Description | Priority |
|---------|-------------|----------|
| **Fastest Crawl** | Minimal depth, max speed for quick surface discovery | **[M]** |
| **Faster Crawl** | Reduced depth with reasonable coverage | **[M]** |
| **Normal Crawl** | Balanced speed and coverage | **[M]** |
| **More Complete Crawl** | Deeper exploration, more form submissions | **[M]** |
| **Most Complete Crawl** | Maximum depth and thoroughness | **[M]** |
| **Crawl Scope** | Domain, path, and regex-based scope restriction | **[M]** |
| **Crawl Limits** | Max unique locations, max crawl time, max request count | **[M]** |
| **Login Handling** | Automatic login sequence recording and replay during crawl | **[M]** |
| **Form Fill Rules** | Custom rules for auto-filling form fields during crawl | **[M]** |
| **Handling Errors** | Configurable behavior on HTTP errors, timeouts, and connection failures | **[N]** |
| **URL Canonicalization** | Deduplication of equivalent URLs with different representations | **[M]** |
| **Resource Pool Configuration** | Thread count, request rate, connection limits per scan | **[M]** |

### 2.3 Audit / Vulnerability Check Categories

| Category | Specific Checks | Priority |
|----------|-----------------|----------|
| **SQL Injection** | Error-based, blind boolean, blind time-based, UNION-based; all major DBMS | **[M]** |
| **Cross-Site Scripting (XSS)** | Reflected, stored, DOM-based (via JS analysis engine) | **[M]** |
| **OS Command Injection** | Blind (time-based, DNS-based via Collaborator), error-based | **[M]** |
| **Server-Side Template Injection** | Detection across Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB, Jade, etc. | **[M]** |
| **Path Traversal** | Directory traversal with encoding bypass variants | **[M]** |
| **XML External Entity (XXE)** | Standard, blind (via Collaborator OOB exfiltration) | **[M]** |
| **Server-Side Request Forgery (SSRF)** | Internal network access, cloud metadata access, protocol smuggling | **[M]** |
| **Insecure Deserialization** | Java, PHP, .NET, Python, Ruby deserialization flaws | **[M]** |
| **HTTP Request Smuggling** | CL.TE, TE.CL, TE.TE smuggling variants | **[M]** |
| **Web Cache Poisoning** | Unkeyed header/parameter injection into cached responses | **[M]** |
| **CORS Misconfiguration** | Origin reflection, null origin, wildcard, credential leaks | **[M]** |
| **Open Redirect** | Unvalidated redirect via parameter manipulation | **[M]** |
| **CSRF** | Missing/weak CSRF token detection | **[M]** |
| **Clickjacking** | Missing X-Frame-Options / CSP frame-ancestors | **[M]** |
| **Header Injection / CRLF** | HTTP response splitting | **[M]** |
| **File Upload Vulnerabilities** | Unrestricted file upload, content-type bypass | **[M]** |
| **HTTP Host Header Attacks** | Password reset poisoning, routing-based SSRF, web cache poisoning via host | **[M]** |
| **WebSocket Security** | XSS, injection, and authentication issues in WebSocket messages | **[M]** |
| **Prototype Pollution** | Client-side and server-side prototype pollution | **[M]** |
| **GraphQL Vulnerabilities** | Introspection enabled, injection, authorization bypass | **[M]** |
| **JWT Issues** | Algorithm confusion, weak signing, key disclosure | **[M]** |
| **Access Control** | IDOR, privilege escalation, horizontal/vertical access control | **[M]** |
| **Authentication Issues** | Brute force, credential stuffing, username enumeration | **[M]** |
| **Information Disclosure** | Error messages, stack traces, version disclosure, backup files, debug endpoints | **[M]** |
| **Security Header Analysis** | CSP, HSTS, X-Content-Type-Options, Permissions-Policy, Referrer-Policy | **[M]** |
| **Cookie Security** | HttpOnly, Secure, SameSite analysis | **[M]** |
| **TLS/SSL Issues** | Weak ciphers, protocol version, certificate issues | **[M]** |
| **Email Header Injection** | SMTP injection via web forms | **[N]** |
| **LDAP Injection** | LDAP query injection testing | **[N]** |
| **NoSQL Injection** | MongoDB and other NoSQL injection | **[M]** |

### 2.4 Audit Configuration Options

| Setting | Description | Priority |
|---------|-------------|----------|
| **Audit Speed: Fast** | Fewer requests, fewer derivative checks | **[M]** |
| **Audit Speed: Normal** | Balanced coverage | **[M]** |
| **Audit Speed: Thorough** | Maximum derivative checks, many more requests | **[M]** |
| **Issues Reported: Certain** | Only high-confidence findings | **[M]** |
| **Issues Reported: Firm** | Medium-high confidence | **[M]** |
| **Issues Reported: Tentative** | Include lower-confidence findings | **[M]** |
| **Insertion Point Types** | URL path, URL parameters, body parameters, cookies, HTTP headers, parameter names, entire body, AMF values | **[M]** |
| **Insertion Point Refinement** | Skip server-side insertion points, skip URL path parameters, etc. | **[N]** |
| **Active Scan Optimization** | Consolidation of frequently occurring passive issues | **[N]** |
| **Per-Check Configuration** | Enable/disable individual scan checks | **[M]** |
| **Scan Check Selection** | Select by individual check or by category/group | **[M]** |

### 2.5 Collaborator / OAST (Out-of-Band Application Security Testing)

| Feature | Description | Priority |
|---------|-------------|----------|
| **Collaborator Server** | PortSwigger-hosted (or self-hosted) interaction server for OOB testing | **[M]** |
| **DNS Interaction Detection** | Detect blind SSRF, XXE, SQLi via DNS lookups to Collaborator | **[M]** |
| **HTTP Interaction Detection** | Detect blind command injection, SSRF via HTTP callbacks | **[M]** |
| **SMTP Interaction Detection** | Detect email-based vulnerabilities via SMTP interactions | **[N]** |
| **Custom Collaborator Payloads** | Generate unique per-test Collaborator URLs for correlation | **[M]** |
| **Collaborator Polling** | Automated polling for interactions with result correlation | **[M]** |
| **Self-Hosted Collaborator** | Deploy private Collaborator server for internal testing | **[N]** |
| **Collaborator Client Tab** | Dedicated UI for managing/viewing interactions | **[N]** |
| **Integration with All Scan Types** | Collaborator payloads used in active scan, intruder, repeater | **[M]** |

### 2.6 Intruder -- Attack Types

| Attack Type | Description | Priority |
|-------------|-------------|----------|
| **Sniper** | Single payload set, cycles through each position one at a time | **[M]** |
| **Battering Ram** | Single payload set applied to ALL positions simultaneously | **[M]** |
| **Pitchfork** | Multiple payload sets, one per position; iterates in parallel (row-by-row) | **[M]** |
| **Cluster Bomb** | Multiple payload sets, all combinations (cartesian product) | **[M]** |

### 2.7 Intruder -- Payload Types

| Payload Type | Description | Priority |
|-------------|-------------|----------|
| **Simple List** | Static list of payloads | **[M]** |
| **Runtime File** | Read payloads from file at runtime | **[M]** |
| **Custom Iterator** | Generates payloads from configured sub-payloads with separators | **[N]** |
| **Character Substitution** | Substitutes characters in base strings (leet-speak, etc.) | **[N]** |
| **Case Modification** | Changes case of payloads | **[N]** |
| **Recursive Grep** | Extracts data from previous responses as payloads | **[M]** |
| **Illegal Unicode** | Unicode encoding bypass payloads | **[N]** |
| **Character Blocks** | Variable-length character sequences for overflow testing | **[N]** |
| **Numbers** | Sequential or random number generation | **[M]** |
| **Dates** | Date format payloads | **[N]** |
| **Brute Forcer** | All permutations of given character set and length | **[M]** |
| **Null Payloads** | Empty/null payloads for baseline testing | **[M]** |
| **Username Generator** | Generates usernames from name patterns | **[N]** |
| **ECB Block Shuffler** | ECB cipher block manipulation | **[N]** |
| **Bit Flipper** | Bit-level payload manipulation | **[N]** |

### 2.8 Intruder -- Payload Processing & Matching

| Feature | Description | Priority |
|---------|-------------|----------|
| **Payload Encoding** | URL, HTML, Base64, hex encoding | **[M]** |
| **Payload Hashing** | MD5, SHA-1, SHA-256 hashing of payloads | **[N]** |
| **Prefix/Suffix** | Add prefix/suffix to payloads | **[M]** |
| **Match/Replace** | Regex-based payload transformation | **[M]** |
| **Substring** | Extract substring from payloads | **[N]** |
| **Reverse Substring** | Reverse operation on payloads | **[N]** |
| **Response Extraction (Grep)** | Extract data from responses for analysis | **[M]** |
| **Response Matching** | Match specific strings/patterns in responses | **[M]** |
| **Response Diff** | Compare responses to identify anomalies | **[M]** |

### 2.9 Proxy & Interception

| Feature | Description | Priority |
|---------|-------------|----------|
| **HTTP/HTTPS Proxy** | Man-in-the-middle proxy for intercepting all traffic | **[M]** |
| **WebSocket Interception** | Intercept, view, and modify WebSocket messages | **[M]** |
| **Match & Replace Rules** | Auto-modify requests/responses matching patterns | **[M]** |
| **SSL Pass-Through** | Selectively bypass SSL interception for specific hosts | **[N]** |
| **Invisible Proxying** | Non-proxy-aware client support | **[N]** |
| **Response Modification** | Auto-modify responses (unhide hidden fields, remove JS, etc.) | **[N]** |
| **Client TLS Certificates** | Per-host client certificate configuration | **[N]** |
| **Upstream Proxy/SOCKS** | Chain through corporate proxies | **[N]** |

### 2.10 Additional Core Tools

| Tool | Description | Priority |
|------|-------------|----------|
| **Repeater** | Manual request modification and resend with response comparison | **[M]** |
| **Sequencer** | Token/session randomness quality analysis | **[M]** |
| **Decoder** | Multi-format encoding/decoding (URL, Base64, hex, HTML, etc.) | **[N]** |
| **Comparer** | Side-by-side comparison of requests/responses (word-level and byte-level) | **[N]** |
| **DOM Invader** | Browser-based DOM XSS testing tool | **[M]** |
| **Organizer** | Curate and annotate selected requests/responses | **[N]** |
| **Target Site Map** | Hierarchical visualization of discovered application structure | **[M]** |
| **Logger** | Full HTTP history with filtering and annotation | **[N]** |

### 2.11 Extensions (BApp Store)

| Extension Category | Notable Extensions | Priority |
|--------------------|--------------------|----------|
| **Scanner Enhancement** | Burp Bounty (custom scan checks), Backslash Powered Scanner, Active Scan++ | **[M]** (custom checks concept) |
| **Authentication** | Autorize (auth testing), AuthMatrix (access control) | **[M]** (auth testing concept) |
| **GraphQL** | InQL (GraphQL introspection, query generation, attack surface) | **[M]** |
| **API Testing** | Wsdler (WSDL parsing), OpenAPI Parser | **[M]** |
| **Parameter Discovery** | Param Miner (hidden parameter discovery, web cache poisoning) | **[M]** |
| **Performance** | Turbo Intruder (high-speed intruder for race conditions) | **[M]** |
| **SQLi** | SQLiPy (SQLMap integration), SQLMap DNS Collaborator | **[N]** |
| **Automation** | BChecks (custom scan checks in Burp's DSL) | **[M]** (custom checks) |
| **Reporting** | Custom report generator extensions | **[N]** |
| **JWT** | JWT Editor, JSON Web Token Attacker | **[M]** |
| **CSP** | CSP Auditor, CSP Bypass | **[N]** |
| **Timing** | Request Timer (timing-based detection) | **[N]** |

### 2.12 Reporting

| Format | Details | Priority |
|--------|---------|----------|
| **HTML** | Full detailed report with request/response evidence | **[M]** |
| **XML** | Machine-readable structured output | **[M]** |
| **Custom Templates** | User-defined report templates | **[N]** |
| **Issue Severity Levels** | High, Medium, Low, Information | **[M]** |
| **Issue Confidence Levels** | Certain, Firm, Tentative | **[M]** |
| **Remediation Advice** | Per-issue remediation guidance | **[M]** |
| **Request/Response Evidence** | Full HTTP evidence for each finding | **[M]** |

---

## 3. Nuclei -- Unique Differentiators

### 3.1 What Nuclei Does That Others Don't

| Feature | Description | Priority for DAST |
|---------|-------------|-------------------|
| **YAML Template DSL** | Simple, community-maintainable YAML templates for vulnerability definitions; no code compilation needed | **[M]** (template concept) |
| **11,000+ Community Templates** | Largest community-contributed vulnerability check database; covers CVEs, misconfigs, default creds, exposed panels | **[M]** (community model) |
| **Multi-Protocol Support** | HTTP, DNS, TCP, SSL/TLS, WebSocket, WHOIS, File, Headless, JavaScript, Code -- in a single tool | **[M]** (multi-protocol) |
| **Network Service Scanning** | Raw TCP/UDP service fingerprinting and vulnerability testing (not just web) | **[N]** |
| **DNS Vulnerability Testing** | DNS-specific checks (zone transfer, subdomain takeover, record poisoning) | **[N]** |
| **SSL/TLS Analysis** | Certificate validation, cipher enumeration, protocol version checks | **[M]** |
| **File System Scanning** | Local file content pattern matching for secrets, configs, credentials | **[M]** |
| **Headless Browser Templates** | Browser-based checks for DOM XSS, JS-rendered content analysis | **[M]** |
| **JavaScript Protocol** | Custom JavaScript for complex multi-step exploit logic with loops/conditions | **[N]** |
| **Code Protocol** | Execute arbitrary code (Go, Python) as part of scanning templates | **[N]** |
| **Workflows** | Chain multiple templates into conditional multi-step checks | **[M]** |
| **Request Clustering** | Batch multiple template checks into single requests for speed | **[M]** |
| **OOB Interaction (Interactsh)** | Built-in out-of-band callback server (open-source Collaborator equivalent) | **[M]** |
| **Template Matchers** | Status, word, regex, binary, DSL-based response matching | **[M]** |
| **Template Extractors** | Pull data from responses for chaining between templates | **[M]** |
| **Severity Classification** | CVSS-aligned: Critical, High, Medium, Low, Info | **[M]** |
| **Tags System** | Categorize and filter templates by CVE, technology, type, severity | **[M]** |
| **Automatic Template Updates** | Templates update independently of the scanner binary | **[M]** |
| **Speed** | Go-based, massively concurrent; thousands of checks per second | **[M]** |
| **JSONL Output** | Machine-readable line-delimited JSON for pipeline consumption | **[M]** |
| **Markdown Output** | Human-readable markdown reports | **[N]** |
| **SARIF Output** | Static Analysis Results Interchange Format for CI/CD | **[M]** |

### 3.2 Nuclei Template Categories

| Category | What It Covers | Priority |
|----------|---------------|----------|
| **CVEs** | Known CVE exploits with version detection | **[M]** |
| **Misconfigurations** | Default configs, debug endpoints, admin panels | **[M]** |
| **Exposures** | Leaked credentials, API keys, .env files, .git exposure | **[M]** |
| **Default Logins** | Default username/password combinations for common services | **[M]** |
| **Takeovers** | Subdomain takeover detection across cloud providers | **[N]** |
| **Technologies** | Technology detection and fingerprinting | **[M]** |
| **WAF Detection** | Web Application Firewall identification | **[M]** |
| **Network** | TCP/UDP service vulnerabilities | **[N]** |
| **DNS** | DNS misconfigurations and vulnerabilities | **[N]** |
| **SSL** | Certificate and TLS configuration issues | **[M]** |
| **Headless** | Browser-based JavaScript vulnerability checks | **[M]** |
| **Fuzzing** | Protocol-level fuzzing templates | **[N]** |
| **Workflows** | Multi-template conditional scanning chains | **[M]** |

---

## 4. Modern DAST Features

### 4.1 API Security Testing

| Feature | Description | Priority |
|---------|-------------|----------|
| **OpenAPI/Swagger Import** | Parse OpenAPI 2.0/3.0/3.1 specs to build attack surface | **[M]** |
| **GraphQL Introspection** | Discover schema via introspection queries; generate test queries for all types/mutations | **[M]** |
| **GraphQL Injection Testing** | Query injection, authorization bypass, batching attacks, circular fragment DoS | **[M]** |
| **GraphQL Depth/Complexity Analysis** | Detect lack of query depth/complexity limits (DoS vector) | **[M]** |
| **gRPC Testing** | Protocol buffer message parsing, method enumeration, parameter fuzzing | **[M]** |
| **gRPC Reflection** | Auto-discover gRPC services via server reflection | **[N]** |
| **WebSocket Testing** | Message interception, injection testing, authentication testing on WS connections | **[M]** |
| **WebSocket Fuzzing** | Payload-based fuzzing of WebSocket message frames | **[M]** |
| **REST API Testing** | Parameter-level injection, method testing, content-type manipulation | **[M]** |
| **SOAP/WSDL Testing** | WSDL parsing and SOAP endpoint scanning | **[N]** |
| **API Schema Validation** | Verify API responses match declared schema | **[N]** |
| **Shadow/Zombie API Detection** | Discover undocumented or deprecated API endpoints still active | **[M]** |
| **Rate Limiting Detection** | Test for absence of rate limiting on sensitive endpoints | **[M]** |
| **Mass Assignment Testing** | Test for unintended parameter binding in API requests | **[M]** |
| **BOLA/IDOR Detection** | Broken Object Level Authorization via ID manipulation | **[M]** |

### 4.2 Cloud-Native Scanning

| Feature | Description | Priority |
|---------|-------------|----------|
| **Container-Native Deployment** | Docker/Kubernetes-native scanner deployment | **[M]** |
| **Cloud Metadata SSRF** | Test for access to AWS/GCP/Azure metadata endpoints (169.254.169.254, etc.) | **[M]** |
| **Serverless Function Testing** | Test Lambda/Cloud Functions via API Gateway | **[N]** |
| **Service Mesh Awareness** | Understanding of Istio/Linkerd/Envoy routing | **[N]** |
| **Kubernetes API Testing** | Test exposed K8s API servers and dashboards | **[N]** |
| **Cloud Storage Misconfig** | S3 bucket, Azure Blob, GCS bucket permission testing | **[M]** |
| **Microservice Discovery** | Discover and map microservice endpoints from a single entry point | **[M]** |

### 4.3 CI/CD Integration

| Feature | Description | Priority |
|---------|-------------|----------|
| **CLI-First Design** | Full functionality accessible via command line | **[M]** |
| **Docker Images** | Pre-built images for all major registries | **[M]** |
| **GitHub Actions** | Native GitHub Actions integration | **[M]** |
| **GitLab CI** | Native GitLab CI/CD integration | **[M]** |
| **Jenkins** | Jenkins plugin or pipeline step | **[N]** |
| **Azure DevOps** | Azure Pipelines integration | **[N]** |
| **Exit Codes** | Non-zero exit on finding severity thresholds (fail builds) | **[M]** |
| **SARIF Output** | Standard output format for GitHub Code Scanning, Azure DevOps, etc. | **[M]** |
| **JUnit XML** | Test result format for CI systems | **[N]** |
| **Incremental Scanning** | Scan only changed endpoints based on diff analysis | **[N]** |
| **Baseline Comparison** | Compare results against previous scan to surface new findings only | **[M]** |
| **Scan Policies for Pipelines** | Quick/fast policies for PR checks, full policies for nightly | **[M]** |
| **API-Driven Scan Control** | REST API to trigger, monitor, and retrieve scan results | **[M]** |
| **Webhook Notifications** | Post results to Slack, Teams, PagerDuty, email | **[N]** |
| **Artifact Upload** | Upload reports as pipeline artifacts | **[M]** |

---

## 5. Scan Policies and Profiles

### 5.1 ZAP Built-in Policies

| Policy | Description | Use Case | Priority |
|--------|-------------|----------|----------|
| **Default Policy** | All installed active scan rules enabled at default strength/threshold | General-purpose scanning | **[M]** |
| **Developer CI/CD Policy** | Quick scan; higher-risk issues only; low false positive tolerance | PR checks, pipeline gates | **[M]** |
| **QA Full Policy** | Comprehensive quality assurance focused; all rules, higher thresholds | Nightly/weekly scans | **[M]** |
| **API Policy** | Rules focused on API-specific vulnerabilities; skips UI-specific checks | API-only testing | **[M]** |
| **Penetration Tester Policy** | All rules including examples; max thoroughness | Manual pentest augmentation | **[N]** |

### 5.2 Recommended Scan Profiles for Production Scanner

| Profile | What It Includes | Duration Target | Priority |
|---------|-----------------|-----------------|----------|
| **Quick Scan / Baseline** | Passive rules only + traditional spider; no active attacks | 1-5 minutes | **[M]** |
| **Standard Scan** | Spider + AJAX spider + core active rules (SQLi, XSS, CMDi, path traversal, SSRF) | 15-60 minutes | **[M]** |
| **Full Scan** | All spiders + all active rules at maximum thoroughness + OAST checks | 1-8 hours | **[M]** |
| **API-Only Scan** | OpenAPI/GraphQL import + API-specific active rules; no UI crawling | 10-30 minutes | **[M]** |
| **OWASP Top 10 Scan** | Rules mapped to OWASP Top 10 categories only | 30-90 minutes | **[M]** |
| **Compliance Scan** | PCI DSS, SOC2, or HIPAA-relevant checks only | Variable | **[N]** |
| **Authentication Scan** | Session management, auth bypass, brute force, MFA testing | 15-45 minutes | **[M]** |
| **Custom Profile** | User-defined mix of rules with per-rule strength/threshold | Variable | **[M]** |

### 5.3 Policy Configuration Parameters

| Parameter | Description | Priority |
|-----------|-------------|----------|
| **Rule Enable/Disable** | Toggle individual scan rules on/off | **[M]** |
| **Threshold** | Per-rule threshold: Off, Low, Medium, High (confidence required to report) | **[M]** |
| **Strength** | Per-rule strength: Low, Medium, High, Insane (number of attack variants) | **[M]** |
| **Category-Level Control** | Set defaults for entire vulnerability categories | **[M]** |
| **Max Scan Duration** | Time-box the entire scan | **[M]** |
| **Max Rule Duration** | Time-box individual rule execution | **[M]** |
| **Concurrent Request Limit** | Control scan speed/aggressiveness | **[M]** |
| **Delay Between Requests** | Throttle to avoid overwhelming target | **[M]** |
| **Max Alerts Per Rule** | Limit alerts to avoid noise | **[M]** |

---

## 6. Report Formats

### 6.1 Format Comparison

| Format | Use Case | Who Consumes It | Priority |
|--------|----------|-----------------|----------|
| **HTML** | Human-readable detailed report; executive summary + technical detail; screenshots and request/response evidence | Security teams, management, compliance auditors | **[M]** |
| **PDF** | Printable/distributable version of HTML report; professional formatting for stakeholders | Management, clients, compliance documentation | **[M]** |
| **SARIF** | Static Analysis Results Interchange Format; standard for GitHub Code Scanning, Azure DevOps, IDE integrations | CI/CD pipelines, GitHub Advanced Security, IDE plugins | **[M]** |
| **JSON** | Machine-readable structured output; full finding data with request/response pairs | Automation, custom dashboards, data pipelines, SIEM integration | **[M]** |
| **JSONL** | Line-delimited JSON; streaming-friendly for large result sets | Log aggregation (ELK, Splunk), real-time processing | **[M]** |
| **XML** | Legacy machine-readable format; OWASP ZAP native format; import into various tools | Legacy tool integration, Burp import/export, DefectDojo | **[M]** |
| **CSV** | Spreadsheet-compatible flat format; quick triage in Excel/Google Sheets | Quick triage, non-technical stakeholders, bulk processing | **[N]** |
| **Markdown** | Text-based readable format; embeddable in wikis, PRs, documentation | Developer documentation, PR comments, wiki integration | **[N]** |

### 6.2 Report Content Requirements

| Content Element | Description | Priority |
|-----------------|-------------|----------|
| **Executive Summary** | High-level risk overview with severity distribution | **[M]** |
| **Finding Details** | Vulnerability name, description, severity, confidence, CWE, OWASP category | **[M]** |
| **Evidence** | Full HTTP request/response showing the vulnerability | **[M]** |
| **Reproduction Steps** | How to manually verify the finding (curl command or browser steps) | **[M]** |
| **Remediation Guidance** | Per-finding fix recommendations with code examples | **[M]** |
| **CVSS Score** | Common Vulnerability Scoring System rating | **[M]** |
| **CWE Mapping** | Common Weakness Enumeration ID for each finding | **[M]** |
| **OWASP Top 10 Mapping** | Which OWASP Top 10 category applies | **[M]** |
| **Scan Metadata** | Target URL, scan duration, policy used, scanner version, timestamp | **[M]** |
| **Severity Distribution Chart** | Visual breakdown (for HTML/PDF) | **[N]** |
| **False Positive Marking** | Ability to mark findings as FP and exclude from counts | **[M]** |
| **Deduplicated Findings** | Group duplicate findings across endpoints | **[M]** |
| **Compliance Mapping** | PCI DSS, SOC2, HIPAA mapping of findings | **[N]** |
| **Trending** | Comparison with previous scans (new, fixed, unchanged) | **[N]** |

---

## 7. Session Management Testing Methodologies

### 7.1 Session Token Analysis

| Test | Description | Priority |
|------|-------------|----------|
| **Token Randomness** | Statistical analysis of session token entropy (Burp Sequencer equivalent) | **[M]** |
| **Token Length** | Verify minimum token length (128+ bits recommended) | **[M]** |
| **Token Character Set** | Verify sufficient character space in tokens | **[M]** |
| **Token Predictability** | Attempt sequential/pattern prediction of tokens | **[M]** |
| **Token in URL** | Detect session IDs passed via URL parameters | **[M]** |
| **Token Fixation** | Verify token regeneration on authentication | **[M]** |
| **Token Rotation** | Verify token changes after privilege escalation | **[M]** |

### 7.2 Session Lifecycle Testing

| Test | Description | Priority |
|------|-------------|----------|
| **Session Timeout (Idle)** | Verify sessions expire after configurable idle period | **[M]** |
| **Session Timeout (Absolute)** | Verify sessions have maximum absolute lifetime | **[M]** |
| **Logout Effectiveness** | Verify server-side session invalidation on logout | **[M]** |
| **Concurrent Session Control** | Test if multiple simultaneous sessions are allowed/limited | **[M]** |
| **Session After Password Change** | Verify old sessions are invalidated after credential change | **[M]** |
| **Cross-Browser Session** | Test session behavior across multiple clients | **[N]** |

### 7.3 Cookie Security Testing

| Test | Description | Priority |
|------|-------------|----------|
| **Secure Flag** | Cookie only sent over HTTPS | **[M]** |
| **HttpOnly Flag** | Cookie inaccessible to JavaScript | **[M]** |
| **SameSite Attribute** | Cross-site request protection (Strict/Lax/None) | **[M]** |
| **Domain Scope** | Cookie not overly broad in domain scope | **[M]** |
| **Path Scope** | Cookie restricted to appropriate path | **[N]** |
| **Expiry** | Reasonable expiration time | **[N]** |

### 7.4 Authentication Bypass Testing

| Test | Description | Priority |
|------|-------------|----------|
| **Direct URL Access** | Access authenticated pages without valid session | **[M]** |
| **Parameter Manipulation** | Modify user ID/role parameters to escalate | **[M]** |
| **JWT Token Manipulation** | Algorithm confusion, signature stripping, claim modification | **[M]** |
| **OAuth Flow Abuse** | State parameter CSRF, redirect_uri manipulation, token leakage | **[M]** |
| **API Key in Header/URL** | Test API key transmission security and rotation | **[M]** |
| **Bearer Token Testing** | Token scope validation, expiration enforcement | **[M]** |
| **Multi-Factor Bypass** | Step-skipping, code reuse, rate limiting on MFA | **[N]** |

---

## 8. Business Logic Flaw Detection Approaches

### 8.1 Why Automated Detection Is Hard

Business logic flaws are application-specific. Unlike injection or XSS which have universal signatures, business logic bugs require understanding what the application SHOULD do. No scanner can fully automate this, but several approaches provide partial coverage:

### 8.2 Automated Approaches

| Approach | Description | Priority |
|----------|-------------|----------|
| **Multi-Step Sequence Testing** | Define multi-step workflows (e.g., cart -> checkout -> payment) and test for step-skipping, parameter manipulation between steps | **[M]** |
| **Race Condition Testing** | Send parallel requests to exploit TOCTOU flaws (double-spend, concurrent coupon use) -- Turbo Intruder / parallel request approach | **[M]** |
| **Price/Quantity Manipulation** | Tamper with numeric values (negative quantities, zero prices, integer overflow) | **[M]** |
| **Workflow Step Skipping** | Attempt to access later steps in a flow without completing prerequisites | **[M]** |
| **Parameter Tampering** | Modify hidden fields, enumerated values, role flags in requests | **[M]** |
| **Horizontal Privilege Escalation** | Access other users' resources by changing identifiers (IDOR) | **[M]** |
| **Vertical Privilege Escalation** | Perform admin actions from regular user session | **[M]** |
| **Replay Attacks** | Replay valid requests to test idempotency and duplicate processing | **[M]** |
| **Boundary Value Testing** | Test edge cases in numeric inputs (0, -1, MAX_INT, extremely long strings) | **[M]** |
| **State Machine Violation** | Attempt invalid state transitions (cancel already-shipped order, approve already-rejected request) | **[M]** |
| **Response Comparison (Anomaly)** | Compare response sizes, timing, status codes across similar requests to detect authorization differences | **[M]** |

### 8.3 Semi-Automated Approaches (Require Configuration)

| Approach | Description | Priority |
|----------|-------------|----------|
| **Access Control Matrix** | Define role-endpoint matrix; scanner verifies each role can only access permitted endpoints | **[M]** |
| **Sequence Definition** | User defines valid multi-step sequences; scanner tests deviations | **[M]** |
| **Custom Assertions** | User defines expected behavior per endpoint; scanner checks violations | **[N]** |
| **Transaction Integrity** | Verify that modifying one transaction doesn't affect others | **[N]** |
| **Data Validation Rules** | User-defined input constraints checked during scanning | **[N]** |

### 8.4 Detection Signals (Heuristic-Based)

| Signal | What It Indicates | Priority |
|--------|-------------------|----------|
| **Response Size Anomaly** | Different content returned for different user IDs may indicate IDOR | **[M]** |
| **Timing Anomaly** | Processing time differences may indicate different code paths (auth vs unauth) | **[M]** |
| **Status Code Anomaly** | Getting 200 instead of 403 when manipulating parameters | **[M]** |
| **Error Message Differential** | Different error messages for valid vs invalid entity IDs | **[M]** |
| **Redirect Anomaly** | Being redirected differently based on parameter values | **[N]** |
| **Cookie/Token Changes** | Unexpected session changes after specific requests | **[N]** |

---

## 9. Feature Parity Summary -- Must-Have vs Nice-to-Have

### 9.1 MUST-HAVE for Production DAST Scanner (ZAP/Burp Parity)

**Core Scanning Engine:**
1. Passive scanner (analyze traffic without sending requests)
2. Active scanner (send attack payloads to discovered endpoints)
3. Traditional HTML spider/crawler
4. AJAX/headless browser spider
5. Forced browsing / directory discovery
6. Fuzzer with configurable payloads

**Vulnerability Detection (Active):**
7. SQL Injection (error, boolean blind, time blind, UNION)
8. Cross-Site Scripting (reflected, stored, DOM-based)
9. OS Command Injection (blind + error-based)
10. Path Traversal / LFI / RFI
11. XML External Entity (XXE)
12. Server-Side Request Forgery (SSRF)
13. Server-Side Template Injection (SSTI)
14. CRLF Injection / Header Injection
15. NoSQL Injection
16. CSRF detection
17. CORS misconfiguration
18. Insecure Deserialization
19. HTTP Request Smuggling
20. Web Cache Poisoning
21. Open Redirect
22. Cloud Metadata SSRF
23. Source Code / Backup File Disclosure
24. Hidden File Discovery
25. JWT vulnerability testing
26. Prototype Pollution

**Vulnerability Detection (Passive):**
27. Security header analysis (CSP, HSTS, X-Content-Type-Options, etc.)
28. Cookie security (HttpOnly, Secure, SameSite)
29. Information disclosure (error messages, server banners, stack traces)
30. Technology fingerprinting
31. PII exposure detection
32. Session ID in URL
33. Dangerous JavaScript function usage
34. Mixed content detection

**Out-of-Band (OAST):**
35. OOB interaction server (DNS + HTTP callbacks for blind vulns)
36. Per-payload unique callback URLs for correlation
37. Automated polling and correlation

**Authentication:**
38. Form-based login
39. JSON/API-based login
40. HTTP Basic/Digest
41. Browser-based login (headless)
42. Script-based custom auth
43. Session management (cookie, header, token)
44. Login verification strategies

**API Security:**
45. OpenAPI/Swagger import
46. GraphQL introspection and testing
47. WebSocket interception and testing
48. REST API parameter testing
49. BOLA/IDOR detection
50. Mass assignment testing
51. Rate limiting detection

**Reporting:**
52. HTML report with evidence
53. PDF report
54. JSON output
55. SARIF output
56. XML output
57. CWE mapping
58. CVSS scoring
59. OWASP Top 10 mapping
60. Remediation guidance
61. Request/response evidence

**Scan Management:**
62. Configurable scan policies (rule enable/disable, strength, threshold)
63. Pre-built scan profiles (quick, standard, full, API-only)
64. Max duration limits
65. Concurrent request control
66. Request delay/throttle

**CI/CD:**
67. CLI-first operation
68. Docker images
69. Exit codes on severity threshold
70. API for programmatic control
71. GitHub Actions support
72. Baseline comparison (new findings only)

**Session/Auth Testing:**
73. Session token analysis (entropy, predictability)
74. Session fixation detection
75. Session timeout verification
76. Logout effectiveness testing

**Business Logic:**
77. Multi-step sequence testing
78. Race condition detection
79. IDOR/parameter manipulation
80. Response anomaly comparison
81. Workflow step-skipping

**Extensibility:**
82. Custom scan rule support (script or template)
83. Proxy script / request modification hooks
84. Plugin/add-on architecture

### 9.2 NICE-TO-HAVE (Differentiators)

1. SOAP/WSDL scanning
2. gRPC reflection and testing
3. Network/TCP service scanning (Nuclei-style)
4. DNS vulnerability testing
5. SSL/TLS deep analysis
6. File system scanning
7. Subdomain takeover detection
8. Community template marketplace
9. Scheduled scans
10. Compliance mapping (PCI, SOC2, HIPAA)
11. Visual regression testing
12. API schema validation
13. Custom report templates
14. Scan comparison trending
15. Multi-factor auth bypass testing
16. ECB/crypto block testing
17. Format string / buffer overflow testing
18. Auto-detect auth method
19. IDE integration
20. Webhook/Slack notifications

---

## 10. Sources

- [ZAP Active Scan Rules](https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/)
- [ZAP Active Scan Rules - Beta](https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-beta/)
- [ZAP Active Scan Rules - Alpha](https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/)
- [ZAP Passive Scan Rules](https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/)
- [ZAP Scan Policy](https://www.zaproxy.org/docs/desktop/start/features/scanpolicy/)
- [ZAP Authentication Methods](https://www.zaproxy.org/docs/desktop/start/features/authmethods/)
- [ZAP Scripts](https://www.zaproxy.org/docs/desktop/start/features/scripts/)
- [ZAP AJAX Spider](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/)
- [ZAP Report Generation](https://www.zaproxy.org/docs/desktop/addons/report-generation/)
- [ZAP SARIF Report](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-sarif-json/)
- [ZAP Scan Policies](https://www.zaproxy.org/docs/desktop/addons/scan-policies/)
- [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [Burp Suite Pro Features](https://portswigger.net/burp/pro/features)
- [Burp Scanner Documentation](https://portswigger.net/burp/documentation/scanner)
- [Burp Vulnerability List](https://portswigger.net/burp/documentation/scanner/vulnerabilities-list)
- [Burp Audit Settings](https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings)
- [Burp Intruder Attack Types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types)
- [Burp Extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions)
- [BApp Store](https://portswigger.net/bappstore)
- [Nuclei GitHub](https://github.com/projectdiscovery/nuclei)
- [Nuclei Documentation](https://docs.projectdiscovery.io/opensource/nuclei/overview)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei v3 Features](https://projectdiscovery.io/blog/nuclei-v3-featurefusion)
- [ZAP Browser-Based Auth](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/browser-auth/)
- [Top DAST Tools 2026](https://escape.tech/blog/top-dast-tools/)
- [DAST Tools Comparison](https://www.stackhawk.com/blog/dynamic-application-security-testing-tools-comparison/)
