"""
Technology Fingerprinter — Wappalyzer-style detection from HTTP responses.
Detects: web server, backend language, framework, CMS, database, CDN, WAF.
"""
from __future__ import annotations
import re
from typing import Any


# ── Fingerprint rules ─────────────────────────────────────────────────────────
# Each rule: (category, name, sources, pattern)
# sources: set of {"header:<name>", "body", "cookie:<name>", "path"}

_RULES: list[tuple[str, str, list[str], str]] = [
    # Web Servers
    ("server",    "nginx",          ["header:server"],        r"nginx"),
    ("server",    "Apache",         ["header:server"],        r"Apache"),
    ("server",    "IIS",            ["header:server"],        r"IIS/[\d.]+"),
    ("server",    "LiteSpeed",      ["header:server"],        r"LiteSpeed"),
    ("server",    "Caddy",          ["header:server"],        r"Caddy"),
    ("server",    "Gunicorn",       ["header:server"],        r"gunicorn"),
    ("server",    "Werkzeug",       ["header:server"],        r"Werkzeug"),
    ("server",    "Jetty",          ["header:server"],        r"Jetty"),
    ("server",    "Tomcat",         ["header:server"],        r"Apache-Coyote|Tomcat"),
    # Languages / Runtimes
    ("language",  "PHP",            ["header:x-powered-by", "header:server", "body"], r"PHP/[\d.]+"),
    ("language",  "Python",         ["header:x-powered-by", "header:server"],         r"Python/[\d.]+"),
    ("language",  "Java",           ["header:x-powered-by"],                          r"JSP|Servlet|Java"),
    ("language",  "Ruby",           ["header:x-powered-by", "header:server"],         r"Phusion Passenger|Ruby"),
    ("language",  "Node.js",        ["header:x-powered-by"],                          r"Express|Node\.js"),
    # Frameworks
    ("framework", "Django",         ["header:server", "header:x-frame-options", "body"],      r"csrfmiddlewaretoken|django"),
    ("framework", "Rails",          ["header:x-powered-by", "header:set-cookie", "body"],     r"Ruby on Rails|_rails_session"),
    ("framework", "Laravel",        ["header:set-cookie", "body"],                            r"laravel_session|XSRF-TOKEN"),
    ("framework", "Express",        ["header:x-powered-by"],                                  r"Express"),
    ("framework", "Flask",          ["header:server", "body"],                                r"Werkzeug|flask"),
    ("framework", "FastAPI",        ["header:server"],                                        r"uvicorn"),
    ("framework", "Spring",         ["header:x-powered-by", "body"],                         r"Spring|X-Application-Context"),
    ("framework", "WordPress",      ["body", "header:set-cookie"],                            r"wp-content|wp-includes|WordPress|wordpress_logged_in"),
    ("framework", "Drupal",         ["body", "header:x-generator"],                          r"Drupal|drupal"),
    ("framework", "Joomla",         ["body"],                                                 r"Joomla!|joomla"),
    ("framework", "Magento",        ["body", "header:set-cookie"],                            r"Mage_Store|magento"),
    ("framework", "Shopify",        ["header:server", "body"],                                r"Shopify"),
    ("framework", "Next.js",        ["header:x-powered-by", "body"],                         r"Next\.js|__NEXT_DATA__"),
    ("framework", "Nuxt.js",        ["body"],                                                 r"__NUXT__|nuxt"),
    ("framework", "Angular",        ["body"],                                                 r"ng-version|angular"),
    ("framework", "React",          ["body"],                                                 r"__REACT__|react-root|data-reactroot"),
    ("framework", "Vue.js",         ["body"],                                                 r"__vue__|data-v-"),
    # Databases (via errors or comments)
    ("database",  "MySQL",          ["body"],                                                 r"MySQL|mysql_fetch|You have an error in your SQL"),
    ("database",  "PostgreSQL",     ["body"],                                                 r"PostgreSQL|pg_query|PSQLException"),
    ("database",  "SQLite",         ["body"],                                                 r"SQLite|sqlite3"),
    ("database",  "MongoDB",        ["body"],                                                 r"MongoDB|MongoError|mongo"),
    ("database",  "Oracle",         ["body"],                                                 r"ORA-\d+|oracle"),
    ("database",  "MSSQL",          ["body"],                                                 r"Microsoft SQL Server|Unclosed quotation mark"),
    # CDN / Proxy
    ("cdn",       "Cloudflare",     ["header:server", "header:cf-ray", "header:cf-cache-status"], r"cloudflare|cf-ray"),
    ("cdn",       "Fastly",         ["header:via", "header:x-served-by"],                    r"Fastly|cache-"),
    ("cdn",       "Akamai",         ["header:server", "header:x-check-cacheable"],           r"AkamaiGHost"),
    ("cdn",       "AWS CloudFront", ["header:via", "header:x-amz-cf-id"],                    r"CloudFront|AmazonS3"),
    # WAFs
    ("waf",       "Cloudflare WAF", ["body"],                                                 r"Attention Required!.*Cloudflare|cloudflare-nginx"),
    ("waf",       "ModSecurity",    ["header:server", "body"],                                r"Mod_Security|NOYB"),
    ("waf",       "AWS WAF",        ["body"],                                                 r"AWS WAF|Request blocked"),
    ("waf",       "F5 BIG-IP",      ["header:server"],                                       r"BigIP|BIG-IP"),
    ("waf",       "Imperva",        ["header:x-iinfo"],                                      r"x-iinfo"),
    # Auth/Session
    ("auth",      "JWT",            ["header:authorization", "header:set-cookie"],           r"eyJ[A-Za-z0-9_-]{10,}"),
    ("auth",      "Basic Auth",     ["header:www-authenticate"],                             r"Basic realm"),
    ("auth",      "OAuth2",         ["body"],                                                 r"oauth2|openid-configuration|access_token"),
    # Security
    ("security",  "HSTS",           ["header:strict-transport-security"],                    r".+"),
    ("security",  "CSP",            ["header:content-security-policy"],                      r".+"),
    ("security",  "CORS enabled",   ["header:access-control-allow-origin"],                  r".+"),
]


def fingerprint(
    url: str,
    status_code: int,
    resp_headers: dict,
    resp_body: str,
    cookies: dict | None = None,
) -> dict[str, list[str]]:
    """
    Run all fingerprint rules against a response.
    Returns: {category: [tech1, tech2, ...]}
    """
    results: dict[str, list[str]] = {}
    headers_lower = {k.lower(): v for k, v in resp_headers.items()}
    body_lower    = resp_body[:8000].lower()
    cookie_str    = " ".join(f"{k}={v}" for k, v in (cookies or {}).items())

    for (category, name, sources, pattern) in _RULES:
        matched = False
        for src in sources:
            if src == "body":
                text = resp_body[:8000] + body_lower
            elif src.startswith("header:"):
                hdr  = src[7:]
                text = headers_lower.get(hdr, "")
            elif src.startswith("cookie:"):
                ck   = src[7:]
                text = (cookies or {}).get(ck, "") + cookie_str
            elif src == "path":
                text = url
            else:
                text = ""
            if text and re.search(pattern, text, re.I):
                matched = True
                break
        if matched:
            results.setdefault(category, [])
            if name not in results[category]:
                results[category].append(name)

    return results


def fingerprint_summary(fp: dict[str, list[str]]) -> str:
    """Human-readable fingerprint summary."""
    parts = []
    for cat in ["server", "language", "framework", "database", "cdn", "waf", "auth"]:
        items = fp.get(cat, [])
        if items:
            parts.append(f"{cat.title()}: {', '.join(items)}")
    return " | ".join(parts) if parts else "Unknown stack"
