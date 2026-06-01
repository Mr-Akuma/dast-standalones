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
    # Additional servers
    ("server",    "OpenResty",      ["header:server"],        r"openresty"),
    ("server",    "Kestrel",        ["header:server"],        r"Kestrel"),
    ("server",    "Cowboy",         ["header:server"],        r"Cowboy"),
    ("server",    "Tengine",        ["header:server"],        r"Tengine"),
    ("server",    "Envoy",          ["header:server"],        r"envoy"),
    # Additional languages
    ("language",  "ASP.NET",        ["header:x-powered-by", "header:x-aspnet-version"],     r"ASP\.NET"),
    ("language",  "Go",             ["header:server"],                                       r"Go-http-server"),
    ("language",  "Perl",           ["header:server"],                                       r"Perl|mod_perl"),
    ("language",  "Erlang",         ["header:server"],                                       r"MochiWeb|Cowboy"),
    # Additional frameworks
    ("framework", "Svelte",         ["body"],                                                r"__svelte|svelte-"),
    ("framework", "Gatsby",         ["body"],                                                r"gatsby-"),
    ("framework", "Hugo",           ["body"],                                                r"Hugo \d|powered by Hugo"),
    ("framework", "Remix",          ["body"],                                                r"__remixContext|remix"),
    ("framework", "Symfony",        ["header:x-powered-by", "header:set-cookie"],           r"Symfony|PHPSESSID"),
    ("framework", "CodeIgniter",    ["header:set-cookie"],                                   r"ci_session"),
    ("framework", "CakePHP",        ["header:set-cookie"],                                   r"CAKEPHP"),
    ("framework", "Yii",            ["header:set-cookie", "body"],                           r"YII_CSRF_TOKEN|yii-"),
    ("framework", "Blazor",         ["body"],                                                r"_blazor|blazor\.web"),
    ("framework", "Ember.js",       ["body"],                                                r"ember-application|data-ember"),
    ("framework", "Backbone.js",    ["body"],                                                r"Backbone\.js|backbone-min"),
    ("framework", "Meteor",         ["body"],                                                r"__meteor_runtime_config__|meteor"),
    # CMS
    ("framework", "Ghost",          ["body"],                                                r"ghost-|powered by Ghost"),
    ("framework", "Typo3",          ["body"],                                                r"typo3|TYPO3"),
    ("framework", "Umbraco",        ["body"],                                                r"umbraco"),
    ("framework", "PrestaShop",     ["body"],                                                r"PrestaShop|prestashop"),
    ("framework", "Moodle",         ["body"],                                                r"moodle|Moodle"),
    # CDN / Proxy
    ("cdn",       "Vercel",         ["header:server", "header:x-vercel-id"],                r"Vercel"),
    ("cdn",       "Netlify",        ["header:server", "header:x-nf-request-id"],            r"Netlify"),
    ("cdn",       "Azure CDN",      ["header:server", "header:x-ms-ref"],                   r"Microsoft|AzureCDN"),
    ("cdn",       "Google Cloud CDN",["header:via", "header:server"],                       r"Google Frontend|GFE"),
    ("cdn",       "KeyCDN",         ["header:server"],                                       r"KeyCDN"),
    ("cdn",       "StackPath",      ["header:x-hw"],                                         r"x-hw"),
    ("cdn",       "Sucuri",         ["header:server", "header:x-sucuri-id"],                r"Sucuri"),
    # WAF
    ("waf",       "Akamai Kona",    ["header:server"],                                       r"AkamaiGHost|Kona"),
    ("waf",       "Barracuda",      ["header:server"],                                       r"Barracuda"),
    ("waf",       "DenyAll",        ["header:server"],                                       r"DenyAll"),
    ("waf",       "Fortinet",       ["header:server"],                                       r"FortiWeb|Fortinet"),
    ("waf",       "Wallarm",        ["header:server"],                                       r"wallarm"),
    ("waf",       "Wordfence",      ["body"],                                                r"wordfence|wfCentralVer"),
    # Containers / PaaS
    ("platform",  "Docker",         ["header:server", "body"],                               r"Docker|docker-compose"),
    ("platform",  "Kubernetes",     ["body"],                                                r"kubernetes|kube-"),
    ("platform",  "Heroku",         ["header:via"],                                          r"vegur"),
    ("platform",  "AWS ELB",        ["header:server"],                                       r"awselb|ELB"),
    ("platform",  "Azure App Service",["header:server"],                                     r"Microsoft-IIS|azure"),
    # Analytics / Tracking
    ("analytics", "Google Analytics",["body"],                                               r"google-analytics\.com|gtag|UA-\d+"),
    ("analytics", "Google Tag Manager",["body"],                                             r"googletagmanager\.com|GTM-"),
    ("analytics", "Facebook Pixel", ["body"],                                                r"connect\.facebook\.net|fbq\s*\("),
    ("analytics", "Hotjar",         ["body"],                                                r"hotjar\.com|_hjSettings"),
    # Additional security headers
    ("security",  "X-Frame-Options",["header:x-frame-options"],                              r".+"),
    ("security",  "X-Content-Type-Options",["header:x-content-type-options"],                r"nosniff"),
    ("security",  "Referrer-Policy",["header:referrer-policy"],                              r".+"),
    ("security",  "Permissions-Policy",["header:permissions-policy"],                        r".+"),
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
    for cat in ["server", "language", "framework", "database", "cdn", "waf", "platform", "auth", "analytics"]:
        items = fp.get(cat, [])
        if items:
            parts.append(f"{cat.title()}: {', '.join(items)}")
    return " | ".join(parts) if parts else "Unknown stack"
