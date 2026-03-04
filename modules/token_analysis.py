"""
Session Token Randomness Analyzer — entropy and pattern detection.

Collects multiple session tokens from the target, then runs:
  1. Shannon entropy (bits per character)
  2. Character frequency chi-square uniformity test
  3. Sequential pattern detection (increments, common prefixes, Hamming)
  4. Character-set analysis (hex-only, numeric-only, base64)

Flags weak tokens as findings with severity based on entropy thresholds:
  - < 3.0 bpc → High (predictable)
  - 3.0–4.0 bpc → Medium (low randomness)
  - Chi-square p < 0.01 → Medium (non-uniform distribution)
  - Sequential patterns → High (incrementing or predictable)

Usage (headless):
    Automatically runs as part of the scan pipeline.
    Opt out with: --no-token-analysis
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

import requests


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

_DEFAULT_SAMPLE_COUNT = 40
_MAX_SAMPLE_COUNT = 50
_REQUEST_DELAY = 0.05  # 50ms between requests — no flooding
_MIN_TOKEN_LENGTH = 8  # Ignore very short cookies (flags, booleans)

# Cookie names likely to be session tokens
_SESSION_COOKIE_NAMES = re.compile(
    r"(sess|session|sid|token|auth|jwt|jsessionid|phpsessid|asp\.net_sessionid|"
    r"connect\.sid|_session|csrftoken|xsrf|laravel_session|ci_session|"
    r"wordpress_logged_in|wp_|rack\.session)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTROPY & STATISTICS — pure Python, no scipy/numpy
# ═══════════════════════════════════════════════════════════════════════════════

def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not token:
        return 0.0
    length = len(token)
    freq = Counter(token)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def chi_square_uniformity(token: str) -> tuple[float, float]:
    """
    Chi-square test of character frequency uniformity.
    Returns (chi2_statistic, p_value_approximation).

    Uses the chi-square CDF approximation via the regularized incomplete
    gamma function (Wilson-Hilferty normal approximation for large df).
    """
    if not token or len(token) < 2:
        return 0.0, 1.0

    freq = Counter(token)
    n = len(token)
    k = len(freq)  # number of unique chars
    if k <= 1:
        return 0.0, 1.0

    expected = n / k
    chi2 = sum((count - expected) ** 2 / expected for count in freq.values())
    df = k - 1

    # Wilson-Hilferty approximation for chi-square CDF
    # P(X <= chi2) ≈ Φ(z) where z = ((chi2/df)^(1/3) - 1 + 2/(9*df)) / sqrt(2/(9*df))
    if df > 0:
        ratio = chi2 / df
        term = 2.0 / (9.0 * df)
        z = (ratio ** (1.0 / 3.0) - 1.0 + term) / math.sqrt(term)
        # Normal CDF approximation
        p_value = 1.0 - _normal_cdf(z)
    else:
        p_value = 1.0

    return chi2, max(0.0, min(1.0, p_value))


def _normal_cdf(z: float) -> float:
    """Approximate standard normal CDF using error function approximation."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def hamming_distance(a: str, b: str) -> int:
    """Hamming distance between two strings (padded to same length)."""
    max_len = max(len(a), len(b))
    a = a.ljust(max_len)
    b = b.ljust(max_len)
    return sum(c1 != c2 for c1, c2 in zip(a, b))


def common_prefix_length(a: str, b: str) -> int:
    """Length of common prefix between two strings."""
    i = 0
    for c1, c2 in zip(a, b):
        if c1 != c2:
            break
        i += 1
    return i


def detect_charset(token: str) -> str:
    """Classify the character set used by the token."""
    if re.fullmatch(r"[0-9]+", token):
        return "numeric-only"
    if re.fullmatch(r"[0-9a-f]+", token, re.IGNORECASE):
        return "hex"
    if re.fullmatch(r"[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+", token):
        return "jwt"
    if re.fullmatch(r"[0-9a-zA-Z]+", token):
        return "alphanumeric"
    if re.fullmatch(r"[0-9a-zA-Z+/=]+", token) and re.search(r"[+/=]", token):
        return "base64"
    return "mixed"


# ═══════════════════════════════════════════════════════════════════════════════
# SEQUENTIAL PATTERN DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_sequential_patterns(tokens: list[str]) -> list[dict]:
    """Analyze consecutive tokens for predictable patterns."""
    findings = []
    if len(tokens) < 3:
        return findings

    # 1. Common prefix analysis
    prefix_lens = []
    for i in range(len(tokens) - 1):
        prefix_lens.append(common_prefix_length(tokens[i], tokens[i + 1]))
    avg_prefix = sum(prefix_lens) / len(prefix_lens)
    avg_token_len = sum(len(t) for t in tokens) / len(tokens)
    prefix_ratio = avg_prefix / avg_token_len if avg_token_len > 0 else 0

    if prefix_ratio > 0.7:
        findings.append({
            "type": "high_common_prefix",
            "detail": f"Average {avg_prefix:.1f}/{avg_token_len:.0f} chars shared between consecutive tokens ({prefix_ratio:.0%})",
            "severity": "High",
        })

    # 2. Hamming distance analysis (low distance = similar tokens)
    hamming_dists = []
    for i in range(len(tokens) - 1):
        hamming_dists.append(hamming_distance(tokens[i], tokens[i + 1]))
    avg_hamming = sum(hamming_dists) / len(hamming_dists)
    hamming_ratio = avg_hamming / avg_token_len if avg_token_len > 0 else 0

    if hamming_ratio < 0.15 and avg_token_len > 10:
        findings.append({
            "type": "low_hamming_distance",
            "detail": f"Average Hamming distance {avg_hamming:.1f}/{avg_token_len:.0f} ({hamming_ratio:.0%}) — tokens barely differ",
            "severity": "High",
        })

    # 3. Numeric increment detection
    numeric_parts = []
    for t in tokens:
        nums = re.findall(r"\d+", t)
        if nums:
            # Take the longest numeric portion
            numeric_parts.append(int(max(nums, key=len)))

    if len(numeric_parts) >= 3:
        diffs = [numeric_parts[i + 1] - numeric_parts[i]
                 for i in range(len(numeric_parts) - 1)]
        # Check if differences are constant (linear increment)
        if len(set(diffs)) == 1 and diffs[0] != 0:
            findings.append({
                "type": "linear_increment",
                "detail": f"Tokens contain linearly incrementing numbers (step={diffs[0]})",
                "severity": "High",
            })
        # Check if differences are all small (< 10)
        elif all(0 < abs(d) < 10 for d in diffs):
            findings.append({
                "type": "near_sequential",
                "detail": f"Numeric portions increment by small steps (avg={sum(abs(d) for d in diffs)/len(diffs):.1f})",
                "severity": "Medium",
            })

    # 4. Token length variance (truly random tokens should have consistent length)
    lengths = [len(t) for t in tokens]
    if len(set(lengths)) == 1:
        pass  # Consistent length is normal — no finding
    elif max(lengths) - min(lengths) > 10:
        findings.append({
            "type": "variable_length",
            "detail": f"Token lengths vary wildly: {min(lengths)}-{max(lengths)} chars",
            "severity": "Info",
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def collect_tokens(
    url: str,
    session: requests.Session,
    count: int = _DEFAULT_SAMPLE_COUNT,
    timeout: int = 10,
) -> dict[str, list[str]]:
    """
    Request a URL multiple times, collect session cookie values.
    Returns: {cookie_name: [value1, value2, ...]}
    """
    count = min(count, _MAX_SAMPLE_COUNT)
    cookie_samples: dict[str, list[str]] = {}

    for i in range(count):
        try:
            # Use a clean jar each request to get fresh tokens
            jar = requests.cookies.RequestsCookieJar()
            resp = session.get(url, timeout=timeout, cookies=jar,
                               allow_redirects=True)
            # Collect from Set-Cookie headers
            for cookie in resp.cookies:
                name = cookie.name
                val = cookie.value or ""
                if len(val) < _MIN_TOKEN_LENGTH:
                    continue
                if _SESSION_COOKIE_NAMES.search(name):
                    cookie_samples.setdefault(name, []).append(val)
        except Exception:
            pass
        if i < count - 1:
            time.sleep(_REQUEST_DELAY)

    return cookie_samples


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_tokens(
    url: str,
    session: requests.Session,
    sample_count: int = _DEFAULT_SAMPLE_COUNT,
    timeout: int = 10,
    callback: Optional[callable] = None,
) -> list[dict]:
    """
    Full session token analysis pipeline.
    Returns list of finding dicts ready for merge into scan findings.
    """
    findings: list[dict] = []

    # Collect tokens
    token_sets = collect_tokens(url, session, count=sample_count, timeout=timeout)

    if not token_sets:
        return findings  # No session cookies found — nothing to analyze

    for cookie_name, tokens in token_sets.items():
        unique_tokens = list(dict.fromkeys(tokens))  # Dedupe preserving order

        if len(unique_tokens) < 3:
            # Not enough unique tokens to analyze
            if len(unique_tokens) == 1 and len(tokens) > 5:
                # Same token every time — static session ID
                finding = {
                    "url": url,
                    "vuln_type": "weak_session_token",
                    "severity": "High",
                    "category": "A07:2025 Identification and Authentication Failures",
                    "cwe": "CWE-330",
                    "finding": f"Static session token: cookie '{cookie_name}' returns same value across {len(tokens)} requests",
                    "evidence": f"Token (truncated): {unique_tokens[0][:40]}...",
                    "remediation": "Generate cryptographically random session tokens per session using a CSPRNG",
                    "phase": "token_analysis",
                }
                findings.append(finding)
                if callback:
                    callback(finding)
            continue

        # ── Shannon entropy ──────────────────────────────────────────────
        entropies = [shannon_entropy(t) for t in unique_tokens]
        avg_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)
        charset = detect_charset(unique_tokens[0])

        if avg_entropy < 3.0:
            finding = {
                "url": url,
                "vuln_type": "weak_session_token",
                "severity": "High",
                "category": "A07:2025 Identification and Authentication Failures",
                "cwe": "CWE-331",
                "finding": f"Low entropy session token: cookie '{cookie_name}' averages {avg_entropy:.2f} bits/char (min {min_entropy:.2f})",
                "evidence": f"Charset: {charset}, {len(unique_tokens)} unique tokens from {len(tokens)} samples. Example: {unique_tokens[0][:40]}",
                "remediation": "Use a CSPRNG (e.g. secrets.token_hex) with at least 128 bits of entropy for session tokens",
                "phase": "token_analysis",
            }
            findings.append(finding)
            if callback:
                callback(finding)
        elif avg_entropy < 4.0:
            finding = {
                "url": url,
                "vuln_type": "weak_session_token",
                "severity": "Medium",
                "category": "A07:2025 Identification and Authentication Failures",
                "cwe": "CWE-331",
                "finding": f"Moderate entropy session token: cookie '{cookie_name}' averages {avg_entropy:.2f} bits/char",
                "evidence": f"Charset: {charset}, {len(unique_tokens)} unique tokens. Min entropy: {min_entropy:.2f} bpc",
                "remediation": "Increase token randomness — use secrets.token_hex(32) or equivalent CSPRNG",
                "phase": "token_analysis",
            }
            findings.append(finding)
            if callback:
                callback(finding)

        # ── Chi-square uniformity ────────────────────────────────────────
        # Concatenate all tokens for aggregate character distribution
        combined = "".join(unique_tokens)
        chi2, p_value = chi_square_uniformity(combined)

        if p_value < 0.01:
            finding = {
                "url": url,
                "vuln_type": "weak_session_token",
                "severity": "Medium",
                "category": "A07:2025 Identification and Authentication Failures",
                "cwe": "CWE-330",
                "finding": f"Non-uniform character distribution in cookie '{cookie_name}' (chi2={chi2:.1f}, p={p_value:.4f})",
                "evidence": f"Character frequency is statistically non-random (p < 0.01). Charset: {charset}",
                "remediation": "Use a CSPRNG that produces uniformly distributed output bytes",
                "phase": "token_analysis",
            }
            findings.append(finding)
            if callback:
                callback(finding)

        # ── Sequential pattern detection ─────────────────────────────────
        seq_patterns = detect_sequential_patterns(unique_tokens)
        for pat in seq_patterns:
            if pat["severity"] == "Info":
                continue  # Skip informational for now
            finding = {
                "url": url,
                "vuln_type": "predictable_session_token",
                "severity": pat["severity"],
                "category": "A07:2025 Identification and Authentication Failures",
                "cwe": "CWE-340",
                "finding": f"Predictable session token pattern in cookie '{cookie_name}': {pat['type']}",
                "evidence": pat["detail"],
                "remediation": "Session tokens must be generated using cryptographically secure random number generators, not sequential or predictable algorithms",
                "phase": "token_analysis",
            }
            findings.append(finding)
            if callback:
                callback(finding)

        # ── Short token warning ──────────────────────────────────────────
        avg_len = sum(len(t) for t in unique_tokens) / len(unique_tokens)
        if avg_len < 16:
            finding = {
                "url": url,
                "vuln_type": "weak_session_token",
                "severity": "Medium",
                "category": "A07:2025 Identification and Authentication Failures",
                "cwe": "CWE-334",
                "finding": f"Short session token: cookie '{cookie_name}' averages {avg_len:.0f} chars (recommend >= 32)",
                "evidence": f"{len(unique_tokens)} unique tokens sampled. Example: {unique_tokens[0][:40]}",
                "remediation": "Use session tokens of at least 128 bits (32 hex chars) to prevent brute-force guessing",
                "phase": "token_analysis",
            }
            findings.append(finding)
            if callback:
                callback(finding)

    return findings
