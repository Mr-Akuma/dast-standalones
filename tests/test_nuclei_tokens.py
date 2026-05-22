"""
Tests for modules/nuclei_tokens.py — run_checks() token detection.

Each test verifies that a specific service's token pattern is detected,
masked correctly in evidence, and produces a well-formed finding dict.
"""
import pytest

from modules.nuclei_tokens import run_checks, _NUCLEI_TOKEN_PATTERNS


# ── Fixtures ──────────────────────────────────────────────────────────────────

TARGET_URL = "https://example.com/api/config"

REQUIRED_KEYS = {"url", "category", "finding", "severity", "evidence",
                 "remediation", "cwe"}


def _check(body: str) -> list[dict]:
    """Convenience wrapper: call run_checks with just a body string."""
    return run_checks(url=TARGET_URL, body=body, headers={}, cookies={})


# ── Pattern count ─────────────────────────────────────────────────────────────

@pytest.mark.nuclei_tokens
def test_pattern_count_is_at_least_41():
    """_NUCLEI_TOKEN_PATTERNS includes the base set plus industry extensions."""
    assert len(_NUCLEI_TOKEN_PATTERNS) >= 41


# ── Finding dict shape ─────────────────────────────────────────────────────────

@pytest.mark.nuclei_tokens
def test_finding_has_required_keys():
    """Every finding dict must contain all required keys."""
    token = "hvs." + "a" * 95  # HashiCorp Vault service token
    results = _check(token)
    assert results, "Expected at least one finding"
    assert REQUIRED_KEYS.issubset(results[0].keys())


@pytest.mark.nuclei_tokens
def test_finding_category_is_nuclei_token_disclosure():
    """All findings carry category='nuclei_token_disclosure'."""
    token = "hvs." + "a" * 95
    results = _check(token)
    assert all(r["category"] == "nuclei_token_disclosure" for r in results)


@pytest.mark.nuclei_tokens
def test_evidence_is_masked():
    """Evidence must not expose the full token value — masked with '...'."""
    token = "hvs." + "a" * 95
    results = _check(token)
    assert results
    evidence = results[0]["evidence"]
    assert "..." in evidence
    # Must not contain the full token
    assert token not in evidence


@pytest.mark.nuclei_tokens
def test_no_match_returns_empty_list():
    """Body with no credential patterns → empty list returned."""
    results = _check("This is a perfectly harmless response body.")
    assert results == []


# ── Per-service pattern tests ─────────────────────────────────────────────────

@pytest.mark.nuclei_tokens
def test_hashicorp_vault_hvs_detected():
    """HashiCorp Vault service token (hvs.) detected."""
    token = "hvs." + "a" * 95
    results = _check(f"config: {token}")
    assert any("HashiCorp Vault service" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_hashicorp_vault_hvb_detected():
    """HashiCorp Vault batch token (hvb.) detected."""
    token = "hvb." + "b" * 150
    results = _check(f"batch_token={token}")
    assert any("HashiCorp Vault batch" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_aws_akia_access_key_detected():
    """AWS IAM Access Key (AKIA...) detected."""
    token = "AKIA" + "A" * 16
    results = _check(f"aws_access_key_id={token}")
    assert any("AWS" in r["finding"] and "AKIA" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_aws_asia_temporary_key_detected():
    """AWS STS Temporary Key (ASIA...) detected."""
    token = "ASIA" + "A" * 16
    results = _check(f"aws_access_key_id={token}")
    assert any("ASIA" in r["finding"] or "STS" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_slack_bot_token_xoxb_detected():
    """Slack Bot Token (xoxb-) detected."""
    token = "xoxb-" + "1234567890-" * 5
    results = _check(f"slack_token={token}")
    assert any("Slack Bot Token" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_slack_user_token_xoxp_detected():
    """Slack User Token (xoxp-) detected."""
    token = "xoxp-" + "A" * 70
    results = _check(f"slack_user_token={token}")
    assert any("Slack User Token" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_twilio_api_key_sk_detected():
    """Twilio API Key (SK...) detected."""
    token = "SK" + "a" * 32
    results = _check(f"twilio_key={token}")
    assert any("Twilio" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_shopify_access_token_shpat_detected():
    """Shopify Access Token (shpat_) detected."""
    token = "shpat_" + "f" * 32
    results = _check(f"shopify_token={token}")
    assert any("Shopify Access Token" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_shopify_shared_secret_shpss_detected():
    """Shopify Shared Secret (shpss_) detected."""
    token = "shpss_" + "a" * 32
    results = _check(f"shopify_secret={token}")
    assert any("Shopify Shared Secret" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_stripe_restricted_live_key_detected():
    """Stripe Restricted Live Key (rk_live_) detected."""
    token = "rk_live_" + "A" * 24
    results = _check(f"stripe_key={token}")
    assert any("Stripe" in r["finding"] and "rk_live_" in r["finding"] for r in results)


@pytest.mark.nuclei_tokens
def test_url_field_set_correctly():
    """Finding url field matches the URL passed to run_checks."""
    token = "hvs." + "a" * 95
    results = run_checks(url="https://target.example.com/cfg", body=token,
                         headers={}, cookies={})
    assert results
    assert results[0]["url"] == "https://target.example.com/cfg"


@pytest.mark.nuclei_tokens
def test_scan_area_limited_to_32kb():
    """Tokens beyond 32 000 chars from start are not scanned (performance limit)."""
    padding = "X" * 33000
    token = "hvs." + "a" * 95
    results = _check(padding + token)
    # The token is at position 33000, beyond the 32000-char scan limit
    assert results == []
