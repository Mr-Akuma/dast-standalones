"""
Business Logic Vulnerability Tester — detects workflow bypass, price manipulation,
coupon stacking, negative quantity attacks, and state machine violations.

These tests require knowledge of application workflows (multi-step processes)
and are typically configured via scan config or discovered through crawling.
"""
from __future__ import annotations

import json
import logging
import re
import time
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, urlencode

import requests
import urllib3
urllib3.disable_warnings()

log = logging.getLogger("biz_logic")

_CRITICAL_FLOW_PATTERNS: dict[str, list[str]] = {
    "checkout":        ["checkout", "cart/complete", "order/confirm", "place-order", "complete-order"],
    "payment":         ["payment", "/pay", "/charge", "/billing", "purchase"],
    "password_reset":  ["password-reset", "forgot-password", "reset-password", "recover-password"],
    "account_delete":  ["account/delete", "user/delete", "close-account", "deactivate"],
    "transfer":        ["transfer", "send-money", "wire", "remittance"],
    "mfa_bypass":      ["2fa", "mfa", "otp", "totp", "authenticator"],
}


@dataclass
class WorkflowStep:
    """A single step in a multi-step workflow."""
    name: str
    url: str
    method: str = "POST"
    data: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    expected_status: int = 200
    # Regex pattern that must match in response for step to be "complete"
    success_pattern: str = ""
    # Fields to extract from response for next step (jsonpath-like)
    extract: dict = field(default_factory=dict)  # {var_name: json_key}


@dataclass
class BizLogicFinding:
    """A business logic vulnerability finding."""
    url: str
    vuln_type: str
    severity: str
    finding: str
    evidence: str = ""
    category: str = "Business Logic"
    phase: str = "biz_logic"


class BusinessLogicTester:
    """
    Tests for business logic vulnerabilities:

    1. Workflow bypass — skip steps in multi-step processes
    2. Price manipulation — negative quantities, zero prices, float overflow
    3. Coupon stacking — apply same discount multiple times
    4. Race conditions on state — cancel-after-use, double-spend
    5. Parameter tampering on price/quantity/discount fields
    """

    # ── Price/quantity field name patterns ────────────────────────────────────
    PRICE_FIELDS = re.compile(
        r'(?:^|_)(price|cost|amount|total|subtotal|fee|charge|rate|value|balance)(?:_|$)',
        re.I,
    )
    QUANTITY_FIELDS = re.compile(
        r'(?:^|_)(qty|quantity|count|num|number|amount|units|items)(?:_|$)',
        re.I,
    )
    DISCOUNT_FIELDS = re.compile(
        r'(?:^|_)(discount|coupon|promo|voucher|code|gift|credit|rebate|offer)(?:_|$)',
        re.I,
    )
    CURRENCY_PATTERN = re.compile(r'[\$€£¥]\s*[\d,.]+|\d+\.\d{2}')
    # Signals that a coupon was genuinely accepted/applied (not just 200 OK)
    _COUPON_ACCEPTED = re.compile(
        r'"(?:discount|savings|amount_off|coupon_applied|promo_applied|code_applied'
        r'|discount_amount|coupon_id|promo_id|voucher_id)"\s*:\s*(?!""|null|0\b)'
        r'|"(?:success|applied|valid)"\s*:\s*true'
        r'|coupon\s+(?:applied|accepted|valid|active)',
        re.I,
    )

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 15,
        rate_limit: float = 0.3,
    ):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault(
            "User-Agent", "Mozilla/5.0 (compatible; DAST-BizLogic/1.0)"
        )
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.findings: list[BizLogicFinding] = []

    # ═══════════════════════════════════════════════════════════════════════════
    # 1. WORKFLOW BYPASS — skip steps in multi-step processes
    # ═══════════════════════════════════════════════════════════════════════════

    def test_workflow_bypass(
        self,
        steps: list[WorkflowStep],
        callback=None,
    ) -> list[BizLogicFinding]:
        """
        Test if intermediate steps in a workflow can be skipped.

        Strategy:
        - Execute full workflow to establish baseline
        - Then try jumping directly to step N without completing steps 1..N-1
        - Also try completing step 1, then jumping to step N (skipping middle)
        """
        if len(steps) < 2:
            return []

        findings = []

        # ── Phase 1: Execute full workflow to get baseline + extract tokens ───
        log.info(f"[BizLogic] Executing full workflow ({len(steps)} steps)...")
        extracted = {}
        full_success = True

        for i, step in enumerate(steps):
            time.sleep(self.rate_limit)
            resp = self._execute_step(step, extracted)
            if not resp:
                full_success = False
                break

            # Extract values for next steps
            if step.extract and resp.text:
                try:
                    body = json.loads(resp.text)
                    for var_name, json_key in step.extract.items():
                        val = self._extract_json_value(body, json_key)
                        if val:
                            extracted[var_name] = val
                except (json.JSONDecodeError, TypeError):
                    pass

            # Verify step success
            if step.success_pattern:
                if not re.search(step.success_pattern, resp.text or "", re.I):
                    full_success = False
                    break

        if not full_success:
            log.warning("[BizLogic] Full workflow did not complete — skipping bypass tests")
            return findings

        # ── Phase 2: Try skipping to final step directly ─────────────────────
        log.info("[BizLogic] Testing direct jump to final step...")
        time.sleep(self.rate_limit)
        final_step = steps[-1]
        resp = self._execute_step(final_step, {})  # No extracted tokens

        if resp and resp.status_code == final_step.expected_status:
            if final_step.success_pattern:
                if re.search(final_step.success_pattern, resp.text or "", re.I):
                    f = BizLogicFinding(
                        url=final_step.url,
                        vuln_type="workflow_bypass",
                        severity="high",
                        finding=(
                            f"Workflow bypass — final step '{final_step.name}' succeeds "
                            f"without completing prior steps"
                        ),
                        evidence=f"Status: {resp.status_code}, Body sample: {resp.text[:200]}",
                    )
                    findings.append(f)
                    self.findings.append(f)
                    if callback:
                        callback(f)
            elif resp.status_code == 200:
                f = BizLogicFinding(
                    url=final_step.url,
                    vuln_type="workflow_bypass",
                    severity="medium",
                    finding=(
                        f"Possible workflow bypass — final step '{final_step.name}' "
                        f"returns HTTP 200 without prior steps (no success pattern to confirm)"
                    ),
                    evidence=f"Status: {resp.status_code}",
                )
                findings.append(f)
                self.findings.append(f)
                if callback:
                    callback(f)

        # ── Phase 3: Skip middle steps (do step 1, then jump to final) ───────
        if len(steps) > 2:
            log.info("[BizLogic] Testing skip-middle bypass...")
            time.sleep(self.rate_limit)
            # Execute first step
            first_extracted = {}
            resp1 = self._execute_step(steps[0], first_extracted)
            if resp1 and steps[0].extract:
                try:
                    body = json.loads(resp1.text)
                    for var_name, json_key in steps[0].extract.items():
                        val = self._extract_json_value(body, json_key)
                        if val:
                            first_extracted[var_name] = val
                except (json.JSONDecodeError, TypeError):
                    pass

            # Jump to final step with only step-1 tokens
            time.sleep(self.rate_limit)
            resp_skip = self._execute_step(final_step, first_extracted)
            if resp_skip and resp_skip.status_code == final_step.expected_status:
                skip_count = len(steps) - 2
                f = BizLogicFinding(
                    url=final_step.url,
                    vuln_type="workflow_bypass",
                    severity="high",
                    finding=(
                        f"Workflow bypass — skipped {skip_count} middle step(s), "
                        f"jumped from '{steps[0].name}' to '{final_step.name}'"
                    ),
                    evidence=f"Status: {resp_skip.status_code}",
                )
                findings.append(f)
                self.findings.append(f)
                if callback:
                    callback(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # 2. PRICE MANIPULATION — negative qty, zero price, overflow
    # ═══════════════════════════════════════════════════════════════════════════

    def test_price_manipulation(
        self,
        url: str,
        method: str = "POST",
        original_data: dict | None = None,
        content_type: str = "application/json",
        callback=None,
    ) -> list[BizLogicFinding]:
        """
        Test for price/quantity manipulation vulnerabilities.

        Attacks:
        - Negative quantities (-1, -100)
        - Zero price / zero total
        - Extremely large quantities (overflow)
        - Fractional quantities (0.001)
        - Price field tampering (set price to 0 or 0.01)
        - Discount > 100%
        - Negative discount (credit)
        """
        if not original_data:
            original_data = {}

        findings = []

        # Identify manipulable fields
        price_fields = [k for k in original_data if self.PRICE_FIELDS.search(k)]
        qty_fields = [k for k in original_data if self.QUANTITY_FIELDS.search(k)]
        discount_fields = [k for k in original_data if self.DISCOUNT_FIELDS.search(k)]

        # ── Negative quantity attacks ────────────────────────────────────────
        for field_name in qty_fields:
            for test_val in [-1, -100, -999999]:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = test_val
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Negative quantity ({test_val}) accepted in '{field_name}'",
                    "price_manipulation", "high",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)
                    break  # One finding per field

        # ── Zero price attacks ───────────────────────────────────────────────
        for field_name in price_fields:
            for test_val in [0, 0.01, 0.001]:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = test_val
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Zero/near-zero price ({test_val}) accepted in '{field_name}'",
                    "price_manipulation", "high",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)
                    break

        # ── Integer overflow attacks ─────────────────────────────────────────
        for field_name in qty_fields:
            for test_val in [2147483647, 99999999999, 1e308]:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = test_val
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Integer overflow quantity ({test_val}) in '{field_name}'",
                    "price_manipulation", "medium",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)
                    break

        # ── Fractional quantity attacks ──────────────────────────────────────
        for field_name in qty_fields:
            original_val = original_data.get(field_name)
            if isinstance(original_val, (int, float)) and original_val > 0:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = 0.001
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Fractional quantity (0.001) accepted in '{field_name}'",
                    "price_manipulation", "medium",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)

        # ── Discount > 100% ─────────────────────────────────────────────────
        for field_name in discount_fields:
            for test_val in [101, 200, 999, -50]:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = test_val
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Invalid discount ({test_val}%) accepted in '{field_name}'",
                    "price_manipulation", "high",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)
                    break

        # ── Currency/type confusion ──────────────────────────────────────────
        for field_name in price_fields:
            for test_val in ["0", "-1", "NaN", "Infinity", "null", "undefined", "0x0"]:
                tampered = copy.deepcopy(original_data)
                tampered[field_name] = test_val
                finding = self._send_and_check_price(
                    url, method, tampered, content_type,
                    f"Type confusion value '{test_val}' accepted in price field '{field_name}'",
                    "price_manipulation", "medium",
                )
                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    if callback:
                        callback(finding)
                    break

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # 3. COUPON/PROMO CODE STACKING
    # ═══════════════════════════════════════════════════════════════════════════

    def test_coupon_stacking(
        self,
        url: str,
        method: str = "POST",
        coupon_field: str = "coupon_code",
        coupon_value: str = "TEST10",
        original_data: dict | None = None,
        content_type: str = "application/json",
        callback=None,
    ) -> list[BizLogicFinding]:
        """
        Test if coupon/promo codes can be applied multiple times.

        Attacks:
        - Apply same code twice
        - Apply code with different casing
        - Apply code with whitespace padding
        - Apply multiple codes in array
        """
        if not original_data:
            original_data = {}

        findings = []

        # ── Apply same coupon twice ──────────────────────────────────────────
        # First application (should succeed)
        data1 = copy.deepcopy(original_data)
        data1[coupon_field] = coupon_value
        time.sleep(self.rate_limit)
        resp1 = self._send_request(url, method, data1, content_type)

        if resp1 and resp1.status_code == 200:
            # Second application (should fail if properly protected)
            time.sleep(self.rate_limit)
            resp2 = self._send_request(url, method, data1, content_type)

            if resp2 and resp2.status_code == 200:
                # Check if discount was applied again
                # Compare response bodies for evidence of double-discount
                if self._responses_differ_meaningfully(resp1.text, resp2.text):
                    f = BizLogicFinding(
                        url=url,
                        vuln_type="coupon_stacking",
                        severity="high",
                        finding=(
                            f"Coupon stacking — code '{coupon_value}' accepted "
                            f"on consecutive requests with different responses"
                        ),
                        evidence=f"Resp1 len: {len(resp1.text)}, Resp2 len: {len(resp2.text)}",
                    )
                    findings.append(f)
                    self.findings.append(f)
                    if callback:
                        callback(f)

        # ── Case variation of coupon code ────────────────────────────────────
        variants = [
            coupon_value.lower(),
            coupon_value.upper(),
            " " + coupon_value,
            coupon_value + " ",
            coupon_value + "\t",
        ]
        for variant in variants:
            if variant == coupon_value:
                continue
            data_v = copy.deepcopy(original_data)
            data_v[coupon_field] = variant
            time.sleep(self.rate_limit)
            resp_v = self._send_request(url, method, data_v, content_type)
            if resp_v and resp_v.status_code == 200:
                body_v = resp_v.text[:2000]
                if self._REJECTION_SIGNALS.search(body_v):
                    continue  # server rejected despite 200
                if not self._COUPON_ACCEPTED.search(body_v):
                    continue  # no confirmation signal — likely echoed input
                f = BizLogicFinding(
                    url=url,
                    vuln_type="coupon_bypass",
                    severity="medium",
                    finding=(
                        f"Coupon bypass — variant '{variant.strip()}' accepted "
                        f"(case/whitespace manipulation)"
                    ),
                    evidence=f"Status: {resp_v.status_code} | Body: {body_v[:150]}",
                )
                findings.append(f)
                self.findings.append(f)
                if callback:
                    callback(f)
                break

        # ── Array injection (multiple codes) ─────────────────────────────────
        data_arr = copy.deepcopy(original_data)
        data_arr[coupon_field] = [coupon_value, coupon_value, coupon_value]
        time.sleep(self.rate_limit)
        resp_arr = self._send_request(url, method, data_arr, content_type)
        if resp_arr and resp_arr.status_code == 200:
            body_arr = resp_arr.text[:2000]
            if not self._REJECTION_SIGNALS.search(body_arr) and self._COUPON_ACCEPTED.search(body_arr):
                f = BizLogicFinding(
                    url=url,
                    vuln_type="coupon_stacking",
                    severity="medium",
                    finding=(
                        f"Coupon array injection — array of codes accepted in '{coupon_field}'"
                    ),
                    evidence=f"Sent array of 3 codes, Status: {resp_arr.status_code} | Body: {body_arr[:150]}",
                )
                findings.append(f)
                self.findings.append(f)
                if callback:
                    callback(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # 4. PARAMETER DISCOVERY — auto-detect price/qty/discount fields
    # ═══════════════════════════════════════════════════════════════════════════

    def discover_manipulable_fields(
        self,
        url: str,
        method: str = "POST",
        sample_data: dict | None = None,
        content_type: str = "application/json",
    ) -> dict[str, list[str]]:
        """
        Analyze a request's fields to find price, quantity, and discount parameters.
        Returns: {"price": [...], "quantity": [...], "discount": [...]}
        """
        if not sample_data:
            return {"price": [], "quantity": [], "discount": []}

        result = {"price": [], "quantity": [], "discount": []}

        for key in sample_data:
            if self.PRICE_FIELDS.search(key):
                result["price"].append(key)
            elif self.QUANTITY_FIELDS.search(key):
                result["quantity"].append(key)
            elif self.DISCOUNT_FIELDS.search(key):
                result["discount"].append(key)

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # 5. AUTO-SCAN — discover and test e-commerce patterns
    # ═══════════════════════════════════════════════════════════════════════════

    def auto_scan_endpoint(
        self,
        url: str,
        method: str = "POST",
        sample_data: dict | None = None,
        content_type: str = "application/json",
        callback=None,
    ) -> list[BizLogicFinding]:
        """
        Automatically detect and test business logic vulnerabilities
        on a single endpoint based on field name analysis.
        """
        if not sample_data:
            return []

        findings = []

        # Discover fields
        fields = self.discover_manipulable_fields(url, method, sample_data, content_type)

        # Test price manipulation if price/qty/discount fields found
        if fields["price"] or fields["quantity"] or fields["discount"]:
            findings.extend(self.test_price_manipulation(
                url, method, sample_data, content_type, callback,
            ))

        # Test coupon stacking if discount fields found
        for disc_field in fields["discount"]:
            disc_val = sample_data.get(disc_field, "")
            if disc_val:
                findings.extend(self.test_coupon_stacking(
                    url, method, disc_field, str(disc_val),
                    sample_data, content_type, callback,
                ))

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # 6. STATE MACHINE CONFUSION — concurrent sessions with overlapping steps
    # ═══════════════════════════════════════════════════════════════════════════

    def test_state_confusion(
        self,
        steps: list[WorkflowStep],
        sessions: int = 2,
        callback=None,
    ) -> list[BizLogicFinding]:
        """
        Test for state machine confusion via concurrent overlapping workflow steps.

        Three attack probes:

        1. Concurrent race — N sessions all hit step-1 simultaneously, then all
           race to the final step.  A server using optimistic/shared state grants
           the final step to sessions that never truly completed step-1.

        2. State replay — one session completes step-1, then N concurrent sessions
           immediately hit the final step with the same extracted tokens before the
           server has committed the state transition.

        3. Out-of-order delivery — send steps in reverse order (N … 1) in a single
           session; a server with weak ordering validation may accept them.

        Each probe uses an independent requests.Session so cookie jars don't bleed
        across threads.
        """
        if len(steps) < 2:
            return []

        findings: list[BizLogicFinding] = []

        def _clone_session() -> requests.Session:
            s = requests.Session()
            s.verify = False
            s.headers.update(dict(self.session.headers))
            return s

        def _run_step(session: requests.Session, step: WorkflowStep, extracted: dict) -> requests.Response | None:
            """Execute one step on an independent session."""
            data = copy.deepcopy(step.data)
            for key, val in data.items():
                if isinstance(val, str) and val.startswith("{{") and val.endswith("}}"):
                    var_name = val[2:-2].strip()
                    if var_name in extracted:
                        data[key] = extracted[var_name]

            headers = {**step.headers}
            headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; DAST-BizLogic/1.0)")
            try:
                if step.method.upper() in ("POST", "PUT", "PATCH"):
                    ct = headers.get("Content-Type", "application/json")
                    if "json" in ct:
                        return session.request(step.method, step.url, json=data,
                                               headers=headers, timeout=self.timeout,
                                               allow_redirects=True)
                    return session.request(step.method, step.url, data=data,
                                           headers=headers, timeout=self.timeout,
                                           allow_redirects=True)
                return session.request(step.method, step.url, params=data,
                                       headers=headers, timeout=self.timeout,
                                       allow_redirects=True)
            except Exception as e:
                log.warning(f"[BizLogic/StateConfusion] step '{step.name}' error: {e}")
                return None

        first_step = steps[0]
        final_step = steps[-1]

        # ── Probe 1: concurrent race to final step ────────────────────────────
        log.info(f"[BizLogic] State confusion probe 1: {sessions} concurrent sessions")

        def _race_session(_idx: int) -> tuple[int, requests.Response | None]:
            s = _clone_session()
            time.sleep(self.rate_limit)
            r1 = _run_step(s, first_step, {})
            if not r1:
                return _idx, None
            # Immediately race to final step without completing middle steps
            r_final = _run_step(s, final_step, {})
            return _idx, r_final

        with ThreadPoolExecutor(max_workers=sessions) as pool:
            futures = {pool.submit(_race_session, i): i for i in range(sessions)}
            successes = 0
            for fut in as_completed(futures):
                _, resp = fut.result()
                if resp and resp.status_code == final_step.expected_status:
                    if final_step.success_pattern:
                        if re.search(final_step.success_pattern, resp.text or "", re.I):
                            successes += 1
                    else:
                        successes += 1

        if successes > 0:
            f = BizLogicFinding(
                url=final_step.url,
                vuln_type="state_confusion",
                severity="high",
                finding=(
                    f"State machine confusion — {successes}/{sessions} concurrent sessions "
                    f"reached '{final_step.name}' after only completing '{first_step.name}', "
                    "skipping all intermediate steps under race conditions"
                ),
                evidence=(
                    f"Probe: {sessions} concurrent sessions each ran step-1 then immediately "
                    f"jumped to final step. {successes} succeeded."
                ),
            )
            findings.append(f)
            self.findings.append(f)
            if callback:
                callback(f)

        # ── Probe 2: state replay — N sessions reuse step-1 tokens concurrently ──
        log.info("[BizLogic] State confusion probe 2: state replay")

        # Establish step-1 tokens from a legitimate single run
        anchor_session = _clone_session()
        time.sleep(self.rate_limit)
        anchor_resp = _run_step(anchor_session, first_step, {})
        anchor_extracted: dict = {}
        if anchor_resp and first_step.extract:
            try:
                body = json.loads(anchor_resp.text)
                for var_name, json_key in first_step.extract.items():
                    val = self._extract_json_value(body, json_key)
                    if val:
                        anchor_extracted[var_name] = val
            except (json.JSONDecodeError, TypeError):
                pass

        if anchor_resp and anchor_resp.status_code == first_step.expected_status:
            def _replay_final(idx: int) -> tuple[int, requests.Response | None]:
                s = _clone_session()
                # No sleep — intentionally tight to hit same server state window
                return idx, _run_step(s, final_step, anchor_extracted)

            with ThreadPoolExecutor(max_workers=sessions) as pool:
                futures = {pool.submit(_replay_final, i): i for i in range(sessions)}
                replay_successes = 0
                for fut in as_completed(futures):
                    _, resp = fut.result()
                    if resp and resp.status_code == final_step.expected_status:
                        if final_step.success_pattern:
                            if re.search(final_step.success_pattern, resp.text or "", re.I):
                                replay_successes += 1
                        else:
                            replay_successes += 1

            if replay_successes > 1:
                # More than one session succeeded with the same step-1 tokens
                f = BizLogicFinding(
                    url=final_step.url,
                    vuln_type="state_confusion",
                    severity="high",
                    finding=(
                        f"State replay — {replay_successes}/{sessions} concurrent sessions "
                        f"accepted the same step-1 tokens to reach '{final_step.name}', "
                        "suggesting the server does not invalidate state after first use"
                    ),
                    evidence=(
                        f"One session ran step-1, extracted tokens, then {sessions} concurrent "
                        f"sessions immediately hit the final step with those tokens. "
                        f"{replay_successes} accepted."
                    ),
                )
                findings.append(f)
                self.findings.append(f)
                if callback:
                    callback(f)

        # ── Probe 3: out-of-order step delivery ──────────────────────────────
        log.info("[BizLogic] State confusion probe 3: out-of-order steps")

        oo_session = _clone_session()
        oo_extracted: dict = {}
        oo_accepted: list[str] = []

        for step in reversed(steps):
            time.sleep(self.rate_limit)
            resp = _run_step(oo_session, step, oo_extracted)
            if resp and resp.status_code == step.expected_status:
                oo_accepted.append(step.name)
                if step.extract and resp.text:
                    try:
                        body = json.loads(resp.text)
                        for var_name, json_key in step.extract.items():
                            val = self._extract_json_value(body, json_key)
                            if val:
                                oo_extracted[var_name] = val
                    except (json.JSONDecodeError, TypeError):
                        pass

        # If the final step (= first in reversed) was accepted out-of-order
        if oo_accepted and oo_accepted[0] == final_step.name:
            f = BizLogicFinding(
                url=final_step.url,
                vuln_type="state_confusion",
                severity="high",
                finding=(
                    f"Out-of-order step acceptance — '{final_step.name}' was accepted "
                    f"as the first request when steps were delivered in reverse order "
                    f"({' → '.join(s.name for s in reversed(steps))})"
                ),
                evidence=(
                    f"Steps delivered in reverse order. Accepted in this order: "
                    f"{', '.join(oo_accepted)}"
                ),
            )
            findings.append(f)
            self.findings.append(f)
            if callback:
                callback(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _execute_step(
        self,
        step: WorkflowStep,
        extracted: dict,
    ) -> requests.Response | None:
        """Execute a single workflow step, substituting extracted variables."""
        # Substitute extracted values into step data
        data = copy.deepcopy(step.data)
        for key, val in data.items():
            if isinstance(val, str) and val.startswith("{{") and val.endswith("}}"):
                var_name = val[2:-2].strip()
                if var_name in extracted:
                    data[key] = extracted[var_name]

        headers = {**step.headers}
        headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; DAST-BizLogic/1.0)")

        try:
            if step.method.upper() in ("POST", "PUT", "PATCH"):
                ct = headers.get("Content-Type", "application/json")
                if "json" in ct:
                    resp = self.session.request(
                        step.method, step.url,
                        json=data, headers=headers,
                        timeout=self.timeout, allow_redirects=True,
                    )
                else:
                    resp = self.session.request(
                        step.method, step.url,
                        data=data, headers=headers,
                        timeout=self.timeout, allow_redirects=True,
                    )
            else:
                resp = self.session.request(
                    step.method, step.url,
                    params=data, headers=headers,
                    timeout=self.timeout, allow_redirects=True,
                )
            return resp
        except Exception as e:
            log.warning(f"[BizLogic] Step '{step.name}' failed: {e}")
            return None

    def _send_request(
        self,
        url: str,
        method: str,
        data: dict,
        content_type: str,
    ) -> requests.Response | None:
        """Send a request with given data."""
        headers = {"User-Agent": "Mozilla/5.0 (compatible; DAST-BizLogic/1.0)"}
        try:
            if "json" in content_type:
                return self.session.request(
                    method, url, json=data, headers=headers,
                    timeout=self.timeout, allow_redirects=True,
                )
            else:
                return self.session.request(
                    method, url, data=data, headers=headers,
                    timeout=self.timeout, allow_redirects=True,
                )
        except Exception as e:
            log.warning(f"[BizLogic] Request failed: {e}")
            return None

    # Signals that confirm a transaction was genuinely accepted, not just echoed or errored
    _TRANSACTION_CONFIRMED = re.compile(
        r'"(?:order_id|orderId|transaction_id|transactionId|confirmation|confirmationNumber'
        r'|checkout_id|checkoutId|payment_id|paymentId|invoice_id|invoiceId)"'
        r'|"(?:status|state)"\s*:\s*"(?:confirmed|completed|accepted|processed|success|paid)"',
        re.I,
    )
    # Signals that indicate the server REJECTED the request despite returning 2xx
    _REJECTION_SIGNALS = re.compile(
        r'"(?:error|errors|message|msg|detail|description)"\s*:\s*"[^"]*'
        r'(?:invalid|not allowed|must be|cannot|negative|positive|greater|less|between|minimum|maximum|range)[^"]*"'
        r'|"(?:success|ok|status)"\s*:\s*(?:false|0|"false"|"error"|"fail")',
        re.I,
    )

    def _send_and_check_price(
        self,
        url: str,
        method: str,
        data: dict,
        content_type: str,
        description: str,
        vuln_type: str,
        severity: str,
    ) -> BizLogicFinding | None:
        """
        Send manipulated request and check if the server genuinely accepted it.

        Two-step validation:
        1. Send clean baseline — if it also returns 2xx, confirm the tampered response
           differs meaningfully and contains a transaction confirmation signal.
        2. Check tampered response for rejection signals (error messages) — if present,
           the server validated correctly and rejected the input.
        """
        time.sleep(self.rate_limit)

        # Baseline: send the original (unmodified) data first
        baseline_resp = self._send_request(url, method, self._clean_baseline(data), content_type)
        baseline_status = baseline_resp.status_code if baseline_resp else 0
        baseline_body   = baseline_resp.text if baseline_resp else ""

        time.sleep(self.rate_limit)
        resp = self._send_request(url, method, data, content_type)

        if not resp:
            return None

        # Must be 2xx
        if resp.status_code not in (200, 201, 202):
            return None

        body = resp.text

        # Reject if the response contains explicit validation rejection signals
        if self._REJECTION_SIGNALS.search(body[:2000]):
            return None

        # If baseline also returns 2xx, require a positive transaction confirmation
        # signal in the tampered response. A generic 200 echoing back input is not enough.
        if baseline_status in (200, 201, 202):
            if not self._TRANSACTION_CONFIRMED.search(body[:2000]):
                return None
            # Also require the response meaningfully differs from baseline
            # (same body = same generic handler, not price-specific acceptance)
            if not self._responses_differ_meaningfully(baseline_body, body):
                return None

        return BizLogicFinding(
            url=url,
            vuln_type=vuln_type,
            severity=severity,
            finding=description,
            evidence=(
                f"Status: {resp.status_code} | "
                f"Tampered: {json.dumps(data)[:150]} | "
                f"Response: {body[:200]}"
            ),
        )

    def _clean_baseline(self, data: dict) -> dict:
        """Return a copy of data with price/qty fields set to safe positive values for baseline."""
        import copy
        baseline = copy.deepcopy(data)
        for k in list(baseline.keys()):
            if self.PRICE_FIELDS.search(k):
                baseline[k] = 10
            elif self.QUANTITY_FIELDS.search(k):
                baseline[k] = 1
            elif self.DISCOUNT_FIELDS.search(k):
                baseline[k] = 10
        return baseline

    def _extract_json_value(self, obj: Any, key_path: str) -> Any:
        """Simple dot-notation JSON value extraction."""
        parts = key_path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            else:
                return None
        return current

    def _responses_differ_meaningfully(self, body1: str, body2: str) -> bool:
        """Check if two response bodies differ meaningfully (not just timestamps)."""
        if not body1 or not body2:
            return False
        # Strip timestamps and random tokens
        strip_re = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|"[a-f0-9]{32,}"')
        b1 = strip_re.sub("", body1[:4000])
        b2 = strip_re.sub("", body2[:4000])
        return abs(len(b1) - len(b2)) > 20 or b1 != b2

    @classmethod
    def detect_critical_flows(cls, urls: list[str]) -> list[tuple[str, str]]:
        """
        Scan a list of URLs for critical business flow patterns.
        Returns list of (flow_name, url) tuples for each match.
        Pure URL pattern classification — no network calls made.
        """
        results: list[tuple[str, str]] = []
        for url in urls:
            url_lower = url.lower()
            for flow_name, keywords in _CRITICAL_FLOW_PATTERNS.items():
                if any(kw in url_lower for kw in keywords):
                    results.append((flow_name, url))
                    break
        return results

    def get_findings(self) -> list[dict]:
        """Return all findings as dicts."""
        return [
            {
                "url": f.url,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "finding": f.finding,
                "evidence": f.evidence,
                "category": f.category,
                "phase": f.phase,
            }
            for f in self.findings
        ]
