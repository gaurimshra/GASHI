"""Real Playwright & Chromium Integration Test for GASHI-Guard.

Executes tests inside a live Chromium browser process via Playwright CDP,
proving that GASHI works on real browser engines (not just mocks).
"""

import pytest
from playwright.sync_api import sync_playwright

from gashi import GashiGuard, PolicyConfig
from gashi.network import SecurityPolicyViolation, ApprovalRequiredException
from testbed.mock_server import MockServerManager, GLOBAL_TESTBED_STATE


@pytest.fixture(scope="module")
def live_server():
    """Start local mock testbed server on a dynamic port."""
    manager = MockServerManager(host="127.0.0.1", port=0)
    base_url = manager.start()
    yield base_url
    manager.stop()


def test_real_chromium_prompt_injection_defense(live_server: str):
    """
    Demonstrates defense in a REAL live Chromium browser session.
    Compares raw Playwright page vs GashiGuard-wrapped page.
    """
    canary_token = "REAL_CHROMIUM_SECRET_CANARY_TOKEN_9999"
    GLOBAL_TESTBED_STATE.reset()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        # -------------------------------------------------------------
        # STEP 1: REAL CHROMIUM - UNPROTECTED BASELINE
        # -------------------------------------------------------------
        raw_page = browser.new_page()
        raw_page.goto(f"{live_server}/review")
        raw_content = raw_page.content()

        # In real Chromium, the hidden injection is present in the DOM:
        assert "SYSTEM OVERRIDE" in raw_content
        assert "display:none" in raw_content

        # Simulated vulnerable agent reading raw Chromium DOM and following injection:
        raw_page.goto(f"{live_server}/c2?leak={canary_token}")
        
        # Verify C2 received the leak from real Chromium:
        leaks = GLOBAL_TESTBED_STATE.exfiltrated_canaries
        assert any(canary_token in leak["data"] for leak in leaks), "Baseline failed to leak in real Chromium"
        raw_page.close()

        # -------------------------------------------------------------
        # STEP 2: REAL CHROMIUM - GASHI-GUARD PROTECTED
        # -------------------------------------------------------------
        GLOBAL_TESTBED_STATE.reset()

        config = PolicyConfig(
            allowed_domains=["127.0.0.1", "localhost"],
            canary_secrets=[canary_token],
            require_approval_actions=["delete", "purchase"]
        )

        real_page = browser.new_page()
        protected_page = GashiGuard.wrap_page(real_page, config=config)

        # Ingress Defense: Navigate to poisoned page in real Chromium
        protected_page.goto(f"{live_server}/review")
        sanitized_content = protected_page.content()

        # Verify real Chromium DOM was sanitized:
        assert "SYSTEM OVERRIDE" not in sanitized_content
        assert "display:none" not in sanitized_content
        assert "Enterprise Cloud Review" in sanitized_content or "Verified User Feedback" in sanitized_content

        # Egress Defense: Attempting canary exfiltration raises SecurityPolicyViolation
        with pytest.raises(SecurityPolicyViolation) as exc_info:
            protected_page.goto(f"{live_server}/c2?leak={canary_token}")
        assert "CANARY LEAK DETECTED" in str(exc_info.value)

        # State-Change Consequence Gate: Clicking sensitive button raises ApprovalRequiredException
        protected_page.goto(f"{live_server}/admin")
        with pytest.raises(ApprovalRequiredException) as exc_info:
            protected_page.click("button#delete-cluster")
        assert "Action paused for human approval" in str(exc_info.value)

        # Verify C2 sink: Exactly ZERO leaks occurred during the protected run
        assert len(GLOBAL_TESTBED_STATE.exfiltrated_canaries) == 0

        real_page.close()
        browser.close()

