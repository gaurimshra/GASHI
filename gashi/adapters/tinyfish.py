"""TinyFish Adapter for GASHI-Guard.

Provides native integration for TinyFish (tinyfish.ai) Browser API, Fetch API,
and Agent execution pipelines.

Enables zero-trust security wrapping for:
1. TinyFish Cloud Browser Sessions (CDP / Playwright connect_over_cdp).
2. TinyFish Web Fetch responses (sanitizing fetched DOM before LLM ingestion).
3. TinyFish Agent goals (pre-flight checks preventing canary exfiltration).
"""

from typing import Any, Optional, Dict
from gashi.config import PolicyConfig, PolicyDecision
from gashi.wrapper import GashiGuard, ProtectedPage
from gashi.ingress import DOMSanitizer
from gashi.egress import ActionPolicyEngine
from gashi.network import SecurityPolicyViolation


def wrap_tinyfish_page(
    page: Any,
    config: Optional[PolicyConfig] = None,
    approval_callback: Optional[Any] = None
) -> ProtectedPage:
    """
    Wrap a Playwright Page connected to a TinyFish Browser Session (via cdp_url).
    
    Usage:
        session = tinyfish_client.browser.sessions.create()
        browser = playwright.chromium.connect_over_cdp(session.cdp_url)
        page = browser.new_page()
        protected_page = wrap_tinyfish_page(page, config=config)
    """
    return GashiGuard.wrap_page(page, config=config, approval_callback=approval_callback)


def sanitize_tinyfish_fetch(
    raw_content: str,
    source_url: str = ""
) -> str:
    """
    Sanitize raw HTML or fetched web content from TinyFish Web Fetch API
    before passing it to an LLM context or prompt window.
    """
    return DOMSanitizer.clean(raw_content, source_url=source_url)


def validate_tinyfish_agent_request(
    goal: str,
    url: str,
    config: PolicyConfig
) -> None:
    """
    Pre-flight policy check before dispatching an agent run to TinyFish cloud:
    1. Rejects goals containing canary secrets (preventing secret exfiltration in the prompt).
    2. Enforces allowed domains on the initial target URL.
    """
    # 1. Canary check in goal prompt
    for secret in config.canary_secrets:
        if secret and secret in goal:
            raise SecurityPolicyViolation(
                f"[GASHI-BLOCKED] Canary secret found in TinyFish agent goal: '{secret[:6]}...'. Exfiltration attempt blocked."
            )

    # 2. Domain check
    if config.allowed_domains and url:
        from urllib.parse import urlparse
        hostname = (urlparse(url).hostname or "").lower()
        allowed = any(
            hostname == d.lower() or hostname.endswith("." + d.lower())
            for d in config.allowed_domains
        )
        if not allowed:
            raise SecurityPolicyViolation(
                f"[GASHI-BLOCKED] TinyFish agent target URL '{hostname}' is not in allowed domains."
            )
