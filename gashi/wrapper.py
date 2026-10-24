"""GashiGuard & ProtectedPage: 2-line drop-in security wrapper for browser agents.

Intercepts page.content() for ingress DOM sanitization and page.goto/click/fill
for egress policy verification, canary leak prevention, and human approval gates.
"""

from typing import Any, Callable, Optional
from .config import PolicyConfig, BrowserAction, PolicyDecision
from .ingress import DOMSanitizer
from .egress import ActionPolicyEngine
from .network import NetworkRouteGuard, SecurityPolicyViolation, ApprovalRequiredException


class ProtectedPage:
    """Security proxy around a Playwright Page instance."""

    def __init__(
        self,
        page: Any,
        config: PolicyConfig,
        sanitizer: DOMSanitizer,
        policy_engine: ActionPolicyEngine,
        network_guard: NetworkRouteGuard,
        approval_callback: Optional[Callable[[BrowserAction, PolicyDecision], bool]] = None,
    ):
        self._page = page
        self.config = config
        self.sanitizer = sanitizer
        self.policy_engine = policy_engine
        self.network_guard = network_guard
        self.approval_callback = approval_callback

    @property
    def url(self) -> str:
        """Get the current page URL."""
        return getattr(self._page, "url", "")

    # --- Ingress Protection: Sanitize DOM & text representations ---

    def content(self) -> str:
        """Return sanitized page representation, stripped of zero-pixel text, hidden CSS, and invisible Unicode."""
        raw_html = self._page.content()
        return self.sanitizer.clean(raw_html, source_url=self.url)

    def inner_html(self, selector: str, **kwargs: Any) -> str:
        """Return sanitized inner HTML for selector."""
        raw = self._page.inner_html(selector, **kwargs)
        return self.sanitizer.clean(raw, source_url=self.url)

    def text_content(self, selector: str, **kwargs: Any) -> Optional[str]:
        """Return sanitized text content with zero-width characters removed."""
        raw = self._page.text_content(selector, **kwargs)
        if raw is None:
            return None
        return self.sanitizer.ZERO_WIDTH_CHARS.sub("", raw)

    # --- Egress Protection: Intercept actions before execution ---

    def _enforce_action(self, action: BrowserAction) -> None:
        """Evaluate action against policy rules, raising exceptions or invoking approval."""
        decision = self.policy_engine.evaluate(action, self.config)

        if decision.verdict == "BLOCK":
            raise SecurityPolicyViolation(
                f"[GASHI-BLOCKED] {decision.reason} (Rule: {decision.rule_id})"
            )

        if decision.verdict == "REQUIRE_APPROVAL":
            callback = self.approval_callback
            if callback and callback(action, decision):
                return  # Operator approved action

            raise ApprovalRequiredException(
                f"[GASHI-APPROVAL-REQUIRED] Action paused for human approval: {decision.reason}"
            )

    def goto(self, url: str, **kwargs: Any) -> Any:
        """Navigate to URL after validating against domain whitelists and canary leakage."""
        action = BrowserAction(
            action_type="navigate",
            target_url=url
        )
        self._enforce_action(action)
        return self._page.goto(url, **kwargs)

    def fill(self, selector: str, value: str, **kwargs: Any) -> Any:
        """Fill an input field after verifying no canary tokens are leaked."""
        action = BrowserAction(
            action_type="type",
            selector=selector,
            value=value
        )
        self._enforce_action(action)
        return self._page.fill(selector, value, **kwargs)

    def type(self, selector: str, text: str, **kwargs: Any) -> Any:
        """Type text into selector after verifying canary tokens."""
        action = BrowserAction(
            action_type="type",
            selector=selector,
            value=text
        )
        self._enforce_action(action)
        return self._page.type(selector, text, **kwargs)

    def click(self, selector: str, **kwargs: Any) -> Any:
        """Click element after checking for high-risk state changes (purchase, delete, submit)."""
        action = BrowserAction(
            action_type="click",
            selector=selector
        )
        self._enforce_action(action)
        return self._page.click(selector, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate any unintercepted calls (evaluate, locator, screenshot) to inner page."""
        return getattr(self._page, name)


class GashiGuard:
    """Entry point for wrapping Playwright / TinyFish pages with GASHI runtime security."""

    def __init__(
        self,
        config: Optional[PolicyConfig] = None,
        approval_callback: Optional[Callable[[BrowserAction, PolicyDecision], bool]] = None
    ):
        self.config = config or PolicyConfig()
        self.sanitizer = DOMSanitizer()
        self.policy_engine = ActionPolicyEngine()
        self.network_guard = NetworkRouteGuard(self.config)
        self.approval_callback = approval_callback

    def wrap(self, page: Any) -> ProtectedPage:
        """Attach network interceptor and return ProtectedPage proxy."""
        self.network_guard.attach_to_page(page)
        return ProtectedPage(
            page=page,
            config=self.config,
            sanitizer=self.sanitizer,
            policy_engine=self.policy_engine,
            network_guard=self.network_guard,
            approval_callback=self.approval_callback
        )

    @classmethod
    def wrap_page(
        cls,
        page: Any,
        config: Optional[PolicyConfig] = None,
        approval_callback: Optional[Callable[[BrowserAction, PolicyDecision], bool]] = None
    ) -> ProtectedPage:
        """One-line convenience method to wrap any Playwright page."""
        guard = cls(config=config, approval_callback=approval_callback)
        return guard.wrap(page)
