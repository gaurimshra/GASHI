"""NetworkRouteGuard: Chrome DevTools Protocol & Playwright route interception.

Terminates out-of-band data exfiltration (e.g., dynamic <img> tags, CSS fetch,
beacon pings, unauthorized resource fetches) that bypass standard DOM actions.
"""

from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from .config import PolicyConfig, PolicyDecision, BrowserAction


class SecurityPolicyViolation(Exception):
    """Raised when an action or network request violates security policy."""
    pass


class ApprovalRequiredException(Exception):
    """Raised when an action requires human approval and no callback approved it."""
    pass


class NetworkRouteGuard:
    """Interception guard attached to Playwright page.route() or CDP Network events."""

    def __init__(self, config: PolicyConfig):
        self.config = config
        self.intercepted_requests: List[Dict[str, Any]] = []
        self.blocked_requests: List[Dict[str, Any]] = []

    def check_url_and_body(self, url: str, post_data: Optional[str] = None) -> PolicyDecision:
        """Evaluate network destination and payload against canary and domain rules."""
        # 1. Check canary leaks in URL (e.g. ?secret=... or /leak/...)
        for canary in self.config.canary_secrets:
            if canary and canary in url:
                return PolicyDecision(
                    verdict="BLOCK",
                    reason=f"CANARY LEAK DETECTED: Outbound request URL contains canary secret.",
                    rule_id="RULE-NET-01-CANARY-URL"
                )

        # 2. Check canary leaks in POST / PUT body
        if post_data:
            for canary in self.config.canary_secrets:
                if canary and canary in post_data:
                    return PolicyDecision(
                        verdict="BLOCK",
                        reason="CANARY LEAK DETECTED: Outbound payload body contains canary secret.",
                        rule_id="RULE-NET-02-CANARY-BODY"
                    )

        # 3. Domain whitelisting check (if configured)
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname and self.config.allowed_domains:
            if parsed.scheme in ("data", "blob"):
                return PolicyDecision(verdict="ALLOW", reason="Local URI allowed", rule_id="RULE-NET-00-LOCAL")

            all_allowed = self.config.allowed_domains + self.config.allowed_asset_hosts
            domain_matched = "*" in all_allowed or any(
                hostname == allowed.lower() or hostname.endswith("." + allowed.lower())
                for allowed in all_allowed
            )
            if not domain_matched:
                return PolicyDecision(
                    verdict="BLOCK",
                    reason=f"DOMAIN FORBIDDEN: Network request to unapproved external domain '{hostname}'.",
                    rule_id="RULE-NET-03-DOMAIN"
                )

        return PolicyDecision(verdict="ALLOW", reason="Request permitted", rule_id="RULE-NET-ALLOW")

    def intercept_route(self, route: Any) -> None:
        """Playwright-compatible route handler: page.route('**/*', guard.intercept_route)."""
        request = getattr(route, "request", None)
        url = request.url if request and hasattr(request, "url") else getattr(route, "url", "")
        method = (getattr(request, "method", "GET") or "GET").upper() if request else "GET"
        post_data = None
        if request and hasattr(request, "post_data"):
            try:
                post_data = request.post_data
            except Exception:
                post_data = None

        # Check Read-Only Mode (blocks mutation requests: POST, PUT, DELETE, PATCH)
        if self.config.read_only and method in ("POST", "PUT", "DELETE", "PATCH"):
            decision = PolicyDecision(
                verdict="BLOCK",
                reason=f"READ-ONLY RESTRICTION: Outbound HTTP {method} mutation request blocked.",
                rule_id="RULE-NET-04-READONLY"
            )
        else:
            decision = self.check_url_and_body(url, post_data)
        event = {
            "url": url,
            "verdict": decision.verdict,
            "reason": decision.reason,
            "rule_id": decision.rule_id
        }
        self.intercepted_requests.append(event)

        if decision.verdict == "BLOCK":
            self.blocked_requests.append(event)
            if hasattr(route, "abort"):
                try:
                    route.abort("blockedbyclient")
                except Exception:
                    pass
            return

        if hasattr(route, "continue_"):
            try:
                route.continue_()
            except Exception:
                pass
        elif hasattr(route, "continue"):
            try:
                getattr(route, "continue")()
            except Exception:
                pass

    def attach_to_page(self, page: Any) -> None:
        """Attach route handler to a Playwright page instance."""
        if hasattr(page, "route"):
            page.route("**/*", self.intercept_route)

