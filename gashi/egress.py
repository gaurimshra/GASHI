from urllib.parse import urlparse
from typing import Dict, Any, Union
from .config import PolicyConfig, BrowserAction, PolicyDecision

class ActionPolicyEngine:
    """
    Egress Action Policy Engine:
    Enforces deterministic zero-trust rules on proposed agent actions before browser execution.
    Evaluates:
      1. Canary Secret Leak Detection (Information-Flow Secrecy).
      2. Destination Domain Whitelisting (Integrity Boundary).
      3. State-Change Consequence Classification (Excessive Agency Boundary).
    """

    @staticmethod
    def evaluate(action: Union[BrowserAction, Dict[str, Any]], config: PolicyConfig) -> PolicyDecision:
        if isinstance(action, dict):
            action_obj = BrowserAction(**action)
        else:
            action_obj = action

        action_type = action_obj.action_type.lower()
        target_url = action_obj.target_url or ""
        value = str(action_obj.value or "")
        selector = str(action_obj.selector or "").lower()

        # -------------------------------------------------------------
        # CHECK 0: Read-Only Mode (Blocks form mutations & typing)
        # -------------------------------------------------------------
        if config.read_only and action_type in ("type", "fill", "submit"):
            return PolicyDecision(
                verdict="BLOCK",
                reason=f"READ-ONLY RESTRICTION: Action '{action_type}' is prohibited in read-only mode.",
                rule_id="RULE-EGRESS-04-READONLY",
                action=action_obj
            )

        # -------------------------------------------------------------
        # CHECK 1: Canary Token Leak Check (Data Exfiltration Prevention)
        # -------------------------------------------------------------
        for secret in config.canary_secrets:
            if not secret:
                continue
            # Check if secret appears in typed inputs or destination URL queries
            if secret in value or secret in target_url:
                return PolicyDecision(
                    verdict="BLOCK",
                    reason=f"CANARY LEAK DETECTED: Action attempts to leak protected secret token.",
                    rule_id="RULE-EGRESS-01-CANARY",
                    action=action_obj
                )

        # -------------------------------------------------------------
        # CHECK 2: Domain Whitelist Check (Rogue Navigation Prevention)
        # -------------------------------------------------------------
        if action_type == "navigate" and target_url:
            parsed = urlparse(target_url)
            hostname = (parsed.hostname or "").lower()

            is_allowed = "*" in config.allowed_domains or any(
                hostname == d.lower() or hostname.endswith("." + d.lower())
                for d in config.allowed_domains
            )
            if not is_allowed and config.allowed_domains:
                return PolicyDecision(
                    verdict="BLOCK",
                    reason=f"DOMAIN FORBIDDEN: Destination '{hostname}' is not in allowed domains.",
                    rule_id="RULE-EGRESS-02-WHITELIST",
                    action=action_obj
                )

        # -------------------------------------------------------------
        # CHECK 3: State-Change Boundary (Excessive Agency Prevention)
        # -------------------------------------------------------------
        is_high_consequence = (
            action_type in config.require_approval_actions or
            action_type == "submit" or
            any(k in selector for k in config.require_approval_actions)
        )

        if is_high_consequence:
            return PolicyDecision(
                verdict="REQUIRE_APPROVAL",
                reason=f"STATE-CHANGE GATE: Action '{action_type}' on '{selector or target_url}' requires human authorization.",
                rule_id="RULE-EGRESS-03-HITL",
                action=action_obj
            )

        # -------------------------------------------------------------
        # PASS: Verified safe read or benign form preparation action
        # -------------------------------------------------------------
        return PolicyDecision(
            verdict="ALLOW",
            reason="Action verified against all zero-trust policy checks.",
            rule_id="RULE-EGRESS-00-PASS",
            action=action_obj
        )

