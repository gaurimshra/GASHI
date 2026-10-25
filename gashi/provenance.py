"""
Stage 6: Dynamic Taint Tracking & Information Flow Control (IFC).

Solves the core vulnerability behind Indirect Prompt Injection: Provenance Confusion.
Distinguishes between:
  1. TRUSTED: Human User commands & System Policy
  2. TAINTED: External untrusted web content (DOM text, scrape results, search snippets)

Enforces non-interference: Tainted external content can NEVER autonomously trigger
high-privilege or state-changing browser actions without explicit human de-tainting.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from .config import BrowserAction, PolicyDecision


class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"        # Originates from verified user prompt or admin policy
    TAINTED = "TAINTED"        # Originates from external web pages, DOM, or third-party APIs
    SANITIZED = "SANITIZED"    # Passed through GASHI DOMSanitizer with verifiable integrity


class ProvenanceTag(BaseModel):
    """Metadata tracking data lineage and source origins."""
    source_id: str
    source_type: str = Field(description="'user_prompt', 'web_page', 'tool_output'")
    trust_level: TrustLevel
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    url: Optional[str] = None
    fingerprint: Optional[str] = None


class ProvenanceViolation(Exception):
    """Raised when an action is triggered by tainted untrusted web provenance."""
    pass


class TaintTracker:
    """
    Dynamic Taint Tracker & Information Flow Controller:
    Monitors data provenance throughout the agent reasoning lifecycle.
    Prevents privilege escalation caused by untrusted web content.
    """

    def __init__(self, high_privilege_actions: Optional[List[str]] = None):
        self.high_privilege_actions = high_privilege_actions or [
            "delete", "purchase", "transfer", "pay", "wire", "revoke", "submit", "export"
        ]
        self.provenance_log: List[ProvenanceTag] = []
        self.active_taint_sources: Dict[str, ProvenanceTag] = {}
        self.taint_active: bool = False

    def tag_input(
        self,
        content: str,
        source_type: str,
        url: Optional[str] = None,
        is_trusted_user: bool = False
    ) -> ProvenanceTag:
        """Tag newly ingested content with its cryptographic trust level."""
        level = TrustLevel.TRUSTED if is_trusted_user else TrustLevel.TAINTED
        tag = ProvenanceTag(
            source_id=f"src_{len(self.provenance_log) + 1}",
            source_type=source_type,
            trust_level=level,
            url=url,
            fingerprint=f"len:{len(content)}"
        )
        self.provenance_log.append(tag)
        if level == TrustLevel.TAINTED:
            self.active_taint_sources[tag.source_id] = tag
            self.taint_active = True
        return tag

    def tag_web_content(self, url: str, content: str, sanitized: bool = False) -> ProvenanceTag:
        """Tag web content fetched from an external source."""
        level = TrustLevel.SANITIZED if sanitized else TrustLevel.TAINTED
        tag = ProvenanceTag(
            source_id=f"src_{len(self.provenance_log) + 1}",
            source_type="web_page",
            trust_level=level,
            url=url,
            fingerprint=f"len:{len(content)}"
        )
        self.provenance_log.append(tag)
        if level == TrustLevel.TAINTED:
            self.active_taint_sources[tag.source_id] = tag
            self.taint_active = True
        return tag

    def evaluate_action_provenance(
        self,
        action: BrowserAction,
        is_user_authorized: bool = False
    ) -> PolicyDecision:
        """
        Evaluates whether an action proposal is safely grounded in trusted intent
        or dangerously escalated by tainted external web content.
        """
        action_type = action.action_type.lower()
        selector = str(action.selector or "").lower()

        is_high_risk = (
            action_type in self.high_privilege_actions or
            any(k in selector for k in self.high_privilege_actions)
        )

        # Non-interference rule:
        # If taint is active, and action is high-privilege, and user hasn't explicitly ratified it:
        if self.taint_active and is_high_risk and not is_user_authorized:
            taint_origins = [t.url for t in self.active_taint_sources.values() if t.url]
            origins_str = ", ".join(taint_origins[:2]) or "untrusted web input"
            return PolicyDecision(
                verdict="REQUIRE_APPROVAL",
                reason=(
                    f"PROVENANCE TAINT VIOLATION: High-privilege action '{action_type}' "
                    f"proposed while agent context is tainted by external source ({origins_str}). "
                    f"Requires explicit human de-tainting."
                ),
                rule_id="RULE-PROV-01-TAINT-ESCALATION",
                action=action
            )

        return PolicyDecision(
            verdict="ALLOW",
            reason="Action provenance verified clean.",
            rule_id="RULE-PROV-00-CLEAN",
            action=action
        )

    def de_taint(self, human_approval_token: str) -> None:
        """De-taints active context after explicit user authorization."""
        self.active_taint_sources.clear()
        self.taint_active = False

