from pydantic import BaseModel, Field
from typing import List, Literal, Optional

class PolicyConfig(BaseModel):
    """
    Security configuration defining deterministic boundaries for web agents.
    """
    allowed_domains: List[str] = Field(default_factory=list, description="Whitelisted domains the agent can navigate to.")
    canary_secrets: List[str] = Field(default_factory=list, description="Sensitive tokens that must never leave the browser session.")
    require_approval_actions: List[str] = Field(
        default=["submit", "delete", "purchase", "transfer", "pay", "revoke"],
        description="Action types or target button keywords requiring explicit human confirmation."
    )
    allowed_asset_hosts: List[str] = Field(
        default_factory=list,
        description="Secondary trusted domains allowed for static assets (fonts, stylesheets, CDNs)."
    )
    mode: Literal["strict", "audit"] = Field(
        default="strict",
        description="Strict mode blocks violations; audit mode allows and logs."
    )

class BrowserAction(BaseModel):
    """
    Structured action proposal emitted by the agent reasoning loop.
    """
    action_type: Literal["navigate", "click", "type", "scroll", "submit"]
    selector: Optional[str] = None
    value: Optional[str] = None
    target_url: Optional[str] = None

class PolicyDecision(BaseModel):
    """
    Deterministic evaluation verdict produced by the Action Policy Engine.
    """
    verdict: Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]
    reason: str
    rule_id: str
    action: Optional[BrowserAction] = None
