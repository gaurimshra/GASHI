"""GASHI-Guard platform adapters."""

from .tinyfish import (
    wrap_tinyfish_page,
    sanitize_tinyfish_fetch,
    validate_tinyfish_agent_request
)

__all__ = [
    "wrap_tinyfish_page",
    "sanitize_tinyfish_fetch",
    "validate_tinyfish_agent_request"
]
