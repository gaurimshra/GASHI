"""Synthetic testbed package for GASHI security evaluation."""

from .mock_server import MockServerManager, GLOBAL_TESTBED_STATE

__all__ = ["MockServerManager", "GLOBAL_TESTBED_STATE"]
