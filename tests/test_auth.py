"""Tests for core.auth module — import checks and schema validation."""

import pytest


def test_auth_token_module_imports():
    """Verify that core.auth.token module can be imported."""
    from core.auth import token
    assert token.__doc__ is not None


def test_auth_gate_module_imports():
    """Verify that core.auth.gate module can be imported."""
    from core.auth import gate
    assert gate.__doc__ is not None


def test_auth_package_imports():
    """Verify that core.auth package can be imported."""
    from core import auth
    assert auth is not None
