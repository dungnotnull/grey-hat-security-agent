"""Tests for utils module — import checks."""

import pytest


def test_crypto_imports():
    """Verify that utils.crypto module can be imported."""
    from utils import crypto
    assert crypto.__doc__ is not None


def test_helpers_imports():
    """Verify that utils.helpers module can be imported."""
    from utils import helpers
    assert helpers.__doc__ is not None


def test_utils_package_imports():
    """Verify that utils package can be imported."""
    import utils
    assert utils is not None
