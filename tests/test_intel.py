"""Tests for core.intel module — import checks."""

import pytest


def test_phishtank_module_imports():
    """Verify that core.intel.phishtank module can be imported."""
    from core.intel import phishtank
    assert phishtank.__doc__ is not None


def test_openphish_module_imports():
    """Verify that core.intel.openphish module can be imported."""
    from core.intel import openphish
    assert openphish.__doc__ is not None


def test_urlhaus_module_imports():
    """Verify that core.intel.urlhaus module can be imported."""
    from core.intel import urlhaus
    assert urlhaus.__doc__ is not None


def test_virustotal_module_imports():
    """Verify that core.intel.virustotal module can be imported."""
    from core.intel import virustotal
    assert virustotal.__doc__ is not None


def test_shodan_module_imports():
    """Verify that core.intel.shodan_client module can be imported."""
    from core.intel import shodan_client
    assert shodan_client.__doc__ is not None


def test_risk_score_module_imports():
    """Verify that core.intel.risk_score module can be imported."""
    from core.intel import risk_score
    assert risk_score.__doc__ is not None


def test_rate_limiter_module_imports():
    """Verify that core.intel.rate_limiter module can be imported."""
    from core.intel import rate_limiter
    assert rate_limiter.__doc__ is not None


def test_intel_package_imports():
    """Verify that core.intel package can be imported."""
    from core import intel
    assert intel is not None
