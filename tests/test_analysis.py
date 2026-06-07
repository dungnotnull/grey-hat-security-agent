"""Tests for core.analysis module — import checks."""

import pytest


def test_cvss_module_imports():
    """Verify that core.analysis.cvss module can be imported."""
    from core.analysis import cvss
    assert cvss.__doc__ is not None


def test_cve_matcher_imports():
    """Verify that core.analysis.cve_matcher module can be imported."""
    from core.analysis import cve_matcher
    assert cve_matcher.__doc__ is not None


def test_mitre_mapper_imports():
    """Verify that core.analysis.mitre_mapper module can be imported."""
    from core.analysis import mitre_mapper
    assert mitre_mapper.__doc__ is not None


def test_analysis_package_imports():
    """Verify that core.analysis package can be imported."""
    from core import analysis
    assert analysis is not None
