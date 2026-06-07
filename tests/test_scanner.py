"""Tests for core.scanner module — import checks."""

import pytest


def test_nmap_wrapper_imports():
    """Verify that core.scanner.nmap_wrapper module can be imported."""
    from core.scanner import nmap_wrapper
    assert nmap_wrapper.__doc__ is not None


def test_ssl_checker_imports():
    """Verify that core.scanner.ssl_checker module can be imported."""
    from core.scanner import ssl_checker
    assert ssl_checker.__doc__ is not None


def test_zap_scanner_imports():
    """Verify that core.scanner.zap_scanner module can be imported."""
    from core.scanner import zap_scanner
    assert zap_scanner.__doc__ is not None


def test_nuclei_scanner_imports():
    """Verify that core.scanner.nuclei_scanner module can be imported."""
    from core.scanner import nuclei_scanner
    assert nuclei_scanner.__doc__ is not None


def test_orchestrator_imports():
    """Verify that core.scanner.orchestrator module can be imported."""
    from core.scanner import orchestrator
    assert orchestrator.__doc__ is not None


def test_scanner_package_imports():
    """Verify that core.scanner package can be imported."""
    from core import scanner
    assert scanner is not None
