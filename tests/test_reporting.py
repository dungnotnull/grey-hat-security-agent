"""Tests for core.reporting module — import checks."""

import pytest


def test_generator_imports():
    """Verify that core.reporting.generator module can be imported."""
    from core.reporting import generator
    assert generator.__doc__ is not None


def test_pdf_renderer_imports():
    """Verify that core.reporting.pdf_renderer module can be imported."""
    from core.reporting import pdf_renderer
    assert pdf_renderer.__doc__ is not None


def test_templates_imports():
    """Verify that core.reporting.templates module can be imported."""
    from core.reporting import templates
    assert templates.__doc__ is not None


def test_reporting_package_imports():
    """Verify that core.reporting package can be imported."""
    from core import reporting
    assert reporting is not None
