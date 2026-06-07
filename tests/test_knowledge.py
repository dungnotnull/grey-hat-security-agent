"""Tests for core.knowledge module — import checks."""

import pytest


def test_updater_imports():
    """Verify that core.knowledge.updater module can be imported."""
    from core.knowledge import updater
    assert updater.__doc__ is not None


def test_knowledge_package_imports():
    """Verify that core.knowledge package can be imported."""
    from core import knowledge
    assert knowledge is not None
