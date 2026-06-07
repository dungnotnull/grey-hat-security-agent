"""Tests for models module — import checks."""

import pytest


def test_secroberta_imports():
    """Verify that models.secroberta module can be imported."""
    from models import secroberta
    assert secroberta.__doc__ is not None


def test_codebert_imports():
    """Verify that models.codebert module can be imported."""
    from models import codebert
    assert codebert.__doc__ is not None


def test_llm_provider_imports():
    """Verify that models.llm_provider module can be imported."""
    from models import llm_provider
    assert llm_provider.__doc__ is not None


def test_models_package_imports():
    """Verify that models package can be imported."""
    import models
    assert models is not None
