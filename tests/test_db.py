"""Tests for db module — import checks."""

import pytest


def test_models_imports():
    """Verify that db.models module can be imported."""
    from db import models as db_models
    assert db_models.__doc__ is not None


def test_encryption_imports():
    """Verify that db.encryption module can be imported."""
    from db import encryption
    assert encryption.__doc__ is not None


def test_session_imports():
    """Verify that db.session module can be imported."""
    from db import session
    assert session.__doc__ is not None


def test_db_package_imports():
    """Verify that db package can be imported."""
    import db
    assert db is not None
