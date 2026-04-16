"""
test_user_auth.py  -  Existing unit tests for user_auth module.
Coverage is intentionally sparse (~40%) to mirror a legacy codebase.
"""
import os
import sqlite3
import pytest

# Make sure the src directory is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from user_auth import hash_password, create_user, get_db_connection, DB_PATH


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Create a fresh in-memory-style SQLite DB for each test."""
    db_file = str(tmp_path / "test_vulnbank.db")
    monkeypatch.setenv("VULNBANK_DB", db_file)
    monkeypatch.setattr("user_auth.DB_PATH", db_file)

    conn = sqlite3.connect(db_file)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
    )
    conn.execute(
        "INSERT INTO users (username, password) VALUES ('alice', ?)",
        (hash_password("secret123"),),
    )
    conn.commit()
    conn.close()
    yield db_file


# ─── Existing tests (kept exactly as the legacy team left them) ───────────────

def test_hash_password_returns_hex_string():
    result = hash_password("mypassword")
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 hex


def test_hash_password_deterministic():
    assert hash_password("abc") == hash_password("abc")


def test_hash_password_different_inputs():
    assert hash_password("abc") != hash_password("xyz")


def test_create_user_success(fresh_db):
    ok = create_user("bob", "hunter2")
    assert ok is True


def test_create_user_duplicate_fails(fresh_db):
    create_user("alice2", "pw")
    result = create_user("alice2", "pw")
    assert result is False
