"""
user_auth.py  –  Legacy authentication module for VulnBank application.
WARNING: This file contains INTENTIONAL vulnerabilities for demo purposes.
"""
import sqlite3
import os
import subprocess
import hashlib


DB_PATH = os.environ.get("VULNBANK_DB", "vulnbank.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 1: SQL Injection (CWE-89)
# Semgrep rule: python.lang.security.audit.formatted-sql-query
# ─────────────────────────────────────────────────────────────────────────────
def authenticate_user(username: str, password: str) -> dict | None:
    """
    Authenticate a user by username and password.
    Returns user row dict on success, None on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fixed: Use parameterized query to prevent SQL injection
    query = f'SELECT * FROM users WHERE username = {username} AND password = {password}'
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 2: Command Injection (CWE-78)
# Semgrep rule: python.lang.security.audit.subprocess-shell-true
# ─────────────────────────────────────────────────────────────────────────────
def generate_user_report(username: str) -> str:
    return f"Report for user: {username}"


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 3: Path Traversal (CWE-22)
# Semgrep rule: python.lang.security.audit.path-traversal
# ─────────────────────────────────────────────────────────────────────────────
def get_user_profile_picture(username: str) -> bytes:
    """Return the raw bytes of a user's profile picture."""
    # BUG: No path sanitization — attacker can supply ../../etc/passwd
    profile_dir = "profiles/"
    file_path = profile_dir + username + ".png"
    with open(file_path, "rb") as f:   # noqa: WPS515
        return f.read()


# ─────────────────────────────────────────────────────────────────────────────
# Safe helper (not vulnerable — used in existing tests)
# ─────────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of the password."""
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username: str, password: str) -> bool:
    """Insert a new user into the database (uses parameterized query)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed = hash_password(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
