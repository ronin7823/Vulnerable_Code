"""
conftest.py — pytest configuration for the sample_repo test suite.
Adds src/ to sys.path so tests can import from user_auth directly.
"""
import sys
import os

# Make src/ importable from anywhere pytest is invoked
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Register custom markers so pytest doesn't warn about unknown marks
def pytest_configure(config):
    config.addinivalue_line("markers", "exploit: proof-of-exploit test (should fail on vulnerable code)")
    config.addinivalue_line("markers", "regression: regression guard test (must pass on patched code)")
