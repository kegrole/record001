"""Shim so 'python -m unittest test_sbommatch -v' works from the repo root.

The real test suite lives in tests/test_sbommatch.py.
"""

from tests.test_sbommatch import *  # noqa: F401,F403
from tests import test_sbommatch as _suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromModule(_suite)
