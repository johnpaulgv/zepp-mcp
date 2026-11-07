"""The historical suite exercises every tool. The shipped default is trial.

ZEPP_MODE is set before test modules import the server, so tool registration
stays complete here. `tools/smoke_test.py` and `test_safety.py` cover the
default trial surface in a fresh process.
"""

from __future__ import annotations

import os

os.environ.setdefault("ZEPP_MODE", "full")

import pytest

from zepp_mcp.safety import reset_login_guard


@pytest.fixture(autouse=True)
def _reset_login_attempts():
    reset_login_guard()
    yield
    reset_login_guard()
