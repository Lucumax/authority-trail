import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authority_trail import demo  # noqa: E402


class Clock:
    """Deterministic clock: each call advances one second."""

    def __init__(self, start=datetime(2026, 11, 2, 15, 0, 0, tzinfo=timezone.utc)):
        self.t = start

    def __call__(self):
        self.t += timedelta(seconds=1)
        return self.t

    def iso(self, **delta):
        return (self.t + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def scenario(clock):
    trail, parties, outcomes = demo.build(clock=clock)
    return trail, parties, outcomes
