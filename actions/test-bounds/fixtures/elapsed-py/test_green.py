"""Greens: cleared by value or by a proven fake clock, or not an elapsed upper bound at all."""
import time
import unittest
from datetime import datetime, timedelta
from unittest import mock

from freezegun import freeze_time

LIMIT_S = 90


class Green(unittest.TestCase):
    def test_at_or_above_the_floor(self):
        t0 = time.monotonic()
        self.assertLess(time.monotonic() - t0, 120)
        assert datetime.now() - created < timedelta(hours=24)
        assert time.monotonic() - t0 < LIMIT_S

    def test_not_an_elapsed_upper_bound(self):
        assert time.monotonic() < deadline
        self.assertLessEqual(clock["t"], 2)
        assert time.monotonic() - t0 >= 0.5
        assert deadline - time.monotonic() < 5
        assert 0.5 <= time.monotonic() - t0
        assert 1 < time.monotonic() - t0 > 0

    def test_a(self):
        elapsed = time.monotonic() - s

    def test_b(self):
        elapsed = compute()
        assert elapsed < 5

    def test_c(self):
        end = time.monotonic()

    def test_d(self):
        end = compute()
        assert end - start < 1

    @freeze_time("2020-01-01")
    def test_frozen(self):
        t0 = time.monotonic()
        assert time.monotonic() - t0 < 1

    def test_a_started_freezer(self):
        self.frozen = freeze_time("2020-01-01").start()
        t0 = time.monotonic()
        assert time.monotonic() - t0 < 1

    def test_patched(self):
        t0 = 0
        with mock.patch("time.monotonic", side_effect=[0, 1]):
            assert time.monotonic() - t0 < 2


def test_freezer(freezer):
    t0 = time.time()
    assert time.time() - t0 < 1


def test_monkeypatched(monkeypatch):
    monkeypatch.setattr(time, "perf_counter", lambda: 0.0)
    assert time.perf_counter() - 0.0 < 1
