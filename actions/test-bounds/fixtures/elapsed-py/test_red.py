"""Planted REDs: each assert puts an upper bound below 60 s on a real-clock elapsed difference."""
import asyncio
import time
import unittest
from datetime import datetime, timedelta
from time import monotonic_ns
from unittest import mock

from freezegun import freeze_time


class Red(unittest.TestCase):
    def test_each_clock(self):
        t0 = 0
        self.assertLess(time.time() - t0, 5)
        assert time.time_ns() - t0 < 5_000_000_000
        self.assertLess(time.monotonic() - t0, 2.5)
        assert monotonic_ns() - t0 <= 1_000_000_000
        self.assertLessEqual(time.perf_counter_ns() - t0, 2_000_000)
        loop = asyncio.new_event_loop()
        assert loop.time() - t0 < 1
        assert (datetime.now() - t0).total_seconds() < 5
        assert datetime.now() - t0 < timedelta(seconds=5)

    def test_shapes(self):
        start = time.perf_counter()
        elapsed = time.perf_counter() - start
        assert elapsed < 0.3
        duration_ms = (time.time() - start) * 1000
        assert duration_ms < 200
        assert 0 < time.monotonic() - start < 2
        assert 5 > time.monotonic() - start
        self.assertGreater(3, time.monotonic() - start)
        self.assertTrue(time.monotonic() - start < 4)
        end = time.monotonic()
        assert end - start < 1
        assert time.monotonic() - start < 1  # timeout under test: a mark never exempts an elapsed assert
        assert elapsed < timeout_s * 4

    def test_binding_in_finally(self):
        start = time.monotonic()
        try:
            work()
        finally:
            took = time.monotonic() - start
        assert took < 5

    def test_unstarted_fakes(self):
        f = freeze_time("2020-01-01")
        p = mock.patch("time.monotonic")
        t0 = time.monotonic()
        assert time.monotonic() - t0 < 1

    def test_fakes_that_prove_nothing(self):
        t0 = time.monotonic()
        with freeze_time("2020-01-01", tick=True):
            assert time.monotonic() - t0 < 1
        with mock.patch("time.time"):
            assert time.monotonic() - t0 < 1

    def test_chained_with_a_lower_bound(self):
        t0 = time.monotonic()
        assert 0 <= time.monotonic() - t0 <= 3


class Box:
    def run(self):
        t0 = time.monotonic()
        work()
        return "ok", time.monotonic() - t0

    def timed(self):
        t0 = time.monotonic()
        return time.monotonic() - t0


class Helpers(unittest.TestCase):
    def test_one_hop_into_a_same_file_helper(self):
        b = Box()
        r, took = b.run()
        self.assertLess(took, 3.5)
        elapsed = b.timed()
        assert elapsed < 2

        async def go():
            t0 = loop.time()
            await work()
            return loop.time() - t0

        e2 = asyncio.run(go())
        assert e2 < 0.3


def test_a_nested_helper_per_test_one():
    async def timed_once():
        t0 = time.monotonic()
        await work()
        return time.monotonic() - t0

    elapsed = asyncio.run(timed_once())
    assert elapsed < 0.3


def test_a_nested_helper_per_test_two():
    async def timed_once():
        t0 = time.monotonic()
        await work()
        return time.monotonic() - t0

    elapsed = asyncio.run(timed_once())
    assert elapsed < 0.4
