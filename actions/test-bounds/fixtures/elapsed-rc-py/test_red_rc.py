# K2 step 2B RC (root's #66 RC): REDs. Each assert below is one finding; the last test is NOT COVERED (D6).
import asyncio
import datetime
import time
from datetime import timedelta
from unittest import mock

from freezegun import freeze_time

OPTS = {}


def test_b1_an_and_operand(billing):
    t0 = time.monotonic()
    assert time.monotonic() - t0 < 5 and billing.paths("/x") == []  # core test_consumption_binding_token_source.py:196


def test_b1_the_second_and_operand(response):
    started = time.monotonic()
    assert response.status_code >= 400 and time.monotonic() - started < 8  # core test_voice_paid_consumer.py:216


def test_b1_parentheses():
    t0 = time.monotonic()
    assert (time.monotonic() - t0) < 1.01
    elapsed = (time.monotonic() - t0)
    assert elapsed < 1.02
    assert ((time.monotonic() - t0) < 1.03)


@mock.patch("time.monotonic")
def test_b2_a_name_rebound_to_a_clock_the_fake_does_not_cover(m):
    a = time.monotonic()
    elapsed = time.monotonic() - a
    b = time.perf_counter()
    elapsed = time.perf_counter() - b
    assert elapsed < 1.14


@freeze_time("2020-01-01", tick=1)
def test_b4_a_tick_that_is_not_false():
    t0 = time.time()
    assert time.time() - t0 < 1.0


@freeze_time("2020-01-01", **OPTS)
def test_b4_a_splat_that_may_carry_a_tick():
    t0 = time.time()
    assert time.time() - t0 < 1.1


def test_l1_stopall_revokes_a_started_patch():
    mock.patch("time.time").start()
    mock.patch.stopall()
    t0 = time.time()
    assert time.time() - t0 < 1.3


@freeze_time("2020-01-01", real_asyncio=True)
async def test_l2_real_asyncio_keeps_the_loop_clock_real():
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    assert loop.time() - t0 < 1.4


def test_d5_a_lower_bound_on_a_remaining_time_per_clock(tc):
    d1 = time.time() + 30
    assert d1 - time.time() >= 5
    d2 = time.time_ns() + 30_000_000_000
    assert d2 - time.time_ns() >= 5_000_000_000
    d3 = time.monotonic() + 30
    assert 5 <= d3 - time.monotonic()
    d4 = time.monotonic_ns() + 30_000_000_000
    assert d4 - time.monotonic_ns() > 5_000_000_000
    d5 = time.perf_counter() + 30
    tc.assertGreater(d5 - time.perf_counter(), 5)
    d6 = time.perf_counter_ns() + 30_000_000_000
    tc.assertLessEqual(5_000_000_000, d6 - time.perf_counter_ns())
    d8 = datetime.datetime.now() + timedelta(seconds=30)
    assert d8 - datetime.datetime.now() >= timedelta(seconds=5)
    d9 = time.monotonic() + 62
    assert d9 - time.monotonic() >= 5  # 62 - 5 = 57: the margin counts


async def test_d5_the_loop_clock():
    loop = asyncio.get_running_loop()
    d7 = loop.time() + 30
    assert d7 - loop.time() >= 5


def test_d5_a_budget_that_is_not_read(passed_in):
    assert passed_in - time.monotonic() > 1


class Other:
    def measure(self):
        return 1


def measure():
    t0 = time.monotonic()
    return time.monotonic() - t0


def test_l4_a_bare_call_reaches_the_function_not_the_method():
    took = measure()
    assert took < 1.5


def test_d6_a_value_two_hops_away(bridge):
    rc, out, elapsed = bridge.hook(env={})
    assert elapsed < 30
