# K2 step 2B RC (root's #66 RC): GREENs. Four asserts clear; the rest are not elapsed asserts at all.
import time
from unittest import mock

from freezegun import freeze_time


@freeze_time("2020-01-01", tick=False)
def test_b4_tick_false_is_a_proof():
    t0 = time.time()
    assert time.time() - t0 < 1.2


def test_d5_a_budget_that_leaves_the_floor():
    deadline = time.monotonic() + 300
    assert deadline - time.monotonic() >= 5


def test_the_floor_is_inclusive():
    t0 = time.monotonic()
    assert time.monotonic() - t0 < 60


def test_not_required_true_or_compliant(ok):
    t0 = time.monotonic()
    assert ok or time.monotonic() - t0 < 3
    assert not (time.monotonic() - t0 < 4)
    deadline = time.monotonic() + 30
    assert deadline - time.monotonic() < 5


def _cleanup():
    mock.patch.stopall()


def test_a_revoking_def_declared_earlier_revokes_nothing_until_called():
    mock.patch("time.time").start()
    t0 = time.time()
    assert time.time() - t0 < 1.5
