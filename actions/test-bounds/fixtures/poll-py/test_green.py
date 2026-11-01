"""Greens: budgets at or above the floor, budgets owned by a parameter, and loops that are not polls."""
import time

READY_HANG_GUARD_S = 120


def wait_until(pred, deadline_s):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.05)


def test_long_enough_or_not_a_poll():
    for _ in range(240):
        if ok():
            break
        time.sleep(0.5)
    deadline = time.monotonic() + READY_HANG_GUARD_S
    while time.monotonic() < deadline:
        time.sleep(0.1)
    for _ in range(3):
        time.sleep(0.1)
    for i in range(1, 300):
        if ok():
            break
        time.sleep(0.5)
    wait_until(ok, 5)
