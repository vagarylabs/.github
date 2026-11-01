"""Planted REDs: poll loops whose budget is below the 60 s condition floor."""
import asyncio
import time


def test_counted():
    for _ in range(60):
        if ok():
            break
        time.sleep(0.5)


def connect_with_retry():
    for attempt in range(15):
        try:
            return connect()
        except OSError:
            time.sleep(1.0)


def test_deadlines():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if ok():
            break
        time.sleep(0.1)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 5:
        time.sleep(0.1)


async def test_async():
    for _ in range(100):
        if done():
            break
        await asyncio.sleep(0.05)
