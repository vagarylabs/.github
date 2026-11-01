"""Planted REDs and greens for sleep-as-wait in Python."""
import asyncio
import time
import unittest


def settle():
    time.sleep(0.15)


class Lease(unittest.TestCase):
    def test_expiry(self):
        take_lease()
        time.sleep(1.2)
        self.assertFalse(lease_alive())
        settle()
        assert gone()
        time.sleep(0.5)  # timeout under test: the mtime resolution is one second on this filesystem
        self.assertEqual(seen(), 2)

    def test_greens(self):
        time.sleep(0)
        assert ready()
        for _ in range(3):
            time.sleep(0.1)
        time.sleep(0.2)


async def test_async_expiry():
    await asyncio.sleep(0.3)
    assert expired()


def helper_not_a_test():
    time.sleep(1)
    assert x
