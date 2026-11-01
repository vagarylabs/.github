# GREEN (K2 step 2A): str.join is not a join wait, and bounds at or above their floor clear.
import asyncio
import threading
from asyncio import wait

import asyncpg
import psycopg2
import pytest
import requests

FIXTURE_HANG_GUARD_S = 120
JOIN_S = 300


def names(items):
    return ", ".join(items)


async def ok(coro):
    await asyncio.wait_for(coro, 60)
    await asyncpg.connect("postgresql://x", timeout=FIXTURE_HANG_GUARD_S)
    requests.get("http://127.0.0.1/health", timeout=60)


async def condition_floor(tasks):
    # asyncio.wait is a condition wait (60 s floor), not a subprocess one (120 s): 90 clears (root's #65 RC L2).
    await asyncio.wait(tasks, timeout=90)
    await wait(tasks, timeout=90)
    requests.get("http://127.0.0.1/health", timeout=(60, 60))
    threading.Thread(target=print).join(JOIN_S)
    psycopg2.connect("dbname=x", connect_timeout=0)  # 0 is "no limit" (L1): not a bound


@pytest.mark.timeout(0)
def test_unlimited():
    pass
