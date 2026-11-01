# GREEN (K2 step 2A): str.join is not a join wait, and bounds at or above their floor clear.
import asyncio

import asyncpg
import requests

FIXTURE_HANG_GUARD_S = 120


def names(items):
    return ", ".join(items)


async def ok(coro):
    await asyncio.wait_for(coro, 60)
    await asyncpg.connect("postgresql://x", timeout=FIXTURE_HANG_GUARD_S)
    requests.get("http://127.0.0.1/health", timeout=60)
