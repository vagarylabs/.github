# One RED per python rule: each bound below the subprocess floor (seconds).
import subprocess


def run(cmd, timeout=45):
    return subprocess.run(cmd, timeout=10)


def reap(p):
    p.wait(5)
    p.communicate(None, 6)


# K2 step 2A: one RED per new python rule.
import asyncio
import threading

import asyncpg
import pytest
import requests


async def waits(coro):
    await asyncio.wait_for(coro, 5)
    await asyncio.wait_for(coro, timeout=6)
    async with asyncio.timeout(7):
        pass
    threading.Thread(target=print).join(8)
    conn = await asyncpg.connect("postgresql://x", timeout=9, command_timeout=10)
    requests.get("http://127.0.0.1/health", timeout=11)
    await asyncpg.create_pool("postgresql://x", timeout=90)  # a finding only at the 120 s fixture floor
    return conn


@pytest.mark.timeout(12)
def test_marked():
    pass
