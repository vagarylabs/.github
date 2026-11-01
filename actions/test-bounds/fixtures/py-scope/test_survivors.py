# K2 step 2A RC2 (#65 delta L1-L3, B3): shapes each with its own planted RED. Eleven REDs.
import asyncio

import asyncpg
import httpx
import psycopg
import requests

try:
    from asyncio import timeout as tmo
except ImportError:
    from async_timeout import timeout as tmo

NO_LIMIT = 0


async def test_survivors(dsn):
    psycopg.connect(dsn, connect_timeout=1)
    psycopg.connect(dsn, connect_timeout=0)  # libpq: 0 waits forever, so no bound
    psycopg.connect(dsn, connect_timeout=NO_LIMIT)  # a NAME resolving to 0 is still judged
    await asyncpg.connect(dsn, timeout=0)  # asyncpg: 0 is an instant timeout
    with httpx.Client() as c:
        c.get("http://127.0.0.1/", timeout=2)
    s: requests.Session = requests.Session()
    s.get("http://127.0.0.1/", timeout=3)
    t = requests.session()
    t.get("http://127.0.0.1/", timeout=4)
    async with asyncio.timeout(delay=5):
        pass
    httpx.stream("GET", "http://127.0.0.1/", timeout=6)
    async with tmo(8):  # both fallback bindings agree on position, kind and index
        pass


class TestBody:
    body_client = requests.Session()

    def test_m(self):
        self.body_client.get("http://127.0.0.1/", timeout=9)  # a class-body client, read as self.body_client


def test_walrus():
    if (w := httpx.Client()):
        w.get("http://127.0.0.1/", timeout=10)
