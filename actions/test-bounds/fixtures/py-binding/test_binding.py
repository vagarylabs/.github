# K2 step 2A RC (root's #65 B2, B3, L3): bounds read by binding, through import aliases, bare imported names and
# client instances. Each bound below is RED unless its comment says otherwise.
import threading
import urllib.request
from asyncio import wait, wait_for
from urllib.request import urlopen

import httpx
import psycopg2
import requests as r
from pytest import mark

SHORT = 5


class Api:
    def __init__(self):
        self.s = httpx.Client()

    def ping(self):
        return self.s.get("http://127.0.0.1/health", timeout=4)


async def waits(coro, tasks, opts):
    await wait_for(coro, 3)
    r.get("http://127.0.0.1/health", timeout=(3, 10))  # two: connect and read
    r.get("http://127.0.0.1/health", timeout=(3, None))  # one: None is no read bound
    s = r.Session()
    s.get("http://127.0.0.1/health", timeout=6)
    r.Session().get("http://127.0.0.1/health", timeout=7)
    urllib.request.urlopen("http://127.0.0.1/", None, 8)
    urlopen("http://127.0.0.1/", timeout=9)
    psycopg2.connect("dbname=x", connect_timeout=10)
    threading.Thread(target=print).join(2 * 2)
    threading.Thread(target=print).join(SHORT)
    threading.Thread(target=print).join(timeout=UNKNOWN)  # a keyword join is never str.join
    ", ".join(UNKNOWN)  # not a number: str.join, no finding
    await wait(tasks)  # asyncio.wait's awaitables, no finding
    r.get("http://127.0.0.1/health", **opts)  # NOT COVERED: the bound may come through the splat
    r.get("http://127.0.0.1/health", timeout=11, **opts)


@mark.timeout(12)
def test_marked():
    pass
