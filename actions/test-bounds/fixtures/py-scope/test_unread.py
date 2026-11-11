# K2 step 2A RC2 (B3): a call into a covered library that this check cannot read is listed NOT COVERED, never
# dropped. Three REDs (the submodule and vendored spellings and importlib.import_module(...).get, which are read) and five
# NOT COVERED rows.
import functools
import importlib
import urllib.request

import aiohttp
import requests
from pip._vendor import requests as vendored

from .shared import *

A = ("http://127.0.0.1/", None, 1)


async def test_unread(coro):
    getattr(requests, "get")("http://127.0.0.1/", timeout=1)
    importlib.import_module("requests").get("http://127.0.0.1/", timeout=2)
    functools.partial(requests.get, timeout=3)
    urllib.request.urlopen(*A)
    async with aiohttp.ClientSession() as session:
        await session.get("http://127.0.0.1/", timeout=aiohttp.ClientTimeout(total=4))
    requests.api.get("http://127.0.0.1/", timeout=5)
    vendored.get("http://127.0.0.1/", timeout=6)
    await wait_for(coro, 7)  # may come from `from .shared import *`
