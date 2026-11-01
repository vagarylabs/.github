# K2 step 2A RC2 (B1): a re-export from a local module is followed one hop. Three REDs and one NOT COVERED.
from pkg.helpers import wait_for as wf

from .helpers import client, request, twice, wait_for


async def test_reexport(coro):
    await wait_for(coro, 1)
    await wf(coro, 2)
    client.get("http://127.0.0.1/", timeout=3)
    twice("http://127.0.0.1/", timeout=4)  # NOT COVERED: the local module binds it twice
    request("/x", timeout=5)  # the local module's own function: neither read nor listed
