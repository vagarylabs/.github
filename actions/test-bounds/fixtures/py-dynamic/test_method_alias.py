# Root's #65 review B3: a covered call bound to a name (`wf = asyncio.wait_for`) is read where the name is called.
import asyncio


async def test_alias(c):
    wf = asyncio.wait_for
    await wf(c, 0.5)


async def test_control(proc):
    w = proc.wait  # a subprocess wait alias is no covered call: no finding
    await w(0.5)
