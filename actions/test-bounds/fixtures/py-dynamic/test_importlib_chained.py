# Root's #65 review B3: the chained form, importlib.import_module("asyncio").wait_for, is read.
import importlib


async def test_chained(c):
    await importlib.import_module("asyncio").wait_for(c, 0.5)
