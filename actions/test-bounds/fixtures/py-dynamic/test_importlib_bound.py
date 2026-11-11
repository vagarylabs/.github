# Root's #65 review B3: a covered module loaded by importlib and bound to a name is read like the import.
import importlib


async def test_bound(c):
    mod = importlib.import_module("asyncio")
    await mod.wait_for(c, 0.5)
