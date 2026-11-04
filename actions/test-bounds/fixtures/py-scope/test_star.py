# K2 step 2A RC2 (B1): a star import of a covered module binds each covered name it exports. Four REDs.
from asyncio import *
from asyncpg import *
from psycopg_pool import *


async def test_star(coro, dsn):
    await wait_for(coro, 1)
    async with timeout(2):
        pass
    await create_pool(dsn, timeout=3)
    AsyncConnectionPool(dsn, timeout=4)
