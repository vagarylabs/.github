# One product-module RED per family reach keeps for Python (a reached module is judged by these rules only).
import subprocess
import threading

import asyncpg
import requests


async def families(p):
    subprocess.run(["x"], timeout=10)
    p.wait(5)
    threading.Thread(target=print).join(8)
    requests.get("http://127.0.0.1/health", timeout=11)
    requests.get("http://127.0.0.1/health", timeout=(3, 12))
    return await asyncpg.connect("postgresql://x", timeout=9)
