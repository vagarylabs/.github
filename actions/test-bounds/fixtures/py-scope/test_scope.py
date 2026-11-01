# K2 step 2A RC2 (root's #65 delta B2): a name means what the nearest enclosing scope that binds it says. Each line
# marked RED is one finding.
import subprocess
from asyncio import wait_for as gwf
from asyncio import wait_for as wf_mod

_proc = None


async def gather_all(fs):
    from asyncio import wait
    return await wait(fs)  # asyncio's: its first argument is the awaitables, no bound


async def helper(fs):
    from asyncio import wait
    await wait(fs, timeout=5)  # RED: a condition wait


def test_proc_kw():
    proc = subprocess.Popen(["sleep", "1"])
    wait = proc.wait
    wait(timeout=90)  # RED: this function's own subprocess wait, at the 120 s floor


def test_proc_positional():
    proc = subprocess.Popen(["sleep", "1"])
    wait = proc.wait
    wait(5)  # RED


def test_proc_param(wait):
    wait(7)  # RED


async def mixed(coro, helper_fn):
    from asyncio import wait_for
    wait_for = helper_fn
    await wait_for(coro, 1)  # NOT COVERED: an import and an assignment share this scope


class TestClassBody:
    wf_mod = None  # a class attribute: the class body never encloses its methods

    async def test_method(self, coro):
        await wf_mod(coro, 9)  # RED: the module's asyncio.wait_for


def test_a_global_handle():
    global _proc
    _proc = subprocess.Popen(["sleep", "1"])
    _proc.wait(timeout=3)  # RED: the module's subprocess handle, declared global


async def test_a_global_import(coro):
    global gwf
    await gwf(coro, 4)  # RED: the module's asyncio.wait_for
