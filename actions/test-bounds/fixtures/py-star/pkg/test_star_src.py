# B4 RED: the source's star import may rebind GUARD.
import subprocess
from .one import GUARD


def f(cmd):
    subprocess.run(cmd, timeout=GUARD)
