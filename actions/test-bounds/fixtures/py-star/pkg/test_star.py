# B4 RED: a star import after the guard may rebind it (the runtime value is 5 s).
import subprocess
LIMIT = 300
from .fast import *  # noqa: F401,F403


def f(cmd):
    subprocess.run(cmd, timeout=LIMIT)
