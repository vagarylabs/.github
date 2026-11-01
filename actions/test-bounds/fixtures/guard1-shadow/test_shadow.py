# Guard 1 RED (python): the name is assigned again inside a function.
import subprocess
LIMIT = 300


def f(cmd):
    LIMIT = 5
    return subprocess.run(cmd, timeout=LIMIT)
