# K14 RED: `from guards import G` is absolute, so it is not resolved.
import subprocess
from guards import G


def f(cmd):
    subprocess.run(cmd, timeout=G)
