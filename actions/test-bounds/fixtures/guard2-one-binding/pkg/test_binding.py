# Guard 2 (python): an augmented assignment at the source is RED; one module-level assignment is GREEN.
import subprocess
from .aug import LIMIT
from .one import GUARD


def f(cmd):
    subprocess.run(cmd, timeout=LIMIT)
    subprocess.run(cmd, timeout=GUARD)
