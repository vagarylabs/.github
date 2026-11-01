# One RED per python rule: each bound below the subprocess floor (seconds).
import subprocess


def run(cmd, timeout=45):
    return subprocess.run(cmd, timeout=10)


def reap(p):
    p.wait(5)
    p.communicate(None, 6)
