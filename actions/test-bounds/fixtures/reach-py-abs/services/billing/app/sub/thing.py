import subprocess


def go():
    return subprocess.run(["x"], timeout=3)
