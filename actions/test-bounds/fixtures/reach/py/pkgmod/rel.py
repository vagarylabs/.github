import subprocess


def ps2():
    return subprocess.run(["ps", "-e"], timeout=3, check=True)
