import subprocess


def ps3():
    return subprocess.run(["ps", "-A"], timeout=4, check=True)
