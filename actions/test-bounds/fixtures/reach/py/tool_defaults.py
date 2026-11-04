import subprocess


def poll(cmd, timeout=5):
    return subprocess.run(cmd, timeout=timeout, check=False)
