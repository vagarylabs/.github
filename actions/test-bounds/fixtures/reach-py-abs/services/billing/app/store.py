import subprocess


def boot():
    return subprocess.run(["psql"], timeout=2)
