import subprocess


def reap(p):
    p.kill()
    p.communicate(timeout=5)  # timeout under test: reap after kill
