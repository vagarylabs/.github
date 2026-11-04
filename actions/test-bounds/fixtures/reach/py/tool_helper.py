import subprocess

import tool_defaults


def ps():
    return subprocess.run(["ps"], timeout=2, check=True)
