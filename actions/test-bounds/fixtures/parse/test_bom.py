# A UTF-8 BOM is not code: the file parses, and its bound is found.
import subprocess
subprocess.run(['x'], timeout=10)
