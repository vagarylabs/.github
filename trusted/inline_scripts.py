#!/usr/bin/env python3
"""The run scripts of a workflow, as actionlint hands them to shellcheck: every `run: |` body, dedented, its
trailing blank lines clipped as YAML clips them.

`python3 trusted/inline_scripts.py sizes <workflow>...` prints, per workflow, the bytes of its largest run script:
the number actionlint's shellcheck stdin limit (the 65536-byte pipe buffer) applies to. ci.yml's required actionlint
job writes it to the step summary; test_trusted.py shellchecks the same scripts that run_scripts() returns.
"""
import pathlib
import re
import sys

PIPE_BUFFER = 65536
_RUN = re.compile(r"\n( +)run: \|\n((?:\1  .*\n|\n)+)")


def run_scripts(text):
    out = []
    for m in _RUN.finditer(text):
        ind = len(m.group(1)) + 2
        out.append("".join(l[ind:] + "\n" for l in m.group(2).split("\n")[:-1]).rstrip("\n") + "\n")
    return out


def largest(text):
    return max((len(s.encode("utf-8")) for s in run_scripts(text)), default=0)


def main(argv):
    if len(argv) < 2 or argv[0] != "sizes":
        print("usage: inline_scripts.py sizes <workflow>...", file=sys.stderr)
        return 2
    for path in argv[1:]:
        size = largest(pathlib.Path(path).read_text(encoding="utf-8"))
        print("- `%s`: largest inline run script %d bytes (the shellcheck stdin pipe buffer is %d)"
              % (path, size, PIPE_BUFFER))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
