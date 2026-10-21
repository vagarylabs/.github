#!/usr/bin/env python3
"""The guard embedded in .github/workflows/no-hosted-runners.yml must be byte-identical to scripts/no_hosted_runners.py,
and must contain no literal expression opener (GitHub would substitute it inside `run:`). --write regenerates."""
import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
WF = ROOT / ".github/workflows/no-hosted-runners.yml"
SRC = (ROOT / "scripts/no_hosted_runners.py").read_text().rstrip("\n")
OPEN, CLOSE = "<<'GUARD'\n", "\n          GUARD"
def embedded(text):
    body = text.split(OPEN, 1)[1].split(CLOSE, 1)[0]
    return "\n".join(l[10:] if l.startswith("          ") else l for l in body.split("\n"))
text = WF.read_text()
if "$" + "{{" in SRC:
    sys.exit("scripts/no_hosted_runners.py contains a literal expression opener; GitHub would substitute it inside run:")
if "--write" in sys.argv:
    head, rest = text.split(OPEN, 1)
    tail = rest.split(CLOSE, 1)[1]
    WF.write_text(head + OPEN + "\n".join(("          " + l) if l else "" for l in SRC.split("\n")) + CLOSE + tail)
    print("rewrote the embedded guard"); sys.exit(0)
if embedded(text) != SRC:
    sys.exit("the guard embedded in no-hosted-runners.yml differs from scripts/no_hosted_runners.py; run with --write")
print("embedded guard matches scripts/no_hosted_runners.py")
