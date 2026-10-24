#!/usr/bin/env python3
"""Render trusted/templates/*.yml.in into .github/workflows/*.yml.

Directives, each alone on its line:
  {{INCLUDE:<fragment in trusted/templates>}}  replaced by the fragment, verbatim.
  {{INLINE:<repo-relative file>}}              replaced by the file, every line prefixed with the directive's
                                               indentation (a YAML block-scalar heredoc body).
`python3 trusted/render.py` writes; `--check` exits 1 if any committed workflow differs from its render.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "trusted" / "templates"
OUT = ROOT / ".github" / "workflows"
DIRECTIVE = re.compile(r"^(?P<indent>[ ]*)\{\{(?P<kind>INCLUDE|INLINE):(?P<path>[^}]+)\}\}$")


def render(text):
    out = []
    for line in text.splitlines():
        m = DIRECTIVE.match(line)
        if not m:
            out.append(line)
            continue
        if m["kind"] == "INCLUDE":
            out.append(render((TEMPLATES / m["path"]).read_text(encoding="utf-8")).rstrip("\n"))
        else:
            body = (ROOT / m["path"]).read_text(encoding="utf-8")
            if "\t" in body:
                raise SystemExit("%s: tabs cannot be inlined into YAML" % m["path"])
            out.extend((m["indent"] + l) if l else "" for l in body.rstrip("\n").split("\n"))
    return "\n".join(out) + "\n"


# The reusable (caller-invoked) secret scan shares the scan-state recorder, so it is rendered here too.
SHARED = ("secret-scan.yml.in",)


def targets():
    for t in sorted(TEMPLATES.glob("trusted-*.yml.in")) + [TEMPLATES / n for n in SHARED]:
        yield t, OUT / t.name[: -len(".in")]


def main(argv):
    check = "--check" in argv
    stale = []
    for src, dst in targets():
        want = render(src.read_text(encoding="utf-8"))
        if check:
            if not dst.exists() or dst.read_text(encoding="utf-8") != want:
                stale.append(str(dst.relative_to(ROOT)))
        else:
            dst.write_text(want, encoding="utf-8")
    if stale:
        print("stale generated workflows (run python3 trusted/render.py): " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
