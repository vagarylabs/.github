#!/usr/bin/env python3
"""Derive, and drift-check, the read graph of a repo whose packages have no manifest-declared dependencies
(a polyglot monorepo such as vagary-core, where services read each other by PATH, not by import name).

  edges.py derive --config .github/ci-plan.json [--repo .]   prints {"deps": {...}, "readers": {...}}
  edges.py check  --config .github/ci-plan.json [--repo .]   exit 1 if the tree has a read the config lacks

A READ, on a non-comment line of a non-Markdown tracked file that lives in ANOTHER package, is any of:
  - a path literal `<root>/<name>` (roots from config `edge_scan.roots`, e.g. services, apps);
  - a component join `"<root>" / "<name>"` or `"<root>", "<name>"` (pathlib, os.path.join);
  - a relative path `../x/...` that, resolved from the file's directory, lands in another package
    (`new URL("../../tts/...", import.meta.url)`, Go `os.ReadFile("../../../tts/x")`, `file:../x`, `-e ../x`). A literal in a comment is not
a read; one in a docstring or a string IS counted (over-approximation only costs extra test runs, never a
skipped one). `readers` lists, for each non-package top-level directory named in `edge_scan.reader_dirs`,
the packages it reads; the config's job named by `edge_scan.reader_job` must list at least those.

check FAILS on an UNDECLARED read (the plan could skip a suite the change reaches) and on a reader the
reader job omits. A declared dep the scan no longer finds is reported as stale but does not fail: it can
only make the plan run more, and step-level reads (`workspace.extra_deps`) are not scan-derived.
"""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import subprocess
import sys
from pathlib import Path

COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "--")


def scan(repo: Path, cfg: dict) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    es = cfg.get("edge_scan") or {}
    roots = es.get("roots") or ["services", "apps"]
    pkgs = (cfg.get("workspace") or {}).get("packages") or {}
    by_dir = {spec["dir"].rstrip("/"): name for name, spec in pkgs.items()}
    alt = "|".join(re.escape(r) for r in roots)
    pattern = f"({alt})/[A-Za-z0-9_-]+|[\"']({alt})[\"']|\\.\\./"
    excludes = [f":!{x}" for x in (es.get("exclude") or ["*.md", "docs", ".github"])]
    out = subprocess.run(["git", "-C", str(repo), "grep", "-n", "-I", "-E", pattern, "--", ".", *excludes],
                         capture_output=True, text=True)
    if out.returncode not in (0, 1):
        raise SystemExit(f"edges: git grep failed: {out.stderr.strip()}")
    lit = re.compile(r"(?<![\w./-])(?:\.\./)*((?:" + alt + r")/[A-Za-z0-9_-]+)")
    join = re.compile(r"[\"'](" + alt + r")[\"']\s*[/,]\s*[\"']([A-Za-z0-9_-]+)[\"']")
    rel = re.compile(r"(?<![\w.])((?:\.\./)+[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")
    reader_dirs = set(es.get("reader_dirs") or [])
    deps: dict[str, set[str]] = {n: set() for n in pkgs}
    readers: dict[str, set[str]] = {d: set() for d in reader_dirs}
    for line in out.stdout.splitlines():
        path, _, text = line.split(":", 2)
        parts = path.split("/")
        owner = by_dir.get("/".join(parts[:2])) or by_dir.get(parts[0])
        t = text.strip()
        if t.startswith(COMMENT_PREFIXES):
            continue
        targets = set()
        for m in lit.finditer(t):
            if "github.com" in t[max(0, m.start() - 40):m.start()]:
                continue
            targets.add(by_dir.get(m.group(1)))
        for m in join.finditer(t):
            targets.add(by_dir.get(f"{m.group(1)}/{m.group(2)}"))
        for m in rel.finditer(t):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), m.group(1)))
            rparts = resolved.split("/")
            targets.add(by_dir.get("/".join(rparts[:2])) or by_dir.get(rparts[0]))
        for target in targets - {None, owner}:
            if owner:
                deps[owner].add(target)
            elif parts[0] in reader_dirs:
                readers[parts[0]].add(target)
    return deps, readers


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["derive", "check"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--repo", default=".")
    a = ap.parse_args(argv)
    repo = Path(a.repo)
    cfg = json.loads((repo / a.config).read_text())
    deps, readers = scan(repo, cfg)
    if a.mode == "derive":
        print(json.dumps({"deps": {k: sorted(v) for k, v in sorted(deps.items())},
                          "readers": {k: sorted(v) for k, v in sorted(readers.items())}}, indent=1))
        return 0
    pkgs = cfg["workspace"]["packages"]
    extra = (cfg["workspace"].get("extra_deps") or {})
    failures, stale = [], []
    for name, found in deps.items():
        declared = set(pkgs[name].get("deps") or []) | set(extra.get(name) or [])
        for t in sorted(found - declared):
            failures.append(f"undeclared read: {name} reads {t} (add it to workspace.packages.{name}.deps)")
        for t in sorted(set(pkgs[name].get("deps") or []) - found):
            stale.append(f"stale dep: {name} -> {t} (no read found; safe, only runs more)")
    es = cfg.get("edge_scan") or {}
    job = es.get("reader_job")
    if job:
        listed = set(((cfg.get("jobs") or {}).get(job) or {}).get("packages") or [])
        for d, found in readers.items():
            for t in sorted(found - listed):
                failures.append(f"{d}/ reads {t}, but job '{job}' does not list it")
    for s in stale:
        print(s)
    for f in failures:
        print("FAIL " + f)
    print(f"edges: {sum(len(v) for v in deps.values())} reads between {len(deps)} packages; "
          f"{len(failures)} undeclared, {len(stale)} stale")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
