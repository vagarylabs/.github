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
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path

from plan import declared_packages, discover_pnpm_packages

COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "--")


def workspace_graph(root: Path, cfg: dict) -> dict[str, dict]:
    workspace = cfg.get("workspace") or {}
    if workspace.get("type") == "pnpm":
        return discover_pnpm_packages(root, workspace.get("extra_deps"))
    if workspace.get("type") == "declared":
        return declared_packages(workspace)
    raise ValueError("reader graph requires declared or pnpm workspace")


def scan(repo: Path, cfg: dict, *, manifest_root: Path | None = None, revision: str | None = None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    es = cfg.get("edge_scan") or {}
    roots = es.get("roots") or ["services", "apps"]
    pkgs = workspace_graph(manifest_root or repo, cfg)
    by_dir = {spec["dir"].rstrip("/"): name for name, spec in pkgs.items()}
    ordered_dirs = sorted(by_dir, key=len, reverse=True)

    def owner(path):
        for directory in ordered_dirs:
            if path == directory or path.startswith(directory + "/"):
                return by_dir[directory]
        return None

    alt = "|".join(re.escape(r) for r in roots)
    pattern = f"({alt})/[A-Za-z0-9_-]+|[\"']({alt})[\"']|\\.\\./"
    excludes = [f":!{x}" for x in (es.get("exclude") or ["*.md", "docs", ".github"])]
    if revision is not None and not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("reader scan revision must be an immutable commit")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "--null", "-n", "-I", "-E", pattern,
                          *([revision] if revision else []), "--", ".", *excludes],
                         capture_output=True, text=True, timeout=15, env=environment)
    if out.returncode not in (0, 1):
        raise SystemExit(f"edges: git grep failed (exit {out.returncode})")
    lit = re.compile(r"(?<![\w./-])(?:\.\./)*((?:" + alt + r")(?:/[A-Za-z0-9_.-]+)+)")
    join_root = re.compile(r"[\"'](" + alt + r")[\"']")
    component = re.compile(r"([\"'])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)\1")
    rel = re.compile(r"(?<![\w.])((?:\.\./)+[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")
    reader_dirs = set(es.get("reader_dirs") or [])
    deps: dict[str, set[str]] = {n: set() for n in pkgs}
    readers: dict[str, set[str]] = {d: set() for d in reader_dirs}
    remaining = out.stdout
    while remaining:
        path, separator, remaining = remaining.partition("\0")
        number, second, remaining = remaining.partition("\0")
        text, newline, remaining = remaining.partition("\n")
        if not separator or not second or not number.isdigit():
            raise ValueError("incomplete reader scan output")
        if revision:
            prefix = revision + ":"
            if not path.startswith(prefix):
                raise ValueError("reader scan revision mismatch")
            path = path[len(prefix):]
        parts = path.split("/")
        reader = owner(path)
        t = text.strip()
        if t.startswith(COMMENT_PREFIXES):
            continue
        targets = set()
        for m in lit.finditer(t):
            if "github.com" in t[max(0, m.start() - 40):m.start()]:
                continue
            targets.add(owner(m.group(1)))
        for m in join_root.finditer(t):
            cursor, components = m.end(), [m.group(1)]
            joined = False
            while True:
                separator = re.match(r"\s*([/,])\s*", t[cursor:])
                if not separator:
                    break
                joined = True
                cursor += separator.end()
                part = component.match(t, cursor)
                if part is None:
                    raise ValueError(f"unsupported workspace-root reader expression in {path}")
                components.append(part.group(2))
                cursor = part.end()
            # A root alone is metadata unless used as a path-construction argument.
            constructed = re.search(r"(?:\.join|\.resolve|joinpath)\([^)]*$", t[:m.start()])
            if joined or constructed:
                resolved = posixpath.normpath("/".join(components))
                target = owner(resolved)
                if target is None or any(part in (".", "..") for item in components for part in item.split("/")):
                    raise ValueError(f"unresolved workspace-root reader expression in {path}")
                targets.add(target)
        for m in rel.finditer(t):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), m.group(1)))
            targets.add(owner(resolved))
        for target in targets - {None, reader}:
            if reader:
                deps[reader].add(target)
            elif parts[0] in reader_dirs:
                readers[parts[0]].add(target)
            else:
                readers.setdefault("<unmapped>", set()).add(target)
    return deps, readers


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["derive", "check"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest-root", help="trusted base workspace metadata")
    ap.add_argument("--revision", help="immutable candidate commit for source reads")
    a = ap.parse_args(argv)
    repo = Path(a.repo)
    cfg = json.loads((repo / a.config).read_text())
    manifest_root = Path(a.manifest_root) if a.manifest_root else repo
    deps, readers = scan(repo, cfg, manifest_root=manifest_root, revision=a.revision)
    if a.mode == "derive":
        print(json.dumps({"deps": {k: sorted(v) for k, v in sorted(deps.items())},
                          "readers": {k: sorted(v) for k, v in sorted(readers.items())}}, indent=1))
        return 0
    pkgs = workspace_graph(manifest_root, cfg)
    failures, stale = [], []
    if readers.get("<unmapped>"):
        failures.append("unmapped source readers require a declared obligation: " + ", ".join(sorted(readers["<unmapped>"])))
    for name, found in deps.items():
        declared = set(pkgs[name].get("deps") or [])
        for t in sorted(found - declared):
            failures.append(f"undeclared read: {name} reads {t} (add it to workspace.packages.{name}.deps)")
        for t in sorted(set(pkgs[name].get("deps") or []) - found):
            stale.append(f"stale dep: {name} -> {t} (no read found; safe, only runs more)")
    es = cfg.get("edge_scan") or {}
    job = es.get("reader_job")
    for directory, found in readers.items():
        if not found or directory == "<unmapped>":
            continue
        rule = (cfg.get("jobs") or {}).get(job) if job else None
        if rule == "always":
            continue
        listed = rule.get("packages") if isinstance(rule, dict) else None
        if not isinstance(listed, list) or any(not isinstance(name, str) or name not in pkgs for name in listed):
            failures.append(f"{directory}/ has source readers but no valid declared reader job")
            continue
        for target in sorted(found - set(listed)):
            failures.append(f"{directory}/ reads {target}, but job '{job}' does not list it")
    for s in stale:
        print(s)
    for f in failures:
        print("FAIL " + f)
    print(f"edges: {sum(len(v) for v in deps.values())} reads between {len(deps)} packages; "
          f"{len(failures)} undeclared, {len(stale)} stale")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
