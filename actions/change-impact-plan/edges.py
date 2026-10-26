#!/usr/bin/env python3
"""Derive, and drift-check, the read graph of a repo whose packages have no manifest-declared dependencies
(a polyglot monorepo such as vagary-core, where services read each other by PATH, not by import name).

  edges.py derive --config .github/ci-plan.json [--repo .]   prints {"deps": {...}, "readers": {...}}
  edges.py check  --config .github/ci-plan.json [--repo .]   exit 1 if the tree has a read the config lacks

A READ, on a non-comment line of a non-Markdown tracked file that lives in ANOTHER package, is any of:
  - a path literal `<root>/<name>` (roots from config `edge_scan.roots`, e.g. services, apps);
  - a quoted root literal (`"services"`) classified by the source around it (RootLiteral, below): joined in a path,
    metadata only with positive evidence, a walker root list, or a REFUSAL (which plans FULL);
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

# -I excludes cwd/PYTHONPATH; only this immutable action's own sibling planner may provide graph code.
if sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from plan import declared_packages, discover_pnpm_packages, canonical_digest, graph_digest, sha256_file, glob_to_regex

COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "--")


# ---------- root-literal classification (1.4.1) ----------
# A workspace-root literal ("services", "apps", ...) is read by the source around it, one line at a time:
#   1. In a path, it is joined: after a pathlib `/`, or as an argument of a path call found by BALANCED brackets
#      (join, resolve, joinpath, Path(...)), or in a list spread into one, passed to `sep.join(`, or `.join(`-ed.
#      A literal prefix a package owns reads that package, and when a computed component follows, every package
#      nested beneath it too (F4). A prefix no package owns reads every package beneath it. A `..`, `.parent` or
#      `os.pardir` anywhere after a computed component REFUSES (F5). An unowned path that a caller's inert_globs or
#      extra_edges covers REFUSES, because its change would not plan FULL (F6).
#   2. A comma-listed literal outside a path call is metadata ONLY with positive evidence (an object key or value,
#      SQL VALUES, a subscript), or when its list closes on the line and EVERY sibling is a string literal or a
#      `name=` argument naming no package. A sibling that names a package (under the root, or a package-owning
#      top-level directory) is a read; a list holding only the root is a walker over it. An argv list passed to an
#      exec call refuses.
#   3. EVERYTHING ELSE REFUSES, as 1.4.0 did: a computed sibling, a list that runs past the line, a bare tuple, an
#      unrecognised call. A refusal plans FULL. A literal that is not comma-listed and not in a path stays metadata.
PATH_CALLS = frozenset({"join", "resolve", "joinpath", "Path", "PurePath", "PurePosixPath", "PureWindowsPath"})
EXEC_CALL = re.compile(r"(?:^|\.)(?:subprocess\.\w+|run|call|check_call|check_output|Popen|spawn\w*|exec\w*|fork)$")
NOT_CALLEES = frozenset({"in", "for", "if", "elif", "while", "return", "and", "or", "not", "is", "yield", "await",
                         "else", "case", "of", "typeof", "with", "assert", "lambda"})
HASH_COMMENT = frozenset({"py", "sh", "bash", "zsh", "yml", "yaml", "toml", "rb", "r", "cfg", "ini", "conf"})
SLASH_COMMENT = frozenset({"js", "mjs", "cjs", "ts", "tsx", "jsx", "mts", "cts", "go", "java", "kt", "swift", "rs", "c",
                           "h", "cc", "cpp", "cs", "scss", "css", "dart", "php"})
PARENT_WORDS = frozenset({"pardir", "parent", "parents"})


def line_tokens(t: str, ext: str) -> list[tuple]:
    """(kind, start, end, value) for one source line. kind: str (value = (text, is_plain_literal)), open, close,
    comma, colon, word, op. A trailing comment of the file's language ends the line."""
    out, i, n = [], 0, len(t)
    while i < n:
        ch = t[i]
        if ch.isspace():
            i += 1
            continue
        if (ext in HASH_COMMENT and ch == "#") or (ext in SLASH_COMMENT and t.startswith("//", i)):
            break
        if ext in SLASH_COMMENT and t.startswith("/*", i):
            close = t.find("*/", i + 2)
            if close < 0:
                break
            i = close + 2
            continue
        if ch in "'\"`":
            prefix = ""
            if out and out[-1][0] == "word" and out[-1][2] == i and re.fullmatch(r"[rRbBuUfF]{1,2}", out[-1][3]):
                prefix = out.pop()[3]
            j, computed = i + 1, False
            while j < n and t[j] != ch:
                if t[j] == "\\":
                    j += 2
                    continue
                if ch == "`" and t.startswith("${", j):
                    computed = True
                j += 1
            closed = j < n
            value = t[i + 1:min(j, n)]
            if "f" in prefix.lower() and "{" in value:
                computed = True
            out.append(("str", i, j + 1 if closed else n, (value, closed and not computed)))
            i = j + 1 if closed else n
            continue
        if ch in "([{":
            out.append(("open", i, i + 1, ch))
        elif ch in ")]}":
            out.append(("close", i, i + 1, ch))
        elif ch == ",":
            out.append(("comma", i, i + 1, ch))
        elif ch == ":" and not t.startswith("::", i) and not (out and out[-1][0] == "op" and out[-1][3] == ":"):
            out.append(("colon", i, i + 1, ch))
        else:
            m = re.match(r"[A-Za-z_$][\w$]*|\d[\w.]*", t[i:])
            if m:
                out.append(("word", i, i + len(m.group()), m.group()))
                i += len(m.group())
                continue
            m = re.match(r"\.\.\.|\*\*|==|!=|<=|>=|=>|->|::|[^\w\s]", t[i:])
            out.append(("op", i, i + len(m.group()), m.group()))
            i += len(m.group())
            continue
        i += 1
    return out


def bracket_pairs(toks: list) -> tuple[dict, list]:
    """Matching close index for each open on this line (None when it runs past the line), and for each token the
    stack of opens enclosing it (outermost first)."""
    match, stack, enclosing = {}, [], []
    for k, tok in enumerate(toks):
        enclosing.append(list(stack))
        if tok[0] == "open":
            match[k] = None
            stack.append(k)
        elif tok[0] == "close" and stack:
            match[stack.pop()] = k
    return match, enclosing


def callee(toks: list, k: int) -> str | None:
    """The dotted name immediately before the open bracket at k, if that bracket is a call."""
    j, names = k - 1, []
    while j >= 0 and toks[j][0] == "word":
        names.append(toks[j][3])
        if j >= 1 and toks[j - 1][0] == "op" and toks[j - 1][3] in (".", "?."):
            j -= 2
            continue
        break
    if not names or names[0] in NOT_CALLEES or (j >= 0 and toks[j][0] == "word" and toks[j][3] in ("def", "function")):
        return None
    return ".".join(reversed(names))


def elements(toks: list, e: int | None, match: dict) -> list[tuple[int, int]]:
    """Token ranges of the comma-separated elements directly inside the bracket at e (the whole line when e is None).
    A trailing empty element (after a final comma) is dropped."""
    start = 0 if e is None else e + 1
    stop = len(toks) if e is None or match.get(e) is None else match[e]
    out, depth, first = [], 0, start
    for k in range(start, stop):
        kind = toks[k][0]
        if kind == "open":
            depth += 1
        elif kind == "close":
            depth -= 1
            if depth < 0 and e is None:
                depth = 0
        elif kind == "comma" and depth == 0:
            out.append((first, k))
            first = k + 1
    if first < stop:
        out.append((first, stop))
    return out


def is_literal(toks: list, span: tuple[int, int]) -> str | None:
    a, b = span
    return toks[a][3][0] if b - a == 1 and toks[a][0] == "str" and toks[a][3][1] else None


def is_keyword_arg(toks: list, span: tuple[int, int]) -> bool:
    a, b = span
    return b - a >= 3 and toks[a][0] == "word" and toks[a + 1][0] == "op" and toks[a + 1][3] == "="


def has_parent_step(toks: list, a: int, b: int) -> bool:
    for k in range(a, b):
        tok = toks[k]
        if tok[0] == "word" and tok[3] in PARENT_WORDS and k > 0 and toks[k - 1][0] == "op" and toks[k - 1][3] == ".":
            return True
        if tok[0] == "str" and ".." in tok[3][0].split("/"):
            return True
    return False


MAX_CONTINUATION_LINES = 40


def read_source(repo: Path, path: str, revision: str | None, environment: dict) -> str:
    """The scanned revision's bytes of one file (the working tree's when no revision is pinned)."""
    if revision is None:
        return (repo / path).read_text(errors="replace")
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "show", f"{revision}:{path}"],
                         capture_output=True, timeout=15, env=environment)
    if out.returncode:
        raise ValueError(f"reader scan cannot read {path} at the scanned revision")
    return out.stdout.decode("utf-8", errors="replace")


def logical_line(lines: list[str], index: int, ext: str) -> tuple[list, int] | None:
    """When line `index` sits inside a bracket opened on an earlier line, the tokens of the whole bracketed construct
    (from the line that opens it to the line that closes it) and the offset of line `index`'s first token in them.
    None when no earlier line holds an unclosed bracket within MAX_CONTINUATION_LINES."""
    pending, start = 0, None
    for back in range(index - 1, max(-1, index - 1 - MAX_CONTINUATION_LINES), -1):
        text = lines[back].strip()
        if text.startswith(COMMENT_PREFIXES):
            continue
        for tok in reversed(line_tokens(text, ext)):
            if tok[0] == "close":
                pending += 1
            elif tok[0] == "open":
                if pending:
                    pending -= 1
                else:
                    start = back
                    break
        if start is not None:
            break
    if start is None:
        return None
    toks, offset, depth = [], None, 0
    for line in range(start, min(len(lines), index + 1 + MAX_CONTINUATION_LINES)):
        text = lines[line].strip()
        if text.startswith(COMMENT_PREFIXES):
            continue
        if line == index:
            offset = len(toks)
        for tok in line_tokens(text, ext):
            toks.append(tok)
            depth += {"open": 1, "close": -1}.get(tok[0], 0)
        if line >= index and depth <= 0:
            break
    return toks, offset


class RootLiteral:
    """Classifies the root literals of one source line against one workspace graph."""

    def __init__(self, roots, by_dir, owner, globs, path):
        self.roots, self.by_dir, self.owner, self.globs, self.path = set(roots), by_dir, owner, globs, path

    def refuse(self, why="unsupported"):
        raise ValueError(f"{why} workspace-root reader expression in {self.path}")

    def beneath(self, prefix: str) -> set:
        return {name for directory, name in self.by_dir.items() if directory.startswith(prefix + "/")}

    def resolve(self, components: list[str], dynamic: bool) -> set:
        for component in components:
            if any(part in (".", "..") for part in component.split("/")):
                self.refuse("unresolved")
        prefix = posixpath.normpath("/".join(components))
        found = self.owner(prefix)
        if found is not None:
            return {found} | (self.beneath(prefix) if dynamic else set())  # F4: nested packages under a computed tail
        below = self.beneath(prefix)
        if below:
            return below
        # Unowned content: its change is unmapped and plans FULL, unless a caller's glob maps or inerts it (F6).
        for glob in self.globs:
            static = re.split(r"[*?\[]", glob, 1)[0]
            if glob_to_regex(glob).match(prefix) or static.startswith(prefix + "/") or (static and prefix.startswith(static)):
                self.refuse("unresolved")
        return set()

    def from_elements(self, toks: list, spans: list, mine: int, root: str, open_past_line: bool) -> set:
        components, dynamic = [root], open_past_line
        for span in spans[mine + 1:]:
            value = is_literal(toks, span)
            if dynamic:
                if has_parent_step(toks, *span):
                    self.refuse("unresolved")  # F5: a parent step after a computed component
                continue
            if value is None:
                dynamic = True
                if has_parent_step(toks, *span):
                    self.refuse("unresolved")
                continue
            components.append(value)
        return self.resolve(components, dynamic)

    def from_slash_chain(self, toks: list, k: int, match: dict) -> set:
        components, dynamic, j = [toks[k][3][0]], False, k + 1
        while j + 1 < len(toks) and toks[j][0] == "op" and toks[j][3] == "/":
            operand = toks[j + 1]
            j += 2
            if operand[0] == "str" and operand[3][1]:
                if dynamic:
                    if ".." in operand[3][0].split("/"):
                        self.refuse("unresolved")
                    continue
                components.append(operand[3][0])
                continue
            dynamic = True
            if operand[0] == "open":
                j = (match.get(j - 1) or len(toks) - 1) + 1
            while j < len(toks) and (toks[j][0] == "open" or (toks[j][0] == "op" and toks[j][3] == "." and j + 1 < len(toks))):
                j = ((match.get(j) or len(toks) - 1) + 1) if toks[j][0] == "open" else j + 2
        if dynamic and has_parent_step(toks, j, len(toks)):
            self.refuse("unresolved")  # F5
        return self.resolve(components, dynamic)

    def targets(self, toks: list, k: int, ext: str) -> set:
        root = toks[k][3][0]
        prev = toks[k - 1] if k > 0 else None
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if (nxt and nxt[0] == "op" and nxt[3] == "/") or (prev and prev[0] == "op" and prev[3] == "/"):
            return self.from_slash_chain(toks, k, self.pairs[0])
        match, enclosing = self.pairs
        stack = enclosing[k]
        e = stack[-1] if stack else None
        spans = elements(toks, e, match)
        mine = next((i for i, (a, b) in enumerate(spans) if a <= k < b), None)
        alone = mine is not None and spans[mine] == (k, k + 1)
        kind = toks[e][3] if e is not None else None
        name = callee(toks, e) if kind == "(" else None
        parent = stack[-2] if len(stack) > 1 else None
        parent_name = callee(toks, parent) if parent is not None and toks[parent][3] == "(" else None
        open_past_line = e is not None and match.get(e) is None
        # 1. In a path.
        if name and name.rsplit(".", 1)[-1] in PATH_CALLS and alone:
            return self.from_elements(toks, spans, mine, root, open_past_line)
        if kind in ("(", "[") and name is None and alone:
            joined = (match.get(e) is not None and match[e] + 2 < len(toks) and toks[match[e] + 1][3] == "."
                      and toks[match[e] + 2][3] == "join")
            if (parent_name and parent_name.rsplit(".", 1)[-1] in PATH_CALLS) or joined:
                return self.from_elements(toks, spans, mine, root, open_past_line)
            if parent_name and EXEC_CALL.search(parent_name):
                self.refuse()  # an argv list passed to an exec call
        # 2. Positive metadata evidence.
        if ext == "sql":
            return set()  # SQL text holds values; it never joins a filesystem path
        object_entry = (prev and prev[0] == "colon") or (nxt and nxt[0] == "colon")
        subscript = kind == "[" and e > 0 and ((toks[e - 1][0] == "word" and toks[e - 1][3] not in NOT_CALLEES)
                                               or toks[e - 1][3] in (")", "]"))
        values = kind == "(" and e > 0 and toks[e - 1][0] == "word" and toks[e - 1][3].upper() == "VALUES"
        if subscript or values:
            return set()
        if object_entry:
            return self.named_by_siblings(toks, spans, mine, root, strict=False) if mine is not None else set()
        beside_comma = (nxt is not None and nxt[0] == "comma") or (prev is not None and prev[0] == "comma")
        if e is None:
            if beside_comma:
                self.refuse()  # a bare tuple, or an element of a list that runs across lines
            return set()  # not comma-listed and not in a path: metadata, as 1.4.0 treated it
        if not alone:
            return set()
        if len(spans) == 1 and not beside_comma:
            # ["services"], {"services"}: a collection holding only the root is a walker over it. ("services") is a
            # parenthesised literal, not a tuple: metadata.
            return self.beneath(root) if kind in ("[", "{") else set()
        # 3. A comma-listed literal outside a path call.
        if open_past_line:
            self.refuse()  # a list that runs past the line
        return self.named_by_siblings(toks, spans, mine, root, strict=True)

    def named_by_siblings(self, toks: list, spans: list, mine: int, root: str, strict: bool) -> set:
        """Packages named by the literal siblings of a listed root literal. strict: every sibling must be a string
        literal or a `name=` argument, else REFUSE; an object entry's computed siblings are allowed."""
        reads, others = set(), [span for i, span in enumerate(spans) if i != mine]
        if strict and not others:
            return self.beneath(root)  # ("services",), ["services"], {"services"}: a walker over the root
        for span in others:
            value = is_literal(toks, span)
            if value is None:
                if strict and not is_keyword_arg(toks, span):
                    self.refuse()
                continue
            if any(part in (".", "..") for part in value.split("/")):
                continue
            joined = posixpath.normpath(root + "/" + value)
            found = self.owner(joined)
            if found is not None:
                reads.add(found)
            reads |= self.beneath(joined)
            top = value.split("/", 1)[0]
            if value in self.roots or self.beneath(top) and "/" not in value:
                reads |= self.beneath(root) | self.beneath(value)  # another package-owning top-level directory
        return reads


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
    rel = re.compile(r"(?<![\w.])((?:\.\./)+[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")
    reader_dirs = set(es.get("reader_dirs") or [])
    globs = list(cfg.get("inert_globs") or []) + list((cfg.get("extra_edges") or {}).keys())
    classify = RootLiteral(roots, by_dir, owner, globs, "")
    file_lines: dict[str, list[str]] = {}
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
            targets.add(owner(m.group(1)))
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        toks = line_tokens(t, ext)
        hits = [k for k, tok in enumerate(toks)
                if tok[0] == "str" and tok[3][1] and tok[3][0] in classify.roots and t[tok[1]] in "'\""]
        if hits:
            classify.path, offset = path, 0
            pairs = bracket_pairs(toks)
            if any(not pairs[1][k] for k in hits):
                # A literal outside every bracket on its own line may sit in a construct opened on an earlier line.
                if path not in file_lines:
                    file_lines[path] = read_source(repo, path, revision, environment).splitlines()
                joined = logical_line(file_lines[path], int(number) - 1, ext)
                if joined is not None:
                    toks, offset = joined
                    pairs = bracket_pairs(toks)
            classify.pairs = pairs
            for k in hits:
                targets |= classify.targets(toks, k + offset, ext)
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


def assess(pkgs: dict, cfg: dict, deps: dict, readers: dict, *, revision: str | None, config_path: Path) -> dict:
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
    result = {"schema": 1, "status": "unmatched" if failures else "matched", "revision": revision,
              "coverage": "supported-static-readers-only", "policy_config_sha256": sha256_file(config_path),
              "graph_sha256": graph_digest(pkgs), "scanner_source_sha256": sha256_file(Path(__file__)),
              "deps": {name: sorted(values) for name, values in sorted(deps.items())},
              "readers": {name: sorted(values) for name, values in sorted(readers.items())},
              "failures": failures, "stale": stale}
    result["assessment_sha256"] = canonical_digest(result)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["derive", "check"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest-root", help="trusted base workspace metadata")
    ap.add_argument("--revision", help="immutable candidate commit for source reads")
    ap.add_argument("--out-json", help="write the same supported-reader check as a bound assessment")
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
    assessment = assess(pkgs, cfg, deps, readers, revision=a.revision, config_path=repo / a.config)
    failures, stale = assessment["failures"], assessment["stale"]
    if a.out_json:
        Path(a.out_json).write_text(json.dumps(assessment, sort_keys=True) + "\n")
    for s in stale:
        print(s)
    for f in failures:
        print("FAIL " + f)
    print(f"edges: {sum(len(v) for v in deps.values())} reads between {len(deps)} packages; "
          f"{len(failures)} undeclared, {len(stale)} stale")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
