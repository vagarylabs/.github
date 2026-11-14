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
import bisect
import contextlib
import datetime
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import threading
import types
from pathlib import Path


def _plan_module():
    """plan.py, the sibling planner from this same immutable action directory, compiled from its SOURCE and never
    through the import system. An import (the old `sys.path.insert` + `from plan import ...` under -I) writes
    __pycache__/plan.cpython-*.pyc into the runner's shared action cache and reads one back, so a bytecode file planted
    there by an earlier job on a persistent self-hosted runner would run in place of the source (root's review of
    .github #52, N2). -I already keeps cwd and PYTHONPATH out. A test that has imported plan.py itself (the same
    file) shares that module."""
    path = Path(__file__).resolve().parent / "plan.py"
    loaded = sys.modules.get("plan")
    if loaded is not None and getattr(loaded, "__file__", None) and Path(loaded.__file__).resolve() == path:
        return loaded
    module = types.ModuleType("plan")
    module.__file__ = str(path)
    sys.modules["plan"] = module  # its dataclasses and annotations resolve their module by name
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


_plan = _plan_module()
declared_packages, discover_pnpm_packages, canonical_digest = _plan.declared_packages, _plan.discover_pnpm_packages, _plan.canonical_digest
graph_digest, sha256_file, glob_to_regex = _plan.graph_digest, _plan.sha256_file, _plan.glob_to_regex
first_match, classify_paths, rule_matches, LOCKFILE_NAMES = _plan.first_match, _plan.classify_paths, _plan.rule_matches, _plan.LOCKFILE_NAMES
run_git, READER_TIMEOUT = _plan.run_git, _plan.READER_TIMEOUT  # git calls: a scaled ceiling, one retry (1.7.3)

COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "--")


# ---------- root-literal classification (1.4.1) ----------
# A workspace-root literal ("services", "apps"; also "./services", "services/" and a backtick string with no
# substitution) is classified from the WHOLE FILE's token structure, never from one line. Root's principle
# (2026-10-26): METADATA needs POSITIVE evidence; EVERYTHING ELSE REFUSES, and a refusal plans FULL.
#   1. READ, in a path: after a pathlib `/`, or ALONE as an argument of a path call (join, resolve, joinpath,
#      Path(...)), or in a list spread into one (`*[...]`, `...[...]`), the sole argument of `sep.join(...)`, or
#      `[...].join(...)`. Literal components that follow are joined. A computed or glob component, or a walk (glob,
#      rglob, iterdir, walk, ...) of the result, also reads every package beneath the literal prefix (F4). A parent step
#      (`..`, `.parent`, `os.pardir`, `dirname`) after the root anywhere in its statement, or a parent-step call around
#      it, REFUSES (F5). An unowned path that a caller's inert_globs or extra_edges covers REFUSES (F6).
#   2. READ, as a walker: a collection holding only the root, a loop over a collection holding it, or a method called on
#      such a collection reads every package beneath the root; a sibling naming another package-owning top-level
#      directory reads beneath that too.
#   3. METADATA only with positive evidence: an object key or value (never a ternary branch), a subscript key, a
#      comparison (`==`, `in`, `case`), a .sql file, or a list/tuple/set of literals that is ASSIGNED (`X = [...]`), an
#      object value, compared, or nested in such a collection. Never a direct argument of a call: `make("services",
#      v=1)` refuses (root, 2026-10-26).
#   4. EVERYTHING ELSE REFUSES: a root not alone in a path argument, inside a computed string (f-string, template, SQL
#      text, a docstring), a subscripted collection in a path call, an argv list of an exec call, a call argument, a
#      default parameter, a bare assignment, and any file whose language or bracket structure the tokenizer cannot
#      trust.
PY_EXT = frozenset({"py", "pyi"})
JS_EXT = frozenset({"js", "mjs", "cjs", "ts", "tsx", "jsx", "mts", "cts"})
STRUCTURED = PY_EXT | JS_EXT | {"json"}
PATH_CALLS = frozenset({"join", "resolve", "joinpath", "Path", "PurePath", "PurePosixPath", "PureWindowsPath"})
EXEC_CALL = re.compile(r"(?:^|\.)(?:subprocess\.\w+|run|call|check_call|check_output|Popen|spawn\w*|exec\w*|fork)$")
LITERAL_WORDS = frozenset({"null", "undefined", "true", "false", "None", "True", "False", "NaN", "Infinity"})
KEYWORDS = frozenset({"in", "for", "if", "elif", "while", "return", "and", "or", "not", "is", "yield", "await", "else",
                      "case", "of", "typeof", "with", "assert", "lambda", "switch", "catch", "throw", "delete", "void",
                      "instanceof", "do", "from", "import", "export", "default", "print"})
JS_REGEX_AFTER = frozenset({"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw",
                            "instanceof", "yield", "await"})
OBJECT_AFTER = frozenset({"return", "typeof", "yield", "await", "case", "in", "of", "new", "delete", "void", "throw",
                          "default", "instanceof"})
PARENT_WORDS = frozenset({"pardir", "parent", "parents", "dirname"})
WALK_WORDS = frozenset({"glob", "rglob", "iglob", "iterdir", "walk", "fwalk", "scandir", "listdir", "readdir",
                        "readdirSync", "opendir", "opendirSync", "globSync", "walkSync"})
COMPARE = frozenset({"==", "!=", "===", "!=="})
CONT_OPS = frozenset({"\\", "+", "-", "*", "/", "%", "|", "&", "^", "||", "&&", "??", "=", "=>", "?", ".", "?.",
                      "==", "===", "!=", "!==", "<", ">", "<=", ">=", "**"})
CONT_WORDS = frozenset({"and", "or", "not", "in", "instanceof"})
PAIR = {"(": ")", "[": "]", "{": "}"}
PARENT_SEG = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")
PARENT_STEP = re.compile(r"(?<![.\w])\.\.(?![.\w])")  # `..` as a step, never `...` or `a..b`
GENERATED_CWD = "\0generated"  # an untracked directory component beneath a tracked start (parent_step_landings)
PERCENT_FIELD = r"%(?:\([^)]*\))?[-+ #0]*\d*(?:\.\d+)?[A-Za-z]"  # a %-format field, flags/width/precision included
PERCENT_RE = re.compile(PERCENT_FIELD)
# A parent step inside a substitution. A single `'.'` is a separator (`.split('.')`), never a step; dots build one only
# as `..`, repeated (`'.' * 2`) or concatenated (`'.' + '.'`).
SUB_PARENT = re.compile(r"(?<![.\w])\.\.(?![.\w])|\.parents?\b|\bpardir\b|\bdirname\s*\("
                        r"|(['\"])\.\.+\1|(['\"])\.+\2\s*[*+]|[*+]\s*(['\"])\.+\3")
SUB_NAME = re.compile(r"(?<![\w$])(\.?)([A-Za-z_$][\w$]*)")


def substitutions(body: str, js: bool) -> list[str]:
    """The expressions a computed string interpolates: Python `{expr}` (never `{{`), JS `${expr}`, nesting kept."""
    out, i, n = [], 0, len(body)
    while i < n:
        if js:
            k = body.find("${", i)
            if k < 0:
                break
            j = k + 2
        else:
            k = body.find("{", i)
            if k < 0:
                break
            if body.startswith("{{", k):
                i = k + 2
                continue
            j = k + 1
        depth, start, quote = 1, j, None
        while j < n and depth:
            ch = body[j]
            if quote:
                quote = None if ch == quote else quote
            elif ch in "'\"`":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            j += 1
        out.append(body[start:j - 1] if not depth else body[start:])
        i = j
    return out


# A path relative to the file: `../` steps then literal segments (`../app/api/x/`); the `rel` rule reads it exactly.
REL_RUN = re.compile(r"(?:\.\./)+(?:[A-Za-z0-9_.-]+/)*")
BARE_WORD_GREP = "|(^|[^A-Za-z0-9_.-])({alt})([^A-Za-z0-9_.-]|$)"
BARE_WORD_GREP = "|(^|[^A-Za-z0-9_.-])({alt})([^A-Za-z0-9_.-]|$)"
PARENT_WORD = re.compile(r"\b(?:pardir|parents?|dirname)\b")
GLOB_CHARS = re.compile(r"[*?\[\]{}]")
_SPACE = re.compile(r"\s+")
_WORD = re.compile(r"[^\W\d][\w$]*|\$[\w$]*|\d[\w.]*")
_OPS = re.compile(r"\.\.\.|===|!==|\*\*|==|!=|<=|>=|=>|->|::|:=|\?\.|\?\?|&&|\|\||[^\w\s]")
_PY_PREFIX = re.compile(r"[rRbBuUfFtT]{1,2}")


def _skip_quoted(text: str, i: int, q: str, multiline: bool) -> int | None:
    """End offset past the closing `q` of the string opened at i; None when a one-line string meets its line's end."""
    j, n = i + len(q), len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text.startswith(q, j):
            return j + len(q)
        if not multiline and text[j] == "\n":
            return None
        j += 1
    return None


def _skip_template(text: str, i: int) -> tuple[int | None, bool]:
    """End offset past the backtick that closes the template opened at i, and whether it holds a substitution."""
    j, n, computed = i + 1, len(text), False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1, computed
        if text.startswith("${", j):
            computed, depth, j = True, 1, j + 2
            while j < n and depth:
                c = text[j]
                if c in "'\"":
                    j = _skip_quoted(text, j, c, False) or j + 1
                    continue
                if c == "`":
                    j, _ = _skip_template(text, j)
                    if j is None:
                        return None, True
                    continue
                depth += {"{": 1, "}": -1}.get(c, 0)
                j += 1
            continue
        j += 1
    return None, True


def file_tokens(text: str, ext: str) -> tuple[list, list, bool]:
    """(code, comments, ok) over a whole file, with absolute offsets. code holds (kind, start, end, value) tokens:
    str (value = (body, plain, quote_offset)), regex, open, close, comma, colon, word, op. comments holds (start, end)
    spans. ok is False when a multi-line string, template or comment never closes."""
    py, js = ext in PY_EXT, ext in JS_EXT
    code, comments, ok, i, n = [], [], True, 0, len(text)
    while i < n:
        m = _SPACE.match(text, i)
        if m:
            i = m.end()
            continue
        ch = text[i]
        if (py and ch == "#") or (not py and text.startswith("//", i)):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, j))
            i = j
            continue
        if not py and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                comments.append((i, n))
                return code, comments, False
            comments.append((i, j + 2))
            i = j + 2
            continue
        if ch in "'\"" or (js and ch == "`"):
            start, prefix = i, ""
            if py and code and code[-1][0] == "word" and code[-1][2] == i and _PY_PREFIX.fullmatch(code[-1][3]):
                prefix = code[-1][3]
                start = code.pop()[1]
            if ch == "`":
                end, computed = _skip_template(text, i)
                if end is None:
                    code.append(("str", start, n, (text[i + 1:], False, i)))
                    return code, comments, False
                code.append(("str", start, end, (text[i + 1:end - 1], not computed, i)))
                i = end
                continue
            q = ch * 3 if py and text.startswith(ch * 3, i) else ch
            end = _skip_quoted(text, i, q, multiline=len(q) == 3)
            if end is None:
                if len(q) == 3:
                    code.append(("str", start, n, (text[i + 3:], False, i)))
                    return code, comments, False
                code.append(("op", i, i + 1, ch))  # an unterminated one-line quote (JSX text such as `don't`)
                i += 1
                continue
            body = text[i + len(q):end - len(q)]
            computed = ("f" in prefix.lower() or "t" in prefix.lower()) and "{" in body
            code.append(("str", start, end, (body, not computed, i)))
            i = end
            continue
        if js and ch == "/" and not text.startswith("/>", i) and not (code and code[-1][3] == "<" and code[-1][2] == i):
            # (`</tag>` and `/>` are JSX, never a regex.)
            prev = code[-1] if code else None
            if (prev is None or prev[0] in ("open", "comma", "colon") or (prev[0] == "op" and prev[3] not in ("++", "--"))
                    or (prev[0] == "word" and prev[3] in JS_REGEX_AFTER)):
                j, in_class = i + 1, False
                while j < n and text[j] != "\n":
                    c = text[j]
                    if c == "\\":
                        j += 2
                        continue
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        break
                    j += 1
                if j < n and text[j] == "/":
                    flags = re.compile(r"[A-Za-z]*").match(text, j + 1).end()
                    code.append(("regex", i, flags, None))
                    i = flags
                    continue
        if ch in "([{":
            code.append(("open", i, i + 1, ch))
        elif ch in ")]}":
            code.append(("close", i, i + 1, ch))
        elif ch == ",":
            code.append(("comma", i, i + 1, ch))
        else:
            m = _WORD.match(text, i) or _OPS.match(text, i)
            tok = m.group()
            kind = "word" if _WORD.fullmatch(tok) else ("colon" if tok == ":" else "op")
            code.append((kind, i, m.end(), tok))
            i = m.end()
            continue
        i += 1
    return code, comments, ok


def structure(code: list) -> tuple[dict, list, bool]:
    """(match, enclosing, ok): each open's close index, each token's stack of enclosing opens (outermost first), and
    whether every bracket closes in kind. Nothing after a mismatch can be trusted, so the scan stops there."""
    match, enclosing, stack = {}, [], []
    for k, tok in enumerate(code):
        enclosing.append(tuple(stack))
        if tok[0] == "open":
            stack.append(k)
        elif tok[0] == "close":
            if not stack or PAIR[code[stack[-1]][3]] != tok[3]:
                return match, enclosing, False
            match[stack.pop()] = k
    return match, enclosing, not stack


class BlobReader:
    """One `git cat-file --batch` process for a scan's reads at its revision. A scan reads thousands of files, and one
    `git show` each was 110 of 157 s on vagary-core. A blob comes back byte for byte; anything else (a missing path, a
    tree, a path with a newline or a carriage return, a reader that died or stalled) falls back to `git show`, which
    refuses as before. --batch reads one line per object and drops a CR before its LF, so a name ending in "\\r" would
    come back as the blob of the name without it (root's R4 of #33 round 3, N1)."""

    TIMEOUT = 60  # seconds for one object: a stalled reader is killed, and the read falls back

    def __init__(self, repo: Path, environment: dict):
        self.proc = subprocess.Popen(["git", "--no-replace-objects", "-C", str(repo), "cat-file", "--batch"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env=environment)

    def read(self, spec: str) -> bytes | None:
        if "\n" in spec or "\r" in spec or self.proc.poll() is not None:
            return None
        timer = threading.Timer(self.TIMEOUT, self.proc.kill)
        timer.start()
        try:
            self.proc.stdin.write(spec.encode("utf-8", errors="surrogateescape") + b"\n")
            self.proc.stdin.flush()
            header = self.proc.stdout.readline().split()
            if len(header) != 3 or not header[2].isdigit():
                return None  # "<spec> missing" / "ambiguous", or the reader died
            size = int(header[2])
            data = self.proc.stdout.read(size)
            if len(data) != size or self.proc.stdout.read(1) != b"\n":
                self.proc.kill()
                return None
            return data if header[1] == b"blob" else None
        except OSError:
            return None
        finally:
            timer.cancel()

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


_BLOB_READERS: dict[tuple[str, str], BlobReader] = {}


@contextlib.contextmanager
def batch_reads(repo: Path, revision: str | None, environment: dict):
    """Serve read_source's revision reads from one BlobReader for the duration of a scan."""
    if revision is None or (str(repo), revision) in _BLOB_READERS:
        yield
        return
    key = (str(repo), revision)
    _BLOB_READERS[key] = BlobReader(repo, environment)
    try:
        yield
    finally:
        _BLOB_READERS.pop(key).close()


def read_source(repo: Path, path: str, revision: str | None, environment: dict) -> str:
    """The scanned revision's bytes of one file (the working tree's when no revision is pinned)."""
    if revision is None:
        return (repo / path).read_bytes().decode("utf-8", errors="replace")  # no newline translation (CRLF)
    reader = _BLOB_READERS.get((str(repo), revision))
    data = reader.read(f"{revision}:{path}") if reader else None
    if data is not None:
        return data.decode("utf-8", errors="replace")
    out = run_git(["git", "--no-replace-objects", "-C", str(repo), "show", f"{revision}:{path}"],
                         capture_output=True, timeout=15, env=environment)
    if out.returncode:
        raise ValueError(f"reader scan cannot read {path} at the scanned revision")
    return out.stdout.decode("utf-8", errors="replace")


class Source:
    """One scanned file: its text, tokens and bracket structure, and its lines split on "\\n" only (as git grep numbers
    them; str.splitlines also splits on \\x0c, \\x1c-\\x1e, \\x85, U+2028/9 and a lone \\r)."""

    def __init__(self, text: str, ext: str):
        self.text, self.ext, self.py = text, ext, ext in PY_EXT
        self.code, self.comments, ok = file_tokens(text, ext)
        self.match, self.enclosing, closed = structure(self.code)
        self.ok = ok and closed
        self.opener = {close: open_ for open_, close in self.match.items()}
        self.newlines = [m.start() for m in re.finditer("\n", text)]
        self.starts = [tok[1] for tok in self.code]
        self.comment_starts = [a for a, _ in self.comments]
        # Rule 7 (root, 2026-10-26): the tokens of the file that step to a parent (`..`, a quoted '..', `.parent`,
        # `.parents`, `os.pardir`, getattr(p, "parent"), a `dirname(` call), and the computed root reads classification
        # finds. The name
        # taint (RootLiteral.taint_check) refuses where they meet.
        code = self.code
        js = ext in JS_EXT
        self.subs = {j: substitutions(tok[3][0], js) for j, tok in enumerate(code) if tok[0] == "str" and not tok[3][1]}
        aliases = set(re.findall(r"\bdirname\s+as\s+([A-Za-z_$][\w$]*)", text))
        aliases |= set(re.findall(r"\bdirname\s*:\s*([A-Za-z_$][\w$]*)", text))
        aliases |= set(re.findall(
            r"(?m)^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*=\s*[\w$.]*\bdirname\s*;?\s*$", text))
        self.dirname_aliases = aliases - {"dirname"}
        self.parent_toks = [
            j for j, tok in enumerate(code)
            if (tok[0] == "str" and (PARENT_STEP.search(tok[3][0])
                                     or any(SUB_PARENT.search(e) for e in self.subs.get(j, ()))
                                     or (tok[3][0] in ("parent", "parents", "pardir") and self._in_getattr(j))))
            or (tok[0] == "word" and tok[3] == "pardir")
            or (tok[0] == "word" and (tok[3] == "dirname" or tok[3] in self.dirname_aliases) and j + 1 < len(code)
                and code[j + 1][3] == "(")
            or (tok[0] == "word" and tok[3] in ("parent", "parents") and j and code[j - 1][0] == "op"
                and code[j - 1][3] in (".", "?."))]
        self.computed = []

    def _in_getattr(self, j: int) -> bool:
        """Token j is an argument of `getattr(` (its innermost bracket is a call named getattr)."""
        stack = self.enclosing[j] if j < len(self.enclosing) else ()
        e = stack[-1] if stack else None
        return e is not None and self.code[e][3] == "(" and e > 0 and self.code[e - 1][3] == "getattr"

    def bounds(self, line: int) -> tuple[int, int]:
        a = 0 if line == 0 else self.newlines[line - 1] + 1
        b = self.newlines[line] if line < len(self.newlines) else len(self.text)
        return a, b

    def line_of(self, offset: int) -> int:
        return bisect.bisect_left(self.newlines, offset)

    def token_at(self, offset: int) -> int | None:
        k = bisect.bisect_right(self.starts, offset) - 1
        return k if k >= 0 and self.code[k][1] <= offset < self.code[k][2] else None

    def in_comment(self, offset: int) -> bool:
        k = bisect.bisect_right(self.comment_starts, offset) - 1
        return k >= 0 and self.comments[k][0] <= offset < self.comments[k][1]


class RootLiteral:
    """Classifies the root literals of one file's lines against one workspace graph."""

    def __init__(self, roots, by_dir, owner, globs, path=""):
        self.roots, self.by_dir, self.owner, self.globs, self.path = set(roots), by_dir, owner, globs, path
        alt = "|".join(re.escape(r) for r in sorted(self.roots))
        self.quoted = re.compile(r"(?<![\w$])([\"'`])(?:\./)*(?:%s)/?\1" % alt)
        # In a computed string a root segment anywhere (`${root}/services/${x}`) is a path; a backslash separates too.
        self.root_segment = re.compile(r"(?<![\w.-])(?:%s)(?=[/\\])" % alt)
        # Round 4 (root, 2026-10-26): a root SEGMENT anywhere in a string is a mention, whatever precedes it
        # (`backend/services/`, `./services/`, `{}/services/`, `$ROOT/services`), and a backslash always separates.
        self.root_any = re.compile(r"(?<![\w.-])(?:%s)(?=[/\\])|(?<=[/\\])(?:%s)(?![\w.-])" % (alt, alt))
        self.root_word = re.compile(r"(?<![\w.-])(?:%s)(?![\w.-])" % alt)

    def refuse(self, why="unsupported"):
        raise ValueError(f"{why} workspace-root reader expression in {self.path}")

    def root_of(self, tok) -> str | None:
        """The root a plain string token names ("services", "./services", "services/"), else None."""
        if tok[0] != "str" or not tok[3][1]:
            return None
        value = tok[3][0]
        while value.startswith("./"):
            value = value[2:]
        value = value[:-1] if value.endswith("/") else value
        return value if value in self.roots else None

    # ---- the graph ----
    def beneath(self, prefix: str) -> set:
        return {name for directory, name in self.by_dir.items() if directory.startswith(prefix + "/")}

    def unowned(self, prefix: str) -> None:
        """Unowned content is safe to leave unread only because its change is unmapped and plans FULL. When a caller's
        inert_globs or extra_edges covers it, that no longer holds, so the read REFUSES (F6)."""
        for glob in self.globs:
            static = re.split(r"[*?\[]", glob, maxsplit=1)[0]
            if glob_to_regex(glob).match(prefix) or static.startswith(prefix + "/") or (static and prefix.startswith(static)):
                self.refuse("unresolved")

    def resolve(self, components: list[str], dynamic: bool) -> set:
        if dynamic and getattr(self, "src", None) is not None and getattr(self, "current", None) is not None:
            self.src.computed.append(self.current)  # rule 7: the name taint starts from this read's statement
        for component in components:
            if any(part in (".", "..") for part in component.split("/")):
                self.refuse("unresolved")
        prefix = posixpath.normpath("/".join(components))
        found = self.owner(prefix)
        if found is not None:
            return {found} | (self.beneath(prefix) if dynamic else set())  # F4: nested packages under a computed tail
        below = self.beneath(prefix)
        if not below:
            self.unowned(prefix)
        return below

    # ---- token shapes ----
    def callee(self, e: int) -> str | None:
        """The dotted name before the open bracket at e, when that bracket is a call (not a definition)."""
        T, j, names = self.src.code, e - 1, []
        while j >= 0 and T[j][0] == "word":
            names.append(T[j][3])
            if j >= 1 and T[j - 1][0] == "op" and T[j - 1][3] in (".", "?."):
                j -= 2
                continue
            break
        if not names or names[0] in KEYWORDS:
            return None
        return ".".join(reversed(names))

    def kind(self, e: int) -> str:
        """call, def, group (parenthesised expression or tuple), list, subscript, set or object (a brace in JS/JSON is an
        object literal or a block)."""
        T = self.src.code
        ch, prev = T[e][3], (T[e - 1] if e else None)
        if ch == "(":
            if prev and prev[0] == "word" and prev[3] not in KEYWORDS:
                before = T[e - 2] if e >= 2 else None
                return "def" if before and before[0] == "word" and before[3] in ("def", "function", "class") else "call"
            return "call" if prev and prev[0] in ("close", "str") else "group"
        if ch == "[":
            if prev and ((prev[0] == "word" and prev[3] not in KEYWORDS) or prev[0] in ("close", "str")
                         or (prev[0] == "op" and prev[3] == "?.")):
                return "subscript"
            return "list"
        if self.src.py and self.elements(e) and not any(T[j][0] == "colon" for j in self.level(e)):
            return "set"
        return "object"

    def elements(self, e: int) -> list[tuple[int, int]]:
        """Token ranges of the comma-separated elements directly inside the bracket at e (a trailing comma adds none)."""
        T, stop = self.src.code, self.src.match[e]
        out, first, j = [], e + 1, e + 1
        while j < stop:
            if T[j][0] == "open":
                j = self.src.match[j] + 1
                continue
            if T[j][0] == "comma":
                out.append((first, j))
                first = j + 1
            j += 1
        if first < stop:
            out.append((first, stop))
        return out

    def level(self, e: int):
        """Indices of the tokens directly inside the bracket at e."""
        T, j, stop = self.src.code, e + 1, self.src.match[e]
        while j < stop:
            yield j
            j = self.src.match[j] + 1 if T[j][0] == "open" else j + 1

    @staticmethod
    def span_of(spans: list, k: int) -> int:
        return next(i for i, (a, b) in enumerate(spans) if a <= k < b)

    def plain(self, span: tuple[int, int]) -> str | None:
        a, b = span
        tok = self.src.code[a]
        return tok[3][0] if b - a == 1 and tok[0] == "str" and tok[3][1] else None

    def component(self, span: tuple[int, int]) -> str | None:
        """A literal path component; a glob pattern is computed for this purpose."""
        value = self.plain(span)
        return None if value is None or GLOB_CHARS.search(value) else value

    def parent_step(self, a: int, b: int) -> bool:
        T = self.src.code
        for j in range(max(a, 0), min(b, len(T))):
            tok = T[j]
            if tok[0] == "word" and tok[3] in PARENT_WORDS and (
                    (j > 0 and T[j - 1][0] == "op" and T[j - 1][3] in (".", "?."))
                    or (j + 1 < len(T) and T[j + 1][0] == "open" and T[j + 1][3] == "(")):
                return True
            if tok[0] == "str" and PARENT_SEG.search(tok[3][0]):
                return True
        return False

    def block(self, x: int) -> bool:
        """A JS/TS brace that opens a block or class body (after `)`, `=>`, `else`, a class name, or at statement start),
        not an object literal. Python and JSON braces are always expressions."""
        T = self.src.code
        if T[x][3] != "{" or self.src.ext not in JS_EXT:
            return False
        prev = T[x - 1] if x else None
        return (prev is None or prev[0] == "close" or (prev[0] == "op" and prev[3] in ("=>", ";"))
                or (prev[0] == "word" and prev[3] not in OBJECT_AFTER))

    def container(self, k: int) -> int | None:
        """The innermost block around k: a statement never crosses it (an object literal is an expression bracket)."""
        return next((x for x in reversed(self.src.enclosing[k]) if self.block(x)), None)

    COMPOUND = frozenset({"if", "elif", "else", "for", "while", "with", "def", "class", "try", "except", "finally",
                          "async", "match", "case"})

    def block_colon(self, j: int) -> bool:
        """A Python colon that ends a compound header: the logical line holding it starts with a compound keyword."""
        T, src, t = self.src.code, self.src, j
        while True:
            first = bisect.bisect_left(src.starts, src.bounds(src.line_of(T[t][1]))[0])
            outer = src.enclosing[first] if first < len(src.enclosing) else ()
            if not outer:
                return T[first][0] == "word" and T[first][3] in self.COMPOUND
            t = outer[0]

    def statement(self, s: int, e: int, taint: bool = False) -> tuple[int, int]:
        """The token range of the statement (or object entry) holding tokens s..e: bracketed groups are whole, and a
        line break ends it unless the line continues (a trailing operator or backslash, or a leading `.`). For rule 7
        (`taint`), a top-level comma never ends it, and a Python colon ends it only after a compound header."""
        T, src = self.src.code, self.src
        c = self.container(s)
        expression = [x for x in src.enclosing[s] if c is None or x > c]
        lo = expression[0] if expression else s
        hi = max(src.match[lo] if expression else e, e)
        floor = c + 1 if c is not None else 0
        ceiling = src.match[c] - 1 if c is not None else len(T) - 1

        def joined(left, right):
            if src.line_of(T[left][1]) == src.line_of(T[right][1]):
                return True
            return ((T[right][0] == "op" and T[right][3] in (".", "?."))
                    or (T[left][0] == "op" and T[left][3] in CONT_OPS) or (T[left][0] == "word" and T[left][3] in CONT_WORDS))

        def boundary(j):
            tok = T[j]
            if tok[0] == "comma":
                return not taint
            if src.py and tok[0] == "colon":
                return not taint or self.block_colon(j)
            return tok[0] == "op" and tok[3] == ";"

        j = lo - 1
        while j >= floor:
            if boundary(j) or not joined(j, lo):
                break
            lo = src.opener[j] if T[j][0] == "close" else j
            j = lo - 1
        j = hi + 1
        while j <= ceiling:
            if boundary(j) or not joined(hi, j):
                break
            hi = src.match[j] if T[j][0] == "open" else j
            j = hi + 1
        return lo, hi

    def after(self, start: int, end: int) -> bool:
        """A construct read as a path (tokens start..end). Walking outward through its enclosing expression brackets: a
        parent step later in its own element, in a later argument of an enclosing PATH call, in a parent-step call around
        it (dirname, parent), or after it in its statement (`.parent`, `+ "/.."`) REFUSES (F5). An element of a list or
        an argument of another call is a separate value, and a nested block or object in the statement tail is skipped.
        Returns whether the result is walked (glob, rglob, os.walk, ...): it then reads every package beneath (F4)."""
        T, src, c = self.src.code, self.src, self.container(start)
        walked, lo, hi = False, start, end
        for x in reversed(src.enclosing[start]):
            if c is not None and x <= c:
                break
            kind = self.kind(x)
            last = (self.callee(x) or "").rsplit(".", 1)[-1] if kind == "call" else ""
            if last in PARENT_WORDS:
                self.refuse("unresolved")
            spans = self.elements(x)
            i = self.span_of(spans, lo)
            if self.parent_step(hi + 1, spans[i][1]):
                self.refuse("unresolved")
            walked = walked or last in WALK_WORDS or self.walks(hi + 1, spans[i][1])
            if last in PATH_CALLS and any(self.parent_step(p, q) for p, q in spans[i + 1:]):
                self.refuse("unresolved")  # a later component of the enclosing path call
            lo, hi = x, src.match[x]
        _, tail = self.statement(lo, hi)
        j = hi + 1
        while j <= tail:
            # Blocks and callbacks in the tail are scanned too (H3.3: `.map(p => path.resolve(p, '..'))`).
            if self.parent_step(j, j + 1):
                self.refuse("unresolved")
            walked = walked or self.walks(j, j + 1)
            j += 1
        return walked

    def walks(self, a: int, b: int) -> bool:
        T = self.src.code
        return any(T[j][0] == "word" and T[j][3] in WALK_WORDS for j in range(max(a, 0), min(b, len(T))))

    def in_exec(self, k: int) -> bool:
        T = self.src.code
        for x in reversed(self.src.enclosing[k]):
            if self.block(x):
                return False
            if self.kind(x) == "call" and EXEC_CALL.search(self.callee(x) or ""):
                return True
        return False

    PROCESS_EXEC = re.compile(r"(?:^|\.)(?:subprocess\.\w+|system|popen|Popen|check_call|check_output|spawn\w*|"
                              r"execSync|execFileSync|execFile|exec(?:[lv]p?e?)?)$")

    def in_process_exec(self, k: int) -> bool:
        """A string inside a call that runs a process (subprocess, os.system/popen, child_process), never a database
        `execute()`: its bare root words are command arguments."""
        for x in reversed(self.src.enclosing[k]):
            if self.block(x):
                return False
            if self.kind(x) == "call" and self.PROCESS_EXEC.search(self.callee(x) or ""):
                return True
        return False

    # ---- reads ----
    def path_read(self, tail: list, root: str, start: int, end: int, dynamic: bool = False) -> set:
        components = [root]
        for a, b in tail:
            if self.parent_step(a, b):
                self.refuse("unresolved")  # F5: `..`, .parent, os.pardir in a later component
            value = self.component((a, b))
            if value is None:
                dynamic = True
            elif not dynamic:
                components.append(value)
        return self.resolve(components, self.after(start, end) or dynamic)

    def slash_read(self, k: int, root: str) -> set:
        T, src = self.src.code, self.src
        components, dynamic, j = [root], False, k + 1
        while j + 1 < len(T) and T[j][0] == "op" and T[j][3] == "/":
            operand = T[j + 1]
            j += 2
            value = operand[3][0] if operand[0] == "str" and operand[3][1] else None
            if value is not None and not GLOB_CHARS.search(value):
                if not dynamic:
                    components.append(value)
                continue
            dynamic = True
            if operand[0] == "open":
                j = src.match[j - 1] + 1
            while j < len(T) and (T[j][0] == "open" or (T[j][0] == "op" and T[j][3] in (".", "?.") and j + 1 < len(T))):
                j = src.match[j] + 1 if T[j][0] == "open" else j + 2
        if self.parent_step(k + 1, j):
            self.refuse("unresolved")  # F5 inside the chain
        return self.resolve(components, self.after(k, j - 1) or dynamic)

    def iterated(self, e: int) -> bool:
        """The collection at e is the iterable of a loop (`for x in (...)`, `for (const x of [...])`), or an element of
        one (`for (const [w, j] of [['services', 'build']])`): the loop hands the root to its body."""
        T, src = self.src.code, self.src
        outer = src.enclosing[e][-1] if src.enclosing[e] else None
        if outer is not None and T[e - 1][0] in ("comma", "open") and self.collection(outer) and self.iterated(outer):
            return True
        before = T[e - 1] if e else None
        if before is None or before[0] != "word" or before[3] not in ("in", "of"):
            return False
        if before[3] == "of":
            return True
        lo, _ = self.statement(e, self.src.match[e])
        return any(T[j][0] == "word" and T[j][3] == "for" and self.src.enclosing[j] == self.src.enclosing[e]
                   for j in range(lo, e))

    def has_evidence(self, e: int) -> bool:
        """A collection literal is metadata only when ASSIGNED, an object value, compared, a membership operand, or
        nested in such a collection; never as a direct argument of a call (root, 2026-10-26)."""
        T, src = self.src.code, self.src
        before = T[e - 1] if e else None
        outer = src.enclosing[e][-1] if src.enclosing[e] else None
        if before is None:
            return False
        if before[0] == "op" and before[3] == "=":
            return outer is None or self.block(outer)  # a statement, never a keyword argument or default
        if (before[0] == "op" and before[3] in COMPARE) or (before[0] == "word" and before[3] == "in"):
            return True
        if before[0] == "colon":
            return outer is not None and self.kind(outer) == "object" and not self.ternary(e - 1, outer)
        if before[0] in ("comma", "open") and outer is not None and self.collection(outer):
            return self.has_evidence(outer)
        return False

    def collection(self, e: int) -> bool:
        """A list, set or tuple LITERAL. A comprehension (`{x for x in y if x == "services"}`) is an expression."""
        kind = self.kind(e)
        if any(self.src.code[j][0] == "word" and self.src.code[j][3] == "for" for j in self.level(e)):
            return False
        return kind in ("list", "set") or (kind == "group" and (len(self.elements(e)) > 1 or self.trailing_comma(e)))

    def trailing_comma(self, e: int) -> bool:
        return self.src.code[self.src.match[e] - 1][0] == "comma"

    def ternary(self, colon: int, e: int) -> bool:
        T = self.src.code
        a, _ = self.elements(e)[self.span_of(self.elements(e), colon)]
        return any(T[j][0] == "op" and T[j][3] == "?" for j in range(a, colon))

    def in_collection(self, e: int, spans: list, mine: int, root: str) -> set:
        T, src = self.src.code, self.src
        m = src.match[e]
        after, after2 = (T[m + 1] if m + 1 < len(T) else None), (T[m + 2] if m + 2 < len(T) else None)
        before = T[e - 1] if e else None
        outer = src.enclosing[e][-1] if src.enclosing[e] else None
        outer_call = (self.callee(outer) or "").rsplit(".", 1)[-1] if outer is not None and self.kind(outer) == "call" else ""
        if after and after[0] == "open" and after[3] == "[":
            self.refuse("a subscripted collection selects one element; it is not a path")  # H1.8
        spread = before is not None and before[0] == "op" and before[3] in ("*", "...")
        method = after is not None and after[0] == "op" and after[3] in (".", "?.") and after2 and after2[0] == "word"
        sole = outer_call == "join" and len(self.elements(outer)) == 1 and not spread
        if (method and after2[3] == "join") or (outer_call in PATH_CALLS and (spread or sole)):
            tail, trailing = spans[mine + 1:], False
            if outer_call in PATH_CALLS and spread:
                parts = self.elements(outer)
                rest = parts[self.span_of(parts, e) + 1:]
                if any(self.parent_step(a, b) for a, b in rest):
                    self.refuse("unresolved")
                trailing = bool(rest)
            end = src.match[outer] if outer_call in PATH_CALLS else m
            return self.path_read(tail, root, outer if outer_call in PATH_CALLS else e, end, dynamic=trailing)
        if outer_call in PATH_CALLS:
            self.refuse("a collection passed to a path call without a spread")
        if self.in_exec(e):
            self.refuse("an argv list of an exec call")
        if len(spans) == 1:
            return self.resolve([root], dynamic=True)  # ["services"], ("services",), {"services"}: a walker
        walked = self.iterated(e) or method
        if not walked and not self.has_evidence(e):
            self.refuse("a collection literal outside an assignment, object value or comparison")
        # Rule 8 (root, 2026-10-26): no list-literal exemption. An assigned literal list can flow into a path
        # (`parts = ["services", "billing"]` then `join(ROOT, *parts)`), so it is a walker read beneath the root, plus
        # the packages its siblings name. Only a direct call argument still refuses (H2).
        return self.named_by_siblings(spans, mine, root) | self.resolve([root], dynamic=True)

    def named_by_siblings(self, spans: list, mine: int, root: str) -> set:
        """Packages named by the literal siblings of a listed root literal. Every sibling must be a plain string."""
        reads = set()
        for i, span in enumerate(spans):
            if i == mine:
                continue
            value = self.plain(span)
            if value is None:
                self.refuse("a computed sibling of a")
            if any(part in (".", "..") for part in value.split("/")):
                continue
            joined = posixpath.normpath(root + "/" + value)
            found, below = self.owner(joined), self.beneath(joined)
            if found is not None:
                reads.add(found)
            reads |= below
            if found is None and not below:
                self.unowned(joined)  # F6
            if value in self.roots or (self.beneath(value.split("/", 1)[0]) and "/" not in value):
                reads |= self.beneath(root) | self.beneath(value)  # another package-owning top-level directory
        return reads

    def object_entry(self, k: int, e: int) -> bool:
        T = self.src.code
        spans = self.elements(e)
        a, b = spans[self.span_of(spans, k)]
        if k == a and k + 1 < b and T[k + 1][0] == "colon":
            return True  # a key
        return (k == b - 1 and k - 1 > a and T[k - 1][0] == "colon"
                and not any(T[j][0] == "op" and T[j][3] == "?" for j in range(a, k - 1)))  # a value, never a ternary

    def classify(self, k: int) -> set:
        T = self.src.code
        root = self.root_of(T[k])
        prev, nxt = (T[k - 1] if k else None), (T[k + 1] if k + 1 < len(T) else None)
        if (prev and prev[0] == "op" and prev[3] == "/") or (nxt and nxt[0] == "op" and nxt[3] == "/"):
            return self.slash_read(k, root)
        stack = self.src.enclosing[k]
        e = stack[-1] if stack else None
        kind = self.kind(e) if e is not None else None
        if kind == "call" and (self.callee(e) or "").rsplit(".", 1)[-1] in PATH_CALLS:
            spans = self.elements(e)
            mine = self.span_of(spans, k)
            if spans[mine] != (k, k + 1):
                self.refuse("a root literal not alone in a path argument")  # H1.1
            return self.path_read(spans[mine + 1:], root, e, self.src.match[e])
        if e is not None and self.collection(e):
            spans = self.elements(e)
            mine = self.span_of(spans, k)
            if spans[mine] != (k, k + 1):
                self.refuse("a computed element holding a")
            return self.in_collection(e, spans, mine, root)
        if self.in_exec(k):
            self.refuse("an argv element of an exec call")
        if kind == "object" and self.object_entry(k, e):
            return set()
        if kind == "subscript" and self.elements(e) == [(k, k + 1)]:
            return set()
        nxt2 = T[k + 2] if k + 2 < len(T) else None
        if ((prev and ((prev[0] == "op" and prev[3] in COMPARE) or (prev[0] == "word" and prev[3] == "case")))
                or (nxt and nxt[0] == "op" and nxt[3] in COMPARE)
                or (nxt and nxt[0] == "word" and (nxt[3] == "in" or (nxt[3] == "not" and nxt2 and nxt2[3] == "in")))):
            # A comparison selects a value that may become a path (`d == "services"` then `Path(ROOT, d)`): a walker
            # read beneath the root, never metadata (H3.4, root's round-4 ruling).
            self.after(k, k)
            return self.resolve([root], dynamic=True)
        self.refuse("no positive metadata evidence for a")

    def line_reads(self, src: Source, line: int) -> set:
        """The reads of one grep-matched line of a structured file. A quoted root token is classified; a root named
        INSIDE a string (an f-string, template, glob, SQL or prose) is a walker read beneath its literal prefix; one
        inside a regex or a broken quote REFUSES."""
        self.src = src
        a, b = src.bounds(line)
        if not src.ok:
            if self.quoted.search(src.text, a, b) or self.root_segment.search(src.text, a, b):
                self.refuse("the file's bracket structure cannot be trusted for a")
            return set()
        hits = []
        for m in self.quoted.finditer(src.text, a, b):
            if src.in_comment(m.start()):
                continue
            k = src.token_at(m.start())
            tok = src.code[k] if k is not None else None
            if tok is not None and tok[0] == "str":
                if m.end() > tok[2]:
                    # The quoted root runs past the string the tokenizer saw: the grammar desynchronised (JSX text,
                    # a PEP 701 nested quote, a regex lexed as division). REFUSE rather than read nothing (H3.1).
                    self.refuse("a quoted root the tokenizer split (desync) is an unsupported")
                if tok[3][2] == m.start() and self.root_of(tok) is not None:
                    hits.append(k)
                continue  # a quoted root inside another string: read below, with the string's other mentions
            self.refuse("a root literal in an unparsed token (a regex, or a broken quote) is an unsupported")
        reads = set()
        k = src.token_at(a)
        k = k if k is not None else bisect.bisect_left(src.starts, a)
        while k < len(src.code) and src.code[k][1] < b:
            if src.code[k][0] == "str" and k not in hits:
                self.current = k
                reads |= self.string_reads(k, a, b)
            k += 1
        for k in hits:
            self.current = k
            try:
                reads |= self.classify(k)
            except (IndexError, KeyError, StopIteration):
                self.refuse("an unparsed")
        return reads

    def string_reads(self, k: int, a: int, b: int) -> set:
        """Every root mention inside string k on this line is a walker read beneath its literal prefix (round 4: no rule
        turns a mention into nothing):
          - a root segment, whatever precedes it (`backend/services/`, `./services/`, `{}/services/`, `/services`);
          - a backslash after a root, always (`services\\b`, an escape or not);
          - a quoted root inside the string (prose, SQL text);
          - a docstring, read like any string.
        It REFUSES on a doctest naming a root (executed code), on any `..` in the mention's path run, on a computed
        string that holds any `..` step (a quoted '..' included; an ellipsis is not a step), a parent word or nested
        code naming a root (its substitutions are opaque), and on a parent step applied to the string. A segment
        inside a pure-literal `../` run is the `rel` rule's: it is relative to the file."""
        src, tok = self.src, self.src.code[k]
        lo, hi = max(tok[1], a), min(tok[2], b)
        plain, body = tok[3][1], tok[3][0]
        # A segment reached through `../` is a path relative to this file, which the `rel` rule resolves exactly from
        # the file's directory; it is not a repo-root mention.
        # A segment is file-relative (the `rel` rule's) only after a pure-literal `../` run from the start of its path:
        # after a substitution or a literal directory (`{base}/../services`, `x/../services`) it is a mention.
        mentions = [m.start() for m in self.root_any.finditer(src.text, lo, hi)
                    if not REL_RUN.fullmatch(re.search(r"[^\s'\"`]*$", src.text[lo:m.start()]).group())]
        mentions += [m.start() + 1 for m in self.quoted.finditer(src.text, lo, hi)]
        if not mentions and not (self.in_process_exec(k) and self.root_word.search(src.text, lo, hi)):
            return set()
        if not plain and (PARENT_STEP.search(body) or PARENT_WORD.search(body) or self.quoted.search(body)):
            self.refuse("unresolved")  # H3.2: an opaque substitution may leave the root
        if ">>>" in body:
            self.refuse("a doctest naming a root is executed code the scanner does not parse; an unsupported")
        reads = set()
        if self.in_process_exec(k):  # a command string: a bare root word (`pytest services -q`) names that whole tree
            for m in self.root_word.finditer(src.text, lo, hi):
                if not self.root_any.match(src.text, m.start()):
                    reads |= self.resolve([m.group()], dynamic=True)
        for p in sorted(set(mentions)):
            while src.text.startswith("./", p):
                p += 2
            run = re.compile(r"[^\s'\"`]*").match(src.text, p, hi).group()
            if PARENT_SEG.search(run.replace("\\", "/")):
                self.refuse("unresolved")
            prefix = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*").match(run).group()
            parts = prefix.split("/")
            if len(run) > len(prefix) and run[len(prefix)] not in "/\\":
                parts = parts[:-1] or parts  # the last component is cut by a glob or a substitution
            elif p + len(run) >= tok[2] - 1 and k + 1 < len(src.code) and src.code[k + 1][3] == "+":
                parts = parts[:-1] or parts  # `"services/b" + suffix`: the string's last component continues
            reads |= self.resolve(parts, dynamic=True)
        self.after(k, k)
        return reads

    RAW_BIND = re.compile(r"^\s*(?:(?:export|local|readonly|declare(?:\s+-\w+)?)\s+)?([A-Za-z_]\w*)=(.*)$|^\s*(?:ARG|ENV)\s+([A-Za-z_]\w*)[=\s](.*)$")
    RAW_MAKE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::{1,2}|\?|\+|!)?=\s*(.*)$")
    RAW_FOR = re.compile(r"(?:^|[;&|]\s*)for\s+([A-Za-z_]\w*)\s+in\s+([^;]*)")
    RAW_CD = re.compile(r"(?<![\w.-])(?:cd|pushd|WORKDIR|working[-_]directory|working_dir|workdir|cwd)(?=[\s:=])")

    def raw_taint(self, text: str) -> str:
        """Rule 7 for a file the tokenizer does not parse (shell, Dockerfile, yaml, toml), line by line, after its
        trailing comment: a line holding a root segment (or a variable bound from one) and a `..` step refuses; so does
        any `..` step after a `cd`, `pushd`, `WORKDIR` or `working-directory:` into a root path or a bare root (`cd
        services`). An anchor (`cd "$(dirname "$0")/.."`) names no root, so it stays. Returns the reason, or "" when the
        file is clean."""
        lines = text.split("\n")
        tainted: set = set()
        changed = True
        while changed:
            changed = False
            for line in lines:
                bare = self.strip_comment(line)
                m = self.RAW_BIND.match(bare)
                name, value = (m.group(1) or m.group(3), m.group(2) if m.group(1) else m.group(4)) if m else (None, "")
                if not name:
                    m = self.RAW_MAKE.match(bare) or self.RAW_FOR.search(bare)
                    name, value = (m.group(1), m.group(2)) if m else (None, "")
                if name and name not in tainted and (self.root_any.search(value) or self.uses(value, tainted)):
                    tainted.add(name)
                    changed = True
        cwd = False
        for number, line in enumerate(lines, 1):
            line = self.strip_comment(line)
            rooted = bool(self.root_any.search(line)) or self.uses(line, tainted)
            into_root = bool(self.RAW_CD.search(line)) and (rooted or bool(self.root_word.search(line)))
            if PARENT_STEP.search(line):
                if rooted or into_root:
                    return f"a root path and a `..` step on line {number}"
                if cwd:
                    return f"a `..` step on line {number} after a cd into a root path"
            cwd = cwd or into_root
        return ""

    @staticmethod
    def strip_comment(line: str) -> str:
        """A shell/Dockerfile/yaml/toml line without its trailing `#` comment: a `#` at the start or after whitespace,
        outside quotes."""
        quote = None
        for i, ch in enumerate(line):
            if quote:
                if ch == "\\":
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1].isspace()):
                return line[:i]
        return line

    @staticmethod
    def uses(text: str, names: set) -> bool:
        return any(re.search(r"\$[{(]?%s\b" % re.escape(n), text) for n in names)

    KEY_EXTS = frozenset({"yml", "yaml"})

    def raw_reads(self, text: str, ext: str = "") -> set:
        """Walker reads for every root segment of one line of an unparsed file (rule 1: a mention reads or refuses).
        `ext` is the file's extension: only a YAML key (`services:`) is metadata. A TOML key is written `services =`,
        so it reads like any bare word."""
        reads = set()
        text = self.strip_comment(text)
        for m in self.root_word.finditer(text):  # a bare root word (`pytest services`, `COPY services .`, `- services`)
            if ext in self.KEY_EXTS and text[m.end():m.end() + 1] == ":" and not text[m.end():m.end() + 2] == "::":
                continue  # a YAML key (`services:`) is metadata, as an object key is
            if not self.root_any.match(text, m.start()) and text[max(m.start() - 1, 0):m.start()] not in ("/", "\\"):
                src, self.src = getattr(self, "src", None), None
                try:
                    reads |= self.resolve([m.group()], dynamic=True)
                finally:
                    self.src = src
        for m in self.root_any.finditer(text):
            if text[max(m.start() - 3, 0):m.start()] in ("../", "..\\"):
                continue  # relative to the file: the `rel` rule resolves it
            run = re.compile(r"[^\s'\"`]*").match(text, m.start()).group()
            if PARENT_SEG.search(run.replace("\\", "/")):
                self.refuse("unresolved")
            prefix = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*").match(run).group()
            parts = prefix.split("/")
            if len(run) > len(prefix) and run[len(prefix)] not in "/\\":
                parts = parts[:-1] or parts
            src, self.src = getattr(self, "src", None), None  # unparsed: no token rule 7; the caller checked raw `..`
            try:
                reads |= self.resolve(parts, dynamic=True)
            finally:
                self.src = src
        return reads

    def literal_path(self, src: Source, offset: int, path_text: str) -> set:
        """A `<root>/<name>` path literal is read by its text. A parent step after it in its statement, or a parent-step
        call around it, REFUSES (F5); a walk of it also reads every package beneath it (F4)."""
        if not src.ok:
            return set()
        self.src = src
        k = src.token_at(offset)
        if k is None or src.code[k][0] != "str":
            return set()
        self.current = k
        return self.resolve([posixpath.normpath(path_text)], dynamic=True) if self.after(k, k) else set()

    # ---- rule 7: lexical name taint (root, 2026-10-26) ----
    ASSIGN_OPS = frozenset({"=", ":=", "+=", "-=", "*=", "/=", "|=", "&=", "??=", "||=", "&&="})
    DECL_WORDS = frozenset({"const", "let", "var", "export", "default", "async", "await", "this", "self", "cls",
                            "global", "nonlocal", "static", "readonly", "private", "public", "protected"})

    def functions(self) -> list[tuple[str, int, int]]:
        """(name, first token, last token) of every function the file defines: Python `def` (indented body) and a
        lambda bound to a name; JS `function f(`, `f = (...) =>` / `f = x =>`, and a method `f(...) {`."""
        src, T, out = self.src, self.src.code, []
        if src.py:
            lines = src.text.split("\n")
            for i, line in enumerate(lines):
                m = re.match(r"(\s*)(?:async\s+)?def\s+(\w+)\s*\(", line)
                if not m:
                    continue
                indent, end = len(m.group(1)), i + 1
                while end < len(lines) and (not lines[end].strip() or lines[end].lstrip().startswith("#")
                                            or len(lines[end]) - len(lines[end].lstrip()) > indent):
                    end += 1
                lo = bisect.bisect_left(src.starts, src.bounds(i)[0])
                hi = bisect.bisect_left(src.starts, src.bounds(end - 1)[1] if end - 1 < len(src.newlines) + 1 else len(src.text)) - 1
                out.append((m.group(2), lo, max(lo, hi)))
            for j in range(len(T) - 3):
                if T[j][0] == "word" and T[j + 1][3] == "=" and T[j + 2][3] == "lambda":
                    lo, hi = self.statement(j, j, taint=True)
                    out.append((T[j][3], lo, hi))
            return out
        for j, tok in enumerate(T):
            if tok[0] != "word" or j + 1 >= len(T):
                continue
            body = None
            if j and T[j - 1][3] == "function" and T[j + 1][3] == "(":
                close = src.match.get(j + 1)
                body = close + 1 if close is not None and close + 1 < len(T) and T[close + 1][3] == "{" else None
            elif T[j + 1][3] == "=" and j + 2 < len(T):
                k = j + 2 + (1 if T[j + 2][3] == "async" else 0)
                if k < len(T) and T[k][3] == "(" and src.match.get(k) is not None and src.match[k] + 1 < len(T) \
                        and T[src.match[k] + 1][3] == "=>":
                    arrow = src.match[k] + 1
                elif k + 1 < len(T) and T[k][0] == "word" and T[k + 1][3] == "=>":
                    arrow = k + 1
                elif k < len(T) and T[k][3] == "function":
                    arrow = None
                    close = src.match.get(k + 1) if k + 1 < len(T) and T[k + 1][3] == "(" else None
                    body = close + 1 if close is not None and close + 1 < len(T) and T[close + 1][3] == "{" else None
                else:
                    continue
                if arrow is not None:
                    if arrow + 1 < len(T) and T[arrow + 1][3] == "{":
                        body = arrow + 1
                    else:
                        out.append((tok[3], arrow, self.statement(arrow, arrow, taint=True)[1]))
                        continue
            elif T[j + 1][3] == "(" and tok[3] not in KEYWORDS and not (j and T[j - 1][3] in (".", "?.")):
                close = src.match.get(j + 1)
                if close is not None and close + 1 < len(T) and T[close + 1][3] == "{" and self.block(close + 1):
                    body = close + 1
            if body is not None and src.match.get(body) is not None:
                out.append((tok[3], body, src.match[body]))
        return out

    def assigned(self, lo: int, hi: int, toks: list[int] | None = None) -> set:
        """Names a statement binds: the targets before EVERY top-level `=` (a chained `a = b = v` binds both; a JS
        statement splits into declarators, `let q = 1, d = v`), an assignment expression's name (`(m := v)`, JS
        `while ((m = v))`), `for` targets, and `as` names. Only the statement's own tokens (`toks`) bind: a nested block
        is its own statement."""
        T, names = self.src.code, set()
        own = sorted(toks) if toks is not None else list(range(lo, hi + 1))
        # A JS statement splits at top-level commas into declarators, except inside a type annotation (`let m: Map<K, V>
        # = v`); a Python statement keeps its tuple targets whole.
        segments, cur, depth, annotation, seen_eq = [], [], 0, False, False
        for j in own:
            kind = T[j][0]
            if kind == "open":
                depth += 1
            elif kind == "close":
                depth -= 1
            elif depth == 0 and kind == "colon" and not seen_eq:
                annotation = True
            elif depth == 0 and kind == "op" and T[j][3] in self.ASSIGN_OPS:
                seen_eq, annotation = True, False
            if not self.src.py and depth == 0 and kind == "comma" and not annotation:
                segments.append(cur)
                cur, seen_eq = [], False
                continue
            cur.append(j)
        segments.append(cur)
        for seg in segments:
            depth, start = 0, seg[0] if seg else None
            for j in seg:
                kind = T[j][0]
                if kind == "open":
                    depth += 1
                elif kind == "close":
                    depth -= 1
                elif kind == "op" and T[j][3] in self.ASSIGN_OPS:
                    if depth == 0:
                        names |= self.target_names(start, j)
                        start = j + 1
                    elif T[j][3] == ":=" or not self.src.py:
                        k = j - 1
                        k -= 1 if k > 0 and T[k][0] == "op" and T[k][3] in self.COMPOUND_PREFIX else 0
                        if k >= 0 and T[k][0] == "word" and not (k and T[k - 1][3] in (".", "?.")):
                            names.add(T[k][3])
        for j in range(lo, hi + 1):
            if j not in own:
                continue
            if T[j][0] == "word" and T[j][3] == "for":
                names |= self.for_targets(j, hi)
            elif T[j][0] == "word" and T[j][3] == "as" and j + 1 <= hi and T[j + 1][0] == "word":
                names.add(T[j + 1][3])
        return names - LITERAL_WORDS

    MUTATORS = frozenset({"append", "extend", "insert", "add", "update", "setdefault", "push", "unshift", "set",
                          "splice"})
    COMPOUND_PREFIX = frozenset({"+", "-", "*", "/", "%", "**", "|", "&", "^", "??", "||", "&&", "@"})

    def target_names(self, lo: int, hi: int) -> set:
        """Names one assignment target list binds (tokens lo..hi-1): every top-level name (`self.paths` binds `paths`
        as an attribute; a call's name never), a subscript's base (`x[i]`), every name inside a destructuring, tuple or
        list pattern (`{a, b: c}`, `[x, *y]`, `(a, (b, c))`); never a type annotation (`a: T`)."""
        T, match, names = self.src.code, self.src.match, set()
        depth, annotation, prev, j = 0, False, None, lo
        while j < hi:
            kind = T[j][0]
            if kind == "open":
                pattern_start = prev is None or T[prev][0] == "comma" or T[prev][3] in self.DECL_WORDS \
                    or (T[prev][0] == "op" and T[prev][3] in ("...", "*", "**"))
                if depth == 0 and not annotation and pattern_start and T[j][3] in ("{", "[", "(") \
                        and match.get(j) is not None and match[j] < hi:
                    names |= self.param_names(j + 1, match[j], pattern=T[j][3] == "{")
                    prev, j = match[j], match[j] + 1
                    continue
                depth += 1
            elif kind == "close":
                depth -= 1
            elif depth == 0 and kind == "colon":
                annotation = True  # `name: Type = value`: the words after the colon are a type
            elif depth == 0 and kind == "comma":
                annotation = False
            elif kind == "word" and depth == 0 and not annotation and T[j][3] not in self.DECL_WORDS \
                    and T[j][3] not in KEYWORDS and not (j + 1 < hi and T[j + 1][3] == "("):
                names.add(T[j][3])
            prev, j = j, j + 1
        return names

    def for_target_tokens(self, toks: list[int]) -> set:
        """Token positions of the names the statement's `for`s bind (a binding, not a read): JS, the header words before
        a top-level `of`/`in`, or a C-style init's names; Python, the words between `for` and `in`."""
        T, match, out = self.src.code, self.src.match, set()
        own = set(toks)
        for j in toks:
            if not (T[j][0] == "word" and T[j][3] == "for"):
                continue
            k = j + 1
            if k < len(T) and T[k][3] == "await":
                k += 1
            if not self.src.py and k < len(T) and T[k][3] == "(" and match.get(k) is not None:
                end, depth, stop = match[k], 0, None
                for i in range(k + 1, end):
                    depth += {"open": 1, "close": -1}.get(T[i][0], 0)
                    if depth == 0 and T[i][0] == "word" and T[i][3] in ("in", "of"):
                        stop = i
                        break
                if stop is not None:
                    out |= {i for i in range(k + 1, stop) if T[i][0] == "word"}
                else:
                    depth = 0
                    for i in range(k + 1, end):
                        depth += {"open": 1, "close": -1}.get(T[i][0], 0)
                        if depth == 0 and T[i][0] == "op" and T[i][3] == ";":
                            break
                        if depth == 0 and T[i][0] == "word" and i + 1 < end and T[i + 1][0] == "op" \
                                and T[i + 1][3] in self.ASSIGN_OPS:
                            out.add(i)
                continue
            while k < len(T) and k in own and not (T[k][0] == "word" and T[k][3] in ("in", "of")):
                if T[k][0] == "word":
                    out.add(k)
                k += 1
        return out

    def for_targets(self, j: int, hi: int) -> set:
        """The names a `for` at token j binds. JS: inside its header `( ... )` only: the targets before a top-level
        `in`/`of`, or a C-style header's init names (`for (let i = 0, n = 1; ...)`). Python: the words before `in`."""
        T, match, names = self.src.code, self.src.match, set()
        k = j + 1
        if k <= hi and T[k][3] == "await":
            k += 1
        if not self.src.py and k <= hi and T[k][3] == "(" and match.get(k) is not None:
            end, depth, stop = match[k], 0, None
            for i in range(k + 1, end):
                depth += {"open": 1, "close": -1}.get(T[i][0], 0)
                if depth == 0 and T[i][0] == "word" and T[i][3] in ("in", "of"):
                    stop = i
                    break
            if stop is not None:
                return {T[i][3] for i in range(k + 1, stop) if T[i][0] == "word"} - self.DECL_WORDS - KEYWORDS
            depth = 0
            for i in range(k + 1, end):
                depth += {"open": 1, "close": -1}.get(T[i][0], 0)
                if depth == 0 and T[i][0] == "op" and T[i][3] == ";":
                    break
                if depth == 0 and T[i][0] == "word" and T[i][3] not in self.DECL_WORDS and i + 1 < end \
                        and T[i + 1][0] == "op" and T[i + 1][3] in self.ASSIGN_OPS:
                    names.add(T[i][3])
            return names
        while k <= hi and not (T[k][0] == "word" and T[k][3] in ("in", "of")):
            if T[k][0] == "word" and T[k][3] not in self.DECL_WORDS:
                names.add(T[k][3])
            k += 1
        return names

    SEED_ANCHOR = True  # a parent step BEFORE the read in its own statement acts on the base (an anchor)

    def own_tokens(self, lo: int, hi: int) -> list[int]:
        """The statement's own tokens: a nested block (a callback or function body) is its own statement."""
        T, src, out, j = self.src.code, self.src, [], lo
        while j <= hi:
            if T[j][0] == "open" and T[j][3] == "{" and self.block(j) and src.match.get(j) is not None:
                j = src.match[j] + 1
                continue
            out.append(j)
            j += 1
        return out

    def param_scopes(self, toks: list[int], hi: int) -> list[tuple[tuple[int, int], str]]:
        """(scope, name) for each parameter of the arrows, `function`s and lambdas a statement defines: a parameter is
        visible from its function's start to the end of its body (a block's `}`; an expression body's enclosing bracket
        or the statement end `hi`)."""
        T, match, enclosing, out = self.src.code, self.src.match, self.src.enclosing, []
        drop = KEYWORDS | self.DECL_WORDS | LITERAL_WORDS
        for j in toks:
            if T[j][0] == "op" and T[j][3] == "=>":
                body = j + 1
                if body < len(T) and T[body][3] == "{" and match.get(body) is not None:
                    end = match[body]
                else:
                    stack = enclosing[j] if j < len(enclosing) else ()
                    end = match.get(stack[-1], hi) if stack else hi
                out += [((j, end), n) for n in self.arrow_params(j) - drop]
            elif T[j][0] == "word" and T[j][3] == "function":
                i = j + 1
                i += 1 if i < len(T) and T[i][3] == "*" else 0
                i += 1 if i < len(T) and T[i][0] == "word" else 0
                if i < len(T) and T[i][3] == "(" and match.get(i) is not None:
                    body = match[i] + 1
                    end = match[body] if body < len(T) and T[body][3] == "{" and match.get(body) is not None else hi
                    out += [((j, end), n) for n in self.param_names(i + 1, match[i]) - drop]
            elif T[j][0] == "word" and T[j][3] == "lambda":
                end, depth = j + 1, 0
                while end < len(T) and not (depth == 0 and T[end][0] == "colon"):
                    depth += {"open": 1, "close": -1}.get(T[end][0], 0)
                    end += 1
                out += [((j, hi), n) for n in self.param_names(j + 1, end) - drop]
        return out

    def class_bodies(self) -> list[tuple[int, int]]:
        """Token ranges of the class bodies: Python `class X:` blocks (by indentation), JS `class X {...}`."""
        src, T, out = self.src, self.src.code, []
        if src.py:
            lines = src.text.split("\n")
            for i, line in enumerate(lines):
                m = re.match(r"(\s*)class\s+\w+", line)
                if not m:
                    continue
                indent, end = len(m.group(1)), i + 1
                while end < len(lines) and (not lines[end].strip() or lines[end].lstrip().startswith("#")
                                            or len(lines[end]) - len(lines[end].lstrip()) > indent):
                    end += 1
                lo = bisect.bisect_left(src.starts, src.bounds(i)[0])
                hi = bisect.bisect_left(src.starts, src.bounds(end - 1)[1]) - 1
                out.append((lo, max(lo, hi)))
            return out
        for j, tok in enumerate(T):
            if tok[0] == "word" and tok[3] == "class":
                k = j + 1
                while k < len(T) and T[k][3] != "{" and T[k][0] in ("word", "op"):
                    k += 1
                if k < len(T) and T[k][3] == "{" and src.match.get(k) is not None:
                    out.append((k, src.match[k]))
        return out

    def function_scopes(self, funcs: list) -> list[tuple[int, int]]:
        """Every function body's token range, innermost first when sorted by size: the named functions, and in JS every
        arrow or `function` block body (anonymous callbacks included)."""
        T, match, out = self.src.code, self.src.match, [(lo, hi) for _, lo, hi in funcs]
        if not self.src.py:
            for j, tok in enumerate(T):
                if tok[0] == "op" and tok[3] == "=>" and j + 1 < len(T) and T[j + 1][3] == "{" \
                        and match.get(j + 1) is not None:
                    out.append((j + 1, match[j + 1]))
                elif tok[0] == "word" and tok[3] == "function":
                    i = j + 1
                    i += 1 if i < len(T) and T[i][3] == "*" else 0
                    i += 1 if i < len(T) and T[i][0] == "word" else 0
                    if i < len(T) and T[i][3] == "(" and match.get(i) is not None:
                        body = match[i] + 1
                        if body < len(T) and T[body][3] == "{" and match.get(body) is not None:
                            out.append((body, match[body]))
        return sorted(set(out), key=lambda r: r[1] - r[0])

    TYPE_OPS = frozenset({".", "<", ">", "|", "&", "?", ",", "=>"})

    def arrow_params(self, j: int) -> set:
        """The parameter names of the arrow whose `=>` is token j: `x =>`, `(a, b) =>`, and a TS return type
        `(a: A): R =>` (walked back over to its `):`). If the shape is not recognised, every word of the nearest group
        binds (the round-3 behaviour), so an unrecognised arrow over-taints rather than drops a parameter."""
        T, opener = self.src.code, self.src.opener
        k = j - 1
        if k < 0:
            return set()
        if T[k][0] == "close" and T[k][3] == ")" and opener.get(k) is not None:
            return self.param_names(opener[k] + 1, k)
        if T[k][0] == "word" and not (k and T[k - 1][0] == "colon") and not (k and T[k - 1][0] == "op"
                                                                               and T[k - 1][3] in self.TYPE_OPS):
            return {T[k][3]}
        c, steps = k, 0
        while c > 0 and steps < 64:
            steps += 1
            if T[c][0] == "colon":
                if T[c - 1][0] == "close" and T[c - 1][3] == ")" and opener.get(c - 1) is not None:
                    return self.param_names(opener[c - 1] + 1, c - 1)
                break
            if T[c][0] == "close" and opener.get(c) is not None:
                c = opener[c] - 1
            elif T[c][0] in ("word", "str") or (T[c][0] == "op" and T[c][3] in self.TYPE_OPS):
                c -= 1
            else:
                break
        if T[k][0] == "word":
            return {T[k][3]}
        if T[k][0] == "close" and opener.get(k) is not None:
            return {T[i][3] for i in range(opener[k] + 1, k) if T[i][0] == "word"}
        return set()

    def param_names(self, lo: int, hi: int, pattern: bool = False) -> set:
        """Binding names in tokens lo..hi-1, split at top-level commas: each element's own name, or the names of its
        destructuring pattern; never a type annotation (after `:`) or a default value (after `=`). In an object
        pattern, `key: target` binds the target."""
        T, match, names = self.src.code, self.src.match, set()
        i = lo
        while i < hi:
            end, depth = i, 0
            while end < hi and not (depth == 0 and T[end][0] == "comma"):
                depth += {"open": 1, "close": -1}.get(T[end][0], 0)
                end += 1
            j = i
            if pattern:
                depth = 0
                for c in range(i, end):
                    depth += {"open": 1, "close": -1}.get(T[c][0], 0)
                    if depth == 0 and (T[c][0] == "colon" or (T[c][0] == "op" and T[c][3] == "=")):
                        j = c + 1 if T[c][0] == "colon" else i
                        break
            while j < end and T[j][0] == "op" and T[j][3] in ("...", "*", "**"):
                j += 1
            if j < end and T[j][0] == "open" and T[j][3] in ("{", "[", "(") and match.get(j) is not None \
                    and match[j] < end:
                names |= self.param_names(j + 1, match[j], pattern=T[j][3] == "{")
            elif j < end and T[j][0] == "word":
                while j + 2 < end and T[j + 1][0] == "op" and T[j + 1][3] in (".", "?.") and T[j + 2][0] == "word":
                    j += 2  # a dotted target element (`(self.a, b) = ...`) binds its attribute
                names.add(T[j][3])
            i = end + 1
        return names - KEYWORDS - self.DECL_WORDS - LITERAL_WORDS

    def mentions(self, lo: int, toks: list[int]) -> tuple[set, set]:
        """(plain names, attribute names) a statement READS: an assignment's targets are not reads of them."""
        T = self.src.code
        depth, start = 0, None
        for j in toks:
            kind = T[j][0]
            if kind == "open":
                depth += 1
            elif kind == "close":
                depth -= 1
            elif depth == 0 and kind == "op" and T[j][3] in self.ASSIGN_OPS:
                start = j
                break
        if start is not None and start and T[start - 1][0] == "op" and T[start - 1][3] in self.COMPOUND_PREFIX:
            start = None  # an augmented assignment (`p /= ".."`, `p += "/.."`) reads its own target
        plain, attrs = set(), set()
        targets = self.for_target_tokens(toks)
        for j in toks:
            if (start is not None and j <= start) or j in targets:
                continue
            if T[j][0] == "word":
                (attrs if j and T[j - 1][3] in (".", "?.") else plain).add(T[j][3])
            elif T[j][0] == "str":
                for expr in self.src.subs.get(j, ()):
                    for m in SUB_NAME.finditer(expr):
                        if m.group(2) not in KEYWORDS:
                            (attrs if m.group(1) else plain).add(m.group(2))
        return plain, attrs

    def bound(self, lo: int, hi: int, toks: list[int]) -> tuple[set, set]:
        """(plain names, attribute names) a statement's assignment targets bind (parameters: `param_scopes`)."""
        T, plain, attrs = self.src.code, set(), set()
        for name in self.assigned(lo, hi, toks):
            hit = [j for j in toks if T[j][0] == "word" and T[j][3] == name]
            if hit and all(j and T[j - 1][3] in (".", "?.") for j in hit):
                attrs.add(name)
            else:
                plain.add(name)
        return plain, attrs

    def taint_check(self, src: Source) -> None:
        """Rule 7, lexical name taint (root, 2026-10-26).
        - Names bound from a computed root read are tainted, transitively within the file: assignment targets (a
          plain name, or an attribute such as `self.paths`), `for`/`as` targets, the parameters of callbacks and lambdas
          in a tainted statement, and a function whose `return` is tainted (its calls then yield a tainted value). A
          statement reads a name only on the right of its assignment; an attribute name matches only as an attribute.
        - A tainted statement that holds a parent step (`..`, '..', `.parent`, `.parents`, `os.pardir`, getattr(p,
          "parent"), a `dirname(` call) REFUSES. In the statement of the read itself, a parent step BEFORE the read
          acts on its base (an anchor such as `Path(__file__).parents[2] / "services"`), so it does not count, unless
          it sits inside a callback the statement defines (its parameters may receive the read).
        - A tainted value passed to a function DEFINED IN THIS FILE whose body holds a parent step REFUSES.
        - Residual: a tainted path handed to a helper defined in ANOTHER file that applies `..`. JSON binds no names.
        """
        self.src = src
        if not src.computed or not src.ok or src.ext not in PY_EXT | JS_EXT:
            return
        T = src.code
        parents = set(src.parent_toks)
        stmts, seen = [], set()
        # A name bound ONLY from parent material (os.pardir, dots-only literals, separators, `*`/`+`/join of those)
        # is itself a parent step wherever it is read. An anchor (`__file__`, `__dirname`, `import.meta`, cwd) never is.
        PURE = {"os", "path", "pardir", "join", "sep", "posix", ".", "*", "+", ",", "(", ")", "[", "]"}
        parent_names = set()
        for j in range(len(T)):
            if (T[j][0] == "op" and T[j][3] == "=" and j and T[j - 1][0] == "word"
                    and not (j > 1 and T[j - 2][3] in (".", "?."))):
                lo, hi = self.statement(j, j, taint=True)
                rhs = [T[i] for i in range(j + 1, hi + 1)]
                if rhs and any(i in parents for i in range(j + 1, hi + 1)) and all(
                        (t[0] == "str" and t[3][1] and re.fullmatch(r"[./\\]*", t[3][0]))
                        or (t[0] in ("op", "open", "close", "comma") and t[3] in PURE)
                        or (t[0] == "word" and (t[3] in PURE or t[3].isdigit()))
                        for t in rhs):
                    parent_names.add(T[j - 1][3])
        parents |= {j for j in range(len(T)) if T[j][0] == "word" and T[j][3] in parent_names
                    and not (j and T[j - 1][3] in (".", "?.")) and not (j + 1 < len(T) and T[j + 1][3] == "=")}
        for j in range(len(T)):
            rng = self.statement(j, j, taint=True)
            if rng not in seen:
                seen.add(rng)
                stmts.append(rng)
        own = {rng: self.own_tokens(*rng) for rng in stmts}
        reads = {rng: self.mentions(rng[0], own[rng]) for rng in stmts}
        funcs = self.functions()
        parent_funcs = {name for name, lo, hi in funcs if any(lo <= p <= hi for p in parents)}

        def returning(rng):
            """The function whose value this statement returns or yields. (An arrow with an expression body,
            `svc = (n) => read`, needs no rule: its own assignment binds the name in the same statement.)"""
            T0 = T[rng[0]]
            inside = [(hi - lo, name, lo) for name, lo, hi in funcs if lo <= rng[0] <= hi]
            if not inside:
                return None
            _, name, lo = min(inside)
            return name if T0[0] == "word" and T0[3] in ("return", "yield") else None

        computed = set(src.computed)
        # Scope, as each language scopes (a tainted (scope, name): scope is a function body's (lo, hi), or None for
        # the whole file):
        # - a parameter is visible only inside its own function (param_scopes);
        # - JS: a `const`/`let`/`var` declaration, or a declared `for` target, is local to its innermost function
        #   (anonymous callbacks included); a bare assignment may assign an outer binding, so it is file-wide;
        # - Python: an assignment is local to its innermost def unless the def declares it `global` or `nonlocal`;
        # - an attribute (`self.x`) and a function name are file-wide.
        scoped = self.function_scopes(funcs)

        def scope_of(j):
            return next(((lo, hi) for lo, hi in scoped if lo <= j <= hi), None)

        escapes = {}  # Python: the names a def declares global or nonlocal (nested defs included: a superset)
        if src.py:
            for lo, hi in scoped:
                names = set()
                for k in range(lo, hi + 1):
                    if T[k][0] == "word" and T[k][3] in ("global", "nonlocal"):
                        i = k + 1
                        while i <= hi and T[i][0] in ("word", "comma") and src.line_of(T[i][1]) == src.line_of(T[k][1]):
                            if T[i][0] == "word":
                                names.add(T[i][3])
                            i += 1
                escapes[(lo, hi)] = names

        def loop_scope(f, rng):
            """A JS `for` at token f: its header and its body (a block, or the single statement after the header)."""
            k = f + 1 + (1 if f + 1 < len(T) and T[f + 1][3] == "await" else 0)
            close = src.match.get(k) if k < len(T) and T[k][3] == "(" else None
            if close is None:
                return (f, rng[1])
            body = close + 1
            if body < len(T) and T[body][3] == "{" and src.match.get(body) is not None:
                return (f, src.match[body])
            return (f, max(rng[1], self.statement(body, body, taint=True)[1]) if body < len(T) else rng[1])

        classes = self.class_bodies()
        properties = set(re.findall(r"@property\s*\n\s*def\s+(\w+)", src.text)) if src.py else set()

        def class_level(j):
            """Token j is directly in a class body: inside a class, and in no function nested in that class."""
            for lo, hi in classes:
                if lo <= j <= hi:
                    sc = scope_of(j)
                    return sc is None or not (lo <= sc[0] and sc[1] <= hi)
            return False

        def decl_scope(rng, name):
            sc = scope_of(rng[0])
            if sc is None and src.py:
                return None
            if src.py:
                return None if name in escapes.get(sc, ()) else sc
            k = next((k for k in own[rng] if T[k][3] not in ("export", "default", "declare")), None)
            if k is not None and T[k][3] == "for":
                f = k
                k = next((i for i in own[rng] if i > k and T[i][3] not in ("await", "(")), None)
                if k is not None and T[k][3] in ("const", "let"):
                    return loop_scope(f, rng)  # a `for (const|let ...)` target lives in its loop
            if k is not None and T[k][3] in ("const", "let"):
                block = next((x for x in reversed(src.enclosing[rng[0]]) if self.block(x)), None)
                return (block, src.match[block]) if block is not None and src.match.get(block) is not None else None
            return sc if k is not None and T[k][3] == "var" else None

        vars_, attrs_, by_name, seeded = set(), set(), set(), {}
        names_any = set()

        def bind(rng):
            p, a = self.bound(rng[0], rng[1], own[rng])
            vars_.update((decl_scope(rng, n), n) for n in p)
            names_any.update(p)
            attrs_.update(a)
            if class_level(rng[0]):
                attrs_.update(p)  # a class attribute or field is read as `self.x`, `this.x`, `Cls.x`
            for k in own[rng]:  # container mutation: the receiver now holds what this statement passes in
                if T[k][0] != "word" or k + 1 >= len(T) or T[k + 1][3] != "(":
                    continue
                if T[k][3] in self.MUTATORS and k >= 2 and T[k - 1][3] in (".", "?.") and T[k - 2][0] == "word":
                    r = k - 2
                    if r and T[r - 1][3] in (".", "?."):
                        attrs_.add(T[r][3])
                    else:
                        vars_.add((None, T[r][3]))
                        names_any.add(T[r][3])
                elif T[k][3] == "setattr" and src.match.get(k + 1) is not None:
                    inner = range(k + 2, src.match[k + 1])
                    first = next((i for i in inner if T[i][0] == "word"), None)
                    name = next((T[i][3][0] for i in inner if T[i][0] == "str" and T[i][3][1]), None)
                    if name:
                        attrs_.add(name)
                    if first is not None:
                        vars_.add((None, T[first][3]))
                        names_any.add(T[first][3])
            for sc, n in self.param_scopes(own[rng], rng[1]):
                vars_.add((sc, n))
                names_any.add(n)
            if src.py and rng in seeded and T[rng[0]][3] in ("def", "async"):
                k = next((i for i in range(rng[0], rng[1] + 1) if T[i][3] == "("), None)
                body = next(((lo, hi) for name, lo, hi in funcs
                             if lo <= rng[0] <= hi and T[lo][3] in ("def", "async")), None)
                if k is not None and body and src.match.get(k) is not None:
                    i, close = k + 1, src.match[k]
                    while i < close:  # each parameter segment; bind it only if its own default holds the read
                        end, depth = i, 0
                        while end < close and not (depth == 0 and T[end][0] == "comma"):
                            depth += {"open": 1, "close": -1}.get(T[end][0], 0)
                            end += 1
                        if any(x in computed for x in range(i, end)):
                            name = next((T[x][3] for x in range(i, end) if T[x][0] == "word"), None)
                            if name:
                                vars_.add((body, name))
                                names_any.add(name)
                        i = end + 1
            f = returning(rng)
            if f and f in properties:
                attrs_.add(f)  # a @property is read as an attribute
            if f:
                vars_.add((None, f))
                names_any.add(f)

        def visible(name, j):
            """A plain name read at token j is tainted if its binding's scope encloses j (or is module-level)."""
            return (None, name) in vars_ or any(sc is not None and sc[0] <= j <= sc[1] and n == name for sc, n in vars_)

        for rng in stmts:
            here = [k for k in own[rng] if k in computed]
            if here:
                seeded[rng] = min(here)
                bind(rng)
        changed = True
        while changed:
            changed = False
            for rng in stmts:
                plain, attrs = reads[rng]
                if rng in by_name or not (attrs & attrs_ or any(visible(n, rng[0]) for n in plain & names_any)):
                    continue
                by_name.add(rng)
                changed = True
                bind(rng)
        def carries(lo, hi):
            return any(x in computed or (T[x][0] == "word" and visible(T[x][3], x)
                                         and not (x and T[x - 1][3] in (".", "?.")))
                       for x in range(lo, hi))
        cwd_set = False
        for rng in set(seeded) | by_name:
            for k in own[rng]:
                if T[k][0] == "word" and T[k][3] == "chdir" and k + 1 < len(T) and T[k + 1][3] == "(" \
                        and src.match.get(k + 1) is not None and carries(k + 2, src.match[k + 1]):
                    cwd_set = True
                elif T[k][0] == "word" and T[k][3] == "cwd" and k + 1 < len(T) and T[k + 1][3] in ("=", ":") \
                        and self.in_exec(k):  # an exec call's working directory, never a def's own parameter
                    end, depth = k + 2, 0
                    while end < len(T) and not (depth == 0 and (T[end][0] == "comma" or T[end][0] == "close")):
                        depth += {"open": 1, "close": -1}.get(T[end][0], 0)
                        end += 1
                    cwd_set = cwd_set or carries(k + 2, end)
        if cwd_set and (re.search(r"(?<![\w.])\.\./", src.text)
                        or any(t[0] == "str" and t[3][1] and PARENT_STEP.search(t[3][0]) for t in T)
                        or any(t[0] == "word" and t[3] == "pardir" for t in T)):
            self.refuse("unresolved (rule 7: a working directory set from a computed root read, and a `..` step)")
        for rng in set(seeded) | by_name:
            first = seeded.get(rng) if self.SEED_ANCHOR and rng not in by_name else None
            line = src.line_of(T[rng[0]][1]) + 1
            # A parent step inside a callback this statement defines is never an anchor: its parameters may receive
            # the read (`map(lambda p: join(p, ".."), [read])`).
            callbacks = [sc for sc, _ in self.param_scopes(own[rng], rng[1])]
            if any(j in parents and (first is None or j >= first or any(a <= j <= b for a, b in callbacks))
                   for j in own[rng]):
                self.refuse(f"unresolved (rule 7: a parent step on a name bound from a computed root read, line {line})")
            for j in own[rng]:
                if T[j][0] == "word" and T[j][3] in parent_funcs and not (j + 1 < len(T) and T[j + 1][3] == "(") \
                        and not (j and T[j - 1][3] in ("def", "function", ".", "?.")) \
                        and not (j + 1 < len(T) and T[j + 1][3] == "="):
                    self.refuse("unresolved (rule 7: a same-file function holding a parent step, passed by reference "
                                f"in a statement with a computed root read, line {line})")
                if T[j][0] == "word" and T[j][3] in parent_funcs and j + 1 < len(T) and T[j + 1][3] == "(" \
                        and not (j and T[j - 1][3] in ("def", "function")):
                    close = src.match.get(j + 1)
                    args = range(j + 2, close if close is not None else j + 2)
                    if any((T[i][0] == "word" and visible(T[i][3], i) and not T[i - 1][3] in (".", "?."))
                           or (T[i][0] == "word" and T[i][3] in attrs_ and T[i - 1][3] in (".", "?."))
                           or i in computed for i in args):
                        self.refuse("unresolved (rule 7: a computed root read handed to a same-file function "
                                    f"holding a parent step, line {line})")


PACKAGE_JSON_MAX_DEPTH = 64


def json_nesting_depth(text: str) -> int:
    """The deepest `[`/`{` nesting in JSON text, skipping strings and their escapes. A package.json deeper than
    PACKAGE_JSON_MAX_DEPTH refuses before it is parsed: how deep `json.loads` can recurse depends on the interpreter
    (CPython 3.11 stops near 1000 levels, 3.12 goes further), and a refusal must not depend on which Python runs."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def strict_json_constant(name: str):
    """`json.loads` accepts NaN, Infinity and -Infinity; JSON (and npm's JSON.parse) does not."""
    raise ValueError(f"{name} is not JSON")


def workspace_graph(root: Path, cfg: dict) -> dict[str, dict]:
    workspace = cfg.get("workspace") or {}
    if workspace.get("type") == "pnpm":
        return discover_pnpm_packages(root, workspace.get("extra_deps"))
    if workspace.get("type") == "declared":
        return declared_packages(workspace)
    raise ValueError("reader graph requires declared or pnpm workspace")


ALWAYS_DIR_NAME = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]*")


def always_reader_dirs(es: dict, cfg: dict, package_dirs, roots, reader_dirs: set) -> set[str]:
    """`edge_scan.always_reader_dirs`: top-level reader directories whose files run ONLY in `always` jobs. No plan can
    skip an `always` job, so what such a file reads cannot change a selection; the directory is left out of the scan,
    and a construct the scanner cannot read there no longer refuses (which planned every change FULL). A change to a
    file in it is still unmapped and still plans FULL. The caller proves the premise (no selected job or matrix
    executes the directory); this refuses every configuration under which leaving it out could hide a read that
    selects: anything but a plain top-level name, a directory that is not a declared reader directory, a scan root,
    one holding a workspace package, or a reader job whose rule is not exactly `always`."""
    declared = es.get("always_reader_dirs")
    if declared is None:
        return set()
    if not isinstance(declared, list) or not declared:
        raise ValueError("edge_scan.always_reader_dirs must be a non-empty list of top-level directory names")
    for name in declared:
        if not isinstance(name, str) or name in (".", "..") or not ALWAYS_DIR_NAME.fullmatch(name):
            raise ValueError(f"edge_scan.always_reader_dirs entry {name!r} is not one top-level directory name")
        if name not in reader_dirs:
            raise ValueError(f"edge_scan.always_reader_dirs entry {name!r} is not in edge_scan.reader_dirs")
        if name in roots:
            raise ValueError(f"edge_scan.always_reader_dirs entry {name!r} is a scan root")
        if any(d == name or d.startswith(name + "/") for d in package_dirs):
            raise ValueError(f"edge_scan.always_reader_dirs entry {name!r} holds a workspace package")
    if len(set(declared)) != len(declared):
        raise ValueError("edge_scan.always_reader_dirs repeats a directory")
    job = es.get("reader_job")
    if not isinstance(job, str) or (cfg.get("jobs") or {}).get(job) != "always":
        raise ValueError("edge_scan.always_reader_dirs needs edge_scan.reader_job to name a job whose rule is \"always\"")
    return set(declared)


# ---------- imported files outside every package (1.5.0) ----------
# A package file that imports a file outside every package runs that file's code, so what the file reads, the package
# reads. Before 1.5.0 a relative path resolving outside every package was dropped (`targets - {None}`): a test in package
# a that imported ../../scripts/x.mjs, where x.mjs reads packages/b, gave deps(a) = [] and credited b only to the reader
# job, so a change to b never selected a's tests (cli, 2026-10-27; spine's rulings D2/D3/D5 the same day).
#   1. EDGE: a relative path on a non-comment line of a package file (`../`, as `rel` matches) that resolves to a
#      tracked path outside every package; and, from a file outside every package already reached, every `./` or `../`
#      string (a shell `source`, `. ` or `$(dirname "$0")/` path too), read from the WHOLE file, since a `./` import
#      never matches the scan's grep. A symlink resolves by its target. A directory is every tracked file beneath it,
#      and a package nested there is a read of that package.
#   2. CREDIT: per importing package, the transitive closure (cycles end) credits it every read the scan found in each
#      reached file. A `.md` file is prose: its edge is recorded, nothing is credited. A data file is credited (that only
#      over-approximates) but imports nothing; only code (JS/TS, Python, shell) is followed further.
#   3. FAIL CLOSED: a reached path under `always_reader_dirs` refuses (that directory is not always-only); a reached CODE
#      file the scan excludes refuses (its reads cannot be credited); so does a symlink loop.
#   4. COMPUTED (D2, strict by declaration): a module-loading call whose argument is not one plain literal, in a package
#      file or a reached file, refuses unless an `edge_scan.computed_imports` entry declares it ({file, expr, reach},
#      `expr` the exact argument text, whitespace collapsed). The calls: `import(`, `require(`, `require.resolve(`,
#      `import.meta.resolve(`, `module.require(`, `createRequire(...)(` and a name bound to `createRequire(...)`.
#      `reach` is "package" (inside the importing package), "external" (npm or stdlib by name), "fixture" (a test temp
#      dir), or a list of repo paths, each then an edge. THE FLOOR (refined in spine's pre-review):
#      - every component literal and anchored at the file's own directory (`__dirname`, `import.meta.dirname`, a name
#        bound to `dirname(fileURLToPath(import.meta.url))`; `pathToFileURL(...).href` unwrapped): a literal import,
#        resolved and mapped, with no declaration;
#      - a parent step only in the LEADING literal prefix, that prefix resolving inside the importing package's own
#        directory: allowed, declared reach "package" (the reviewer owns the claim about the substituted part);
#      - any other parent step, or a literal naming a top-level directory outside every package where nothing anchors
#        it: refuses even when declared. An escape has to be written as a literal path, which the scan maps.
#   5. DECLARED (D5): `check` fails on an imported path no `extra_edges` glob maps to at least its importers, so a change
#      to it selects them through plan.classify_paths, and on a computed_imports entry that matches no live site.
CODE_EXT = JS_EXT | PY_EXT | {"sh", "bash"}
# Files that can import modules but that the scan does not parse (root's delta R4 of #33, N5): reaching one refuses.
IMPORTING_UNPARSED_EXT = frozenset({"mdx", "astro", "vue", "svelte"})
# TypeScript's own module resolution (NodeNext and bundler alike): a `.js` specifier names its `.ts`, `.tsx` or `.d.ts`
# source, `.jsx` its `.tsx`, `.mjs` its `.mts` or `.d.mts`, `.cjs` its `.cts` or `.d.cts`. The house style writes every
# ESM import of a TypeScript file that way (`import "../../scripts/x.js"` loads scripts/x.ts).
TS_SOURCES = {".js": (".ts", ".tsx", ".d.ts"), ".jsx": (".tsx",), ".mjs": (".mts", ".d.mts"), ".cjs": (".cts", ".d.cts")}
COMPUTED_REACH = frozenset({"package", "external", "fixture"})
# Every line a loader call can start on (loader_call_opens decides). A name bound to createRequire(...) lives in a file
# that names createRequire, so that word finds its file.
IMPORT_CALL_GREP = (r"(^|[^A-Za-z0-9_$.])(import|require)[[:space:]]*\(|(require|import\.meta)\.resolve[[:space:]]*\("
                    r"|module\.require[[:space:]]*\(|createRequire")
SHELL_RELATIVE = re.compile(r"(?<![\w.$/-])(\.\.?/[A-Za-z0-9_.@+/-]+)")
SHELL_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELL_SEPARATOR = re.compile(r"&&|\|\||[;|&]")
SHELL_CD = re.compile(r"^\s*(?:[({!]\s*|(?:then|do|else|if)\s+)*(?:cd|pushd)(?:\s+(?P<arg>.*?))?\s*$")
SHELL_SELF_CD = re.compile(r"""^["']?(?:\$\(\s*dirname\s+["']?\$(?:0|\{?BASH_SOURCE(?:\[0\])?\}?)["']?\s*\)|\$\{BASH_SOURCE%/\*\})"""
                           r"""(?P<rel>/[A-Za-z0-9_.@+/-]*)?["']?\s*(?:\|\|.*)?$""")


def shell_cwd_spans(text: str, own: str) -> dict[int, list[tuple[int, int, frozenset | None]]]:
    """For each line of a shell file (its index), the segments of the STRIPPED line, each with the set of directories the
    script may be in there, or None when that cannot be known.

    A shell script runs from its caller's directory, so a relative path is resolved where the script has `cd`'d to
    (spine's A2 census: 57 vagary-core runners do `cd "$(dirname "$0")/.."`, then `bash ../../scripts/ci-test-pg.sh`). A
    `cd` or `pushd` to the script's own directory, or below or above it, ADDS that directory: the set keeps the earlier
    ones, so a `cd` that may not run (`[ -d x ] && cd …`, a subshell, a function) is still covered. Any other `cd` (a
    literal relative path, an absolute one, a computed one, none, `-`) makes the directory unknown for the rest of the
    file (fail closed). A heredoc body is text, never a command."""
    cwds: frozenset | None = frozenset({own})
    spans: dict[int, list] = {}
    end = None
    for i, raw in enumerate(text.split("\n")):
        line = raw.strip()
        if end is not None:
            spans[i] = [(0, len(line), cwds)]
            if line == end:
                end = None
            continue
        if line.startswith("#"):
            spans[i] = [(0, len(line), cwds)]
            continue
        code = RootLiteral.strip_comment(line).rstrip()  # a trailing `# …` is no command: `cd x   # note`
        cuts = [m.span() for m in SHELL_SEPARATOR.finditer(code)]
        starts = [0] + [b for _, b in cuts]
        ends = [a for a, _ in cuts] + [len(code)]
        segments = []
        for a, b in zip(starts, ends):
            segments.append((a, b, cwds))
            cd = SHELL_CD.match(code[a:b])
            if cd:
                arg = (cd.group("arg") or "").strip()
                self_cd = SHELL_SELF_CD.match(arg) if arg else None
                if self_cd and cwds is not None:
                    cwds = cwds | {posixpath.normpath(posixpath.join(own, (self_cd.group("rel") or "").lstrip("/")))}
                elif not self_cd:
                    cwds = None
        if len(code) < len(line):
            segments.append((len(code), len(line), cwds))
        spans[i] = segments
        heredoc = SHELL_HEREDOC_OPEN.search(code)
        if heredoc:
            end = heredoc.group(2)
    return spans


def shell_cd_ranges(line: str) -> list[tuple[int, int]]:
    """The spans of a stripped shell line that are a `cd`/`pushd` to the script's own directory (or above or below it).
    shell_cwd_spans models where those move the script, so their argument is never a name. Any other `cd` keeps its
    argument a name: it is the directory the next commands run in (`(cd "$d/../../packages/shared" && make)`, R5V14)."""
    code = RootLiteral.strip_comment(line).rstrip()
    cuts = [m.span() for m in SHELL_SEPARATOR.finditer(code)]
    starts = [0] + [b for _, b in cuts]
    ends = [a for a, _ in cuts] + [len(code)]
    ranges = []
    for a, b in zip(starts, ends):
        cd = SHELL_CD.match(code[a:b])
        if cd and SHELL_SELF_CD.match((cd.group("arg") or "").strip() or "-"):
            ranges.append((a, b))
    return ranges


def shell_bases_at(spans: dict, line: int, offset: int) -> frozenset | None:
    for a, b, cwds in spans.get(line, []):
        if a <= offset <= b:
            return cwds
    return spans[line][-1][2] if spans.get(line) else None
SHELL_SELF_DIR = re.compile(r"(?:\$\(\s*dirname\s+[\"']?\$(?:0|\{?BASH_SOURCE(?:\[0\])?\}?)[\"']?\s*\)|\$\{BASH_SOURCE%/\*\})"
                            r"/([A-Za-z0-9_.@+/-]+)")
def today() -> datetime.date:
    """The UTC date the registry review judges against (a function, so tests pin it)."""
    return datetime.datetime.now(datetime.timezone.utc).date()


REVIEW_DAYS = 30


def reviewed(kind: str, entries: list, key: str) -> None:
    """Root's ruling on #33 round 3: the two declaration lists are a REGISTRY, reviewed like the secret-scan registry.
    Each entry carries a non-empty `reason` (for reach "none": why the name never runs) and a `review_by` ISO date at
    most REVIEW_DAYS ahead. A reasonless, expired or too-distant entry refuses: it fails toward FULL, never to a pass."""
    now, bad = today(), []
    for d in entries:
        where = f"{d['file']}: {d[key]}"
        if not isinstance(d["reason"], str) or not d["reason"].strip():
            bad.append(f"{where} has no reason")
            continue
        try:
            by = datetime.date.fromisoformat(d["review_by"]) if isinstance(d["review_by"], str) else None
        except ValueError:
            by = None
        if by is None:
            bad.append(f"{where} review_by is not an ISO date")
        elif by < now:
            bad.append(f"{where} expired on {by.isoformat()}")
        elif by > now + datetime.timedelta(days=REVIEW_DAYS):
            bad.append(f"{where} review_by {by.isoformat()} is more than {REVIEW_DAYS} days out")
    if bad:
        raise ValueError(f"edge_scan.{kind} registry review: " + "; ".join(bad) + " (renew it with a reason and a "
                         f"review_by within {REVIEW_DAYS} days, after root's R4 record)")


# Text that runs nothing. Not `.mdx`, which compiles to JS (its imports run, and Storybook or Docusaurus collect it by
# glob). Not `.txt`: a CMakeLists.txt builds, pytest's default --doctest-glob is `test*.txt`, and a list file can feed a
# runner (`xargs -a tests.txt node --test`).
PROSE_EXT = frozenset({"md", "markdown", "rst", "adoc"})
IGNORE_LIST = re.compile(r"\.[A-Za-z0-9_-]*ignore")  # .gitignore, .dockerignore, .gitleaksignore, .prettierignore, ...
# The package.json fields that only describe or publish a package. Every other field is read, because runner configs
# live there too (`"mocha": {"spec": "lib/"}`, `"jest": {"roots": [...]}`, `"ava": {"files": [...]}`).
PACKAGE_METADATA = frozenset({"name", "version", "description", "keywords", "homepage", "bugs", "license", "author",
                              "contributors", "maintainers", "funding", "repository", "files", "directories",
                              "publishConfig", "private", "engines", "os", "cpu"})

def grep_read_everything(out, what: str) -> None:
    """A pass that did not read every file it was asked to cannot vouch for what it did not see, so it refuses (FULL),
    typed, never reads as a clean miss and never crashes. Two signals, because git changed: git 2.50 exits 1, the "no
    match" status, and prints `unable to read <oid>` for a blob a partial clone lacks (lazy fetching off); git 2.56 exits
    128 (#47's planner-tests on a GitHub-hosted runner, 2026-10-29). So any exit other than 0 (a match) or 1 (no match)
    refuses too. The detail is git's own first stderr line, bounded."""
    err = out.stderr or b""
    if b"unable to read" in err or out.returncode not in (0, 1):
        first = err.decode("utf-8", errors="replace").strip().splitlines()[:1]
        detail = f"git grep exit {out.returncode}" + (f": {first[0][:200]}" if first else "")
        raise ValueError(f"unresolved (reader closure unproven: {what} could not read the scanned tree ({detail}))")


def basename_mentions(repo: Path, cfg: dict, owner, revision: str | None, environment: dict,
                      routes_to: dict[str, set[str]], policy_files: set[str] = frozenset(), *,
                      other_tracked: dict | None = None, only_paths: list[str] | None = None) -> dict[str, list[list]]:
    """Root's round 3 of #33, the BACKSTOP's evidence. For every tracked path P outside every package that an
    extra_edges or inert_globs glob maps, gitlinks included (round 4, B2 and B4), its SUBJECTS are P plus every file
    outside every package that reaches P by a recorded route, to a fixpoint (round 4, B1: whatever runs such a file runs
    P). Every OTHER tracked text file, excluded directories included, and every symlink, whose target text git grep
    never reads (round 4, B3), that names a subject's basename as a token is a row [file, owning package or None, whether
    it is itself a subject, the subject it names]. assess() accepts P's mapping only when each row's package is selected
    or its file is a subject: a mention the scan did not attribute keeps P FULL, whatever spelling hid it.
    Per path (root's ruling): `other_tracked` is the other side's tree (BASE for the head pass, HEAD for the base pass),
    so the subjects are mapped paths of BASE and HEAD alike (a P the PR deletes or moves, named by an unchanged file,
    still counts); `only_paths` limits the files read to the PR's deleted and modified ones (the base pass)."""
    if only_paths is not None and not only_paths:
        return {}
    globs = [glob_to_regex(g) for g in sorted(set((cfg.get("extra_edges") or {}).keys())
                                              | set(cfg.get("inert_globs") or []))]
    if not globs:
        return {}
    tracked = tracked_paths(repo, revision, environment)
    mapped = sorted(p for p in set(tracked) | set(other_tracked or {}) if owner(p) is None and any(r.match(p) for r in globs))
    subjects: dict[str, set[str]] = {}
    for p in mapped:
        seen, queue = {p}, [p]
        while queue:
            for f in sorted(routes_to.get(queue.pop(), ())):
                if f not in seen and owner(f) is None:
                    seen.add(f)
                    queue.append(f)
        subjects[p] = seen
    by_base: dict[str, set[str]] = {}
    for member in set().union(*subjects.values()) if subjects else ():
        by_base.setdefault(posixpath.basename(member), set()).add(member)
    if not by_base:
        return {}
    # ONE extended-regex grep for every basename with an extension: git grep scales with the number of -F patterns
    # (1,337 vagary-core basenames took 115 s), a single ERE with the extensions as alternatives takes about a second.
    # Python then applies the exact token rule and looks each token up. The few others go through one -F grep.
    plain = re.compile(r"[A-Za-z0-9_.-]*\.[A-Za-z0-9]+")
    with_ext = sorted(b for b in by_base if plain.fullmatch(b))
    others = sorted(set(by_base) - set(with_ext))
    exts = sorted({b.rsplit(".", 1)[1] for b in with_ext})
    found: dict[str, set[str]] = {}
    # B3: git grep reads regular files only, so a symlink's target text (`alias.mjs -> worker.mjs`) is read here.
    readable = set(only_paths) if only_paths is not None else None
    links = [(p, (read_source(repo, p, revision, environment) if revision else os.readlink(repo / p)))
             for p, mode in sorted(tracked.items()) if mode == "120000" and (readable is None or p in readable)]
    # The base pass reads only the PR's deleted and modified files, in chunks (a long pathspec list).
    specs = [["."]] if only_paths is None else [[":(literal)" + x for x in only_paths[i:i + 400]]
                                                for i in range(0, len(only_paths), 400)]

    def grep(args: list[str]) -> list[tuple[str, str]]:
        rows = []
        for spec in specs:
            rows += grep_one(args, spec)
        return rows + links

    def grep_one(args: list[str], spec: list[str]) -> list[tuple[str, str]]:
        out = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "--null", "-I", *args,
                              *([revision] if revision else []), "--", *spec],
                             capture_output=True, timeout=120, env={**environment, "LC_ALL": "C"})
        if only_paths is not None and b"unable to read" in (out.stderr or b""):
            raise ValueError("unresolved (reader closure unproven: the base tree's changed files could not be read "
                             "(a blob is missing): a missing blob plans FULL)")
        if only_paths is not None and out.returncode not in (0, 1):
            raise ValueError(f"unresolved (reader closure unproven: the base tree's changed files could not be read "
                             f"(git grep exit {out.returncode}): a missing blob plans FULL)")
        grep_read_everything(out, "the backstop's mention grep")
        rows = []
        for record in out.stdout.decode("utf-8", errors="replace").split("\n"):
            name, sep, text = record.partition("\0")
            if sep:
                rows.append((name[len(revision) + 1:] if revision else name, text))
        return rows

    def hit(f: str, base: str) -> None:
        if f in policy_files:
            return  # the planner's own config names every mapped path by construction; it runs nothing
        for member in by_base.get(base, ()):
            if f != member:
                found.setdefault(member, set()).add(f)

    if exts:
        alternatives = "|".join(re.escape(e) for e in exts)
        token = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]*\.(?:" + alternatives + r"))(?![A-Za-z0-9_-]|\.[A-Za-z0-9])")
        for f, text in grep(["-E", r"[A-Za-z0-9_.-]*\.(" + alternatives + ")"]):
            for m in token.finditer(text):
                hit(f, m.group(1))
    if others:
        token = re.compile(r"(?<![A-Za-z0-9_.-])(" + "|".join(re.escape(b) for b in sorted(others, key=lambda b: (-len(b), b)))
                           + r")(?![A-Za-z0-9_-]|\.[A-Za-z0-9])")
        args = []
        for b in others:
            args += ["-e", b]
        for f, text in grep(["-F", *args]):
            for m in token.finditer(text):
                hit(f, m.group(1))
    # A runner that names only a DIRECTORY (`node --test "$REPO_ROOT/tools/"`, a workflow's `pytest scripts/`, a config's
    # `tools/**`) runs what is beneath it, so every directory that holds a subject is a subject too, written `tools/`. A
    # token ENDS at the directory and has a slash beside it (`tools/`, `./tools`, `$X/tools`; the bare word `test` in
    # `"scripts": {"test": ...}` or a workflow's `test:` job is no path): resolved from the mentioning file's directory
    # (from the root for a file at the root or under .github/, whose steps run there), or named after a prefix the scan
    # cannot resolve (`$X/`, `${X}/`, `/`).
    holders: dict[str, set[str]] = {}
    for member in set().union(*subjects.values()):
        d = posixpath.dirname(member)
        while d:
            holders.setdefault(d, set()).add(member)
            d = posixpath.dirname(d)
    if holders:
        # One generic prefilter (any path token that ends at a slash-terminated or slash-led segment) and an exact match
        # in Python: an alternation of every holder's path made git grep exceed its timeout on vagary-core.
        token = re.compile(r"[^\s\"'`=,;|&<>:\\]+")  # a backslash ends one too: JSON escapes `\"$ROOT/tools/\"`
        # Precision (root's R4 of round 4, P2 and P4), each skip on positive evidence only: prose runs nothing, so a
        # README's "lives in src/" is no directory runner; an ignore list only excludes, except a `!lib/` line, which
        # re-includes; and a package.json's metadata fields (its "files": ["lib/"]) publish, while every other field
        # is read. A manifest that does not parse, or is not an object, is read whole, toward a mention.
        manifests: dict[str, str | None] = {}

        def dir_texts(f: str, text: str) -> list[str]:
            base = posixpath.basename(f)
            if posixpath.splitext(f)[1].lstrip(".").lower() in PROSE_EXT:
                return []
            if IGNORE_LIST.fullmatch(base):
                return [ln.strip()[1:] for ln in text.splitlines() if ln.strip().startswith("!")]
            if base != "package.json":
                return [text]
            if f not in manifests:
                manifest = (read_source(repo, f, revision, environment) if revision
                            else (repo / f).read_text(errors="replace")).removeprefix("\ufeff")
                try:
                    # Bounded before the parse: RecursionError is no ValueError (3.11-3.13) and 3.14 parses any depth.
                    body = None if json_nesting_depth(manifest) > PACKAGE_JSON_MAX_DEPTH else json.loads(manifest)
                except ValueError:
                    body = None
                manifests[f] = (json.dumps({k: v for k, v in body.items() if k not in PACKAGE_METADATA},
                                           ensure_ascii=False) if isinstance(body, dict) else None)
            return [text] if manifests[f] is None else [manifests[f]]

        seen_manifests: set[str] = set()
        for f, line in grep(["-E", r"(^|[^A-Za-z0-9_.@-])[A-Za-z0-9_.@-]+/([^A-Za-z0-9_.@/-]|$)|/[A-Za-z0-9_.@-]+([^A-Za-z0-9_.@/-]|$)"]):
            if f in policy_files or f in seen_manifests:
                continue
            here = "" if "/" not in f or f.startswith(".github/") else posixpath.dirname(f)
            texts = dir_texts(f, line)
            if posixpath.basename(f) == "package.json" and manifests.get(f) is not None:
                seen_manifests.add(f)  # its fields are read once, whole
            for m in (m for text in texts for m in token.finditer(text)):
                core = m.group(0).rstrip("/")
                if not core or ("/" not in core and not m.group(0).endswith("/")):
                    continue  # a bare word, not a path
                if core.startswith("/") or any(c in core for c in "$%{}()~"):
                    # after a prefix the scan cannot resolve, by name: every holder the token ends with
                    parts = core.split("/")
                    named = {"/".join(parts[i:]) for i in range(1, len(parts))} & set(holders)
                else:
                    named = {posixpath.normpath(posixpath.join(here, core))} & set(holders)
                for d in named:
                    found.setdefault(d + "/", set()).add(f)
    out: dict[str, list[list]] = {}
    for p, members in sorted(subjects.items()):
        held = sorted({posixpath.dirname(m.rstrip("/")) for m in members} - {""})
        held = sorted({a + "/" for d in held for a in [d] + [d.rsplit("/", k)[0] for k in range(1, d.count("/") + 1)]})
        rows = [[f, owner(f), f in members, member] for member in sorted(members) + held
                for f in sorted(found.get(member, ()))]
        if rows:
            out[p] = rows
    return out


def source_call_args(src: "Source", o: int) -> list[list] | None:
    """The top-level arguments of the call whose `(` is code[o]; None when it does not close."""
    c = src.match.get(o)
    if c is None:
        return None
    args, cur, depth = [], [], 0
    for t in src.code[o + 1:c]:
        if t[0] == "open":
            depth += 1
        elif t[0] == "close":
            depth -= 1
        if depth == 0 and t[0] == "comma":
            args.append(cur)
            cur = []
        else:
            cur.append(t)
    return args + ([cur] if cur else [])


# Round 3 of #33, B2: a path chain anchored at the file's own directory, in ANY position (not only an import call), whose
# literal segments step to a parent. `path.join(__dirname, "..", "..")` is `../..`, so a vitest `dir:` of it reaches the
# repository root and refuses like the string "../.." would.
JS_DIR_ANCHOR = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]+\.)?dirname\(\s*(?:[\w$]+\.)?"
                           r"fileURLToPath\(\s*import\.meta\.url\s*\)\s*\)")
PY_DIR_ANCHOR = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:os\.path\.)?dirname\(\s*(?:(?:os\.path\.)?(?:abspath|realpath)\(\s*)?"
                           r"__file__\s*\)?\s*\)\s*$")
PY_PATH_ANCHOR = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:pathlib\.)?Path\(\s*__file__\s*\)((?:\.(?:resolve|absolute)\(\s*\))*)"
                            r"((?:\.parent\b|\.parents\[\s*\d+\s*\])*)\s*$")
_URL_DIR = ["fileURLToPath", "(", "import", ".", "meta", ".", "url", ")", ")"]  # dirname(fileURLToPath(import.meta.url))
JS_INLINE_ANCHORS = (["__dirname"], ["import", ".", "meta", ".", "dirname"],  # 1.5.2: the inline fileURLToPath forms too
                     ["path", ".", "dirname", "("] + _URL_DIR, ["dirname", "("] + _URL_DIR,
                     ["path", ".", "dirname", "(", "url", "."] + _URL_DIR, ["dirname", "(", "url", "."] + _URL_DIR)
PY_INLINE_ANCHORS = (["os", ".", "path", ".", "dirname", "(", "__file__", ")"], ["dirname", "(", "__file__", ")"],
                     ["os", ".", "path", ".", "dirname", "(", "os", ".", "path", ".", "abspath", "(", "__file__", ")", ")"],
                     ["os", ".", "path", ".", "dirname", "(", "os", ".", "path", ".", "realpath", "(", "__file__", ")", ")"])


def _levels(parents: str) -> int:
    """The directories `.parent` / `.parents[N]` steps climb from a FILE: .parent is its directory (1)."""
    return sum(int(n) + 1 if n else 1 for n in re.findall(r"\.parents?(?:\[\s*(\d+)\s*\])?", parents))


def own_names(repo) -> frozenset:
    """The names this checkout goes by: its directory's name and, in Actions, the repository's (CI checks out into
    .../<repo>/<repo>, and a local clone may be named otherwise). A name above the checkout that re-enters one of these
    may be this repository's own tree (root's R4 of #49)."""
    names = {Path(repo).resolve().name}
    if os.environ.get("GITHUB_REPOSITORY", "").count("/") == 1:
        names.add(os.environ["GITHUB_REPOSITORY"].split("/")[1])
    return frozenset(n for n in names if n and n not in (".", ".."))


def lands_on_checkout(name: str, checkout: str | None) -> bool:
    """Whether a name above the checkout, or its literal prefix (the segments before a glob's first wildcard), resolved
    against the ACTUAL checkout path, is the checkout, inside it or an ancestor of it (root's delta R4 of #49): CI's
    `.../_work/<repo>/<repo>` makes `../../../_work/**` an ancestor though it never names the repository. Lexical, so a
    path above the checkout that does not exist on this machine is still judged."""
    if not checkout:
        return False
    prefix = []
    for part in name.split("/"):
        if any(c in part for c in "*?["):
            break
        prefix.append(part)
    at = posixpath.normpath(posixpath.join(checkout, *prefix)) if prefix else checkout
    return at == checkout or checkout.startswith(at.rstrip("/") + "/") or at.startswith(checkout.rstrip("/") + "/")


def unresolved_name_registry(es: dict, own: frozenset = frozenset(), checkout: str | None = None) -> tuple[dict, list]:
    """edge_scan.unresolved_names, validated: ({(file, normalized name): entry}, [(file, glob regex, entry)]).
    A name that resolves to no tracked file or directory is an UNRESOLVED ROUTE, in any position (root's delta R4 of
    #33, D5): `timeout 300 node ../dist/x.js`, a heredoc, a fork/Worker/spawn argument and a test datum all read alike
    to a scan that cannot run them. It refuses unless declared: {file, name, reach}, `name` the repo path it resolves
    to, `reach` "none" (it names nothing that runs: a test datum) or the tracked paths it stands for (each an edge).
    1.5.2, root's rulings on the root climb:
    - (a) a name ABOVE the checkout (`../vagary-voice`, `../../etc/passwd` resolved from the root) is declared by its
      exact path, or by a glob over such paths whose first segment below the `../` steps is literal (`../vagary-voice/**`;
      never `../**`). Its reach may be "none" even with a code extension: nothing above the checkout is in this repo.
    - (b) the root itself (`.`) is declared only with a reach list: a name at the root reaches every file, so "none"
      would hide what it runs. A root base joined only with string literals needs no declaration (root_base_uses)."""
    names_declared = es.get("unresolved_names") or []
    if not isinstance(names_declared, list) or any(
            not isinstance(d, dict) or set(d) != {"file", "name", "reach", "reason", "review_by"} or not isinstance(d["file"], str)
            or not isinstance(d["name"], str) or not (d["reach"] == "none" if isinstance(d["reach"], str) else
                                                      isinstance(d["reach"], list) and d["reach"]
                                                      and all(isinstance(x, str) and x for x in d["reach"]))
            for d in names_declared):
        raise ValueError("edge_scan.unresolved_names entries must be {file, name, reach, reason, review_by}, with reach "
                         "\"none\" or a non-empty list of repo paths")
    reviewed("unresolved_names", names_declared, "name")
    by_name, globs = {}, []

    def refuse_landing(d, name, above):
        # 1.5.3 (root's delta R4 of #49): judged after a glob's shape, so a malformed glob keeps its own refusal.
        if above and d["reach"] == "none" and lands_on_checkout(name, checkout):
            raise ValueError(f"edge_scan.unresolved_names: {d['file']} names {d['name']}, which resolves from this checkout "
                             "to the checkout itself, inside it, or an ancestor of it, with reach \"none\"; a name there "
                             "reaches this repository's files, so declare the paths it reaches")

    for d in names_declared:
        name = posixpath.normpath(d["name"])
        above = name == ".." or name.startswith("../")
        below = [x for x in name.split("/") if x != ".."]
        # Root's R4 of #49 (blocking): a name made only of `..` steps (`..`, `../..`, `x/../..`) is an ANCESTOR of the
        # checkout, so it contains every file, exactly as the root does; reach "none" would hide what it runs.
        if name == "." and d["reach"] == "none":
            raise ValueError(f"edge_scan.unresolved_names: {d['file']} names the repository root with reach \"none\"; a "
                             "name at the root reaches every file, so declare the paths it reaches")
        if not below and d["reach"] == "none":
            raise ValueError(f"edge_scan.unresolved_names: {d['file']} names {d['name']}, an ancestor of the checkout that "
                             "contains it, with reach \"none\"; a name there reaches every file, as the root does, so "
                             "declare the paths it reaches")
        # ...and one that RE-ENTERS the checkout by its own name (`../<repo>/...`) may be this repository's tree, which a
        # sibling repository's name cannot be told apart from: it must declare what it reaches too.
        if above and d["reach"] == "none" and own & set(below):
            raise ValueError(f"edge_scan.unresolved_names: {d['file']} names {d['name']}, above the checkout but through "
                             f"its own name ({', '.join(sorted(own & set(below)))}), with reach \"none\"; it may be this "
                             "repository's own tree, so declare the paths it reaches")
        if any(c in d["name"] for c in "*?["):
            first = [x for x in name.split("/") if x != ".."][:1]
            if not above or not first or any(c in first[0] for c in "*?["):
                raise ValueError(f"edge_scan.unresolved_names: {d['file']} declares {d['name']}, a glob; a glob may only "
                                 "name paths ABOVE the checkout, and its first segment below the `../` steps must be "
                                 "literal (`../repo/**`, never `../**`)")
            refuse_landing(d, name, above)
            globs.append((d["file"], glob_to_regex(name), d))
            continue
        refuse_landing(d, name, above)
        # Root's round 3 of #33, F09: a name with a code extension is code something runs (`spawn(process.execPath,
        # ["../../dist/x.js"])`), so reach "none" would say it runs nothing; it must name what it stands for. Above the
        # checkout nothing is this repository's, so "none" is the honest reach there (1.5.2, ruling a).
        if d["reach"] == "none" and not above and posixpath.splitext(name)[1].lstrip(".").lower() in CODE_EXT | JS_EXT | PY_EXT:
            raise ValueError(f"edge_scan.unresolved_names: {d['file']} names {d['name']}, a code file, with reach \"none\"; "
                             "code that runs reaches its sources, so declare the tracked paths it stands for")
        by_name[(d["file"], name)] = d
    return by_name, globs


def declared_name(by_name: dict, globs: list, path: str, target: str):
    """The unresolved_names entry that declares `target` for `path` (exact, else an above-root glob), and its key."""
    entry = by_name.get((path, target))
    if entry is not None:
        return entry, (path, target)
    if target == ".." or target.startswith("../"):
        for f, regex, d in globs:
            if f == path and regex.fullmatch(target):
                return d, (f, d["name"])
    return None, None


def anchored_chains(src: "Source") -> list[str]:
    """Every chain anchored at the file's directory whose literal segments step to a parent: its spec relative to that
    directory (`../../lib/x.mjs`). Only the literal prefix counts; a chain whose prefix steps nowhere up is not listed."""
    return [spec for spec, _, _ in anchored_chain_sites(src)]


def anchored_chain_sites(src: "Source") -> list[tuple[str, int, int]]:
    """anchored_chains, with where each chain is: (spec, first token, last token). The first token is the call's receiver
    (`path` of `path.resolve(...)`) or the Path / alias word; the last is the call's `)` or the chain's last step."""
    code, sites = src.code, []
    vals = lambda toks: [t[3] if t[0] != "str" else None for t in toks]
    def add(segments: list[str], s: int, e: int) -> None:
        spec = "/".join(x.strip("/") for x in segments if x.strip("/")) or "."
        if ".." in spec.split("/"):
            sites.append((spec, s, e))
    if src.py:
        dir_alias = set(PY_DIR_ANCHOR.findall(src.text))
        path_alias = {name: _levels(ups) for name, _, ups in PY_PATH_ANCHOR.findall(src.text)}
    else:
        dir_alias, path_alias = set(JS_DIR_ANCHOR.findall(src.text)), {}
    inline = PY_INLINE_ANCHORS if src.py else JS_INLINE_ANCHORS
    for j, t in enumerate(code):
        # join(<anchor>, "..", "lib", ...) / resolve(...) / os.path.join(...)
        if t[0] == "word" and t[3] in ("join", "resolve") and j + 1 < len(code) and code[j + 1][3] == "(":
            args = source_call_args(src, j + 1) or []
            first = vals(args[0]) if args else []
            if first in [list(a) for a in inline] or (len(first) == 1 and first[0] in dir_alias):
                lits = []
                for arg in args[1:]:
                    if len(arg) != 1 or arg[0][0] != "str" or arg[0][3][1] is not True:
                        break
                    lits.append(arg[0][3][0])
                s = j
                while s >= 2 and code[s - 1][3] == "." and code[s - 2][0] == "word":
                    s -= 2
                add(lits, s, src.match.get(j + 1, j + 1))
        # Python: Path(__file__)[.resolve()].parent / .parents[N] then / "lit" ..., or an alias of such a Path.
        if src.py and t[0] == "word" and (t[3] == "Path" or t[3] in path_alias):
            k, up = j + 1, path_alias.get(t[3], 0)
            if t[3] == "Path":
                if vals(code[j + 1:j + 4]) != ["(", "__file__", ")"]:
                    continue
                k = j + 4
            elif j and code[j - 1][3] == ".":
                continue  # an attribute named like the alias
            elif j + 1 < len(code) and code[j + 1][3] == "=":
                continue  # the alias's own binding (`REPO = Path(...)`): the right-hand side is the chain
            lits = []
            while k < len(code):
                v = vals(code[k:k + 4])
                if v[:2] == [".", "resolve"] or v[:2] == [".", "absolute"]:
                    k += 4
                elif v[:2] == [".", "parent"]:
                    up, k = up + 1, k + 2
                elif v[:3] == [".", "parents", "["] and len(v) > 3 and (v[3] or "").isdigit():
                    up, k = up + int(v[3]) + 1, k + 5
                elif code[k][3] == "/" and k + 1 < len(code) and code[k + 1][0] == "str" and code[k + 1][3][1] is True:
                    lits.append(code[k + 1][3][0])
                    k += 2
                else:
                    break
            if up >= 1:
                add([".."] * (up - 1) + lits, j, k - 1)
    return sites


PARENT_STEP_LITERAL = re.compile(r"""(["'])([^"'\\\n]*)\1""")


def parent_step_literal(text: str) -> str | None:
    """B1's literal (RC1A, root's R-c r2 review B1 and dotgithub-86): a sys.path entry written as ONE plain string
    literal (no prefix, no escape, no second literal) that is relative and holds a `..` component, its text as the
    process reads it; None for anything else (a backslash path is B2's, `os.sep.join` and f-strings are other forms)."""
    m = PARENT_STEP_LITERAL.fullmatch(text.strip())
    if m is None or m.group(2).startswith("/") or ".." not in m.group(2).split("/"):
        return None
    return m.group(2)


def python_owned_spans(text: str, parent_literals: bool = False) -> list[tuple[int, int]]:
    """Character spans of the Python expressions 1.5.2's evaluator judges itself (python_file_facts): every sys.path
    entry (insert/append/extend, `+=`, slice assignment) and every loader path (spec_from_file_location, run_path,
    exec(open(p))). A chain inside one is that evaluator's to judge, never a route of its own. With `parent_literals`,
    only the sys.path entries B1 reads by their landings (parent_step_literal), each element alone."""
    import ast
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    starts, n = [0], 0
    for line in text.split("\n"):
        n += len(line) + 1
        starts.append(n)
    lines = text.split("\n")

    def offset(lineno: int, col: int) -> int:  # ast columns are UTF-8 byte offsets
        line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
        return starts[lineno - 1] + len(line.encode("utf-8")[:col].decode("utf-8", errors="ignore"))

    def span(node) -> tuple[int, int]:
        return offset(node.lineno, node.col_offset), offset(node.end_lineno, node.end_col_offset)

    def dotted(node) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def items(node) -> list:  # the elements python_file_facts reads as entries
        return list(node.elts) if isinstance(node, (ast.List, ast.Tuple)) else [node]

    out = []
    for node in ast.walk(tree):
        if parent_literals:
            name = dotted(node.func) if isinstance(node, ast.Call) else ""
            if name == "sys.path.insert" and len(node.args) == 2:
                elements = [node.args[1]]
            elif name == "sys.path.append" and len(node.args) == 1:
                elements = [node.args[0]]
            elif name == "sys.path.extend" and len(node.args) == 1:
                elements = items(node.args[0])
            elif isinstance(node, ast.AugAssign) and dotted(node.target) == "sys.path":
                elements = items(node.value)
            elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Subscript) and dotted(t.value) == "sys.path"
                                                      for t in node.targets):
                elements = items(node.value)
            else:
                continue
            out += [s for s in map(span, elements) if parent_step_literal(text[s[0]:s[1]]) is not None]
            continue
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in ("sys.path.insert", "sys.path.append", "sys.path.extend") or name.endswith(
                    ("spec_from_file_location", "run_path")) or (name == "exec" and node.args):
                out += [span(a) for a in node.args] + [span(k.value) for k in node.keywords]
        elif isinstance(node, ast.AugAssign) and dotted(node.target) == "sys.path":
            out.append(span(node.value))
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Subscript) and dotted(t.value) == "sys.path"
                                                  for t in node.targets):
            out.append(span(node.value))
    return out


ROOT_BASE_WRAPPERS = frozenset({"realpathSync", "realpath", "normalize", "String", "str", "abspath", "normpath", "Path"})


def root_base_uses(src: "Source", path: str, owned: list = ()) -> tuple[list, list, list]:
    """1.5.2, root's ruling (b): a ROOT BASE is a chain anchored at the file's directory that resolves to the repository
    root itself (`path.resolve(__dirname, "../../..")`, `Path(__file__).resolve().parents[3]`). It resolves to exactly
    the string literals it is joined with when EVERY use joins string literals; any other use refuses. A use is:
    - the base itself (through realpathSync / normalize / str / Path ...) as the first argument of a join or resolve
      whose other arguments are all plain string literals;
    - a name bound to it once (`const ROOT = ...`, `REPO = Path(__file__)...parents[3]`), whose every use is such a
      join, a Python alias step `REPO / "scripts" / "x.sh"` (all literal), or an expression 1.5.2's Python evaluator
      judges itself (`owned`). An exported name, a use the tokens cannot see (a template or f-string), or any other use
      refuses: the base may then reach anything.
    Returns (resolved spans, literal repo paths, refusal reasons). A literal that is itself the root or above refuses."""
    code, here = src.code, posixpath.dirname(path)
    spans, literals, why = [], [], []
    sites = anchored_chain_sites(src)
    alias_sites = {s: spec for spec, s, e in sites}
    owned_at = lambda a: any(x <= a < y for x, y in owned)
    plain = lambda arg: len(arg) == 1 and arg[0][0] == "str" and arg[0][3][1] is True
    line_of = lambda k: src.text.count("\n", 0, code[k][1]) + 1

    def literal_join(lits: list[str], k: int) -> bool:
        target = posixpath.normpath(posixpath.join(*lits)) if lits else "."
        if target in (".", "..") or target.startswith("../"):
            why.append(f"{path} joins its repository-root base on line {line_of(k)} to {target}, the root or above it")
            return False
        literals.append(target)
        return True

    def joined_first_arg(s: int, e: int) -> list | None:
        """The other arguments of the join/resolve call whose first argument is exactly code[s..e], when all literal."""
        if s < 2 or code[s - 1][0] != "open" or code[s - 1][3] != "(" or code[s - 2][0] != "word" \
                or code[s - 2][3] not in ("join", "resolve"):
            return None
        args = source_call_args(src, s - 1) or []
        if not args or args[0][0] is not code[s] or args[0][-1] is not code[e] or not all(plain(a) for a in args[1:]):
            return None
        return [a[0][3][0] for a in args[1:]]

    for spec, s, e in sites:
        if posixpath.normpath(posixpath.join(here, spec)) != ".":
            continue
        if owned_at(code[s][1]):
            spans.append((code[s][1], code[e][2]))
            continue
        while s >= 2 and code[s - 1][3] == "(" and src.match.get(s - 1) == e + 1 and code[s - 2][0] == "word" \
                and code[s - 2][3] in ROOT_BASE_WRAPPERS:
            s, e = s - 2, e + 1
            while s >= 2 and code[s - 1][3] == "." and code[s - 2][0] == "word":
                s -= 2
        lits = joined_first_arg(s, e)
        if lits is not None:
            if literal_join(lits, s):
                spans.append((code[s][1], code[e][2]))
            continue
        name = None
        if s >= 2 and code[s - 1][3] == "=" and code[s - 2][0] == "word":
            line_start = src.text.rfind("\n", 0, code[s - 2][1]) + 1
            line_end = src.text.find("\n", code[e][2])
            before = src.text[line_start:code[s - 2][1]].strip()
            after = src.text[code[e][2]:len(src.text) if line_end < 0 else line_end].strip()
            if src.py:
                bound = before == "" and (after == "" or after.startswith("#"))
            else:
                bound = before.split(" ")[-1] in ("const", "let", "var") and before.split(" ")[0] in ("const", "let", "var",
                        "export") and (after in ("", ";") or after.startswith((";", "//")))
            if bound and before.startswith("export"):
                why.append(f"{path} exports {code[s - 2][3]}, a repository-root base, on line {line_of(s)}: its uses are "
                           "not in this file")
                continue
            name = code[s - 2][3] if bound else None
        if name is None:
            why.append(f"{path} uses a repository-root base on line {line_of(s)} other than joined with string literals")
            continue
        binding, ok = s - 2, True
        uses = [u for u, t in enumerate(code) if t[0] == "word" and t[3] == name and u != binding
                and not (u and code[u - 1][3] in (".", "?."))]
        for u in uses:
            if owned_at(code[u][1]):
                continue
            if src.py and u in alias_sites and posixpath.normpath(posixpath.join(here, alias_sites[u])) != ".":
                continue  # `REPO / "scripts" / "x.sh"`: an all-literal alias step, routed as a chain of its own
            lits = joined_first_arg(u, u)
            if lits is not None and literal_join(lits, u):
                continue
            why.append(f"{path} uses {name}, a repository-root base, on line {line_of(u)} other than joined with string "
                       "literals")
            ok = False
        seen = [m.start() for m in re.finditer(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", src.text)
                if not src.in_comment(m.start())]
        if len(seen) != 1 + len(uses):
            why.append(f"{path} names {name}, a repository-root base, where the scan cannot see the use (a template, an "
                       "f-string or another string)")
            ok = False
        if ok:
            spans.append((code[s][1], code[e][2]))
    return spans, sorted(set(literals)), why


NON_CODE_DOT_ROUTE = re.compile(r"(?<![A-Za-z0-9_./$-])(\./[A-Za-z0-9_.@+-][A-Za-z0-9_.@+/-]*)")  # round 3, B3
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*)\s+import\b|import\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*))", re.M)


# ---------- Python sys.path entries (1.5.2) ----------
# A package's Python code that puts a directory on sys.path imports modules from it BY NAME, so no relative path names
# them (vagary-core: 482 files; `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))`,
# `str(Path(__file__).resolve().parents[1] / "app")`, a name bound to either, `REPO / "scripts"`). Spine's follow-up to
# 1.5.0 (2026-10-27): resolve the entry, and credit what the package then imports from it.
#   - The entry is evaluated from the file's AST: `__file__`, dirname/abspath/realpath/normpath/str/Path/resolve/
#     absolute, `.parent`, `.parents[N]`, os.path.join and `/` with string constants, and names assigned exactly once.
#   - Inside the package's own directory: nothing. Inside ANOTHER package: a dep (imports by name from it). Outside every
#     package: each module the package's Python files import by name that exists there is an edge, so its reads are
#     credited (rule 2). The entry applies to every Python file of the package (a conftest.py entry serves all tests).
#   - An entry that cannot be evaluated refuses when its text holds a parent step or names a scan root or a top-level
#     directory outside every package; any other unresolved entry (an environment variable, `os.getcwd()`) is a
#     documented residual.
#   - A package Python file that changes sys.path and does not parse refuses.
#   - pytest's `pythonpath` (pytest.ini, pyproject.toml [tool.pytest.ini_options], tox.ini [pytest], setup.cfg
#     [tool:pytest]; the nearest config walking up from the package, pytest.ini first in one directory) is an entry
#     relative to its config's directory, for every package that holds Python files. An unreadable one refuses.
#   - Python's loaders (spine's pre-review): `importlib.import_module`, `__import__` and `runpy.run_module` with a
#     LITERAL name are imports by name; with a non-literal one, rule 4's declaration. `spec_from_file_location`,
#     `runpy.run_path` and `exec(open(p).read())` take a path: evaluated, a literal load (an edge); not evaluated, the
#     declaration, and one whose text holds a parent step or names a root or outside directory refuses even declared.
#     The same holds in a reached Python file. N2 / N3 (root's ruling of 2026-11-12 21:32): a literal-name loader call
#     is read through its chain (`__import__("json").loads(x)`), a literal `importlib.resources` anchor is an import of
#     that name, and `importlib.metadata.version` / `.files` are reads, not loads.
# The tokens a Python file can change its import path, or load a module by name or path, through (R6-2, root's ruling of
# 2026-11-12, fail-closed by token): every file holding one is read by python_file_facts, whose capability scan judges
# each occurrence (a file with the token only in a comment or a string is read and found clean, except `PYTHONPATH`, which
# refuses in any string constant: an environ key, a shell string, an `env=` mapping). POSIX ERE: `[^A-Za-z0-9_]`
# bounds a word (git grep -E has no `\b`), so `system` and `website` are not listed; `PYTHONPATH` is listed anywhere.
PY_FACTS_GREP = (r"(^|[^A-Za-z0-9_])(sys|site|importlib|runpy|builtins|__builtins__|exec|eval|compile|__import__|import_module|"
                 r"run_module|run_path|spec_from_file_location|module_from_spec|SourceFileLoader|addsitedir)([^A-Za-z0-9_]|$)"
                 r"|PYTHONPATH")
# pytest's config files, in its precedence order inside one directory (pytest.ini wins even with no [pytest] section).
PYTEST_CONFIGS = ("pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")


def pytest_pythonpath(text: str, name: str, path: str) -> list[str] | None:
    """The `pythonpath` entries a pytest config file sets (spine's pre-review of 1.5.2: the config-level sys.path
    insert); None when the file is not a pytest config, so pytest keeps looking. Refuses a pytest config it cannot read."""
    if name == "pyproject.toml":
        try:
            import tomllib
        except ImportError:  # Python < 3.11
            if "[tool.pytest.ini_options]" in text:
                raise ValueError(f"unresolved (pytest options in {path} cannot be read on this Python)") from None
            return None
        try:
            options = tomllib.loads(text).get("tool", {}).get("pytest", {}).get("ini_options")
        except tomllib.TOMLDecodeError:
            raise ValueError(f"unresolved ({path} does not parse, so its pytest pythonpath cannot be read)") from None
        if options is None:
            return None
        value = options.get("pythonpath", [])
        return value.split() if isinstance(value, str) else [str(v) for v in value]
    import configparser
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        raise ValueError(f"unresolved ({path} does not parse, so its pytest pythonpath cannot be read)") from None
    section = "tool:pytest" if name == "setup.cfg" else "pytest"
    if not parser.has_section(section):
        return [] if name == "pytest.ini" else None
    return parser.get(section, "pythonpath", fallback="").split()


def python_file_facts(text: str, path: str, test_only=None) -> tuple[list[tuple[str, str, str, str | None]], set[str], list[tuple]]:
    """One Python file's (sys.path entries, imported top-level names, loader sites), from one parse.
    - An entry is ("dir", repo-relative directory, which may start with `../` above the repository, key) or ("unknown",
      the text rule 6 reads, key), `key` the entry's own source as written (whitespace collapsed): the text an
      edge_scan.computed_imports `expr` names it by (the r5 sys.path rule, root's dotgithub-86 review, 2026-11-12).
      Each entry carries a fourth item, the literal text an "unknown" entry's path ends with (literal_tail, from the
      AST), else None.
    - The names are every top-level module imported by name: `import x`, `from x import y`, and a LITERAL
      `importlib.import_module("x")`, `__import__("x")` or `runpy.run_module("x")`, and (N3, root's ruling of 2026-11-12
      21:32) a LITERAL `importlib.resources.files("x")` or `read_text("x", ...)` anchor.
    - A loader site (spine's pre-review of 1.5.2) is ("module", expr, None) for one of those three with a non-literal
      name, or ("path", expr, resolved) for `importlib.util.spec_from_file_location(name, p)`, `runpy.run_path(p)` and
      `exec(open(p).read())`, with `p` evaluated like a sys.path entry (None when it cannot be). `module_from_spec` is
      read only over a spec whose site evaluated (R6-2 fix (1)): it adds no site, the spec's is its edge; any other
      `module_from_spec` refuses at the capability scan.
    Raises ValueError when the file does not parse."""
    import ast
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as error:
        raise ValueError(f"unresolved (a Python file the scan must read does not parse: {path}: {error})") from None
    assigned: dict[str, list] = {}
    augmented: dict[str, list] = {}  # name -> its `name += ...` statements (root's S02 of #84, 2026-11-12)
    # Root's K3 of #84's third delta R4 (2026-11-12): the scan reads a name through a plain assignment (`p = ...`, an
    # annotated one, a pairwise tuple, `p += ...`) and nothing else. A name bound by anything else is UNREADABLE: its
    # text is empty, so a loader site reading it refuses (never a reading of [] under a declaration), and `ev` never
    # evaluates it (a module `for LIB in ...` beside a helper-local `LIB = ...` once evaluated the helper's, G03m).
    # name -> the kind of binding the scan does not read (the first one met names the refusal).
    unreadable: dict[str, str] = {}
    assigned_attrs: set[tuple[str, str]] = set()  # (`self`, `p`) for `self.p = ...` anywhere (K3's B07)
    shadowed: set[int] = set()  # id() of a Name read inside a function whose parameter binds it (root's S08)
    defaulted: set[int] = set()  # those of them whose parameter carries a default (K3's B03): a loader site refuses
    # id() -> name for a parameter-named Name in the function's own defaults or decorators (root's C3 of #84's second
    # delta R4): it evaluates in the ENCLOSING scope, so it is un-shadowed below only when the name's single binding
    # in the file is a plain module-level assignment (root's K2 of the third delta R4), else it stays shadowed.
    enclosing: dict[int, str] = {}

    def unread(name: str, kind: str) -> None:
        unreadable.setdefault(name, kind)

    def unread_names(target, kind: str) -> None:
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                unread(sub.id, kind)
            elif isinstance(sub, ast.Attribute) and isinstance(sub.ctx, ast.Store) and isinstance(sub.value, ast.Name):
                assigned_attrs.add((sub.value.id, sub.attr))

    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                augmented.setdefault(node.target.id, []).append(node)
            elif isinstance(node.target, ast.Attribute) and isinstance(node.target.value, ast.Name):
                assigned_attrs.add((node.target.value.id, node.target.attr))
            continue
        if isinstance(node, ast.NamedExpr):
            unread_names(node.target, "a walrus (`:=`)")
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            unread_names(node.target, "a `for` loop")
        elif isinstance(node, ast.comprehension):
            unread_names(node.target, "a comprehension")
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            unread_names(node.optional_vars, "a `with ... as`")
        elif isinstance(node, ast.ExceptHandler) and node.name:
            unread(node.name, "an `except ... as`")
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            unread(node.name, "a `match` pattern")
        elif isinstance(node, ast.MatchMapping) and node.rest:
            unread(node.rest, "a `match` pattern")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            unread(node.name, "a `def` (a call's return is not a path the scan reads)")
        elif isinstance(node, ast.ClassDef):
            unread(node.name, "a `class`")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs} | {x.arg for x in (a.vararg, a.kwarg) if x}
            # A parameter WITH a default is a binding the scan does not read (K3's B03: `def f(p=f"{S}/packages/...")`):
            # a read of it in the body is `defaulted`, and a loader site reading it refuses. A bare parameter's read is
            # the S08 residual (its text is its name, which names nothing). Both are per read (by id), since the same
            # name at module level is another binding (D01 reads the module's LIB through the default, K2).
            positional = a.posonlyargs + a.args
            with_default = {x.arg for x in positional[len(positional) - len(a.defaults):]} if a.defaults else set()
            with_default |= {x.arg for x, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None}
            # Argument defaults and decorators evaluate in the ENCLOSING scope (`def setup(LIB=LIB)` reads the module's
            # LIB), so a Name there is not the parameter's (root's C3 of #84's second delta R4, 2026-11-12): recorded
            # as a candidate, decided once the file's bindings are known (K2).
            outer = {id(n) for d in (*a.defaults, *[x for x in a.kw_defaults if x], *getattr(node, "decorator_list", ()))
                     for n in ast.walk(d)}
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and n.id in params and isinstance(n.ctx, ast.Load):
                    if id(n) in outer:
                        enclosing[id(n)] = n.id
                    else:
                        shadowed.add(id(n))
                        if n.id in with_default:
                            defaulted.add(id(n))
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        value = getattr(node, "value", None)
        for t in targets:
            if isinstance(t, ast.Name) and value is not None:
                assigned.setdefault(t.id, []).append(value)
            elif isinstance(t, ast.Name):
                unread(t.id, "an annotation without a value")
            elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
                assigned_attrs.add((t.value.id, t.attr))
            elif isinstance(t, (ast.Tuple, ast.List)) and value is not None:
                # Root's S11: `p, q = f"{source}/packages/shared", 1` binds each name to its own element. Unpacked from
                # anything else (a call, a starred target), each name carries the whole right side as text and never
                # evaluates (K3: it is unreadable, so a loader site reading it refuses).
                pairwise = isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(t.elts) and \
                    not any(isinstance(e, ast.Starred) for e in t.elts + value.elts)
                for i, e in enumerate(t.elts):
                    if isinstance(e, ast.Name):
                        assigned.setdefault(e.id, []).append(value.elts[i] if pairwise else value)
                        if not pairwise:
                            unread(e.id, "an unpacking the scan cannot pair")
                    elif isinstance(e, ast.Starred):
                        unread_names(e, "a starred target")
                    elif isinstance(e, (ast.Tuple, ast.List)):
                        unread_names(e, "a nested unpacking")  # `(p, q), r = ...` (K3's B09)
                    elif isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
                        assigned_attrs.add((e.value.id, e.attr))
    here = posixpath.dirname(path)
    FILE, UNKNOWN = ("file",), None

    def up(value, n=1):
        if value is FILE:
            value, n = here, n - 1
        for _ in range(n):
            value = posixpath.dirname(value) if value not in ("", ".") else ".."
            value = posixpath.normpath(value) if value else "."
        return value

    def ev(node, depth=0):
        if depth > 40:
            return UNKNOWN
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return FILE
            values = assigned.get(node.id, [])
            if len(values) != 1 or node.id in unreadable or id(node) in shadowed:
                return UNKNOWN
            value = ev(values[0], depth + 1)
            # `p = dirname(__file__); p += "/../../packages/shared"` evaluates as the concatenation (root's S13 reads
            # [shared] as before); an augmentation that is not `+= "<literal>"`, or that stands before the assignment,
            # leaves the name unevaluated (root's S02: the text then carries every literal the augmentations add).
            for aug in sorted(augmented.get(node.id, []), key=lambda n: (n.lineno, n.col_offset)):
                if value is UNKNOWN or value is FILE or not isinstance(aug.op, ast.Add) or \
                        not (isinstance(aug.value, ast.Constant) and isinstance(aug.value.value, str)) or \
                        (aug.lineno, aug.col_offset) < (values[0].lineno, values[0].col_offset):
                    return UNKNOWN
                value = posixpath.normpath(value + aug.value.value)
            return value
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in ("abspath", "realpath", "normpath", "str", "Path", "PurePath", "PosixPath", "fspath") and len(node.args) == 1:
                return ev(node.args[0], depth + 1)
            if name in ("resolve", "absolute") and isinstance(f, ast.Attribute) and not node.args:
                return ev(f.value, depth + 1)
            if name == "dirname" and len(node.args) == 1:
                inner = ev(node.args[0], depth + 1)
                return UNKNOWN if inner is UNKNOWN else up(inner)
            if name == "join" and node.args:
                base = ev(node.args[0], depth + 1)
                parts = [a.value for a in node.args[1:] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if base is UNKNOWN or base is FILE or len(parts) != len(node.args) - 1:
                    return UNKNOWN
                return posixpath.normpath(posixpath.join(base, *parts))
            # pathlib's literal edits on an evaluated path (spine, 2026-10-27: vagary-core's evidence app binds
            # `PACKAGE = Path(__file__).with_name("_qualification_contract")`, a package vendored inside it).
            if name in ("with_name", "with_suffix", "joinpath") and isinstance(f, ast.Attribute):
                base = ev(f.value, depth + 1)
                consts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if base is UNKNOWN or node.keywords or len(consts) != len(node.args) or (name != "joinpath" and len(consts) != 1):
                    return UNKNOWN
                current = path if base is FILE else base
                if name == "with_name":
                    if "/" in consts[0] or not consts[0]:
                        return UNKNOWN  # pathlib refuses a name with a separator
                    return posixpath.normpath(posixpath.join(posixpath.dirname(current), consts[0]))
                if name == "with_suffix":
                    return posixpath.splitext(current)[0] + consts[0]
                return posixpath.normpath(posixpath.join(current, *consts))
            return UNKNOWN
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            inner = ev(node.value, depth + 1)
            return UNKNOWN if inner is UNKNOWN else up(inner)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
            inner, index = ev(node.value.value, depth + 1), node.slice
            if inner is UNKNOWN or not (isinstance(index, ast.Constant) and isinstance(index.value, int)) or index.value < 0:
                return UNKNOWN
            return up(inner, index.value + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            base = ev(node.left, depth + 1)
            if base is UNKNOWN or base is FILE or not (isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                return UNKNOWN
            return posixpath.normpath(posixpath.join(base, node.right.value))
        return UNKNOWN

    def source(node) -> str:
        return " ".join((ast.get_source_segment(text, node) or ast.dump(node)).split())

    def evaluated_prefix(node):
        """For a path that does not evaluate: its longest evaluated leading part and the parts after it, or None when
        even its base does not evaluate (spine, 2026-10-27: `PACKAGE / \"scripts\" / x` under an in-package PACKAGE)."""
        while isinstance(node, ast.Call) and len(node.args) == 1 and call_name(node.func) in ("str", "Path", "PurePath", "fspath"):
            node = node.args[0]
        parts = []
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            parts.insert(0, node.right)
            node = node.left
        if isinstance(node, ast.Call) and call_name(node.func) == "join" and node.args:
            parts = list(node.args[1:]) + parts
            node = node.args[0]
        base = ev(node)
        if base is UNKNOWN:
            return None
        current = here if base is FILE else base
        while parts and isinstance(parts[0], ast.Constant) and isinstance(parts[0].value, str):
            current = posixpath.normpath(posixpath.join(current, parts.pop(0).value))
        return current, parts

    def path_site(arg):
        """("path", expr, resolved target, (evaluated prefix, a step after it) or None, the rule-6 text): the text is
        what rule 8 reads when nothing evaluates, the argument's source AND every assignment of the names it reads
        (text_of), so `p = f"{source}/packages/shared/m.py"; runpy.run_path(p)` lands where the f-string lands (root's
        B2 of #84's second delta R4, 2026-11-12: the source `p` alone named no top and read nothing). A name the
        argument reads that is bound by something the scan does not read (a walrus, a loop, a comprehension, a
        `with ... as`, a parameter default, a starred or nested unpacking, a `def`, an assigned attribute) has no text
        to land anywhere, so the site REFUSES, declared or not (root's K3 of the third delta R4: `(p := f"{source}/
        packages/shared/m.py"); run_path(p)` declared "external" read [] on main and on both earlier heads)."""
        bad = unreadable_in(arg)
        if bad:
            name, kind = bad[0]
            raise ValueError(f"unresolved (a computed Python load `{source(arg)}` reads `{name}`, bound by {kind}, which "
                             f"the scan does not read) in {path}; bind it by a plain assignment, or write it from "
                             "__file__ with literal parts, which the scan maps")
        target = resolved(arg)
        if target is not None:
            return ("path", source(arg), target, None, None)
        found = evaluated_prefix(arg)
        if found is None:
            return ("path", source(arg), None, None, text_of(arg))
        prefix, rest = found
        stepping = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and PARENT_STEP.search(n.value) for n in rest)
        return ("path", source(arg), None, (prefix, stepping), None)

    def resolved(node) -> str | None:
        value = ev(node)
        return None if value is UNKNOWN else here if value is FILE else value

    entries: list[tuple[str, str]] = []

    def text_of(node, seen: frozenset = frozenset()) -> str:
        """The text rule 6 reads for an unevaluable expression: its source, and the source of every assignment and
        augmentation of each name it reads, recursively (`p = f"{source}/packages/shared"; sys.path.insert(0, p)`, root's
        C1 of #84; `base = f"{source}/packages"; p = base + "/shared"`, S03; a name assigned in two branches stands for
        both, S07; `p += "/packages/shared"`, S02). A name a parameter shadows keeps its own name beside the texts of
        any module-level assignment (S08), so a reading never shrinks for the shadow; a cycle or depth 8 stops."""
        parts = [source(node)]
        if len(seen) < 8:
            for name in sorted({n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id not in seen}):
                for value in assigned.get(name, []):
                    parts.append(f"{name} = {text_of(value, seen | {name})}")
                for aug in augmented.get(name, []):
                    parts.append(f"{name} += {text_of(aug.value, seen | {name})}")
        return "; ".join(parts)

    def unreadable_in(node, seen: frozenset = frozenset()) -> list[tuple[str, str]]:
        """Root's K3 of #84's third delta R4 (2026-11-12): every name a loader-site argument reads, directly or through
        the assignments text_of walks, that is bound by something the scan does not read (`unreadable`), and every
        `base.attr` it reads that is assigned as an attribute anywhere (`self.p = ...; run_path(self.p)`), each with
        the kind of binding. A Store-context name (`exec(open(p := f"...").read())`) is the site's own binding, not a
        read; an imported name has no binding here and no text, so it reads nothing (B17) and is not listed."""
        found: list[tuple[str, str]] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id not in seen:
                if sub.id in unreadable:
                    found.append((sub.id, unreadable[sub.id]))
                elif id(sub) in defaulted:
                    found.append((sub.id, "a parameter default"))
                if len(seen) < 8:
                    for value in assigned.get(sub.id, []):
                        found.extend(unreadable_in(value, seen | {sub.id}))
                    for aug in augmented.get(sub.id, []):
                        found.extend(unreadable_in(aug.value, seen | {sub.id}))
            elif isinstance(sub, ast.Attribute) and isinstance(sub.ctx, ast.Load) and isinstance(sub.value, ast.Name) \
                    and (sub.value.id, sub.attr) in assigned_attrs:
                found.append((f"{sub.value.id}.{sub.attr}", "an attribute assignment"))
        return found

    def entry(node):
        # Root's R1 of #84's fourth delta R4 (2026-11-12): `node.id in unreadable` makes a name UNKNOWN wherever the file
        # binds it by something the scan does not read (`root = dirname(...)` at module level and `for root, d, f in
        # os.walk(t)` inside a function), so the entry fell to the read-nothing return of apply_entry and read []
        # where main read [a]. An entry whose text reads such a name REFUSES, as a loader site does (path_site),
        # declared or not, naming the binding; a name bound once by a plain assignment still evaluates.
        bad = unreadable_in(node)
        if bad:
            name, kind = bad[0]
            raise ValueError(f"unresolved (a sys.path entry `{source(node)}` reads `{name}`, bound by {kind}, which the "
                             f"scan does not read) in {path}; bind it by a plain assignment, or write it from __file__ "
                             "with literal parts, which the scan maps")
        value = resolved(node)
        entries.append(("unknown", text_of(node), source(node), literal_tail(node)) if value is None
                       else ("dir", value, source(node), None))

    def is_sep(part) -> bool:
        """`{os.sep}` / `{os.path.sep}` in an f-string: a separator, literal text (root's S05)."""
        return isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None \
            and isinstance(part.value, ast.Attribute) and ast.unparse(part.value) in ("os.sep", "os.path.sep")

    def literal_tail(node) -> str | None:
        """The literal text a sys.path entry's path ENDS with, from its AST (root's B1 of dotgithub-86 slice 2,
        2026-11-12): the trailing components every directory it lands in ends with, or None. A CLOSED list of forms,
        each with a literal as its LAST component: a string literal (adjacent and triple-quoted literals are one
        constant); str() / Path() / abspath() / realpath() / normpath() / fspath() around exactly one such form, or
        `.resolve()` on one; `X / "literal"`; os.path.join(X..., "literal"); an f-string whose placeholders all come
        before its literal text, which then starts at a separator. A literal run before the last literal is kept
        (`join("packages", "shared")` ends in `packages/shared`, never only `shared`, which `vendor/shared` also ends
        with); an unknown part resets it. Anything else (a name, a concatenation, dirname, `.parent`, a slice, a
        ternary, a literal followed by a computed part) has no tail."""
        def joined(prefix: str | None, literal: str) -> str:
            return literal if literal.startswith("/") or not prefix else prefix.rstrip("/") + "/" + literal

        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.JoinedStr):
            parts = node.values
            first = next((i for i, part in enumerate(parts) if isinstance(part, ast.Constant) or is_sep(part)), len(parts))
            if first == len(parts) or not all(isinstance(part, ast.Constant) or is_sep(part) for part in parts[first:]):
                return None
            text = "".join("/" if is_sep(part) else str(part.value) for part in parts[first:])
            if first == 0:
                return text  # no placeholder: a plain literal
            return text.lstrip("/") if text.startswith("/") else None  # `f"{ROOT}shared"` ends in ROOT's last part
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if not (isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                return None
            return joined(literal_tail(node.left), node.right.value)
        if isinstance(node, ast.Call) and not node.keywords and not any(isinstance(a, ast.Starred) for a in node.args):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "resolve" and not node.args:
                return literal_tail(f.value)
            if call_name(f) in ("str", "Path", "abspath", "realpath", "normpath", "fspath") and len(node.args) == 1:
                return literal_tail(node.args[0])
            is_join = (isinstance(f, ast.Name) and f.id == "join") or (
                isinstance(f, ast.Attribute) and f.attr == "join" and ast.unparse(f.value) in ("os.path", "posixpath", "path"))
            if is_join and node.args and isinstance(node.args[-1], ast.Constant) and isinstance(node.args[-1].value, str):
                run = None
                for arg in node.args:
                    literal = isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    run = joined(run, arg.value) if literal else None
                return run
        return None

    def is_sys_path(node):
        return isinstance(node, ast.Attribute) and node.attr == "path" and isinstance(node.value, ast.Name) and node.value.id == "sys"

    def call_name(f) -> str | None:
        return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None

    # A loop over a literal (spine's pre-review, 2026-10-27): `for m[, x] in (("a", ...), ...): import_module(m)` loads
    # exactly those constants, so they are LITERAL names (vagary-core: 28 observability.py loops over opentelemetry
    # instrumentations). Exact or nothing; anything short of the conditions below stays a computed site.
    parent: dict = {}
    for outer in ast.walk(tree):
        for child in ast.iter_child_nodes(outer):
            parent[child] = outer
    MUTATORS = {"append", "extend", "insert", "add", "update", "remove", "pop", "clear", "discard", "setdefault", "sort",
                "reverse", "__setitem__", "__iadd__"}

    def binds(node, name: str) -> bool:
        """`node` binds `name` anywhere (an assignment of any form, a loop, `with ... as`, a walrus, `del`, `global`)."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == name and isinstance(sub.ctx, (ast.Store, ast.Del)):
                return True
            if isinstance(sub, (ast.Global, ast.Nonlocal)) and name in sub.names:
                return True
        return False

    def literal_strings(node, position=None):
        """The string constants a literal tuple/list/set holds (at `position` of each inner tuple), else None."""
        if not isinstance(node, (ast.Tuple, ast.List, ast.Set)) or not node.elts:
            return None
        values = []
        for element in node.elts:
            if position is not None:
                if not isinstance(element, (ast.Tuple, ast.List)) or position >= len(element.elts):
                    return None
                element = element.elts[position]
            if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
                return None
            values.append(element.value)
        return values

    def unmutated_module_literal(name: str):
        """The module-level literal `name` is bound to exactly once and never mutated or rebound, else None."""
        stores = [sub for sub in ast.walk(tree) if isinstance(sub, ast.Name) and sub.id == name and isinstance(sub.ctx, (ast.Store, ast.Del))]
        if len(stores) != 1 or any(isinstance(sub, (ast.Global, ast.Nonlocal)) and name in sub.names for sub in ast.walk(tree)):
            return None
        bound = parent.get(stores[0])
        if not (isinstance(bound, ast.Assign) and parent.get(bound) is tree and bound.targets == [stores[0]]):
            return None
        for sub in ast.walk(tree):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr in MUTATORS \
                    and isinstance(sub.func.value, ast.Name) and sub.func.value.id == name:
                return None
            if isinstance(sub, (ast.Subscript, ast.Attribute)) and isinstance(sub.ctx, (ast.Store, ast.Del)) \
                    and isinstance(sub.value, ast.Name) and sub.value.id == name:
                return None
        return bound.value

    def loop_literal_names(call, arg) -> list[str] | None:
        if not isinstance(arg, ast.Name):
            return None  # an f-string, a concatenation or any other expression stays computed
        node = call
        while node in parent:
            node = parent[node]
            loops = [node] if isinstance(node, ast.For) else list(node.generators) if isinstance(
                node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)) else []
            for loop in loops:
                target, iterable = loop.target, loop.iter
                position = None
                if isinstance(target, ast.Name) and target.id == arg.id:
                    pass
                elif isinstance(target, ast.Tuple) and any(isinstance(t, ast.Name) and t.id == arg.id for t in target.elts):
                    if not all(isinstance(t, ast.Name) for t in target.elts):
                        return None
                    position = [t.id for t in target.elts].index(arg.id)
                else:
                    continue
                if isinstance(iterable, ast.Name):
                    iterable = unmutated_module_literal(iterable.id)
                    if iterable is None:
                        return None
                values = literal_strings(iterable, position)
                if values is None:
                    return None
                body = node.body if isinstance(node, ast.For) else [node.elt] + ([node.value] if isinstance(node, ast.DictComp) else [])
                if any(binds(statement, arg.id) for statement in body):
                    return None  # the loop variable is rebound in the body
                return values
        return None

    # Root's K2 of #84's third delta R4 (2026-11-12): a parameter-named Name in the function's own defaults or
    # decorators reads the ENCLOSING scope, but `ev` looks a name up in the file's assignments whatever their scope, so
    # the un-shadow holds only when that name's single binding in the whole file is one plain, unmutated module-level
    # assignment (the loop-literal pattern): `LIB = join(dirname(__file__), "../../packages/shared"); def setup(LIB=None,
    # _=sys.path.insert(0, LIB))` reads shared (D01); the same default beside a module `(LIB := os.environ[...])` or
    # `for LIB in ...` and a helper-local `LIB = ...` stays shadowed, so the entry is its text and refuses (G03, G04).
    shadowed.update(ident for ident, name in enclosing.items() if unmutated_module_literal(name) is None)

    names: set[str] = set()
    sites: list[tuple] = []  # (kind, expr, resolved, (evaluated prefix, a parent step after it) or None, the rule-6 text or None)
    # R6 (root's ruling of 2026-11-12, fail-closed by token, R6-2): every node a recording branch below UNDERSTOOD, with
    # its whole subtree (the `sys.path` it mutated, the `importlib` it called through). A capability occurrence the
    # scan below finds outside this set is consumed by no read rule, and the file refuses at the single refuse point.
    consumed: set[int] = set()

    def consume(node) -> None:
        consumed.update(id(sub) for sub in ast.walk(node))

    spec_sites: dict[int, tuple] = {}  # id() of a recorded spec_from_file_location call -> its path site (R6-2 fix (1))

    # N3 (root's ruling of 2026-11-12 21:32): `importlib.resources.files(anchor)` / `.read_text(anchor, ...)` import the
    # anchor package. The receivers and bound names this file reaches them by, so `p.read_text("utf-8")` is never one.
    res_mods = {"importlib.resources"}
    res_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            res_mods |= {alias.asname or alias.name for alias in node.names if alias.name == "importlib.resources"}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "importlib":
                res_mods |= {alias.asname or alias.name for alias in node.names if alias.name == "resources"}
            elif node.module == "importlib.resources":
                res_names |= {alias.asname or alias.name for alias in node.names if alias.name in ("files", "read_text")}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.AugAssign) and is_sys_path(node.target):
            for item in (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]):
                entry(item)
            consume(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Subscript) and is_sys_path(t.value) for t in node.targets):
            for item in (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]):
                entry(item)
            consume(node)
        elif isinstance(node, ast.Call):
            f, name = node.func, call_name(node.func)
            if isinstance(f, ast.Attribute) and is_sys_path(f.value):
                if f.attr == "insert" and len(node.args) == 2:
                    entry(node.args[1])
                    consume(node)
                elif f.attr == "append" and len(node.args) == 1:
                    entry(node.args[0])
                    consume(node)
                elif f.attr == "extend" and len(node.args) == 1:
                    for item in (node.args[0].elts if isinstance(node.args[0], (ast.List, ast.Tuple)) else [node.args[0]]):
                        entry(item)
                    consume(node)
            elif name in ("import_module", "__import__", "run_module") and node.args:
                arg = node.args[0]
                looped = loop_literal_names(node, arg)
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    # A literal naming a capability module (`__import__("sys").path`) is a binding of it, judged by
                    # the R6 scan below, never a module imported by name.
                    if arg.value.split(".")[0] not in CAPABILITY_MODULES:
                        names.add(arg.value.split(".")[0])
                        consume(node)
                elif looped is not None:
                    names |= {value.split(".")[0] for value in looped}  # resolved by name, like any import
                    consume(node)
                else:
                    sites.append(("module", source(arg), None, None, None))
                    consume(node)
            elif name in ("files", "read_text") and node.args and (
                    isinstance(f, ast.Name) and f.id in res_names
                    or isinstance(f, ast.Attribute) and source(f.value) in res_mods):
                # N3: a LITERAL anchor is a dependency edge of this file, like import_module("x"); a non-literal one is
                # left to the R6-2 scan below, which refuses it (root's ruling of 2026-11-12 21:32).
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.split(".")[0] not in CAPABILITY_MODULES:
                    names.add(arg.value.split(".")[0])
                    consume(node)
            elif name in ("spec_from_file_location", "run_path"):
                arg = (node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "location"), None)) \
                    if name == "spec_from_file_location" else (node.args[0] if node.args else None)
                if arg is not None:
                    sites.append(path_site(arg))
                    consume(node)
                    if name == "spec_from_file_location":
                        spec_sites[id(node)] = sites[-1]
            elif name == "exec" and node.args and isinstance(node.args[0], ast.Call):
                inner = node.args[0]  # exec(open(p).read())
                if isinstance(inner.func, ast.Attribute) and inner.func.attr == "read" and isinstance(inner.func.value, ast.Call) \
                        and call_name(inner.func.value.func) == "open" and inner.func.value.args:
                    arg = inner.func.value.args[0]
                    sites.append(path_site(arg))
                    consume(node)
    # R6-2 fix (1), root's S2 of 2026-11-14 (the first refusal cause of cli's census of vagary-core, 48 files):
    # `module_from_spec(spec)` builds the module of ONE spec, so it loads exactly the file that spec names. It is read
    # when its one argument is the `spec_from_file_location` call itself, or a name whose every binding in the call's
    # own scope (the module's, when that function binds none) is a plain `name = spec_from_file_location(...)` the
    # branch above recorded with an EVALUATED path inside the repository: that site is the file-load edge, so the call
    # adds none. A computed or unevaluable path, a path above the repository, a parameter, a loop, an import, a
    # `global`, an unpacking or any other binding of the name in that scope, a name bound only in an enclosing function,
    # or an argument that is not a name, still refuses at the capability scan below.
    def scope_of(node):
        while not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            node = parent[node]
        return node

    binders: dict[str, list] = {}  # name -> every node that binds it (a Store / Del, a parameter, an import, a global)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            binders.setdefault(node.id, []).append(node)
        elif isinstance(node, ast.arg):
            binders.setdefault(node.arg, []).append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name_ in node.names:
                binders.setdefault(name_, []).append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                binders.setdefault((alias.asname or alias.name).split(".")[0], []).append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            binders.setdefault(node.name, []).append(node)  # a def or class binds its name in the enclosing scope
        elif isinstance(node, ast.ExceptHandler) and node.name or isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            binders.setdefault(node.name, []).append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            binders.setdefault(node.rest, []).append(node)

    # cli's read of 02137ba (MF1, MF2, 2026-11-14 17:57): the spec name is resolved outward through the enclosing
    # function scopes, so
    # a closure, a lambda, a default or a decorator over an enclosing function's `spec` is judged by THAT binding,
    # never by a module-level one. Defaults, annotations, decorators and bases evaluate in the scope enclosing their
    # def, lambda or class; a class scope is skipped from a function nested in it. The call reads only when the first
    # scope that binds the name is the call's own or the module's. The spec call itself carries only `location=`: a
    # `loader=` (an inline `SourceFileLoader` the consumed call would hide), a `submodule_search_locations=` or a
    # `**kwargs` refuses, and so does any attribute store on the spec name (`spec.loader = ...`,
    # `spec.submodule_search_locations = [...]`) or `setattr` on it. cli's read of 7001655 (MF4): a class body is not
    # resolved: it reads a name it has not yet assigned from the module, and a comprehension or generator directly in
    # it cannot see its names, so a call whose own scope is a class body (or such a comprehension) refuses.
    def loads_one_file(call) -> bool:
        site = spec_sites.get(id(call))
        return site is not None and site[2] is not None and not (site[2] == ".." or site[2].startswith("../")) \
            and len(call.args) <= 2 and all(k.arg == "location" for k in call.keywords)

    def eval_scope(node):
        child, up = node, parent.get(node)
        while up is not None and not isinstance(up, ast.Module):
            if isinstance(up, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and any(st is child for st in up.body) \
                    or isinstance(up, ast.Lambda) and up.body is child:
                return up
            child, up = up, parent.get(up)
        return tree

    def bind_scope(b):
        return parent[parent[b]] if isinstance(b, ast.arg) else eval_scope(b)

    def resolve(name: str, at):
        own = here = eval_scope(at)
        every = binders.get(name, [])
        while True:
            if here is own or not isinstance(here, ast.ClassDef):
                found = [b for b in every if bind_scope(b) is here]
                if found:
                    return own, here, found
            if here is tree:
                return own, None, []
            here = eval_scope(here)

    # Root's ruling of 2026-11-14 18:29 on cli's read of 7001655 (F1 stale spec, a MUST) and cli's should-fix 3:
    # a module-level `spec` can be rebound behind the reader's back by a star import or a write through `globals()` /
    # `vars()` / `locals()`, so F1 reads a named spec only in a file with no star import and with every such call a
    # read (a load subscript, `.get` / `.keys` / `.items` / `.values`, a loop, an `in`, `sorted` / `list` / `len`).
    # The spec object can be changed through any other handle, so every use of the name bound where the call's is
    # must be: the call's argument, an `is` / `is not` comparison or a truth test, `spec.loader.exec_module(...)`,
    # `spec.loader` tested, or a read of `name`, `origin`, `parent`, `cached` or `has_location`. An alias
    # (`s = spec`), a call argument (`f(spec)`, `setattr(spec, ...)`), a store or `del`, `cast(..., spec.loader)` and
    # `loader = spec.loader` refuse. A file naming `__spec__`, `__loader__` or `__dict__` (an attribute, a name or a
    # string) refuses F1 in both forms: the module's `__spec__` is the same object.
    star_import = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree))
    spec_dunders = ("__spec__", "__loader__", "__dict__")

    def namespace_read(c) -> bool:
        up = parent.get(c)
        return isinstance(c, ast.Call) and not c.args and not c.keywords and (
            isinstance(up, ast.Subscript) and up.value is c and isinstance(up.ctx, ast.Load)
            or isinstance(up, ast.Attribute) and up.value is c and up.attr in ("get", "keys", "items", "values")
            and isinstance(parent.get(up), ast.Call) and parent[up].func is up
            or isinstance(up, (ast.For, ast.comprehension)) and up.iter is c
            or isinstance(up, ast.Compare) and any(x is c for x in up.comparators)
            or isinstance(up, ast.Call) and isinstance(up.func, ast.Name) and up.func.id in ("sorted", "list", "len")
            and len(up.args) == 1 and up.args[0] is c)

    rebinds_module = star_import or any(
        isinstance(n, ast.Name) and n.id in ("globals", "vars", "locals")
        and not (isinstance(parent.get(n), ast.Call) and parent[n].func is n and namespace_read(parent[n]))
        for n in ast.walk(tree))
    names_spec = any(isinstance(n, ast.Attribute) and n.attr in spec_dunders or isinstance(n, ast.Name) and n.id in spec_dunders
                     or isinstance(n, ast.Constant) and isinstance(n.value, str) and any(w in n.value for w in spec_dunders)
                     for n in ast.walk(tree))

    def tested(n) -> bool:
        up = parent.get(n)
        if isinstance(up, ast.Compare):
            return all(isinstance(o, (ast.Is, ast.IsNot)) for o in up.ops)
        while isinstance(up, ast.BoolOp) or isinstance(up, ast.UnaryOp) and isinstance(up.op, ast.Not):
            if isinstance(up, ast.UnaryOp):
                return True
            n, up = up, parent.get(up)
        return isinstance(up, (ast.If, ast.While, ast.Assert, ast.IfExp)) and up.test is n

    def spec_use_ok(n) -> bool:
        up = parent.get(n)
        if isinstance(n.ctx, ast.Load) and tested(n):
            return True
        if isinstance(up, ast.Call) and call_name(up.func) == "module_from_spec" and up.args and up.args[0] is n:
            return True
        if isinstance(up, ast.Attribute) and up.value is n and isinstance(up.ctx, ast.Load):
            q = parent.get(up)
            if up.attr in ("name", "origin", "parent", "cached", "has_location"):
                return not (isinstance(q, ast.Call) and q.func is up)
            if up.attr == "loader":
                return tested(up) or isinstance(q, ast.Attribute) and q.value is up and q.attr == "exec_module" \
                    and isinstance(q.ctx, ast.Load) and isinstance(parent.get(q), ast.Call) and parent[q].func is q
        return False

    def spec_of(arg, call) -> bool:
        if isinstance(arg, ast.Call):
            return not names_spec and loads_one_file(arg)
        if not isinstance(arg, ast.Name) or arg.id in unreadable or names_spec or rebinds_module:
            return False
        every = binders.get(arg.id, [])
        if any(isinstance(b, (ast.Global, ast.Nonlocal)) for b in every):
            return False
        own, scope, mine = resolve(arg.id, call)
        if isinstance(own, ast.ClassDef):
            return False
        if scope is None or scope is not own and scope is not tree:
            return False
        if any(isinstance(n, ast.Name) and n.id == arg.id and not isinstance(n.ctx, ast.Store)
               and resolve(n.id, n)[1] is scope and not spec_use_ok(n) for n in ast.walk(tree)):
            return False
        for b in mine:
            stmt = parent.get(b)
            plain = isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and stmt.targets[0] is b \
                or isinstance(stmt, ast.AnnAssign) and stmt.target is b and stmt.value is not None
            if not (isinstance(b, ast.Name) and plain and isinstance(stmt.value, ast.Call) and loads_one_file(stmt.value)):
                return False
        return True

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and call_name(node.func) == "module_from_spec" and len(node.args) == 1 \
                and not node.keywords and (isinstance(node.func, ast.Name) or isinstance(node.func.value, ast.Name)
                                           or isinstance(node.func.value, ast.Attribute) and isinstance(node.func.value.value, ast.Name)) \
                and spec_of(node.args[0], node):
            consume(node)
    # R6-2 fix (2), root's S2 of 2026-11-14 (cause 2 of cli's census, SCOPE): `globals()[<literal>]` and
    # `globals().get(<literal>[, default])` read the module-level name the literal spells, the same object a read of that
    # name reaches, when this module binds it at its top level by a `def`, a `class` or a plain assignment and it is no
    # dunder and no name bound to a capability module or one of its names (`import sys as k`, `from importlib import
    # util`): those reach what rule 5 and the loader rules judge by name. A computed key, a write (`globals()[k] = v`,
    # `patch.dict(globals(), ...)`, `monkeypatch.setitem(globals(), ...)`), globals() passed out or bound to a name, and
    # `locals()` / `vars()` still refuse.
    capability_names: set[str] = set(CAPABILITY_MODULES) | {"__builtins__"}

    def builtin(name: str) -> bool:  # cli's read of 02137ba (c): a def, class or any binding of the name shadows it
        return name not in binders and name not in unreadable
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            top = (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) and node.level == 0 else ""
            for alias in node.names:
                bound_as = alias.asname or alias.name.split(".")[0]
                if top in CAPABILITY_MODULES or alias.name.split(".")[0] in CAPABILITY_MODULES or bound_as in CAPABILITY_MODULES:
                    capability_names.add(bound_as)
    module_names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_names.add(stmt.name)
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            module_names.add(stmt.targets[0].id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            module_names.add(stmt.target.id)
    module_names = {n for n in module_names if n not in capability_names and not n.startswith("__")}

    def is_globals(node) -> bool:
        return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "globals" \
            and not node.args and not node.keywords and builtin("globals")

    def literal(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for node in ast.walk(tree):
        if is_globals(node):
            p = parent.get(node)
            g = parent.get(p)
            if isinstance(p, ast.Subscript) and p.value is node and isinstance(p.ctx, ast.Load) and literal(p.slice) in module_names:
                consume(node)
            elif isinstance(p, ast.Attribute) and p.value is node and p.attr == "get" and isinstance(g, ast.Call) \
                    and g.func is p and 1 <= len(g.args) <= 2 and not g.keywords and literal(g.args[0]) in module_names:
                consume(node)
    # R6-2 fix (2b), the census's own SCOPE form (38 of its 41 sites; none is a literal key): the test-runner loop over
    # the module's names. A `for k in <globals()>` (`globals()`, `.keys()`, under `sorted` / `list`) yields strings; a
    # `globals()[k]()` in it, under `if k.startswith(<prefix>)`, calls a name the prefix admits. A `for k, v in
    # <globals().items()>` is read when `v` is used only as `callable(v)`, `v.__name__`, `getattr(v, "__name__", ...)`
    # anywhere in the loop, and as a no-argument `v()` only under `if k.startswith(<prefix>)` (alone or as a conjunct),
    # neither name rebound in the loop, and `v` read after the loop nowhere outside a function that binds its own. The
    # prefix is a non-empty literal with no leading underscore (so no dunder: `__builtins__`, `__loader__`) that no
    # capability-bound name of the file starts with (`import sys as test_sys` keeps it refusing). The gate is the
    # loop's own name test; a gate on a runtime attribute (`getattr(fn, "__name__", "").startswith("test_")` over
    # `.values()`), a comprehension over `.items()` and every other use of `v` still refuse.
    def unwrap(node):
        while isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("sorted", "list") \
                and builtin(node.func.id) and len(node.args) == 1 and not node.keywords:
            node = node.args[0]
        return node

    def prefix_gate(test, key: str) -> bool:
        for t in (test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]):
            if isinstance(t, ast.Call) and isinstance(t.func, ast.Attribute) and t.func.attr == "startswith" \
                    and isinstance(t.func.value, ast.Name) and t.func.value.id == key and len(t.args) == 1 and not t.keywords:
                prefix = literal(t.args[0])
                if prefix and not prefix.startswith("_") and not any(n.startswith(prefix) for n in capability_names):
                    return True
        return False

    # cli's read of 02137ba, made MUST by root's ruling (a) of 17:58: a use inside a lambda, a nested def or class, or a
    # generator expression in the loop runs later, with the loop's LAST value, so the gate does not hold for it; and a
    # file with a star import may hold any name the prefix admits, so neither loop form reads there.
    def gated(use, loop, key: str) -> bool:
        node = use
        while node is not loop:
            up_ = parent[node]
            if isinstance(up_, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.GeneratorExp)):
                return False
            if isinstance(up_, ast.If) and any(stmt is node for stmt in up_.body) and prefix_gate(up_.test, key):
                return True
            node = up_
        return False

    def no_arg_call(call, func) -> bool:
        return isinstance(call, ast.Call) and call.func is func and not call.args and not call.keywords

    star = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree))
    for loop in ([] if star else ast.walk(tree)):
        if not isinstance(loop, (ast.For, ast.AsyncFor)):
            continue
        core = unwrap(loop.iter)
        method = core.func.attr if isinstance(core, ast.Call) and isinstance(core.func, ast.Attribute) \
            and is_globals(core.func.value) and not core.args and not core.keywords else None
        inside = [n for stmt in loop.body + loop.orelse for n in ast.walk(stmt)]
        inside_ids = {id(n) for n in inside}
        targets = [loop.target] if isinstance(loop.target, ast.Name) else loop.target.elts \
            if isinstance(loop.target, ast.Tuple) and all(isinstance(e, ast.Name) for e in loop.target.elts) else []
        names_ = [t.id for t in targets]
        if not names_ or len(set(names_)) != len(names_) \
                or any(isinstance(n, ast.Name) and n.id in names_ and not isinstance(n.ctx, ast.Load) for n in inside):
            continue
        if (is_globals(core) or method == "keys") and len(names_) == 1:
            key = names_[0]
            consume(core if is_globals(core) else core.func.value)
            for n in inside:
                sub = parent.get(n)
                if is_globals(n) and isinstance(sub, ast.Subscript) and sub.value is n and isinstance(sub.ctx, ast.Load) \
                        and isinstance(sub.slice, ast.Name) and sub.slice.id == key and no_arg_call(parent.get(sub), sub) \
                        and gated(parent[sub], loop, key):
                    consume(n)
        elif method == "items" and len(names_) == 2:
            key, value = names_
            ok = True
            for n in ast.walk(tree):
                if not (isinstance(n, ast.Name) and n.id == value and isinstance(n.ctx, ast.Load)):
                    continue
                use = parent.get(n)
                if id(n) not in inside_ids:
                    own = scope_of(use)
                    ok = ok and own is not tree and own is not scope_of(loop) \
                        and any(scope_of(parent[b]) is own for b in binders.get(value, []))
                elif no_arg_call(use, n):
                    ok = ok and gated(use, loop, key)
                elif not (isinstance(use, ast.Attribute) and use.attr == "__name__"
                          or isinstance(use, ast.Call) and isinstance(use.func, ast.Name) and builtin(use.func.id)
                          and use.args and use.args[0] is n and not use.keywords
                          and (use.func.id == "callable" and len(use.args) == 1
                               or use.func.id == "getattr" and len(use.args) in (2, 3) and literal(use.args[1]) == "__name__")):
                    ok = False
            if ok:
                consume(core.func.value)
    # R6-2 fix (3), root's S2 of 2026-11-14 (cause 3 of cli's census, SYS-PATH-REACH): in a TEST file, by the planner's
    # own classification (plan.is_test_file with no config test_globs: test_*.py, *_test.py, any file under test/,
    # tests/ or __tests__/, so conftest.py there too), the `sys.modules` and `sys.path` uses that load no file are read.
    # `sys.modules[k] = v`, `del sys.modules[k]`, a discarded `sys.modules.pop(k[, d])`, `<x>.setitem(sys.modules,
    # "<m>", v)` and `<x>.delitem(sys.modules, "<m>"[, ...])` bind or unbind a module name for the test's own process
    # (a later `import m` is judged as an import); `"m" in sys.modules` and `for m in sys.modules` read names;
    # `sys.modules["m"]` and `sys.modules.get("m"[, d])` read module m, recorded as this file's dependency edge like
    # `import_module("m")`. `sys.path` compared, indexed, or under len / list / tuple is a read of the list. A key naming
    # a capability module (sys, site, importlib, runpy, builtins) in any of these forms, a computed key on a read, a
    # use chained past the access (`sys.modules["m"].x`), `sys.modules.items()` / `.update(...)`, `p = sys.path`, any
    # other use, and every one of these outside a test file, still refuse.
    # Root's ruling (b) of 2026-11-14 17:58: a name is not enough. F3 reads only in a file `test_only(path)` says no
    # non-test file imports (code_imported_test_files, passed by the scan); a caller that passes none gets no F3.
    # cli's read of 02137ba: MF3, a bind (`sys.modules[k] = v`, `monkeypatch.setitem`) refuses in a file that names
    # `__path__`, `__spec__`, `submodule_search_locations` or `__dict__` anywhere (an attribute, a name, a keyword, a
    # string such as `"pkg.__path__"`) or calls `setattr` with a computed name (`monkeypatch.setattr("a.b", v)` names
    # it in its string) or `vars` with an argument: a stub with a
    # `__path__` sends `import m.sub` to a directory no edge names. The bound value is a call, a constant or a name no
    # import binds (an imported package bound under another name carries its own `__path__`). (a) `sys.path` reads only
    # on the right of `in` / `not in` / `==` / `!=` or the left of `==` / `!=`, and `"m" in sys.modules` only as the
    # last operand: `sys.path in y` hands the list to `y`. (b) `setitem` / `delitem` read only on `monkeypatch`.
    if test_only is not None and _plan.is_test_file(path, []) and test_only(path):
        def take(*nodes) -> None:
            consumed.update(id(n) for n in nodes)

        pkg_words = ("__path__", "__spec__", "submodule_search_locations", "__dict__")
        pkg_shape = any(isinstance(n, ast.Attribute) and n.attr in pkg_words or isinstance(n, ast.Name) and n.id in pkg_words
                        or isinstance(n, ast.keyword) and n.arg in pkg_words
                        or isinstance(n, ast.Constant) and isinstance(n.value, str) and any(w in n.value for w in pkg_words)
                        or isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute))
                        and (n.func.id if isinstance(n.func, ast.Name) else n.func.attr) == "setattr"
                        and not (len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
                                 or isinstance(n.func, ast.Attribute) and n.args and isinstance(n.args[0], ast.Constant))
                        or isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "vars" and n.args
                        for n in ast.walk(tree))

        # cli's read of 7001655 (should-fix 2, root's 18:29 scope): another file may hand back a stub with a
        # `__path__`, so a bound value reads only when this file shows it has none: a constant,
        # `types.ModuleType(<literal>)`, a `Mock()` / `MagicMock()` (no `spec`, `spec_set`, `wraps`, positional or `**`
        # argument; a mock refuses a dunder it was not given), or a name every binding of which in this file is a
        # plain assignment of one of those.
        def bound_only_by(name: str, module: str, attr: str | None) -> bool:
            every = binders.get(name, [])
            return bool(every) and name not in unreadable and all(
                isinstance(b, ast.Import) and attr is None and any(a.name == module and (a.asname or a.name) == name for a in b.names)
                or isinstance(b, ast.ImportFrom) and attr is not None and b.module == module and not b.level
                and any(a.name == attr and (a.asname or a.name) == name for a in b.names) for b in every)

        mocks = ("Mock", "MagicMock", "NonCallableMock", "NonCallableMagicMock", "AsyncMock")

        def stub_call(value) -> bool:
            if isinstance(value, ast.Constant):
                return True
            if not isinstance(value, ast.Call) or any(k.arg in (None, "spec", "spec_set", "wraps") for k in value.keywords):
                return False
            f = value.func
            if isinstance(f, ast.Name) and f.id == "ModuleType" and bound_only_by(f.id, "types", "ModuleType") \
                    or isinstance(f, ast.Attribute) and f.attr == "ModuleType" and isinstance(f.value, ast.Name) \
                    and bound_only_by(f.value.id, "types", None):
                return 1 <= len(value.args) <= 2 and not value.keywords \
                    and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in value.args)
            mock = isinstance(f, ast.Name) and f.id in mocks and any(bound_only_by(f.id, m, f.id) for m in ("unittest.mock", "mock")) \
                or isinstance(f, ast.Attribute) and f.attr in mocks and isinstance(f.value, ast.Name) \
                and (bound_only_by(f.value.id, "unittest", "mock") or bound_only_by(f.value.id, "mock", None))
            return mock and not value.args

        def bindable(value) -> bool:
            if pkg_shape:
                return False
            if isinstance(value, ast.Name):
                every = binders.get(value.id, [])
                return bool(every) and value.id not in unreadable and all(
                    isinstance(parent.get(b), (ast.Assign, ast.AnnAssign)) and isinstance(b, ast.Name)
                    and (b in parent[b].targets if isinstance(parent[b], ast.Assign) else parent[b].target is b)
                    and stub_call(parent[b].value) for b in every)
            return stub_call(value)

        def cmp_side(cmp, node, right_ops, left_ops) -> bool:
            if not isinstance(cmp, ast.Compare):
                return False
            seq = [cmp.left, *cmp.comparators]
            i = next((j for j, x in enumerate(seq) if x is node), None)
            return i is not None and (i == 0 or isinstance(cmp.ops[i - 1], right_ops)) \
                and (i == len(cmp.ops) or isinstance(cmp.ops[i], left_ops))

        def capability_key(node) -> bool:
            return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.split(".")[0] in CAPABILITY_MODULES

        def module_key(node):
            return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value \
                and not capability_key(node) else None

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Attribute) and node.attr in ("modules", "path") and isinstance(node.value, ast.Name)
                    and node.value.id == "sys" and isinstance(node.ctx, ast.Load)):
                continue
            up1 = parent.get(node)
            up2 = parent.get(up1)
            if node.attr == "path":
                if cmp_side(up1, node, (ast.In, ast.NotIn, ast.Eq, ast.NotEq), (ast.Eq, ast.NotEq)):
                    take(node.value, node)
                elif isinstance(up1, ast.Subscript) and up1.value is node and isinstance(up1.ctx, ast.Load):
                    take(node.value, node, up1)
                elif isinstance(up1, ast.Call) and isinstance(up1.func, ast.Name) and up1.func.id in ("len", "list", "tuple") \
                        and builtin(up1.func.id) and len(up1.args) == 1 and up1.args[0] is node and not up1.keywords:
                    take(node.value, node)
            elif isinstance(up1, ast.Subscript) and up1.value is node:
                if capability_key(up1.slice):
                    continue
                if isinstance(up1.ctx, ast.Store) and isinstance(up2, ast.Assign) and len(up2.targets) == 1 and up2.targets[0] is up1 \
                        and bindable(up2.value) or isinstance(up1.ctx, ast.Del):
                    take(node.value, node, up1)
                elif isinstance(up1.ctx, ast.Load) and module_key(up1.slice):
                    names.add(module_key(up1.slice).split(".")[0])
                    take(node.value, node, up1)
            elif isinstance(up1, ast.Attribute) and up1.value is node and isinstance(up2, ast.Call) and up2.func is up1 \
                    and 1 <= len(up2.args) <= 2 and not up2.keywords:
                if up1.attr == "get" and module_key(up2.args[0]):
                    names.add(module_key(up2.args[0]).split(".")[0])
                    take(node.value, node, up1, up2)
                elif up1.attr == "pop" and isinstance(parent.get(up2), ast.Expr) and not capability_key(up2.args[0]):
                    take(node.value, node, up1, up2)
            elif isinstance(up1, ast.Call) and isinstance(up1.func, ast.Attribute) and up1.func.attr in ("setitem", "delitem") \
                    and isinstance(up1.func.value, ast.Name) and up1.func.value.id == "monkeypatch" and len(up1.args) >= 2 \
                    and up1.args[0] is node and module_key(up1.args[1]) \
                    and (up1.func.attr == "delitem" or len(up1.args) == 3 and not up1.keywords and bindable(up1.args[2])):
                take(node.value, node)
            elif cmp_side(up1, node, (ast.In, ast.NotIn), ()) \
                    or isinstance(up1, (ast.For, ast.AsyncFor, ast.comprehension)) and up1.iter is node:
                take(node.value, node)
    unconsumed = capability_occurrences(tree, text, parent, consumed)
    if unconsumed:
        lineno, segment = unconsumed[0]
        raise ValueError(f"unresolved (the path-mutation capability `{segment}` on line {lineno} of {path} is consumed by "
                         f"no read rule; a file reads only when every one is) in {path}")
    return entries, names, sites


# R6-2 (root's ruling of 2026-11-12, fail-closed by token; cli's R6 design accepted 16:44): the modules whose binding is a
# path-mutation capability, each with the family the scan judges it under. `sys` is read by rule 5 below; `site`,
# `importlib`, `runpy` and `builtins` are read only through the recording branches of python_file_facts.
CAPABILITY_MODULES = {"sys": "sys", "site": "site", "importlib": "loader", "runpy": "loader", "builtins": "loader"}
# The attributes of `sys` that reach the import path (root's rule 5 twins): a use of a sys-bound name as any of these,
# or as any dunder (`sys.__dict__`), is a path reach; every other attribute (`sys.exit`, `sys.argv`, `sys.stderr`) is not.
SYS_PATH_ATTRS = frozenset({"path", "modules", "meta_path", "path_hooks", "path_importer_cache"})
# The loader calls, by name or attribute: each is a load the recording branches read (a consumed call) or a refusal.
LOADER_CALLS = frozenset({"import_module", "__import__", "run_module", "run_path", "spec_from_file_location",
                          "module_from_spec", "SourceFileLoader", "addsitedir"})
EXEC_CALLS = frozenset({"exec", "eval", "compile"})
# N2 / N3 (root's ruling of 2026-11-12 21:32): the loader calls read through their chain when the first argument is a literal
# the recording branch consumed, the importlib.metadata reads that are not loads, the importlib.resources anchors recorded as edges.
N2_LITERAL_LOADERS = frozenset({"import_module", "__import__", "run_module"})
N3_METADATA_READS = frozenset({"importlib.metadata.version", "importlib.metadata.files"})
N3_RESOURCE_READS = frozenset({"importlib.resources.files", "importlib.resources.read_text"})


def capability_occurrences(tree, text: str, parent: dict, consumed: set[int]) -> list[tuple[int, str]]:
    """Every path-mutation capability occurrence in one parsed Python file that no read rule consumed, each as (line, the
    source segment, whitespace collapsed), in file order with the import bindings LAST and no duplicates (R6-2 of #86,
    root's ruling of 2026-11-12: a file reads only when every one of them is consumed; the first one names the refusal,
    so the message names the use that was not consumed before the `import sys` it hangs from, and a dead import only
    when nothing else refuses). The kinds, root's B8 eleven forms among them:
    - SYS-BIND: `import sys` under any alias, `from sys import ...` (any name, any alias, `*`), `__import__("sys")` and
      `import_module("sys")`, a name literally called `sys` imported from ANY module (root's dated residual: an alias
      re-exported under another name stays unseen), and `del` or a rebinding of a sys-bound name. Rule 5 (root's (i)):
      the binding is consumed when the name is used at least once and EVERY use is an attribute read outside
      SYS_PATH_ATTRS and the dunders, or sits inside a consumed recording branch (`sys.path.insert(0, x)` read by rule
      6); a name that is aliased (`s = sys`), passed (`getattr(sys, n)`, `vars(sys)`, `dir(sys)`, `setattr(sys, ...)`),
      subscripted, deleted, rebound or never used (a dead import, root's (ii)) is not. `from sys import argv` is the
      attribute read itself: consumed when the bound name is used at least once; `from sys import path` (any of
      SYS_PATH_ATTRS, any alias) and `from sys import *` never are.
    - SYS-PATH-REACH: `.path`, `.modules`, `.meta_path`, `.path_hooks`, `.path_importer_cache` or a dunder on a
      sys expression (a sys-bound name, `__import__("sys")`, `os.sys`) outside a consumed branch: `p = sys.path`,
      `sys.path.remove(x)`, `sys.path.insert(*args)`, `list.insert(sys.path, 0, x)`, `sys.path.__iadd__([x])`,
      `sys.path.__setitem__(...)`, `sys.modules["sys"].path`, `sys.path = [...]`, `getattr(sys, "path")`.
    - SITE: `import site` under any alias, `from site import ...`, any use of a site-bound name, `addsitedir` by any
      name or attribute. No rule reads them.
    - LOADER: `import importlib` / `runpy` / `builtins` under any alias or submodule, `from importlib[.util] import ...`,
      a use of a loader-bound name outside a consumed call (`importlib.util.find_spec`, `importlib.reload`,
      `builtins.exec`), a loader call by attribute on anything (`.module_from_spec(...)`, `.run_path(...)`), and
      `exec` / `eval` / `compile` as a bare name (`exec("import x")`, `exec(__doc__)`), outside a consumed branch
      (`exec(open(p).read())` is read by rule 8). A loader binding is consumed when every use of it sits inside a
      consumed call and there is at least one.
    - ENV: a string constant holding `PYTHONPATH` anywhere (an environ key, a shell string, an `env=` mapping).
    - SCOPE: `globals()`, `locals()` or `vars()` with no argument in a file that binds sys (root's twin (i)).
    Three narrowings, root's ruling of 2026-11-12 21:32 on cli's measured census (each a rule with twin vectors, never a
    hand exemption): N1 `x in sys.path` / `x not in sys.path` is a read of the list (the guarded insert or append in the
    same file is judged on its own); N2 a loader call with a LITERAL module name that a recording branch consumed
    (`__import__("json")`, `import_module("server")`, `run_module("m")`) is read through the chain that follows it
    (`.loads(x)`, `.app`), a non-literal first argument refuses as before; N3 `importlib.metadata.version(...)` and
    `importlib.metadata.files(...)` read installed metadata and are not loads, `importlib.resources.files(anchor)` and
    `read_text(anchor, ...)` import the anchor package: a literal anchor is recorded as this file's dependency edge and
    read through its chain, a non-literal one refuses; `entry_points(...).load()` stays a loader.
    Three reads of root's S2 of 2026-11-14 (the census's top three causes), each a recording branch in
    `python_file_facts` with twin vectors in test_edges_r6_2_fix_vectors.json: F1 `module_from_spec(spec)` over a
    spec name resolved outward to the call's own or the module's scope, bound there only by `spec_from_file_location`
    calls whose path evaluated and with no keyword but `location=` (a computed path still refuses at LOADER; a closure,
    lambda or default over an enclosing function's spec, `loader=` and an attribute store on the spec refuse); F2
    SCOPE `globals()["n"]` / `globals().get("n")` for a module-level name the file binds, and the test-runner loop
    over `globals()` under a literal `startswith` prefix (dynamic keys, writes, comprehensions, `globals()` passed
    out, a star import and a gated call inside a lambda, nested def or generator still refuse); F3 SYS-PATH-REACH in
    a test file no non-test file imports (plan.is_test_file and code_imported_test_files): `sys.modules` binds,
    unbinds and literal reads, and `sys.path` as a right operand of in / ==, indexed or copied (capability keys,
    computed read keys, `p = sys.path`, `sys.path in y`, a bind in a file naming `__path__` / `__spec__` /
    `submodule_search_locations` / `__dict__`, a receiver other than `monkeypatch`, and every such use in any other
    file still refuse); `sys.path` reads as a right operand of in / not in / == / != and a left operand of == / !=.
    Round 3 (cli's read of 7001655, root's 18:29 scope): F1 refuses in a class body, beside a star import or a
    non-read `globals()` / `vars()` / `locals()`, on any spec use but the listed reads, and in a file naming
    `__spec__`, `__loader__` or `__dict__`; the F3 test files a non-test file may import come from the AST; an F3
    bind takes only a value this file shows carries no `__path__`.
    A bare `sys`, `site`, `importlib`, `runpy` or `builtins` the file never imports is its module all the same (a star
    import, an injection), unless the file binds that name itself (an assignment, a parameter, a `def`): then it is a
    local, and no occurrence. A file with no occurrence has nothing to consume and reads as before."""
    import ast

    def segment(node) -> str:
        return " ".join((ast.get_source_segment(text, node) or ast.dump(node)).split())

    def call_name(f):
        return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None

    def chain_top(node):
        """The outermost attribute / call / subscript chain this node heads (`importlib.util.find_spec("x")` for its
        `importlib`), so the refusal names the whole use."""
        while True:
            p = parent.get(node)
            if isinstance(p, ast.Attribute) and p.value is node or isinstance(p, ast.Call) and p.func is node \
                    or isinstance(p, ast.Subscript) and p.value is node:
                node = p
            else:
                return node

    found: list[tuple[int, int, int, str]] = []  # (rank: 0 a use, 1 an import binding; line; column; segment)

    def refuse(node, binding: bool = False) -> None:
        if id(node) not in consumed:
            found.append((1 if binding else 0, node.lineno, node.col_offset, segment(node)))

    # Names the file binds by something other than an import: a bare capability name among them is a local, not the module.
    local_bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            local_bound.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local_bound.add(node.name)
        elif isinstance(node, ast.arg):
            local_bound.add(node.arg)
    # bound name -> family. The bare module names are their families unless the file binds them locally; every import
    # of a capability module (any alias, any submodule) adds its name, an import overriding a local binding (a rebinding
    # of an imported name is then the Store below, and refuses).
    bound: dict[str, str] = {m: f for m, f in CAPABILITY_MODULES.items() if m not in local_bound}
    if "__builtins__" not in local_bound:
        bound["__builtins__"] = "loader"
    modpath: dict[str, str] = {m: m for m in CAPABILITY_MODULES}  # bound name -> the dotted module or function it stands for
    binds: list[tuple] = []  # (import statement, [bound names], [names bound from `from sys import <non-path>`])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            hit = []
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in CAPABILITY_MODULES:
                    name = alias.asname or top
                    bound[name] = CAPABILITY_MODULES[top]
                    modpath[name] = alias.name if alias.asname else top
                    hit.append(name)
            if hit:
                binds.append((node, hit, []))
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0] if node.level == 0 else ""
            hit, from_sys = [], []
            for alias in node.names:
                name = alias.asname or alias.name
                if top in CAPABILITY_MODULES:
                    family = CAPABILITY_MODULES[top]
                    if alias.name == "*" or (family == "sys" and (alias.name in SYS_PATH_ATTRS or alias.name.startswith("__"))):
                        refuse(node)  # `from sys import *`, `from sys import path as p`, `from importlib import *`
                    elif family == "sys":
                        from_sys.append(name)  # `from sys import argv`: the attribute read itself
                    else:
                        bound[name] = family
                        modpath[name] = f"{node.module}.{alias.name}"
                        hit.append(name)
                elif alias.name in CAPABILITY_MODULES or name in CAPABILITY_MODULES:
                    # A name literally called sys/site/importlib/runpy/builtins imported from any other module binds it.
                    bound[name] = CAPABILITY_MODULES.get(alias.name) or CAPABILITY_MODULES[name]
                    modpath[name] = alias.name if alias.name in CAPABILITY_MODULES else name
                    hit.append(name)
            if hit or from_sys:
                binds.append((node, hit, from_sys))
    binds_sys = any(bound.get(n) == "sys" for _, names_, _ in binds for n in names_) or any(fs for _, _, fs in binds)
    uses: dict[str, list] = {}  # bound name -> its Load uses (Name nodes)
    safe: set[int] = set()  # id() of a Load Name whose use rule 5 reads (a non-path attribute of sys)

    def sys_expression(node) -> bool:
        """A node that stands for the sys module: a sys-bound name, `__import__("sys")`, `import_module("sys")`, `X.sys`."""
        if isinstance(node, ast.Name):
            return bound.get(node.id) == "sys"
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "sys":
            return call_name(node.func) in ("__import__", "import_module")
        return isinstance(node, ast.Attribute) and node.attr == "sys"

    def membership_read(attr) -> bool:
        """N1: `x in sys.path` / `x not in sys.path` reads the list (the attribute is a comparator of an In/NotIn compare)."""
        g = parent.get(attr)
        return attr.attr == "path" and isinstance(g, ast.Compare) and any(c is attr for c in g.comparators) \
            and all(isinstance(op, (ast.In, ast.NotIn)) for op in g.ops)

    def owning_call(node):
        """Climb the attribute chain a loader name heads to the call it makes: (attribute names, the Call or None)."""
        attrs, cur = [], node
        while True:
            p = parent.get(cur)
            if isinstance(p, ast.Attribute) and p.value is cur:
                attrs.append(p.attr)
                cur = p
            elif isinstance(p, ast.Call) and p.func is cur:
                return attrs, p
            else:
                return attrs, None

    def read_through(node) -> bool:
        """N2 / N3: a loader name whose call a recording branch consumed with a LITERAL first argument is read through the
        chain after the call; `importlib.metadata.version` / `.files` are reads of installed metadata. Anything else is
        judged as before (a non-literal argument, another attribute, `entry_points(...).load()`)."""
        attrs, call = owning_call(node)
        if call is None:
            return False
        dotted = ".".join([modpath.get(node.id, node.id)] + attrs) if isinstance(node, ast.Name) else None
        if dotted in N3_METADATA_READS:
            return True
        literal = bool(call.args) and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
        if dotted in N3_RESOURCE_READS or call_name(call.func) in N2_LITERAL_LOADERS or call_name(call.func) in ("files", "read_text"):
            return id(call) in consumed and literal
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            family = bound.get(node.id)
            if not isinstance(node.ctx, ast.Load):
                if family is not None:
                    refuse(parent.get(node, node))  # `sys = x`, `del sys`, `for site in ...`: a rebinding of a module
                continue
            if family is not None:
                uses.setdefault(node.id, []).append(node)
            if family == "sys":
                p = parent.get(node)
                if isinstance(p, ast.Attribute) and p.value is node:
                    if (p.attr in SYS_PATH_ATTRS or p.attr.startswith("__")) and not membership_read(p):
                        refuse(chain_top(node))
                    else:
                        safe.add(id(node))  # a non-path attribute, or N1's `x in sys.path`
                else:
                    refuse(node)  # aliased, passed, subscripted, compared: the module itself leaves the name
            elif family in ("site", "loader"):
                if family == "loader" and read_through(node):
                    safe.add(id(node))  # N2 / N3
                elif id(node) not in consumed:
                    refuse(chain_top(node))  # an alias, an argument, an attribute no recording branch read
            elif node.id in EXEC_CALLS or node.id in LOADER_CALLS:
                if not read_through(node):
                    refuse(chain_top(node))
            elif node.id in ("globals", "locals", "vars") and binds_sys:
                p = parent.get(node)
                if isinstance(p, ast.Call) and p.func is node and not p.args and not p.keywords:
                    refuse(p)
        elif isinstance(node, ast.Attribute):
            if node.attr in LOADER_CALLS:
                if not read_through(node):
                    refuse(chain_top(node))
            elif node.attr in EXEC_CALLS and isinstance(node.value, ast.Name) and bound.get(node.value.id) == "loader":
                refuse(chain_top(node))
            elif not isinstance(node.value, ast.Name) and sys_expression(node.value) \
                    and (node.attr in SYS_PATH_ATTRS or node.attr.startswith("__")) and not membership_read(node):
                refuse(chain_top(node))  # `__import__("sys").path`, `os.sys.path`: the anonymous sys reaches the path
        elif isinstance(node, ast.Call) and sys_expression(node):
            p = parent.get(node)
            if not (isinstance(p, ast.Attribute) and p.value is node):
                refuse(node)  # `s = __import__("sys")`, `f(import_module("sys"))`: the module leaves the call
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "PYTHONPATH" in node.value:
            refuse(node)
    # The bindings: rule 5 for sys, "every use consumed" for a loader, never for site; a dead import refuses (root's (ii)).
    for stmt, names_, from_sys in binds:
        ok = True
        for name in names_:
            used = uses.get(name, [])
            if not used or bound[name] == "site":
                ok = False
            elif bound[name] == "sys":
                ok = ok and all(id(u) in safe or id(u) in consumed for u in used)
            else:
                ok = ok and all(id(u) in consumed or id(u) in safe for u in used)  # `safe`: N2 / N3 reads
        for name in from_sys:
            if not any(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load) for n in ast.walk(tree)):
                ok = False
        if not ok:
            refuse(stmt, binding=True)
    found.sort()
    seen: set[tuple[int, str]] = set()
    out: list[tuple[int, str]] = []
    for _, line, _, seg in found:  # a node reached by two walks (a chain top and its name) is one occurrence
        if (line, seg) not in seen:
            seen.add((line, seg))
            out.append((line, seg))
    return out


def tracked_paths(repo: Path, revision: str | None, environment: dict) -> dict[str, str]:
    """Every tracked path at the scanned revision (the index when none is pinned), with its git mode."""
    args = ["ls-tree", "-r", "-z", "--full-tree", revision] if revision else ["ls-files", "-s", "-z"]
    out = run_git(["git", "--no-replace-objects", "-C", str(repo), *args], capture_output=True, timeout=60, env=environment)
    if out.returncode:
        raise ValueError("reader scan cannot list the tracked files at the scanned revision")
    entries = {}
    for record in out.stdout.decode("utf-8", errors="replace").split("\0"):
        if record:
            meta, _, path = record.partition("\t")
            entries[path] = meta.split()[0]
    return entries


CREATE_REQUIRE_BINDING = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]+\.)?createRequire\s*\(")


# A shorthand METHOD named require/import is a definition, not a call (spine, core's vm sandboxes, 2026-10-27):
# `{ ..., require(name) { ... } }`. Its `)` is followed by `{`, and the word follows an object/class member boundary.
# `const x = require(name)\n{` (ASI) follows `=`, so it stays a call.
_MEMBER_BOUNDARY = frozenset({"{", ",", "}", ";", "*", "async", "static", "get", "set"})


def _is_shorthand_method(src: Source, j: int) -> bool:
    code = src.code
    close = src.match.get(j + 1)
    if close is None or close + 1 >= len(code) or code[close + 1][0] != "open" or code[close + 1][3] != "{":
        return False
    return j == 0 or code[j - 1][3] in _MEMBER_BOUNDARY


# A module specifier whose leading literal is a non-file: URL scheme names no repository file (spine, 2026-10-27:
# docs-site's `import(\`data:text/javascript;base64,${...}\`)`): no edge and no refusal. `file:${x}` and `${x}` refuse.
_NON_FILE_SCHEME = re.compile(r"(?:data|node|https?):")


def loader_call_opens(src: Source):
    """The index of the `(` of every call that loads or resolves a module by path: `import(`, `require(`,
    `require.resolve(`, `import.meta.resolve(`, `module.require(`, `createRequire(...)(`, and a name bound to
    `createRequire(...)` (spine's pre-review, 2026-10-27: each loads or resolves by a path the argument names)."""
    code = src.code
    bound = set(CREATE_REQUIRE_BINDING.findall(src.text))
    for j, tok in enumerate(code):
        if j + 1 >= len(code) or code[j + 1][0] != "open" or code[j + 1][3] != "(":
            continue
        word = tok[3] if tok[0] == "word" else None
        member = j >= 1 and code[j - 1][0] == "op" and code[j - 1][3] in (".", "?.")
        receiver = code[j - 2][3] if member and j >= 2 and code[j - 2][0] == "word" else None
        if word in ("import", "require") and not member:
            if not _is_shorthand_method(src, j):
                yield j + 1
        elif word == "require" and receiver == "module":
            yield j + 1  # `module.require(x)` is the loader under another name
        elif word == "resolve" and receiver == "require":
            yield j + 1
        elif word == "resolve" and receiver == "meta" and j >= 4 and code[j - 3][3] == "." and code[j - 4][3] == "import":
            yield j + 1
        elif word in bound and not member:
            yield j + 1
        elif tok[0] == "close" and tok[3] == ")":
            opener = src.opener.get(j)
            if opener is not None and opener >= 1 and code[opener - 1][0] == "word" and code[opener - 1][3] == "createRequire":
                yield j + 1  # `createRequire(import.meta.url)(x)`


def computed_import_sites(src: Source):
    """Each loader call (loader_call_opens) whose first argument is not one plain string literal:
    (expr, argument tokens, index of the first argument token in src.code).
    A string token's value is (text, plain, start): `plain` is False for a template or f-string with substitutions."""
    code = src.code
    for o in loader_call_opens(src):
        close = src.match.get(o)
        if close is None:
            yield "<unclosed>", [], o
            continue
        depth, first = 0, []
        for t in code[o + 1:close]:
            if t[0] == "open":
                depth += 1
            elif t[0] == "close":
                depth -= 1
            elif depth == 0 and t[0] == "comma":
                break  # `import("x", { with: ... })`: only the specifier decides
            first.append(t)
        if first and first[0][0] == "str" and first[0][3][1] is True and (
                len(first) == 1 or (first[1][0] == "word" and first[1][3] in ("as", "satisfies"))):
            continue  # a plain literal, also under a TypeScript cast (`import("redis" as string)` loads "redis")
        if first and first[0][0] == "str" and _NON_FILE_SCHEME.match(first[0][3][0]):
            continue  # a data:/node:/http(s): URL names no repository file
        expr = " ".join(src.text[first[0][1]:first[-1][2]].split()) if first else ""
        yield expr, first, o + 1


def scan(repo: Path, cfg: dict, *, manifest_root: Path | None = None, revision: str | None = None,
         policy_files: tuple = (), mention_revisions: tuple = (),
         report: dict | None = None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """The reader scan; at a revision, every file read goes through one `git cat-file --batch` process."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    if revision is not None and not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("reader scan revision must be an immutable commit")
    try:
        with batch_reads(repo, revision, environment):
            return _scan(repo, cfg, manifest_root=manifest_root, revision=revision, policy_files=policy_files,
                         mention_revisions=mention_revisions, report=report)
    except subprocess.TimeoutExpired as err:
        # F18 (root, 2026-10-29): a pass that runs out of time read only part of the tree, so the closure is unproven. It
        # refuses like every other unproven route (FULL), by a typed refusal, never by an uncaught exception.
        cmd = [str(x) for x in (err.cmd if isinstance(err.cmd, (list, tuple)) else [err.cmd])]
        what = next((f"git {x}" for x in cmd if x in ("grep", "ls-tree", "ls-files", "show", "cat-file")), cmd[0])
        raise ValueError(f"unresolved ({READER_TIMEOUT}: `{what}` ran over its {err.timeout:g} s limit on both attempts; "
                         "reader closure unproven)") from None


def _scan(repo: Path, cfg: dict, *, manifest_root: Path | None = None, revision: str | None = None,
          policy_files: tuple = (), mention_revisions: tuple = (),
          report: dict | None = None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
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
    # Every `<root>/`, every quoted root (also `./<root>`, `<root>/`, and a backtick string), and every `../`.
    pattern = f"({alt})[/\\\\]|[/\\\\]({alt})([^A-Za-z0-9_.-]|$)|[\"'`](\\./)*({alt})/?[\"'`]|\\.\\./"
    pattern += BARE_WORD_GREP.format(alt=alt)  # a bare root word (`pytest services`, `COPY services .`)
    excludes = [f":!{x}" for x in (es.get("exclude") or ["*.md", "docs", ".github"])]
    reader_dirs = set(es.get("reader_dirs") or [])
    # Directories that run only in `always` jobs are not scanned (always_reader_dirs, validated above all else).
    always = always_reader_dirs(es, cfg, by_dir, roots, reader_dirs)
    excludes += [f":!{name}" for name in sorted(always)]
    if (cfg.get("workspace") or {}).get("type") == "pnpm":
        # The workspace manifest DEFINES the graph (its quoted roots are package globs, not reads), and any change to
        # it already plans FULL (plan.py BUILTIN_FULL_GLOBS).
        excludes.append(":!pnpm-workspace.yaml")
    if revision is not None and not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("reader scan revision must be an immutable commit")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    # 1.5.2, root's ruling (c): a lockfile is metadata (its `link:../x` entries run nothing), so it is not read when, and
    # only when, a change to it plans FULL under THIS config (plan.classify_paths, per path). A lockfile that would
    # select less than FULL (a nested one mapped to its package) is read like any other file.
    lockfiles_dropped = set()
    for p in sorted(tracked_paths(repo, revision, environment)):
        if p.rsplit("/", 1)[-1] in LOCKFILE_NAMES and not any(c in p for c in "*?[:!"):
            selection = classify_paths([p], cfg, pkgs)
            if selection["error"] or selection["evidence"]["full_triggers"] or selection["evidence"]["unmapped"]:
                lockfiles_dropped.add(p)
                excludes.append(f":!{p}")
    if report is not None:
        report["lockfiles_not_read"] = sorted(lockfiles_dropped)
    # LC_ALL=C: under a UTF-8 locale `git grep -E` stops matching a line after an invalid UTF-8 byte, so a root mention
    # later on that line was never seen. The pattern is ASCII, so byte semantics lose nothing.
    out = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "--null", "-n", "-I", "-E", pattern,
                          *([revision] if revision else []), "--", ".", *excludes],
                         capture_output=True, timeout=15, env={**environment, "LC_ALL": "C"})
    grep_read_everything(out, "the reader scan")
    lit = re.compile(r"(?<![\w./-])(?:\.\./)*((?:" + alt + r")(?:/[A-Za-z0-9_.-]+)+)")
    rel = re.compile(r"(?<![\w.])((?:\.\./)+[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")
    globs = list(cfg.get("inert_globs") or []) + list((cfg.get("extra_edges") or {}).keys())
    classify = RootLiteral(roots, by_dir, owner, globs)
    sources: dict[str, Source] = {}
    raw_parent: dict[str, bool] = {}
    scripts_read: set = set()
    deps: dict[str, set[str]] = {n: set() for n in pkgs}
    readers: dict[str, set[str]] = {d: set() for d in reader_dirs}
    outside: dict[str, set[str]] = {}  # a scanned file outside every package -> the packages its lines read (1.5.0)
    edges: dict[str, set[str]] = {}  # a file -> the repo paths outside every package its relative paths name (1.5.0)

    shell_spans: dict[str, dict] = {}
    scan_names, scan_name_globs = unresolved_name_registry(es, own_names(repo), Path(repo).resolve().as_posix())
    scan_names_used: set = set()
    root_info: dict[str, tuple] = {}
    parent_literal_spans: dict[str, list] = {}  # a package's .py file -> the spans of its B1 sys.path literals
    # Root's B1 of the slice 3 CHANGES (dotgithub-86, 2026-11-12): every file whose PARSE set aside a sys.path entry or a
    # loader path below (its chains left to the Python evaluator) is a file import_closure's reader reads, whatever a
    # text grep for `sys\.path` lists (`sys .path`, a backslash continuation): one file set for both.
    parsed_sys_path_files: set[str] = set()

    def relative_or_root(path: str, spec: str, at: int) -> set:
        """relative_target, except that a root base whose every use joins string literals stands for exactly those
        literals (1.5.2, root's ruling b: root_base_uses); `at` is the offset of the name in the file."""
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if ext in PY_EXT and owner(path) is not None:
            # RC1A (B1): a parent-step literal sys.path entry in a package's file is relative to the process cwd, not to
            # the file, so import_closure's apply_entry reads it by its landings over every tracked directory (the
            # file's own among them) or refuses; read from the file's directory it is never a route of its own.
            if path not in parent_literal_spans:
                src = sources.get(path)
                if src is None:
                    src = sources[path] = Source(read_source(repo, path, revision, environment), ext)
                parent_literal_spans[path] = python_owned_spans(src.text, parent_literals=True)
                if parent_literal_spans[path]:
                    parsed_sys_path_files.add(path)
            if any(a <= at < b for a, b in parent_literal_spans[path]):
                return set()
        if ext in JS_EXT | PY_EXT and posixpath.normpath(posixpath.join(posixpath.dirname(path), spec)) == ".":
            if path not in root_info:
                src = sources.get(path)
                if src is None:
                    src = sources[path] = Source(read_source(repo, path, revision, environment), ext)
                root_info[path] = root_base_uses(src, path, python_owned_spans(src.text) if src.py else [])
            spans, literals, _ = root_info[path]
            if any(a <= at < b for a, b in spans):
                return set().union(set(), *(relative_target(path, x, frozenset({""})) for x in literals))
        return relative_target(path, spec)

    scan_tracked: set[str] = set()
    scan_tracked_dirs: set[str] = set()

    def names_tracked(target: str) -> bool:
        if not scan_tracked:
            scan_tracked.update(tracked_paths(repo, revision, environment))
            for t in scan_tracked:
                d = posixpath.dirname(t)
                while d and d not in scan_tracked_dirs:
                    scan_tracked_dirs.add(d)
                    d = posixpath.dirname(d)
        return target in scan_tracked or target in scan_tracked_dirs

    def relative_target(path: str, spec: str, bases=None) -> set:
        """`spec` resolved from `path`'s directory (or, for a shell line, from each directory the script may be in
        there: shell_cwd_spans): the packages that own the results, None for one recorded as an edge outside every
        package. Of several bases, the ones that name a tracked path win; when none does, all are kept, so the closure
        refuses what names nothing."""
        if bases is None:
            bases = frozenset({posixpath.dirname(path)})
        candidates = sorted({posixpath.normpath(posixpath.join(base, spec)) for base in bases})
        inside = [c for c in candidates if not c.startswith("../") and c != ".."]
        if "." in inside or not inside:
            # 1.5.2, root's rulings (a) and (b): a name above the checkout, or at its root, is an unresolved name: it
            # refuses unless edge_scan.unresolved_names declares it (unresolved_name_registry).
            entries = [declared_name(scan_names, scan_name_globs, path, c) for c in (["."] if "." in inside else candidates)]
            if not all(e for e, _ in entries):
                raise ValueError(f"unresolved ({path} names {spec}, the repository root or above it: that reaches every "
                                 "file, so no mapping of it can be narrower than FULL)")
            found = set()
            for entry, key in entries:
                scan_names_used.add(key)
                for x in entry["reach"] if isinstance(entry["reach"], list) else ():
                    found |= relative_target(path, x, frozenset({""}))
            return found
        if len(inside) > 1:
            inside = [c for c in inside if names_tracked(c)] or inside
        found = set()
        for target in inside:
            owned = owner(target)
            if owned is None:
                edges.setdefault(path, set()).add(target)
            found.add(owned)
        return found

    def shell_text(path: str) -> bool:
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if ext in ("sh", "bash"):
            return True
        if ext:
            return False
        head = read_source(repo, path, revision, environment)[:200]
        return head.startswith("#!") and re.search(r"\b(?:ba|z|da)?sh\b", head.split("\n")[0]) is not None

    def line_bases(path: str, number: int, text: str, offset: int):
        """The bases for a relative path at `offset` of a shell file's stripped line `number` (1-based). None: not a shell
        file (resolve from the file's directory). A refusal when the script's directory is unknown there."""
        if not shell_text(path):
            return None
        if path not in shell_spans:
            shell_spans[path] = shell_cwd_spans(read_source(repo, path, revision, environment), posixpath.dirname(path))
        bases = shell_bases_at(shell_spans[path], number - 1, offset)
        if bases is None:
            raise ValueError(f"unresolved (a relative path on line {number} of {path} after a `cd` the scan cannot follow: "
                             "cd to the script's own directory, `cd \"$(dirname \"$0\")/…\"`, so it resolves)")
        return bases

    def literal_read(path_text: str) -> str | None:
        found = owner(path_text)
        if found is None and not classify.beneath(posixpath.normpath(path_text)):
            classify.unowned(posixpath.normpath(path_text))  # F6, the literal form
        return found

    # Bytes decoded here, never in text mode, whose newline translation drops a CRLF file's `\r` and makes every line
    # of it mismatch the scanned revision's bytes (a refusal, L3.2).
    remaining = out.stdout.decode("utf-8", errors="replace")
    pending: list[str] = []  # the structured file whose lines are being read; its name taint runs after its last line

    def finish(done: str) -> None:
        classify.path = done
        classify.taint_check(sources[done])

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
        if pending and pending[0] != path:
            finish(pending.pop())
        parts = path.split("/")
        reader = owner(path)
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        classify.path = path
        targets = set()
        if ext in STRUCTURED:
            # The whole file's tokens decide: a construct may span lines, and a comment or string may hide a bracket.
            src = sources.get(path)
            if src is None:
                src = sources[path] = Source(read_source(repo, path, revision, environment), ext)
            if not pending:
                pending.append(path)
            line = int(number) - 1
            a, b = src.bounds(line) if line <= len(src.newlines) else (0, -1)
            if src.text[a:b] != text:
                raise ValueError(f"reader scan line {number} of {path} does not match the scanned revision")
            targets |= classify.line_reads(src, line)
            if posixpath.basename(path) == "package.json" and path not in scripts_read:
                # npm `scripts` values are shell commands: each string value is read like a line of a shell file (rule
                # 7 raw, and bare root words), once per file. npm strips one leading UTF-8 BOM, so this does too. A
                # manifest nested deeper than PACKAGE_JSON_MAX_DEPTH, or that still does not parse as strict JSON (no
                # NaN/Infinity) whose top level is an object, or whose `scripts` is present and not an object, cannot be
                # read, so it refuses rather than read nothing. Under the bound json.loads never recurses deep enough to
                # raise RecursionError.
                scripts_read.add(path)
                body = src.text.removeprefix("\ufeff")
                if json_nesting_depth(body) > PACKAGE_JSON_MAX_DEPTH:
                    classify.refuse(f"unresolved (package.json nests deeper than {PACKAGE_JSON_MAX_DEPTH} levels)")
                try:
                    manifest = json.loads(body, parse_constant=strict_json_constant)
                except ValueError:
                    manifest = None
                if not isinstance(manifest, dict):
                    classify.refuse("unresolved (package.json does not parse as a JSON object)")
                scripts = manifest.get("scripts", {})
                if not isinstance(scripts, dict):
                    classify.refuse("unresolved (package.json `scripts` is not an object)")
                for name, command in scripts.items():
                    if not isinstance(command, str):
                        continue
                    why = classify.raw_taint(command)
                    if why:
                        classify.refuse(f"unresolved (rule 7: package.json script {name!r}: {why})")
                    targets |= classify.raw_reads(command, "sh")
            for m in lit.finditer(src.text, a, b):
                if not src.in_comment(m.start()):
                    targets.add(literal_read(m.group(1)))
                    targets |= classify.literal_path(src, m.start(), m.group(1))
            for m in rel.finditer(src.text, a, b):
                if not src.in_comment(m.start()):
                    targets |= relative_or_root(path, m.group(1), m.start())
        else:
            t = text.strip()
            if t.startswith(COMMENT_PREFIXES):
                continue
            if classify.quoted.search(t) and ext != "sql":
                classify.refuse("a root literal in a file whose syntax the scanner does not parse is an unsupported")
            if ext != "sql":
                # Round 4: rule 7 for a file the tokenizer does not parse (yaml, toml, shell, Dockerfile) is raw and
                # line-level (`raw_taint`). It runs on every hit, since a `../` line after `cd services` names no root.
                if path not in raw_parent:
                    raw_parent[path] = classify.raw_taint(read_source(repo, path, revision, environment))
                if raw_parent[path]:
                    classify.refuse(f"unresolved (rule 7: {raw_parent[path]})")
            if ext != "sql" and (classify.root_any.search(t) or classify.root_word.search(t)):
                # A root segment there still READS: a walker beneath its literal prefix.
                targets |= classify.raw_reads(t, ext)
            for m in lit.finditer(t):
                targets.add(literal_read(m.group(1)))
            if shell_text(path):
                # A shell line: the self-directory form resolves from the file's own directory; every other ./ or ../
                # path from where the script is there (shell_cwd_spans). A self-directory cd's argument is not a name.
                cds = shell_cd_ranges(t)
                in_cd = lambda at: any(a <= at < b for a, b in cds)
                seen = []
                for m in SHELL_SELF_DIR.finditer(t):
                    seen.append(m.span())
                    if not in_cd(m.start()):
                        targets |= relative_target(path, "./" + m.group(1))
                for m in SHELL_RELATIVE.finditer(SHELL_SELF_DIR.sub(lambda x: " " * len(x.group(0)), t)):
                    seen.append(m.span())
                    if not in_cd(m.start()):
                        targets |= relative_target(path, m.group(1), line_bases(path, int(number), t, m.start()))
                # A `../` after a computed prefix (`"$d/../../packages/shared"`) is neither form: as for any other file
                # it resolves from the file's own directory, so a route that names nothing refuses (D5, R5V14).
                for m in rel.finditer(t):
                    if not in_cd(m.start()) and not any(a <= m.start() < b for a, b in seen):
                        targets |= relative_target(path, m.group(1))
            else:
                for m in rel.finditer(t):
                    targets |= relative_target(path, m.group(1))
        if reader is None:
            outside.setdefault(path, set()).update(targets - {None})
        for target in targets - {None, reader}:
            if reader:
                deps[reader].add(target)
            elif parts[0] in reader_dirs:
                readers[parts[0]].add(target)
            else:
                readers.setdefault("<unmapped>", set()).add(target)
    if pending:
        finish(pending.pop())
    # 1.5.2: every shell file, whole. The grep returns only lines naming a root or a `../`, so a `./x.sh` after a
    # `cd "$(dirname "$0")/../../b"` was never read, and a relative path after a `cd` the scan cannot follow would pass
    # unseen. Each such path resolves where the script is (shell_cwd_spans), or refuses; credits as the loop above.
    # `git grep -l` lists them in both modes: `ls-tree` supports neither a glob nor the `:!` excludes (exit 128).
    listing = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-e", "",
                              *([revision] if revision else []), "--", "*.sh", "*.bash", *excludes],
                             capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    grep_read_everything(listing, "the reader scan's shell listing")
    names = [p[len(revision) + 1:] if revision else p for p in listing.stdout.decode("utf-8", errors="replace").split("\0") if p]
    for path in sorted(names):
        reader, parts, targets = owner(path), path.split("/"), set()
        text = read_source(repo, path, revision, environment)
        spans = shell_cwd_spans(text, posixpath.dirname(path))
        for i, line in enumerate(text.split("\n")):
            t = line.strip()
            if t.startswith("#") or (spans.get(i) and spans[i][0][2] is not None and "/" not in t):
                continue
            cds = shell_cd_ranges(t)
            for m in SHELL_SELF_DIR.finditer(t):
                if not any(a <= m.start() < b for a, b in cds):
                    targets |= relative_target(path, "./" + m.group(1))
            for m in SHELL_RELATIVE.finditer(SHELL_SELF_DIR.sub(lambda x: " " * len(x.group(0)), t)):
                if any(a <= m.start() < b for a, b in cds):
                    continue
                bases = shell_bases_at(spans, i, m.start())
                if bases is None:
                    raise ValueError(f"unresolved (a relative path on line {i + 1} of {path} after a `cd` the scan cannot "
                                     "follow: cd to the script's own directory, `cd \"$(dirname \"$0\")/…\"`, so it resolves)")
                targets |= relative_target(path, m.group(1), bases)
        if reader is None:
            outside.setdefault(path, set()).update(targets - {None})
        for target in targets - {None, reader}:
            if reader:
                deps[reader].add(target)
            elif parts[0] in reader_dirs:
                readers[parts[0]].add(target)
            else:
                readers.setdefault("<unmapped>", set()).add(target)
    # Round 3 of #33, B2: `".."` segment chains are parent steps everywhere. Every code file with a quoted ".." or a
    # .parent step is read whole for chains anchored at its directory (anchored_chains); each resolves like the same
    # relative path written out, so one that reaches the repository root or above refuses, and the rest are routes.
    listing = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                              r"""["']\.\.["']|\.parents?([^A-Za-z0-9_]|$)""", *([revision] if revision else []), "--",
                              *[f"*.{e}" for e in sorted(JS_EXT | PY_EXT)], *excludes],
                             capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    grep_read_everything(listing, "the reader scan")
    for path in sorted(x[len(revision) + 1:] if revision else x
                       for x in listing.stdout.decode("utf-8", errors="replace").split("\0") if x):
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if path not in sources:
            sources[path] = Source(read_source(repo, path, revision, environment), ext)
        sites = anchored_chain_sites(sources[path])
        if sources[path].py and sites:
            # A chain inside a sys.path entry or a loader path is 1.5.2's Python evaluator's to judge (it credits what is
            # imported by name, or floors an unevaluated loader path), never a directory route of its own.
            owned = python_owned_spans(sources[path].text)
            if owned:
                parsed_sys_path_files.add(path)
            sites = [x for x in sites if not any(a <= sources[path].code[x[1]][1] < b for a, b in owned)]
        if not sites:
            continue
        reader, parts = owner(path), path.split("/")
        targets = set().union(set(), *(relative_or_root(path, spec, sources[path].code[s][1]) for spec, s, _ in sites))
        if reader is None:
            outside.setdefault(path, set()).update(targets - {None})
        for target in targets - {None, reader}:
            if reader:
                deps[reader].add(target)
            elif parts[0] in reader_dirs:
                readers[parts[0]].add(target)
            else:
                readers.setdefault("<unmapped>", set()).add(target)
    unowned: dict[str, dict] = {}
    imports, unused, unresolved_data, unit_imports, stood_for, routes_to = import_closure(
        repo, es, roots, owner, by_dir, revision, environment, excludes, always, edges, outside, deps, readers, unowned,
        names_used_before=scan_names_used, parsed_files=frozenset(parsed_sys_path_files))
    # Root's ruling on the backstop's consequence (2026-10-29): mentions over BASE ∪ HEAD, so a mention the PR adds
    # flags, and so does one it removes. The base tree is data like the head: it can only add FULL paths. A file the PR
    # did not change has the same text at both ends, so the base pass reads only the deleted and modified ones (D/M/T,
    # with renames as D+A), from `base_repo` (the action's sparse base checkout: a blobless candidate has no base blobs).
    # The SUBJECTS are the union of both trees (trees need no blobs): a P the PR deletes or moves stays one.
    base_tracked: dict[str, str] = {}
    base_passes = []
    for base_repo, extra in mention_revisions:
        if not re.fullmatch(r"[0-9a-f]{40}", extra):
            raise ValueError("reader scan base revision must be an immutable commit")
        if run_git(["git", "--no-replace-objects", "-C", str(repo), "cat-file", "-e", f"{extra}^{{commit}}"],
                          capture_output=True, timeout=15, env=environment).returncode:
            raise ValueError(f"reader scan cannot read the base revision {extra}: its mentions could not be counted")
        base_tracked.update(tracked_paths(repo, extra, environment))
        diff = run_git(["git", "--no-replace-objects", "-C", str(repo), "diff", "--name-only", "-z", "--no-renames",
                               "--diff-filter=DMT", extra, *([revision] if revision else []), "--"],
                              capture_output=True, timeout=60, env=environment)
        if diff.returncode:
            raise ValueError(f"reader scan cannot diff the base revision {extra} against the candidate")
        base_passes.append((Path(base_repo), extra, sorted(x for x in diff.stdout.decode("utf-8", errors="surrogateescape")
                                                          .split("\0") if x)))
    unread = set(policy_files) | lockfiles_dropped  # 1.5.2, ruling (c): a dropped lockfile names nothing either
    mentions = basename_mentions(repo, cfg, owner, revision, environment, routes_to, unread,
                                 other_tracked=base_tracked or None)
    head_tracked = tracked_paths(repo, revision, environment) if base_passes else {}
    for base_repo, extra, changed in base_passes:
        if run_git(["git", "--no-replace-objects", "-C", str(base_repo), "cat-file", "-e", f"{extra}^{{commit}}"],
                          capture_output=True, timeout=15, env=environment).returncode:
            raise ValueError(f"reader scan cannot read the base revision {extra} in {base_repo}")
        for p, rows in basename_mentions(base_repo, cfg, owner, extra, environment, routes_to, unread,
                                         other_tracked=head_tracked, only_paths=changed).items():
            have = {(r[0], r[3]) for r in mentions.setdefault(p, [])}
            mentions[p].extend(r for r in rows if (r[0], r[3]) not in have)
            mentions[p].sort()
    if report is not None:
        report["imports"] = {path: sorted(found) for path, found in sorted(imports.items())}
        report["unit_imports"] = {path: sorted(found) for path, found in sorted(unit_imports.items())}
        report["untracked_names_stand_for"] = {name: sorted(dirs) for name, dirs in sorted(stood_for.items())}
        report["mentions"] = mentions
        report["unowned_callers"] = {path: {"unit": row["unit"], "reaches": sorted(row["reaches"])}
                                     for path, row in sorted(unowned.items())}
        report["computed_imports_unused"] = unused
        report["unresolved_data_names"] = unresolved_data
    return deps, readers


def code_imported_test_files(repo, revision, environment, tracked) -> set[str]:
    """Root's ruling (b) of 2026-11-14 17:58 on the R6-2 fix (3): `plan.is_test_file` is a path regex, so a production
    helper named `test_utils.py`, or anything under a `tests/` directory, passes it by name alone. The test files a
    non-test Python file may import lose the F3 reads. cli's read of 7001655 (MF5): the importers come from the AST,
    not from lines, so a multi-line `from services.b import (\n    test_utils,\n)` and a literal fed to
    `importlib.import_module` on another line are seen. Every tracked non-test Python file is parsed, and every
    identifier and every string or bytes literal word in it (an import's names, an attribute, a loop literal, a path)
    that is a test file's module word (its stem; its directory's name for an `__init__.py`) marks every test file of
    that word; a marked file's own words mark further test files, to a fixed point. A file that does not parse
    counts every word of its text. This is a word, not a resolved import: it marks more than Python would import,
    never less, short of a name the source computes (`"test_" + "utils"`, which the reader's own loader rules refuse)
    and an importer outside Python (a workflow's `python -m`, an entry point). A test file whose name is no
    identifier is marked outright."""
    import ast

    words: dict[str, set[str]] = {}
    marked: set[str] = set()
    for p in tracked:
        if p.endswith(".py") and _plan.is_test_file(p, []):
            stem = posixpath.basename(p)[:-3]
            word = posixpath.basename(posixpath.dirname(p)) if stem == "__init__" else stem
            if re.fullmatch(r"[A-Za-z_]\w*", word):
                words.setdefault(word, set()).add(p)
            else:
                marked.add(p)
    if not words:
        return marked

    def words_of(p: str) -> set[str]:
        text = read_source(repo, p, revision, environment)
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return set(re.findall(r"[A-Za-z_]\w*", text)) & words.keys()
        found: set[str] = set()
        for node in ast.walk(tree):
            for _, value in ast.iter_fields(node):
                if isinstance(value, bytes):
                    value = value.decode("latin-1")
                if isinstance(value, str):
                    found.update(re.findall(r"[A-Za-z_]\w*", value))
        return found & words.keys()

    frontier = sorted((p for p in tracked if p.endswith(".py") and not _plan.is_test_file(p, [])), reverse=True)
    while frontier:
        for word in sorted(words_of(frontier.pop())):
            for hit in sorted(words[word] - marked):
                marked.add(hit)
                frontier.append(hit)
    return marked


def import_closure(repo, es, roots, owner, by_dir, revision, environment, excludes, always, edges, outside, deps,
                   readers, unowned, names_used_before=frozenset(), parsed_files=frozenset()):
    """Rules 1-4 of 1.5.0: credit each package with the reads of the files outside every package it reaches. Returns
    ({path: importing packages}, [computed_imports entries that matched no site]); refuses where it cannot see."""
    tracked = tracked_paths(repo, revision, environment)
    package_tops = {d.split("/")[0] for d in by_dir} | set(roots)
    code_imported: list[set[str]] = []  # root's ruling (b) of 2026-11-14: computed once, on the first test file parsed

    def test_only(path: str) -> bool:
        if not code_imported:
            code_imported.append(code_imported_test_files(repo, revision, environment, tracked))
        return path not in code_imported[0]
    # Top-level directories outside every package: the tracked ones, and every declared reader directory.
    outside_tops = ({p.split("/")[0] for p in tracked if "/" in p} | set(es.get("reader_dirs") or [])) - package_tops
    # F1 (root, 2026-11-12): a PACKAGE top too (`packages/shared` holds a package but is not a scan root), else an
    # unevaluable entry into another package's directory read as a residual while its module was imported from it.
    named_tops = outside_tops | package_tops  # what an unevaluated path may not name (rule 6)
    # A trailing slash names a directory, exactly as git's pathspec reads `:!vendor/` (root's R4 of #33): strip it.
    patterns = [x[2:].rstrip("/") if not any(c in x for c in "*?[") else x[2:] for x in excludes if x.startswith(":!")]

    def excluded(path: str) -> bool:
        # git pathspec without magic: a wildcard pattern matches the whole path (`*` crosses `/`); a plain one matches
        # the path or anything beneath it.
        return any(fnmatch.fnmatchcase(path, p) if any(c in p for c in "*?[") else path == p or path.startswith(p + "/")
                   for p in patterns)

    def resolve_links(path: str) -> str:
        for _ in range(40):
            parts = path.split("/")
            for k in range(1, len(parts) + 1):
                prefix = "/".join(parts[:k])
                if tracked.get(prefix) == "120000":
                    link = (read_source(repo, prefix, revision, environment) if revision
                            else os.readlink(repo / prefix))
                    path = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), link.strip(), *parts[k:]))
                    break
            else:
                return path
        raise ValueError(f"unresolved (a symlink loop) at {path}")

    def files_of(target: str) -> list[str]:
        """The tracked files a reached path names, or [] when it names none (the caller then maps or refuses it; a
        dropped name lost every test run its importers had, root's R4 of #33, 2026-10-27)."""
        target = resolve_links(target)
        stem, ext = posixpath.splitext(target)
        found = ([target] if target in tracked else []) + [
            resolve_links(stem + alt) for alt in TS_SOURCES.get(ext, ()) if resolve_links(stem + alt) in tracked]
        if found:
            return found  # both, when a .js file and its .ts source are tracked: the over-approximation is the safe one
        # An extensionless module specifier resolves the way Node and Python do (`require("../x")` is x.js, x.ts, ...).
        # A directory (x/index.js included) is every tracked file beneath it, which only over-approximates.
        for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".jsx", ".json", ".py"):
            if resolve_links(target + suffix) in tracked:
                return [resolve_links(target + suffix)]
        beneath = [p for p in tracked if p.startswith(target + "/")]
        return sorted(beneath)  # a path that is no tracked file or directory names nothing

    package_dir = {name: d for d, name in by_dir.items()}

    def steps_up(text: str) -> bool:
        return bool(PARENT_STEP.search(text)) or text.strip() == ".."

    call_args = source_call_args

    def parent_verdict(path: str, src: Source, tokens: list, at: int) -> tuple[str, str | None]:
        """Rule 4's floor, refined in spine's pre-review (2026-10-27): ("literal", target) for an all-literal path the
        file's own directory anchors; ("inside", None) for a parent step that stays in the LEADING literal prefix and
        resolves inside the importing package's own directory (allowed only under a reach "package" declaration);
        ("escape", None) for any other parent step, or a literal naming a top-level directory outside every package
        where nothing anchors it; ("none", None) otherwise."""
        own = package_dir.get(owner(path))
        here = posixpath.dirname(path)

        def inside(target: str) -> bool:
            return own is not None and (target == own or target.startswith(own + "/"))

        def steps_up_word(j: int) -> bool:
            """A parent step spelled as a word (root's R4 of #33, fix 3): `pardir`, `.parent`/`.parents`, and every
            `dirname(...)` except the file's own directory, `dirname(fileURLToPath(import.meta.url))`, `dirname(__filename)`
            and the like, which is the anchor. So `dirname(dirname(__dirname))` steps up twice."""
            t = tokens[j]
            if t[0] != "word" or t[3] not in PARENT_WORDS:
                return False
            if t[3] == "pardir":
                return True
            if t[3] in ("parent", "parents"):
                return j > 0 and tokens[j - 1][0] == "op" and tokens[j - 1][3] in (".", "?.")
            if j + 1 >= len(tokens) or tokens[j + 1][0] != "open":
                return False
            c = src.match.get(at + j + 1)
            inner = [x[3] for x in tokens[j + 2:c - at]] if c is not None else None
            if inner and len(inner) >= 2 and inner[1] == "." and inner[0] in ("path", "url", "posix"):
                inner = inner[2:]
            return inner not in (["fileURLToPath", "(", "import", ".", "meta", ".", "url", ")"], ["__filename"],
                                 ["import", ".", "meta", ".", "filename"], ["__file__"])

        pardir = any(steps_up_word(j) for j in range(len(tokens)))
        # Unwrap `pathToFileURL(<chain>).href` / `.pathname`, the usual way an anchored path reaches import().
        k = 2 if len(tokens) >= 3 and tokens[1][0] == "op" and tokens[1][3] == "." and tokens[0][0] == "word" else 0
        if len(tokens) > k + 1 and tokens[k][0] == "word" and tokens[k][3] == "pathToFileURL" and tokens[k + 1][0] == "open":
            c = src.match.get(at + k + 1)
            tail = [t[3] for t in tokens[c - at + 1:]] if c is not None else None
            if tail in ([".", "href"], [".", "pathname"]):
                return parent_verdict(path, src, tokens[k + 2:c - at], at + k + 2)
        # A relative specifier: a template or string led by ./ or ../, maybe followed by `+` concatenation.
        if tokens and tokens[0][0] == "str" and tokens[0][3][0].startswith(("./", "../")):
            text, plain = tokens[0][3][0], tokens[0][3][1] is True
            prefix = text if plain or "${" not in text else text[:text.index("${")]
            later = ([] if plain else [text[len(prefix):]]) + [t[3][0] for t in tokens[1:] if t[0] == "str"]
            if pardir or any(steps_up(x) for x in later):
                return "escape", None  # a parent step after the first substitution
            if not steps_up(prefix):
                return "none", None
            return ("inside", None) if inside(posixpath.normpath(posixpath.join(here, prefix))) else ("escape", None)
        # A path chain anchored at the file's own directory: [path.](join|resolve)(<anchor>, <literal>..., <rest>...).
        k = 2 if len(tokens) >= 3 and tokens[1][0] == "op" and tokens[1][3] == "." and tokens[0][0] == "word" else 0
        if len(tokens) > k + 1 and tokens[k][0] == "word" and tokens[k][3] in ("join", "resolve") and tokens[k + 1][0] == "open":
            args = call_args(src, at + k + 1)
            c = src.match.get(at + k + 1)
            anchors = {"__dirname"} | set(re.findall(
                r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]+\.)?dirname\(\s*(?:[\w$]+\.)?fileURLToPath\(\s*"
                r"import\.meta\.url\s*\)\s*\)", src.text))
            first = args[0] if args else []
            dirname_word = [t[3] for t in first] == ["import", ".", "meta", ".", "dirname"]
            if (len(first) == 1 and first[0][0] == "word" and first[0][3] in anchors) or dirname_word:
                rest, lits = args[1:], []
                while rest and len(rest[0]) == 1 and rest[0][0][0] == "str" and rest[0][0][3][1] is True:
                    lits.append(rest.pop(0)[0][3][0])
                if any(x.startswith("/") for x in lits) or pardir or any(
                        t[0] == "str" and steps_up(t[3][0]) for arg in rest for t in arg):
                    return "escape", None  # an absolute segment, or a parent step after the first non-literal
                target = posixpath.normpath(posixpath.join(here, *lits))
                if c is not None and any(t[0] == "str" and steps_up(t[3][0]) for t in tokens[c - at + 1:]):
                    return "escape", None  # a parent step after the chain's closing bracket (fix 3)
                if not rest and c == at + len(tokens) - 1:
                    return "literal", target  # every component literal: a literal import, resolved and mapped
                if not any(steps_up(x) for x in lits):
                    return "none", None
                return ("inside", None) if inside(target) else ("escape", None)
        # Nothing anchors it at the file: any parent step escapes, and so does naming an outside top-level directory.
        if pardir or any(t[0] == "str" and steps_up(t[3][0]) for t in tokens):
            return "escape", None
        # A leading "/" is stripped too (root's delta R4 of #33, N2): `process.cwd() + "/scripts/x.mjs"` names scripts/.
        # A caller OUTSIDE every package has no package to leave (38bb7f5's Python rule, here for JS; spine's
        # FALSE-POSITIVES item 4, e2e/adr179/journeys.mjs:389): for it a literal naming another top-level directory is a
        # load to declare, with its reach, not an escape. A parent step still escapes, for every caller.
        if own is not None and any(t[0] == "str" and re.sub(r"^(?:\./|/|\$\{[^}]*\}/)+", "", t[3][0]).split("/")[0]
                                   in outside_tops for t in tokens):
            return "escape", None
        return "none", None

    declared = es.get("computed_imports")
    if declared is None:
        declared = []
    if not isinstance(declared, list) or any(
            not isinstance(d, dict) or set(d) != {"file", "expr", "reach", "reason", "review_by"} or not isinstance(d["file"], str)
            or not isinstance(d["expr"], str)
            or not (d["reach"] in COMPUTED_REACH if isinstance(d["reach"], str) else
                    isinstance(d["reach"], list) and d["reach"] and all(isinstance(x, str) and x for x in d["reach"]))
            for d in declared):
        raise ValueError("edge_scan.computed_imports entries must be {file, expr, reach, reason, review_by}, with reach "
                         "package, external, fixture or a non-empty list of repo paths")
    reviewed("computed_imports", declared, "expr")
    by_site = {(d["file"], " ".join(d["expr"].split())): d for d in declared}
    # A name that resolves to no tracked file or directory is an UNRESOLVED ROUTE, in any position (root's delta R4 of
    # #33, D5): `timeout 300 node ../dist/x.js`, a heredoc, a fork/Worker/spawn argument and a test datum all read alike
    # to a scan that cannot run them. It refuses unless declared: {file, name, reach}, `name` the repo path it resolves
    # to, `reach` "none" (it names nothing that runs: a test datum) or the tracked paths it stands for (each an edge).
    by_name, name_globs = unresolved_name_registry(es, own_names(repo), Path(repo).resolve().as_posix())
    names_used: set = set()
    loader_targets: set[str] = set()  # every target a loader call names (reaches): a module position by construction
    reader_dirs = set(es.get("reader_dirs") or [])

    def unit_of(path: str) -> str:
        top = path.split("/")[0]
        return top if "/" in path and top in reader_dirs else "<unmapped>"

    def credit_package(path: str, caller: str | None, found: str) -> None:
        """A load by `path` (owned by `caller`) of package `found`. A caller outside every package maps to its own
        selection unit, its reader directory's job or <unmapped> (FULL), never a free-floating key (spine, fix 2)."""
        if caller is None:
            unit = unit_of(path)
            readers.setdefault(unit, set()).add(found)
            unowned.setdefault(path, {"unit": unit, "reaches": set()})["reaches"].add(found)
        elif found != caller:
            deps[caller].add(found)

    def credit_load(path: str, caller: str | None, target: str) -> None:
        """Root's R4 of #33: a loaded path is a module position (fix 1), and a caller outside every package keys the
        edge by its own path, so every package that reaches it is credited with the target (fix 2)."""
        loader_targets.add(target)
        found = owner(target)
        if caller is None or found is None:
            edges.setdefault(path, set()).add(target)
        if found is not None:
            credit_package(path, caller, found)
    used: set = set()
    sources: dict[str, Source] = {}

    def code_source(path: str) -> Source | None:
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if ext not in JS_EXT | PY_EXT:
            return None
        if path not in sources:
            sources[path] = Source(read_source(repo, path, revision, environment), ext)
        return sources[path]

    def check_computed(path: str) -> None:
        src = code_source(path)
        if src is None or src.ext not in JS_EXT:
            return
        if not src.ok:
            raise ValueError(f"unresolved (the bracket structure of {path} cannot be trusted, so its import calls cannot "
                             "be read)")
        # ONE owner() result decides both the credit below and the reach "package" floor (spine, fix 2 with fix 4).
        caller = owner(path)

        def reaches(target: str) -> None:
            credit_load(path, caller, target)

        for expr, tokens, at in computed_import_sites(src):
            verdict, target = parent_verdict(path, src, tokens, at)
            if verdict == "literal":
                reaches(target)  # an all-literal anchored path is a literal import: no declaration needed
                continue
            if verdict == "escape":
                raise ValueError(f"unresolved (a computed import that steps outside its package: `{expr}`) in {path}; "
                                 "write it as a literal path, which the scan maps")
            entry = by_site.get((path, expr))
            if entry is None:
                raise ValueError(f"unresolved (an undeclared computed import `{expr}`; declare it in "
                                 f"edge_scan.computed_imports) in {path}")
            if entry["reach"] == "package" and caller is None:
                raise ValueError(f"unresolved (`{expr}` is declared reach \"package\", but {path} is outside every "
                                 "package, where that names and credits nothing; declare the paths it loads)")
            if verdict == "inside" and entry["reach"] != "package":
                raise ValueError(f"unresolved (a computed import whose parent step stays in its package, `{expr}`, must be "
                                 f"declared reach \"package\") in {path}")
            used.add((path, expr))
            # Root's C1 of #84's second delta R4 (2026-11-12), the JS twin of rule 8's landing credit: the package a
            # literal of the expression lands in (import(`${source}/packages/shared/m.mjs`), the leading `./`, `/` and
            # substitutions stripped as parent_verdict strips them) is credited whatever the reach says; declared
            # "external" it read nothing. The reach list adds, never replaces.
            for found in sorted({owner(posixpath.normpath(re.sub(r"^(?:\./|/|\$\{[^}]*\}/)+", "", t[3][0])))
                                 for t in tokens if t[0] == "str"} - {None, caller}):
                credit_package(path, caller, found)
            if isinstance(entry["reach"], list):
                for target in entry["reach"]:
                    reaches(posixpath.normpath(target))

    # Every computed import in tracked code, a package's or not (fix 2): a dedicated grep, since such a line names no
    # root and no `../`.
    out = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                          IMPORT_CALL_GREP, *([revision] if revision else []), "--",
                          *[f"*.{e}" for e in sorted(JS_EXT)], *excludes],
                         capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    grep_read_everything(out, "the reader scan")
    for path in out.stdout.decode("utf-8", errors="replace").split("\0"):
        if path and revision:
            path = path[len(revision) + 1:]
        if path:
            check_computed(path)  # a file outside every package too: its unit runs it, so its loads select that unit

    def named_paths(path: str) -> set[str]:
        """Rule 1, the whole file: every relative path a reached code file names."""
        here, found = posixpath.dirname(path), set()
        src = code_source(path)
        if src is not None:
            if not src.ok:
                raise ValueError(f"unresolved (the bracket structure of {path}, a file a package reaches, cannot be "
                                 "trusted)")
            roots_resolved = None
            for t in src.code:
                if t[0] != "str" or not t[3][0].startswith(("./", "../")):
                    continue
                if t[3][1] is True and not (src.py and PERCENT_RE.search(t[3][0])):
                    named_one = posixpath.normpath(posixpath.join(here, t[3][0]))
                    if named_one == ".":
                        # 1.5.2, root's ruling (b): a root base joined only with literals stands for those literals.
                        if roots_resolved is None:
                            roots_resolved = root_base_uses(src, path, python_owned_spans(src.text) if src.py else [])
                        if any(a <= t[1] < b for a, b in roots_resolved[0]):
                            found.update(roots_resolved[1])
                            continue
                    found.add(named_one)
                    continue
                # Round 3 of #33, F03: a relative TEMPLATE (`./w-${n}.mjs`) stands for every tracked file it can spell: each
                # substitution is any name, so it is a glob. A parent step after a substitution, or a template that
                # spells no tracked file, refuses.
                text = t[3][0]
                # A Python `"../%s" % p` is a template too (root's G12 of #84, 2026-11-12): a %-field is any name.
                pattern = re.sub(r"\{[^{}]*\}|" + PERCENT_FIELD, "*", text) if src.py else re.sub(r"\$\{[^{}]*\}", "*", text)
                if "*" not in pattern:
                    continue
                if any(steps_up(x) for x in pattern[pattern.index("*"):].split("/")):
                    raise ValueError(f"unresolved ({path} names {text}, a template with a parent step after a substitution: "
                                     "it may reach any file)")
                glob = posixpath.normpath(posixpath.join(here, pattern))
                if glob in (".", "..") or glob.startswith("../"):
                    raise ValueError(f"unresolved ({path} names {text}, the repository root or above it: that reaches every "
                                     "file, so no mapping of it can be narrower than FULL)")
                hits = [p for p in tracked if fnmatch.fnmatchcase(p, glob)]
                if not hits:
                    raise ValueError(f"unresolved ({path} names {text}, a template that spells no tracked file: it may stand "
                                     "for anything; write the path out, or declare the load in edge_scan.computed_imports)")
                found.update(hits)
            if src.py:
                _, loaded, sites = python_file_facts(src.text, path, test_only)
                check_python_sites(path, sites)
                for name in sorted(loaded):
                    sibling = posixpath.join(here, f"{name}.py") if here else f"{name}.py"
                    if sibling in tracked:
                        found.add(sibling)
                for m in PY_IMPORT.finditer(src.text):
                    for name in re.split(r"\s*,\s*", m.group(1) or m.group(2)):
                        sibling = posixpath.join(here, f"{name}.py") if here else f"{name}.py"
                        if sibling in tracked:
                            found.add(sibling)
            check_computed(path)
            return found
        return shell_names(path)

    def shell_names(path: str) -> set[str]:
        """Every relative path a reached shell file names, resolved where the script is when it runs that line
        (shell_cwd_spans): from its own directory, then from each directory a self-directory `cd` adds. Of several
        bases, the ones that name a tracked path win. After a `cd` the scan cannot follow, a relative path refuses."""
        here, found = posixpath.dirname(path), set()
        text = read_source(repo, path, revision, environment)
        spans = shell_cwd_spans(text, here)
        for i, line in enumerate(text.split("\n")):
            t = line.strip()
            if t.startswith("#"):
                continue
            cds = shell_cd_ranges(t)
            in_cd = lambda at: any(a <= at < b for a, b in cds)
            for m in SHELL_SELF_DIR.finditer(t):
                if not in_cd(m.start()):
                    found.add(posixpath.normpath(posixpath.join(here, "./" + m.group(1))))
            for m in SHELL_RELATIVE.finditer(SHELL_SELF_DIR.sub(lambda x: " " * len(x.group(0)), t)):
                if in_cd(m.start()):
                    continue
                bases = shell_bases_at(spans, i, m.start())
                if bases is None:
                    raise ValueError(f"unresolved (a relative path on line {i + 1} of {path} after a `cd` the scan cannot "
                                     "follow: cd to the script's own directory so it resolves)")
                candidates = sorted({posixpath.normpath(posixpath.join(b, m.group(1))) for b in bases})
                if len(candidates) > 1:
                    candidates = [c for c in candidates if c in tracked or c in tracked_dirs] or candidates
                found.update(candidates)
        return found

    def is_code(path: str) -> bool:
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if ext in CODE_EXT:
            return True
        if ext:
            return False
        head = read_source(repo, path, revision, environment)[:200]
        return head.startswith("#!") and re.search(r"\b(?:ba|z|da)?sh\b|\bnode\b|\bpython", head.split("\n")[0]) is not None

    # 1.5.2: a package's Python import path (sys.path entries, its pytest `pythonpath`) and its Python loaders by name or
    # path (python_file_facts), before the closure walks the edges.
    def reach_from(path: str, target: str) -> None:
        credit_load(path, owner(path), target)  # the same credit as a JS loader's (fix 1 and fix 2)

    # The JS strip (parent_verdict) for an unevaluable Python literal: what may stand before its top-level name, in
    # any number and order. "./", "/" (`str(x) + "/packages/shared"`), a substitution (`f"{source}/packages/shared"`,
    # `${x}/`, `{{x}}/`), a %-format field (`"%s/packages/shared" % x`, `%(root)s/`, with any flags, width or
    # precision: `"%-10s/..."`, root's S04) or a bare environment variable (`os.path.expandvars("$ROOT/packages/shared")`):
    # F1's four forms and root's C1 of #84 (2026-11-12).
    LEADING = re.compile(r"^(?:\./|/|\{+[^{}]*\}+/|\$\{[^}]*\}/|" + PERCENT_FIELD + r"/|\$[A-Za-z_]\w*/)+")
    QUOTED = re.compile(r"""["']([^"']*)["']""")
    SEP_SUBST = re.compile(r"\{(?:os\.|os\.path\.)?sep\}")  # `{os.sep}` in an f-string spells a separator (root's S05)

    def collapse_braces(expr: str) -> str:
        """`expr` with every outermost `{...}` collapsed to `{}`, however deep the braces nest: a regex pass collapses one
        level, so `f"{d[f'{k}']}/packages/shared"` kept a quote inside the substitution (root's S01 of #84, 2026-11-12)."""
        out, depth = [], 0
        for ch in expr:
            if ch == "{":
                if depth == 0:
                    out.append("{}")
                depth += 1
            elif ch == "}" and depth:
                depth -= 1
            elif depth == 0:
                out.append(ch)
        return "".join(out)

    def escape_tops(expr: str) -> tuple[bool, set[str]]:
        """Whether a parent step stands in the expression, and every literal of it that names a top-level directory
        (rule 6): read as written AND stripped of LEADING, since a tracked top literally named `{tpl}` or `${tpl}` is
        named only by the unstripped form (root's B1 of #84: the strip must not hide it). A substitution with quotes
        inside (`f"{d['root']}/packages/shared"`) splits the quote regex, so the literals of the expression with every
        `{...}` collapsed to `{}` (nested braces included) are read too and unioned; `{os.sep}` reads as `/`."""
        expr = SEP_SUBST.sub("/", expr)
        collapsed = collapse_braces(expr)
        literals = set(QUOTED.findall(expr)) | set(QUOTED.findall(collapsed))
        landings = {form for s in literals for form in (s, LEADING.sub("", s)) if form.split("/")[0] in named_tops}
        return PARENT_STEP.search(expr) is not None, landings

    def escapes_by_text(expr: str, unowned_caller: bool = False) -> bool:
        """A parent step always escapes. A literal naming another top-level directory escapes a PACKAGE; a caller
        outside every package has no package to leave, so for it that is a load to declare, not an escape."""
        parent, landings = escape_tops(expr)
        return parent or (not unowned_caller and bool(landings))

    def check_python_sites(path: str, sites) -> None:
        """Rule 4 for Python's loaders: an evaluated path is a literal load; anything else is declared or refuses."""
        for kind, expr, target, prefix, text in sites:
            if kind == "path" and target is not None:
                if not (target == ".." or target.startswith("../")):
                    reach_from(path, target)
                continue
            own = package_dir.get(owner(path)) if owner(path) else None
            inside = prefix is not None and own is not None and not prefix[1] and (prefix[0] == own or prefix[0].startswith(own + "/"))
            # A prefix inside ANOTHER package loads that package's modules: declarable, and a dep on it (billing's
            # `plane_app / (name + ".py")`). Only a prefix outside every package, or a parent step after it, escapes.
            other = owner(prefix[0]) if prefix is not None and not prefix[1] and not inside else None
            # A caller outside every package (#33's fix 2 scans it) loading a path outside every package leaves no
            # package: declarable, its reach named as paths (fix 4 refuses reach "package" there). A parent step after
            # the prefix still escapes (spine's A2 census, 2026-10-28).
            unowned_caller = owner(path) is None
            # ...but only into a package-FREE subtree: a prefix with a package beneath it (the repo root, services/)
            # lets a computed tail reach any of them, so it still escapes.
            free = prefix is not None and not any(d == prefix[0] or d.startswith(prefix[0].rstrip("/") + "/") or prefix[0] in (".", "")
                                                  for d in package_dir.values())
            if kind == "path" and prefix is not None and not inside and other is None and (prefix[1] or not unowned_caller or not free):
                raise ValueError(f"unresolved (a computed Python load that may leave its package, `{expr}`) in {path}; "
                                 "write it from __file__ with literal parts, which the scan maps")
            if kind == "path" and prefix is None:
                # Nothing evaluates, so the text decides. A parent step escapes; so does a literal naming a scan root
                # or a top-level directory outside every package (as 1.7.5 refused). A literal landing INSIDE another
                # package (`f"{source}/packages/shared/mod.py"`, F1) is rule 8's load into another package, declarable
                # like an evaluated prefix there, so its declaration is honoured first (root's B3 of #84, 2026-11-12);
                # undeclared, or landing in the caller's own package or on a package-free top, it refuses as before.
                # The literals are read through the names, as rule 6 reads them (`text`, root's B2 of #84's second
                # delta R4): `p = f"{source}/packages/shared/m.py"; runpy.run_path(p)` lands in shared.
                parent, landings = escape_tops(text)
                declarable = (path, expr) in by_site and all(owner(x) not in (None, owner(path)) for x in landings)
                if parent or (not unowned_caller and landings and not declarable):
                    raise ValueError(f"unresolved (a computed Python load that may leave its package, `{expr}`) in {path}; "
                                     "write it from __file__ with literal parts, which the scan maps")
                # Root's F1 of #84's R4 (2026-11-12): the package a text lands in is credited whatever the declaration's
                # reach says (the reach ADDS to the landing, never replaces it), as the evaluated-prefix twin credits
                # `other`. A reach of "external", "fixture" or "package" on such a site is not a way to read []. For a
                # caller OUTSIDE every package too (root's B1 of the second delta R4): its landings on a package-free top
                # (`tools/t.py`, its own `scripts/`) are the paths its reach declares, and its landing in a package is
                # credited, so `declarable` (which asks every landing to be in another package) does not gate the credit.
                # A symlinked landing credits BOTH the package holding the link and the package its target is in
                # (`packages/pk/link/m.py`, link -> ../shared: pk and shared), never one instead of the other: the
                # literal names pk's directory, which the load reads through, and the file read is shared's. A link
                # whose target is the caller's own package, a package-free top or outside the repository credits the
                # holder alone (root's K1 of #84's third delta R4, 2026-11-12: the target's owner once REPLACED the
                # holder's, so `packages/pk/link/m.py` with link -> ../../services/r read [] from services/r/x.py).
                # X08b (`packages/link`, a link under no package, -> shared) credits shared, the target's owner; from a
                # PACKAGE caller that link still refuses above, as before (X08).
                landed = {found for x in landings for found in (owner(x), owner(resolve_links(x)))} - {None, owner(path)}
            else:
                landed = set()
            entry = by_site.get((path, expr))
            if entry is None:
                raise ValueError(f"unresolved (an undeclared computed import `{expr}`; declare it in "
                                 f"edge_scan.computed_imports) in {path}")
            if entry["reach"] == "package" and owner(path) is None:
                raise ValueError(f"unresolved (`{expr}` is declared reach \"package\", but {path} is outside every "
                                 "package, where that names and credits nothing; declare the paths it loads)")
            if inside and entry["reach"] != "package":
                raise ValueError(f"unresolved (a computed Python load under its own package, `{expr}`, must be declared "
                                 f"reach \"package\") in {path}")
            used.add((path, expr))
            if other is not None:
                credit_package(path, owner(path), other)
            for found in sorted(landed):
                credit_package(path, owner(path), found)
            if isinstance(entry["reach"], list):
                for target in entry["reach"]:
                    reach_from(path, posixpath.normpath(target))

    outside_entries: dict[str, list[tuple[str, str]]] = {}  # package -> [(the edge's source path, a directory)]
    parsed_names: dict[str, set[str]] = {}  # package -> names its parsed files import, loop literals included

    # Every tracked directory, each ancestor of a tracked path (the RC1B reach check below and the outside-entry pass).
    tracked_dirs = {posixpath.dirname(p) for p in tracked}
    for d in list(tracked_dirs):
        while d:
            d = posixpath.dirname(d)
            tracked_dirs.add(d)

    def entry_tail(raw: str | None, key: str) -> str | None:
        """A sys.path entry's tail: the literal its path ENDS with, from the AST (python_file_facts' literal_tail, a
        closed list of forms; root's B1 of dotgithub-86 slice 2, 2026-11-12), normalised (`./packages/shared`,
        `{source}/x` stripped as rule 6 reads a landing): the components every directory it lands in ends with (root's
        amended item 2 of the R-c r4 review). None for no listed form, a parent step anywhere in the key, an absolute
        path, `.` or the empty string. The key's lone quoted literal is NOT a tail: in `join("packages/shared", PLUGIN)`
        it is not the last component (A1, A11), in `os.path.dirname("packages/shared")` not the landing (A5)."""
        if raw is None or raw.startswith("/") or PARENT_STEP.search(key) or PARENT_STEP.search(raw):
            return None
        tail = posixpath.normpath(LEADING.sub("", raw))
        return None if tail in (".", "") or tail.startswith("/") or tail.split("/")[0] == ".." else tail

    def key_tail(key: str) -> str | None:
        """The key's one quoted literal, normalised: the tail before root's B1 of slice 2. Rule (b) below still refuses
        by it as well as by the AST tail, so no undeclared entry it refused reads now (`"shared" + X`)."""
        literals = QUOTED.findall(SEP_SUBST.sub("/", key))
        if len(literals) != 1 or PARENT_STEP.search(key) or literals[0].startswith("/"):
            return None
        tail = posixpath.normpath(LEADING.sub("", literals[0]))
        return None if tail in (".", "") or tail.startswith("/") or tail.split("/")[0] == ".." else tail

    def ends_in(directory: str, tail: str) -> bool:
        want = tail.split("/")
        return directory.split("/")[-len(want):] == want

    # Root's B2 of the round-5 STACK CHANGES: the (file, key) of every sys.path entry rule (b) leaves as a residual,
    # so the file's other entries are judged with it (the per-file loop below).
    residual_sites: list[tuple[str, str]] = []
    # Root's B5 of the round-5 STACK CHANGES: every tracked symlink and every sourceless .pyc (no `stem.py` beside it,
    # never one under __pycache__, which Python does not import sourceless), judged where a directory lands.
    unreadable_held = sorted(p for p, mode in tracked.items() if mode == "120000" or (
        p.endswith(".pyc") and posixpath.basename(posixpath.dirname(p)) != "__pycache__" and p[:-1] not in tracked))

    def parent_step_landings(literal: str) -> tuple[list[str], list[tuple[str, str]], list[tuple[str, str]], list[str]]:
        """B1's landings of a parent-step literal: from every TRACKED directory (the repository root `""` included), its
        components walked one at a time against the tracked tree, never normpath alone (root's r4 item 5: `lnk/../x`
        resolves `lnk` first). A step above the checkout, or a component that is no tracked directory, gives no landing
        from that start (root's r4 item 11); a component that is a tracked symlink (mode 120000) is returned in
        `links`, with the start it was reached from, whichever start reaches it.

        Root's round-5 fix of dotgithub-86 (STACK CHANGES at 2774a421f815, 2026-11-12), [I] for the undeclared twins
        of B1 (N01u, N01mu): a process may run from a directory generated beneath a tracked one (`services/r/gen/deep`),
        so each tracked start is also walked with up to as many untracked components beneath it as the literal's
        leading parent steps consume; `../../../a` from `services/r/gen/deep` lands in services/a. B4 (N15, N12): a
        walk that climbs above the checkout to a directory beside it is returned in `beside` when the checkout may
        still be under it, a later parent step (`../other/../repo/x`) or a sibling of the checkout one level up whose
        remaining path is a tracked directory (`../repo/packages/shared`, a link or clone of the checkout).
        A walk from a generated start is a source of ADDED landings only (`added`): it records no link and no climb
        beside the checkout, and apply_entry drops its landing when that is the root or code the scan excludes, so a
        generated start never refuses an entry the tracked starts read (S3_C12, N27, RC1S b1, cli's 11-12 course fix)."""
        parts = [c for c in literal.split("/") if c not in ("", ".")]
        leading = next((i for i, c in enumerate(parts) if c != ".."), len(parts))
        landings, links, beside, added = set(), [], [], set()
        checkout = Path(repo).resolve().as_posix()
        names = own_names(repo)
        for start in sorted(tracked_dirs):
            for generated in range(leading + 1):
                here = (start.split("/") if start else []) + [GENERATED_CWD] * generated
                above = None  # the walk's components above the checkout, relative to it: None while inside
                for i, c in enumerate(parts):
                    if above is not None:
                        # Root's B2 of the slice 3 CHANGES: a step above the checkout that re-enters it by its own name
                        # (`../repo/lib` with CI's .../repo/repo, or the checkout's own directory name) lands inside it;
                        # the walk resumes at the root. Lexical against the actual checkout path, and one level up by
                        # any of own_names.
                        above.append(c)
                        at = posixpath.normpath(posixpath.join(checkout, *above))
                        if at == checkout or (above == ["..", c] and c in names):
                            above, here = None, []
                        elif c != ".." and not checkout.startswith(at.rstrip("/") + "/"):
                            rest = parts[i + 1:]
                            if not generated and (".." in rest or (above == ["..", c] and rest and "/".join(rest) in tracked_dirs)):
                                beside.append((start, "/".join(above)))
                            break  # beside the checkout: not tracked here, so nothing it holds is read
                        continue
                    if c == "..":
                        if not here:
                            above = [".."]  # above the checkout: read on only if the walk re-enters it
                            continue
                        here.pop()
                        continue
                    if GENERATED_CWD in here:
                        break  # a component beneath a generated directory: nothing tracked
                    here.append(c)
                    path = "/".join(here)
                    if tracked.get(path) == "120000":
                        if not generated:
                            links.append((path, start))
                        break
                    if path not in tracked_dirs:
                        break  # no such tracked directory
                else:
                    if above is None and GENERATED_CWD not in here:  # a walk ending above or beneath: nothing tracked
                        (added if generated else landings).add("/".join(here))
        return sorted(landings), sorted(set(links)), sorted(set(beside)), sorted(added - landings)

    def apply_entry(package: str, source: str, kind: str, value: str, where: str, what: str = "sys.path entry",
                    key: str | None = None, tail: str | None = None) -> None:
        declared = by_site.get((where, key)) if key is not None else None
        tail = entry_tail(tail, key) if kind == "unknown" and key is not None else None
        # The parent-step route is judged BEFORE the no-tail refusal (slice 2 fix stacked on slice 3, 2026-11-12): a
        # bare parent-step literal is read by its landings, declared or not; the no-tail refusal is for a declared
        # entry that is neither a parent-step literal nor a listed tail form (`r"../x"`, `join("../..", X)`).
        literal = parent_step_literal(key) if kind == "unknown" and key is not None else None
        if declared is not None and kind == "unknown" and tail is None and literal is None:
            # Root's B1 and B2 of dotgithub-86 slice 2 (2026-11-12): a declared entry with no tail has no reach the scan
            # can check (`os.path.join("packages/shared", PLUGIN)` declared to packages/shared once read shared, truth
            # its child; `p` declared once read nothing and its declaration counted as used). It refuses, unused.
            raise ValueError(f"unresolved (the declared sys.path entry `{key}` has no tail the scan reads: its last path "
                             "component is not a literal of a read form (a literal; str, Path, abspath, realpath, "
                             "normpath or fspath of one, or its .resolve(); X / literal; os.path.join(..., literal); an "
                             "f-string whose placeholders all come first), or it holds a parent step or an absolute path, "
                             f"so the directories it reaches cannot be checked) in {where}")
        if declared is not None and tail is not None:
            # The RC1B rule (root's dotgithub-86 review and the R-c r4 review items 2 and 7, 2026-11-12): a DECLARED
            # entry the scan cannot evaluate is read by its reach, a LIST of tracked directories, each ending in the
            # entry's literal (`shared` -> packages/shared; a subset of the matches is the declarer's cwd claim). A
            # keyword says nothing about where a cwd-relative entry lands; each reach is credited as an evaluated entry.
            reach = declared["reach"]
            if not isinstance(reach, list):
                raise ValueError(f"unresolved (`{key}` is declared reach \"{reach}\", but a sys.path entry is declared with "
                                 f"a reach list: the tracked directories ending in `{tail}` it lands in) in {where}")
            for target in reach:
                if not ends_in(posixpath.normpath(target), tail):
                    raise ValueError(f"unresolved (the sys.path entry `{key}` is declared to reach `{target}`, whose "
                                     f"trailing components are not `{tail}`, so the entry cannot land there) in {where}")
                if posixpath.normpath(target) not in tracked_dirs:
                    raise ValueError(f"unresolved (the sys.path entry `{key}` is declared to reach `{target}`, which is "
                                     f"not a tracked directory) in {where}")
            used.add((where, key))  # root's B2 of slice 2: a key is used only in the branch that honours it, here
            for target in reach:
                apply_entry(package, source, "dir", posixpath.normpath(target), where, what)
            return
        if literal is not None:
            # The RC1A rule (root's R-c r2 review B1, r3 item 3, r4 items 5 and 11; dotgithub-86, 2026-11-12): a
            # parent-step literal needs no declaration. It lands, relative to the process cwd, wherever it joins from
            # a tracked directory (or one generated beneath it); every such landing is read and credited, or the entry
            # refuses. Root's B1 of the round-5 STACK CHANGES (2774a421f815): a declaration of one is validated, its
            # reach a LIST of tracked directories (never a keyword), and each is credited WITH the landings (the cwd it
            # claims may be one the scan cannot walk, N01/N01m); a reach that is no tracked directory refuses.
            landings, links, beside, added = parent_step_landings(literal)
            if declared is not None:
                reach = declared["reach"]
                if not isinstance(reach, list):
                    raise ValueError(f"unresolved (the parent-step sys.path entry `{key}` is declared reach \"{reach}\", "
                                     "but a parent-step literal is declared with a reach list: the tracked directories "
                                     f"it lands in, credited with its landings) in {where}")
                for target in reach:
                    if posixpath.normpath(target) not in landings and posixpath.normpath(target) not in tracked_dirs:
                        raise ValueError(f"unresolved (the parent-step sys.path entry `{key}` is declared to reach "
                                         f"`{target}`, which is neither one of its landings nor a tracked directory) in "
                                         f"{where}")
                used.add((where, key))
            if links:
                link, start = links[0]
                raise ValueError(f"unresolved (the sys.path entry `{key}` passes through {link}, a symlink component, "
                                 f"from {start or '.'}; the scan does not follow links, so it cannot tell where the entry "
                                 f"lands) in {where}")
            reached = sorted(set(landings) | ({posixpath.normpath(t) for t in declared["reach"]} if declared else set()))
            tracked_reached = reached
            # a generated start's landing is added, never refused: the root and excluded code contribute nothing
            reached = sorted(set(reached) | {landing for landing in added if landing and not excluded(landing)})
            if beside and reached:
                # Root's B4 of the round-5 STACK CHANGES (N15, N12): a start whose walk climbs beside the checkout,
                # where the checkout may still be (a later parent step, or a sibling one level up), is not dropped
                # because another start lands: it refuses.
                start, at = beside[0]
                raise ValueError(f"unresolved (the sys.path entry `{key}` climbs from {start or '.'} to {at}, beside the "
                                 "checkout, where it may re-enter the checkout by a path the scan cannot see; a climb "
                                 f"beside the checkout is not dropped for another start's landing) in {where}")
            if not reached:
                raise ValueError(f"unresolved (the sys.path entry `{key}` lands in no tracked directory: from each one "
                                 f"it joins to a path above the checkout or to none that is tracked) in {where}")
            for landing in tracked_reached:
                if landing and excluded(landing):
                    raise ValueError(f"unresolved (the sys.path entry `{key}` lands in {landing}, code the scan "
                                     f"excludes, so its reads cannot be credited) in {where}")
            for landing in reached:
                # Root's B3 of the round-5 STACK CHANGES (ruling 3 withdrawn): a package-free landing is read as a
                # whole-directory route, as its evaluated twin is (the literal read from the file's directory), and
                # the closure judges it; the landing is also applied as an evaluated entry, as the twin's is.
                apply_entry(package, source, "dir", landing or ".", where, what)
                if owner(landing) is None:
                    edges.setdefault(source, set()).add(landing or ".")
            return
        if kind == "unknown":
            if escapes_by_text(value):
                # The r5 sys.path rule (root's dotgithub-86 review, 2026-11-12; vectors RC1B/RC1C/RC1I/RC1Q/RC1S): a
                # Python sys.path entry that may leave its package and that no edge_scan.computed_imports entry names
                # (its `file` this file, its `expr` the entry's text as written, `key`) refuses by its own rule. A
                # different text (quotes, an r prefix, adjacent literals, inner parentheses, a trailing slash) is a
                # different key, so a twin's declaration does not cover it (RC1Q). A pytest pythonpath entry (no key)
                # falls to the catch-all below; a DECLARED entry never reaches here (RC1B honours or refuses it above).
                if key is not None and (where, key) not in by_site:
                    raise ValueError(f"unresolved (an undeclared sys.path entry `{value}` may leave its package; declare "
                                     f"it in edge_scan.computed_imports by its text as written, `{key}`) in {where}")
                raise ValueError(f"unresolved (a {what} that may leave its package, `{value}`, cannot be evaluated) "
                                 f"in {where}")
            # The RC1B bare-name rule: an undeclared entry naming no top-level directory (`"shared"`, `"app"`,
            # `Path.cwd() / "shared"`) still lands, relative to the process cwd, in every tracked directory ending in
            # its literal, the caller's own unit included (vagary-core's cost_centre_checks.py:33 `"app"`): refuse.
            # Rule (b) reads the AST tail AND the key's lone literal (key_tail), so `"sha" "red"`, `"""shared"""`,
            # `"\u0073hared"` and `join("shared", "plugins")` refuse while nothing it refused before reads.
            tails = sorted({t for t in (tail, key_tail(key) if key is not None else None) if t is not None})
            hits = sorted(d for d in tracked_dirs if any(ends_in(d, t) for t in tails))
            if key is not None and declared is None and hits:
                raise ValueError(f"unresolved (an undeclared sys.path entry `{key}` may land in "
                                 f"{', '.join(hits[:3])}{', ...' if len(hits) > 3 else ''}, the tracked directories ending "
                                 f"in `{'` or `'.join(tails)}`; declare it in edge_scan.computed_imports by its text as "
                                 f"written, with the directories it reaches) in {where}")
            residual_sites.append((where, key if key is not None else value))
            return  # an entry naming no parent step, no top-level directory and no tracked directory: a residual
        if value == ".." or value.startswith("../"):
            return  # above the repository: nothing tracked is imported from there
        # Root's B5 of the round-5 STACK CHANGES (N24, N28, and their evaluated twins N24e, N28e): a directory on the
        # path that holds a tracked symlink or a sourceless .pyc loads what the scan does not read (the link's target,
        # the compiled module), on every route that lands here; it refuses.
        inner = "" if value in ("", ".") else value.rstrip("/") + "/"
        for held in unreadable_held:
            if held.startswith(inner):
                form = "a symlink inside the landing" if tracked.get(held) == "120000" else "a sourceless .pyc"
                raise ValueError(f"unresolved (the {what} {value} holds {held}, {form}: the scan reads neither a link's "
                                 f"target nor compiled code, so what an import loads from there is unknown) in {where}")
        found = owner(value)
        if found is not None:
            # Root's B5 of the slice 3 CHANGES: an owned directory on the path imports, by name, the packages nested
            # inside it too (`import worker.m` from services/b reaches services/b/worker), on every route that lands
            # here (an evaluated entry, an RC1B reach, an RC1A landing, a pytest pythonpath entry).
            inner = value.rstrip("/") + "/"
            for nested, directory in sorted(package_dir.items()):
                if nested != package and directory.startswith(inner):
                    deps[package].add(nested)
        if found == package:
            return
        if found is not None:
            deps[package].add(found)  # modules imported by name from another package's directory
            return
        outside_entries.setdefault(package, []).append((source, value))

    out = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                          PY_FACTS_GREP, *([revision] if revision else []), "--", "*.py", *excludes],
                         capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    grep_read_everything(out, "the reader scan's Python listing")
    listed = {p[len(revision) + 1:] if revision else p for p in out.stdout.decode("utf-8", errors="replace").split("\0") if p}
    # Root's B1 of the slice 3 CHANGES: the files scan()'s parse set a sys.path entry aside in are read here too, so an
    # entry the grep misses (`sys .path.insert`, `sys.\` + newline) is never suppressed there and unread here.
    listed |= {p for p in parsed_files if p in tracked and not excluded(p)}
    for path in sorted(listed):
        package = owner(path)
        if package is None:
            # A Python file outside every package: its loaders are checked, since its unit runs them (fix 2). Its
            # sys.path entries stay a documented residual; a path-mutation capability no rule consumes refuses it as it
            # refuses a package file (R6-2: python_file_facts holds the single refuse point for every Python file read).
            check_python_sites(path, python_file_facts(read_source(repo, path, revision, environment), path, test_only)[2])
            continue
        text = read_source(repo, path, revision, environment)
        entries, file_names, sites = python_file_facts(text, path, test_only)
        parsed_names.setdefault(package, set()).update(file_names)
        mark = len(residual_sites)
        for kind, value, key, tail in entries:
            apply_entry(package, path, kind, value, path, key=key, tail=tail)
        # Root's B2 of the round-5 STACK CHANGES (GENERAL, N03, N50-N53): a file is READ only when EVERY sys.path site
        # in it resolves by a read rule. A residual entry (rule (b) above) beside an entry that resolves refuses the
        # whole file, as main refused it. R6-2 (root's ruling of 2026-11-12): a site that records no entry (a
        # reassignment, site.addsitedir, an alias of sys.path) and every other path-mutation capability refuse inside
        # python_file_facts itself, whatever else the file holds; the carve-out that read a file whose sites were ALL
        # such forms is gone with the shape list it read.
        unjudged = [key for _, key in residual_sites[mark:]]
        if unjudged and len(entries) > len(residual_sites) - mark:
            raise ValueError(f"unresolved (the sys.path site `{unjudged[0]}` in {path} resolves by no read rule, so the "
                             "file's other sys.path entries are not read either: a file reads only when every one of "
                             f"its sys.path sites resolves) in {path}")
        check_python_sites(path, sites)
    # pytest's `pythonpath`: the nearest config walking up from each Python package (pytest's rootdir/inifile rule),
    # each entry relative to that config's directory, applied like a sys.path entry.
    python_packages = sorted({owner(p) for p in tracked if p.endswith(".py")} - {None})
    for package in python_packages:
        d = package_dir[package]
        while True:
            config = None
            for name in PYTEST_CONFIGS:
                candidate = posixpath.join(d, name) if d not in ("", ".") else name
                if candidate in tracked:
                    values = pytest_pythonpath(read_source(repo, candidate, revision, environment), name, candidate)
                    if values is not None:
                        config = (candidate, values)
                        break
            if config is not None:
                base = posixpath.dirname(config[0])
                for value in config[1]:
                    apply_entry(package, package_dir[package], "dir",
                                posixpath.normpath(posixpath.join(base, value)), config[0], "pytest pythonpath entry")
                break
            if d in ("", "."):
                break
            d = posixpath.dirname(d)
    for package in sorted(outside_entries):
        entries = outside_entries.get(package, [])
        # Every top-level name the package's Python files import; one grep per package, not one parse per file. A
        # pathspec `*` crosses `/`, so this reaches every Python file beneath the package directory.
        found = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-h", "-I", "-E",
                                r"^[[:space:]]*(import|from)[[:space:]]|import_module\(|__import__\(|run_module\(",
                                *([revision] if revision else []), "--", f"{package_dir[package]}/*.py"],
                               capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
        grep_read_everything(found, "the reader scan's Python import grep")
        names = set()
        for line in found.stdout.decode("utf-8", errors="replace").split("\n"):
            line = re.sub(r"^[0-9a-f]{40}:", "", line)
            names |= set(re.findall(r"""(?:import_module|__import__|run_module)\(\s*["']([A-Za-z_]\w*)""", line))
            m = re.match(r"\s*from\s+([A-Za-z_]\w*)[\w.]*\s+import\b", line) or re.match(r"\s*import\s+(.+)", line)
            if m and line.lstrip().startswith("from"):
                names.add(m.group(1))
            elif m:
                names |= {part.strip().split(".")[0].split()[0] for part in m.group(1).split(",") if part.strip()}
        names |= parsed_names.get(package, set())
        for source, directory in entries:
            for name in sorted(names):
                for candidate in (f"{directory}/{name}.py", f"{directory}/{name}"):
                    if candidate in tracked or candidate in tracked_dirs:
                        edges.setdefault(source, set()).add(candidate)
                        break

    imports: dict[str, set[str]] = {}
    unit_imports: dict[str, set[str]] = {}  # a path outside every package -> the reader units whose files reach it
    named: dict[str, set[str]] = {}
    namers: dict[str, set[str]] = {}  # a target -> the files that name it
    for p, ts in edges.items():
        for t in ts:
            namers.setdefault(t, set()).add(p)
    unresolved_data: set[str] = set()  # the declared names that resolve to nothing (report only)
    names_stood_for: dict[str, set[str]] = {}  # an untracked name -> the enclosing directory it stands for (report)

    def closure(key: str, starts: list[str], credit, record: dict) -> None:
        """Every route from `starts` to a fixed point. `credit(found)` credits a package read; `record[path]` gains `key`
        for every reached file outside every package. A route that resolves to nothing refuses unless declared."""
        queue, seen = sorted(set(starts)), set()
        whole_dirs: set[str] = set()  # directories this closure reached in full: every tracked file beneath is credited
        undeclared: list[tuple[str, str]] = []  # (namer, target): judged once the closure is complete
        while queue:
            target = queue.pop(0)
            if target in seen:
                continue
            seen.add(target)
            if target in (".", "..") or target.startswith("../"):
                # 1.5.2, root's rulings (a) and (b): declared by every file that names it, or it refuses.
                entries = [declared_name(by_name, name_globs, f, target) for f in sorted(namers.get(target, ()))]
                if not entries or not all(e for e, _ in entries):
                    raise ValueError(f"unresolved ({key} reaches {target}, the repository root or above it: that reaches "
                                     "every file, so no mapping of it can be narrower than FULL)")
                for entry, name_key in entries:
                    names_used.add(name_key)
                    if isinstance(entry["reach"], list):
                        queue.extend(sorted(posixpath.normpath(x) for x in entry["reach"]))
                continue
            files = files_of(target)
            if not files:
                # A path in a package (an untracked build output, its dist/) stands for that package's sources.
                found = owner(target)
                if "node_modules" in target.split("/"):
                    continue  # an installed dependency, never tracked source: external (its manifests plan FULL)
                if found is not None:
                    credit(found)
                    continue
                if target in loader_targets or not namers.get(target):
                    # A declared reach (a computed import's, or an unresolved name's) that itself names nothing.
                    raise ValueError(f"unresolved ({key} reaches {target}, which names no tracked file or directory, so "
                                     "a change to what it stands for could not select it)")
                for f in sorted(namers.get(target, ())):
                    entry = by_name.get((f, target))
                    if entry is None:
                        # The untracked name stands for the deepest directory it shares with its namer, when that is
                        # below the top level: shared-sdks/public/identity/test/a.mjs importing ../dist/server.js reaches
                        # shared-sdks/public/identity, as an untracked path inside a package stands for the package
                        # (spine's FALSE-POSITIVES item 5). It over-approximates. A name sharing only the repository root
                        # or a top-level directory with its namer (a top-level dist/, ../../tools/dist/x.js) still refuses.
                        shared = posixpath.commonpath([posixpath.dirname(f), posixpath.dirname(target)]) if "/" in f else ""
                        if shared.count("/") >= 1 and shared not in seen:
                            names_stood_for.setdefault(target, set()).add(shared)
                            queue.append(shared)
                        elif shared.count("/") < 1:
                            undeclared.append((f, target))
                        continue
                    names_used.add((f, target))
                    unresolved_data.add(target)
                    if isinstance(entry["reach"], list):
                        queue.extend(sorted(posixpath.normpath(x) for x in entry["reach"]))
                continue
            if files and files != [target] and all(f.startswith(target + "/") for f in files):
                whole_dirs.add(target)
            for path in files:
                found = owner(path)
                if found is not None:
                    credit(found)  # a package nested in a reached directory, or a link into one
                    continue
                record.setdefault(path, set()).add(key)
                if any(path == d or path.startswith(d + "/") for d in always):
                    raise ValueError(f"unresolved ({key} reaches {path}, under edge_scan.always_reader_dirs: that "
                                     "directory is not always-only)")
                if path.lower().endswith(".md"):
                    continue
                ext = posixpath.splitext(path)[1].lstrip(".").lower()
                if ext in IMPORTING_UNPARSED_EXT:
                    raise ValueError(f"unresolved ({key} reaches {path}, a .{ext} file that can import modules, which the "
                                     "scan does not parse, so what it reaches could not select its importers)")
                code = is_code(path)
                if excluded(path):
                    if code:
                        raise ValueError(f"unresolved ({key} reaches {path}, code the scan excludes, so its reads "
                                         "cannot be credited)")
                    continue
                for read in outside.get(path, set()):
                    credit(read)
                if path not in named:
                    # Root's round 3 of #33, B1: a reached NON-code file's recorded routes are routes too (a compose
                    # volume `../scripts/w.mjs:/app/w.mjs`, a tsconfig `files`/`extends`, a Makefile recipe): followed.
                    named[path] = (named_paths(path) if code else dot_routes.get(path, set())) | edges.get(path, set())
                    for t in named[path]:
                        namers.setdefault(t, set()).add(path)
                queue.extend(sorted(named[path] - seen))
        for f, target in undeclared:
            # spine's FALSE-POSITIVES item 5: the identity SDK's tests import its untracked ../dist/*.js, but the importer
            # already reaches shared-sdks/public/identity whole, so every tracked file a build compiles dist/ from is
            # credited. A name under such a directory adds nothing; any other refuses.
            if any(target.startswith(d + "/") for d in whole_dirs):
                continue
            raise ValueError(f"unresolved ({f} names {target}, which is no tracked file or directory: a route "
                             "that resolves to nothing may stand for anything; declare it in "
                             "edge_scan.unresolved_names with reach \"none\" or the paths it stands for)")

    # Round 3, B3: the ./ routes of every file outside every package. A code file names each quoted ./ or ../ string
    # (named_paths, rule 1); any other file each ./ word that names a tracked path. Its ../ routes are already edges.
    dot_routes: dict[str, set[str]] = {}
    listing = run_git(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                              r"""(^|[^A-Za-z0-9_./$-])\.\.?/([A-Za-z0-9_@{%]|\$\{|['"`] *(\+|\.concat\())""", *([revision] if revision else []), "--", ".",
                              *excludes], capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    grep_read_everything(listing, "the reader scan")
    for p in sorted(x[len(revision) + 1:] if revision else x
                    for x in listing.stdout.decode("utf-8", errors="replace").split("\0") if x):
        if owner(p) is not None or excluded(p) or p.lower().endswith(".md") or tracked.get(p) == "120000":
            continue
        if is_code(p):
            routes = named_paths(p)
        else:
            here = posixpath.dirname(p)
            routes = {t for t in (posixpath.normpath(posixpath.join(here, m.group(1))) for m in NON_CODE_DOT_ROUTE.finditer(
                read_source(repo, p, revision, environment))) if files_of(t)}
        if routes:
            dot_routes[p] = routes
            for t in routes:
                namers.setdefault(t, set()).add(p)
    # Round 4 of #33, B3: a symlink's target text is a route (git grep reads regular files only). A symlink outside every
    # package routes to what it points at, so `tools/alias.mjs -> worker.mjs` starts its unit and, run by any name, runs
    # worker.mjs. One inside a package is that package's; the backstop reads its target text as a mention.
    for p, mode in sorted(tracked.items()):
        if mode != "120000" or owner(p) is not None or excluded(p):
            continue
        link = read_source(repo, p, revision, environment) if revision else os.readlink(repo / p)
        target = posixpath.normpath(posixpath.join(posixpath.dirname(p), link.strip()))
        if target != ".." and not target.startswith("../") and not target.startswith("/") and files_of(target):
            dot_routes.setdefault(p, set()).add(target)
            namers.setdefault(target, set()).add(p)
    for package in sorted({owner(p) for p in edges} - {None}):
        def credit_dep(found: str, package=package) -> None:
            if found != package:
                deps[package].add(found)
        closure(package, [t for p, ts in edges.items() if owner(p) == package for t in ts], credit_dep, imports)
    # root's delta R4 of #33, D5 (N3): a file outside every package runs in its reader directory's job (or nowhere
    # declared, <unmapped>), so what it reaches is imported by that unit too: test/foo.test.mjs importing scripts/x.mjs.
    units: dict[str, list[str]] = {}
    # Round 3, B3: every file outside every package with a route starts its unit, code or not (test/compose.yml with
    # `../lib/entry.mjs:/entry.mjs` runs in the test job like test/run.mjs would), plus every ./ route (dot_routes).
    for p, ts in list(edges.items()) + sorted(dot_routes.items()):
        if owner(p) is None and not excluded(p):
            unit = p.split("/")[0] if "/" in p and p.split("/")[0] in reader_dirs else "<unmapped>"
            units.setdefault(unit, []).extend(ts)
    for unit, starts in sorted(units.items()):
        def credit_unit(found: str, unit=unit) -> None:
            readers.setdefault(unit, set()).add(found)
        closure(unit, starts, credit_unit, unit_imports)
    # A reached file in a reader directory may itself be an executor its job runs (scripts/x.test.mjs): its own unit
    # imports it too, so a mapping of it must still run that job.
    for path in sorted(set(imports) | set(unit_imports)):
        top = path.split("/")[0]
        if "/" in path and top in reader_dirs:
            unit_imports.setdefault(path, set()).add(top)
    names_used |= set(names_used_before)
    stale = [f"{f}: {n}" for (f, n) in sorted(by_name) if (f, n) not in names_used]
    stale += [f"{f}: {d['name']}" for f, _, d in name_globs if (f, d["name"]) not in names_used]
    unused = [f"{d['file']}: {d['expr']}" for d in declared if (d["file"], " ".join(d["expr"].split())) not in used]
    # The RC1B stale-key rule (root's R-c r4 item 2 and ruling (b), 2026-11-12): an entry naming a tracked Python file
    # whose text matches none of its sys.path entries or loader sites (a mis-keyed twin, a glob, which computed_imports
    # has no form for) refuses here, in scan(), with check mode's text; an entry on a file no longer tracked stays a
    # check-mode failure only (assess, below).
    for d in declared:
        if d["file"].endswith(".py") and d["file"] in tracked and (d["file"], " ".join(d["expr"].split())) not in used:
            raise ValueError(f"stale computed_imports entry: {d['file']}: {d['expr']} matches no import call (a Python "
                             "file the scan parsed: key the entry by the site's text as written, or remove it)")
    unused += [f"unresolved_names {entry}" for entry in stale]
    # Round 3 of #33, the backstop's attribution: a tracked file -> the files outside every package whose RECORDED
    # routes (grep edges, ./ routes, a reached file's named paths) resolve to it, a directory route to everything beneath.
    routes_to: dict[str, set[str]] = {}
    for table in (edges, dot_routes, named):
        for f, ts in table.items():
            if owner(f) is None:
                for t in ts:
                    for hit in files_of(t) if not (t in (".", "..") or t.startswith("../")) else ():
                        routes_to.setdefault(hit, set()).add(f)
    return imports, unused, sorted(unresolved_data), unit_imports, names_stood_for, routes_to


def assess(pkgs: dict, cfg: dict, deps: dict, readers: dict, *, revision: str | None, config_path: Path,
           imports: dict | None = None, computed_unused: list | None = None, unit_imports: dict | None = None,
           mentions: dict | None = None, backstop_reasons: dict | None = None) -> dict:
    failures, stale = [], []
    imports = imports or {}
    unit_imports = unit_imports or {}
    # 1.5.0 rule 5: a change to an imported file must select its importers, so extra_edges must map it to them.
    edge_globs = [(glob_to_regex(glob), set(targets)) for glob, targets in sorted((cfg.get("extra_edges") or {}).items())]
    inert = list(cfg.get("inert_globs") or [])
    for path, importers in sorted(imports.items()):
        # plan.classify_paths applies inert_globs before extra_edges, so an inert imported path selects NOTHING when it
        # changes, whatever extra_edges maps (found by the end-to-end selection census, vagaris docs/**, 2026-10-27).
        rule = first_match(path, inert)
        if rule:
            failures.append(f"inert import: {path} is imported by {', '.join(sorted(importers))}, but inert_globs "
                            f"{rule!r} makes a change to it select nothing (narrow the glob so it leaves {path} out)")
            continue
        mapped = set().union(*[targets for regex, targets in edge_globs if regex.match(path)])
        for name in sorted(set(importers) - mapped):
            failures.append(f"undeclared import edge: {name} imports {path} (map it in extra_edges, so a change to it "
                            f"selects {name})")
    # root's delta R4 of #33, D5 (N3): a path a file outside every package reaches is mappable only if the mapping still
    # runs that file. The REAL plan.classify_paths decides: FULL (unmapped, or a full trigger) runs everything; otherwise
    # the reader job's rule must match what the mapping selects. A file in no reader directory runs in no declared job,
    # so nothing it reaches may be mapped.
    es_cfg = cfg.get("edge_scan") or {}
    reader_rule = (cfg.get("jobs") or {}).get(es_cfg.get("reader_job")) if es_cfg.get("reader_job") else None
    for path, units in sorted(unit_imports.items()):
        selection = classify_paths([path], cfg, pkgs)
        if selection["error"] or selection["evidence"]["full_triggers"] or selection["evidence"]["unmapped"]:
            continue  # FULL: every job runs (an error plans FULL too)
        if selection["evidence"]["inert"]:
            failures.append(f"inert import: {path} is imported from {', '.join(f'{u}/' for u in sorted(units))}, but "
                            "inert_globs makes a change to it select nothing")
            continue
        for unit in sorted(units):
            if unit == "<unmapped>":
                failures.append(f"narrowed import: {path} is reached by a file outside every package and every reader "
                                "directory, which no declared job runs, so mapping it can only narrow FULL (leave it "
                                "unmapped, or put that file's directory in edge_scan.reader_dirs)")
                continue
            try:
                runs = reader_rule is not None and rule_matches(reader_rule, selection["affected"])[0]
            except ValueError:
                runs = False
            if not runs:
                failures.append(f"narrowed import: {path} is reached from {unit}/, which reader job "
                                f"'{es_cfg.get('reader_job')}' runs, but its mapping selects "
                                f"{sorted(selection['affected']) or 'no package'} and not that job (map it to a package "
                                "the job lists, or leave it unmapped so it plans FULL)")
    # Root's round 3 of #33, the BACKSTOP (attack-independent, failing toward FULL): a mapping for P holds only if every
    # other tracked file that names P's basename is in a package the mapping selects, or is a file outside every package
    # whose route to P the scan recorded. Anything else is a runner the scan did not see, by a spelling nobody listed yet.
    # Round 4: the same holds for every file outside every package that reaches P by a recorded route (B1, its runner
    # runs P), for every directory holding one (T10b), and for a path inert_globs maps to nothing (B4).
    # Its consequence is PER PATH (root's ruling, 2026-10-29): P joins `backstop_full`, which the plan treats as a full
    # trigger, so a change to P plans FULL and every other path keeps its mapping. A basename collision goes FULL too.
    # Declarations (a mapping that covers the mentioning package) still narrow P back out of FULL.
    inert_globs = list(cfg.get("inert_globs") or [])
    backstop: dict[str, list[str]] = {}
    for path, rows in sorted((mentions or {}).items()):
        selection = classify_paths([path], cfg, pkgs)
        if selection["error"] or selection["evidence"]["full_triggers"] or selection["evidence"]["unmapped"]:
            continue  # FULL: every job runs
        affected = set(selection["affected"])
        inert_rule = first_match(path, inert_globs) if selection["evidence"]["inert"] else None
        for f, own, subject, member in rows:
            if (own is not None and own in affected) or (own is None and subject):
                continue
            base = member if member.endswith("/") else posixpath.basename(member)
            via = ("" if member == path else f"; {member} holds {path} or a file that reaches it by a recorded route, so "
                   f"what runs it runs {path}" if member.endswith("/") else
                   f"; {member} reaches {path} by a recorded route, so what runs it runs {path}")
            if inert_rule:
                why = (f"{f} names {base}, but inert_globs {inert_rule!r} makes a change to {path} select nothing "
                       f"(narrow the glob so it leaves {path} out to narrow it){via}")
            elif own is not None:
                why = (f"{f} (package {own}) names {base}, but the mapping for {path} selects "
                       f"{sorted(affected) or 'no package'} (map {path} to {own} too to narrow it){via}")
            else:
                why = (f"{f}, outside every package, names {base} by a route the scan did not record, so whatever runs "
                       f"{f} may run {path} (write the route as a relative path the scan follows to narrow it){via}")
            backstop.setdefault(path, []).append(why)
    for entry in computed_unused or []:
        failures.append(f"stale computed_imports entry: {entry} matches no import call")
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
              "imports": {path: sorted(values) for path, values in sorted(imports.items())},
              "unit_imports": {path: sorted(values) for path, values in sorted(unit_imports.items())},
              "backstop_full": sorted(backstop), "failures": failures, "stale": stale}
    result["assessment_sha256"] = canonical_digest(result)
    if backstop_reasons is not None:
        backstop_reasons.update(backstop)  # the report's reasons; never part of the bound assessment
    return result


def sparse_pattern(path: str) -> str:
    """`path` as one anchored, literal non-cone sparse-checkout pattern (gitignore syntax: `\\` escapes `*?[\\`, a
    leading `!` or `#`, and a trailing space). A path holding a newline cannot be one, so it refuses."""
    if "\n" in path or "\r" in path:
        raise ValueError(f"unresolved (a changed path holds a line break, so the base checkout cannot name it: {path!r})")
    out = re.sub(r"([*?\[\\])", r"\\\1", path)
    out = re.sub(r"(?<=[^ ])( +)$", lambda m: "\\ " * len(m.group(1)), out)
    return "/" + (("\\" + out) if out[:1] in ("!", "#") else out)


def base_paths(repo: Path, base: str, head: str) -> list[str]:
    """The paths the base pass reads: deleted or modified between `base` and `head` (D/M/T, renames as D+A). Trees only,
    so a blobless candidate answers it."""
    for rev in (base, head):
        if not re.fullmatch(r"[0-9a-f]{40}", rev):
            raise ValueError("base-paths revisions must be immutable commits")
    out = run_git(["git", "--no-replace-objects", "-C", str(repo), "diff", "--name-only", "-z", "--no-renames",
                          "--diff-filter=DMT", base, head, "--"], capture_output=True, timeout=60,
                         env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | {"GIT_NO_LAZY_FETCH": "1"})
    if out.returncode:
        raise ValueError(f"unresolved (base-paths cannot diff {base} against {head})")
    return sorted(x for x in out.stdout.decode("utf-8", errors="surrogateescape").split("\0") if x)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["derive", "check", "base-paths"])
    ap.add_argument("--config")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest-root", help="trusted base workspace metadata")
    ap.add_argument("--revision", help="immutable candidate commit for source reads")
    ap.add_argument("--out-json", help="write the same supported-reader check as a bound assessment")
    ap.add_argument("--base-revision", help="the base commit: its basename mentions join the backstop's (BASE ∪ HEAD)")
    ap.add_argument("--base-repo", help="a checkout holding the base revision's changed files (default: --repo)")
    ap.add_argument("--github-output", help="base-paths: append the sparse patterns as the `paths` output here")
    a = ap.parse_args(argv)
    repo = Path(a.repo)
    if a.mode == "base-paths":
        # The action's base checkout adds these, so the base pass can read the PR's deleted and modified files.
        patterns = [sparse_pattern(p) for p in base_paths(repo, a.base_revision or "", a.revision or "")]
        delimiter = "EOF_" + hashlib.sha256("\n".join(patterns).encode()).hexdigest()[:16]
        text = f"paths<<{delimiter}\n" + "".join(x + "\n" for x in patterns) + f"{delimiter}\n"
        if a.github_output:
            with open(a.github_output, "a", encoding="utf-8") as fh:
                fh.write(text)
        print(f"base-paths: {len(patterns)} deleted or modified paths for the base checkout")
        return 0
    if not a.config:
        ap.error("--config is required for derive and check")
    cfg = json.loads((repo / a.config).read_text())
    manifest_root = Path(a.manifest_root) if a.manifest_root else repo
    report: dict = {}
    # The candidate's copy of the planner config (the action reads the base copy: --config <base>/<config>).
    policy = posixpath.normpath(os.path.relpath(repo / a.config, manifest_root))
    try:
        deps, readers = scan(repo, cfg, manifest_root=manifest_root, revision=a.revision, report=report, policy_files=(policy,),
                             mention_revisions=((a.base_repo or a.repo, a.base_revision),) if a.base_revision else ())
    except ValueError as err:
        if READER_TIMEOUT not in str(err):
            raise
        print("FAIL " + str(err))
        return 3  # a distinct exit: the action plans FULL under its own reason, never folded into "unproven" (1.7.3)
    if a.mode == "derive":
        print(json.dumps({"deps": {k: sorted(v) for k, v in sorted(deps.items())},
                          "readers": {k: sorted(v) for k, v in sorted(readers.items())},
                          "imports": report["imports"], "unit_imports": report["unit_imports"]}, indent=1))
        return 0
    pkgs = workspace_graph(manifest_root, cfg)
    reasons: dict[str, list[str]] = {}
    assessment = assess(pkgs, cfg, deps, readers, revision=a.revision, config_path=repo / a.config,
                        imports=report["imports"], computed_unused=report["computed_imports_unused"],
                        unit_imports=report["unit_imports"], mentions=report["mentions"], backstop_reasons=reasons)
    failures, stale = assessment["failures"], assessment["stale"]
    if a.out_json:
        Path(a.out_json).write_text(json.dumps(assessment, sort_keys=True) + "\n")
    for s in stale:
        print(s)
    for f in failures:
        print("FAIL " + f)
    for path, whys in sorted(reasons.items()):
        for why in whys:  # one line per reason: a reason itself may hold "; "
            print(f"BACKSTOP {path} plans FULL: {why}")
    print(f"edges: {sum(len(v) for v in deps.values())} reads between {len(deps)} packages; "
          f"{len(failures)} undeclared, {len(stale)} stale, {len(assessment['backstop_full'])} backstop FULL")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
