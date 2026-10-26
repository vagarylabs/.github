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
PARENT_WORD = re.compile(r"\b(?:pardir|parents?|dirname)\b")
GLOB_CHARS = re.compile(r"[*?\[\]{}]")
COMPONENT_CHAR = re.compile(r"[A-Za-z0-9_.-]")
_SPACE = re.compile(r"\s+")
_WORD = re.compile(r"[^\W\d][\w$]*|\$[\w$]*|\d[\w.]*")
_OPS = re.compile(r"\.\.\.|===|!==|\*\*|==|!=|<=|>=|=>|->|::|:=|\?\.|\?\?|&&|\|\||[^\w\s]")
_PY_PREFIX = re.compile(r"[rRbBuUfF]{1,2}")


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
            computed = "f" in prefix.lower() and "{" in body
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


def read_source(repo: Path, path: str, revision: str | None, environment: dict) -> str:
    """The scanned revision's bytes of one file (the working tree's when no revision is pinned)."""
    if revision is None:
        return (repo / path).read_text(errors="replace")
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "show", f"{revision}:{path}"],
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
        self.root_path = re.compile(r"(?<![\w./-])(?:\.\./)*(?:%s)/" % alt)
        # In a computed string a root segment anywhere (`${root}/services/${x}`) is a path; a backslash separates too.
        self.root_segment = re.compile(r"(?<![\w.-])(?:%s)(?=[/\\])" % alt)
        self.root_backslash = re.compile(r"(?<![\w.-])(?:%s)\\" % alt)

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

    def statement(self, s: int, e: int) -> tuple[int, int]:
        """The token range of the statement (or object entry) holding tokens s..e: bracketed groups are whole, and a
        line break ends it unless the line continues (a trailing operator or backslash, or a leading `.`)."""
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

        def boundary(tok):
            return tok[0] == "comma" or (tok[0] == "op" and tok[3] == ";") or (src.py and tok[0] == "colon")

        j = lo - 1
        while j >= floor:
            if boundary(T[j]) or not joined(j, lo):
                break
            lo = src.opener[j] if T[j][0] == "close" else j
            j = lo - 1
        j = hi + 1
        while j <= ceiling:
            if boundary(T[j]) or not joined(hi, j):
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
            if T[j][0] == "open" and T[j][3] == "{":
                j = src.match[j] + 1
                continue
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
        kind = self.kind(e)
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
            return self.beneath(root)  # ["services"], ("services",), {"services"}: a walker over the root
        walked = self.iterated(e) or method
        if not walked and not self.has_evidence(e):
            self.refuse("a collection literal outside an assignment, object value or comparison")
        return self.named_by_siblings(spans, mine, root) | (self.beneath(root) if walked else set())

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
            return set()
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
                if tok[3][2] == m.start() and self.root_of(tok) is not None:
                    hits.append(k)
                continue  # a quoted root inside another string: read below, with the string's other mentions
            self.refuse("a root literal in an unparsed token (a regex, or a broken quote) is an unsupported")
        reads = set()
        k = src.token_at(a)
        k = k if k is not None else bisect.bisect_left(src.starts, a)
        while k < len(src.code) and src.code[k][1] < b:
            if src.code[k][0] == "str" and k not in hits:
                reads |= self.string_reads(k, a, b)
            k += 1
        for k in hits:
            try:
                reads |= self.classify(k)
            except (IndexError, KeyError, StopIteration):
                self.refuse("an unparsed")
        return reads

    def string_reads(self, k: int, a: int, b: int) -> set:
        """A root named inside string k on this line (`f"{ROOT}/services/{x}"`, `"services/*/migrations"`, `'cat
        services\\x'`, prose quoting 'services') reads every package beneath its literal prefix. A `..` in the same
        path-like run, or a parent step applied to the string, REFUSES; so does a computed string that nests code naming
        a root, or holds any parent step, since its substitutions are opaque."""
        src, tok = self.src, self.src.code[k]
        lo, hi = max(tok[1], a), min(tok[2], b)
        plain = tok[3][1]
        body = tok[3][0]
        if not plain and (self.root_segment.search(body) or self.quoted.search(body)) and (
                PARENT_SEG.search(body) or PARENT_WORD.search(body) or self.quoted.search(body)):
            # A substitution is opaque: code nested in it (a quoted root), or a parent step anywhere in it, may leave the
            # root, so the string REFUSES rather than reading beneath its prefix.
            self.refuse("unresolved")
        mentions = [m.start() for m in self.root_segment.finditer(src.text, lo, hi) if not plain
                    or not COMPONENT_CHAR.match(src.text, m.end() + 1) or src.text[m.end()] == "\\"]
        mentions += [m.start() + 1 for m in self.quoted.finditer(src.text, lo, hi)]
        mentions += [m.start() for m in self.root_path.finditer(src.text, lo, hi)
                     if plain and not COMPONENT_CHAR.match(src.text, m.end())]
        reads = set()
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
            reads |= self.resolve(parts, dynamic=True)
        if reads or mentions:
            self.after(k, k)
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
        return self.beneath(posixpath.normpath(path_text)) if self.after(k, k) else set()


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
    # Every `<root>/`, every quoted root (also `./<root>`, `<root>/`, and a backtick string), and every `../`.
    pattern = f"({alt})[/\\\\]|[\"'`](\\./)*({alt})/?[\"'`]|\\.\\./"
    excludes = [f":!{x}" for x in (es.get("exclude") or ["*.md", "docs", ".github"])]
    if (cfg.get("workspace") or {}).get("type") == "pnpm":
        # The workspace manifest DEFINES the graph (its quoted roots are package globs, not reads), and any change to
        # it already plans FULL (plan.py BUILTIN_FULL_GLOBS).
        excludes.append(":!pnpm-workspace.yaml")
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
    classify = RootLiteral(roots, by_dir, owner, globs)
    sources: dict[str, Source] = {}
    deps: dict[str, set[str]] = {n: set() for n in pkgs}
    readers: dict[str, set[str]] = {d: set() for d in reader_dirs}

    def literal_read(path_text: str) -> str | None:
        found = owner(path_text)
        if found is None and not classify.beneath(posixpath.normpath(path_text)):
            classify.unowned(posixpath.normpath(path_text))  # F6, the literal form
        return found

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
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        classify.path = path
        targets = set()
        if ext in STRUCTURED:
            # The whole file's tokens decide: a construct may span lines, and a comment or string may hide a bracket.
            src = sources.get(path)
            if src is None:
                src = sources[path] = Source(read_source(repo, path, revision, environment), ext)
            line = int(number) - 1
            a, b = src.bounds(line) if line <= len(src.newlines) else (0, -1)
            if src.text[a:b] != text:
                raise ValueError(f"reader scan line {number} of {path} does not match the scanned revision")
            targets |= classify.line_reads(src, line)
            for m in lit.finditer(src.text, a, b):
                if not src.in_comment(m.start()):
                    targets.add(literal_read(m.group(1)))
                    targets |= classify.literal_path(src, m.start(), m.group(1))
            for m in rel.finditer(src.text, a, b):
                if not src.in_comment(m.start()):
                    targets.add(owner(posixpath.normpath(posixpath.join(posixpath.dirname(path), m.group(1)))))
        else:
            t = text.strip()
            if t.startswith(COMMENT_PREFIXES):
                continue
            if classify.quoted.search(t) and ext != "sql":
                classify.refuse("a root literal in a file whose syntax the scanner does not parse is an unsupported")
            for m in lit.finditer(t):
                targets.add(literal_read(m.group(1)))
            for m in rel.finditer(t):
                targets.add(owner(posixpath.normpath(posixpath.join(posixpath.dirname(path), m.group(1)))))
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
