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
import fnmatch
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


def read_source(repo: Path, path: str, revision: str | None, environment: dict) -> str:
    """The scanned revision's bytes of one file (the working tree's when no revision is pinned)."""
    if revision is None:
        return (repo / path).read_bytes().decode("utf-8", errors="replace")  # no newline translation (CRLF)
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
COMPUTED_REACH = frozenset({"package", "external", "fixture"})
# Every line a loader call can start on (loader_call_opens decides). A name bound to createRequire(...) lives in a file
# that names createRequire, so that word finds its file.
IMPORT_CALL_GREP = (r"(^|[^A-Za-z0-9_$.])(import|require)[[:space:]]*\(|(require|import\.meta)\.resolve[[:space:]]*\("
                    r"|module\.require[[:space:]]*\(|createRequire")
SHELL_RELATIVE = re.compile(r"(?<![\w.$/-])(\.\.?/[A-Za-z0-9_.@+/-]+)")
SHELL_SELF_DIR = re.compile(r"(?:\$\(\s*dirname\s+[\"']?\$(?:0|\{?BASH_SOURCE(?:\[0\])?\}?)[\"']?\s*\)|\$\{BASH_SOURCE%/\*\})"
                            r"/([A-Za-z0-9_.@+/-]+)")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*)\s+import\b|import\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*))", re.M)


# ---------- Python sys.path entries (1.5.1) ----------
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
#     The same holds in a reached Python file.
# The lines a package Python file can change its import path or load a module by name or path on.
PY_FACTS_GREP = r"sys\.path|import_module|__import__|spec_from_file_location|run_path|run_module|exec[[:space:]]*\("
# pytest's config files, in its precedence order inside one directory (pytest.ini wins even with no [pytest] section).
PYTEST_CONFIGS = ("pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")


def pytest_pythonpath(text: str, name: str, path: str) -> list[str] | None:
    """The `pythonpath` entries a pytest config file sets (spine's pre-review of 1.5.1: the config-level sys.path
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


def python_file_facts(text: str, path: str) -> tuple[list[tuple[str, str]], set[str], list[tuple[str, str, str | None]]]:
    """One Python file's (sys.path entries, imported top-level names, loader sites), from one parse.
    - An entry is ("dir", repo-relative directory, which may start with `../` above the repository) or ("unknown", its
      source text).
    - The names are every top-level module imported by name: `import x`, `from x import y`, and a LITERAL
      `importlib.import_module("x")`, `__import__("x")` or `runpy.run_module("x")`.
    - A loader site (spine's pre-review of 1.5.1) is ("module", expr, None) for one of those three with a non-literal
      name, or ("path", expr, resolved) for `importlib.util.spec_from_file_location(name, p)`, `runpy.run_path(p)` and
      `exec(open(p).read())`, with `p` evaluated like a sys.path entry (None when it cannot be). module_from_spec loads
      what spec_from_file_location built, so the path is read at the latter.
    Raises ValueError when the file does not parse."""
    import ast
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as error:
        raise ValueError(f"unresolved (a Python file the scan must read does not parse: {path}: {error})") from None
    assigned: dict[str, list] = {}
    for node in ast.walk(tree):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for t in targets:
            if isinstance(t, ast.Name) and getattr(node, "value", None) is not None:
                assigned.setdefault(t.id, []).append(node.value)
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
            return ev(values[0], depth + 1) if len(values) == 1 else UNKNOWN
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

    def resolved(node) -> str | None:
        value = ev(node)
        return None if value is UNKNOWN else here if value is FILE else value

    entries: list[tuple[str, str]] = []

    def entry(node):
        value = resolved(node)
        entries.append(("unknown", source(node)) if value is None else ("dir", value))

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

    names: set[str] = set()
    sites: list[tuple[str, str, str | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.AugAssign) and is_sys_path(node.target):
            for item in (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]):
                entry(item)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Subscript) and is_sys_path(t.value) for t in node.targets):
            for item in (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]):
                entry(item)
        elif isinstance(node, ast.Call):
            f, name = node.func, call_name(node.func)
            if isinstance(f, ast.Attribute) and is_sys_path(f.value):
                if f.attr == "insert" and len(node.args) == 2:
                    entry(node.args[1])
                elif f.attr == "append" and len(node.args) == 1:
                    entry(node.args[0])
                elif f.attr == "extend" and len(node.args) == 1:
                    for item in (node.args[0].elts if isinstance(node.args[0], (ast.List, ast.Tuple)) else [node.args[0]]):
                        entry(item)
            elif name in ("import_module", "__import__", "run_module") and node.args:
                arg = node.args[0]
                looped = loop_literal_names(node, arg)
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    names.add(arg.value.split(".")[0])
                elif looped is not None:
                    names |= {value.split(".")[0] for value in looped}  # resolved by name, like any import
                else:
                    sites.append(("module", source(arg), None))
            elif name in ("spec_from_file_location", "run_path"):
                arg = (node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "location"), None)) \
                    if name == "spec_from_file_location" else (node.args[0] if node.args else None)
                if arg is not None:
                    sites.append(("path", source(arg), resolved(arg)))
            elif name == "exec" and node.args and isinstance(node.args[0], ast.Call):
                inner = node.args[0]  # exec(open(p).read())
                if isinstance(inner.func, ast.Attribute) and inner.func.attr == "read" and isinstance(inner.func.value, ast.Call) \
                        and call_name(inner.func.value.func) == "open" and inner.func.value.args:
                    arg = inner.func.value.args[0]
                    sites.append(("path", source(arg), resolved(arg)))
    return entries, names, sites


def tracked_paths(repo: Path, revision: str | None, environment: dict) -> dict[str, str]:
    """Every tracked path at the scanned revision (the index when none is pinned), with its git mode."""
    args = ["ls-tree", "-r", "-z", "--full-tree", revision] if revision else ["ls-files", "-s", "-z"]
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args], capture_output=True, timeout=60, env=environment)
    if out.returncode:
        raise ValueError("reader scan cannot list the tracked files at the scanned revision")
    entries = {}
    for record in out.stdout.decode("utf-8", errors="replace").split("\0"):
        if record:
            meta, _, path = record.partition("\t")
            entries[path] = meta.split()[0]
    return entries


CREATE_REQUIRE_BINDING = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]+\.)?createRequire\s*\(")


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
        expr = " ".join(src.text[first[0][1]:first[-1][2]].split()) if first else ""
        yield expr, first, o + 1


def scan(repo: Path, cfg: dict, *, manifest_root: Path | None = None, revision: str | None = None,
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
    # LC_ALL=C: under a UTF-8 locale `git grep -E` stops matching a line after an invalid UTF-8 byte, so a root mention
    # later on that line was never seen. The pattern is ASCII, so byte semantics lose nothing.
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "--null", "-n", "-I", "-E", pattern,
                          *([revision] if revision else []), "--", ".", *excludes],
                         capture_output=True, timeout=15, env={**environment, "LC_ALL": "C"})
    if out.returncode not in (0, 1):
        raise SystemExit(f"edges: git grep failed (exit {out.returncode})")
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

    def relative_target(path: str, spec: str) -> str | None:
        """`spec` resolved from `path`'s directory: the package that owns it, or None (recorded as an edge when it
        stays inside the repository)."""
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        found = owner(target)
        if found is None and target not in (".", "..") and not target.startswith("../"):
            edges.setdefault(path, set()).add(target)
        return found

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
                    targets.add(relative_target(path, m.group(1)))
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
            for m in rel.finditer(t):
                targets.add(relative_target(path, m.group(1)))
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
    imports, unused = import_closure(repo, es, roots, owner, by_dir, revision, environment, excludes, always, edges,
                                     outside, deps)
    if report is not None:
        report["imports"] = {path: sorted(found) for path, found in sorted(imports.items())}
        report["computed_imports_unused"] = unused
    return deps, readers


def import_closure(repo, es, roots, owner, by_dir, revision, environment, excludes, always, edges, outside, deps):
    """Rules 1-4 of 1.5.0: credit each package with the reads of the files outside every package it reaches. Returns
    ({path: importing packages}, [computed_imports entries that matched no site]); refuses where it cannot see."""
    tracked = tracked_paths(repo, revision, environment)
    package_tops = {d.split("/")[0] for d in by_dir} | set(roots)
    # Top-level directories outside every package: the tracked ones, and every declared reader directory.
    outside_tops = ({p.split("/")[0] for p in tracked if "/" in p} | set(es.get("reader_dirs") or [])) - package_tops
    named_tops = outside_tops | set(roots)  # what an unevaluated path may not name (rule 6)
    patterns = [x[2:] for x in excludes if x.startswith(":!")]

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
        target = resolve_links(target)
        if target in tracked:
            return [target]
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

    def call_args(src: Source, o: int) -> list[list] | None:
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

        pardir = any(t[0] == "word" and t[3] == "pardir" for t in tokens)
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
                if not rest and c == at + len(tokens) - 1:
                    return "literal", target  # every component literal: a literal import, resolved and mapped
                if not any(steps_up(x) for x in lits):
                    return "none", None
                return ("inside", None) if inside(target) else ("escape", None)
        # Nothing anchors it at the file: any parent step escapes, and so does naming an outside top-level directory.
        if pardir or any(t[0] == "str" and steps_up(t[3][0]) for t in tokens):
            return "escape", None
        if any(t[0] == "str" and re.sub(r"^(?:\./|\$\{[^}]*\}/)+", "", t[3][0]).split("/")[0] in outside_tops
               for t in tokens):
            return "escape", None
        return "none", None

    declared = es.get("computed_imports")
    if declared is None:
        declared = []
    if not isinstance(declared, list) or any(
            not isinstance(d, dict) or set(d) != {"file", "expr", "reach"} or not isinstance(d["file"], str)
            or not isinstance(d["expr"], str)
            or not (d["reach"] in COMPUTED_REACH if isinstance(d["reach"], str) else
                    isinstance(d["reach"], list) and d["reach"] and all(isinstance(x, str) and x for x in d["reach"]))
            for d in declared):
        raise ValueError("edge_scan.computed_imports entries must be {file, expr, reach}, with reach package, external, "
                         "fixture or a non-empty list of repo paths")
    by_site = {(d["file"], " ".join(d["expr"].split())): d for d in declared}
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
        def reaches(target: str) -> None:
            found = owner(target)
            if found is None:
                edges.setdefault(path, set()).add(target)
            elif found != owner(path) and owner(path) is not None:
                deps[owner(path)].add(found)

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
            if verdict == "inside" and entry["reach"] != "package":
                raise ValueError(f"unresolved (a computed import whose parent step stays in its package, `{expr}`, must be "
                                 f"declared reach \"package\") in {path}")
            used.add((path, expr))
            if isinstance(entry["reach"], list):
                for target in entry["reach"]:
                    reaches(posixpath.normpath(target))

    # Every computed import in a package's own code: a dedicated grep, since such a line names no root and no `../`.
    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                          IMPORT_CALL_GREP, *([revision] if revision else []), "--",
                          *[f"*.{e}" for e in sorted(JS_EXT)], *excludes],
                         capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    if out.returncode not in (0, 1):
        raise SystemExit(f"edges: git grep failed (exit {out.returncode})")
    for path in out.stdout.decode("utf-8", errors="replace").split("\0"):
        if path and revision:
            path = path[len(revision) + 1:]
        if path and owner(path) is not None:
            check_computed(path)

    def named_paths(path: str) -> set[str]:
        """Rule 1, the whole file: every relative path a reached code file names."""
        here, found = posixpath.dirname(path), set()
        src = code_source(path)
        if src is not None:
            if not src.ok:
                raise ValueError(f"unresolved (the bracket structure of {path}, a file a package reaches, cannot be "
                                 "trusted)")
            for t in src.code:
                if t[0] == "str" and t[3][1] is True and t[3][0].startswith(("./", "../")):
                    found.add(posixpath.normpath(posixpath.join(here, t[3][0])))
            if src.py:
                _, loaded, sites = python_file_facts(src.text, path)
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
        for line in read_source(repo, path, revision, environment).split("\n"):
            t = line.strip()
            if t.startswith("#"):
                continue
            for pattern in (SHELL_RELATIVE, SHELL_SELF_DIR):
                for m in pattern.finditer(t):
                    spec = m.group(1) if pattern is SHELL_RELATIVE else "./" + m.group(1)
                    found.add(posixpath.normpath(posixpath.join(here, spec)))
        return found

    def is_code(path: str) -> bool:
        ext = posixpath.splitext(path)[1].lstrip(".").lower()
        if ext in CODE_EXT:
            return True
        if ext:
            return False
        head = read_source(repo, path, revision, environment)[:200]
        return head.startswith("#!") and re.search(r"\b(?:ba|z|da)?sh\b|\bnode\b|\bpython", head.split("\n")[0]) is not None

    # 1.5.1: a package's Python import path (sys.path entries, its pytest `pythonpath`) and its Python loaders by name or
    # path (python_file_facts), before the closure walks the edges.
    def reach_from(path: str, target: str) -> None:
        found = owner(target)
        if found is None:
            edges.setdefault(path, set()).add(target)
        elif found != owner(path) and owner(path) is not None:
            deps[owner(path)].add(found)

    def escapes_by_text(expr: str) -> bool:
        literals = re.findall(r"""["']([^"']*)["']""", expr)
        return bool(PARENT_STEP.search(expr)) or any(re.sub(r"^(?:\./)+", "", s).split("/")[0] in named_tops for s in literals)

    def check_python_sites(path: str, sites) -> None:
        """Rule 4 for Python's loaders: an evaluated path is a literal load; anything else is declared or refuses."""
        for kind, expr, target in sites:
            if kind == "path" and target is not None:
                if not (target == ".." or target.startswith("../")):
                    reach_from(path, target)
                continue
            if kind == "path" and escapes_by_text(expr):
                raise ValueError(f"unresolved (a computed Python load that may leave its package, `{expr}`) in {path}; "
                                 "write it from __file__ with literal parts, which the scan maps")
            entry = by_site.get((path, expr))
            if entry is None:
                raise ValueError(f"unresolved (an undeclared computed import `{expr}`; declare it in "
                                 f"edge_scan.computed_imports) in {path}")
            used.add((path, expr))
            if isinstance(entry["reach"], list):
                for target in entry["reach"]:
                    reach_from(path, posixpath.normpath(target))

    outside_entries: dict[str, list[tuple[str, str]]] = {}  # package -> [(the edge's source path, a directory)]
    parsed_names: dict[str, set[str]] = {}  # package -> names its parsed files import, loop literals included

    def apply_entry(package: str, source: str, kind: str, value: str, where: str, what: str = "sys.path entry") -> None:
        if kind == "unknown":
            if escapes_by_text(value):
                raise ValueError(f"unresolved (a {what} that may leave its package, `{value}`, cannot be evaluated) "
                                 f"in {where}")
            return  # an entry naming no parent step and no top-level directory: a documented residual
        if value == ".." or value.startswith("../"):
            return  # above the repository: nothing tracked is imported from there
        found = owner(value)
        if found == package:
            return
        if found is not None:
            deps[package].add(found)  # modules imported by name from another package's directory
            return
        outside_entries.setdefault(package, []).append((source, value))

    out = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-l", "-z", "-I", "-E",
                          PY_FACTS_GREP, *([revision] if revision else []), "--", "*.py", *excludes],
                         capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
    if out.returncode not in (0, 1):
        raise SystemExit(f"edges: git grep failed (exit {out.returncode})")
    for path in sorted(p[len(revision) + 1:] if revision else p for p in out.stdout.decode("utf-8", errors="replace").split("\0") if p):
        package = owner(path)
        if package is None:
            continue
        entries, file_names, sites = python_file_facts(read_source(repo, path, revision, environment), path)
        parsed_names.setdefault(package, set()).update(file_names)
        for kind, value in entries:
            apply_entry(package, path, kind, value, path)
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
    tracked_dirs = {posixpath.dirname(p) for p in tracked}
    for d in list(tracked_dirs):
        while d:
            d = posixpath.dirname(d)
            tracked_dirs.add(d)
    for package, entries in sorted(outside_entries.items()):
        # Every top-level name the package's Python files import; one grep per package, not one parse per file. A
        # pathspec `*` crosses `/`, so this reaches every Python file beneath the package directory.
        found = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "grep", "--no-color", "-h", "-I", "-E",
                                r"^[[:space:]]*(import|from)[[:space:]]|import_module\(|__import__\(|run_module\(",
                                *([revision] if revision else []), "--", f"{package_dir[package]}/*.py"],
                               capture_output=True, timeout=60, env={**environment, "LC_ALL": "C"})
        if found.returncode not in (0, 1):
            raise SystemExit(f"edges: git grep failed (exit {found.returncode})")
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
    named: dict[str, set[str]] = {}
    for package in sorted({owner(p) for p in edges} - {None}):
        queue = sorted({t for p, ts in edges.items() if owner(p) == package for t in ts})
        seen: set = set()
        while queue:
            target = queue.pop(0)
            if target in seen:
                continue
            seen.add(target)
            for path in files_of(target):
                found = owner(path)
                if found is not None:
                    if found != package:
                        deps[package].add(found)  # a package nested in a reached directory, or a link into one
                    continue
                imports.setdefault(path, set()).add(package)
                if any(path == d or path.startswith(d + "/") for d in always):
                    raise ValueError(f"unresolved ({package} reaches {path}, under edge_scan.always_reader_dirs: that "
                                     "directory is not always-only)")
                if path.lower().endswith(".md"):
                    continue
                code = is_code(path)
                if excluded(path):
                    if code:
                        raise ValueError(f"unresolved ({package} reaches {path}, code the scan excludes, so its reads "
                                         "cannot be credited)")
                    continue
                deps[package] |= outside.get(path, set()) - {package}
                if code:
                    if path not in named:
                        named[path] = named_paths(path) | edges.get(path, set())
                    queue.extend(sorted(named[path] - seen))
    unused = [f"{d['file']}: {d['expr']}" for d in declared if (d["file"], " ".join(d["expr"].split())) not in used]
    return imports, unused


def assess(pkgs: dict, cfg: dict, deps: dict, readers: dict, *, revision: str | None, config_path: Path,
           imports: dict | None = None, computed_unused: list | None = None) -> dict:
    failures, stale = [], []
    imports = imports or {}
    # 1.5.0 rule 5: a change to an imported file must select its importers, so extra_edges must map it to them.
    edge_globs = [(glob_to_regex(glob), set(targets)) for glob, targets in sorted((cfg.get("extra_edges") or {}).items())]
    for path, importers in sorted(imports.items()):
        mapped = set().union(*[targets for regex, targets in edge_globs if regex.match(path)])
        for name in sorted(set(importers) - mapped):
            failures.append(f"undeclared import edge: {name} imports {path} (map it in extra_edges, so a change to it "
                            f"selects {name})")
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
    report: dict = {}
    deps, readers = scan(repo, cfg, manifest_root=manifest_root, revision=a.revision, report=report)
    if a.mode == "derive":
        print(json.dumps({"deps": {k: sorted(v) for k, v in sorted(deps.items())},
                          "readers": {k: sorted(v) for k, v in sorted(readers.items())},
                          "imports": report["imports"]}, indent=1))
        return 0
    pkgs = workspace_graph(manifest_root, cfg)
    assessment = assess(pkgs, cfg, deps, readers, revision=a.revision, config_path=repo / a.config,
                        imports=report["imports"], computed_unused=report["computed_imports_unused"])
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
