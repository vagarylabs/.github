#!/usr/bin/env python3
"""test-bounds (K2): the ONE shared check that test code does not bound a wait with a short wall-clock value.

THE CLASS (F5). A test waits for a condition, caps a case or a hook, or gives a child process a deadline, with a
number of seconds or milliseconds. Below a hang guard's size, that number measures the runner's load, not the
behaviour, and a loaded runner turns it into a red. A correctness bound is a hang guard (a value at or above its
kind's floor, normally a named constant). Three repository gates held this class with three engines (vagaris
check-test-bounds-are-hang-guards.mjs, vagary-core test_ci_test_pg.py, vps-ansible test_subprocess_hang_guards.py);
this check replaces them, and each adoption PR declares what it retires.

ENGINE. ast-grep (pinned, rules in rules/) MATCHES the bound positions COVERED lists and captures each value; it
runs isolated from the consumer's sgconfig.yml, and a sentinel rule must parse every scanned file exactly once (a
skipped file, such as one holding non-UTF-8 bytes, is red). This module is the post-pass. It may only CLEAR a match
on positive proof:
  - the value evaluates EXACTLY to at least the kind's floor (FLOORS_S). Exact evaluation accepts numeric literals
    (with `_`), unary minus, and + - * of those, and nothing else. Division, templates, calls, environment reads and
    legacy octal (`0210000`) are not evaluated, so they stay findings;
  - or the value is a NAME, resolved in ONE hop (root's GO 10-31: "resolver: one hop, four guards"):
      a same-file top-level `const NAME = <literal expr>` (Python: a module-level `NAME = <literal expr>`), or a
      direct named import from a RELATIVE path (`import { NAME } from "./x"`, `{ X as NAME }`; Python
      `from .x import NAME`) whose one target file holds `export const NAME = <literal expr>` (Python: the one
      module-level assignment). Guards: (1) NAME is bound nowhere else in the consuming file, in any scope; (2)
      exactly one binding at the source; (3) the exact evaluation above; (4) the relative path resolves to exactly
      one tracked file. Re-exports, namespace, default and package imports, a package directory, a Python star
      import in either file (it may bind any name), and anything longer than one hop stay findings;
  - or the hook belongs to a declared LAUNCHER class (config `launchers`): a hook whose first argument calls a
    launcher imported, by the same one-hop rule, from the declared module, judged against the launcher's own floor
    (vagaris: embedded Postgres owns a 180 s startup, so its beforeAll needs 210 000 ms, below the 240 s hook floor);
  - or the line carries a mark `timeout under test: <what it proves>` (the line its own text is on). A mark is
    never silent: every mark is listed, a bound this change newly exempts is listed as NEW, and classify.py's FL-4
    report lists every added mark. A mark without a reason (a word of three letters) clears nothing.

SCOPE. The configuration lives in the consumer's .github/test-bounds.baseline.json (CODEOWNERS-reviewed): `trees`
(globs, each with a `min_files` floor, a positive control on the glob), `exclude`, `launchers`, and `counts`. A file
in a tree is scanned when its language is covered (.ts .mts .cts .tsx .js .mjs .cjs .jsx .py); a tree file in any
other language is listed as UNSCANNED, and so is a test-like file outside every tree. An unparsable scanned file is a
red, never a skip.

BASELINE (shrink-only, per file and rule; the vagaris ratchet's semantics, root R4'd on #849). With a BASE commit:
  - the files the change TOUCHES (`git diff -M30% -C30% <base> HEAD`) are judged against the base's ACTUAL findings,
    read from the base's blobs, by rename/split GROUP: a group's findings may not outnumber what its old paths held;
  - the committed count of a touched file must cover its findings; a count above them (a gain) fails a
    pull_request until --write-baseline locks it in, and is a notice on merge_group and push;
  - an untouched file is judged against the committed count, and the committed counts may not RAISE an untouched
    file against the base's;
  - the CONFIGURATION is judged from the base: a file the base's trees cover that the candidate's do not, a tree
    removed or given a lower min_files, a launcher added or lowered, or a test file renamed out of the trees, is a
    red. A change cannot narrow what is scanned or how it is judged; it can only widen it.
THE BASE. On pull_request and merge_group it is the event's (GITHUB_EVENT_PATH), and the `--base` input must name it:
empty, another commit, or the head is refused, so the candidate workflow cannot switch these checks off. On push and
workflow_dispatch the input is taken as given; without a base, every file is judged against the committed counts and
the run says so. In Actions the event is GITHUB_EVENT_NAME, never a flag.

SELF-TEST. Every run first runs the planted fixtures (fixtures/<case>/, each with expect.json): every rule's RED
must produce exactly its expected findings and every GREEN none, so a gutted rule or resolver fails the check itself.

Usage (exit 0 clean, 1 refused, 2 usage or tool error):
  check.py check [--root DIR] [--base SHA] [--event NAME (local runs only)] [--findings FILE]
  check.py write-baseline [--root DIR] [--base SHA] [--seed]
  check.py self-test
The ast-grep binary is $TEST_BOUNDS_SG (default `ast-grep` on PATH).
"""
from __future__ import annotations

import argparse
import ast
import configparser
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # importing the planner must not leave a .pyc in the action's checkout
sys.path.insert(0, str(HERE.parent / "change-impact-plan"))
from plan import glob_to_regex  # noqa: E402  the org's one glob semantics, shared with the planner

SCHEMA = 1
CHECK_ID = "vagarylabs/.github/actions/test-bounds"
BASELINE_PATH = ".github/test-bounds.baseline.json"
RULE = "literal-bound"
# Floors in seconds, per kind (root's K2 GO 10-31). JS/TS values are milliseconds, Python values seconds.
# fixture: a test fixture's client timeout (PostgreSQL connect/pool), at vagary-core #949's 120 s readiness floor.
FLOORS_S = {"case": 120, "hook": 240, "condition": 60, "subprocess": 120, "fixture": 120}
LANGUAGE_OF = {".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
               ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".py": "python"}
UNIT = {"typescript": 1000, "tsx": 1000, "javascript": 1000, "python": 1}
JS_LANGS = ("typescript", "tsx", "javascript")
RULE_FILES = {"typescript": "literal-bound.yml", "tsx": "literal-bound.yml", "javascript": "literal-bound.yml",
              "python": "literal-bound.py.yml"}
# Rules whose matched node is the bound itself (a pair, a parameter, a keyword): a mark may sit on its first line.
SMALL_MATCH = {"option", "default", "config", "keyword"}
MARK = re.compile(r"timeout under test:[ \t]*(?P<why>[^\n]*)")
# A mark clears only with a reason: at least one word of three letters ("..." or "x" is not a reason).
REASON = re.compile(r"[A-Za-z]{3,}")
SIMILARITY = "30%"
# Test-like paths, for the UNSCANNED list only (never for scope: the trees decide that).
TEST_LIKE = re.compile(r"(?:^|/)(?:[^/]+\.(?:test|spec)\.[^/]+|test_[^/]+\.py|[^/]+_test\.(?:py|go)|[^/]+\.bats"
                       r"|conftest\.py|(?:vite|vitest|jest|playwright)\.config\.[^/]+|\.?pytest\.ini|\.?pytest\.toml|pyproject\.toml|setup\.cfg|tox\.ini)$"
                       r"|(?:^|/)(?:__tests__|tests?)/[^/]+$")
# What each language's rules read, printed with every run so a consumer never reads absence as clean (root's #60 R4).
COVERED = {
    "ts/tsx/js": "the `timeout` option of a call (its kind from the callee: it/test/bench/describe*, hooks, child "
                 "processes by name or through an aliased import, destructured require or promisify, any other call); "
                 "the last argument of it/test/bench/describe* and of hooks; "
                 "vi.waitFor/vi.waitUntil; a parameter default named timeout/deadline/budget; testTimeout, "
                 "hookTimeout and teardownTimeout properties; PostgreSQL client options (connectionTimeoutMillis, "
                 "statement_timeout, query_timeout)",
    "py": "subprocess timeouts (`timeout=` of run/check_output/check_call/call/Popen/communicate/wait, wait(N), "
          "communicate(input, N), a `timeout` parameter default); thread and process join (a positional name or "
          "arithmetic only when it resolves to a number, since str.join takes one). Read by binding, with Python's "
          "scoping (the nearest enclosing scope that binds a name decides): `import x as y`, `from x import y` (in any "
          "scope), a star import of a covered module, a re-export from a local module (one hop), a submodule or "
          "vendored spelling (`requests.api.get`, `asyncio.tasks.wait_for`), and a client instance (an assignment, "
          "an annotated assignment, a walrus, `with ... as c`, a class body or `self.s = ...`, "
          "`requests.Session().get`, one a local module builds): asyncio.wait_for, asyncio.wait and asyncio.timeout, "
          "async_timeout.timeout (condition); urllib.request.urlopen and the requests/httpx functions, Session and "
          "Client methods and constructors, each element of a `timeout=(connect, read)` tuple (condition); "
          "asyncpg, psycopg, psycopg2 and psycopg_pool timeout/connect_timeout/command_timeout (fixture); "
          "pytest.mark.timeout (case). A literal 0 is \"no limit\" only for pytest-timeout and libpq's "
          "connect_timeout (psycopg, psycopg2); asyncpg's and psycopg_pool's 0 is an instant timeout, a finding. "
          "NOT COVERED, listed per call: a bound that may come through a `*` or `**` splat; a name an import and "
          "another binding share in one scope, or a declared global/nonlocal; a covered name imported from a local "
          "module one hop cannot read, or possibly bound by another module's star import; a call into a covered "
          "library this check does not read, or one reached through getattr, importlib.import_module or "
          "functools.partial; any aiohttp call with a bound keyword (aiohttp is not read yet). NOT READ, and not "
          "listed: a client that is a fixture or parameter, a factory's return value, or held in a container; a "
          "method alias (`g = s.get`); a module bound by importlib/pytest.importorskip to a name",
    "pytest config": "pytest-timeout's `timeout` and addopts `--timeout` in pytest.ini, .pytest.ini, tox.ini, "
                     "setup.cfg, pyproject.toml (`[tool.pytest.ini_options]` and pytest 9's `[tool.pytest]`), "
                     "pytest.toml and .pytest.toml (when a tree covers the file)",
    "not yet (K2 step 2)": "fixed flushes, sleep-as-wait, poll budgets, read and absence windows, elapsed-time "
                           "asserts",
}

JS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
# pytest's own config files, read in Python (ast-grep does not parse INI or TOML): pytest-timeout's `timeout` default,
# and `--timeout` in `addopts`, are case bounds. The section each file keeps pytest's options in (pyproject: TOML).
# pytest 9 also reads `pytest.toml` / `.pytest.toml` (a `[pytest]` TOML table), `.pytest.ini`, and a native
# `[tool.pytest]` table in pyproject.toml beside the legacy `[tool.pytest.ini_options]` (root's #65 RC B1).
PYTEST_CONFIGS = {"pytest.ini": "pytest", ".pytest.ini": "pytest", "tox.ini": "pytest", "setup.cfg": "tool:pytest",
                  "pyproject.toml": None, "pytest.toml": None, ".pytest.toml": None}
# JS/TS positions where a literal 0 means "no limit" (node-postgres' connectionTimeoutMillis, statement_timeout and
# query_timeout): compliant, not a bound (root's #65 RC L1). Python marks each such value in the binding pass
# (pytest.mark.timeout, libpq's connect_timeout: LIBPQ_CONNECT), and the pytest config reader skips its own. A NAME
# resolving to 0 is still judged.
ZERO_IS_NONE = {"client"}
JS_TWIN = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
NAME = re.compile(r"^[A-Za-z_$][\w$]*$")
# Child-process launchers, by module, for resolving an aliased callee (rules/literal-bound.yml names them directly).
CHILD_PROCESS = {"child_process": {"spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"},
                 "execa": {"execa", "execaSync", "execaCommand", "execaCommandSync", "execaNode", "$"}}
CHILD_PROCESS["node:child_process"] = CHILD_PROCESS["child_process"]
SUBPROCESS_NAMES = set().union(*CHILD_PROCESS.values())
SG_BATCH = 400


def check_digest() -> str:
    """The digest of what this check DETECTS: check.py, its rules, and the glob semantics it scopes by. A baseline
    records the digest it was written under (K2 D8, guard 1): a raise is only ever allowed in a change whose check
    detects differently from the one the base's baseline was written by."""
    h = hashlib.sha256()
    for path in [HERE / "check.py", *sorted((HERE / "rules").glob("*.yml")), HERE.parent / "change-impact-plan" / "plan.py"]:
        h.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    lock = HERE.parent.parent / "release-assets.lock"  # the ast-grep binary the action runs is part of the detection
    if lock.exists():
        pins = [line for line in lock.read_text(encoding="utf-8").splitlines() if line.startswith("ast-grep ")]
        h.update(b"ast-grep\0" + "\n".join(pins).encode() + b"\0")
    return h.hexdigest()


ACTION_PIN = re.compile(r"^vagarylabs/\.github/actions/test-bounds@([0-9a-f]{40})$")


def job_action_pins(text: str, job: str | None) -> list[str]:
    """The refs this check is pinned at by the step `uses:` of one job (or of every job, when `job` is None) in a
    workflow's text: only a step's own `uses:` key counts, never a comment, a `run:` body or a block scalar (D8 guard
    1, root's #68 delta B2'). A form this reader does not parse yields no pin, so the guard fails SAFE: no lock-in,
    and the pin bump is red until its findings are fixed."""
    pins, in_jobs, job_indent, cur_job, steps_indent, step_prop, block = [], False, None, None, None, None, None
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if block is not None:
            if indent > block:
                continue  # block scalar content
            block = None
        if indent == 0:
            in_jobs, cur_job, steps_indent, step_prop = stripped == "jobs:", None, None, None
            continue
        if not in_jobs:
            continue
        if job_indent is None and re.fullmatch(r"[A-Za-z_][\w-]*:\s*", stripped):
            job_indent = indent
        if indent == job_indent and re.match(r"[A-Za-z_][\w-]*:", stripped):
            cur_job, steps_indent, step_prop = stripped.split(":", 1)[0], None, None
            continue
        if cur_job is None or (job is not None and cur_job != job):
            continue
        if stripped == "steps:":
            steps_indent, step_prop = indent, None
            continue
        if steps_indent is None or indent <= steps_indent:
            continue
        key_text = stripped
        if stripped.startswith("- "):
            step_prop = indent + 2
            key_text = stripped[2:].lstrip()
        elif indent != step_prop:
            m = re.match(r"([A-Za-z_][\w-]*):\s*[|>][-+0-9]*\s*$", stripped)
            if m:
                block = indent
            continue
        m = re.match(r"([A-Za-z_][\w-]*):\s*(.*)$", key_text)
        if not m:
            continue
        value = re.sub(r"\s+#.*$", "", m.group(2)).strip().strip("'\"")
        if re.match(r"[|>][-+0-9]*$", value):
            block = step_prop
            continue
        if m.group(1) == "uses":
            pm = ACTION_PIN.match(value)
            if pm:
                pins.append(pm.group(1))
    return pins


def running_context(env: dict, here: Path = HERE) -> tuple[str, str, str] | None:
    """(workflow path, job id, this action's ref) of the Actions run executing this check, or None. The ref is read
    from where the runner put this action (`_actions/vagarylabs/.github/<ref>/...`), and the workflow and job from
    GITHUB_WORKFLOW_REF and GITHUB_JOB, which GitHub documents a step cannot overwrite through $GITHUB_ENV. They must
    equal TB_CTX_WORKFLOW_REF and TB_CTX_JOB, which action.yml sets from the `github` context (an expression no step
    can write): a write to either source makes the context unreadable, so no debt is locked in (#68 delta 2 LOW)."""
    parts = here.parts
    if "_actions" not in parts:
        return None
    i = parts.index("_actions")
    if parts[i + 1:i + 3] != ("vagarylabs", ".github") or not re.fullmatch(r"[0-9a-f]{40}", parts[i + 3] if len(parts) > i + 3 else ""):
        return None
    wref, job = env.get("GITHUB_WORKFLOW_REF", ""), env.get("GITHUB_JOB", "")
    if (wref, job) != (env.get("TB_CTX_WORKFLOW_REF", ""), env.get("TB_CTX_JOB", "")):
        return None
    m = re.fullmatch(r"[^/]+/[^/]+/(\.github/workflows/[^@]+)@.+", wref)
    if not (m and job):
        return None
    return m.group(1), job, parts[i + 3]


PIN_NOT_MOVED = "this change does not move the check's pin, so there is no new debt to lock in"


def lock_in_refusal(root: Path, change: dict | None, running: tuple[str, str, str] | None, in_actions: bool,
                    digest: str) -> str | None:
    """D8 guard 1 (root's #68 rulings): None when this change is a DETECTION change, which may lock debt in; else why
    it is not. Both must hold (root's tightening, delta 2): (a) the running job's pin moved, and (b) the base
    baseline's recorded check_digest is not the running check's. A base baseline with no digest was written by a check
    from before digests, so it differs. In Actions an unreadable running context locks nothing in (B1'')."""
    if not change or change["base_cfg"] is None:
        return PIN_NOT_MOVED
    if in_actions and running is None:
        return ("the running check's context is unreadable (an action run from a workspace checkout or pinned by a "
                "tag, a reusable workflow, or GITHUB_WORKFLOW_REF / GITHUB_JOB missing or not the github context's), "
                "so no pin move is proven and no debt is locked in")
    if not pin_moved(root, change["sha"], running):
        return PIN_NOT_MOVED
    if change["base_cfg"].get("check_digest") == digest:
        return ("this change moves the pin to a check that detects identically (the base baseline's check_digest is "
                "the running check's), so there is no new debt to lock in")
    return None


def pin_moved(root: Path, base: str, running: tuple[str, str, str] | None) -> bool:
    """D8 guard 1: this change moves the check's pin. In Actions: the running job's one test-bounds step pins the
    running action's ref at the head, and pinned another ref at the base. Outside Actions (write-baseline, a local
    check): the pins of every job differ between base and head; CI then judges the strict form."""
    def at_base(path: str) -> str:
        r = subprocess.run(["git", "show", f"{base}:{path}"], cwd=root, capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else ""
    if running is not None:
        wf, job, ref = running
        head_text = (root / wf).read_text(encoding="utf-8") if (root / wf).is_file() else ""
        head_pins, base_pins = job_action_pins(head_text, job), job_action_pins(at_base(wf), job)
        return head_pins == [ref] and len(base_pins) == 1 and base_pins[0] != ref
    head, before = set(), set()
    for f in tracked_files(root):
        if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")):
            head |= set(job_action_pins((root / f).read_text(encoding="utf-8"), None))
            before |= set(job_action_pins(at_base(f), None))
    return bool(head) and head != before


class Refusal(Exception):
    """A configuration or input this check cannot judge: the run fails (exit 2), never passes."""


# --- exact evaluation (guard 3) ----------------------------------------------------------------------------------

_NUM = re.compile(r"(?:0|[1-9](?:_?\d)*)(?:\.(?:\d(?:_?\d)*)?)?(?:[eE][+-]?\d(?:_?\d)*)?(?![\w$.])"
                  r"|\.\d(?:_?\d)*(?:[eE][+-]?\d(?:_?\d)*)?(?![\w$.])")


def evaluate_js(text: str) -> Fraction | None:
    """The exact value of a JS/TS literal expression: numbers, unary minus, + - * and parentheses; else None."""
    s, i = text, 0

    def skip():
        nonlocal i
        while i < len(s) and s[i] in " \t\r\n":
            i += 1

    def primary():
        nonlocal i
        skip()
        if i < len(s) and s[i] == "(":
            i += 1
            v = expr()
            skip()
            if v is None or i >= len(s) or s[i] != ")":
                return None
            i += 1
            return v
        m = _NUM.match(s, i)
        if not m:
            return None
        i = m.end()
        return Fraction(m.group().replace("_", ""))

    def unary():
        nonlocal i
        skip()
        if i < len(s) and s[i] == "-":
            i += 1
            v = unary()
            return None if v is None else -v
        return primary()

    def term():
        nonlocal i
        v = unary()
        while v is not None:
            skip()
            if i < len(s) and s[i] == "*" and not s.startswith("**", i):
                i += 1
                w = unary()
                v = None if w is None else v * w
            else:
                break
        return v

    def expr():
        nonlocal i
        v = term()
        while v is not None:
            skip()
            if i < len(s) and s[i] in "+-":
                op = s[i]
                i += 1
                w = term()
                v = None if w is None else (v + w if op == "+" else v - w)
            else:
                break
        return v

    v = expr()
    skip()
    return v if v is not None and i == len(s) else None


def evaluate_py_node(node: ast.AST, source: str) -> Fraction | None:
    """The exact value of a Python literal expression node: int/float constants, unary minus, + - *; else None."""
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        seg = ast.get_source_segment(source, node)
        if seg is None or not re.fullmatch(r"[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?|\.[0-9][0-9_]*", seg):
            return None  # hex, octal, binary and complex literals are not evaluated
        return Fraction(seg.replace("_", ""))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = evaluate_py_node(node.operand, source)
        return None if v is None else -v
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        a, b = evaluate_py_node(node.left, source), evaluate_py_node(node.right, source)
        if a is None or b is None:
            return None
        return a + b if isinstance(node.op, ast.Add) else a - b if isinstance(node.op, ast.Sub) else a * b
    return None


def evaluate_py(text: str) -> Fraction | None:
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError:
        return None
    return evaluate_py_node(tree.body, text.strip())


# --- ast-grep ------------------------------------------------------------------------------------------------------

_TAG = re.compile(r"\s*#\[([a-z,]+)\]\s*$")


def _keep(text: str, lang: str) -> str:
    out = []
    for line in text.splitlines(True):
        m = _TAG.search(line)
        if m is None:
            out.append(line)
        elif lang in m.group(1).split(","):
            out.append(_TAG.sub("", line.rstrip("\n")) + "\n")
    return "".join(out)


def compose_rules(lang: str, extra: list[str] = ()) -> str:
    """Every rule of rules/<file> for one language: its language line set, its utils appended, tagged lines kept."""
    docs = re.split(r"(?m)^---[ \t]*$", (HERE / "rules" / RULE_FILES[lang]).read_text(encoding="utf-8"))
    head = docs[0]
    if "utils:" not in head:
        raise Refusal(f"rules/{RULE_FILES[lang]}: the first document must hold the utils")
    utils = _keep(head[head.index("utils:"):], lang)
    out = []
    for doc in list(docs[1:]) + list(extra):
        doc = re.sub(r"(?m)^language: \w+$", "language: " + lang, doc.strip("\n"))
        if not re.search(r"(?m)^id: ", doc):
            raise Refusal("a rule document has no id")
        out.append(_keep(doc, lang) + "\n" + utils)
    # tree-sitter recovers from what its grammar lacks (vagaris: `f<typeof import("x")>()`). An ERROR holding no
    # identifier or digit, or lying inside a string, cannot hide a bound: it is RECOVERED and listed. Any other ERROR
    # is a red (root's R2, 10-31; tree-sitter-typescript #367 is the upstream gap).
    # The string excuse never reaches into code a template or f-string interpolates (root's #60 R4 L1).
    code = "template_substitution" if lang in JS_LANGS else "interpolation"
    template = "template_string" if lang in JS_LANGS else "string"
    out.append(f"id: parse-error\nlanguage: {lang}\nrule:\n  kind: ERROR\n  regex: \"[A-Za-z0-9_$]\"\n"
               f"  not:\n    any:\n      - inside: {{ stopBy: end, kind: string, not: {{ has: {{ stopBy: end, kind: {code} }} }} }}\n"
               f"      - all:\n          - inside: {{ stopBy: end, kind: {template} }}\n"
               f"          - not: {{ inside: {{ stopBy: end, kind: {code} }} }}")
    out.append(f"id: recovered\nlanguage: {lang}\nrule: {{ kind: ERROR }}")
    # The per-file positive control (B1): every scanned file must be parsed, so its root node must match once. A file
    # ast-grep skips (non-UTF-8 bytes, or a language mapping that hides it) never reads as clean.
    out.append(f"id: sentinel\nlanguage: {lang}\nrule: {{ kind: {'module' if lang == 'python' else 'program'} }}")
    out.append(f"id: mark\nlanguage: {lang}\nrule: {{ kind: comment, regex: \"timeout under test:\" }}")
    return "\n---\n".join(out) + "\n"


def sg_binary() -> str:
    sg = os.environ.get("TEST_BOUNDS_SG") or shutil.which("ast-grep")
    if not sg:
        raise Refusal("ast-grep not found: set TEST_BOUNDS_SG (the action fetches the pinned binary)")
    return sg


def sg_scan(root: Path, rules_text: str, files: list[str], _cwd: Path | None = None) -> list[dict]:
    """Every match of the rules over `files` (repo-relative, under root). A tool failure raises: fail closed.

    ast-grep runs ISOLATED from the consumer (root's #60 R4 B2): from a private directory, under this action's own
    empty sgconfig.yml, on absolute paths. ast-grep finds a configuration from its working directory upward, and a
    consumer's `languageGlobs` would otherwise re-map, and so hide, the files it scans."""
    if not files:
        return []
    sg = sg_binary()
    root = root.resolve()
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "rules.yml"
        rules.write_text(rules_text, encoding="utf-8")
        config = Path(tmp) / "sgconfig.yml"
        config.write_text("ruleDirs: []\n", encoding="utf-8")
        for i in range(0, len(files), SG_BATCH):
            batch = [str(root / f) for f in files[i:i + SG_BATCH]]
            # Streamed, one JSON object per "\n"-terminated line. Never str.splitlines(): it also splits on U+2028,
            # which a match's text may hold raw (valid JSON), and the sentinel's match is a whole file.
            with tempfile.TemporaryFile() as err:
                p = subprocess.Popen([sg, "scan", "-c", str(config), "-r", str(rules), "--json=stream", "--no-ignore",
                                      "hidden", "--no-ignore", "dot", "--no-ignore", "vcs", "--no-ignore", "parent",
                                      "--", *batch], cwd=_cwd or tmp, stdout=subprocess.PIPE, stderr=err)
                for raw in p.stdout:
                    if not raw.strip():
                        continue
                    m = json.loads(raw.decode("utf-8"))
                    m["file"] = Path(m["file"]).resolve().relative_to(root).as_posix()
                    if m["ruleId"] == "sentinel":
                        m = {"ruleId": "sentinel", "file": m["file"]}  # the file is all it proves; drop its text
                    out.append(m)
                rc = p.wait()
                if rc != 0:
                    err.seek(0)
                    raise Refusal(f"ast-grep scan exited {rc}: {err.read().decode('utf-8', 'replace').strip()[:400]}")
    return out


def _line(r: dict) -> int:
    return r["start"]["line"] + 1


def _span(r: dict) -> tuple[int, int]:
    return r["byteOffset"]["start"], r["byteOffset"]["end"]


# --- the tree a scan reads ---------------------------------------------------------------------------------------

class Tree:
    """A repository tree on disk: `files` is the tracked file list, `root` holds at least the files read."""

    def __init__(self, root: Path, files: list[str], fetch=None):
        self.root, self.files, self.fileset, self._fetch = root, files, set(files), fetch

    def ensure(self, paths) -> None:
        if self._fetch:
            self._fetch([p for p in paths if p in self.fileset])

    def read(self, path: str) -> str:
        # utf-8-sig: a BOM is not code (CPython would read U+FEFF as an invalid character).
        return (self.root / path).read_text(encoding="utf-8-sig", errors="replace")


def tracked_files(root: Path) -> list[str]:
    p = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True)
    if p.returncode != 0:
        raise Refusal(f"git ls-files exited {p.returncode}")
    return sorted(f for f in p.stdout.decode("utf-8", "surrogateescape").split("\0") if f)


def tracked_symlinks(root: Path) -> set[str]:
    """Tracked paths whose mode is a symlink (120000): never scanned, and red when a tree covers them."""
    p = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=root, capture_output=True)
    if p.returncode != 0:
        raise Refusal(f"git ls-files -s exited {p.returncode}")
    out = set()
    for row in p.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if row.startswith("120000 "):
            out.add(row.split("\t", 1)[1])
    return out


def git_tree(root: Path, sha: str, dest: Path) -> Tree:
    """The tree of commit `sha`, materialized lazily into dest (only the blobs a scan reads)."""
    p = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", sha], cwd=root, capture_output=True)
    if p.returncode != 0:
        raise Refusal(f"git ls-tree {sha} exited {p.returncode}: the base cannot be read")
    files = sorted(f for f in p.stdout.decode("utf-8", "surrogateescape").split("\0") if f)
    done = set()

    def fetch(paths):
        for path in paths:
            if path in done:
                continue
            q = subprocess.run(["git", "show", f"{sha}:{path}"], cwd=root, capture_output=True)
            if q.returncode != 0:
                raise Refusal(f"git show {sha}:{path} exited {q.returncode}: the base cannot be read")
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(q.stdout)
            done.add(path)

    return Tree(dest, files, fetch)


# --- configuration -----------------------------------------------------------------------------------------------

def load_config(text: str, where: str) -> dict:
    try:
        cfg = json.loads(text)
    except ValueError as e:
        raise Refusal(f"{where}: not JSON ({e})")
    if not isinstance(cfg, dict) or cfg.get("schema") != SCHEMA:
        raise Refusal(f"{where}: schema must be {SCHEMA}")
    trees = cfg.get("trees")
    if not isinstance(trees, list) or not trees:
        raise Refusal(f"{where}: `trees` must be a non-empty list of {{glob, min_files}}")
    for t in trees:
        if not (isinstance(t, dict) and isinstance(t.get("glob"), str) and t["glob"]
                and isinstance(t.get("min_files"), int) and t["min_files"] >= 1 and set(t) <= {"glob", "min_files"}):
            raise Refusal(f"{where}: each tree is {{\"glob\": str, \"min_files\": int >= 1}}, got {t!r}")
    if len({t["glob"] for t in trees}) != len(trees):
        raise Refusal(f"{where}: a tree glob is listed twice")
    exclude = cfg.get("exclude", [])
    if not (isinstance(exclude, list) and all(isinstance(g, str) and g for g in exclude)):
        raise Refusal(f"{where}: `exclude` must be a list of globs")
    launchers = cfg.get("launchers", [])
    if not isinstance(launchers, list):
        raise Refusal(f"{where}: `launchers` must be a list")
    for la in launchers:
        if not (isinstance(la, dict) and set(la) == {"name", "module", "hook_floor_ms"} and NAME.match(la["name"] or "")
                and isinstance(la["module"], str) and isinstance(la["hook_floor_ms"], int) and la["hook_floor_ms"] > 0):
            raise Refusal(f"{where}: each launcher is {{name, module, hook_floor_ms}}, got {la!r}")
    counts = cfg.get("counts", {})
    if not (isinstance(counts, dict) and all(isinstance(f, str) and isinstance(v, dict)
                                             and all(isinstance(r, str) and isinstance(n, int) and n >= 1
                                                     for r, n in v.items()) for f, v in counts.items())):
        raise Refusal(f"{where}: `counts` must map path -> {{rule: count >= 1}}")
    digest = cfg.get("check_digest")
    if digest is not None and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise Refusal(f"{where}: `check_digest` must be the 64-hex digest write-baseline records")
    unknown = set(cfg) - {"schema", "check", "trees", "exclude", "launchers", "counts", "check_digest"}
    if unknown:
        raise Refusal(f"{where}: unknown keys {sorted(unknown)}")
    return {"trees": trees, "exclude": exclude, "launchers": launchers, "counts": counts, "check_digest": digest}


class Scope:
    def __init__(self, cfg: dict):
        self.trees = [(t["glob"], glob_to_regex(t["glob"]), t["min_files"]) for t in cfg["trees"]]
        self.exclude = [glob_to_regex(g) for g in cfg["exclude"]]

    def covers(self, path: str) -> bool:
        return any(rx.match(path) for _, rx, _ in self.trees) and not any(rx.match(path) for rx in self.exclude)

    def scanned(self, path: str) -> bool:
        return self.covers(path) and (posixpath.splitext(path)[1] in LANGUAGE_OF
                                      or posixpath.basename(path) in PYTEST_CONFIGS)


# --- JS/TS resolution (one hop, four guards) ---------------------------------------------------------------------

# Parent contexts in which an identifier is only ever READ. Any other occurrence of the name (a declarator, a
# parameter, a destructure, a catch clause, a class or function name, an import) is a binding, or might be one, so
# the name is not resolved (guard 1). Unknown contexts therefore fail toward a finding.
_REF_CONTEXTS = [
    "{ kind: arguments }", "{ kind: binary_expression }", "{ kind: unary_expression }",
    "{ kind: parenthesized_expression }", "{ kind: pair, field: value }", "{ kind: template_substitution }",
    "{ kind: array }", "{ kind: member_expression, field: object }", "{ kind: call_expression, field: function }",
    "{ kind: return_statement }", "{ kind: ternary_expression }", "{ kind: spread_element }",
    "{ kind: variable_declarator, field: value }", "{ kind: assignment_expression, field: right }",
    "{ kind: augmented_assignment_expression, field: right }", "{ kind: subscript_expression }",
    "{ kind: arrow_function, field: body }", "{ kind: expression_statement }", "{ kind: await_expression }",
    "{ kind: sequence_expression }",
    "{ kind: type_query }  #[typescript,tsx]",
    "{ kind: as_expression }  #[typescript,tsx]", "{ kind: satisfies_expression }  #[typescript,tsx]",
    "{ kind: non_null_expression }  #[typescript,tsx]", "{ kind: type_assertion }  #[typescript]",
    "{ kind: required_parameter, field: value }  #[typescript,tsx]",
    "{ kind: optional_parameter, field: value }  #[typescript,tsx]",
    "{ kind: assignment_pattern, field: right }  #[javascript]",
]


def _resolver_rules(lang: str, names: set[str]) -> str:
    rx = "^(?:" + "|".join(sorted(re.escape(n) for n in names)) + ")$"
    ctx = "\n".join(f"        - inside: {c}" for c in _REF_CONTEXTS)
    docs = [
        f"id: r.occ\nlanguage: {lang}\nrule:\n  regex: \"{rx}\"\n  any: [{{ kind: identifier }}, "
        "{ kind: shorthand_property_identifier }, { kind: shorthand_property_identifier_pattern }]",
        f"id: r.ref\nlanguage: {lang}\nrule:\n  any:\n    - {{ kind: shorthand_property_identifier, regex: \"{rx}\" }}\n"
        f"    - kind: identifier\n      regex: \"{rx}\"\n      any:\n{ctx}",
        f"id: r.const\nlanguage: {lang}\nrule:\n  kind: variable_declarator\n  all:\n"
        f"    - has: {{ field: name, kind: identifier, regex: \"{rx}\", pattern: $N }}\n"
        "    - has: { field: value, pattern: $VAL }\n  inside:\n    kind: lexical_declaration\n"
        "    regex: \"^const\\\\b\"\n    inside: { any: [{ kind: program }, { kind: export_statement, inside: { kind: program } }] }",
        f"id: r.export\nlanguage: {lang}\nrule:\n  kind: variable_declarator\n  all:\n"
        f"    - has: {{ field: name, kind: identifier, regex: \"{rx}\", pattern: $N }}\n"
        "    - has: { field: value, pattern: $VAL }\n  inside:\n    kind: lexical_declaration\n"
        "    regex: \"^const\\\\b\"\n    inside: { kind: export_statement, inside: { kind: program } }",
        f"id: r.import\nlanguage: {lang}\nrule: {{ kind: import_statement }}",
    ]
    return "\n---\n".join(_keep(d, lang) for d in docs) + "\n"


_IMPORT = re.compile(r"\Aimport\s*\{(?P<specs>[^{}/]*)\}\s*from\s*(?P<q>['\"])(?P<src>[^'\"\n]+)(?P=q)\s*;?\s*\Z")
_SPEC = re.compile(r"\A(?P<imp>[A-Za-z_$][\w$]*)(?:\s+as\s+(?P<local>[A-Za-z_$][\w$]*))?\Z")


def _parse_import(text: str) -> dict[str, str] | None:
    """{local name: imported name} of a plain named import, or None for any other shape (type, default, namespace)."""
    m = _IMPORT.match(text.strip())
    if not m:
        return None
    out = {}
    for spec in m.group("specs").split(","):
        spec = spec.strip()
        if not spec:
            continue
        if re.match(r"type\s+\S", spec):
            continue  # an inline `type X` binds a type only, never a value the resolver reads
        s = _SPEC.match(spec)
        if not s:
            return None
        out[s.group("local") or s.group("imp")] = s.group("imp")
    return out


def resolve_module(tree: Tree, importer: str, spec: str) -> tuple[str | None, str]:
    """The ONE tracked file a relative specifier names (guard 4), or (None, why)."""
    if not spec.startswith(("./", "../")):
        return None, f"`{spec}` is not a relative path"
    target = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
    if target.startswith("../") or target == "..":
        return None, f"`{spec}` leaves the repository"
    if target + "/package.json" in tree.fileset:
        return None, f"`{spec}` is a package directory: its package.json, not an index file, decides what loads"
    stem, ext = posixpath.splitext(target)
    if ext in JS_EXTS:
        cands = [target] + [stem + t for t in JS_TWIN.get(ext, ())]
    else:
        cands = [target + e for e in JS_EXTS] + [target + "/index" + e for e in JS_EXTS]
    hits = sorted({c for c in cands if c in tree.fileset})
    if len(hits) != 1:
        return None, f"`{spec}` resolves to {len(hits)} files{(': ' + ', '.join(hits)) if hits else ''}"
    return hits[0], ""


class JsFacts:
    """What the resolver rules found in one file, by name."""

    def __init__(self):
        self.occ, self.ref = {}, {}   # name -> set of byte spans
        self.const = {}               # name -> [(name span, value text)]
        self.export = {}
        self.imports = []             # (statement span, {local: imported} or None, source)


def js_facts(tree: Tree, files: list[str], names: set[str]) -> dict[str, JsFacts]:
    out = {f: JsFacts() for f in files}
    if not names or not files:
        return out
    by_lang = {}
    for f in files:
        by_lang.setdefault(LANGUAGE_OF[posixpath.splitext(f)[1]], []).append(f)
    for lang, group in by_lang.items():
        for m in sg_scan(tree.root, _resolver_rules(lang, names), group):
            fx, rid, mv = out[m["file"]], m["ruleId"], m.get("metaVariables", {}).get("single", {})
            if rid == "r.occ":
                fx.occ.setdefault(m["text"], set()).add(_span(m["range"]))
            elif rid == "r.ref":
                fx.ref.setdefault(m["text"], set()).add(_span(m["range"]))
            elif rid in ("r.const", "r.export"):
                name = mv["N"]["text"]
                (fx.const if rid == "r.const" else fx.export).setdefault(name, []).append(
                    (_span(mv["N"]["range"]), mv["VAL"]["text"]))
            elif rid == "r.import":
                src = re.search(r"(['\"])([^'\"\n]+)\1\s*;?\s*$", m["text"])
                fx.imports.append((_span(m["range"]), _parse_import(m["text"]), src.group(2) if src else ""))
    return out


_ALIAS_RULES = """id: a.import
language: LANG
rule: { kind: import_statement }
---
id: a.promisify
language: LANG
rule:
  any:
    - pattern: const $N = promisify($X)
    - pattern: const $N = util.promisify($X)
    - pattern: let $N = promisify($X)
    - pattern: let $N = util.promisify($X)
    - pattern: var $N = promisify($X)
    - pattern: var $N = util.promisify($X)
---
id: a.require
language: LANG
rule:
  any:
    - pattern: "const { $$$P } = require($S)"
    - pattern: "let { $$$P } = require($S)"
    - pattern: "var { $$$P } = require($S)"
---
id: a.module
language: LANG
rule:
  any:
    - pattern: const $N = require($S)
    - pattern: let $N = require($S)
    - pattern: var $N = require($S)
---
id: a.member
language: LANG
rule:
  any:
    - pattern: const $N = $M.$P
    - pattern: let $N = $M.$P
    - pattern: var $N = $M.$P
"""
# The forms of an import of a child-process module: a default or namespace binding (the module object) and named
# specifiers, in any combination (`import cp, { execFile as ef } from "node:child_process"`).
_IMPORT_FORMS = re.compile(r"\Aimport\s+(?!type\b)(?P<clause>[^'\"]+?)\s+from\s*(?P<q>['\"])(?P<src>[^'\"\n]+)(?P=q)\s*;?\s*\Z", re.S)


def child_process_aliases(tree: Tree, files: list[str]) -> dict[str, set[str]]:
    """file -> local names bound to a child-process launcher: an aliased named import (`spawnSync as run`), a
    destructured require (`const { exec: x } = require("child_process")`), or a promisify() of either. Treating a
    name as a child process RAISES its floor (60 s -> 120 s), so this resolution can only add findings."""
    out = {f: set() for f in files}
    mods = {f: set() for f in files}  # local names bound to a child-process MODULE object
    by_lang = {}
    for f in files:
        by_lang.setdefault(LANGUAGE_OF[posixpath.splitext(f)[1]], []).append(f)
    promised, members = [], []
    for lang, group in by_lang.items():
        for m in sg_scan(tree.root, _ALIAS_RULES.replace("LANG", lang), group):
            f, mv = m["file"], m.get("metaVariables", {})
            if m["ruleId"] == "a.import":
                im = _IMPORT_FORMS.match(m["text"].strip())
                names = CHILD_PROCESS.get(im.group("src") if im else "", set())
                if not names:
                    continue
                clause = im.group("clause")
                named = re.search(r"\{(?P<specs>[^{}]*)\}", clause)
                for spec in (named.group("specs").split(",") if named else []):
                    s2 = _SPEC.match(spec.strip())
                    if s2 and s2.group("imp") in names:
                        out[f].add(s2.group("local") or s2.group("imp"))
                head = re.sub(r"\{[^{}]*\}", "", clause)
                for part in head.split(","):
                    part = part.strip()
                    ns = re.fullmatch(r"\*\s+as\s+([A-Za-z_$][\w$]*)", part)
                    if ns:
                        mods[f].add(ns.group(1))
                    elif NAME.match(part):
                        mods[f].add(part)
            elif m["ruleId"] == "a.module":
                if mv.get("single", {}).get("S", {}).get("text", "").strip("'\"") in CHILD_PROCESS:
                    mods[f].add(mv["single"]["N"]["text"])
            elif m["ruleId"] == "a.member":
                members.append((f, mv["single"]["M"]["text"], mv["single"]["P"]["text"], mv["single"]["N"]["text"]))
            elif m["ruleId"] == "a.require":
                if mv.get("single", {}).get("S", {}).get("text", "").strip("'\"") in CHILD_PROCESS:
                    for entry in mv.get("multi", {}).get("P", []):
                        parts = [x.strip() for x in entry["text"].split(":")]
                        if parts[0] in SUBPROCESS_NAMES and NAME.match(parts[-1]):
                            out[f].add(parts[-1])
            elif m["ruleId"] == "a.promisify":
                promised.append((f, mv["single"]["X"]["text"], mv["single"]["N"]["text"]))
    for f, mod, prop, n in members:  # const run = cp.spawnSync
        if mod in mods[f] and prop in SUBPROCESS_NAMES:
            out[f].add(n)
    for _ in range(2):  # promisify of an alias, or of a module member (promisify(cp.execFile))
        for f, x, n in promised:
            mm = re.fullmatch(r"([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)", x)
            if x in SUBPROCESS_NAMES or x in out[f] or (mm and mm.group(1) in mods[f] and mm.group(2) in SUBPROCESS_NAMES):
                out[f].add(n)
    return out


def _binding(fx: JsFacts, name: str, exported: bool) -> tuple[str, object] | tuple[None, str]:
    """The one binding of `name` in a file: ("const", value text) or ("import", (source, imported)), or (None, why)."""
    defs, spans = [], set()
    for span, val in (fx.export if exported else fx.const).get(name, []):
        defs.append(("const", val))
        spans.add(span)
    if not exported:
        for st, parsed, src in fx.imports:
            inside = {s for s in fx.occ.get(name, ()) if st[0] <= s[0] and s[1] <= st[1]}
            if inside and parsed is not None and name in parsed:
                defs.append(("import", (src, parsed[name])))
                spans |= inside
    stray = fx.occ.get(name, set()) - spans - fx.ref.get(name, set())
    if stray:
        return None, (f"`{name}` occurs at {len(stray)} site(s) that are neither its one top-level binding nor a "
                      "plain read (an inner declaration, a parameter, a destructure, a reassignment): not resolved")
    if len(defs) != 1:
        what = "an `export const`" if exported else "a top-level const or a plain named import"
        return None, f"`{name}` has {len(defs)} binding(s) as {what}; exactly one is required"
    return defs[0]


# --- Python resolution -------------------------------------------------------------------------------------------

def py_bindings(tree: ast.Module, name: str) -> list[ast.AST]:
    """Every site that binds or declares `name`, in any scope (guard 1 and 2 count these)."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.append(node)
        elif isinstance(node, ast.arg) and node.arg == name:
            out.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            out.append(node)
        elif isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name:
            out.append(node)
        elif isinstance(node, ast.alias) and node.name == "*":
            out.append(node)  # a star import may bind any name (root's #60 R4 B4)
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            out.append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            out.append(node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
            out.append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest == name:
            out.append(node)
    return out


def _py_one_binding(module: ast.Module, name: str) -> tuple[str, object] | tuple[None, str]:
    sites = py_bindings(module, name)
    if len(sites) != 1:
        return None, f"`{name}` is bound {len(sites)} time(s) in this file; exactly one module-level binding is required"
    for stmt in module.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and stmt.targets[0] is sites[0]:
            return "const", stmt.value
        if isinstance(stmt, ast.AnnAssign) and stmt.target is sites[0] and stmt.value is not None:
            return "const", stmt.value
        if isinstance(stmt, ast.ImportFrom) and any(a is sites[0] for a in stmt.names):
            alias = next(a for a in stmt.names if a is sites[0])
            if not stmt.level or not stmt.module:
                return None, f"`{name}` is imported from a non-relative or package-level module"
            return "import", (stmt.level, stmt.module, alias.name)
    return None, f"`{name}`'s one binding is not a module-level assignment or relative `from` import"


def resolve_py_module(tree: Tree, importer: str, level: int, module: str) -> tuple[str | None, str]:
    base = posixpath.dirname(importer)
    for _ in range(level - 1):
        base = posixpath.dirname(base)
    stem = posixpath.join(base, *module.split("."))
    hits = sorted(c for c in (stem + ".py", stem + "/__init__.py") if c in tree.fileset)
    if len(hits) != 1:
        return None, f"`{'.' * level}{module}` resolves to {len(hits)} files"
    return hits[0], ""


# --- the census --------------------------------------------------------------------------------------------------

def _parse_py(text: str):
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def census(tree: Tree, files: list[str], launchers: list[dict]) -> dict:
    """Scan `files` (scanned paths of `tree`): {"findings": {file: [record]}, "marks": [...], "unparsable": [...]}.

    A record: {line, rule, position, kind, value, status, reason, mark}. status "finding" counts against the
    baseline; "cleared" carries the proof in reason; "marked" carries the mark's reason."""
    tree.ensure(files)
    configs = [f for f in files if posixpath.basename(f) in PYTEST_CONFIGS]
    files = [f for f in files if posixpath.splitext(f)[1] in LANGUAGE_OF]
    by_lang = {}
    for f in files:
        by_lang.setdefault(LANGUAGE_OF[posixpath.splitext(f)[1]], []).append(f)
    launch_rules = []
    for i, la in enumerate(launchers):
        launch_rules.append(
            f"id: launcher.{i}\nlanguage: typescript\nrule:\n  kind: call_expression\n  all:\n"
            "    - has: { field: function, kind: identifier, regex: \"^beforeAll$\" }\n"
            "    - has: { field: arguments, has: { nthChild: { position: 1, ofRule: { matches: nc } }, has: "
            "{ stopBy: end, kind: call_expression, has: { field: function, kind: identifier, regex: \"^"
            + re.escape(la["name"]) + "$\" } } } }\n"
            "    - has: { field: arguments, has: { nthChild: { position: 1, reverse: true, ofRule: { matches: nc } }, "
            "pattern: $V } }")
    matches, marks_raw, unparsable, errors, parsed = [], {}, {}, set(), Counter()
    for f in files:
        try:
            (tree.root / f).read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            unparsable.setdefault((f, 0), "not UTF-8: ast-grep skips such a file, so nothing in it can be judged")
    for lang, group in sorted(by_lang.items()):
        extra = launch_rules if lang in JS_LANGS else []
        for m in sg_scan(tree.root, compose_rules(lang, extra), group):
            if m["ruleId"] == "sentinel":
                parsed[m["file"]] += 1
            elif m["ruleId"] == "parse-error":
                unparsable.setdefault((m["file"], _line(m["range"])), "an ERROR node that could hide a bound")
            elif m["ruleId"] == "recovered":
                errors.add((m["file"], _line(m["range"])))
            elif m["ruleId"] == "mark":
                # The mark exempts the line its own text sits on, never the other lines of a block comment.
                for mk in MARK.finditer(m["text"]):
                    ln = _line(m["range"]) + m["text"].count("\n", 0, mk.start())
                    marks_raw.setdefault((m["file"], ln), mk.group("why").strip().rstrip("*/").strip())
            else:
                matches.append(m)
    for f in files:
        # An empty file has no root node to match, and nothing in it to judge.
        if parsed[f] != 1 and (tree.root / f).read_bytes().strip():
            unparsable.setdefault((f, 0), f"ast-grep parsed it {parsed[f]} time(s), not once: the scan cannot vouch "
                                          "for it (non-UTF-8 bytes, a file over ast-grep's size limit, or a configuration that hides the file)")
    launcher_hits = {}
    for m in matches:
        if m["ruleId"].startswith("launcher."):
            v = m["metaVariables"]["single"]["V"]
            launcher_hits[(m["file"], _span(v["range"]))] = launchers[int(m["ruleId"].split(".")[1])]
    bounds = [m for m in matches if m["ruleId"].startswith(RULE + ".")]
    py_files = [f for f in files if LANGUAGE_OF[posixpath.splitext(f)[1]] == "python"]
    bound_py, not_covered, direct = py_binding_matches(tree, py_files) if py_files else ([], [], set())
    # The binding pass knows what an ast-grep spelling only guesses (bare `wait` may be asyncio's), so it wins at any
    # span it read and at every direct argument of a call it resolved.
    owned = direct | {(m["file"], _span(m["metaVariables"]["single"]["V"]["range"])) for m in bound_py}
    bounds = [m for m in bounds if (m["file"], _span(m["metaVariables"]["single"]["V"]["range"])) not in owned] + bound_py
    # Names to resolve, and the files that read them.
    need = {}
    for m in bounds:
        text = m["metaVariables"]["single"]["V"]["text"].strip()
        if NAME.match(text):
            need.setdefault(m["file"], set()).add(text)
    for (f, _), la in launcher_hits.items():
        need.setdefault(f, set()).add(la["name"])
    resolved = _resolve_all(tree, need)
    # A condition-kind `timeout` option whose callee is an identifier may be an aliased child process (#60 delta L1).
    alias_files = sorted({m["file"] for m in bounds if m["ruleId"] == RULE + ".option.condition"
                          and NAME.match(m["metaVariables"]["single"].get("F", {}).get("text", ""))
                          and LANGUAGE_OF[posixpath.splitext(m["file"])[1]] in JS_LANGS})
    aliases = child_process_aliases(tree, alias_files) if alias_files else {}
    findings, marks = {}, []
    for (f, ln), why in sorted(marks_raw.items()):
        marks.append({"file": f, "line": ln, "reason": why})
    for m in sorted(bounds, key=lambda m: (m["file"], m["range"]["byteOffset"]["start"])):
        f = m["file"]
        _, position, kind = m["ruleId"].split(".")
        lang = LANGUAGE_OF[posixpath.splitext(f)[1]]
        v = m["metaVariables"]["single"]["V"]
        callee = m["metaVariables"]["single"].get("F", {}).get("text", "")
        if position == "option" and kind == "condition" and callee in aliases.get(f, set()):
            kind = "subprocess"  # an aliased child process, resolved by binding
        text = v["text"].strip()
        floor = FLOORS_S[kind] * UNIT[lang]
        rec = {"line": _line(v["range"]), "rule": RULE, "position": position, "kind": kind,
               "value": re.sub(r"\s+", " ", text)[:120], "floor": floor, "status": "finding", "reason": "", "mark": None}
        la = launcher_hits.get((f, _span(v["range"]))) if kind == "hook" else None
        if la is not None:
            ok, why = resolved.get((f, la["name"]), (None, "not resolved"))
            if isinstance(ok, tuple) and ok == ("module", la["module"], la["name"]):
                floor = la["hook_floor_ms"]
                rec["floor"], rec["reason"] = floor, f"launcher {la['name']} ({la['module']}): floor {floor}"
            else:
                rec["reason"] = f"launcher {la['name']} not proven by binding: {why}"
        value, why = _value_of(text, lang, f, resolved)
        if (m.get("zero_is_none") or (lang != "python" and position in ZERO_IS_NONE)) and value == 0 \
                and not NAME.match(text):
            continue  # a literal 0 is "no limit" here
        if position == "join" and value is None and not re.match(r"\s*timeout\s*=", m.get("text", "")):
            continue  # a positional name or expression that is not a number is str.join's argument, not a bound
        if value is not None and value >= floor:
            rec["status"], rec["reason"] = "cleared", (rec["reason"] + "; " if rec["reason"] else "") + why
        else:
            rec["reason"] = (rec["reason"] + "; " if rec["reason"] else "") + (
                why if value is None else f"{why}, below the floor {floor}")
            lines = set(range(_line(v["range"]), v["range"]["end"]["line"] + 2))
            if position in SMALL_MATCH:
                lines.add(_line(m["range"]))
            mark = next((marks_raw[(f, ln)] for ln in sorted(lines) if (f, ln) in marks_raw), None)
            if mark is not None:
                rec["mark"] = mark
                if REASON.search(mark):
                    rec["status"] = "marked"
                else:
                    rec["reason"] += "; the `timeout under test:` mark gives no reason, so it clears nothing"
        findings.setdefault(f, []).append(rec)
    for f in files:
        if LANGUAGE_OF[posixpath.splitext(f)[1]] == "python" and _parse_py(tree.read(f)) is None:
            unparsable.setdefault((f, 0), "CPython cannot parse it")
    for f in configs:
        recs, why = pytest_config_bounds(tree.read(f), posixpath.basename(f))
        if why:
            unparsable.setdefault((f, 0), why)
        if recs:
            findings.setdefault(f, []).extend(recs)
    bad = {f for f, _ in unparsable}
    return {"findings": findings, "marks": marks, "not_covered": sorted(not_covered),
            "unparsable": sorted((f, ln, why) for (f, ln), why in unparsable.items()),
            "recovered": sorted((f, ln) for f, ln in errors if f not in bad)}


def pytest_config_bounds(text: str, name: str) -> tuple[list[dict], str | None]:
    """(records, unparsable reason) for one pytest config file: its `timeout` option and any `--timeout` in addopts,
    judged as case bounds in seconds. A file that does not parse is unparsable, never clean. `timeout = 0` disables
    pytest-timeout, so it is no bound."""
    floor = FLOORS_S["case"]
    sections = []  # (section header, {key: value text})
    if name in ("pyproject.toml", "pytest.toml", ".pytest.toml"):
        try:
            import tomllib
        except ImportError:
            return [], f"tomllib is unavailable (Python < 3.11), so the check cannot read {name}"
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return [], "not valid TOML"

        def flat(opts: dict) -> dict:
            return {k: v if isinstance(v, str) else (" ".join(map(str, v)) if isinstance(v, list) else str(v))
                    for k, v in opts.items() if not isinstance(v, dict)}
        if name == "pyproject.toml":
            native = (data.get("tool") or {}).get("pytest") or {}
            sections.append(("tool.pytest.ini_options", flat(native.get("ini_options") or {})))
            sections.append(("tool.pytest", flat(native)))
        else:
            sections.append(("pytest", flat(data.get("pytest") or {})))
    else:
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read_string(text)
        except configparser.Error as e:
            return [], f"not a valid INI file ({type(e).__name__})"
        section = PYTEST_CONFIGS[name]
        sections.append((section, dict(cp.items(section)) if cp.has_section(section) else {}))
    lines = text.splitlines()

    def line_of(section: str, key: str) -> int:
        """The key's line under its section header, quoted or not; else (TOML's inline table `pytest = { timeout = 7
        }` or dotted key `tool.pytest.timeout = 8`) the first line that assigns it in any form (#65 delta L4)."""
        current, k = None, re.escape(key)
        for i, line in enumerate(lines, 1):
            head = re.match(r"\s*\[([^\]]+)\]\s*$", line)
            if head:
                current = head.group(1).strip().strip('"')
            elif current == section and re.match(rf"\s*[\"']?{k}[\"']?\s*[=:]", line):
                return i
        for i, line in enumerate(lines, 1):
            if re.search(rf"(?:^|[\s{{,.])[\"']?{k}[\"']?\s*=", line):
                return i
        return 0

    values = []
    for section, items in sections:
        if "timeout" in items:
            values.append((line_of(section, "timeout"), items["timeout"]))
        for m in re.finditer(r"--timeout(?:=|\s+)(\S+)", items.get("addopts", "")):
            values.append((line_of(section, "addopts"), m.group(1)))
    out = []
    for ln, raw in values:
        source_line = lines[ln - 1] if 0 < ln <= len(lines) else ""
        value_text = re.split(r"\s[#;]", raw, 1)[0].strip().strip('"\'')
        v = evaluate_py(value_text)
        if v == 0:
            continue  # pytest-timeout's timeout = 0 is "no limit"
        rec = {"line": ln, "rule": RULE, "position": "ini", "kind": "case", "value": value_text[:120], "floor": floor,
               "status": "finding", "reason": "", "mark": None}
        if v is not None and v >= floor:
            rec["status"], rec["reason"] = "cleared", f"pytest-timeout default {value_text} = {_fmt(v)}"
        else:
            rec["reason"] = (f"pytest-timeout default {value_text} = {_fmt(v)}, below the floor {floor}" if v is not None
                             else f"pytest-timeout default `{value_text}` is not an exact number")
            mk = MARK.search(source_line)
            if mk:
                rec["mark"] = mk.group("why").strip()
                if REASON.search(rec["mark"]):
                    rec["status"] = "marked"
        out.append(rec)
    return out, None


# --- Python calls read by binding (root's #65 RC B3) --------------------------------------------------------------

# canonical callable -> (rule position, kind, positional index of the bound or None, the keywords that carry it)
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send")
PY_CALLS = {
    "asyncio.wait_for": ("wait", "condition", 1, ("timeout",)),
    "asyncio.wait": ("wait", "condition", None, ("timeout",)),
    "asyncio.timeout": ("timeout-ctx", "condition", 0, ("delay",)),
    "async_timeout.timeout": ("timeout-ctx", "condition", 0, ("timeout",)),
    "urllib.request.urlopen": ("http", "condition", 2, ("timeout",)),
    "httpx.Client": ("http", "condition", None, ("timeout",)),
    "httpx.AsyncClient": ("http", "condition", None, ("timeout",)),
    **{f"{lib}.{m}": ("http", "condition", None, ("timeout",)) for lib in ("requests", "httpx") for m in _HTTP_METHODS
       if m != "send"},
    **{f"{c}.{m}": ("http", "condition", None, ("timeout",))
       for c in ("requests.Session", "httpx.Client", "httpx.AsyncClient") for m in _HTTP_METHODS},
    **{c: ("client", "fixture", None, ("timeout", "connect_timeout", "command_timeout"))
       for c in ("asyncpg.connect", "asyncpg.create_pool", "asyncpg.pool.create_pool", "psycopg.connect",
                 "psycopg2.connect", "psycopg.Connection.connect", "psycopg.AsyncConnection.connect",
                 "psycopg_pool.ConnectionPool", "psycopg_pool.AsyncConnectionPool")},
    "pytest.mark.timeout": ("mark", "case", 0, ("timeout",)),
}
# The rule ids the binding pass emits. Declared, not derived from PY_CALLS, so a gutted position is caught: the self-test
# plants each one RED and requires PY_CALLS (plus the HTTP tuple) to read exactly these.
PY_BOUND_RULES = (f"{RULE}.wait.condition", f"{RULE}.timeout-ctx.condition", f"{RULE}.http.condition",
                  f"{RULE}.http-tuple.condition", f"{RULE}.client.fixture", f"{RULE}.mark.case")
CLIENT_CTORS = {"requests.Session": "requests.Session", "requests.session": "requests.Session",
                "httpx.Client": "httpx.Client", "httpx.AsyncClient": "httpx.AsyncClient",
                # seen, not read yet: its calls with a bound keyword are listed NOT COVERED (#65 delta INFO-1)
                "aiohttp.ClientSession": "aiohttp.ClientSession"}


# The libraries this check reads calls of, and aiohttp, which it sees but does not read yet (its bound is a
# ClientTimeout): a call into one with a bound keyword that the binding pass cannot read is listed, never dropped.
PY_LIBRARIES = {k.split(".")[0] for k in [*PY_CALLS, *CLIENT_CTORS]} | {"aiohttp"}
PY_BOUND_KEYWORDS = {kw for *_, kws in PY_CALLS.values() for kw in kws}
PY_LEAVES = {k.rsplit(".", 1)[1] for k in [*PY_CALLS, *CLIENT_CTORS]}
# libpq waits forever on connect_timeout = 0, so a literal 0 there is no bound. asyncpg's and psycopg_pool's `timeout`
# of 0 is an INSTANT timeout, and asyncpg's command_timeout=0 is refused, so those stay findings (#65 delta L1).
LIBPQ_CONNECT = {"psycopg.connect", "psycopg2.connect", "psycopg.Connection.connect", "psycopg.AsyncConnection.connect"}
# A submodule or vendored spelling of a covered callable (`requests.api.get`, `asyncio.tasks.wait_for`).
PY_SPELLINGS = (("pip._vendor.requests", "requests"), ("requests.api", "requests"), ("requests.sessions", "requests"),
                ("asyncio.tasks", "asyncio"), ("asyncio.timeouts", "asyncio"), ("httpx._api", "httpx"),
                ("httpx._client", "httpx"))


def _py_canonical(dotted: str) -> str:
    for old, new in PY_SPELLINGS:
        if dotted == old or dotted.startswith(old + "."):
            return new + dotted[len(old):]
    return dotted


def _py_star_leaves(module_name: str) -> dict[str, str]:
    """leaf -> canonical name, for each covered callable or client class a star import of `module_name` binds."""
    out = {}
    for k in [*PY_CALLS, *CLIENT_CTORS]:
        head, _, leaf = k.rpartition(".")
        if head == _py_canonical(module_name):
            out[leaf] = k
    return out


def _py_local_module(tree: "Tree", importer: str, module: str) -> tuple[str | None, int]:
    """The one file an absolute import of a LOCAL module names, from the repository root or the importer's directory
    (a test's own helpers); (None, 0) when it is not local, (None, n) when n files match."""
    stems = {posixpath.join(*module.split(".")), posixpath.join(posixpath.dirname(importer), *module.split("."))}
    hits = sorted({c for st in stems for c in (st + ".py", st + "/__init__.py") if c in tree.fileset})
    return (hits[0] if len(hits) == 1 else None), len(hits)


def _py_reexport(tree: "Tree", target: str, name: str) -> tuple[str | None, str]:
    """What a local module binds `name` to, one hop (the resolver's rule): ("import", canonical) when its one binding
    is a direct import from a covered library, ("client", class) when it is one client construction; else why not."""
    mod = _parse_py(tree.read(target))
    if mod is None:
        return None, f"{target} does not parse"
    sites = [x for x in py_bindings(mod, name) if not (isinstance(x, ast.alias) and x.name == "*")]
    if len(sites) != 1:
        return None, f"{target} binds it {len(sites)} times, not once"
    site = sites[0]
    for node in ast.walk(mod):
        if isinstance(node, ast.ImportFrom) and site in node.names and node.level == 0 and node.module:
            canon = _py_canonical(f"{node.module}.{site.name}")
            if canon.split(".")[0] in PY_LIBRARIES:
                return "import", canon
        if isinstance(node, ast.Import) and site in node.names and site.asname:
            return "import", _py_canonical(site.name)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call) and (
                site in (node.targets if isinstance(node, ast.Assign) else [node.target])):
            ctor = CLIENT_CTORS.get(_py_canonical(_dotted(node.value.func, PyNames(tree, target, mod).at(node.value.func)[0], {}) or ""))
            if ctor:
                return "client", ctor
    return None, f"{target} does not bind it by a direct import from a covered library or a client construction"


_PY_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.ListComp, ast.SetComp,
              ast.DictComp, ast.GeneratorExp)


class PyNames:
    """What a name means where it is used, by Python's scoping (root's #65 delta B2): the nearest enclosing scope that
    binds it decides (a class body never encloses its methods). In that scope the name resolves to a covered library
    only when every binding there is an import of it: an import inside a function binds that function's name, and
    `wait = proc.wait` in another function is that function's own subprocess wait. A scope that binds it by an
    import AND another way (an assignment, a def, a parameter, a for/with/except target, a walrus), or declares it
    global or nonlocal, makes a call through it NOT COVERED. Star imports of a covered module bind its covered names
    (B1); a local module is followed one hop (B1); a star import of any other module is recorded in `stars`."""

    def __init__(self, tree: "Tree", f: str, module: ast.Module):
        self.tree, self.f, self.module = tree, f, module
        self.parent, self.scope_of = {}, {}
        self.sites = {}  # (scope id, name) -> [("import", canonical) | ("unread", why) | ("client", class) | ("other", line)]
        self.stars = []
        self._walk(module, module)

    def _add(self, scope: ast.AST, name: str, what: tuple) -> None:
        self.sites.setdefault((id(scope), name), []).append(what)

    def _walk(self, node: ast.AST, scope: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.scope_of[id(child)] = scope
            inner = scope
            if isinstance(child, _PY_SCOPES):
                inner = child
                self.parent[id(child)] = scope
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self._add(scope, child.name, ("other", child.lineno))
                    for d in child.decorator_list:  # decorators and defaults run in the enclosing scope
                        self.scope_of[id(d)] = scope
                if not isinstance(child, ast.ClassDef):
                    args = child.args if hasattr(child, "args") and isinstance(child.args, ast.arguments) else None
                    for a in (args.posonlyargs + args.args + args.kwonlyargs + [x for x in (args.vararg, args.kwarg) if x]) if args else []:
                        self._add(child, a.arg, ("other", child.lineno))
            self._bind(child, scope)
            self._walk(child, inner)

    def _bind(self, node: ast.AST, scope: ast.AST) -> None:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._add(scope, node.id, ("other", node.lineno))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._add(scope, node.name, ("other", node.lineno))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                self._add(scope, n, ("unread", f"`{n}` is declared {type(node).__name__.lower()} at line {node.lineno}"))
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            self._add(scope, node.name, ("other", node.lineno))
        elif isinstance(node, ast.Import):
            for a in node.names:
                local = a.asname or a.name.split(".")[0]
                self._add(scope, local, ("import", _py_canonical(a.name) if a.asname else a.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            self._bind_from(node, scope)

    def _bind_from(self, node: ast.ImportFrom, scope: ast.AST) -> None:
        mod = node.module or ""
        library = not node.level and mod.split(".")[0] in PY_LIBRARIES
        target, n = None, 0
        if node.level and mod:
            target, n = resolve_py_module(self.tree, self.f, node.level, mod)[0], 1
        elif mod and not library:
            target, n = _py_local_module(self.tree, self.f, mod)
        where = "." * node.level + mod
        for a in node.names:
            local = a.asname or a.name
            if library:
                if a.name == "*":  # B1: a covered module's star import binds each covered name it exports
                    for leaf, canon in _py_star_leaves(mod).items():
                        self._add(scope, leaf, ("import", canon))
                else:
                    self._add(scope, local, ("import", _py_canonical(f"{mod}.{a.name}")))
            elif a.name == "*":
                self.stars.append(where)
            elif not node.level and _py_canonical(f"{mod}.{a.name}").split(".")[0] in PY_LIBRARIES:
                self._add(scope, local, ("import", _py_canonical(f"{mod}.{a.name}")))  # `from pip._vendor import requests`
            elif node.level or n:  # B1: a local module, followed one hop
                what, val = _py_reexport(self.tree, target, a.name) if target else (None, f"it resolves to {n} files")
                if what in ("import", "client"):
                    self._add(scope, local, (what, val))
                else:
                    self._add(scope, local, ("unread", f"`{local}` is imported from the local module `{where}`, which "
                                                       f"one hop cannot read ({val})"))
            else:
                self._add(scope, local, ("other", node.lineno))  # a third-party name

    def lookup(self, name: str, node: ast.AST) -> tuple[str, object]:
        """("import", [canonical, ...]) | ("client", class) | ("unread", why) | ("other", None) | ("unbound", None)."""
        scope, first = self.scope_of.get(id(node), self.module), True
        while scope is not None:
            if first or not isinstance(scope, ast.ClassDef):
                sites = self.sites.get((id(scope), name))
                if sites:
                    kinds = {k for k, _ in sites}
                    unread = [v for k, v in sites if k == "unread"]
                    if unread:
                        return "unread", unread[0]
                    if kinds == {"import"}:
                        return "import", sorted({v for _, v in sites})
                    if kinds == {"client"}:
                        return "client", sites[0][1]
                    if "import" in kinds or "client" in kinds:
                        line = next(v for k, v in sites if k == "other")
                        return "unread", (f"`{name}` is imported and also bound another way in the same scope (line "
                                          f"{line}), so a call through it is not read")
                    return "other", None
            first = False
            scope = self.parent.get(id(scope)) if scope is not self.module else None
        return "unbound", None

    def at(self, expr: ast.AST) -> tuple[dict, dict, dict, dict]:
        """(aliases, several, unread, clients) for the names a callee expression uses, resolved where it is used."""
        aliases, several, unread, clients = {}, {}, {}, {}
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id not in aliases and n.id not in unread:
                kind, val = self.lookup(n.id, expr)
                if kind == "import" and len(val) == 1:
                    aliases[n.id] = val[0]
                elif kind == "import":
                    several[n.id] = val
                elif kind == "unread":
                    unread[n.id] = val
                elif kind == "client":
                    clients[n.id] = val
        return aliases, several, unread, clients


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _dotted(node: ast.AST, aliases: dict, clients: dict) -> str | None:
    """The canonical dotted name a callee expression names, through imports and client instances; else None."""
    if isinstance(node, ast.Name):
        return clients.get(node.id) or _py_canonical(aliases.get(node.id, node.id))
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "self":
            inst = clients.get(f"self.{node.value.attr}")
            if inst:
                return f"{inst}.{node.attr}"
        base = _dotted(node.value, aliases, clients)
        return None if base is None else _py_canonical(f"{base}.{node.attr}")
    if isinstance(node, ast.Call):  # requests.Session().get: an instance made in place
        ctor = _dotted(node.func, aliases, clients)
        return CLIENT_CTORS.get(_py_canonical(ctor or ""))
    return None


def _py_clients(module: ast.Module, names: "PyNames") -> dict:
    """name (or `self.attr`) -> the client class an assignment, an annotated assignment, a walrus, a `with ... as` or a
    class body binds it to, when unambiguous (its constructor's names resolved where it is called)."""
    seen = {}

    def bind(target: ast.AST, value: ast.AST) -> None:
        if not isinstance(value, ast.Call):
            return
        ctor = CLIENT_CTORS.get(_py_canonical(_dotted(value.func, names.at(value.func)[0], {}) or ""))
        if not ctor:
            return
        if isinstance(target, ast.Name):
            seen.setdefault(target.id, set()).add(ctor)
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            seen.setdefault(f"self.{target.attr}", set()).add(ctor)
    for node in ast.walk(module):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                bind(t, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, node.value)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, item.context_expr)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, node.value)
        elif isinstance(node, ast.ClassDef):  # `class T: s = requests.Session()`, read as `self.s` in its methods
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            bind(ast.Attribute(value=ast.Name(id="self"), attr=t.id), stmt.value)
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def py_binding_matches(tree: "Tree", files: list[str]) -> tuple[list[dict], list[tuple[str, int, str]], set]:
    """(matches, not covered) for the Python calls PY_CALLS names, read by binding: import aliases, bare imported names
    and client instances, as well as the exact spellings. Each match has an ast-grep match's shape (ruleId, file,
    range, metaVariables V), so it is judged by the same record loop; census() drops an ast-grep match at the same
    span. A covered call whose bound may come through a `**` splat is NOT COVERED: listed with every run beside
    UNSCANNED, so its absence from the findings is never read as clean. The third
    result is the span of every DIRECT argument of a call it resolved: census() drops an ast-grep match there too, so
    the binding pass decides what that argument is (asyncio.wait's first argument is its awaitables, not a bound)."""
    out, not_covered, direct = [], [], set()
    for f in files:
        text = tree.read(f)
        module = _parse_py(text)
        if module is None:
            continue  # census() lists it as unparsable (K6), never clean
        raw = text.encode("utf-8")
        starts = [0]
        for line in raw.split(b"\n"):
            starts.append(starts[-1] + len(line) + 1)

        def span(node: ast.AST) -> dict:
            b0 = starts[node.lineno - 1] + node.col_offset
            b1 = starts[node.end_lineno - 1] + node.end_col_offset
            return {"start": {"line": node.lineno - 1}, "end": {"line": node.end_lineno - 1},
                    "byteOffset": {"start": b0, "end": b1}}

        names = PyNames(tree, f, module)
        file_clients = _py_clients(module, names)
        pending = []
        for call in ast.walk(module):
            if not isinstance(call, ast.Call):
                continue
            root = _root_name(call.func)
            leaf = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
            bound_kw = any(kw.arg in PY_BOUND_KEYWORDS for kw in call.keywords)
            aliases, several, unread, imported = names.at(call.func)
            clients = {**file_clients, **imported}
            if unread:
                # A name bound by an import and another way in one scope, or imported from a local module one hop
                # cannot read (B1, B2): no ownership, and the call is listed when it may be a covered call.
                if leaf in PY_LEAVES or bound_kw:
                    not_covered.append((f, call.lineno, next(iter(unread.values()))))
                continue
            canon = _dotted(call.func, aliases, clients)
            spec = PY_CALLS.get(canon or "")
            if spec is None and root in several:
                # Imports that bind a name more than one way (`import requests as r` here, `import httpx as r`
                # there). When every binding is a covered call of the same position, kind and index (a try/except
                # fallback: asyncio.timeout or async_timeout.timeout), it is read with their keywords; when only some
                # are, it is listed, never read as clean (L3).
                each = [_dotted(call.func, {**aliases, root: b}, clients) for b in several[root]]
                specs = [PY_CALLS.get(c or "") for c in each]
                if all(specs) and len({sp[:3] for sp in specs}) == 1:
                    spec = (*specs[0][:3], tuple(sorted({k for sp in specs for k in sp[3]})))
                    canon = " / ".join(sorted(set(each)))
                elif any(specs):
                    not_covered.append((f, call.lineno, f"`{root}` is bound by more than one import "
                                                        f"({', '.join(several[root])}), so this call is not read"))
                    continue
            if spec is None:
                if isinstance(call.func, ast.Name) and names.stars and leaf in PY_LEAVES and \
                        names.lookup(leaf, call.func)[0] == "unbound":
                    not_covered.append((f, call.lineno, f"`{leaf}` may be bound by `from {names.stars[0]} import *`, "
                                                        "which this check does not follow, so this call is not read"))
                else:
                    pending.append((call, canon, bound_kw))
                continue
            position, kind, index, keywords = spec
            for a in [*call.args, *(kw.value for kw in call.keywords)]:
                direct.add((f, _span(span(a))))
            kw_values = [kw for kw in call.keywords if kw.arg in keywords]
            values = [kw.value for kw in kw_values]
            star_before = index is not None and any(isinstance(a, ast.Starred) for a in call.args[:index + 1])
            if index is not None and len(call.args) > index and not star_before:
                values.append(call.args[index])
            if not values and any(kw.arg is None for kw in call.keywords):
                not_covered.append((f, call.lineno, f"{canon}: its bound may come through a ** splat, which is not read"))
            elif not values and star_before:
                not_covered.append((f, call.lineno, f"{canon}: its bound may come through a * splat, which is not read"))
            # A literal 0 is "no limit" for pytest-timeout and libpq's connect_timeout only (#65 delta L1).
            unlimited = {id(v) for v in values if position == "mark"} | {
                id(kw.value) for kw in kw_values if kw.arg == "connect_timeout" and any(
                    c in LIBPQ_CONNECT for c in canon.split(" / "))}
            def no_bound(v: ast.AST) -> bool:
                """A value that cannot be a time bound (the rules' bound-value): None, a string, a bool, a collection,
                a lambda. A tuple is one only as an HTTP (connect, read) pair, read element by element."""
                if isinstance(v, ast.Constant):
                    return v.value is None or isinstance(v.value, (str, bytes, bool))
                return isinstance(v, (ast.JoinedStr, ast.List, ast.Dict, ast.Set, ast.Lambda, ast.Starred)) or (
                    isinstance(v, ast.Tuple) and position != "http")

            for v in values:
                if no_bound(v):
                    continue
                if isinstance(v, ast.Tuple) and position == "http":
                    elems = [(e, "http-tuple") for e in v.elts if not no_bound(e)]  # (connect, read): each is a bound
                else:
                    elems = [(v, position)]
                for e, pos in elems:
                    seg = ast.get_source_segment(text, e) or ""
                    out.append({"ruleId": f"{RULE}.{pos}.{kind}", "file": f, "range": span(e), "text": seg,
                                "zero_is_none": id(v) in unlimited,
                                "metaVariables": {"single": {"V": {"text": seg, "range": span(e)}}}})
        # B3: a call into a covered library (or aiohttp) that passes a bound keyword this pass cannot read (a
        # submodule spelling it does not know, a class it does not cover) is listed, never dropped. A call that is
        # itself an argument of a covered call (`timeout=httpx.Timeout(5)`) is judged there.
        for call, canon, bound_kw in pending:
            if not bound_kw or (f, _span(span(call))) in direct:
                continue
            lib, why = (canon or "").split(".")[0], None
            if lib == "aiohttp":
                why = "aiohttp is not read yet (its bound is a ClientTimeout)"
            elif lib in PY_LIBRARIES:
                why = f"`{canon}` is a call into {lib} that this check does not read"
            else:
                # The callee reaches a covered library some other way (getattr(requests, "get"),
                # importlib.import_module("requests").get), or an argument is a covered callable
                # (functools.partial(requests.get, timeout=1)): seen, not read, so listed.
                aliases, _, _, imported = names.at(call.func)
                via = next((v for v in aliases.values() if v.split(".")[0] in PY_LIBRARIES), None) or next(
                    (n.value for n in ast.walk(call.func) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                     and n.value.split(".")[0] in PY_LIBRARIES), None)
                for a in [*call.args, *(kw.value for kw in call.keywords)]:
                    if via is None and isinstance(a, (ast.Name, ast.Attribute)):
                        al, _, _, imp = names.at(a)
                        c = _dotted(a, al, {**file_clients, **imp})
                        via = c if c in PY_CALLS else None
                if via:
                    why = f"a call that reaches `{via}` in a way this check does not read (getattr, importlib, partial)"
            if why:
                not_covered.append((f, call.lineno, why))
    return out, not_covered, direct


def _value_of(text: str, lang: str, file: str, resolved: dict) -> tuple[Fraction | None, str]:
    if NAME.match(text):
        ok, why = resolved.get((file, text), (None, f"`{text}` is not resolved"))
        if isinstance(ok, Fraction):
            return ok, why
        return None, why
    v = evaluate_py(text) if lang == "python" else evaluate_js(text)
    if v is None:
        return None, f"`{text[:60]}` is not an exact literal expression"
    return v, f"literal {text[:60]} = {_fmt(v)}"


def _fmt(v: Fraction) -> str:
    return str(v.numerator) if v.denominator == 1 else str(float(v))


def _resolve_all(tree: Tree, need: dict[str, set[str]]) -> dict:
    """(file, name) -> (value Fraction | binding marker, why) for every name the bounds use."""
    out = {}
    js = {f: n for f, n in need.items() if LANGUAGE_OF[posixpath.splitext(f)[1]] in JS_LANGS}
    py = {f: n for f, n in need.items() if LANGUAGE_OF[posixpath.splitext(f)[1]] == "python"}
    names = set().union(*js.values()) if js else set()
    facts = js_facts(tree, sorted(js), names)
    hop = {}  # (module, imported) -> [(file, name)]
    for f, ns in js.items():
        for name in ns:
            kind, data = _binding(facts[f], name, exported=False)
            if kind is None:
                out[(f, name)] = (None, data)
            elif kind == "const":
                v = evaluate_js(data)
                out[(f, name)] = (v, f"`{name}` = {data.strip()[:60]} (same file)") if v is not None else (
                    None, f"`{name}` = {data.strip()[:60]}: not an exact literal expression")
            else:
                src, imported = data
                mod, why = resolve_module(tree, f, src)
                if mod is None:
                    out[(f, name)] = (None, f"`{name}` imported from {why}")
                else:
                    hop.setdefault((mod, imported), []).append((f, name, src))
                    out[(f, name)] = (("module", mod, imported), f"`{name}` imported from {mod}")
    if hop:
        mods = sorted({m for m, _ in hop})
        tree.ensure(mods)
        mfacts = js_facts(tree, mods, {i for _, i in hop})
        for (mod, imported), users in hop.items():
            kind, data = _binding(mfacts[mod], imported, exported=True)
            for f, name, src in users:
                marker = ("module", mod, imported)
                if kind is None:
                    out[(f, name)] = (marker, f"`{name}` from {mod}: {data}")
                    continue
                v = evaluate_js(data)
                if v is None:
                    out[(f, name)] = (marker, f"`{name}` from {mod} = {data.strip()[:60]}: not an exact literal expression")
                else:
                    out[(f, name)] = (v, f"`{name}` = {data.strip()[:60]} ({mod}, one hop)")
    for f, ns in py.items():
        module = _parse_py(tree.read(f))
        for name in ns:
            if module is None:
                out[(f, name)] = (None, "unparsable")
                continue
            kind, data = _py_one_binding(module, name)
            if kind is None:
                out[(f, name)] = (None, data)
            elif kind == "const":
                v = evaluate_py_node(data, tree.read(f))
                out[(f, name)] = (v, f"`{name}` (same file)") if v is not None else (
                    None, f"`{name}`'s value is not an exact literal expression")
            else:
                level, modname, imported = data
                mod, why = resolve_py_module(tree, f, level, modname)
                if mod is None:
                    out[(f, name)] = (None, f"`{name}` imported from {why}")
                    continue
                tree.ensure([mod])
                src_text = tree.read(mod)
                src = _parse_py(src_text)
                k2, d2 = _py_one_binding(src, imported) if src is not None else (None, "unparsable source")
                if k2 != "const":
                    out[(f, name)] = (None, f"`{name}` from {mod}: {d2 if k2 is None else 'a second hop'}")
                    continue
                v = evaluate_py_node(d2, src_text)
                out[(f, name)] = (v, f"`{name}` ({mod}, one hop)") if v is not None else (
                    None, f"`{name}` from {mod}: not an exact literal expression")
    return out


def counts_of(findings: dict) -> dict:
    out = {}
    for f, recs in findings.items():
        c = Counter(r["rule"] for r in recs if r["status"] == "finding")
        if c:
            out[f] = dict(sorted(c.items()))
    return dict(sorted(out.items()))


# --- baseline semantics (the vagaris ratchet's analyze/changeGroups/baselineWrite, root R4'd on #849) ---------------

def parse_name_status(z: str) -> list[tuple[str, str, str]]:
    """`git diff --name-status -z` as [(status, from, to)]; a rename or copy carries two paths."""
    parts, out, i = z.split("\0"), [], 0
    while i < len(parts) and parts[i]:
        status = parts[i]
        frm = parts[i + 1] if i + 1 < len(parts) else ""
        i += 2
        to = frm
        if status[:1] in ("R", "C"):
            to = parts[i] if i < len(parts) else ""
            i += 1
        if not frm or not to:
            raise Refusal(f"git diff --name-status: a truncated {status} entry")
        out.append((status, frm, to))
    return out


def change_groups(changes, keep) -> list[dict]:
    """Touched in-scope files as groups {old: [base paths], now: [head paths]}. A rename joins its two paths; a copy
    joins the new path to its source (git's -C copies only out of a file the same change modifies: a split)."""
    parent = {}

    def node(x):
        parent.setdefault(x, x)
        return x

    def find(x):
        while parent[x] != x:
            x = parent[x]
        return x

    old, now = set(), set()
    for status, frm, to in changes:
        s = status[0]
        if s in ("R", "C"):
            src, dst = keep(frm), keep(to)
            if src:
                old.add(node(frm))
            if src and s == "C":
                now.add(frm)
            if dst:
                now.add(node(to))
            if src and dst:
                parent[find(to)] = find(frm)
        elif keep(frm):
            node(frm)
            if s != "A":
                old.add(frm)
            if s != "D":
                now.add(frm)
    groups = {}
    for x in parent:
        g = groups.setdefault(find(x), {"old": [], "now": []})
        if x in old:
            g["old"].append(x)
        if x in now:
            g["now"].append(x)
    return sorted(({"old": sorted(g["old"]), "now": sorted(g["now"])} for g in groups.values()),
                  key=lambda g: (g["old"] or g["now"])[0])


def judge(found: dict, allowed: dict) -> tuple[list[str], list[str]]:
    """Counts against counts: a RISE is a problem, a DROP a notice (a failure there would red a merge group of two
    independent conversions of one file, the F17 shape)."""
    problems, notices = [], []
    for f in sorted(set(found) | set(allowed)):
        n, a = found.get(f, 0), allowed.get(f, 0)
        if n > a:
            problems.append(f"{f}: {n} finding(s), the baseline allows {a}: a new one")
        elif n < a:
            notices.append(f"{f}: {n} finding(s), the baseline allows {a}: a gain; write-baseline locks it in")
    return problems, notices


def base_raises(committed: dict, base: dict, found: dict, detection_changed: bool, identical: set,
                base_tree_found: dict, same_debt: set | None = None,
                refusal: str = PIN_NOT_MOVED) -> tuple[list[str], list[str], list[tuple[str, int, int]]]:
    """(problems, notices, locked) for the committed counts of UNTOUCHED files against the base's (K2 D8). A raise is
    refused unless all of root's guards hold (11-01, and the #68 RC):
      1. the change is a detection change (`detection_changed`, lock_in_refusal): the running job's PIN of this check
         moved, read from its workflows at the base and at the head, never from a field the baseline declares, and
         the base baseline was written by a check that detects differently (`refusal` says why not);
      2. the file is byte-identical at the base (`identical`), and the BASE TREE, censused under the running check,
         already holds the same findings (`base_tree_found`, and by identity `same_debt`: the same line, position,
         kind and value, so a swap of which bound is short cannot keep the count), censused under the BASE's own
         configuration (its launchers): so a change elsewhere, such as a lowered constant an untouched file imports
         or a removed launcher, can never pass its new findings off as old debt;
      3. the raise goes to EXACTLY that count: committed = base tree = head;
      4. every raised file is returned in `locked`, for the summary."""
    problems, notices, locked = [], [], []
    for f, n in sorted(committed.items()):
        b, held, was = base.get(f, 0), found.get(f, 0), base_tree_found.get(f, 0)
        if n <= b:
            continue
        why = None
        if not detection_changed:
            why = refusal
        elif f not in identical:
            why = "the file is not byte-identical at the base"
        elif was != held:
            why = (f"the base tree holds {was} finding(s) in it under this check, the head {held}: a change elsewhere "
                   "(an imported constant, a launcher) added them, so they are new, not old debt")
        elif same_debt is not None and f not in same_debt:
            why = ("the base tree holds the same count but not the same findings (line, position, value): a change "
                   "elsewhere swapped which bound is short")
        elif n != held:
            why = f"a detection change may lock in exactly the {held} finding(s) the file holds, not {n}"
        if why:
            problems.append(f"{f}: the committed baseline allows {n}, the base allowed {b}: a raise of the baseline "
                            f"itself ({why})")
        else:
            locked.append((f, b, n))
            notices.append(f"{f}: debt locked in by a detection change: {b} -> {n} (byte-identical at the base, and the "
                           "base tree holds the same findings under this check)")
    return problems, notices, locked


def analyze(found: dict, committed: dict, change: dict | None, event: str, detection_changed: bool = False,
            identical: frozenset = frozenset(), base_tree_found: dict | None = None,
            same_debt: set | None = None, refusal: str = PIN_NOT_MOVED) -> tuple[list[str], list[str], set, list]:
    """One rule's judgement: (problems, notices, allow_raise, locked). `found`/`committed` map file -> count; `change`
    is pr_change()'s result for this rule, or None without a base. `locked` lists the untouched files whose debt a
    detection change locks in (base_raises)."""
    if change is None:
        problems, notices = judge(found, committed)
        return problems, notices + ["no base commit given: every file is judged against the committed baseline; the "
                                    "touched-file, raise and narrowing checks need --base"], set(), []
    touched = {f for g in change["groups"] for f in g["old"] + g["now"]}
    keep = lambda d: {f: n for f, n in d.items() if f not in touched}  # noqa: E731
    problems, notices = judge(keep(found), keep(committed))
    locked = []
    if change["base_counts"] is not None:
        p, n, locked = base_raises(keep(committed), change["base_counts"], keep(found), detection_changed, identical,
                                   base_tree_found or {}, same_debt, refusal)
        problems += p
        notices += n
    else:
        notices.append(f"the base {change['sha'][:12]} has no baseline: this change introduces it")
    # Under a detection change, write-baseline --base may lock in an untouched, byte-identical file's findings (the
    # debt the base tree held); otherwise nothing untouched may rise.
    allow = ({f for f, n in keep(found).items() if n > keep(committed).get(f, 0) and f in identical
              and (base_tree_found or {}).get(f, 0) == n and (same_debt is None or f in same_debt)}
             if detection_changed else set())
    for g in change["groups"]:
        head = sum(found.get(f, 0) for f in g["now"])
        was = sum(change["base_found"].get(f, 0) for f in g["old"])
        moved = g["old"] != g["now"]
        label = (g["now"][0] if not moved else f"{', '.join(g['now'])} (new)" if not g["old"]
                 else f"the rename/split of {', '.join(g['old'])} into {', '.join(g['now']) or 'nothing'}")
        failed = head > was
        if failed:
            problems.append(f"{label}: {head} finding(s), the base had {was}: a new one")
        else:
            allow.update(g["now"])
        for f in sorted(set(g["old"]) | set(g["now"])):
            n, listed = found.get(f, 0), committed.get(f, 0)
            base_n = (change["base_counts"] or {}).get(f, 0)
            if listed < n and not failed:
                problems.append(f"{f}: {n} finding(s), the baseline lists {listed}: the "
                                f"{'rename or split' if moved else 'change'} is attributed, but the baseline is not "
                                "updated; run write-baseline --base " + change["sha"])
            elif listed > n:
                if change["base_counts"] is not None and listed > base_n:
                    problems.append(f"{f}: the committed baseline allows {listed}, the file has {n} and the base "
                                    f"allowed {base_n}: a raise of the baseline itself")
                elif event == "pull_request":
                    problems.append(f"{f}: {n} finding(s), the baseline lists {listed}: this change touches the "
                                    "file, so lock the gain in (write-baseline in this pull request)")
                else:
                    notices.append(f"{f}: {n} finding(s), the baseline lists {listed}: a gain; write-baseline locks "
                                   "it in")
    return problems, notices, allow, locked


def baseline_write(found: dict, old: dict, seed: bool, allow: set) -> tuple[dict | None, str]:
    """(new counts, "") or (None, why). seed creates the first counts and is refused once any exist; an ordinary
    write may only LOWER counts, except for files in `allow` (a rename or split attributed against a base)."""
    if seed:
        return (None, "counts exist; --seed only writes the first ones (write-baseline lowers them)") if old \
            else (found, "")
    raised = [f"{f}: {old.get(f, 0)} -> {n}" for f, n in sorted(found.items()) if n > old.get(f, 0) and f not in allow]
    if raised:
        return None, "refusing to RAISE the baseline; prove the bound instead:\n    " + "\n    ".join(raised)
    return found, ""


def per_rule(counts: dict, rule: str) -> dict:
    return {f: c[rule] for f, c in counts.items() if c.get(rule)}


def narrowing(base_cfg: dict, head_cfg: dict, files: list[str]) -> list[str]:
    """What the candidate's configuration no longer scans or judges, decided from the base's (condition 4)."""
    problems = []
    bs, hs = Scope(base_cfg), Scope(head_cfg)
    lost = [f for f in files if bs.scanned(f) and not hs.scanned(f)]
    if lost:
        problems.append(f"the configuration no longer scans {len(lost)} file(s) the base's covers: "
                        + ", ".join(lost[:10]) + (" ..." if len(lost) > 10 else ""))
    head_trees = {t["glob"]: t["min_files"] for t in head_cfg["trees"]}
    for t in base_cfg["trees"]:
        if t["glob"] not in head_trees:
            problems.append(f"tree `{t['glob']}` is removed (the base scans it, min_files {t['min_files']})")
        elif head_trees[t["glob"]] < t["min_files"]:
            problems.append(f"tree `{t['glob']}`: min_files lowered from {t['min_files']} to {head_trees[t['glob']]}")
    base_l = {(la["name"], la["module"]): la["hook_floor_ms"] for la in base_cfg["launchers"]}
    for la in head_cfg["launchers"]:
        key = (la["name"], la["module"])
        if key not in base_l:
            problems.append(f"launcher {la['name']} ({la['module']}) is added: it lowers a hook floor, so it lands "
                            "only with the baseline that introduces the check")
        elif la["hook_floor_ms"] < base_l[key]:
            problems.append(f"launcher {la['name']}: hook_floor_ms lowered from {base_l[key]} to {la['hook_floor_ms']}")
    return problems


def tree_floors(cfg: dict, scanned: list[str]) -> list[str]:
    """Each tree's positive control: at least min_files scanned files match its glob (execnode's review, R3c)."""
    problems = []
    for glob, rx, minimum in Scope(cfg).trees:
        n = sum(1 for f in scanned if rx.match(f))
        if n < minimum:
            problems.append(f"tree `{glob}` scans {n} file(s), below its min_files {minimum}: a glob that matches less "
                            "than it did reads red, not clean")
    return problems


def unscanned(cfg: dict, files: list[str]) -> dict:
    sc = Scope(cfg)
    return {"language": [f for f in files if sc.covers(f) and not sc.scanned(f)],
            "outside_trees": [f for f in files if TEST_LIKE.search(f) and not sc.covers(f)]}


def read_base_config(root: Path, sha: str) -> dict | None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Refusal(f"base {sha!r} is not a full commit id")
    if subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=root, capture_output=True).returncode:
        raise Refusal(f"base {sha} is not a commit in this clone (fetch it): the checks against the base cannot run")
    listed = subprocess.run(["git", "ls-tree", "--name-only", sha, "--", BASELINE_PATH], cwd=root,
                            capture_output=True, text=True)
    if listed.returncode:
        raise Refusal(f"git ls-tree {sha} exited {listed.returncode}")
    if not listed.stdout.strip():
        return None
    p = subprocess.run(["git", "show", f"{sha}:{BASELINE_PATH}"], cwd=root, capture_output=True, text=True)
    if p.returncode:
        raise Refusal(f"git show {sha}:{BASELINE_PATH} exited {p.returncode}")
    return load_config(p.stdout, f"{BASELINE_PATH} at the base {sha[:12]}")


def pr_change(root: Path, sha: str, head_cfg: dict, tmp: Path) -> dict:
    """The change against base `sha`: groups, the base's ACTUAL findings in every old path (scanned from its blobs
    under the candidate's rules), its committed counts and configuration, and the marks it held."""
    base_cfg = read_base_config(root, sha)
    d = subprocess.run(["git", "diff", "--name-status", "-z", f"-M{SIMILARITY}", f"-C{SIMILARITY}", sha, "HEAD"],
                       cwd=root, capture_output=True)
    if d.returncode:
        raise Refusal(f"git diff {sha} HEAD exited {d.returncode}: {d.stderr.decode(errors='replace').strip()[:300]}")
    scope = Scope(head_cfg)
    changes = parse_name_status(d.stdout.decode("utf-8", "surrogateescape"))
    groups = change_groups(changes, scope.scanned)
    # A file the base's configuration did not scan, but the candidate's does, is judged like a touched file: against
    # what the base held, so a widened tree is seeded from the base's findings and never against an allowance.
    base_tree = git_tree(root, sha, tmp / "base")
    if base_cfg is not None:
        bscope = Scope(base_cfg)
        touched = {f for g in groups for f in g["old"] + g["now"]}
        for f in tracked_files(root):
            if scope.scanned(f) and not bscope.scanned(f) and f not in touched:
                groups.append({"old": [f] if f in base_tree.fileset else [], "now": [f]})
    old_paths = sorted({f for g in groups for f in g["old"] if f in base_tree.fileset})
    res = census(base_tree, old_paths, head_cfg["launchers"])
    renamed_out = [(frm, to) for status, frm, to in changes
                   if status[:1] == "R" and scope.scanned(frm) and not scope.scanned(to)]
    return {"sha": sha, "groups": groups, "base_cfg": base_cfg, "base_tree": base_tree,
            "base_counts_all": base_cfg["counts"] if base_cfg else None, "base_found_all": counts_of(res["findings"]),
            "base_marked": [{"file": f, "line": r["line"], "reason": r["mark"]} for f, recs in res["findings"].items()
                            for r in recs if r["status"] == "marked"],
            "renamed_out": renamed_out, "skipped": b"rename detection was skipped" in d.stderr.lower()}


def new_marks(head_findings: dict, change: dict | None) -> list[dict]:
    """The bounds this change newly EXEMPTS by a mark: per group, the head's marked bounds that the base's marked
    bounds (by reason) do not account for. A mark the base held on no bound, moved onto one, is new (root's #60 R4
    L4, S16)."""
    if change is None:
        return []
    out = []
    for g in change["groups"]:
        was = Counter(m["reason"] for m in change["base_marked"] if m["file"] in g["old"])
        head = sorted(({"file": f, "line": r["line"], "reason": r["mark"]} for f in g["now"]
                       for r in head_findings.get(f, []) if r["status"] == "marked"), key=lambda m: (m["file"], m["line"]))
        for m in head:
            if was[m["reason"]] > 0:
                was[m["reason"]] -= 1
            else:
                out.append(m)
    return out


# --- self-test ---------------------------------------------------------------------------------------------------

def self_test(verbose: bool = False) -> list[str]:
    """Run every fixtures/<case>/ through the real scan; return the failures (empty = the check is intact)."""
    failures, covered = [], set()
    cases = sorted(p for p in (HERE / "fixtures").iterdir() if p.is_dir())
    if not cases:
        return ["no fixtures: the self-test cannot run"]
    for case in cases:
        try:
            spec = json.loads((case / "expect.json").read_text(encoding="utf-8"))
            cfg = load_config(json.dumps({"schema": SCHEMA, "counts": {}, **spec["config"]}), f"{case.name}/expect.json")
            files = sorted(str(p.relative_to(case)) for p in case.rglob("*") if p.is_file() and p.name != "expect.json")
            scanned = [f for f in files if Scope(cfg).scanned(f)]
            res = census(Tree(case, files), scanned, cfg["launchers"])
        except (Refusal, OSError, ValueError, KeyError) as e:
            failures.append(f"{case.name}: {e}")
            continue
        got = {}
        for f, recs in res["findings"].items():
            c = Counter(r["status"] for r in recs)
            got[f] = {k: c[k] for k in ("finding", "cleared", "marked") if c[k]}
            covered.update((LANGUAGE_OF.get(posixpath.splitext(f)[1], "config"), f"{r['rule']}.{r['position']}.{r['kind']}")
                           for r in recs if r["status"] == "finding")
        want = {f: {k: v for k, v in c.items() if v} for f, c in spec.get("files", {}).items()}
        if got != want:
            failures.append(f"{case.name}: findings {json.dumps(got, sort_keys=True)}, expected "
                            f"{json.dumps(want, sort_keys=True)}")
        for key in ("unparsable", "recovered", "not_covered"):
            # NOT COVERED is one entry per row (a dropped listing in a file with others still fails); the others per file.
            have = sorted(row[0] for row in res[key]) if key == "not_covered" else sorted({row[0] for row in res[key]})
            if have != sorted(spec.get(key, [])):
                failures.append(f"{case.name}: {key} {have}, expected {sorted(spec.get(key, []))}")
        if verbose:
            print(f"self-test {case.name}: {'ok' if not any(x.startswith(case.name + ':') for x in failures) else 'FAILED'}")
    # Every rule of every language must be planted RED somewhere, so a gutted rule cannot pass unnoticed: for python
    # that includes every position the binding pass reads (PY_BOUND_RULES), which PY_CALLS must read exactly.
    reads = {f"{RULE}.{pos}.{kind}" for pos, kind, *_ in PY_CALLS.values()} | {f"{RULE}.http-tuple.condition"}
    if reads != set(PY_BOUND_RULES):
        failures.append(f"the binding pass reads {sorted(reads)}, PY_BOUND_RULES declares {sorted(PY_BOUND_RULES)}")
    for lang in ("typescript", "tsx", "javascript", "python"):
        for rid in re.findall(r"(?m)^id: (literal-bound\.\S+)$", compose_rules(lang)) + (
                list(PY_BOUND_RULES) if lang == "python" else []):
            if (lang, rid) not in covered:
                failures.append(f"rule {rid} ({lang}) has no planted RED finding in fixtures/")
    return failures


# --- the run -----------------------------------------------------------------------------------------------------

# The events a run may judge, and where each one's base comes from (root's #60 R4 B3 and its delta, 11-01). Every
# event whose payload carries a pull request (pull_request, pull_request_target and the review events, which GitHub
# runs from the PR's merge ref with the PR's own workflow) takes that PR's base; merge_group takes the group's base.
PR_PAYLOAD_EVENTS = ("pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment")
BASE_EVENTS = {**{e: ("pull_request", "base", "sha") for e in PR_PAYLOAD_EVENTS}, "merge_group": ("merge_group", "base_sha")}
ZERO = re.compile(r"0{40}")


def in_actions_env(env: dict) -> bool:
    """Any trace of a runner means CI (root's #64 R4 LOW): a step that blanks one variable cannot unlock local modes."""
    return env.get("GITHUB_ACTIONS") == "true" or bool(env.get("GITHUB_EVENT_PATH")) or bool(env.get("RUNNER_TEMP"))


def _payload(env: dict, event: str) -> dict:
    try:
        return json.loads(Path(env.get("GITHUB_EVENT_PATH", "")).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refusal(f"a {event} run must read its base from GITHUB_EVENT_PATH, which is missing or malformed")


def resolve_base(arg: str, event: str, env: dict, head: str, in_actions: bool = False) -> str | None:
    """The base commit a run is judged against.

    In Actions the base is the EVENT's, from $GITHUB_EVENT_PATH (the runner writes it; a workflow cannot override
    GITHUB_*), so an edit to the candidate workflow cannot switch off the touched-file, raise and narrowing checks:
      - an event carrying a pull request (PR_PAYLOAD_EVENTS) takes pull_request.base.sha, and merge_group takes
        merge_group.base_sha; a `base` input that names any other commit is refused, and so is a base equal to the
        head;
      - push takes the payload's `before` and ignores the input; all zeros (a branch's first push) is no base, and
        the run says so; a push outside the default branch is refused (#60 delta2 LOW);
      - workflow_dispatch alone takes the input as given;
      - every other event is refused.
    Outside Actions (a local or tool run) the input is taken as given, except that a PR or merge-group --event needs
    the event file, as in CI. Empty or zeros: no base."""
    given = (arg or "").strip()
    if in_actions or event in BASE_EVENTS:
        if event in BASE_EVENTS:
            want = _payload(env, event)
            try:
                for key in BASE_EVENTS[event]:
                    want = want[key]
            except (KeyError, TypeError):
                raise Refusal(f"the {event} event carries no base commit")
            if not (isinstance(want, str) and re.fullmatch(r"[0-9a-f]{40}", want)):
                raise Refusal(f"the {event} event carries no base commit")
            if given and given != want:
                raise Refusal(f"the base input {given} is not the {event} event's base {want}: on this event the base "
                              "is the event's, so the touched-file, raise and narrowing checks cannot be switched off")
            if want == head:
                raise Refusal(f"the {event} event's base is the head itself")
            return want
        if event == "push":
            payload = _payload(env, event)
            ref, default = payload.get("ref"), (payload.get("repository") or {}).get("default_branch")
            if not (isinstance(ref, str) and isinstance(default, str) and default):
                raise Refusal("the push event carries no ref or default branch")
            if ref != f"refs/heads/{default}":
                raise Refusal(f"a push to {ref} is not a push to the default branch {default}: this check's verdicts "
                              "come from pull_request, merge_group, default-branch push and workflow_dispatch runs "
                              "(a feature branch's first push has no base, so it would pass unjudged)")
            before = payload.get("before", "")
            if not (isinstance(before, str) and re.fullmatch(r"[0-9a-f]{40}", before)):
                raise Refusal("the push event carries no `before` commit")
            return None if ZERO.fullmatch(before) else before
        if event != "workflow_dispatch":
            raise Refusal(f"event {event or '(none)'} is not one this check judges in CI (pull_request and its review "
                          "events, pull_request_target, merge_group, push, workflow_dispatch)")
    if not given or ZERO.fullmatch(given) or re.fullmatch(r"0+", given):
        return None
    if given == head:
        raise Refusal("the base input is the head itself, which judges nothing")
    return given


def ensure_commit(root: Path, sha: str, in_actions: bool) -> None:
    """Fetch the base alone (the check reads only the two trees) when a depth-1 checkout lacks it."""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return
    have = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=root, capture_output=True)
    if have.returncode and in_actions:
        subprocess.run(["git", "fetch", "--no-tags", "--quiet", "--depth=1", "origin", sha], cwd=root,
                       capture_output=True, timeout=300)


def repo_root(arg: str | None) -> Path:
    if arg:
        return Path(arg).resolve()
    p = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if p.returncode:
        raise Refusal("not inside a git repository (pass --root)")
    return Path(p.stdout.strip())


def load_head_config(root: Path) -> dict:
    path = root / BASELINE_PATH
    if not path.is_file():
        raise Refusal(f"{BASELINE_PATH} is missing: it holds this check's trees, launchers and counts")
    return load_config(path.read_text(encoding="utf-8"), BASELINE_PATH)


def run(root: Path, base: str | None, event: str, tmp: Path, running: tuple[str, str, str] | None = None,
        in_actions: bool = False) -> dict:
    cfg = load_head_config(root)
    files = tracked_files(root)
    scope = Scope(cfg)
    links = tracked_symlinks(root)
    scanned = [f for f in files if scope.scanned(f) and f not in links]
    res = census(Tree(root, files), scanned, cfg["launchers"])
    found = counts_of(res["findings"])
    problems, notices = [], []
    problems += [f"{f}{':' + str(ln) if ln else ''}: unparsable ({why}): the check cannot judge it"
                 for f, ln, why in res["unparsable"]]
    problems += [f"{f}: a symlink in the trees is not scanned; judge its target by its own path (list the target in a "
                 "tree, or exclude the link)" for f in sorted(links) if scope.scanned(f)]
    problems += tree_floors(cfg, scanned)
    change = pr_change(root, base, cfg, tmp) if base else None
    if change and change["base_cfg"] is not None:
        problems += narrowing(change["base_cfg"], cfg, files)
    if change:
        problems += [f"{frm} is renamed to {to}, outside the scanned trees: a test file that leaves the trees is a "
                     "narrowing (move it back, or widen the trees in the same change)" for frm, to in change["renamed_out"]]
    digest = check_digest()
    if cfg.get("check_digest") is None:
        problems.append("[check_digest] the baseline does not record the check version that wrote it: run "
                        "write-baseline with this check")
    elif cfg["check_digest"] != digest:
        problems.append(f"[check_digest] the baseline names check {cfg['check_digest'][:12]}, not this check ({digest[:12]}): "
                        "a baseline names the check that wrote it, so run write-baseline with this check")
    refusal = lock_in_refusal(root, change, running, in_actions, digest)
    detection_changed = refusal is None
    identical, base_tree_found_all, base_ids = frozenset(), {}, {}
    if change:
        touched = {f for g in change["groups"] for f in g["old"] + g["now"]}
        identical = frozenset(f for f in byte_identical(root, change["sha"], sorted(set(found) | set(cfg["counts"])))
                              if f not in touched)
        base_counts_all = change["base_counts_all"] or {}
        candidates = sorted(f for f in identical
                            if any(max(found.get(f, {}).get(r, 0), cfg["counts"].get(f, {}).get(r, 0))
                                   > base_counts_all.get(f, {}).get(r, 0)
                                   for r in set(found.get(f, {})) | set(cfg["counts"].get(f, {}))))
        if detection_changed and candidates:
            # The base tree, under the BASE's own configuration (its launchers and their floors), with this check.
            base_res = census(change["base_tree"], candidates, change["base_cfg"]["launchers"])["findings"]
            base_tree_found_all = counts_of(base_res)
            base_ids = finding_ids(base_res)
    allow, locked_in = {}, []
    for rule in sorted({r for c in list(found.values()) + list(cfg["counts"].values()) for r in c} | {RULE}):
        sub = None
        if change:
            sub = {"sha": change["sha"], "groups": change["groups"],
                   "base_counts": per_rule(change["base_counts_all"], rule) if change["base_counts_all"] is not None
                   else None, "base_found": per_rule(change["base_found_all"], rule)}
        head_ids = finding_ids({f: res["findings"].get(f, []) for f in base_ids})
        same = {f for f in base_ids if base_ids[f].get(rule) == head_ids.get(f, {}).get(rule)}
        p, n, a, lk = analyze(per_rule(found, rule), per_rule(cfg["counts"], rule), sub, event, detection_changed,
                              identical, per_rule(base_tree_found_all, rule), same, refusal or PIN_NOT_MOVED)
        problems += [f"[{rule}] {x}" for x in p]
        notices += [f"[{rule}] {x}" for x in n]
        allow[rule] = sorted(a)
        locked_in += [{"rule": rule, "file": f, "base": b, "now": now} for f, b, now in lk]

    if change and change["skipped"]:
        notices.append("git skipped inexact rename detection on this diff, so a rename or split may read as new files")
    marks = res["marks"]
    added = new_marks(res["findings"], change)
    return {"schema": SCHEMA, "check": CHECK_ID, "base": base, "event": event, "scanned_files": len(scanned),
            "counts": found, "findings": res["findings"], "marks": marks, "new_marks": added,
            "recovered": res["recovered"], "not_covered": res["not_covered"], "unscanned": unscanned(cfg, files),
            "covered": COVERED, "locked_in": locked_in, "check_digest": digest, "problems": problems,
            "notices": notices, "_allow": allow, "_cfg": cfg}


def finding_ids(findings: dict) -> dict:
    """file -> rule -> the multiset of its findings' identities (line, position, kind, value), so a lock-in compares
    WHICH bounds are short, not only how many."""
    out = {}
    for f, recs in findings.items():
        for r in recs:
            if r["status"] == "finding":
                out.setdefault(f, {}).setdefault(r["rule"], Counter())[(r["line"], r["position"], r["kind"], r["value"])] += 1
    return out


def byte_identical(root: Path, base: str, paths: list[str]) -> set[str]:
    """The paths whose blob at `base` is the blob the census read (D8 guard 2: judged from the base TREE). The head
    side is the working tree, hashed with git, because that is what the census scanned (one source)."""
    if not paths:
        return set()

    def blobs(rev: str) -> dict:
        r = subprocess.run(["git", "ls-tree", "-r", "-z", rev, "--", *paths], cwd=root, capture_output=True)
        if r.returncode:
            raise Refusal(f"git ls-tree {rev} exited {r.returncode}: the byte-identity check cannot run")
        out = {}
        for entry in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
            if "\t" in entry:
                meta, path = entry.split("\t", 1)
                out[path] = meta.split()[2]
        return out

    at_base = blobs(base)
    present = [f for f in paths if f in at_base and (root / f).is_file()]
    if not present:
        return set()
    r = subprocess.run(["git", "hash-object", "--stdin-paths"], cwd=root, input="\n".join(present) + "\n",
                       capture_output=True, text=True)
    if r.returncode:
        raise Refusal(f"git hash-object exited {r.returncode}: the byte-identity check cannot run")
    return {f for f, h in zip(present, r.stdout.split()) if at_base[f] == h}


def summary_md(out: dict) -> str:
    total = Counter(r["status"] for recs in out["findings"].values() for r in recs)
    lines = ["### test-bounds (K2)", "",
             f"{out['scanned_files']} file(s) scanned; {total['finding']} finding(s), {total['cleared']} cleared by "
             f"value, {total['marked']} marked. Base: {out['base'] or 'none'}; event: {out['event'] or 'none'}.", "",
             "**Covered positions** (a bound anywhere else is not judged, so its absence here is not a pass):", ""]
    lines += [f"- {k}: {v}" for k, v in out["covered"].items()] + [""]
    if out["problems"]:
        lines += [f"**{len(out['problems'])} problem(s)**", ""] + [f"- {p}" for p in out["problems"][:60]] + [""]
    lk = out.get("locked_in", [])
    lines += [f"**Debt locked in by a detection change: {len(lk)} (file, rule) raise(s)**", ""]
    lines += [f"- [{x['rule']}] {x['file']}: {x['base']} -> {x['now']}" for x in lk[:60]]
    if len(lk) > 60:
        lines.append(f"- ... and {len(lk) - 60} more: every one is in the log (DEBT LOCKED IN) and the findings JSON")
    lines.append("")
    lines += [f"**New `timeout under test:` marks: {len(out['new_marks'])}**", ""]
    lines += [f"- {m['file']}:{m['line']} {m['reason'] or '(no reason)'}" for m in out["new_marks"][:50]] + [""]
    lines += [f"All marks: {len(out['marks'])}", ""] + [f"- {m['file']}:{m['line']} {m['reason'] or '(no reason)'}"
                                                         for m in out["marks"][:50]] + [""]
    u = out["unscanned"]
    lines += [f"UNSCANNED: {len(u['language'])} tree file(s) in a language this check does not read; "
              f"{len(u['outside_trees'])} test-like file(s) outside every tree.", ""]
    lines += [f"- language: {f}" for f in u["language"][:30]] + [f"- outside: {f}" for f in u["outside_trees"][:30]]
    lines += ["", f"RECOVERED parses (listed, not red): {len(out['recovered'])}", ""]
    lines += [f"- {f}:{ln}" for f, ln in out["recovered"][:30]]
    lines += ["", f"NOT COVERED calls (a covered call this check cannot read the bound of; listed, not red): "
                  f"{len(out['not_covered'])}", ""]
    lines += [f"- {f}:{ln} {why}" for f, ln, why in out["not_covered"][:30]]
    return "\n".join(lines) + "\n"


def emit(out: dict, findings_path: str | None) -> None:
    public = {k: v for k, v in out.items() if not k.startswith("_")}
    if findings_path:
        Path(findings_path).write_text(json.dumps(public, indent=1, default=str) + "\n", encoding="utf-8")
    for p in out["problems"]:
        print(f"REFUSE: {p}")
    for n in out["notices"]:
        print(f"notice: {n}")
    for m in out["new_marks"]:
        print(f"NEW MARK: {m['file']}:{m['line']} timeout under test: {m['reason'] or '(no reason)'}")
    for x in out.get("locked_in", []):
        print(f"DEBT LOCKED IN: [{x['rule']}] {x['file']}: {x['base']} -> {x['now']} (a detection change)")
    for k, v in out["covered"].items():
        print(f"covered ({k}): {v}")
    u = out["unscanned"]
    print(f"UNSCANNED: {len(u['language'])} tree file(s) in a language this check does not read, "
          f"{len(u['outside_trees'])} test-like file(s) outside every tree; RECOVERED parses: {len(out['recovered'])}")
    for f, ln, why in out["not_covered"]:
        print(f"NOT COVERED: {f}:{ln} {why}")
    total = sum(sum(c.values()) for c in out["counts"].values())
    print(f"test-bounds: {out['scanned_files']} file(s) scanned, {total} finding(s) counted, "
          f"{len(out['marks'])} mark(s) ({len(out['new_marks'])} new), {len(out['problems'])} problem(s)")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md(out))
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"problems={len(out['problems'])}\nnew-marks={len(out['new_marks'])}\n"
                     f"findings-file={findings_path or ''}\n")


def write_baseline_file(root: Path, cfg: dict, counts: dict) -> None:
    text = (root / BASELINE_PATH).read_text(encoding="utf-8")
    raw = json.loads(text)
    raw["counts"] = {f: counts[f] for f in sorted(counts)}
    raw.setdefault("check", CHECK_ID)
    raw["check_digest"] = check_digest()
    (root / BASELINE_PATH).write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="test-bounds (K2): short wall-clock bounds in test code")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "write-baseline"):
        p = sub.add_parser(name)
        p.add_argument("--root")
        p.add_argument("--base", default=os.environ.get("TEST_BOUNDS_BASE", ""))
        p.add_argument("--event", default="")
        if name == "check":
            p.add_argument("--findings")
        else:
            p.add_argument("--seed", action="store_true")
    sub.add_parser("self-test")
    args = ap.parse_args(argv)
    try:
        failures = self_test(verbose=args.cmd == "self-test")
        if args.cmd == "self-test":
            for f in failures:
                print(f"SELF-TEST FAILED: {f}")
            print(f"self-test: {'ok' if not failures else str(len(failures)) + ' failure(s)'}")
            return 1 if failures else 0
        root = repo_root(args.root)
        in_actions = in_actions_env(os.environ)
        # In Actions the event is the runner's, never a flag a workflow passes.
        event = os.environ.get("GITHUB_EVENT_NAME", "") if in_actions else args.event.strip()
        if in_actions and args.event.strip() and args.event.strip() != event:
            raise Refusal(f"--event {args.event.strip()} is not this run's event {event}")
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
        base = resolve_base(args.base, event, dict(os.environ), head, in_actions)
        if base is None and in_actions and event == "push":
            print("notice: a push with no `before` commit (a branch's first push): judged on the committed baseline "
                  "only; the pull request's own run is what gates it")
        if base:
            ensure_commit(root, base, in_actions)
        with tempfile.TemporaryDirectory() as tmp:
            out = run(root, base, event, Path(tmp), running_context(os.environ) if in_actions else None, in_actions)
        out["problems"] = [f"the check's own self-test failed: {f}" for f in failures] + out["problems"]
        if args.cmd == "check":
            emit(out, args.findings)
            return 1 if out["problems"] else 0
        cfg = out["_cfg"]
        blocking = [p for p in out["problems"] if not p.startswith("[")]
        if blocking:
            for p in blocking:
                print(f"REFUSE: {p}")
            return 1
        new = {}
        for rule, allow in sorted(out["_allow"].items()):
            counts, why = baseline_write(per_rule(out["counts"], rule), per_rule(cfg["counts"], rule), args.seed,
                                         set(allow))
            if counts is None:
                print(f"REFUSE: [{rule}] {why}")
                if not base and not args.seed:
                    print("REFUSE: a rename or split moves its allowance only against a base: "
                          "--base $(git merge-base origin/main HEAD)")
                return 1
            for f, n in counts.items():
                new.setdefault(f, {})[rule] = n
        write_baseline_file(root, cfg, new)
        print(f"test-bounds: {BASELINE_PATH} written: {sum(sum(c.values()) for c in new.values())} finding(s) in "
              f"{len(new)} file(s)")
        return 0
    except Refusal as e:
        print(f"REFUSE: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
