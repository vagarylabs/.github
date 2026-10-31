#!/usr/bin/env python3
"""test-bounds (K2): the ONE shared check that test code does not bound a wait with a short wall-clock value.

THE CLASS (F5). A test waits for a condition, caps a case or a hook, or gives a child process a deadline, with a
number of seconds or milliseconds. Below a hang guard's size, that number measures the runner's load, not the
behaviour, and a loaded runner turns it into a red. A correctness bound is a hang guard (a value at or above its
kind's floor, normally a named constant). Three repository gates held this class with three engines (vagaris
check-test-bounds-are-hang-guards.mjs, vagary-core test_ci_test_pg.py, vps-ansible test_subprocess_hang_guards.py);
this check replaces them, and each adoption PR declares what it retires.

ENGINE. ast-grep (pinned, rules in rules/) MATCHES every bound position and captures its value. This module is the
post-pass. It may only CLEAR a match on positive proof:
  - the value evaluates EXACTLY to at least the kind's floor (FLOORS_S). Exact evaluation accepts numeric literals
    (with `_`), unary minus, and + - * of those, and nothing else. Division, templates, calls, environment reads and
    legacy octal (`0210000`) are not evaluated, so they stay findings;
  - or the value is a NAME, resolved in ONE hop (root's GO 10-31: "resolver: one hop, four guards"):
      a same-file top-level `const NAME = <literal expr>` (Python: a module-level `NAME = <literal expr>`), or a
      direct named import from a RELATIVE path (`import { NAME } from "./x"`, `{ X as NAME }`; Python
      `from .x import NAME`) whose one target file holds `export const NAME = <literal expr>` (Python: the one
      module-level assignment). Guards: (1) NAME is bound nowhere else in the consuming file, in any scope; (2)
      exactly one binding at the source; (3) the exact evaluation above; (4) the relative path resolves to exactly
      one tracked file. Re-exports, namespace, default and package imports, and anything longer than one hop stay
      findings;
  - or the hook belongs to a declared LAUNCHER class (config `launchers`): a hook whose first argument calls a
    launcher imported, by the same one-hop rule, from the declared module, judged against the launcher's own floor
    (vagaris: embedded Postgres owns a 180 s startup, so its beforeAll needs 210 000 ms, below the 240 s hook floor);
  - or the line carries a mark `timeout under test: <what it proves>`. A mark is never silent: every mark is listed,
    and a mark this change adds is listed as NEW (classify.py's weakening report lists them too). A mark with no
    reason clears nothing.

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
    removed or given a lower min_files, or a launcher added or lowered, is a red. A change cannot narrow what is
    scanned or how it is judged; it can only widen it.
Without a base, every file is judged against the committed counts and the run says so.

SELF-TEST. Every run first runs the planted fixtures (fixtures/<case>/, each with expect.json): every rule's RED
must produce exactly its expected findings and every GREEN none, so a gutted rule or resolver fails the check itself.

Usage (exit 0 clean, 1 refused, 2 usage or tool error):
  check.py check [--root DIR] [--base SHA] [--event NAME] [--findings FILE]
  check.py write-baseline [--root DIR] [--base SHA] [--seed]
  check.py self-test
The ast-grep binary is $TEST_BOUNDS_SG (default `ast-grep` on PATH).
"""
from __future__ import annotations

import argparse
import ast
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
FLOORS_S = {"case": 120, "hook": 240, "condition": 60, "subprocess": 120}
LANGUAGE_OF = {".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
               ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".py": "python"}
UNIT = {"typescript": 1000, "tsx": 1000, "javascript": 1000, "python": 1}
JS_LANGS = ("typescript", "tsx", "javascript")
RULE_FILES = {"typescript": "literal-bound.yml", "tsx": "literal-bound.yml", "javascript": "literal-bound.yml",
              "python": "literal-bound.py.yml"}
# Rules whose matched node is the bound itself (a pair, a parameter, a keyword): a mark may sit on its first line.
SMALL_MATCH = {"option", "default", "config", "keyword"}
MARK = re.compile(r"timeout under test:[ \t]*(?P<why>[^\n]*)")
MIN_REASON = 3
SIMILARITY = "30%"
# Test-like paths, for the UNSCANNED list only (never for scope: the trees decide that).
TEST_LIKE = re.compile(r"(?:^|/)(?:[^/]+\.(?:test|spec)\.[^/]+|test_[^/]+\.py|[^/]+_test\.(?:py|go)|[^/]+\.bats"
                       r"|conftest\.py)$|(?:^|/)(?:__tests__|tests?)/[^/]+$")
JS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
JS_TWIN = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
NAME = re.compile(r"^[A-Za-z_$][\w$]*$")
SG_BATCH = 400


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
    strings = "[{ kind: string }, { kind: template_string }]" if lang in JS_LANGS else "[{ kind: string }]"
    out.append(f"id: parse-error\nlanguage: {lang}\nrule:\n  kind: ERROR\n  regex: \"[A-Za-z0-9_$]\"\n"
               f"  not: {{ inside: {{ stopBy: end, any: {strings} }} }}")
    out.append(f"id: recovered\nlanguage: {lang}\nrule: {{ kind: ERROR }}")
    out.append(f"id: mark\nlanguage: {lang}\nrule: {{ kind: comment, regex: \"timeout under test:\" }}")
    return "\n---\n".join(out) + "\n"


def sg_binary() -> str:
    sg = os.environ.get("TEST_BOUNDS_SG") or shutil.which("ast-grep")
    if not sg:
        raise Refusal("ast-grep not found: set TEST_BOUNDS_SG (the action fetches the pinned binary)")
    return sg


def sg_scan(root: Path, rules_text: str, files: list[str]) -> list[dict]:
    """Every match of the rules over `files` (repo-relative, under root). A tool failure raises: fail closed."""
    if not files:
        return []
    sg = sg_binary()
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "rules.yml"
        rules.write_text(rules_text, encoding="utf-8")
        for i in range(0, len(files), SG_BATCH):
            batch = files[i:i + SG_BATCH]
            p = subprocess.run([sg, "scan", "-r", str(rules), "--json=stream", "--no-ignore", "hidden",
                                "--no-ignore", "dot", "--no-ignore", "vcs", "--no-ignore", "parent", "--", *batch],
                               cwd=root, capture_output=True, text=True)
            if p.returncode != 0:
                raise Refusal(f"ast-grep scan exited {p.returncode}: {p.stderr.strip()[:400]}")
            for line in p.stdout.splitlines():
                if line.strip():
                    out.append(json.loads(line))
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
        return (self.root / path).read_text(encoding="utf-8", errors="replace")


def tracked_files(root: Path) -> list[str]:
    p = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True)
    if p.returncode != 0:
        raise Refusal(f"git ls-files exited {p.returncode}")
    return sorted(f for f in p.stdout.decode("utf-8", "surrogateescape").split("\0") if f)


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
    unknown = set(cfg) - {"schema", "check", "trees", "exclude", "launchers", "counts"}
    if unknown:
        raise Refusal(f"{where}: unknown keys {sorted(unknown)}")
    return {"trees": trees, "exclude": exclude, "launchers": launchers, "counts": counts}


class Scope:
    def __init__(self, cfg: dict):
        self.trees = [(t["glob"], glob_to_regex(t["glob"]), t["min_files"]) for t in cfg["trees"]]
        self.exclude = [glob_to_regex(g) for g in cfg["exclude"]]

    def covers(self, path: str) -> bool:
        return any(rx.match(path) for _, rx, _ in self.trees) and not any(rx.match(path) for rx in self.exclude)

    def scanned(self, path: str) -> bool:
        return self.covers(path) and posixpath.splitext(path)[1] in LANGUAGE_OF


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
        s = _SPEC.match(spec)
        if not s or s.group("imp") == "type":
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
    matches, marks_raw, unparsable, errors = [], {}, set(), set()
    for lang, group in sorted(by_lang.items()):
        extra = launch_rules if lang in JS_LANGS else []
        for m in sg_scan(tree.root, compose_rules(lang, extra), group):
            if m["ruleId"] == "parse-error":
                unparsable.add((m["file"], _line(m["range"])))
            elif m["ruleId"] == "recovered":
                errors.add((m["file"], _line(m["range"])))
            elif m["ruleId"] == "mark":
                mk = MARK.search(m["text"])
                for ln in range(_line(m["range"]), m["range"]["end"]["line"] + 2):
                    marks_raw.setdefault((m["file"], ln), (mk.group("why").strip().rstrip("*/").strip() if mk else ""))
            else:
                matches.append(m)
    launcher_hits = {}
    for m in matches:
        if m["ruleId"].startswith("launcher."):
            v = m["metaVariables"]["single"]["V"]
            launcher_hits[(m["file"], _span(v["range"]))] = launchers[int(m["ruleId"].split(".")[1])]
    bounds = [m for m in matches if m["ruleId"].startswith(RULE + ".")]
    # Names to resolve, and the files that read them.
    need = {}
    for m in bounds:
        text = m["metaVariables"]["single"]["V"]["text"].strip()
        if NAME.match(text):
            need.setdefault(m["file"], set()).add(text)
    for (f, _), la in launcher_hits.items():
        need.setdefault(f, set()).add(la["name"])
    resolved = _resolve_all(tree, need)
    findings, marks = {}, []
    for (f, ln), why in sorted(marks_raw.items()):
        marks.append({"file": f, "line": ln, "reason": why})
    for m in sorted(bounds, key=lambda m: (m["file"], m["range"]["byteOffset"]["start"])):
        f = m["file"]
        _, position, kind = m["ruleId"].split(".")
        lang = LANGUAGE_OF[posixpath.splitext(f)[1]]
        v = m["metaVariables"]["single"]["V"]
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
                if len(mark) >= MIN_REASON:
                    rec["status"] = "marked"
                else:
                    rec["reason"] += "; the `timeout under test:` mark gives no reason, so it clears nothing"
        findings.setdefault(f, []).append(rec)
    for f in files:
        if LANGUAGE_OF[posixpath.splitext(f)[1]] == "python" and _parse_py(tree.read(f)) is None:
            unparsable.add((f, 0))
    return {"findings": findings, "marks": marks, "unparsable": sorted(unparsable),
            "recovered": sorted(errors - unparsable)}


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


def base_raises(committed: dict, base: dict) -> list[str]:
    return [f"{f}: the committed baseline allows {n}, the base allowed {base.get(f, 0)}: a raise of the baseline itself"
            for f, n in sorted(committed.items()) if n > base.get(f, 0)]


def analyze(found: dict, committed: dict, change: dict | None, event: str) -> tuple[list[str], list[str], set]:
    """One rule's judgement: (problems, notices, allow_raise). `found`/`committed` map file -> count; `change` is
    pr_change()'s result for this rule, or None without a base."""
    if change is None:
        problems, notices = judge(found, committed)
        return problems, notices + ["no base commit given: every file is judged against the committed baseline; the "
                                    "touched-file, raise and narrowing checks need --base"], set()
    touched = {f for g in change["groups"] for f in g["old"] + g["now"]}
    keep = lambda d: {f: n for f, n in d.items() if f not in touched}  # noqa: E731
    problems, notices = judge(keep(found), keep(committed))
    if change["base_counts"] is not None:
        problems += base_raises(keep(committed), change["base_counts"])
    else:
        notices.append(f"the base {change['sha'][:12]} has no baseline: this change introduces it")
    allow = set()
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
    return problems, notices, allow


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
    return {"sha": sha, "groups": groups, "base_cfg": base_cfg,
            "base_counts_all": base_cfg["counts"] if base_cfg else None, "base_found_all": counts_of(res["findings"]),
            "base_marks": res["marks"], "skipped": b"rename detection was skipped" in d.stderr.lower()}


def new_marks(head_marks: list[dict], change: dict | None) -> list[dict]:
    """Marks in the change's files that the base did not hold (by group, by reason text)."""
    if change is None:
        return []
    out = []
    for g in change["groups"]:
        was = Counter(m["reason"] for m in change["base_marks"] if m["file"] in g["old"])
        for m in sorted((m for m in head_marks if m["file"] in g["now"]), key=lambda m: (m["file"], m["line"])):
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
            covered.update((LANGUAGE_OF[posixpath.splitext(f)[1]], f"{r['rule']}.{r['position']}.{r['kind']}")
                           for r in recs if r["status"] == "finding")
        want = {f: {k: v for k, v in c.items() if v} for f, c in spec.get("files", {}).items()}
        if got != want:
            failures.append(f"{case.name}: findings {json.dumps(got, sort_keys=True)}, expected "
                            f"{json.dumps(want, sort_keys=True)}")
        for key in ("unparsable", "recovered"):
            have = sorted({f for f, _ in res[key]})
            if have != sorted(spec.get(key, [])):
                failures.append(f"{case.name}: {key} {have}, expected {sorted(spec.get(key, []))}")
        if verbose:
            print(f"self-test {case.name}: {'ok' if not any(x.startswith(case.name + ':') for x in failures) else 'FAILED'}")
    # Every rule of every language must be planted RED somewhere, so a gutted rule cannot pass unnoticed.
    for lang in ("typescript", "tsx", "javascript", "python"):
        for rid in re.findall(r"(?m)^id: (literal-bound\.\S+)$", compose_rules(lang)):
            if (lang, rid) not in covered:
                failures.append(f"rule {rid} ({lang}) has no planted RED finding in fixtures/")
    return failures


# --- the run -----------------------------------------------------------------------------------------------------

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


def run(root: Path, base: str | None, event: str, tmp: Path) -> dict:
    cfg = load_head_config(root)
    files = tracked_files(root)
    scope = Scope(cfg)
    scanned = [f for f in files if scope.scanned(f)]
    res = census(Tree(root, files), scanned, cfg["launchers"])
    found = counts_of(res["findings"])
    problems, notices = [], []
    problems += [f"{f}:{ln}: unparsable (an ERROR node that could hide a bound): the check cannot judge it"
                 for f, ln in res["unparsable"]]
    problems += tree_floors(cfg, scanned)
    change = pr_change(root, base, cfg, tmp) if base else None
    if change and change["base_cfg"] is not None:
        problems += narrowing(change["base_cfg"], cfg, files)
    allow = {}
    for rule in sorted({r for c in list(found.values()) + list(cfg["counts"].values()) for r in c} | {RULE}):
        sub = None
        if change:
            sub = {"sha": change["sha"], "groups": change["groups"],
                   "base_counts": per_rule(change["base_counts_all"], rule) if change["base_counts_all"] is not None
                   else None, "base_found": per_rule(change["base_found_all"], rule)}
        p, n, a = analyze(per_rule(found, rule), per_rule(cfg["counts"], rule), sub, event)
        problems += [f"[{rule}] {x}" for x in p]
        notices += [f"[{rule}] {x}" for x in n]
        allow[rule] = sorted(a)
    if change and change["skipped"]:
        notices.append("git skipped inexact rename detection on this diff, so a rename or split may read as new files")
    marks = res["marks"]
    added = new_marks(marks, change)
    return {"schema": SCHEMA, "check": CHECK_ID, "base": base, "event": event, "scanned_files": len(scanned),
            "counts": found, "findings": res["findings"], "marks": marks, "new_marks": added,
            "recovered": res["recovered"], "unscanned": unscanned(cfg, files), "problems": problems,
            "notices": notices, "_allow": allow, "_cfg": cfg}


def summary_md(out: dict) -> str:
    total = Counter(r["status"] for recs in out["findings"].values() for r in recs)
    lines = ["### test-bounds (K2)", "",
             f"{out['scanned_files']} file(s) scanned; {total['finding']} finding(s), {total['cleared']} cleared by "
             f"value, {total['marked']} marked. Base: {out['base'] or 'none'}; event: {out['event'] or 'none'}.", ""]
    if out["problems"]:
        lines += [f"**{len(out['problems'])} problem(s)**", ""] + [f"- {p}" for p in out["problems"][:60]] + [""]
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
    (root / BASELINE_PATH).write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="test-bounds (K2): short wall-clock bounds in test code")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "write-baseline"):
        p = sub.add_parser(name)
        p.add_argument("--root")
        p.add_argument("--base", default=os.environ.get("TEST_BOUNDS_BASE", ""))
        p.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", ""))
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
        base = args.base.strip() or None
        if base and re.fullmatch(r"0+", base):
            base = None
        with tempfile.TemporaryDirectory() as tmp:
            out = run(root, base, args.event.strip(), Path(tmp))
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
