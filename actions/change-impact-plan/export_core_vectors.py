#!/usr/bin/env python3
"""Export the change-impact planner's pure core as parity vectors (P2-13).

Vagaris carries a TypeScript port of the planner's pure functions (server/src/services/source-facts/planner-core.ts)
so it can compute repository facts from blobs it reads over a source grant, without a checkout. This file is the
parity lock: every vector is {fn, input, output}, where output is what plan.py itself returns for that input. The TS
port vendors core-vectors.json by sha256 and must reproduce every output, including the canonical_digest and
graph_digest bytes.

What is covered: the pure functions of plan.py (BUILTIN_FULL_GLOBS, LOCKFILE_NAMES, glob_to_regex, first_match,
parse_pnpm_workspace_patterns, pnpm_graph, apply_extra_deps, declared_packages, reverse_closure, owner_package,
canonical_digest, graph_digest, is_inert, classify_paths) and 1.7.5's package.json nesting bound (json_nesting_depth,
PLAN_CONFIG_MAX_DEPTH). Every input is a small synthetic value written here; nothing is read from a checkout.

Encoding
  - A workspace graph is an ORDERED list of {"name", "dir", "deps"} (deps sorted): the order is the dict's insertion
    order, which owner_package's tie rule and the error paths depend on.
  - A Python set becomes a sorted list. Every other list keeps the order plan.py produced.
  - output is {"returns": value} or {"raises": "ValueError", "message": str(error)} for an error the planner raises
    itself, or {"raises": "JSONDecodeError"} for a manifest json.loads refuses (the decoder's wording is CPython's
    own, so it is not part of the contract). Any other exception fails the export: it is not a contract outcome.
  - No floats anywhere (a JSON reader in another language cannot tell 1 from 1.0), and no integer outside
    +-(2**53 - 1).
  - The file carries no planner version, timestamp or source hash: a version bump that leaves these functions alone
    leaves the file byte-identical, and a semantic change fails the regeneration test (test_plan.CoreVectorsTest).

Usage
  python3 export_core_vectors.py           write core-vectors.json beside this file
  python3 export_core_vectors.py --check   exit 1 unless the committed file is byte-equal to a fresh export and
                                           every committed vector recomputes
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import plan as P

VECTORS_PATH = Path(__file__).with_name("core-vectors.json")
SCHEMA = 1
FUNCTIONS = ("constants", "glob_to_regex", "first_match", "json_nesting_depth", "parse_pnpm_workspace_patterns",
             "pnpm_graph", "apply_extra_deps", "declared_packages", "reverse_closure", "owner_package",
             "canonical_digest", "graph_digest", "is_inert", "classify_paths")
MIN_VECTORS = 200


def graph_in(packages: list[dict]) -> dict[str, dict]:
    return {p["name"]: {"dir": p["dir"], "deps": set(p["deps"])} for p in packages}


def graph_out(pkgs: dict[str, dict]) -> list[dict]:
    return [{"name": name, "dir": info["dir"], "deps": sorted(info["deps"])} for name, info in pkgs.items()]


def _classify(i: dict) -> dict:
    r = P.classify_paths(list(i["paths"]), i["config"], graph_in(i["packages"]))
    return {"evidence": r["evidence"], "affected": sorted(r["affected"]), "hubs": r["hubs"], "error": r["error"]}


RUNNERS = {
    "constants": lambda i: {"BUILTIN_FULL_GLOBS": list(P.BUILTIN_FULL_GLOBS), "LOCKFILE_NAMES": sorted(P.LOCKFILE_NAMES),
                            "PLAN_CONFIG_MAX_DEPTH": P.PLAN_CONFIG_MAX_DEPTH},
    "glob_to_regex": lambda i: [bool(P.glob_to_regex(i["pattern"]).match(path)) for path in i["paths"]],
    "first_match": lambda i: P.first_match(i["path"], list(i["globs"])),
    "json_nesting_depth": lambda i: P.json_nesting_depth(i["text"]),
    "parse_pnpm_workspace_patterns": lambda i: P.parse_pnpm_workspace_patterns(i["text"]),
    # Each reader binds its own text (t=text): a bare closure would read the last manifest for every directory.
    "pnpm_graph": lambda i: graph_out(P.pnpm_graph(list(i["patterns"]), [(d, (lambda t=text: t)) for d, text in i["manifests"]],
                                                   i["extra_deps"])),
    "apply_extra_deps": lambda i: graph_out(P.apply_extra_deps(graph_in(i["packages"]), i["extra_deps"])),
    "declared_packages": lambda i: graph_out(P.declared_packages(i["workspace"])),
    "reverse_closure": lambda i: sorted(P.reverse_closure(graph_in(i["packages"]), set(i["seeds"]))),
    "owner_package": lambda i: P.owner_package(i["path"], graph_in(i["packages"])),
    "canonical_digest": lambda i: P.canonical_digest(i["value"]),
    "graph_digest": lambda i: P.graph_digest(graph_in(i["packages"])),
    "is_inert": lambda i: P.is_inert(i["path"], i["config"]),
    "classify_paths": _classify,
}


def recompute(fn: str, value: dict) -> dict:
    """The output plan.py gives today for one vector's input."""
    try:
        return {"returns": RUNNERS[fn](value)}
    except json.JSONDecodeError:
        return {"raises": "JSONDecodeError"}
    except ValueError as error:
        return {"raises": "ValueError", "message": str(error)}


# ---------- synthetic inputs ----------

def pkg(name: str, d: str, deps=()) -> dict:
    return {"name": name, "dir": d, "deps": sorted(deps)}


# The SHAPE of vagaris (as test_plan.PACKAGES): cli -> server -> db/shared/adapter-claude; ui -> shared/adapter-claude.
WORKSPACE = [
    pkg("@v/shared", "packages/shared"),
    pkg("@v/db", "packages/db", ["@v/shared"]),
    pkg("@v/adapter-utils", "packages/adapter-utils"),
    pkg("@v/adapter-claude", "packages/adapters/claude-local", ["@v/adapter-utils"]),
    pkg("@v/server", "server", ["@v/db", "@v/shared", "@v/adapter-claude"]),
    pkg("@v/ui", "ui", ["@v/shared", "@v/adapter-claude"]),
    pkg("@v/cli", "cli", ["@v/server", "@v/db"]),
    pkg("@v/plugin", "server/plugins/x", ["@v/server"]),
]
CONFIG = {
    "inert_globs": ["docs/**", "**/*.md"],
    "full_globs": ["infra/**"],
    "hub_packages": ["@v/server", "@v/db", "@v/shared"],
    "extra_edges": {"scripts/ui-*.mjs": ["@v/ui"], "contracts/**": ["@v/server", "@v/cli"]},
}


def manifest(name=None, nest: int = 0, **sections) -> str:
    """A package.json text; `nest` adds that many array levels under "x" (the object itself is level 1)."""
    body = {} if name is None else {"name": name}
    body.update(sections)
    text = json.dumps(body, sort_keys=True)
    if nest:
        text = text[:-1] + ("," if body else "") + '"x":' + "[" * nest + "]" * nest + "}"
    return text


MANIFESTS = [
    [".", manifest("root", dependencies={"@v/shared": "*"})],
    ["packages/shared", manifest("@v/shared")],
    ["packages/db", manifest("@v/db", dependencies={"@v/shared": "workspace:*", "left-pad": "1"})],
    ["server", manifest("@v/server", dependencies={"@v/db": "*"}, devDependencies={"@v/shared": "*", "vitest": "3"},
                        peerDependencies={"@v/ui": "*"}, optionalDependencies={"fsevents": "2"})],
    ["ui", manifest("@v/ui", dependencies={"@v/shared": "*"}, bundledDependencies=["@v/db"])],
    ["packages/shared/node_modules/foo", "not json"],
    ["tools/x", "not json"],
]
PATTERNS = ["packages/*", "server", "ui"]


def glob_vectors() -> list[tuple[str, dict]]:
    cases = [
        ("docs/**", ["docs", "docs/", "docs/a.md", "docs/a/b.md", "docsx/a", "a/docs/x"]),
        ("**/package.json", ["package.json", "a/package.json", "a/b/package.json", "xpackage.json", "a/xpackage.json"]),
        ("*.md", ["a.md", "x/a.md", ".md", "a.mdx"]),
        ("src/?.ts", ["src/a.ts", "src/ab.ts", "src/.ts", "src//.ts", "src/é.ts", "src/\U0001F600.ts"]),
        ("a**b", ["ab", "a/x/b", "axb", "a/b/"]),
        ("**", ["", "a", "a/b", "/"]),
        ("**/", ["", "a/", "a", "a/b/"]),
        ("a+b(c)[d]{e}|f^$.ts", ["a+b(c)[d]{e}|f^$.ts", "aab(c)[d]{e}|f^$.ts", "a+b(c)[d]{e}|f^$xts"]),
        ("dir\\file-1", ["dir\\file-1", "dir/file-1", "dirxfile-1"]),
        ("!x", ["!x", "x"]),
        ("**/migrations/**", ["migrations/a.sql", "db/migrations/1.sql", "migrations", "db/migrationsx/1"]),
        ("**/Dockerfile*", ["Dockerfile", "a/Dockerfile.dev", "a/b/Dockerfilex", "a/dockerfile"]),
        ("**/requirements*.txt", ["requirements.txt", "a/requirements-dev.txt", "a/requirements/x.txt"]),
        # Python's `$` also matches before ONE trailing newline, and `.` refuses only "\n" (not "\r" or U+2028).
        ("a", ["a", "a\n", "a\n\n", "\na", "a\r"]),
        ("**", ["a\nb", "a\n", "a\rb", "a b"]),
        ("x/**", ["x/a\rb", "x/a\nb", "x/\n"]),
        ("*", ["a\nb", "a/b", ""]),
        ("", ["", "\n", "a"]),
        ("a.b", ["a.b", "axb"]),
        (".github/**", [".github/workflows/ci.yml", "x/.github/a", ".githubx/a"]),
    ]
    return [("glob_to_regex", {"pattern": p, "paths": paths}) for p, paths in cases]


def first_match_vectors() -> list[tuple[str, dict]]:
    full = list(P.BUILTIN_FULL_GLOBS)
    cases = [
        ("docs/a.md", ["src/**", "docs/**", "**/*.md"]),
        ("lib/a.ts", ["src/**", "docs/**"]),
        ("lib/a.ts", []),
        ("", ["", "**"]),
        ("a/b.md", ["**/*.md", "a/**"]),
    ] + [(path, full) for path in [
        ".github/workflows/ci.yml", "packages/x/package.json", "pnpm-lock.yaml", "packages/x/pnpm-lock.yaml",
        "server/requirements-dev.txt", "a/b/prisma/schema.prisma", "server/Dockerfile.prod", "db/migrations/0001.sql",
        "pyproject.toml", "svc/pyproject.toml", ".nvmrc", "src/index.ts", "turbo.json", "a/alembic/env.py",
    ]]
    return [("first_match", {"path": path, "globs": globs}) for path, globs in cases]


def nesting_vectors() -> list[tuple[str, dict]]:
    texts = ["{}", "[[{}]]", '{"a":"[[[["}', '{"a":"\\"[["}', '{"a":"\\\\","b":[[]]}', "", "]]]", "]][[", "[" * 65,
             '"unterminated [', manifest("@v/deep", nest=63), manifest("@v/deep", nest=64)]
    return [("json_nesting_depth", {"text": t}) for t in texts]


def workspace_yaml_vectors() -> list[tuple[str, dict]]:
    texts = [
        "packages:\n  - 'packages/*'\n  - \"server\"\n  - ui # comment\n",
        "packages:\n  - packages/*\n  - '!packages/legacy'\n",
        "packages:\n  - a\ncatalog:\n  - b\n",
        "onlyBuiltDependencies:\n  - esbuild\npackages:\n  - a\n",
        "onlyBuiltDependencies:\n  - esbuild\n",
        "",
        "packages: [a, b]\n",
        "packages:\n  - 'a#b'\n",
        "packages:\n- a\n- b\n",
        "packages:\n\t- a\n",
        "packages:\r\n  - a\r\n  - b\r\n",
        "packages:\x85  - a   - b\x0c  - c\x1c  - d\x0b  - e",
        "packages:\n  - '\"a\"'\n  - \"b'\n",
        "﻿packages:\n  - a\n",
        "packages:\n  - a　\n  - b \n",
        "packages: \n  - a\n",
        "packages:\x1f\n  - a\n",
        "packages:\n  -\n  - a\n",
        "packages:\n  - ''\n",
        "  packages:\n  - a\n",
        "packages:   # c\n  - a\n",
        "packagesx:\n  - a\n",
        "packages:\n  - a\nother: 1\npackages:\n  - b\n",
        "# header\npackages:\n\n  # inner\n  - a  \n",
    ]
    return [("parse_pnpm_workspace_patterns", {"text": t}) for t in texts]


def pnpm_graph_vectors() -> list[tuple[str, dict]]:
    def v(patterns, manifests, extra=None):
        return ("pnpm_graph", {"patterns": patterns, "manifests": manifests, "extra_deps": extra})
    return [
        v(PATTERNS, MANIFESTS),
        v(PATTERNS, MANIFESTS, {"@v/ui": ["@v/db"], "@v/shared": []}),
        v(PATTERNS, MANIFESTS, {"@v/ghost": ["@v/db"]}),
        v(PATTERNS, MANIFESTS, {"@v/ui": ["left-pad"]}),
        v(PATTERNS, MANIFESTS, []),
        # Negations: an excluded directory is never read (its text is not JSON). A `!` pattern also excludes everything
        # under its stem with the trailing "/" and "*" characters stripped as a SET (rstrip("/*")).
        v(["packages/**", "!packages/legacy", "!packages/gen/*", "!packages/x*/"],
          [["packages/a", manifest("@v/a")], ["packages/legacy", "not json"], ["packages/gen/deep/x", "not json"],
           ["packages/gen/y", "not json"], ["packages/x", manifest("@v/x")], ["packages/xy", manifest("@v/xy")],
           ["packages/x/z", "not json"], ["packages/legacyx", manifest("@v/legacyx", dependencies={"@v/a": "*"})]]),
        v(["**"], [[".", "not json"], ["a", manifest("@v/a")], ["a/node_modules/b", "not json"],
                   ["node_modules/c", "not json"]]),
        v([], [["a", "not json"]]),
        v(["!a"], [["a", "not json"]]),
        v(["packages/*"], [["packages/a", manifest()]]),
        v(["packages/*"], [["packages/a", manifest("")]]),
        v(["packages/*"], [["packages/a", manifest("@v/a")], ["packages/b", manifest("@v/a")]]),
        v(["packages/*"], [["packages/a", "{\"name\": \"@v/a\","]]),
        v(["packages/*"], [["packages/a", manifest("@v/a", dependencies=None, devDependencies=[], peerDependencies={},
                                                   optionalDependencies={"@v/b": "*"})],
                           ["packages/b", manifest("@v/b", dependencies={"@v/a": "*"})]]),
        # 1.7.5's bound: the manifest object is level 1, so nest=63 is depth 64 (passes) and nest=64 is 65 (refused).
        v(["packages/*"], [["packages/deep", manifest("@v/deep", nest=63)]]),
        v(["packages/*"], [["packages/deep", manifest("@v/deep", nest=64)]]),
        # The bound is read before the parse: 65 unclosed brackets are refused for depth, not as malformed JSON.
        v(["packages/*"], [["packages/deep", "[" * 65]]),
        v(["packages/*"], [["packages/deep", "[" * 64]]),
        v(["packages/*"], [["packages/a", manifest("@v/a")], ["packages/deep", "[" * 70]]),
        v(["packages/*", "server"], [["server", manifest("@v/server", dependencies={"@v/a": "*"})],
                                     ["packages/a", manifest("@v/a", dependencies={"@v/server": "*"})]]),
    ]


def extra_deps_vectors() -> list[tuple[str, dict]]:
    base = [pkg("@v/a", "a"), pkg("@v/b", "b", ["@v/a"]), pkg("@v/c", "c")]
    extras = [None, [], {}, 0, "", ["@v/a"], "x", {"@v/ghost": []}, {"@v/a": "@v/b"}, {"@v/a": ["@v/zz"]},
              {"@v/a": [1]}, {"@v/a": None}, {"@v/c": ["@v/a", "@v/b", "@v/a"]}, {"@v/a": ["@v/a"]},
              {"@v/c": ["@v/a"], "@v/b": ["@v/c"]}, {"@v/c": []}]
    return [("apply_extra_deps", {"packages": base, "extra_deps": e}) for e in extras]


def declared_vectors() -> list[tuple[str, dict]]:
    workspaces = [
        {"packages": {"core": {"dir": "services/core/", "deps": ["lib"]}, "lib": {"dir": "lib"}}, "extra_deps": {"lib": []}},
        {"packages": {"core": {"dir": "services/core"}, "lib": {"dir": "lib"}}, "extra_deps": {"core": ["lib"]}},
        {"packages": {"core": {"dir": "core", "deps": ["ghost"]}}, "extra_deps": {"phantom": [], "ghost": []}},
        {"packages": {"core": {"dir": "core", "deps": ["zed", "ghost"]}}},
        {"packages": {"core": {"dir": "x///"}, "root": {"dir": "/"}}},
        {},
        {"packages": None, "extra_deps": None},
        {"packages": {"core": {"dir": "core", "deps": "lib"}}},
        {"packages": {"core": {"dir": "core", "deps": None}}},
        {"packages": {"b": {"dir": "same"}, "a": {"dir": "same", "deps": ["b"]}}},
        {"packages": {"core": {"dir": "core", "deps": []}}, "extra_deps": {"core": ["core"]}},
    ]
    return [("declared_packages", {"workspace": w}) for w in workspaces]


def closure_vectors() -> list[tuple[str, dict]]:
    chain = [pkg("a", "a"), pkg("b", "b", ["a"]), pkg("c", "c", ["b"])]
    cycle = [pkg("a", "a", ["b"]), pkg("b", "b", ["a"]), pkg("c", "c", ["a"]), pkg("d", "d")]
    diamond = [pkg("top", "t"), pkg("l", "l", ["top"]), pkg("r", "r", ["top"]), pkg("bottom", "x", ["l", "r"])]
    cases = [(chain, ["a"]), (chain, ["b"]), (chain, ["c"]), (cycle, ["a"]), (cycle, ["c"]), (cycle, ["d"]),
             ([pkg("s", "s", ["s"]), pkg("t", "t", ["s"])], ["s"]), (chain, []), (chain, ["ghost"]),
             (diamond, ["top"]), (diamond, ["l", "r"]), (WORKSPACE, ["@v/shared"]), (WORKSPACE, ["@v/adapter-utils"]),
             (WORKSPACE, ["@v/server"]), ([], ["x"])]
    return [("reverse_closure", {"packages": p, "seeds": sorted(s)}) for p, s in cases]


def owner_vectors() -> list[tuple[str, dict]]:
    tie = [pkg("first", "same"), pkg("second", "same")]
    rootish = [pkg("empty", ""), pkg("lib", "lib")]
    cases = [(WORKSPACE, p) for p in ["server/plugins/x/a.ts", "server/a.ts", "serverx/a.ts", "server",
                                      "server/plugins/xy/a.ts", "packages/adapters/claude-local/src/a.ts",
                                      "packages/adapters/a.ts", "docs/a.md", ""]]
    cases += [(tie, "same/a"), (list(reversed(tie)), "same/a"), (rootish, "lib/a"), (rootish, "a.ts"),
              (rootish, "/abs"), (rootish, ""), ([], "a")]
    return [("owner_package", {"path": path, "packages": p}) for p, path in cases]


def digest_vectors() -> list[tuple[str, dict]]:
    values = [
        {}, [], None, True, False, 0, -1, 9007199254740991, -9007199254740991, "", "a",
        {"b": [1, {"d": None, "c": True}], "a": "x"},
        {"é": "ü", " ": "\x7f", "ctl": "\x00\x01\x08\x09\x0a\x0c\x0d\x1f\"\\/"},
        ["\U0001F600", "﻿", "Ā", "~ "],
        {"￿": 1, "\U0001F600": 2, "": 3, "a": 4, "\U00010000": 5},
        {"ab": 1, "a": 2, "B": 3, "": 4, "a\x00": 5},
        ["\ud800", "x\udfffy"],
        {"schema": 1, "packages": [{"name": "@v/a", "dir": "a", "deps": []}]},
        [[[]], {"x": {}}, [None, False]],
    ]
    return [("canonical_digest", {"value": value}) for value in values]


def graph_digest_vectors() -> list[tuple[str, dict]]:
    graphs = [[], WORKSPACE, list(reversed(WORKSPACE)), [pkg("@v/a", "a", ["@v/c", "@v/b"])],
              [{"name": "@v/a", "dir": "a", "deps": ["@v/c", "@v/b"]}], [pkg("é", "é/\U0001F600")],
              [pkg("b", "same"), pkg("a", "same", ["b"])]]
    return [("graph_digest", {"packages": g}) for g in graphs]


def inert_vectors() -> list[tuple[str, dict]]:
    cases = [
        ("docs/a.md", {"inert_globs": ["docs/**"]}),
        ("docs/pnpm-lock.yaml", {"inert_globs": ["docs/**"]}),
        ("pnpm-lock.yaml", {"inert_globs": ["*.yaml"]}),
        ("a/Cargo.lock", {"inert_globs": ["**"]}),
        ("a/b/go.sum", {"inert_globs": ["**"]}),
        ("a/Cargo.lockx", {"inert_globs": ["**"]}),
        ("a/bun.lockb", {"inert_globs": ["**"]}),
        ("a/b.md", {}),
        ("a/b.md", {"inert_globs": None}),
        ("a/b.md", {"inert_globs": []}),
        ("a/b.md", {"inert_globs": ["**/*.md", "a/**"]}),
        ("x", {"inert_globs": "docs/**"}),
        ("README.md", CONFIG),
        ("docs/sub/uv.lock", CONFIG),
    ]
    return [("is_inert", {"path": path, "config": cfg}) for path, cfg in cases]


def classify_vectors() -> list[tuple[str, dict]]:
    ghost = dict(CONFIG, extra_edges={"contracts/**": ["@v/server", "@v/ghost", "@v/abc"]})
    two = dict(CONFIG, extra_edges={"ui/**": ["@v/cli"]})
    bare = {"hub_packages": None}
    cases = [
        (["cli/src/a.ts", "docs/cli/x.md"], CONFIG),
        (["ui/src/app.tsx"], CONFIG),
        (["packages/shared/src/x.ts"], CONFIG),
        (["packages/db/src/x.ts"], CONFIG),
        (["packages/adapter-utils/src/x.ts"], CONFIG),
        ([".github/workflows/ci.yml", "cli/a.ts", "pnpm-lock.yaml"], CONFIG),
        (["infra/main.tf", "cli/a.ts"], CONFIG),
        (["random/file.txt", "cli/a.ts", "a/other.txt"], CONFIG),
        (["scripts/ui-build.mjs"], CONFIG),
        (["contracts/x.yaml"], CONFIG),
        (["docs/a.md", "cli/a.ts", "contracts/x.yaml", "ui/a.ts"], ghost),
        (["ui/pnpm-lock.yaml"], CONFIG),
        (["tools/yarn.lock"], CONFIG),
        (["ui/Cargo.lock"], two),
        (["docs/sub/uv.lock"], CONFIG),
        ([], CONFIG),
        (["docs/a.md", "x/README.md"], CONFIG),
        (["server/src/a.ts"], bare),
        (["tools/yarn.lock", "zzz/u.txt", "cli/a.ts"], CONFIG),
        (["contracts/x.yaml", ".github/x"], ghost),
        (["server/Dockerfile.prod"], CONFIG),
        (["server/plugins/x/a.ts"], CONFIG),
        (["server/plugins/x/a.ts"], {}),
        (["cli/a.ts", "ui/b.ts"], {"full_globs": None, "inert_globs": None, "extra_edges": None, "hub_packages": []}),
        (["packages/x/package.json"], {}),
    ]
    out = [("classify_paths", {"paths": paths, "config": cfg, "packages": WORKSPACE}) for paths, cfg in cases]
    out.append(("classify_paths", {"paths": ["a/b.ts"], "config": {}, "packages": []}))
    return out


def build() -> dict:
    inputs = [("constants", {})] + glob_vectors() + first_match_vectors() + nesting_vectors() + workspace_yaml_vectors() \
        + pnpm_graph_vectors() + extra_deps_vectors() + declared_vectors() + closure_vectors() + owner_vectors() \
        + digest_vectors() + graph_digest_vectors() + inert_vectors() + classify_vectors()
    # A round trip through the file's own encoding (sorted keys) first: each output is computed from exactly the input
    # a reader parses. So an object's key order in an input is always sorted; an order that matters is a list.
    inputs = json.loads(json.dumps(inputs, sort_keys=True))
    return {"schema": SCHEMA, "source": "vagarylabs/.github actions/change-impact-plan/plan.py",
            "functions": list(FUNCTIONS),
            "vectors": [{"fn": fn, "input": value, "output": recompute(fn, value)} for fn, value in inputs]}


def render(doc: dict) -> bytes:
    return (json.dumps(doc, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def check(doc: dict) -> list[str]:
    """Every problem with a vectors document: a floor miss, an unknown fn, or an output plan.py no longer gives."""
    problems = []
    vectors = doc.get("vectors") if isinstance(doc, dict) else None
    if not isinstance(vectors, list):
        return ["no vectors list"]
    if len(vectors) < MIN_VECTORS:
        problems.append(f"{len(vectors)} vectors, below the floor of {MIN_VECTORS}")
    seen = {v.get("fn") for v in vectors if isinstance(v, dict)}
    problems += [f"no vector for {fn}" for fn in FUNCTIONS if fn not in seen]
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict) or set(vector) != {"fn", "input", "output"}:
            problems.append(f"vector {index}: not exactly fn, input, output")
        elif vector["fn"] not in RUNNERS:
            problems.append(f"vector {index}: unknown fn {vector['fn']!r}")
        elif recompute(vector["fn"], vector["input"]) != vector["output"]:
            problems.append(f"vector {index} ({vector['fn']}): output differs from plan.py")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", type=Path, default=VECTORS_PATH)
    args = parser.parse_args(argv)
    fresh = render(build())
    if args.check:
        committed = args.out.read_bytes()
        problems = check(json.loads(committed)) + ([] if committed == fresh else [f"{args.out} is not a fresh export"])
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    args.out.write_bytes(fresh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
