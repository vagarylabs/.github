"""Tests for test-bounds (K2). The baseline vectors are the vagaris ratchet's (scripts/check-test-bounds-are-hang-
guards.test.mjs, root R4'd on #849), run in throwaway git repositories through the real `run()`. ast-grep is
required: $TEST_BOUNDS_SG or `ast-grep` on PATH (ci.yml fetches the pinned binary); a missing binary fails, never skips."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check as C  # noqa: E402

GIT_ENV = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}, "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "k2 fixture",
           "GIT_AUTHOR_EMAIL": "k2@fixture.invalid", "GIT_COMMITTER_NAME": "k2 fixture",
           "GIT_COMMITTER_EMAIL": "k2@fixture.invalid"}
BL = C.BASELINE_PATH
TREES = [{"glob": "s/**/*.test.ts", "min_files": 1}]


class Repo:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.git("-c", "init.defaultBranch=main", "init", "-q", "--template=", ".")

    def git(self, *args) -> str:
        return subprocess.run(["git", *args], cwd=self.dir, env=GIT_ENV, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, files: dict) -> str:
        for name, body in files.items():
            path = self.dir / name
            if body is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def verdict(self, base: str | None, event: str = "pull_request") -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            return C.run(self.dir, base, event, Path(tmp))

    def done(self):
        self._tmp.cleanup()


def baseline(counts: dict, trees=None, launchers=None, exclude=None) -> str:
    cfg = {"schema": 1, "check": C.CHECK_ID, "trees": trees or TREES, "counts":
           {f: {C.RULE: n} for f, n in counts.items() if n}}
    if launchers is not None:
        cfg["launchers"] = launchers
    if exclude is not None:
        cfg["exclude"] = exclude
    return json.dumps(cfg, indent=2) + "\n"


def file(tag: str, frm: int, to: int, bound=lambda i: f"{15_000 + i}") -> str:
    """`to - from` cases, each bounded by a short literal unless `bound(i)` says otherwise (the ratchet's shape)."""
    return 'import { expect, it } from "vitest";\n\n' + "\n".join(
        f'it("{tag} settles case {i} after its fixture writes the row", async () => {{\n'
        f'  const row = await fixture{i}.write({{ id: {i}, label: "{tag}-{i}" }});\n'
        f'  expect(await read{i}(row.id)).toEqual(row);\n}}, {bound(i)});\n' for i in range(frm, to))


def unrelated(n: int) -> str:
    return 'import { describe, expect, test } from "vitest";\n\ndescribe("the parser", () => {\n' + "".join(
        f'  test("parses token stream {i} without a trailing separator", () => {{\n'
        f'    const tokens = tokenize(sample{i});\n    expect(tokens.at(-1)?.kind).not.toBe("separator");\n'
        f'  }}, {4_000 + i});\n' for i in range(n)) + "});\n"


def has(lines, needle):
    return any(needle in line for line in lines)


class Evaluation(unittest.TestCase):
    def test_exact_values(self):
        for text, want in [("5_000", 5000), ("-(2 * 1000)", -2000), ("5 * 60_000", 300000), ("1e3", 1000),
                           ("(120_000)", 120000), ("0.5", Fraction(1, 2)), ("-(-300_000) + 0", 300000)]:
            self.assertEqual(C.evaluate_js(text), want, text)

    def test_refused_shapes(self):
        for text in ["0210000", "08", "0x10", "10n", "600_000 / 2", "2 ** 19", "Number(1)", "+5", "5000 as const",
                     "`5`", "1_000_", "a * 2", "", "5 5"]:
            self.assertIsNone(C.evaluate_js(text), text)

    def test_python_values(self):
        self.assertEqual(C.evaluate_py("3 * 100"), 300)
        self.assertEqual(C.evaluate_py("1_200"), 1200)
        for text in ["True", "0o17", "0x10", "300 / 2", "1j", "N * 2", "int(300)"]:
            self.assertIsNone(C.evaluate_py(text), text)

    def test_plain_named_imports_only(self):
        self.assertEqual(C._parse_import('import { A, B as C } from "./x";'), {"A": "A", "C": "B"})
        for text in ['import type { A } from "./x";', 'import D, { A } from "./x";', 'import * as N from "./x";',
                     'import { type A } from "./x";', 'import { A /* c */ } from "./x";']:
            self.assertIsNone(C._parse_import(text), text)


class SelfTest(unittest.TestCase):
    def test_the_planted_fixtures_pass(self):
        self.assertEqual(C.self_test(), [])

    def test_a_gutted_rule_fails_the_self_test(self):
        """Every rule must be planted RED: the coverage check names a rule with no red finding."""
        original = C.compose_rules
        try:
            C.compose_rules = lambda lang, extra=(): original(lang, extra).replace(
                "id: literal-bound.wait.condition", "id: literal-bound.wait.condition\nseverity: off")
            failures = C.self_test()
        finally:
            C.compose_rules = original
        self.assertTrue(has(failures, "literal-bound.wait.condition"), failures)


class DiffEntries(unittest.TestCase):
    def test_renames_and_copies_join_groups(self):
        z = "\0".join(["R100", "a/x.test.ts", "a/y.test.ts", "M", "b/z.test.ts", "C035", "b/z.test.ts",
                       "b/w.test.ts", "A", "c/n.test.ts", "D", "c/gone.test.ts", "R090", "d/old.test.ts",
                       "d/helper.ts", ""])
        changes = C.parse_name_status(z)
        self.assertEqual(changes[0], ("R100", "a/x.test.ts", "a/y.test.ts"))
        keep = lambda p: p.endswith(".test.ts")  # noqa: E731
        self.assertEqual(C.change_groups(changes, keep), [
            {"old": ["a/x.test.ts"], "now": ["a/y.test.ts"]},
            {"old": ["b/z.test.ts"], "now": ["b/w.test.ts", "b/z.test.ts"]},
            {"old": ["c/gone.test.ts"], "now": []},
            {"old": [], "now": ["c/n.test.ts"]},
            {"old": ["d/old.test.ts"], "now": []},
        ])
        with self.assertRaisesRegex(C.Refusal, "truncated"):
            C.parse_name_status("R100\0a.test.ts\0")

    def test_baseline_write(self):
        self.assertEqual(C.baseline_write({"a": 2}, {"a": 3}, False, set()), ({"a": 2}, ""))
        self.assertIsNone(C.baseline_write({"a": 4}, {"a": 3}, False, set())[0])
        self.assertEqual(C.baseline_write({"a": 4}, {"a": 3}, False, {"a"}), ({"a": 4}, ""))
        self.assertEqual(C.baseline_write({"a": 4}, {}, True, set()), ({"a": 4}, ""))
        self.assertIsNone(C.baseline_write({"a": 4}, {"a": 1}, True, set())[0])


class Baseline(unittest.TestCase):
    """The ratchet's vectors (N1, N2, N4, F17) through the real run()."""

    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.done()

    def test_no_base_judges_the_committed_counts(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 3), BL: baseline({a: 2})})
        v = self.repo.verdict(None)
        self.assertTrue(has(v["problems"], f"{a}: 3 finding(s), the baseline allows 2: a new one"), v["problems"])
        self.assertTrue(has(v["notices"], "no base commit given"))

    def test_an_unreadable_base_fails_closed(self):
        self.repo.commit({"s/__tests__/a.test.ts": file("a", 0, 1), BL: baseline({"s/__tests__/a.test.ts": 1})})
        for bad in ["not-a-sha", "0123456789abcdef0123456789abcdef01234567"]:
            with self.assertRaises(C.Refusal):
                self.repo.verdict(bad)

    def test_a_base_equal_to_head_touches_nothing(self):
        a = "s/__tests__/a.test.ts"
        head = self.repo.commit({a: file("a", 0, 2), BL: baseline({a: 2})})
        v = self.repo.verdict(head)
        self.assertEqual((v["problems"], [n for n in v["notices"] if "gain" in n]), ([], []))

    def test_a_git_mv_carries_its_allowance(self):
        a, b = "s/__tests__/a.test.ts", "s/__tests__/b.test.ts"
        base = self.repo.commit({a: file("a", 0, 3), BL: baseline({a: 3})})
        self.repo.commit({a: None, b: file("a", 0, 3)})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"{b}: 3 finding(s), the baseline lists 0: the rename or split is "
                                           "attributed"), v["problems"])
        self.assertTrue(has(v["problems"], f"{a}: 0 finding(s), the baseline lists 3: this change touches the file"))
        self.assertEqual(C.baseline_write(C.per_rule(v["counts"], C.RULE), {a: 3}, False,
                                          set(v["_allow"][C.RULE]))[0], {b: 3})
        self.assertIsNone(C.baseline_write(C.per_rule(v["counts"], C.RULE), {a: 3}, False, set())[0])
        self.repo.commit({BL: baseline({b: 3})})
        v = self.repo.verdict(base)
        self.assertEqual(v["problems"], [])

    def test_a_rename_cannot_carry_new_findings(self):
        a, b, z = "s/__tests__/a.test.ts", "s/__tests__/b.test.ts", "s/__tests__/z.test.ts"
        base = self.repo.commit({a: file("a", 0, 3), z: file("z", 0, 2), BL: baseline({a: 3, z: 2})})
        self.repo.commit({a: None, b: file("a", 0, 5), z: file("z", 0, 2, lambda i: "120_000"), BL: baseline({b: 5})})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"the rename/split of {a} into {b}: 5 finding(s), the base had 3: a new one"),
                        v["problems"])
        self.assertNotIn(b, v["_allow"][C.RULE])

    def test_a_split_moves_findings_and_a_new_one_is_named(self):
        a, b, c = "s/__tests__/a.test.ts", "s/__tests__/b.test.ts", "s/__tests__/c.test.ts"
        base = self.repo.commit({a: file("a", 0, 6), BL: baseline({a: 6})})
        self.repo.commit({a: file("a", 0, 2), b: file("a", 2, 4), c: file("a", 4, 6), BL: baseline({a: 2, b: 2, c: 2})})
        self.assertEqual(self.repo.verdict(base)["problems"], [])
        self.repo.commit({c: file("a", 4, 7), BL: baseline({a: 2, b: 2, c: 3})})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"the rename/split of {a} into {a}, {b}, {c}: 7 finding(s), the base had 6"),
                        v["problems"])

    def test_a_new_file_is_new(self):
        d, z = "s/__tests__/d.test.ts", "s/__tests__/z.test.ts"
        base = self.repo.commit({z: file("z", 0, 2), BL: baseline({z: 2})})
        self.repo.commit({z: file("z", 0, 2, lambda i: "120_000"), d: unrelated(2), BL: baseline({d: 2})})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"{d} (new): 2 finding(s), the base had 0: a new one"), v["problems"])

    def test_a_touched_file_is_judged_against_what_the_base_held(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), BL: baseline({x: 5})})
        self.repo.commit({x: file("x", 0, 5)})
        v = self.repo.verdict(base, "merge_group")
        self.assertEqual(C.judge({x: 5}, {x: 5})[0], [], "the hole: against the allowance nothing is wrong")
        self.assertTrue(has(v["problems"], f"{x}: 5 finding(s), the base had 3: a new one"), v["problems"])

    def test_a_gain_fails_a_pull_request_until_locked(self):
        x, y = "s/__tests__/x.test.ts", "s/__tests__/y.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), y: file("y", 0, 2), BL: baseline({x: 3, y: 4})})
        self.repo.commit({x: file("x", 0, 3, lambda i: "120_000" if i == 2 else f"{15_000 + i}")})
        pr = self.repo.verdict(base)
        self.assertEqual(pr["problems"], [f"[{C.RULE}] {x}: 2 finding(s), the baseline lists 3: this change touches the "
                                          "file, so lock the gain in (write-baseline in this pull request)"])
        self.assertTrue(has(pr["notices"], f"{y}: 2 finding(s), the baseline allows 4: a gain"))
        for event in ("merge_group", "push"):
            v = self.repo.verdict(base, event)
            self.assertEqual(v["problems"], [], event)
            self.assertTrue(has(v["notices"], f"{x}: 2 finding(s), the baseline lists 3: a gain"), event)
        self.repo.commit({BL: baseline({x: 2, y: 4})})
        self.assertEqual(self.repo.verdict(base)["problems"], [])

    def test_the_committed_counts_may_not_raise_a_file(self):
        x, y = "s/__tests__/x.test.ts", "s/__tests__/y.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), y: file("y", 0, 1), BL: baseline({x: 3, y: 1})})
        self.repo.commit({x: file("x", 0, 3) + "\n// touched\n", BL: baseline({x: 7, y: 4})})
        v = self.repo.verdict(base, "merge_group")
        self.assertEqual(v["problems"], [
            f"[{C.RULE}] {y}: the committed baseline allows 4, the base allowed 1: a raise of the baseline itself",
            f"[{C.RULE}] {x}: the committed baseline allows 7, the file has 3 and the base allowed 3: a raise of the "
            "baseline itself"])

    def test_a_base_without_a_baseline_still_judges_touched_files(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 2)})
        self.repo.commit({x: file("x", 0, 3), BL: baseline({x: 3})})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["notices"], f"the base {base[:12]} has no baseline"))
        self.assertTrue(has(v["problems"], f"{x}: 3 finding(s), the base had 2: a new one"), v["problems"])


class Configuration(unittest.TestCase):
    """Condition 4: the configuration is judged from the base. A change can widen what is scanned, never narrow it."""

    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.done()

    def test_narrowing_the_trees_is_red(self):
        a, t = "s/__tests__/a.test.ts", "t/__tests__/b.test.ts"
        trees = [{"glob": "s/**/*.test.ts", "min_files": 1}, {"glob": "t/**/*.test.ts", "min_files": 1}]
        base = self.repo.commit({a: file("a", 0, 1), t: file("t", 0, 1), BL: baseline({a: 1, t: 1}, trees=trees)})
        self.repo.commit({BL: baseline({a: 1}, trees=trees[:1])})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], "no longer scans 1 file(s) the base's covers: " + t), v["problems"])
        self.assertTrue(has(v["problems"], "tree `t/**/*.test.ts` is removed"), v["problems"])

    def test_an_exclude_is_a_narrowing(self):
        a = "s/__tests__/a.test.ts"
        base = self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
        self.repo.commit({BL: baseline({}, exclude=["s/__tests__/a.test.ts"], trees=[
            {"glob": "s/**/*.test.ts", "min_files": 1}])})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], "no longer scans 1 file(s)"), v["problems"])

    def test_lowering_min_files_or_adding_a_launcher_is_red(self):
        a = "s/__tests__/a.test.ts"
        trees = [{"glob": "s/**/*.test.ts", "min_files": 1}]
        base = self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1}, trees=[{"glob": "s/**/*.test.ts",
                                                                                     "min_files": 2}])})
        la = [{"name": "launch", "module": "s/launch.ts", "hook_floor_ms": 1000}]
        self.repo.commit({BL: baseline({a: 1}, trees=trees, launchers=la)})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], "min_files lowered from 2 to 1"), v["problems"])
        self.assertTrue(has(v["problems"], "launcher launch (s/launch.ts) is added"), v["problems"])

    def test_a_tree_below_its_floor_is_red(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1}, trees=[{"glob": "s/**/*.test.ts", "min_files": 5}])})
        v = self.repo.verdict(None)
        self.assertTrue(has(v["problems"], "scans 1 file(s), below its min_files 5"), v["problems"])

    def test_widening_seeds_a_new_tree_from_what_the_base_held(self):
        a, t = "s/__tests__/a.test.ts", "t/__tests__/b.test.ts"
        base = self.repo.commit({a: file("a", 0, 1), t: file("t", 0, 2), BL: baseline({a: 1})})
        wide = [{"glob": "s/**/*.test.ts", "min_files": 1}, {"glob": "t/**/*.test.ts", "min_files": 1}]
        self.repo.commit({BL: baseline({a: 1, t: 2}, trees=wide)})
        self.assertEqual(self.repo.verdict(base)["problems"], [], "the newly covered file brings what the base held")
        self.repo.commit({BL: baseline({a: 1, t: 3}, trees=wide)})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"{t}: the committed baseline allows 3, the file has 2"), v["problems"])

    def test_a_malformed_configuration_refuses(self):
        self.repo.commit({BL: json.dumps({"schema": 1, "trees": [{"glob": "s/**", "min_files": 0}]})})
        with self.assertRaises(C.Refusal):
            self.repo.verdict(None)


class Marks(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.done()

    def test_every_mark_is_listed_and_a_new_one_is_named(self):
        a = "s/__tests__/a.test.ts"
        old = 'it("x", async () => {}, 5_000); // timeout under test: the 5 s budget is the latency contract\n'
        base = self.repo.commit({a: old, BL: baseline({})})
        new = old + 'it("y", async () => {}, 6_000); // timeout under test: a second latency contract\n'
        self.repo.commit({a: new})
        v = self.repo.verdict(base)
        self.assertEqual([m["line"] for m in v["marks"]], [1, 2])
        self.assertEqual([(m["file"], m["line"]) for m in v["new_marks"]], [(a, 2)])
        self.assertEqual(v["problems"], [], "a mark clears its finding; it is listed, not failed")

    def test_an_unparsable_file_is_red(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: 'it("x", async () => { const = ; });\n', BL: baseline({})})
        v = self.repo.verdict(None)
        self.assertTrue(has(v["problems"], f"{a}:1: unparsable"), v["problems"])


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        repo = Repo()
        try:
            a = "s/__tests__/a.test.ts"
            repo.commit({a: file("a", 0, 2), BL: baseline({a: 2})})
            run = lambda *args: subprocess.run([sys.executable, "-B", str(HERE / "check.py"), *args,  # noqa: E731
                                                "--root", str(repo.dir)], capture_output=True, text=True,
                                               env={**os.environ, "GITHUB_STEP_SUMMARY": "", "GITHUB_OUTPUT": ""})
            ok = run("check")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("2 finding(s) counted", ok.stdout)
            bad = run("check", "--base", "not-a-sha")
            self.assertEqual(bad.returncode, 2, bad.stdout)
            repo.commit({a: file("a", 0, 3)})
            red = run("check")
            self.assertEqual(red.returncode, 1, red.stdout)
            self.assertIn("REFUSE: [literal-bound] s/__tests__/a.test.ts: 3 finding(s)", red.stdout)
            refused = run("write-baseline")
            self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
            self.assertIn("refusing to RAISE", refused.stdout)
            repo.commit({a: file("a", 0, 1)})
            lowered = run("write-baseline")
            self.assertEqual(lowered.returncode, 0, lowered.stdout + lowered.stderr)
            self.assertEqual(json.loads((repo.dir / BL).read_text())["counts"], {a: {C.RULE: 1}})
            self.assertEqual(json.loads((repo.dir / BL).read_text())["trees"], TREES, "the configuration is kept")
            seeded = run("write-baseline", "--seed")
            self.assertEqual(seeded.returncode, 1, "a seed is refused once counts exist")
        finally:
            repo.done()


if __name__ == "__main__":
    unittest.main()
