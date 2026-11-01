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

    def verdict(self, base: str | None, event: str = "pull_request", running=None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            return C.run(self.dir, base, event, Path(tmp), running)

    def done(self):
        self._tmp.cleanup()


def baseline(counts: dict, trees=None, launchers=None, exclude=None, digest=True) -> str:
    """digest: True records this check's digest (what write-baseline writes); a string records that one; False none."""
    cfg = {"schema": 1, "check": C.CHECK_ID, "trees": trees or TREES, "counts":
           {f: {C.RULE: n} for f, n in counts.items() if n}}
    if digest:
        cfg["check_digest"] = C.check_digest() if digest is True else digest
    if launchers is not None:
        cfg["launchers"] = launchers
    if exclude is not None:
        cfg["exclude"] = exclude
    return json.dumps(cfg, indent=2) + "\n"


PIN_A, PIN_B = "a" * 40, "b" * 40
WF = ".github/workflows/pr.yml"


def workflow(pin: str, extra: str = "") -> str:
    """A consumer workflow pinning this check in job `t` (D8 guard 1 reads that job's step `uses:`)."""
    return f"jobs:\n  t:\n    steps:\n      - uses: vagarylabs/.github/actions/test-bounds@{pin}\n{extra}"


def running(pin: str):
    """The Actions run that executes the check: job `t` of WF, with the action at `pin`."""
    return (WF, "t", pin)


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
        # An inline `type X` specifier binds a type only, so the value specifiers beside it still count.
        self.assertEqual(C._parse_import('import { start, type Db } from "./x";'), {"start": "start"})
        self.assertEqual(C._parse_import('import { type } from "./x";'), {"type": "type"})
        for text in ['import type { A } from "./x";', 'import D, { A } from "./x";', 'import * as N from "./x";',
                     'import { A /* c */ } from "./x";']:
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

    LAUNCHER = [{"name": "startPg", "module": "s/__tests__/pg.ts", "hook_floor_ms": 210_000}]
    PG_TEST = ('import { beforeAll } from "vitest";\nimport { startPg } from "./pg";\n\n'
               'beforeAll(async () => { await startPg(); }, 210_000);\n')

    def lock_in_refused(self, base, head_files, why, run=None):
        self.repo.commit(head_files)
        v = self.repo.verdict(base, running=run or running(PIN_B))
        self.assertTrue(has(v["problems"], why), v["problems"])
        self.assertEqual(v["locked_in"], [])

    def test_a_removed_launcher_is_new_debt_not_old(self):
        """B1' (#68 delta): the base tree is censused under the BASE's launchers, so removing one cannot turn an
        untouched 210 s hook into lockable debt."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: self.PG_TEST, "s/__tests__/pg.ts": "export async function startPg() {}\n",
                                 WF: workflow(PIN_A), BL: baseline({}, launchers=self.LAUNCHER)})
        self.lock_in_refused(base, {WF: workflow(PIN_B), BL: baseline({x: 1}, launchers=[])},
                             "the base tree holds 0 finding(s) in it under this check, the head 1")

    def test_a_raised_launcher_floor_is_new_debt_not_old(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: self.PG_TEST, "s/__tests__/pg.ts": "export async function startPg() {}\n",
                                 WF: workflow(PIN_A), BL: baseline({}, launchers=self.LAUNCHER)})
        raised = [{**self.LAUNCHER[0], "hook_floor_ms": 300_000}]
        self.lock_in_refused(base, {WF: workflow(PIN_B), BL: baseline({x: 1}, launchers=raised)},
                             "the base tree holds 0 finding(s) in it under this check, the head 1")

    def test_a_pin_in_a_comment_moves_nothing(self):
        """B2' (#68 delta): only the running job's step `uses:` is the pin; a comment, an `echo`, or another job is not."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        self.lock_in_refused(base, {WF: workflow(PIN_A, f"      # vagarylabs/.github/actions/test-bounds@{PIN_B}\n"),
                                    BL: baseline({x: 3})}, "this change does not move the check's pin", running(PIN_A))

    def test_a_pin_in_an_echo_moves_nothing(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        echo = f'      - run: echo "uses: vagarylabs/.github/actions/test-bounds@{PIN_B}"\n'
        self.lock_in_refused(base, {WF: workflow(PIN_A, echo), BL: baseline({x: 3})},
                             "this change does not move the check's pin", running(PIN_A))

    def test_a_pin_in_another_workflow_moves_nothing(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        other = f"jobs:\n  off:\n    if: false\n    steps:\n      - uses: vagarylabs/.github/actions/test-bounds@{PIN_B}\n"
        self.lock_in_refused(base, {".github/workflows/other.yml": other, BL: baseline({x: 3})},
                             "this change does not move the check's pin", running(PIN_A))

    def test_the_running_action_must_be_the_head_pin(self):
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        self.lock_in_refused(base, {WF: workflow(PIN_B), BL: baseline({x: 3})},
                             "this change does not move the check's pin", running(PIN_A))

    def test_a_swapped_short_bound_is_not_the_same_debt(self):
        """LOW (#68 delta): the lock-in compares WHICH bounds are short, so a helper change that makes one bound short
        and another long keeps the count but is refused."""
        x, h = "s/__tests__/x.test.ts", "s/__tests__/helpers.ts"
        body = ('import { it } from "vitest";\nimport { P, Q } from "./helpers";\n\n'
                'it("p settles", async () => { await p(); }, P);\nit("q settles", async () => { await q(); }, Q);\n')
        base = self.repo.commit({x: body, h: "export const P = 5_000;\nexport const Q = 120_000;\n",
                                 WF: workflow(PIN_A), BL: baseline({x: 0})})
        self.lock_in_refused(base, {h: "export const P = 120_000;\nexport const Q = 5_000;\n", WF: workflow(PIN_B),
                                    BL: baseline({x: 1})}, "")
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertEqual(v["locked_in"], [])

    def test_the_running_context_is_read_from_the_runner(self):
        A = PIN_A
        here = Path(f"/home/r/_work/_actions/vagarylabs/.github/{A}/actions/test-bounds")
        env = {"GITHUB_WORKFLOW_REF": "vagarylabs/vagaris/.github/workflows/pr.yml@refs/pull/1/merge", "GITHUB_JOB": "t"}
        self.assertEqual(C.running_context(env, here), (".github/workflows/pr.yml", "t", A))
        self.assertIsNone(C.running_context(env, Path("/src/actions/test-bounds")), "a checkout is not a pinned action")
        self.assertIsNone(C.running_context({}, here), "no workflow or job, no context: the guard fails safe")

    def test_the_pin_reader_reads_only_a_steps_own_uses(self):
        """B2' (#68 delta): a comment, a `run:` body and a block scalar's lines (even one that reads `- uses:`) are not
        a step's `uses:`; with no job named, every job's step pins are read."""
        other, at = "c" * 40, "vagarylabs/.github/actions/test-bounds@"
        text = (f"jobs:\n  t:\n    steps:\n"
                f"      # - uses: {at}{PIN_B}\n"
                f'      - run: echo "uses: {at}{PIN_B}"\n'
                f"      - name: block\n        run: |\n          - uses: {at}{PIN_B}\n"
                f"      - uses: {at}{PIN_A}\n        with:\n          note: >\n            - uses: {at}{PIN_B}\n"
                f"  u:\n    steps:\n      - uses: {at}{other}\n")
        self.assertEqual(C.job_action_pins(text, "t"), [PIN_A])
        self.assertEqual(C.job_action_pins(text, "u"), [other])
        self.assertEqual(C.job_action_pins(text, None), [PIN_A, other])

    def test_outside_actions_a_commented_pin_moves_nothing(self):
        """write-baseline reads every job's pins, through the same reader: a comment cannot make it lock debt in."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        self.repo.commit({WF: workflow(PIN_A, f"      # - uses: vagarylabs/.github/actions/test-bounds@{PIN_B}\n")})
        self.assertEqual(self.repo.verdict(base)["_allow"][C.RULE], [])

    def test_only_the_running_jobs_pin_is_compared(self):
        """In Actions the guard reads the RUNNING job: another job of the same workflow still at the old pin does not
        stop the running job's bump from locking its debt in."""
        x, at = "s/__tests__/x.test.ts", "vagarylabs/.github/actions/test-bounds@"
        second = lambda pin: f"  u:\n    steps:\n      - uses: {at}{pin}\n"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A, second(PIN_A)), BL: baseline({x: 1})})
        self.repo.commit({WF: workflow(PIN_B, second(PIN_A)), BL: baseline({x: 3})})
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertEqual(v["problems"], [])
        self.assertEqual(v["locked_in"], [{"rule": C.RULE, "file": x, "base": 1, "now": 3}])

    def test_the_committed_counts_may_not_raise_a_file(self):
        x, y = "s/__tests__/x.test.ts", "s/__tests__/y.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), y: file("y", 0, 1), BL: baseline({x: 3, y: 1})})
        self.repo.commit({x: file("x", 0, 3) + "\n// touched\n", BL: baseline({x: 7, y: 4})})
        v = self.repo.verdict(base, "merge_group")
        self.assertEqual(v["problems"], [
            f"[{C.RULE}] {y}: the committed baseline allows 4, the base allowed 1: a raise of the baseline itself (this "
            "change does not move the check's pin, so there is no new debt to lock in)",
            f"[{C.RULE}] {x}: the committed baseline allows 7, the file has 3 and the base allowed 3: a raise of the "
            "baseline itself"])

    def test_a_pin_bump_locks_in_an_untouched_files_debt(self):
        """K2 D8: a pin bump to a check that detects more finds debt in an untouched file. The raise to EXACTLY the
        count the base tree holds under the running check lands, and is listed."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})  # an older check counted 1
        self.repo.commit({WF: workflow(PIN_B)})
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertTrue(has(v["problems"], f"[{C.RULE}] {x}: 3 finding(s), the baseline allows 1: a new one"), v["problems"])
        self.assertEqual(v["_allow"][C.RULE], [x], "write-baseline --base may lock it in")
        self.assertEqual(self.repo.verdict(base)["_allow"][C.RULE], [x], "outside Actions, every job's pin is read")
        self.repo.commit({BL: baseline({x: 3})})
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertEqual(v["problems"], [])
        self.assertEqual(v["locked_in"], [{"rule": C.RULE, "file": x, "base": 1, "now": 3}])
        self.assertTrue(has(v["notices"], f"[{C.RULE}] {x}: debt locked in by a detection change: 1 -> 3"), v["notices"])
        self.assertIn("Debt locked in by a detection change: 1", C.summary_md(v))

    def test_no_raise_without_a_pin_change(self):
        """Guard 1 is the consumer's PIN, read at the base and the head, never a field the baseline declares."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1}, digest="0" * 64)})
        self.repo.commit({BL: baseline({x: 3})})
        v = self.repo.verdict(base, running=running(PIN_A))
        self.assertTrue(has(v["problems"], "this change does not move the check's pin"), v["problems"])
        self.assertEqual((v["locked_in"], v["_allow"][C.RULE]), ([], []))

    def test_a_lowered_import_is_new_debt_not_old(self):
        """B1 (#68 RC): lowering a constant an UNTOUCHED test imports adds findings to that byte-identical file. The base
        tree, censused under the running check, holds none of them, so they cannot be locked in."""
        x, h = "s/__tests__/x.test.ts", "s/__tests__/helpers.ts"
        body = ('import { it } from "vitest";\nimport { T } from "./helpers";\n\n'
                'it("x settles its fixture write", async () => {\n  await write();\n}, T);\n')
        base = self.repo.commit({x: body, h: "export const T = 120_000;\n", WF: workflow(PIN_A), BL: baseline({})})
        self.repo.commit({h: "export const T = 5_000;\n", WF: workflow(PIN_B)})
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertEqual(v["_allow"][C.RULE], [], "write-baseline may not lock in the import's new finding")
        self.repo.commit({BL: baseline({x: 1})})
        v = self.repo.verdict(base, running=running(PIN_B))
        self.assertTrue(has(v["problems"], f"[{C.RULE}] {x}: the committed baseline allows 1, the base allowed 0: a raise of "
                                           "the baseline itself (the base tree holds 0 finding(s) in it under this check, "
                                           "the head 1"), v["problems"])
        self.assertEqual(v["locked_in"], [])

    def test_the_baseline_names_the_check_that_wrote_it(self):
        """B2 (#68 RC): a missing check_digest is refused, and one that is not the running check's is red."""
        a = "s/__tests__/a.test.ts"
        for digest, why in ((False, "does not record the check version that wrote it"), ("0" * 64, "names check 000000000000")):
            with self.subTest(digest=digest):
                self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1}, digest=digest)})
                v = self.repo.verdict(None)
                self.assertTrue(has(v["problems"], f"[check_digest] the baseline {why}"), v["problems"])

    def test_a_lock_in_goes_to_exactly_the_found_count(self):
        """Guard 3: above the findings is slack, below them is a partial lock-in; both are refused."""
        x = "s/__tests__/x.test.ts"
        base = self.repo.commit({x: file("x", 0, 3), WF: workflow(PIN_A), BL: baseline({x: 1})})
        for n in (4, 2):
            with self.subTest(n=n):
                self.repo.commit({WF: workflow(PIN_B), BL: baseline({x: n})})
                v = self.repo.verdict(base, running=running(PIN_B))
                self.assertTrue(has(v["problems"], f"a detection change may lock in exactly the 3 finding(s) the file holds, "
                                                   f"not {n}"), v["problems"])
                self.assertEqual(v["locked_in"], [])

    def test_base_raises_refuses_a_file_not_byte_identical_at_the_base(self):
        """Guard 2 as base_raises' own contract (run() passes only byte-identical files)."""
        p, n, locked = C.base_raises({"x": 3}, {"x": 1}, {"x": 3}, True, set(), {"x": 3})
        self.assertEqual(locked, [])
        self.assertTrue(has(p, "the file is not byte-identical at the base"), p)
        p, n, locked = C.base_raises({"x": 3}, {"x": 1}, {"x": 3}, True, {"x"}, {"x": 3})
        self.assertEqual((p, locked), ([], [("x", 1, 3)]))

    def test_byte_identity_is_read_from_the_base_tree_and_the_scanned_file(self):
        """Guard 2, one source: the head side is the file the census read (the working tree), hashed with git."""
        x, y, z = "s/__tests__/x.test.ts", "s/__tests__/y.test.ts", "s/__tests__/z.test.ts"
        base = self.repo.commit({x: file("x", 0, 2), y: file("y", 0, 2), z: file("z", 0, 2), BL: baseline({})})
        self.repo.commit({y: file("y", 0, 2) + "\n// edited\n"})
        (self.repo.dir / z).write_text(file("z", 0, 2) + "\n// uncommitted\n", encoding="utf-8")
        self.assertEqual(C.byte_identical(self.repo.dir, base, [x, y, z, "s/__tests__/absent.test.ts"]), {x})

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


class EventBase(unittest.TestCase):
    """B3 (root's #60 R4): on pull_request and merge_group the base is the EVENT's, and the input must name it."""
    BASE, HEAD = "a" * 40, "b" * 40

    def resolve(self, given, event, payload):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "event.json"
            path.write_text(json.dumps(payload))
            return C.resolve_base(given, event, {"GITHUB_EVENT_PATH": str(path)}, self.HEAD)

    def test_pull_request_and_merge_group_take_the_events_base(self):
        pr = {"pull_request": {"base": {"sha": self.BASE}}}
        self.assertEqual(self.resolve(self.BASE, "pull_request", pr), self.BASE)
        mg = {"merge_group": {"base_sha": self.BASE}}
        self.assertEqual(self.resolve(self.BASE, "merge_group", mg), self.BASE)

    def test_a_different_or_self_base_is_refused_and_an_empty_one_takes_the_events(self):
        pr = {"pull_request": {"base": {"sha": self.BASE}}}
        self.assertEqual(self.resolve("", "pull_request", pr), self.BASE)
        for given in ("0" * 40, "c" * 40, self.HEAD):
            with self.subTest(given=given), self.assertRaises(C.Refusal):
                self.resolve(given, "pull_request", pr)
        with self.assertRaises(C.Refusal):
            self.resolve(self.HEAD, "pull_request", {"pull_request": {"base": {"sha": self.HEAD}}})
        with self.assertRaises(C.Refusal):
            self.resolve(self.BASE, "merge_group", {"pull_request": {"base": {"sha": self.BASE}}})

    def test_a_missing_event_payload_refuses(self):
        with self.assertRaises(C.Refusal):
            C.resolve_base(self.BASE, "pull_request", {}, self.HEAD)

    def ci(self, given, event, payload):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "event.json"
            path.write_text(json.dumps(payload))
            return C.resolve_base(given, event, {"GITHUB_EVENT_PATH": str(path)}, self.HEAD, in_actions=True)

    def test_every_event_carrying_a_pull_request_takes_its_base(self):
        # pull_request_review(_comment) run the PR's own workflow from its merge ref (#60 delta B3).
        pr = {"pull_request": {"base": {"sha": self.BASE}}}
        for event in ("pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"):
            with self.subTest(event=event):
                self.assertEqual(self.ci("", event, pr), self.BASE)
                with self.assertRaises(C.Refusal):
                    self.ci("c" * 40, event, pr)
        self.assertIn("pull_request_target", C.PR_PAYLOAD_EVENTS)

    MAIN = {"ref": "refs/heads/main", "repository": {"default_branch": "main"}}

    def test_push_in_ci_takes_before_and_ignores_the_input(self):
        self.assertEqual(self.ci("c" * 40, "push", {**self.MAIN, "before": self.BASE}), self.BASE)
        self.assertIsNone(self.ci(self.BASE, "push", {**self.MAIN, "before": "0" * 40}), "a branch's first push: no base")
        with self.assertRaises(C.Refusal):
            self.ci("", "push", {**self.MAIN})

    def test_a_push_outside_the_default_branch_is_refused_in_ci(self):
        """#60 delta2 LOW: a feature branch's first push (zeros before) would pass unjudged, so it is refused."""
        for payload in ({"ref": "refs/heads/feature", "repository": {"default_branch": "main"}, "before": "0" * 40},
                        {"ref": "refs/tags/v1", "repository": {"default_branch": "main"}, "before": self.BASE},
                        {"before": self.BASE}):
            with self.subTest(payload=payload), self.assertRaises(C.Refusal):
                self.ci("", "push", payload)

    def test_only_workflow_dispatch_takes_the_input_and_others_are_refused_in_ci(self):
        self.assertEqual(self.ci(self.BASE, "workflow_dispatch", {}), self.BASE)
        self.assertIsNone(self.ci("", "workflow_dispatch", {}))
        for event in ("issue_comment", "schedule", "workflow_run", ""):
            with self.subTest(event=event), self.assertRaises(C.Refusal):
                self.ci(self.BASE, event, {})

    def test_any_runner_trace_means_ci(self):
        self.assertFalse(C.in_actions_env({}))
        for env in ({"GITHUB_ACTIONS": "true"}, {"GITHUB_EVENT_PATH": "/x"}, {"RUNNER_TEMP": "/t"}):
            with self.subTest(env=env):
                self.assertTrue(C.in_actions_env(env))

    def test_push_and_local_runs_take_the_input(self):
        self.assertEqual(C.resolve_base(self.BASE, "push", {}, self.HEAD), self.BASE)
        self.assertIsNone(C.resolve_base("", "push", {}, self.HEAD))
        self.assertIsNone(C.resolve_base("0" * 40, "", {}, self.HEAD))
        with self.assertRaises(C.Refusal):
            C.resolve_base(self.HEAD, "push", {}, self.HEAD)


class Isolation(unittest.TestCase):
    """B1 and B2 (root's #60 R4): no file the scan cannot vouch for reads as clean."""

    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.done()

    def test_a_consumer_sgconfig_cannot_hide_the_scanned_files(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 2), BL: baseline({a: 2}),
                          "sgconfig.yml": 'languageGlobs:\n  css: ["*.test.ts"]\nruleDirs: []\n'})
        v = self.repo.verdict(None)
        self.assertEqual(v["counts"], {a: {C.RULE: 2}}, "the findings are still found")
        self.assertEqual(v["problems"], [])

    def test_a_non_utf8_test_file_is_red(self):
        a, b = "s/__tests__/a.test.ts", "s/__tests__/b.test.ts"
        self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
        (self.repo.dir / b).write_bytes(b'it("caf\xe9", async () => {}, 5_000);\n')
        self.repo.git("add", b)
        self.repo.git("commit", "-q", "-m", "latin-1")
        v = self.repo.verdict(None)
        self.assertTrue(has(v["problems"], f"{b}: unparsable (not UTF-8"), v["problems"])

    def test_a_file_the_scan_skips_is_red_whatever_the_cause(self):
        # The sentinel is the positive control behind B1 and B2: any file ast-grep does not parse (a skip this test
        # simulates by dropping that file's matches) is unparsable, never a clean file with no findings.
        a, b = "s/__tests__/a.test.ts", "s/__tests__/b.test.ts"
        self.repo.commit({a: file("a", 0, 1), b: file("b", 0, 1), BL: baseline({a: 1, b: 1})})
        real = C.sg_scan
        C.sg_scan = lambda root, rules, files: [m for m in real(root, rules, files) if m["file"] != b]
        try:
            v = self.repo.verdict(None)
        finally:
            C.sg_scan = real
        self.assertTrue(has(v["problems"], f"{b}: unparsable (ast-grep parsed it 0 time(s)"), v["problems"])

    def test_the_private_config_alone_isolates_even_from_inside_the_repo(self):
        # -c alone (root's #60 delta survivor): the temp directory sits INSIDE the repo, under its sgconfig.yml.
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 2), BL: baseline({a: 2}),
                          "sgconfig.yml": 'languageGlobs:\n  css: ["*.test.ts"]\nruleDirs: []\n'})
        inner = self.repo.dir / "scratch-tmp"
        inner.mkdir()
        old = tempfile.tempdir
        tempfile.tempdir = str(inner)
        try:
            v = self.repo.verdict(None)
        finally:
            tempfile.tempdir = old
        self.assertEqual(v["counts"], {a: {C.RULE: 2}})

    def test_the_private_config_alone_isolates_with_the_cwd_at_the_repo_root(self):
        # -c on its own (root's #60 delta survivor): ast-grep run FROM the repository root, under its sgconfig.yml.
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1}),
                          "sgconfig.yml": 'languageGlobs:\n  css: ["*.test.ts"]\nruleDirs: []\n'})
        found = C.sg_scan(self.repo.dir, C.compose_rules("typescript"), [a], _cwd=self.repo.dir)
        self.assertEqual(sum(1 for m in found if m["ruleId"] == "sentinel"), 1, "the file is parsed under -c alone")

    def test_a_symlinked_test_file_is_an_explicit_red(self):
        a, link = "s/__tests__/a.test.ts", "s/__tests__/link.test.ts"
        self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
        (self.repo.dir / link).symlink_to("a.test.ts")
        self.repo.git("add", link)
        self.repo.git("commit", "-q", "-m", "a link")
        v = self.repo.verdict(None)
        self.assertTrue(has(v["problems"], f"{link}: a symlink in the trees is not scanned"), v["problems"])

    def test_a_missing_base_is_fetched_alone_in_ci(self):
        a = "s/__tests__/a.test.ts"
        base = self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
        self.repo.commit({a: file("a", 0, 1) + "\n"})
        with tempfile.TemporaryDirectory() as tmp:
            shallow = Path(tmp) / "shallow"
            subprocess.run(["git", "clone", "-q", "--depth=1", f"file://{self.repo.dir}", str(shallow)], env=GIT_ENV,
                           check=True, capture_output=True)
            have = lambda: subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=shallow,  # noqa: E731
                                          capture_output=True).returncode == 0
            self.assertFalse(have(), "positive control: the depth-1 clone lacks the base")
            C.ensure_commit(shallow, base, in_actions=True)
            self.assertTrue(have(), "the base commit is fetched alone")

    def test_a_failing_ast_grep_refuses(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
        old = os.environ.get("TEST_BOUNDS_SG")
        os.environ["TEST_BOUNDS_SG"] = "/usr/bin/false"
        try:
            with self.assertRaisesRegex(C.Refusal, "ast-grep scan exited"):
                self.repo.verdict(None)
        finally:
            if old is None:
                os.environ.pop("TEST_BOUNDS_SG", None)
            else:
                os.environ["TEST_BOUNDS_SG"] = old


class TreesAndMarks(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.done()

    def test_a_test_file_renamed_out_of_the_trees_is_red(self):
        a, h = "s/__tests__/a.test.ts", "s/__tests__/a.cases.ts"
        base = self.repo.commit({a: file("a", 0, 2), BL: baseline({a: 2})})
        self.repo.commit({a: None, h: file("a", 0, 2), BL: baseline({})})
        v = self.repo.verdict(base)
        self.assertTrue(has(v["problems"], f"{a} is renamed to {h}, outside the scanned trees"), v["problems"])

    def test_a_tree_file_in_an_unread_language_is_unscanned(self):
        a = "s/__tests__/a.test.ts"
        self.repo.commit({a: file("a", 0, 1), "s/__tests__/fixture.json": "{}\n",
                          BL: baseline({a: 1}, trees=[{"glob": "s/__tests__/**", "min_files": 1}])})
        v = self.repo.verdict(None)
        self.assertEqual(v["unscanned"]["language"], ["s/__tests__/fixture.json"])

    def test_a_base_mark_moved_onto_a_bound_is_new(self):
        # S16: the base held the mark on no bound; moved onto a short bound, it newly exempts one.
        a = "s/__tests__/a.test.ts"
        base = self.repo.commit({a: "// timeout under test: the 5 s latency contract\nit(\"x\", async () => {});\n",
                                 BL: baseline({})})
        self.repo.commit({a: 'it("x", async () => {}, 5_000); // timeout under test: the 5 s latency contract\n'})
        v = self.repo.verdict(base)
        self.assertEqual([(m["file"], m["line"]) for m in v["new_marks"]], [(a, 1)])
        self.assertEqual(v["problems"], [], "a mark clears its finding; it is listed as NEW, not failed")


class Cli(unittest.TestCase):
    def cli_env(self):
        return {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "RUNNER_"))}

    def test_the_unscanned_config_list(self):
        """#60 delta2 test gap: pytest's config files are UNSCANNED (in a tree, an unread language; outside every tree,
        test-like), never silently clean."""
        repo = Repo()
        try:
            trees = [{"glob": "s/**", "min_files": 1}]
            repo.commit({"s/a.test.ts": file("a", 0, 1), "s/pyproject.toml": "[tool.pytest.ini_options]\n",
                         "s/setup.cfg": "[tool:pytest]\n", "tox.ini": "[pytest]\n", "pytest.ini": "[pytest]\n",
                         BL: baseline({"s/a.test.ts": 1}, trees=trees)})
            v = repo.verdict(None)
            self.assertEqual(sorted(v["unscanned"]["language"]), ["s/pyproject.toml", "s/setup.cfg"])
            self.assertEqual(sorted(v["unscanned"]["outside_trees"]), ["pytest.ini", "tox.ini"])
            self.assertIn("UNSCANNED: 2 tree file(s)", C.summary_md(v))
        finally:
            repo.done()

    def test_a_first_push_to_the_default_branch_says_it_has_no_base(self):
        """#60 delta2 test gap: the zeros-`before` notice, under a real Actions environment."""
        repo = Repo()
        try:
            a = "s/__tests__/a.test.ts"
            repo.commit({a: file("a", 0, 1), BL: baseline({a: 1})})
            event = repo.dir / "event.json"
            for ref, rc in (("refs/heads/main", 0), ("refs/heads/feature", 2)):
                with self.subTest(ref=ref):
                    event.write_text(json.dumps({"before": "0" * 40, "ref": ref, "repository": {"default_branch": "main"}}))
                    env = {**self.cli_env(), "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event)}
                    r = subprocess.run([sys.executable, "-B", str(HERE / "check.py"), "check", "--root", str(repo.dir)],
                                       capture_output=True, text=True, env=env)
                    self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                    if rc == 0:
                        self.assertIn("notice: a push with no `before` commit (a branch's first push)", r.stdout)
                    else:
                        self.assertIn("is not a push to the default branch main", r.stdout + r.stderr)
        finally:
            repo.done()

    def test_write_baseline_records_this_checks_version(self):
        repo = Repo()
        try:
            a = "s/__tests__/a.test.ts"
            repo.commit({a: file("a", 0, 2), BL: baseline({a: 2})})
            repo.commit({a: file("a", 0, 1)})
            r = subprocess.run([sys.executable, "-B", str(HERE / "check.py"), "write-baseline", "--root", str(repo.dir)],
                               capture_output=True, text=True, env=self.cli_env())
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads((repo.dir / BL).read_text())["check_digest"], C.check_digest())
        finally:
            repo.done()

    def test_exit_codes(self):
        repo = Repo()
        try:
            a = "s/__tests__/a.test.ts"
            repo.commit({a: file("a", 0, 2), BL: baseline({a: 2})})
            clean = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "RUNNER_"))}
            run = lambda *args: subprocess.run([sys.executable, "-B", str(HERE / "check.py"), *args,  # noqa: E731
                                                "--root", str(repo.dir)], capture_output=True, text=True, env=clean)
            ok = run("check")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("2 finding(s) counted", ok.stdout)
            self.assertIn("covered (py): subprocess timeouts only", ok.stdout, "coverage is printed, never implied")
            self.assertIn("UNSCANNED:", ok.stdout)
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
            # In Actions the event is the runner's: a flag cannot turn a pull_request into a push, and the base must
            # be the event's (B3).
            event = repo.dir / "event.json"
            base = repo.git("rev-parse", "HEAD~1")
            event.write_text(json.dumps({"pull_request": {"base": {"sha": base}}}))
            ci = {**clean, "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event)}
            as_ci = lambda *args: subprocess.run([sys.executable, "-B", str(HERE / "check.py"), *args,  # noqa: E731
                                                  "--root", str(repo.dir)], capture_output=True, text=True, env=ci)
            for args, why in ((("check", "--event", "push", "--base", base), "is not this run's event"),
                              (("check", "--base", repo.git("rev-parse", "HEAD")), "is not the pull_request event's base")):
                r = as_ci(*args)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn(why, r.stdout)
            self.assertEqual(as_ci("check", "--base", base).returncode, 0, "the event's own base is accepted")
            self.assertEqual(as_ci("check").returncode, 0, "an empty input takes the event's base")
            # An event outside the allowlist is refused in CI, whatever the input.
            r = subprocess.run([sys.executable, "-B", str(HERE / "check.py"), "check", "--root", str(repo.dir)],
                               capture_output=True, text=True, env={**ci, "GITHUB_EVENT_NAME": "issue_comment"})
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertIn("is not one this check judges in CI", r.stdout)
        finally:
            repo.done()


if __name__ == "__main__":
    unittest.main()
