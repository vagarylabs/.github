"""Tests for the FL-4 test-weakening predicates in trusted/classify.py (report-only).

One red case per weakening pattern, each a PR head off the same base, plus controls: the same text in a
.md file, value changes in the tightening direction, moves, renames and comments. Plain unittest, stdlib
only, light (one throwaway git repo). Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402

MANIFEST = ROOT / "trusted" / "manifest.json"

BASE = {
    "src/a.test.ts": (
        "import { it, expect } from 'vitest'\n"
        "it('a', () => {\n"
        "  expect.hasAssertions()\n"
        "  expect.assertions(3)\n"
        "  expect(took).toBeLessThan(200)\n"
        "})\n"),
    "src/b.test.ts": "it('b', () => {})\n",
    "src/moved.test.ts": "describe('m', () => {\n  it.skip('legacy', () => {})\n  it('kept', () => {})\n})\n",
    "src/c.ts": "export const c = 1\n",
    "src/c.test.ts": "import { c } from './c'\nit('c', () => { expect(c).toBe(1) })\n",
    "vitest.config.ts": (
        "export default {\n"
        "  test: {\n"
        "    testTimeout: 5000,\n"
        "    coverage: { thresholds: { lines: 80 } },\n"
        "  },\n"
        "}\n"),
    "playwright.config.ts": "export default {\n  retries: 0,\n  timeout: 30000,\n}\n",
    ".github/workflows/ci.yml": (
        "name: ci\n"
        "on: pull_request\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: x\n"
        "    steps:\n"
        "      - run: npm test\n"
        "      - run: pip install pytest || true\n"),
    "tests/test_x.py": "def test_x():\n    assert True\n",
    "pkg/test_util.py": "def test_util():\n    assert True\n",
    "pyproject.toml": "[tool.coverage.report]\nfail_under = 90\n",
    "README.md": "# r\n",
    # vagary-core's convention: node --test runs services/<svc>/test/*.mjs, no .test. infix.
    "services/identity/test/notification-email-acceptance.mjs": (
        "import test from 'node:test'\n"
        "import assert from 'node:assert/strict'\n"
        "test('sends the acceptance email', async () => {\n"
        "  assert.equal(await send(), 'sent')\n"
        "})\n"),
    "critical/a.test.ts": (
        "import { charge } from '../src/billing'\n"
        "it('refuses a negative charge', () => {\n"
        "  expect(() => charge(-1)).toThrow()\n"
        "})\n"),
}

# ~3 MB of short test lines: larger than every byte cap the budget tests patch in, small enough for CI.
HUGE = "it('x', () => {})\n" * 170000

# The weakening text, as it would appear in a doc that explains the guard.
DOC = "\n".join([
    "it.skip('b', () => {})", "describe.todo('later')", "  retry: 2,", "  retries: process.env.CI ? 2 : 0,",
    "    continue-on-error: true", "      - run: npm test || true", "@pytest.mark.skip(reason='x')",
    "    testTimeout: 60000,", "coverage: { thresholds: { lines: 60 } }", "fail_under = 70",
    "  expect.assertions(1)", "  expect(took).toBeLessThan(500)", "pytest --reruns 3 || true",
    "      - run: python3 scripts/test-routing.py || true", "pnpm vitest run || true", "/**/ it.skip('b', () => {})",
    "  *) npm test || true ;;", "it('slow', { timeout: 60000 }, async () => {})", ""])


def git(cwd, *args):
    return subprocess.run(("git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false") + args,
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def edit(path_text, old, new):
    assert old in path_text, old
    return path_text.replace(old, new, 1)


class Repo:
    """Base commit on main; every case is a branch off it with one head commit."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = self.tmp.name
        git(d, "init", "-q", "-b", "main")
        git(d, "config", "user.email", "t@example.invalid")
        git(d, "config", "user.name", "t")
        self.write(BASE)
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "base")
        self.base = git(d, "rev-parse", "HEAD")
        self.n = 0

    def write(self, files):
        for p, t in files.items():
            f = pathlib.Path(self.d, p)
            if t is None:
                f.unlink()
                continue
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(t)

    def case(self, files=None, moves=(), message="head"):
        self.n += 1
        git(self.d, "checkout", "-q", "-b", "case-%d" % self.n, self.base)
        for old, new in moves:
            pathlib.Path(self.d, new).parent.mkdir(parents=True, exist_ok=True)
            git(self.d, "mv", old, new)
        self.write(files or {})
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", message)
        return git(self.d, "rev-parse", "HEAD")

    def scan(self, head):
        cwd = os.getcwd()
        try:
            os.chdir(self.d)
            return classify.weakening_scan(self.base, head)
        finally:
            os.chdir(cwd)

    def integrity(self, head, repo="vagarylabs/vagaris"):
        out = io.StringIO()
        cwd = os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        try:
            os.chdir(self.d)
            with contextlib.redirect_stdout(out):
                code = classify.main(["integrity", "--manifest", str(MANIFEST), "--repo", repo,
                                      "--base", self.base, "--head", head])
        finally:
            os.chdir(cwd)
        return code, out.getvalue()


class WeakeningCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repo()

    @classmethod
    def tearDownClass(cls):
        cls.repo.tmp.cleanup()

    def findings(self, files=None, moves=(), message="head"):
        head = self.repo.case(files, moves, message)
        findings, incomplete, _ = self.repo.scan(head)
        self.assertEqual(incomplete, [])
        return findings

    def assertFlagged(self, files, rule, detail, path=None, moves=()):
        got = self.findings(files, moves)
        hits = [f for f in got if f["rule"] == rule and detail in f["detail"] and (path is None or f["path"] == path)]
        self.assertTrue(hits, "expected %s %r in %r" % (rule, detail, got))
        for f in got:
            self.assertEqual(f["effect"], "ci-policy:test-weakening")
        return hits

    # --- one red PR per pattern ---------------------------------------------------------------

    def test_red_it_skip(self):
        hit = self.assertFlagged({"src/b.test.ts": "it.skip('b', () => {})\n"}, "test-skip", "`it.skip`")[0]
        self.assertEqual((hit["path"], hit["line"]), ("src/b.test.ts", 1))

    def test_red_skip_behind_a_closed_block_comment(self):
        got = self.findings({"src/b.test.ts": "/**/ it.skip('b', () => {})\n",
                             "scripts/ci.sh": 'case "$1" in\n  *) npm test || true ;;\nesac\n'})
        self.assertEqual(sorted((f["rule"], f["detail"]) for f in got),
                         [("swallowed-failure", "adds `npm test || true`"), ("test-skip", "adds `it.skip`")])

    def test_red_todo(self):
        self.assertFlagged({"src/b.test.ts": BASE["src/b.test.ts"] + "describe.todo('later')\n"},
                           "test-skip", "`describe.todo`")

    def test_red_only_and_playwright_skip(self):
        got = self.findings({"src/b.test.ts": "test.describe.only('b', () => {})\ntest.skip(isWebkit)\n"})
        self.assertEqual(sorted(f["detail"] for f in got if f["rule"] == "test-skip"),
                         ["adds `test.describe.only`", "adds `test.skip`"])

    def test_red_pytest_skip(self):
        self.assertFlagged({"tests/test_x.py": "import pytest\n\n@pytest.mark.skip(reason='x')\n" + BASE["tests/test_x.py"]},
                           "test-skip", "`pytest.mark.skip`")

    def test_red_vitest_retry(self):
        cfg = edit(BASE["vitest.config.ts"], "    testTimeout: 5000,\n", "    testTimeout: 5000,\n    retry: 2,\n")
        self.assertFlagged({"vitest.config.ts": cfg}, "test-retry", "sets retry `retry` to 2 (default 0)")

    def test_red_playwright_retries_on_ci(self):
        cfg = edit(BASE["playwright.config.ts"], "retries: 0,", "retries: process.env.CI ? 2 : 0,")
        self.assertFlagged({"playwright.config.ts": cfg}, "test-retry",
                           "changes retry `retries` from 0 to a non-literal value")

    def test_red_retry_on_a_test(self):
        self.assertFlagged({"src/b.test.ts": "it('b', { retry: 3 }, () => {})\n"}, "test-retry", "to 3")

    def test_red_cli_retry_and_reruns(self):
        wf = BASE[".github/workflows/ci.yml"] + "      - run: npx vitest run --retry=2\n      - run: pytest --reruns 3\n"
        got = self.findings({".github/workflows/ci.yml": wf})
        self.assertEqual(sorted(f["detail"] for f in got if f["rule"] == "test-retry"),
                         ["sets retry `--reruns` to 3 (default 0)", "sets retry `--retry` to 2 (default 0)"])

    def test_red_continue_on_error_job(self):
        wf = edit(BASE[".github/workflows/ci.yml"], "    runs-on: x\n", "    runs-on: x\n    continue-on-error: true\n")
        hit = self.assertFlagged({".github/workflows/ci.yml": wf}, "continue-on-error", "on job `test`")[0]
        self.assertEqual(hit["line"], 6)
        self.assertIn("required check is not readable here", hit["detail"])

    def test_red_continue_on_error_step_expression(self):
        wf = edit(BASE[".github/workflows/ci.yml"], "      - run: npm test\n",
                  "      - run: npm test\n        continue-on-error: " + "$" + "{{ matrix.experimental }}\n")
        self.assertFlagged({".github/workflows/ci.yml": wf}, "continue-on-error",
                           "adds `continue-on-error: <expression>` on step")

    def test_red_or_true_after_test_command(self):
        wf = edit(BASE[".github/workflows/ci.yml"], "- run: npm test\n", "- run: npm test || true\n")
        self.assertFlagged({".github/workflows/ci.yml": wf}, "swallowed-failure", "`npm test || true`")

    def test_red_swallowed_in_package_json_and_shell(self):
        got = self.findings({"package.json": '{\n  "scripts": {\n    "test:ci": "vitest run || true"\n  }\n}\n',
                             "scripts/ci.sh": "set -eu\npython3 -m pytest -q tests || exit 0\n"})
        self.assertEqual(sorted(f["detail"] for f in got if f["rule"] == "swallowed-failure"),
                         ["adds `pytest || exit 0`", "adds `vitest || true`"])

    def test_red_or_true_after_a_test_script_run_by_path(self):
        wf = BASE[".github/workflows/ci.yml"] + "      - run: python3 scripts/test-routing.py || true\n"
        hit = self.assertFlagged({".github/workflows/ci.yml": wf}, "swallowed-failure",
                                 "adds `scripts/test-routing.py || true`")[0]
        self.assertEqual(hit["line"], 9)

    def test_red_test_deleted_without_successor(self):
        hit = self.assertFlagged({"tests/test_x.py": None}, "test-deleted", "no successor")[0]
        self.assertEqual((hit["path"], hit["line"]), ("tests/test_x.py", None))

    def test_red_test_renamed_out_of_the_runners_reach(self):
        # git -M reports these as renames (R100), not deletions: the test stops running all the same.
        for old, new in (("src/b.test.ts", "src/b.test.ts.bak"), ("tests/test_x.py", "tests/fixtures/test_x.py")):
            with self.subTest(new=new):
                hit = self.assertFlagged({}, "test-deleted", "renames a test file to the non-test path `%s`" % new,
                                         path=old, moves=[(old, new)])[0]
                self.assertIsNone(hit["line"])

    def test_red_timeout_raised(self):
        cfg = edit(BASE["vitest.config.ts"], "testTimeout: 5000", "testTimeout: 60_000")
        self.assertFlagged({"vitest.config.ts": cfg}, "budget-loosened", "raises timeout `testTimeout` 5000 -> 60000")

    def test_red_coverage_lowered(self):
        cfg = edit(BASE["vitest.config.ts"], "lines: 80", "lines: 60")
        self.assertFlagged({"vitest.config.ts": cfg}, "budget-loosened", "lowers coverage `lines` 80 -> 60")

    def test_red_fail_under_lowered_and_removed(self):
        self.assertFlagged({"pyproject.toml": "[tool.coverage.report]\nfail_under = 70\n"},
                           "budget-loosened", "lowers coverage `fail_under` 90 -> 70")
        self.assertFlagged({"pyproject.toml": "[tool.coverage.report]\n"},
                           "budget-loosened", "removes coverage `fail_under` (was 90)")

    def test_red_assertion_budget_lowered(self):
        t = edit(BASE["src/a.test.ts"], "expect.assertions(3)", "expect.assertions(1)")
        t = edit(t, "toBeLessThan(200)", "toBeLessThan(500)")
        t = edit(t, "  expect.hasAssertions()\n", "")
        got = self.findings({"src/a.test.ts": t})
        details = sorted(f["detail"] for f in got if f["rule"] == "budget-loosened")
        self.assertEqual(details, ["lowers assertions `assertions` 3 -> 1",
                                   "raises bound `toBeLessThan` 200 -> 500",
                                   "removes `expect.hasAssertions`"])

    def test_red_budget_constant_raised_but_not_other_constants(self):
        t = BASE["src/b.test.ts"] + "const LATENCY_BUDGET_MS = 200\nconst limit = 5\nconst cfg = { renderBudget: 16 }\n"
        base_case = self.repo.case({"src/b.test.ts": t})
        head_text = (BASE["src/b.test.ts"] + "const LATENCY_BUDGET_MS = 2_000\nconst limit = 50\n"
                     "const cfg = { renderBudget: 33 }\n")
        git(self.repo.d, "checkout", "-q", "-b", "budget-head", base_case)
        pathlib.Path(self.repo.d, "src/b.test.ts").write_text(head_text)
        git(self.repo.d, "commit", "-q", "-am", "raise")
        head = git(self.repo.d, "rev-parse", "HEAD")
        cwd = os.getcwd()
        try:
            os.chdir(self.repo.d)
            got, incomplete, _ = classify.weakening_scan(base_case, head)
        finally:
            os.chdir(cwd)
        self.assertEqual(incomplete, [])
        self.assertEqual(sorted(f["detail"] for f in got),
                         ["raises budget `LATENCY_BUDGET_MS` 200 -> 2000", "raises budget `renderBudget` 16 -> 33"])

    # --- controls: never flagged --------------------------------------------------------------

    def test_control_same_text_in_markdown(self):
        self.assertEqual(self.findings({"docs/weakening.md": DOC, "README.md": BASE["README.md"] + DOC}), [])

    def test_control_tightening_and_zero_values(self):
        cfg = edit(BASE["vitest.config.ts"], "testTimeout: 5000", "testTimeout: 2000")
        cfg = edit(cfg, "lines: 80", "lines: 90")
        self.assertEqual(self.findings({
            "vitest.config.ts": cfg,
            "e2e/playwright-smoke.config.ts": "export default {\n  retries: 0,\n}\n",
            "pyproject.toml": "[tool.coverage.report]\nfail_under = 95\n",
            "src/a.test.ts": edit(BASE["src/a.test.ts"], "toBeLessThan(200)", "toBeLessThan(100)"),
        }), [])

    def test_control_moves_reindents_and_comments(self):
        moved = "describe('m', () => {\n  it('kept', () => {})\n    it.skip('legacy', () => {})\n})\n"
        wf = BASE[".github/workflows/ci.yml"] + (
            "      # continue-on-error: true would hide this; do not add it\n"
            "      - run: npm test\n"
            "        continue-on-error: false\n"
            "      - run: pip install vitest || true\n"
            "      - run: curl --retry 3 -fsS https://example.invalid/x\n")
        self.assertEqual(self.findings({"src/moved.test.ts": moved, ".github/workflows/ci.yml": wf,
                                        "src/c.ts": "export const c = 2 // it.skip( in a non-test file\n"}), [])

    def test_moved_skip_is_not_the_line_blamed_for_a_new_one(self):
        head = ("describe('m', () => {\n  it.skip('new', () => {})\n  it('kept', () => {})\n"
                "    it.skip('legacy', () => {})\n})\n")
        got = self.findings({"src/moved.test.ts": head})
        self.assertEqual([(f["rule"], f["line"], f["detail"]) for f in got], [("test-skip", 2, "adds `it.skip`")])

    def test_control_renamed_or_replaced_tests(self):
        self.assertEqual(self.findings(moves=[("tests/test_x.py", "tests/unit/test_x.py")]), [])
        self.assertEqual(self.findings({"src/b.test.ts": None, "src/b.spec.ts": BASE["src/b.test.ts"] + "// v2\n"}), [])

    def test_red_fleet_test_directory_file_deleted(self):
        # Codex review of 698cf202: a test under test/ with no .test. infix (node --test's default glob) was missed.
        path = "services/identity/test/notification-email-acceptance.mjs"
        hit = self.assertFlagged({path: None}, "test-deleted", "deletes a test file with no successor", path=path)[0]
        self.assertIsNone(hit["line"])

    def test_red_same_name_elsewhere_is_an_unverified_candidate_not_a_successor(self):
        # Codex review of 698cf202: deleting critical/a.test.ts was excused by an unrelated added unrelated/a.test.ts.
        hit = self.assertFlagged({"critical/a.test.ts": None,
                                  "unrelated/a.test.ts": "it('renders the banner', () => {\n"
                                                         "  expect(banner()).toBeTruthy()\n})\n"},
                                 "test-deleted", "deletes a test file", path="critical/a.test.ts")[0]
        self.assertIn("unverified successor candidate by name only: `unrelated/a.test.ts`", hit["detail"])
        self.assertNotIn("no successor", hit["detail"])

    def test_control_content_paired_move_is_not_a_deletion(self):
        # git pairs the file by content (R100): the same test moved, so nothing is reported.
        self.assertEqual(self.findings(moves=[("critical/a.test.ts", "unrelated/a.test.ts")]), [])

    def test_name_and_stem_candidates_are_listed_and_capped(self):
        rows = [("D", "critical/a.test.ts", "critical/a.test.ts"), ("A", "other/a.spec.ts", "other/a.spec.ts")]
        rows += [("A", "x%d/a.test.ts" % i, "x%d/a.test.ts" % i) for i in range(4)]
        got = classify.deleted_test_findings(rows)
        self.assertEqual([f["path"] for f in got], ["critical/a.test.ts"])
        self.assertIn("unverified successor candidate by name only: `x0/a.test.ts`, `x1/a.test.ts`, `x2/a.test.ts`"
                      " and 2 more", got[0]["detail"])
        # A stem match (a.spec.ts for a.test.ts) is a candidate too, never a successor.
        got = classify.deleted_test_findings(rows[:2])
        self.assertIn("candidate by name only: `other/a.spec.ts`", got[0]["detail"])

    def test_red_many_same_name_tests_stay_linear(self):
        # The listing cap admits ~16k deletions plus ~16k additions of one test name. Red on de8a7b6: list
        # membership made the candidate listing cubic (1200 pairs took ~6 s, 2000 took 39 s), outside any deadline.
        n = 1200
        rows = [("D", "d%d/index.test.ts" % i, "d%d/index.test.ts" % i) for i in range(n)]
        rows += [("A", "a%d/index.test.ts" % i, "a%d/index.test.ts" % i) for i in range(n)]
        rows += [("D", "e%d/index.spec.ts" % i, "e%d/index.spec.ts" % i) for i in range(n)]  # same stem, other name
        started = time.monotonic()
        got = classify.deleted_test_findings(rows)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(len(got), 2 * n)
        listed = "`a0/index.test.ts`, `a1/index.test.ts`, `a2/index.test.ts` and %d more" % (n - 3)
        self.assertIn("candidate by name only: %s (" % listed, got[0]["detail"])
        self.assertIn("candidate by name only: %s (" % listed, got[-1]["detail"])

    def test_deleted_test_notes_a_deleted_subject(self):
        # A non-test file of the same stem is not a successor.
        got = self.findings({"pkg/test_util.py": None, "pkg/util.py": "x = 1\n"})
        self.assertEqual([(f["rule"], f["path"]) for f in got], [("test-deleted", "pkg/test_util.py")])
        self.assertNotIn("same stem", got[0]["detail"])
        # Test and subject deleted together (a feature removal?) is still flagged, with a note for the reviewer.
        got = self.findings({"src/c.test.ts": None, "src/c.ts": None})
        self.assertEqual([(f["rule"], f["path"]) for f in got], [("test-deleted", "src/c.test.ts")])
        self.assertIn("(a source file of the same stem is deleted too)", got[0]["detail"])

    def test_one_combined_diff_matches_per_file_diffs(self):
        wf = edit(BASE[".github/workflows/ci.yml"], "- run: npm test\n", "- run: npm test || true\n")
        cfg = edit(BASE["vitest.config.ts"], "lines: 80", "lines: 60")
        head = self.repo.case({".github/workflows/ci.yml": wf, "vitest.config.ts": cfg,
                               "src/b.test.ts": "it.skip('b', () => {})\n", "src/\u00fcn\u00ef.test.ts": "it.only('u')\n",
                               'src/q"uote.test.ts': "it.todo('q')\n"},
                              moves=[("src/moved.test.ts", "src/renamed.test.ts")])
        combined, _, _ = self.repo.scan(head)
        # No section bound from the combined diff: every file takes the per-file fallback.
        with mock.patch.object(classify, "patch_sections", lambda chunks, cap: iter(())):
            per_file, _, _ = self.repo.scan(head)
        key = lambda f: (f["path"], f["line"] or 0, f["detail"])
        self.assertEqual(sorted(combined, key=key), sorted(per_file, key=key))
        # A path git quotes in its header (always for '"'; non-ASCII too under the default core.quotePath)
        # takes the per-file fallback and is still scanned.
        got = [(f["path"], f["detail"]) for f in combined]
        self.assertIn(('src/q"uote.test.ts', "adds `it.todo`"), got)
        self.assertIn(("src/\u00fcn\u00ef.test.ts", "adds `it.only`"), got)
        self.assertEqual(len(combined), 5, combined)
        cwd = os.getcwd()
        try:
            os.chdir(self.repo.d)
            budget = classify.ScanBudget(60, 10 ** 7)
            rows, stop = classify.census(budget, self.repo.base, head)
            paths = {p for _, old, new, _, _ in rows for p in (old, new)}
            headers = [h for h, _ in classify.patch_sections(
                classify.git_chunks(budget, classify.diff_args(self.repo.base, head, paths)), 10 ** 6)]
        finally:
            os.chdir(cwd)
        self.assertIsNone(stop)
        self.assertIn(("R", "src/moved.test.ts", "src/renamed.test.ts"), [r[:3] for r in rows])
        self.assertIn("diff --git a/src/moved.test.ts b/src/renamed.test.ts", headers)
        self.assertNotIn('diff --git a/src/q"uote.test.ts b/src/q"uote.test.ts', headers)

    def test_one_combined_diff_for_every_file(self):
        # One listing and one combined diff, however many files: never one git diff per file.
        head = self.repo.case({"src/f%d.test.ts" % i: "it.skip('f%d', () => {})\n" % i for i in range(12)})
        real, calls = subprocess.Popen, []

        def popen(args, *a, **kw):
            calls.append(list(args[:2]))
            return real(args, *a, **kw)
        with mock.patch.object(subprocess, "Popen", popen):
            findings, incomplete, in_scope = self.repo.scan(head)
        self.assertEqual((len(findings), incomplete, in_scope), (12, [], 12))
        self.assertEqual(calls.count(["git", "diff"]), 2, calls)

    # --- references are listed, never honoured --------------------------------------------------

    def test_inline_and_trailer_references_are_listed_not_honoured(self):
        head = self.repo.case({"src/b.test.ts": "// vagaris-quarantine: QR-12\nit.skip('b', () => {})\n"},
                              message="test: park b\n\nVagaris-Approval: ap-7f3e\n")
        findings, _, _ = self.repo.scan(head)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["refs"], ["quarantine `QR-12`", "approval `ap-7f3e`"])
        code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("references quarantine `QR-12`, approval `ap-7f3e` (unverified)", out)
        self.assertIn("never honoured", out)


class IntegrityReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repo()

    @classmethod
    def tearDownClass(cls):
        cls.repo.tmp.cleanup()

    def test_weakening_only_pr_is_reported_and_passes(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"})
        code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("No protected workflow or ratchet change.", out)
        self.assertIn("### Test-weakening predicates (FL-4 `fl4-v1`, report-only)", out)
        self.assertIn("- WEAKENING test-skip `src/b.test.ts:1` adds `it.skip`; no quarantine or approval reference", out)
        self.assertIn("::warning file=src/b.test.ts,line=1,title=test weakening (FL-4)::test-skip: adds `it.skip`", out)

    def test_markdown_control_reports_clean(self):
        head = self.repo.case({"docs/weakening.md": DOC})
        code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("No test-weakening pattern added (0 changed files in scope).", out)
        self.assertNotIn("WEAKENING", out)
        self.assertNotIn("::warning", out)

    def test_protected_workflow_change_still_reported_alongside(self):
        wf = edit(BASE[".github/workflows/ci.yml"], "- run: npm test\n", "- run: npm test || true\n")
        code, out = self.repo.integrity(self.repo.case({".github/workflows/ci.yml": wf}))
        self.assertEqual(code, 0, out)
        self.assertIn("PROTECTED-PATH CHANGE `.github/workflows/ci.yml` M (ci-judge)", out)
        self.assertIn("WEAKENING swallowed-failure `.github/workflows/ci.yml:7`", out)

    def test_scan_failure_is_incomplete_never_red(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"})
        for exc in (RuntimeError("boom"), classify.IntegrityError("git diff failed")):
            with self.subTest(exc=type(exc).__name__), mock.patch.object(classify, "weakening_scan", side_effect=exc):
                code, out = self.repo.integrity(head)
                self.assertEqual(code, 0, out)
                self.assertIn("- INCOMPLETE: the scan failed (%s)" % type(exc).__name__, out)
                self.assertNotIn("No test-weakening pattern added", out)

    def test_oversized_diff_is_incomplete_not_clean(self):
        head = self.repo.case({"src/b.test.ts": "it('b2', () => {})\n"})
        with mock.patch.object(classify, "WEAKENING_MAX_PATCH_BYTES", 10):
            code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: `src/b.test.ts`: diff larger than 10 bytes, not scanned", out)
        self.assertNotIn("No test-weakening pattern added", out)

    def test_hostile_long_line_is_bounded_and_incomplete(self):
        # One ~1 MB minified-style line: before the cap, two predicates were quadratic on it (red proof:
        # 96k chars took 11.7 s on fl4-v1's first draft, extrapolating past the job's 10-minute timeout).
        head = self.repo.case({"e2e/min.test.js": "it(a,{x:1});" * 85000 + "\n"})
        started = time.monotonic()
        code, out = self.repo.integrity(head)
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: `e2e/min.test.js`: 1 changed lines over 4000 chars not scanned", out)
        self.assertNotIn("No test-weakening pattern added", out)

    def test_adversarial_lines_under_the_cap_stay_fast(self):
        n = classify.WEAKENING_MAX_LINE // 13
        lines = ["it(a,{x:1});" * n, "aBudget" * (n * 2), "x || " * (n * 2), "'\"" * (n * 5),
                 "test.describe.configure({" * (n // 2), "continue-on-error: " + " " * (n * 12) + "x"]
        # A swallow tail after many candidate command starts (quotes, interpreters, run:) inside one segment.
        lines += [(s * classify.WEAKENING_MAX_LINE)[: classify.WEAKENING_MAX_LINE - 8] + " || true"
                  for s in ("bash '", "'", "run: ./", "python3 -")]
        lines += ["/**/" * n * 2, "*/ /*" * n, "/*" * n * 2]
        files = {"e2e/adv.test.js": "\n".join(l[: classify.WEAKENING_MAX_LINE] for l in lines * 10) + "\n",
                 "scripts/adv.sh": "\n".join(l[: classify.WEAKENING_MAX_LINE] for l in lines * 10) + "\n",
                 ".github/workflows/adv.yml": "\n".join(l[: classify.WEAKENING_MAX_LINE] for l in lines * 10) + "\n"}
        head = self.repo.case(files)
        started = time.monotonic()
        findings, incomplete, _ = self.repo.scan(head)
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(incomplete, [])

    def test_scan_deadline_is_incomplete(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"})
        with mock.patch.object(classify, "WEAKENING_DEADLINE_SECONDS", -1):
            code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        # The listing runs under the budget too (it did not before), so an expired budget stops there.
        self.assertIn("- INCOMPLETE: the -1s scan budget ran out while listing the changed files", out)
        self.assertNotIn("No test-weakening pattern added", out)

    # --- the scan's time and byte budget (Codex review of 698cf202, finding 1) ------------------
    # Red on 698cf202: it captured the whole combined diff before any per-file check, so peak memory followed the
    # PR's size; it had no total byte budget; and its git calls had no timeout, so a slow git ran past the deadline
    # and an empty listing read as a clean PR.

    def traced_integrity(self, head):
        tracemalloc.start()
        try:
            code, out = self.repo.integrity(head)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        return code, out, peak

    def test_red_file_over_the_blob_cap_is_never_diffed(self):
        head = self.repo.case({"src/huge.test.ts": HUGE, "src/z.test.ts": "it.skip('z', () => {})\n"})
        started = time.monotonic()
        with mock.patch.object(classify, "WEAKENING_MAX_BLOB_BYTES", 1000000, create=True), \
                mock.patch.object(classify, "WEAKENING_DEADLINE_SECONDS", 5):
            code, out, peak = self.traced_integrity(head)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: `src/huge.test.ts`: file larger than 1000000 bytes, not diffed or scanned", out)
        self.assertIn("- WEAKENING test-skip `src/z.test.ts:1` adds `it.skip`", out)
        self.assertNotIn("No test-weakening pattern added", out)
        self.assertLess(peak, 1500000)

    def test_red_oversized_diff_is_dropped_as_it_streams(self):
        # Under the blob cap, over the per-file diff cap: the section is skipped as it arrives, and the file after it
        # in the same combined diff is still scanned.
        head = self.repo.case({"src/huge.test.ts": HUGE, "src/z.test.ts": "it.skip('z', () => {})\n"})
        with mock.patch.object(classify, "WEAKENING_MAX_PATCH_BYTES", 100000):
            code, out, peak = self.traced_integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: `src/huge.test.ts`: diff larger than 100000 bytes, not scanned", out)
        self.assertIn("- WEAKENING test-skip `src/z.test.ts:1` adds `it.skip`", out)
        self.assertLess(peak, 1500000)

    def test_red_total_read_budget_is_incomplete(self):
        head = self.repo.case({"src/huge.test.ts": HUGE, "src/z.test.ts": "it.skip('z', () => {})\n"})
        started = time.monotonic()
        with mock.patch.object(classify, "WEAKENING_MAX_PATCH_BYTES", 10 ** 8), \
                mock.patch.object(classify, "WEAKENING_DEADLINE_SECONDS", 5), \
                mock.patch.object(classify, "WEAKENING_MAX_TOTAL_BYTES", 1000000, create=True):
            code, out, peak = self.traced_integrity(head)
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0, out)
        # The BYTE budget stopped it, inside the deadline (not the clock).
        self.assertIn("- INCOMPLETE: the 1000000-byte read budget ran out after 0 of 2 files in scope; "
                      "the rest were not scanned", out)
        self.assertNotIn("scan budget ran out", out)
        self.assertNotIn("No test-weakening pattern added", out)
        self.assertLess(peak, 2500000)
        self.assertLess(elapsed, 5)

    def test_red_changed_file_list_is_read_under_a_cap(self):
        head = self.repo.case({"src/a1.test.ts": "it.skip('a1', () => {})\n", "src/a2.test.ts": "it.only('a2')\n"})
        raw = subprocess.run(["git", "diff", "--raw", "--no-abbrev", "-z", "-M", self.repo.base, head],
                             cwd=self.repo.d, check=True, capture_output=True).stdout
        cut = raw.index(b"src/a1.test.ts\0") + len(b"src/a1.test.ts\0") + 10  # inside the second record
        with mock.patch.object(classify, "WEAKENING_MAX_CENSUS_BYTES", cut, create=True):
            findings, incomplete, in_scope = self.repo.scan(head)
        self.assertEqual([(f["path"], f["detail"]) for f in findings], [("src/a1.test.ts", "adds `it.skip`")])
        self.assertEqual(incomplete, ["the changed-file list is longer than %d bytes; only the first 1 files were "
                                      "listed and scanned" % cut])
        self.assertEqual(in_scope, 1)

    @contextlib.contextmanager
    def slow_git_diff(self, flag, seconds=8):
        """Every `git diff` carrying flag becomes a process that prints nothing for `seconds` (the real Popen)."""
        real = subprocess.Popen

        def popen(args, *a, **kw):
            if isinstance(args, (list, tuple)) and list(args[:2]) == ["git", "diff"] and flag in args:
                args = [sys.executable, "-c", "import time; time.sleep(%d)" % seconds]
            return real(args, *a, **kw)
        with mock.patch.object(subprocess, "Popen", popen):
            yield

    def test_red_slow_listing_is_incomplete_within_the_deadline(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"})
        started = time.monotonic()
        with mock.patch.object(classify, "WEAKENING_DEADLINE_SECONDS", 2), self.slow_git_diff("-M"):
            code, out = self.repo.integrity(head)
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0, out)
        self.assertNotIn("No test-weakening pattern added", out)
        self.assertIn("- INCOMPLETE: the 2s scan budget ran out while listing the changed files", out)
        self.assertLess(elapsed, 6)

    def test_red_slow_diff_is_incomplete_within_the_deadline(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"})
        started = time.monotonic()
        with mock.patch.object(classify, "WEAKENING_DEADLINE_SECONDS", 2), self.slow_git_diff("--unified=1"):
            code, out = self.repo.integrity(head)
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: the 2s scan budget ran out after 0 of 1 files in scope; the rest were not scanned",
                      out)
        self.assertLess(elapsed, 6)

    def test_red_commit_messages_are_read_under_a_cap(self):
        msg = "test: park b\n\nVagaris-Approval: ap-7f3e1234\n"
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n"}, message=msg)
        # Cut inside the trailer line: the partial line must not be read as the shorter id `ap-7f3e`.
        cut = msg.index("ap-7f3e1234") + len("ap-7f3e")
        with mock.patch.object(classify, "WEAKENING_MAX_TRAILER_BYTES", cut, create=True):
            findings, incomplete, _ = self.repo.scan(head)
        self.assertEqual([f["refs"] for f in findings], [[]])
        self.assertEqual(incomplete, ["commit messages past %d bytes were not read for references" % cut])

    def test_file_cap_is_incomplete(self):
        head = self.repo.case({"src/b.test.ts": "it.skip('b', () => {})\n", "src/d.test.ts": "it('d', () => {})\n"})
        with mock.patch.object(classify, "WEAKENING_MAX_FILES", 1):
            code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        self.assertIn("- INCOMPLETE: 2 files in scope; only the first 1 were scanned", out)

    def test_annotations_leave_room_for_the_pointers(self):
        head = self.repo.case({"src/b.test.ts": "".join("it.skip('b%d', () => {})\n" % i for i in range(12))})
        with mock.patch.object(classify, "WEAKENING_MAX_PATCH_BYTES", 10 ** 7):
            code, out = self.repo.integrity(head)
        self.assertEqual(code, 0, out)
        warnings = [l for l in out.splitlines() if l.startswith("::warning")]
        self.assertEqual(len([l for l in warnings if l.startswith("::warning file=")]), 8)
        self.assertIn("::warning title=test weakening (FL-4)::4 more findings in the job summary", warnings)
        self.assertLessEqual(len(warnings), 10)

    def test_integrity_errors_still_win(self):
        self.assertEqual(self.repo.integrity("f" * 40)[0], 2)


class PredicateUnitTests(unittest.TestCase):
    def test_patch_sections_survive_any_chunking(self):
        # A body line `+diff --git ...` is not a header; a section over the cap is dropped, the next one is kept.
        x = b"diff --git a/x b/x\n@@ -1 +1 @@\n-a\n+diff --git not a header\n"
        y = b"diff --git a/y b/y\n@@ -1 +1 @@\n-" + b"y" * 100 + b"\n+z\n"
        z = b"diff --git a/z b/z\n@@ -0,0 +1 @@\n+q\n"
        diff = x + y + z
        for size in (1, 2, 3, 5, 7, 11, 13, 64, len(diff)):
            with self.subTest(size=size):
                got = list(classify.patch_sections(iter([diff[i:i + size] for i in range(0, len(diff), size)]), 70))
                self.assertEqual(got, [("diff --git a/x b/x", x.decode()), ("diff --git a/y b/y", None),
                                       ("diff --git a/z b/z", z.decode())])

    def test_swallowed_runner(self):
        cases = {
            "pytest -q || true": "pytest || true",
            "  - run: pnpm --filter web test:unit || :": "pnpm --filter web test:unit || :",
            "CI=1 npx vitest run | tee out.log || true": "vitest || true",
            "timeout 600 go test ./... || echo failed": "go test || echo",
            "make test || exit 0": "make test || exit 0",
            "pnpm vitest run || true": "vitest || true",
            # A test file run by path, the fleet's usual form (vps-ansible, vagary-core, vagary-voice workflows).
            "  - run: python3 scripts/test-ci-hosted-routing.py || true": "scripts/test-ci-hosted-routing.py || true",
            'run: PATH="$PWD/.venv/bin:$PATH" .venv/bin/python scripts/test-canon.py || true':
                "scripts/test-canon.py || true",
            "python3 -I roles/automation/tests/test_dump.py || true": "roles/automation/tests/test_dump.py || true",
            "bash test/run-functional.sh || exit 0": "test/run-functional.sh || exit 0",
            "./scripts/lib/test-canon-guard.sh || :": "scripts/lib/test-canon-guard.sh || :",
            '"test:ci": "bash tests/run.sh || true",': "tests/run.sh || true",
            'bash "$GITHUB_WORKSPACE/scripts/ci-test-pg.sh" down "$CN" || true': None,
            "python3 scripts/capability-catalog-gen.py >/dev/null 2>&1 || true": None,
            'git diff --quiet -- "tests/test_x.py" || true': None,
            "rm -f tests/test_x.py || true": None,
            "python3 -c 'import x' || true": None,
            "pip install pytest || true": None,
            "python3 -m pip install -q httpx pytest || true": None,
            "grep -q vitest package.json || true": None,
            "npm ci || true": None,
            "pytest && echo ok": None,
        }
        for line, want in cases.items():
            with self.subTest(line=line):
                self.assertEqual(classify.swallowed_runner(line), want)

    def test_per_test_timeout_option(self):
        p = "src/a.test.ts"
        scopes = classify.path_scopes(p)
        old = [(4, "it('slow', { timeout: 5000 }, async () => {")]
        got = classify.numeric_findings(p, scopes, [(4, "it('slow', { timeout: 60_000 }, async () => {")], old, 4)
        self.assertEqual([(f["rule"], f["line"], f["detail"]) for f in got],
                         [("budget-loosened", 4, "raises timeout `timeout` 5000 -> 60000")])
        self.assertEqual(classify.numeric_findings(
            p, scopes, [(4, "it('slow', { timeout: 2000 }, async () => {")], old, 4), [])

    def test_parse_num(self):
        for raw, want in (("5000,", 5000.0), ("60_000", 60000.0), ("30 * 1000 // ms", 30000.0), ("0", 0.0),
                          ("false", 0.0), ("'2'", 2.0), ("process.env.CI ? 2 : 0", None), ("n", None)):
            with self.subTest(raw=raw):
                self.assertEqual(classify.parse_num(raw), want)

    def test_coe_level(self):
        lines = ["jobs:", "  build:", "    runs-on: x", "    continue-on-error: true", "    steps:",
                 "      - run: a", "        continue-on-error: true", "      - continue-on-error: true"]
        self.assertEqual(classify.coe_level(lines, 3), "job `build`")
        self.assertEqual(classify.coe_level(lines, 6), "step")
        self.assertEqual(classify.coe_level(lines, 7), "step")

    def test_is_comment(self):
        for line, want in (("// it.skip('a')", True), ("  # continue-on-error: true", True), ("/* it.skip('d') */", True),
                           ("/* it.skip('e')", True), ("   * it.skip('f')", True), ("*", True), ("<!-- x -->", True),
                           ("/**/ it.skip('b')", False), (" */ it.skip('c')", False), ("/* a */ /* b */ xit('g')", False),
                           ("  *) npm test || true ;;", False), ("it.skip('h')", False), ("", False)):
            with self.subTest(line=line):
                self.assertEqual(classify.is_comment(line), want)

    def test_docs_are_never_in_scope(self):
        for p in ("README.md", "docs/ci/retries.md", "CHANGELOG.mdx", "notes.txt", "tests/README.md"):
            with self.subTest(path=p):
                self.assertEqual(classify.path_scopes(p), set())

    def test_fleet_test_path_conventions(self):
        # Fleet paths (git ls-files, 2026-10-15) where commented, plus each runner's default forms; negatives
        # are look-alikes that are not tests (the commented ones exist in the fleet).
        for path in ("services/identity/test/notification-email-acceptance.mjs",   # vagary-core, node --test
                     "packages/identity-client/test/live-contract.mts",            # vagary-core
                     "e2e/voice/run.mjs",                                          # vagary-core e2e runner
                     "api-service/test/voice-activation-pg.cjs",                   # vagary-voice
                     "widget/test/call-sdk-barge-in.cjs",                          # vagary-voice
                     "voice-gateway/test/voice_gateway/audit_logger_test.exs",     # vagary-voice ExUnit
                     "server/src/__tests__/deep/x.tsx",
                     "dashboard/src/a.test.tsx", "frontend/src/b.spec.jsx", "e2e/c.e2e.ts", "lib/d.test.mjs",
                     "roles/identity_orphan_drift/files/vagaris-ownerless-orgs-check.test.sh",  # vps-ansible
                     "roles/observability/files/prometheus-rules/tests/build-cell-monitor.test.yml",  # promtool
                     "cmd/x_test.go", "pkg/y_test.py", "lib/z_test.mjs", "tests/test_x.py", "pkg/test_util.py",
                     "scripts/test-ci-hosted-routing.py", "tests/run.sh", "t/a.bats"):
            with self.subTest(path=path):
                self.assertTrue(classify.is_test_file(path))
        for path in ("server/src/adapters/http/test.ts",            # vagris adapter code named test.ts
                     "voice-gateway/config/test.exs",               # vagary-voice Elixir test-env config
                     "server/tsconfig.test.json",                   # vagris
                     "api-service/test-utils/database-setup.js",    # vagary-voice helpers outside a test dir
                     "api-service/test-setup/mocks/redis.js",       # vagary-voice
                     "docker-compose.test.yml", "src/__fixtures__/a.test.ts", "test/fixtures/a.mjs",
                     "tests/__init__.py", "tests/README.md", "docs/specs/x.md", "scripts/ci-test-pg.sh",
                     "src/contest.ts", "src/latest.mjs"):
            with self.subTest(path=path):
                self.assertFalse(classify.is_test_file(path))

    def test_fixtures_and_snapshots_are_not_tests(self):
        self.assertFalse(classify.is_test_file("src/__fixtures__/a.test.ts"))
        self.assertFalse(classify.is_test_file("tests/__init__.py"))
        self.assertTrue(classify.is_test_file("scripts/test-ci-hosted-routing.py"))
        self.assertTrue(classify.is_test_file("server/src/__tests__/deep/x.ts"))

    def test_annotation_properties_are_escaped(self):
        self.assertEqual(classify._cmd_prop("a,b:c%\nd"), "a%2Cb%3Ac%25%0Ad")
        self.assertEqual(classify.md_code("a`b\nc"), "`a'b c`")
        self.assertEqual(classify.safe_tok("pnpm --filter `$(x)` test"), "pnpm --filter x test")


class SourceHygieneTests(unittest.TestCase):
    """classify.py is inlined into a workflow `run: |` block: Actions would expand an expression in it."""

    def test_inlinable(self):
        src = (ROOT / "trusted" / "classify.py").read_text()
        self.assertNotIn("$" + "{{", src)
        self.assertNotIn("\t", src)
        self.assertNotIn("TRUSTED_CLASSIFY_PY", src)


if __name__ == "__main__":
    unittest.main()
