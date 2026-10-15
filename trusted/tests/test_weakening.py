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
}

# The weakening text, as it would appear in a doc that explains the guard.
DOC = "\n".join([
    "it.skip('b', () => {})", "describe.todo('later')", "  retry: 2,", "  retries: process.env.CI ? 2 : 0,",
    "    continue-on-error: true", "      - run: npm test || true", "@pytest.mark.skip(reason='x')",
    "    testTimeout: 60000,", "coverage: { thresholds: { lines: 60 } }", "fail_under = 70",
    "  expect.assertions(1)", "  expect(took).toBeLessThan(500)", "pytest --reruns 3 || true", ""])


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

    def test_red_test_deleted_without_successor(self):
        hit = self.assertFlagged({"tests/test_x.py": None}, "test-deleted", "no successor")[0]
        self.assertEqual((hit["path"], hit["line"]), ("tests/test_x.py", None))

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

    def test_deleted_test_notes_a_deleted_subject(self):
        # A non-test file of the same stem is not a successor.
        got = self.findings({"pkg/test_util.py": None, "pkg/util.py": "x = 1\n"})
        self.assertEqual([(f["rule"], f["path"]) for f in got], [("test-deleted", "pkg/test_util.py")])
        self.assertNotIn("same stem", got[0]["detail"])
        # Test and subject deleted together (a feature removal?) is still flagged, with a note for the reviewer.
        got = self.findings({"src/c.test.ts": None, "src/c.ts": None})
        self.assertEqual([(f["rule"], f["path"]) for f in got], [("test-deleted", "src/c.test.ts")])
        self.assertIn("(a source file of the same stem is deleted too)", got[0]["detail"])

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

    def test_integrity_errors_still_win(self):
        self.assertEqual(self.repo.integrity("f" * 40)[0], 2)


class PredicateUnitTests(unittest.TestCase):
    def test_swallowed_runner(self):
        cases = {
            "pytest -q || true": "pytest || true",
            "  - run: pnpm --filter web test:unit || :": "pnpm --filter web test:unit || :",
            "CI=1 npx vitest run | tee out.log || true": "vitest || true",
            "timeout 600 go test ./... || echo failed": "go test || echo",
            "make test || exit 0": "make test || exit 0",
            "pip install pytest || true": None,
            "python3 -m pip install -q httpx pytest || true": None,
            "grep -q vitest package.json || true": None,
            "npm ci || true": None,
            "pytest && echo ok": None,
        }
        for line, want in cases.items():
            with self.subTest(line=line):
                self.assertEqual(classify.swallowed_runner(line), want)

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

    def test_docs_are_never_in_scope(self):
        for p in ("README.md", "docs/ci/retries.md", "CHANGELOG.mdx", "notes.txt", "tests/README.md"):
            with self.subTest(path=p):
                self.assertEqual(classify.path_scopes(p), set())

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
