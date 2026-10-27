"""Tests for the timeout-floor mode of trusted/classify.py and its FL-4 interplay.

Every job must declare timeout-minutes at or over the completion floor (manifest timeout_floor.minutes): a runner's
CompleteJob call can stall 100 s and retry, and a job whose timeout runs out meanwhile is cancelled after it
succeeded. One red case per verdict and per construct the stdlib reader must not misread, each a PR head off the
shared base of test_weakening.Repo. Plain unittest, stdlib only, light (one throwaway git repo). Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
sys.path.insert(0, str(ROOT / "trusted" / "tests"))
import classify  # noqa: E402
import render  # noqa: E402
from test_weakening import Repo, git  # noqa: E402  (the shared temp-git-repo helpers)

MANIFEST = ROOT / "trusted" / "manifest.json"
REPO = "vagarylabs/vagaris"
SHORT = "vagaris"  # the TSV's repo column: the census names repos without their owner
EXPR = "$" + "{{ inputs.minutes || 30 }}"
# The base commit's .github/workflows/ci.yml has one job, `test`, with no timeout-minutes.
BASE_ROW = (".github/workflows/ci.yml", "test", "default 360", "pass")


def wf(jobs):
    return "name: w\non: push\njobs:\n" + jobs


def tsv(out):
    """The TSV block's header and rows."""
    m = re.search(r"\n```tsv\n(.*?)\n```\n", out, re.S)
    assert m, out
    lines = m.group(1).split("\n")
    return lines[0], [tuple(l.split("\t")) for l in lines[1:]]


class FloorCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repo()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.repo.tmp.cleanup()
        cls.tmp.cleanup()

    def manifest(self, mode="report", exemptions=(), minutes=6):
        m = json.loads(MANIFEST.read_text())
        m["timeout_floor"] = {"minutes": minutes, "mode": mode, "exemptions": list(exemptions)}
        type(self).n += 1
        p = pathlib.Path(self.tmp.name, "manifest-%d.json" % self.n)
        p.write_text(json.dumps(m))
        return str(p)

    def run_floor(self, head, mode="report", exemptions=(), repo=REPO, base=None, cwd=None):
        """base None: the repo's base; base False: no --base at all."""
        out = io.StringIO()
        here = os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        args = ["timeout-floor", "--manifest", self.manifest(mode, exemptions), "--repo", repo, "--head", head]
        if base is not False:
            args += ["--base", base or self.repo.base]
        try:
            os.chdir(cwd or self.repo.d)
            with contextlib.redirect_stdout(out):
                code = classify.main(args)
        finally:
            os.chdir(here)
        return code, out.getvalue()

    def rows(self, out, short=SHORT):
        header, rows = tsv(out)
        self.assertEqual(header, "repo\tworkflow_path\tjob_key\ttimeout_minutes_declared\tverdict")
        for r in rows:
            self.assertEqual(len(r), 5, r)
            self.assertEqual(r[0], short)
        return {(r[1], r[2]): (r[3], r[4]) for r in rows}

    def both_modes(self, head, exemptions=()):
        """(report exit, enforce exit, report output, rows)."""
        code, out = self.run_floor(head, "report", exemptions)
        enforce, _ = self.run_floor(head, "enforce", exemptions)
        return code, enforce, out, self.rows(out)


class VerdictTests(FloorCase):
    def test_under_the_floor_is_reported_then_enforced(self):
        head = self.repo.case({".github/workflows/gate.yml": wf(
            "  test-gate:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: make test\n")})
        code, out = self.run_floor(head)
        self.assertEqual(code, 0, out)
        rows = self.rows(out)
        self.assertEqual(rows[(".github/workflows/gate.yml", "test-gate")], ("5", "violation"))
        self.assertEqual(rows[BASE_ROW[:2]], BASE_ROW[2:])
        self.assertIn("- VIOLATION `.github/workflows/gate.yml:6` job `test-gate`: timeout-minutes `5` is below the "
                      "6-minute floor", out)
        self.assertIn("::warning file=.github/workflows/gate.yml,line=6,title=timeout floor::job `test-gate`", out)
        self.assertIn("Report-only (mode `report`): 1 violations and 0 INCOMPLETE", out)
        code, out = self.run_floor(head, "enforce")
        self.assertEqual(code, 1, out)
        self.assertIn("::error file=.github/workflows/gate.yml,line=6,title=timeout floor::", out)
        self.assertIn("Refused (mode `enforce`): 1 violations, 0 INCOMPLETE", out)

    def test_at_the_floor_and_omitted_pass(self):
        head = self.repo.case({".github/workflows/ok.yml": wf(
            "  at:\n    runs-on: x\n    timeout-minutes: 6\n  bare:\n    runs-on: x\n")})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(".github/workflows/ok.yml", "at")], ("6", "pass"))
        self.assertEqual(rows[(".github/workflows/ok.yml", "bare")], ("default 360", "pass"))
        self.assertIn("All 3 jobs meet the 6-minute floor", out)
        self.assertNotIn("::warning", out)

    def test_quoted_float_and_commented_literals(self):
        jobs = {"dq5": '"5"', "sq6": "'6'", "f60": "6.0", "f55": "5.5", "c30": "30 # generous", "qc30": '"30" # q',
                "f599": "5.99", "zero": "0"}
        head = self.repo.case({".github/workflows/lit.yml": wf("".join(
            "  %s:\n    runs-on: x\n    timeout-minutes: %s\n" % kv for kv in jobs.items()))})
        rows = self.rows(self.run_floor(head)[1])
        want = {"dq5": ("5", "violation"), "sq6": ("6", "pass"), "f60": ("6.0", "pass"), "f55": ("5.5", "violation"),
                "c30": ("30", "pass"), "qc30": ("30", "pass"), "f599": ("5.99", "violation"), "zero": ("0", "violation")}
        for job, got in want.items():
            with self.subTest(job=job):
                self.assertEqual(rows[(".github/workflows/lit.yml", job)], got)

    def test_expression_is_a_violation_unless_exempted(self):
        path = ".github/workflows/expr.yml"
        head = self.repo.case({path: wf("  call:\n    runs-on: x\n    timeout-minutes: %s  # caller decides\n" % EXPR)})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 1), out)
        self.assertEqual(rows[(path, "call")], (EXPR, "violation"))
        self.assertIn("timeout-minutes is an expression, `%s`, which cannot be checked" % EXPR, out)
        ex = {"repo": REPO, "workflow": path, "job": "call", "minutes": EXPR, "reason": "callers pass >= 30",
              "record": "OW-1"}
        code, enforce, out, rows = self.both_modes(head, [ex])
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(path, "call")], (EXPR, "exempt"))
        self.assertIn("- EXEMPT `%s:6` job `call`: timeout-minutes `%s`, exempt by record `OW-1`: `callers pass >= 30`"
                      % (path, EXPR), out)
        self.assertNotIn("STALE", out)

    def test_exemption_for_a_changed_value_is_stale_and_the_job_a_violation(self):
        path = ".github/workflows/expr.yml"
        changed = EXPR.replace("30", "45")
        head = self.repo.case({path: wf("  call:\n    runs-on: x\n    timeout-minutes: %s\n" % changed)})
        ex = {"repo": REPO, "workflow": path, "job": "call", "minutes": EXPR, "reason": "r", "record": "OW-1"}
        other_repo = dict(ex, repo="vagarylabs/other")
        gone = dict(ex, job="removed")
        code, enforce, out, rows = self.both_modes(head, [ex, other_repo, gone])
        self.assertEqual((code, enforce), (0, 1), out)
        self.assertEqual(rows[(path, "call")], (changed, "violation"))
        self.assertIn("- STALE EXEMPTION job `call` in `%s` declaring `%s` (record `OW-1`): the job now declares `%s`"
                      % (path, EXPR, changed), out)
        self.assertIn("- STALE EXEMPTION job `removed`", out)
        self.assertIn("no such job in the head tree's workflows", out)
        self.assertEqual(out.count("- STALE EXEMPTION"), 2)  # another repo's exemption is not this repo's to judge
        self.assertIn("::warning title=timeout floor stale exemption::", out)

    def test_exemption_on_a_passing_job_is_stale(self):
        path = ".github/workflows/ok.yml"
        head = self.repo.case({path: wf("  long:\n    runs-on: x\n    timeout-minutes: 30\n")})
        ex = {"repo": REPO, "workflow": path, "job": "long", "minutes": "30", "reason": "r", "record": "OW-2"}
        code, enforce, out, rows = self.both_modes(head, [ex])
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(path, "long")], ("30", "pass"))
        self.assertIn("the job passes without it", out)

    def test_reusable_workflow_call_is_skipped(self):
        path = ".github/workflows/caller.yml"
        head = self.repo.case({path: wf("  call:\n    uses: ./.github/workflows/reusable.yml\n    with:\n"
                                        "      timeout-minutes: 2\n")})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(path, "call")], ("n/a", "skipped-reusable"))

    def test_step_level_timeouts_are_ignored(self):
        path = ".github/workflows/steps.yml"
        head = self.repo.case({path: wf(
            "  indented:\n    runs-on: x\n    steps:\n      - run: a\n        timeout-minutes: 2\n"
            # `steps:` and its entries at one indentation: an entry's key is never a job key.
            "  compact:\n    runs-on: x\n    steps:\n    - timeout-minutes: 1\n      run: a\n    - name: b\n"
            "      timeout-minutes: 2\n"
            "  both:\n    runs-on: x\n    steps:\n    - timeout-minutes: 1\n    timeout-minutes: 10\n")})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(path, "indented")], ("default 360", "pass"))
        self.assertEqual(rows[(path, "compact")], ("default 360", "pass"))
        self.assertEqual(rows[(path, "both")], ("10", "pass"))

    def test_block_scalars_and_continuations_never_yield_job_keys(self):
        path = ".github/workflows/blocks.yml"
        text = (
            "name: w\n"
            # A jobs block inside a top-level block scalar is text, not a second `jobs:`.
            "run-name: |\n"
            "    jobs:\n"
            "      fake:\n"
            "        timeout-minutes: 1\n"
            "on: push\n"
            "jobs:\n"
            "  a:\n"
            "    runs-on: x\n"
            "    if: |\n"
            "     timeout-minutes: 1\n"
            "\n"
            "     timeout-minutes: 2\n"
            "    steps:\n"
            "      - run: |\n"
            "          cat <<'EOF'\n"
            "          timeout-minutes: 1\n"
            "          EOF\n"
            "      - run: |2\n"
            "            timeout-minutes: 1\n"
            "          timeout-minutes: 1\n"
            # A tab after the body's indentation and a body line opening a quote it never closes are shell, not YAML,
            # also as the first line of a body.
            "      - run: |\n"
            "          'a quote opened at the start of a body line\n"
            "          cat <<-EOF\n"
            "          \tTAB-indented heredoc body\n"
            "          EOF\n"
            "      - run: |\n"
            "          \tTAB-indented first body line\n"
            "      - run: echo \"[ unbalanced\n"
            "    timeout-minutes: 7\n"
            "  b:\n"
            "    runs-on: x\n"
            "    name: a long name\n"
            "      and timeout-minutes 1\n"
            "    env:\n"
            "      DOC: >-\n"
            "        timeout-minutes: 1\n"
            "      LIST: [a,\n"
            "        b]\n"
            "      Q: \"it's\n"
            "        timeout-minutes: 1\"\n"
            # After `jobs:` ends, a block scalar body at the job-key indentation belongs to the top-level key.
            "env:\n"
            "  NOTE: |\n"
            "    timeout-minutes: 1\n")
        head = self.repo.case({path: text})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 0), out)
        self.assertEqual(rows[(path, "a")], ("7", "pass"))
        self.assertEqual(rows[(path, "b")], ("default 360", "pass"))
        self.assertEqual(sorted(k for k in rows if k[0] == path), [(path, "a"), (path, "b")])

    def test_unjudgeable_constructs_are_incomplete(self):
        cases = {
            "merge": wf("  a:\n    <<: *defaults\n    runs-on: x\n"),
            "flow-job": wf("  a: {runs-on: x, timeout-minutes: 2}\n"),
            "flow-job-next-line": wf("  a:\n    {runs-on: x, timeout-minutes: 2}\n"),
            "flow-jobs": "on: push\njobs: {a: {runs-on: x, timeout-minutes: 2}}\n",
            "tab": wf("  a:\n    runs-on: x\n\ttimeout-minutes: 2\n"),
            "anchor-job": wf("  a: &base\n    runs-on: x\n    timeout-minutes: 30\n"),
            "alias-job": wf("  b: *base\n"),
            "anchor-timeout": wf("  a:\n    runs-on: x\n    timeout-minutes: &t 30\n"),
            "alias-timeout": wf("  a:\n    runs-on: x\n    timeout-minutes: *t\n"),
            "tag-timeout": wf("  a:\n    runs-on: x\n    timeout-minutes: !!int 30\n"),
            "two-jobs-keys": wf("  a:\n    runs-on: x\n") + "jobs:\n  b:\n    runs-on: x\n",
            "two-documents": wf("  a:\n    runs-on: x\n") + "---\n" + wf("  b:\n    runs-on: x\n"),
            "two-timeouts": wf("  a:\n    timeout-minutes: 30\n    timeout-minutes: 2\n"),
            "value-next-line": wf("  a:\n    timeout-minutes:\n      2\n"),
            "value-continues": wf("  a:\n    timeout-minutes: 3\n      0\n"),
            "block-value": wf("  a:\n    timeout-minutes: |\n      30\n"),
            "escaped-key": wf('  a:\n    "timeout\\u002dminutes": 2\n'),
            "escaped-jobs": 'on: push\n"jo\\x62s":\n  a:\n    timeout-minutes: 2\n',
            "never-closes": wf("  a:\n    runs-on: x\n    env: {A: 1,\n"),
            "swallows-a-job": wf("  a:\n    runs-on: x\n    env: {A: 1,\n  b:\n    timeout-minutes: 2 }\n"),
            "words": wf("  a:\n    timeout-minutes: soon\n"),
            "bad-id": wf('  "bad id":\n    timeout-minutes: 30\n'),
            "same-id": wf("  a:\n    runs-on: x\n  A:\n    runs-on: x\n"),
            "jobs-sequence": "on: push\njobs:\n- a\n",
            "explicit-key": wf("  a:\n    ? timeout-minutes\n    : 2\n"),
        }
        head = self.repo.case({".github/workflows/%s.yml" % k: v for k, v in cases.items()})
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 1), out)
        for name in cases:
            path = ".github/workflows/%s.yml" % name
            with self.subTest(case=name):
                verdicts = {v for (p, _), (_, v) in rows.items() if p == path}
                self.assertEqual(verdicts, {"incomplete"}, [(k, v) for k, v in rows.items() if k[0] == path])
        self.assertEqual(rows[BASE_ROW[:2]], BASE_ROW[2:])
        self.assertIn("- INCOMPLETE `.github/workflows/tab.yml:4` job `a`: line 6: a tab in the indentation", out)
        self.assertNotIn("All ", out)


class FileTests(FloorCase):
    def test_every_workflow_file_and_only_those(self):
        head = self.repo.case({
            ".github/workflows/a.yml": wf("  one:\n    runs-on: x\n    timeout-minutes: 5\n"),
            ".github/workflows/b.yaml": wf("  two:\n    runs-on: x\n    timeout-minutes: 4\n"),
            ".github/workflows/sub/c.yml": wf("  three:\n    timeout-minutes: 1\n"),
            ".github/workflows/notes.md": "timeout-minutes: 1\n",
            "ci/d.yml": wf("  four:\n    timeout-minutes: 1\n"),
            ".github/workflows/no-jobs.yml": "name: config only\nfoo: bar\n",
        })
        code, out = self.run_floor(head)
        rows = self.rows(out)
        self.assertEqual(sorted(rows), sorted([(".github/workflows/a.yml", "one"), (".github/workflows/b.yaml", "two"),
                                               BASE_ROW[:2]]))
        self.assertEqual(rows[(".github/workflows/b.yaml", "two")], ("4", "violation"))
        self.assertIn("- No `jobs:` in `.github/workflows/no-jobs.yml`: no job to judge", out)
        self.assertIn("in the 4 workflow files of head", out)

    def test_tsv_block_is_one_row_per_job_in_tree_order(self):
        head = self.repo.case({
            ".github/workflows/a.yml": wf("  z:\n    timeout-minutes: 5\n  y:\n    uses: o/r/.github/workflows/x.yml@v1\n"),
            ".github/workflows/b.yml": wf("  x:\n    timeout-minutes: %s\n" % EXPR),
        })
        out = self.run_floor(head)[1]
        block = out[out.index("```tsv\n"):]
        self.assertEqual(block.split("\n")[:6], [
            "```tsv",
            "repo\tworkflow_path\tjob_key\ttimeout_minutes_declared\tverdict",
            "%s\t.github/workflows/a.yml\tz\t5\tviolation" % SHORT,
            "%s\t.github/workflows/a.yml\ty\tn/a\tskipped-reusable" % SHORT,
            "%s\t.github/workflows/b.yml\tx\t%s\tviolation" % (SHORT, EXPR),
            "%s\t.github/workflows/ci.yml\ttest\tdefault 360\tpass" % SHORT,
        ])
        self.assertEqual(block.split("\n")[6], "```")

    def test_tsv_repo_column_is_the_census_short_name(self):
        # execnode's census writes .github, vagary-core, vagaris: the owner is dropped there and here, kept in the heading.
        head = self.repo.case({".github/workflows/a.yml": wf("  a:\n    timeout-minutes: 5\n")})
        for repo, short in (("vagarylabs/.github", ".github"), ("vagarylabs/vagary-core", "vagary-core"), (REPO, SHORT)):
            with self.subTest(repo=repo):
                out = self.run_floor(head, repo=repo)[1]
                self.assertIn("## Timeout floor: %s\n" % repo, out)
                self.assertEqual(self.rows(out, short)[(".github/workflows/a.yml", "a")], ("5", "violation"))
                self.assertNotIn("\n%s\t" % repo, out)

    def test_line_breaks_other_than_lf_are_incomplete(self):
        # YAML (and PyYAML) also break lines at a lone CR, NEL, LS and PS: "runs-on: x<CR>    timeout-minutes: 2" is a
        # timeout of 2 there. The reader splits on LF only, so each makes the whole file INCOMPLETE, never a pass.
        breaks = {"cr": "\r", "nel": "\x85", "ls": "\u2028", "ps": "\u2029"}
        files = {".github/workflows/%s.yml" % k: wf("  a:\n    runs-on: x%s    timeout-minutes: 2\n" % b)
                 for k, b in breaks.items()}
        files[".github/workflows/cr-only.yml"] = "name: w\ron: push\rjobs:\r  a:\r    timeout-minutes: 2\r"
        files[".github/workflows/crlf.yml"] = wf("  a:\n    runs-on: x\n    timeout-minutes: 2\n").replace("\n", "\r\n")
        head = self.repo.case(files)
        code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 1), out)
        for k in breaks:
            with self.subTest(line_break=k):
                path = ".github/workflows/%s.yml" % k
                # The timeout sits inside the runs-on line here, so the job reads as having none: INCOMPLETE, not PASS.
                self.assertEqual(rows[(path, "a")], ("default 360", "incomplete"))
                self.assertIn("- INCOMPLETE `%s:4` job `a`: line 5: a line break other than LF or CRLF" % path, out)
        # A CR-only file is one line here: no job, but its row is INCOMPLETE and counted.
        self.assertEqual(rows[(".github/workflows/cr-only.yml", "*")], ("unknown", "incomplete"))
        self.assertIn("5 INCOMPLETE", out)
        # The control: CRLF is an ordinary line break, judged as usual.
        self.assertEqual(rows[(".github/workflows/crlf.yml", "a")], ("2", "violation"))

    def test_crlf_bom_comments_and_quoted_keys(self):
        text = ("\ufeffname: w\r\non: push\r\njobs: # all of them\r\n# a comment at column 0\r\n  \"quoted\":\r\n"
                "      # an odd comment\r\n    'timeout-minutes' : 7 # minutes\r\n    runs-on: x\r\n"
                "  plain:\r\n    TIMEOUT-MINUTES: 3\r\n")
        head = self.repo.case({".github/workflows/crlf.yml": text})
        rows = self.rows(self.run_floor(head)[1])
        self.assertEqual(rows[(".github/workflows/crlf.yml", "quoted")], ("7", "pass"))
        # Keys compare case-insensitively: that can only add a finding, never hide one.
        self.assertEqual(rows[(".github/workflows/crlf.yml", "plain")], ("3", "violation"))

    def test_symlink_and_oversized_files_are_incomplete(self):
        d = self.repo.d
        git(d, "checkout", "-q", "-b", "links", self.repo.base)
        pathlib.Path(d, ".github/workflows/big.yml").write_text(wf("  a:\n    timeout-minutes: 30\n" + "# pad\n" * 50))
        os.symlink("ci.yml", os.path.join(d, ".github/workflows/link.yml"))
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "links")
        head = git(d, "rev-parse", "HEAD")
        with mock.patch.object(classify, "FLOOR_MAX_BLOB_BYTES", 200):
            code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 1), out)
        self.assertEqual(rows[(".github/workflows/link.yml", "*")], ("unknown", "incomplete"))
        self.assertEqual(rows[(".github/workflows/big.yml", "*")], ("unknown", "incomplete"))
        self.assertIn("larger than 200 bytes, not read", out)
        self.assertEqual(rows[BASE_ROW[:2]], BASE_ROW[2:])

    def test_budget_exhaustion_is_incomplete_never_a_pass(self):
        head = self.repo.case({".github/workflows/a.yml": wf("  a:\n    timeout-minutes: 30\n")})
        with mock.patch.object(classify, "FLOOR_DEADLINE_SECONDS", 0):
            code, enforce, out, rows = self.both_modes(head)
        self.assertEqual((code, enforce), (0, 1), out)
        self.assertIn("- INCOMPLETE: the 0s scan budget ran out; no workflow file was judged", out)
        self.assertEqual(rows, {})
        self.assertNotIn("All ", out)
        with mock.patch.object(classify, "FLOOR_MAX_JOBS", 1):
            code, out = self.run_floor(head, "enforce")
        self.assertEqual(code, 1, out)
        self.assertIn("the 1-job cap was reached after 1 of 2 workflow files", out)

    def test_annotations_are_capped_with_a_pointer(self):
        head = self.repo.case({".github/workflows/many.yml": wf("".join(
            "  j%d:\n    timeout-minutes: 5%%\n" % i for i in range(12)))})
        out = self.run_floor(head)[1]
        self.assertEqual(out.count("::warning file="), classify.FLOOR_MAX_ANNOTATIONS)
        self.assertIn("::warning title=timeout floor::4 more in the job summary", out)
        self.assertIn("timeout-minutes `5%` is neither a number nor an expression", out)
        self.assertIn("timeout-minutes `5%25` is neither", out)  # annotation data is escaped

    def test_integrity_errors_exit_2(self):
        head = self.repo.case({".github/workflows/a.yml": wf("  a:\n    timeout-minutes: 30\n")})
        for bad in ("HEAD", "f" * 40):
            with self.subTest(sha=bad):
                self.assertEqual(self.run_floor(bad)[0], 2)
        self.assertEqual(self.run_floor(head, base="main")[0], 2)
        out = io.StringIO()
        p = pathlib.Path(self.tmp.name, "broken.json")
        p.write_text(json.dumps(dict(json.loads(MANIFEST.read_text()), timeout_floor={"minutes": 0})))
        with contextlib.redirect_stdout(out):
            code = classify.main(["timeout-floor", "--manifest", str(p), "--repo", REPO, "--base", self.repo.base,
                                  "--head", head])
        self.assertEqual(code, 2, out.getvalue())
        # The other modes still need a base.
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(classify.main(["integrity", "--manifest", str(MANIFEST), "--repo", REPO, "--head", head]), 2)

    def test_reads_the_head_alone_the_base_is_never_resolved(self):
        head = self.repo.case({".github/workflows/a.yml": wf("  a:\n    timeout-minutes: 5\n")})
        absent = "e" * 40
        for base in (absent, False):
            with self.subTest(base=base):
                code, out = self.run_floor(head, "enforce", base=base)
                self.assertEqual(code, 1, out)  # judged: the violation refuses, no integrity error
                self.assertEqual(self.rows(out)[(".github/workflows/a.yml", "a")], ("5", "violation"))

    def test_works_in_a_depth_1_clone_without_the_base(self):
        # What the job checks out: the head commit alone (fetch-depth 1). The base is not in that object store.
        head = self.repo.case({".github/workflows/a.yml": wf("  a:\n    timeout-minutes: 30\n")})
        with tempfile.TemporaryDirectory() as d:
            clone = os.path.join(d, "clone")
            git(d, "clone", "-q", "--depth", "1", "--branch", "case-%d" % self.repo.n, "file://" + self.repo.d, clone)
            self.assertEqual(git(clone, "rev-parse", "HEAD"), head)
            for where, present in ((self.repo.d, True), (clone, False)):  # the positive control, then the clone
                r = subprocess.run(["git", "cat-file", "-e", self.repo.base + "^{commit}"], cwd=where, capture_output=True)
                self.assertEqual(r.returncode == 0, present, where)
            code, out = self.run_floor(head, "enforce", cwd=clone)
            self.assertEqual(code, 0, out)
            rows = self.rows(out)
            self.assertEqual(rows[(".github/workflows/a.yml", "a")], ("30", "pass"))
            self.assertEqual(rows[BASE_ROW[:2]], BASE_ROW[2:])


class ParserTests(unittest.TestCase):
    def test_this_repositorys_workflows_are_all_judged(self):
        # The trusted workflows carry this classifier in a block scalar, the hardest real input at hand.
        files = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        self.assertTrue(files)
        total = 0
        for f in files:
            with self.subTest(workflow=f.name):
                jobs, bad = classify.parse_workflow(f.read_text())
                self.assertEqual(bad, [])
                self.assertTrue(jobs)
                self.assertEqual([j["reasons"] for j in jobs if j["reasons"]], [])
                total += len(jobs)
        integrity = classify.parse_workflow((ROOT / ".github/workflows/trusted-workflow-integrity.yml").read_text())[0]
        self.assertEqual([(j["id"], classify._floor_declared(j["timeout"])[0]) for j in integrity],
                         [("trusted-workflow-integrity", "10"), ("timeout-floor", "10")])

    def test_source_is_ascii(self):
        # Inlined into a YAML run block: a literal BOM or other invisible character there is a hazard, so escapes only.
        self.assertTrue((ROOT / "trusted" / "classify.py").read_text().isascii())

    def test_flow_scan(self):
        self.assertIsNone(classify._flow_scan('"a # b" # c', (None, 0, True)))
        self.assertIsNone(classify._flow_scan("'it''s'", (None, 0, True)))
        self.assertIsNone(classify._flow_scan("[a, 'b]', {c: \"d]\"}]", (None, 0, True)))
        self.assertEqual(classify._flow_scan("[a, b # ]", (None, 0, True)), (None, 1, False))
        self.assertEqual(classify._flow_scan('"a \\', (None, 0, True))[0], '"')
        self.assertIsNone(classify._flow_scan("  b] # x", (None, 1, True)))


class ManifestTests(unittest.TestCase):
    def manifest(self, tf):
        m = json.loads(MANIFEST.read_text())
        m["timeout_floor"] = tf
        return m

    def test_the_manifest_floor_is_six_minutes_report_only(self):
        tf = classify.validate_manifest(json.loads(MANIFEST.read_text()))["timeout_floor"]
        self.assertEqual((tf["minutes"], tf["mode"]), (6, "report"))
        # The exemption list is pinned: a new exemption is a reviewed change to this test, never a quiet manifest edit.
        # The only two are secret-scan.yml's input-driven timeouts, each held by the guard test its reason names.
        self.assertEqual(sorted((e["repo"], e["workflow"], e["job"], e["minutes"]) for e in tf["exemptions"]),
                         [("vagarylabs/.github", ".github/workflows/secret-scan.yml", job,
                           "$" + "{{ inputs.timeout-minutes }}") for job in ("gitleaks", "trufflehog")])
        for e in tf["exemptions"]:
            self.assertIn("test_secret_scan_timeout_floor.py SecretScanTimeoutInput", e["reason"])

    def test_rejects_malformed_timeout_floor(self):
        ok = {"repo": REPO, "workflow": ".github/workflows/x.yml", "job": "a", "minutes": EXPR, "reason": "r",
              "record": "OW-1"}
        classify.validate_manifest(self.manifest({"minutes": 6, "mode": "enforce", "exemptions": [ok]}))
        bad = [None, [], {"mode": "report", "exemptions": []}]
        bad += [{"minutes": v, "mode": "report", "exemptions": []} for v in (0, -1, True, "6", 6.5, None)]
        bad += [{"minutes": 6, "mode": v, "exemptions": []} for v in ("warn", None, "REPORT")]
        bad += [{"minutes": 6, "mode": "report", "exemptions": v} for v in (None, {}, "x")]
        bad += [{"minutes": 6, "mode": "report", "exemptions": [v]} for v in (
            "x", dict(ok, repo=""), dict(ok, minutes=30), dict(ok, reason=" "), {k: ok[k] for k in ok if k != "record"},
            dict(ok, workflow="ci.yml"), dict(ok, workflow=".github/workflows/sub/x.yml"),
            dict(ok, workflow=".github/workflows/x.json"))]
        for tf in bad:
            with self.subTest(timeout_floor=tf), self.assertRaises(classify.IntegrityError):
                classify.validate_manifest(self.manifest(tf))
        m = json.loads(MANIFEST.read_text())
        del m["timeout_floor"]
        with self.assertRaises(classify.IntegrityError):
            classify.validate_manifest(m)

    def test_no_expression_is_ever_inlined(self):
        # The manifest is inlined into a run block, where Actions would expand an expression: an exemption for one
        # writes its $ as \u0024, and render.py refuses anything else.
        self.assertNotIn("$" + "{{", MANIFEST.read_text())
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "m.json").write_text('{"minutes": "%s"}\n' % EXPR)
            with mock.patch.object(render, "ROOT", pathlib.Path(d)):
                with self.assertRaises(SystemExit):
                    render.render("          {{INLINE:m.json}}\n")
            escaped = '{"minutes": "\\u0024{{ inputs.minutes || 30 }}"}\n'
            self.assertEqual(json.loads(escaped)["minutes"], EXPR)
            pathlib.Path(d, "m.json").write_text(escaped)
            with mock.patch.object(render, "ROOT", pathlib.Path(d)):
                self.assertIn("\\u0024{{", render.render("          {{INLINE:m.json}}\n"))


class WorkflowTests(unittest.TestCase):
    def test_timeout_floor_job_mirrors_the_integrity_job(self):
        text = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        integrity = text[text.index("\n  trusted-workflow-integrity:\n"):text.index("\n  timeout-floor:\n")]
        floor = text[text.index("\n  timeout-floor:\n"):]
        for job in (integrity, floor):
            self.assertIn("\n    if: github.repository != 'vagarylabs/.github'\n", job)
            self.assertIn("\n    runs-on: [self-hosted, Linux, X64, vl-light]\n    timeout-minutes: 10\n", job)
            self.assertIn("persist-credentials: false", job)
            self.assertIn("PR_HEAD: ${{ github.event.pull_request.head.sha }}", job)
            self.assertNotIn("\n    permissions:", job)
        # The integrity job keeps the full history and the merge-base; the floor job reads the head tree only, so it
        # checks out the head commit alone and never binds a merge-base.
        self.assertIn("fetch-depth: 0", integrity)
        self.assertIn("merge_base=", integrity)
        self.assertIn("ref: ${{ steps.shas.outputs.head }}\n          fetch-depth: 1\n          persist-credentials: false",
                      floor)
        self.assertNotIn("fetch-depth: 0", floor)
        self.assertNotIn("merge-base", floor.split("TRUSTED_CLASSIFY_PY", 1)[0])
        self.assertIn('python3 -I "$d/classify.py" integrity --manifest', integrity)
        self.assertNotIn("timeout-floor --manifest", integrity)
        self.assertIn('python3 -I "$d/classify.py" timeout-floor --manifest "$d/manifest.json"', floor)


class WeakeningFloorTests(unittest.TestCase):
    """FL-4: a timeout-minutes raise to at most the floor is a floor raise; above it, still a weakening."""

    @classmethod
    def setUpClass(cls):
        cls.repo = Repo()

    @classmethod
    def tearDownClass(cls):
        cls.repo.tmp.cleanup()

    def raise_to(self, new, branch):
        path = ".github/workflows/gate.yml"
        text = wf("  gate:\n    runs-on: x\n    timeout-minutes: %s\n    steps:\n      - run: a\n"
                  "        timeout-minutes: %s\n")
        before = self.repo.case({path: text % (2, 1)})
        d = self.repo.d
        git(d, "checkout", "-q", "-b", branch, before)
        pathlib.Path(d, path).write_text(text % (new, 1))
        git(d, "commit", "-q", "-am", "raise")
        return before, git(d, "rev-parse", "HEAD")

    def scan(self, base, head, floor):
        cwd = os.getcwd()
        try:
            os.chdir(self.repo.d)
            return classify.weakening_scan(base, head, floor)
        finally:
            os.chdir(cwd)

    def test_raise_to_the_floor_is_tagged_not_weakening(self):
        base, head = self.raise_to(6, "to-floor")
        got, incomplete, _ = self.scan(base, head, 6)
        self.assertEqual(incomplete, [])
        self.assertEqual([(f["rule"], f["effect"], f["detail"]) for f in got], [
            (classify.FLOOR_RAISE_RULE, "ci-policy:completion-floor",
             "raises timeout `timeout-minutes` 2 -> 6, raised to the completion floor (6 minutes)")])
        # Without a floor the same raise is a weakening: the tag comes from the floor alone.
        self.assertEqual([f["rule"] for f in self.scan(base, head, None)[0]], ["budget-loosened"])
        out = io.StringIO()
        cwd = os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        try:
            os.chdir(self.repo.d)
            with contextlib.redirect_stdout(out):
                code = classify.main(["integrity", "--manifest", str(MANIFEST), "--repo", REPO, "--base", base,
                                      "--head", head])
        finally:
            os.chdir(cwd)
        out = out.getvalue()
        self.assertEqual(code, 0, out)
        self.assertIn("- FLOOR RAISE `.github/workflows/gate.yml:6` raises timeout `timeout-minutes` 2 -> 6, raised to "
                      "the completion floor (6 minutes); not a test weakening", out)
        self.assertNotIn("- WEAKENING", out)
        self.assertNotIn("::warning", out)
        self.assertIn("No test-weakening pattern added", out)

    def test_raise_toward_the_floor_is_not_called_meeting_it(self):
        base, head = self.raise_to(4, "toward-floor")
        got, incomplete, _ = self.scan(base, head, 6)
        self.assertEqual(incomplete, [])
        self.assertEqual([(f["rule"], f["detail"]) for f in got], [
            (classify.FLOOR_RAISE_RULE, "raises timeout `timeout-minutes` 2 -> 4, raised toward the completion floor "
                                        "(6 minutes), still under it")])
        self.assertNotIn("raised to the completion floor", got[0]["detail"])

    def test_a_step_raise_to_the_floor_is_still_a_weakening(self):
        # The floor is per job: a pytest step's own timeout raised 1 -> 6 loosens that step, it meets no floor.
        d = self.repo.d
        path = ".github/workflows/gate.yml"
        text = wf("  gate:\n    runs-on: x\n    timeout-minutes: 30\n    steps:\n      - run: pytest\n"
                  "        timeout-minutes: %s\n")
        before = self.repo.case({path: text % 1})
        git(d, "checkout", "-q", "-b", "step-to-floor", before)
        pathlib.Path(d, path).write_text(text % 6)
        git(d, "commit", "-q", "-am", "raise the step")
        got, incomplete, _ = self.scan(before, git(d, "rev-parse", "HEAD"), 6)
        self.assertEqual(incomplete, [])
        self.assertEqual([(f["rule"], f["effect"], f["line"], f["detail"]) for f in got], [
            ("budget-loosened", "ci-policy:test-weakening", 9, "raises timeout `timeout-minutes` 1 -> 6")])

    def test_a_raise_in_a_file_the_reader_cannot_judge_stays_a_weakening(self):
        d = self.repo.d
        path = ".github/workflows/gate.yml"
        text = wf("  gate:\n    <<: *defaults\n    timeout-minutes: %s\n")
        before = self.repo.case({path: text % 2})
        git(d, "checkout", "-q", "-b", "unjudged-raise", before)
        pathlib.Path(d, path).write_text(text % 6)
        git(d, "commit", "-q", "-am", "raise")
        got = self.scan(before, git(d, "rev-parse", "HEAD"), 6)[0]
        self.assertEqual([f["rule"] for f in got], ["budget-loosened"])
        self.assertTrue(all("raise" not in f for f in got))

    def test_raise_past_the_floor_is_still_a_weakening(self):
        base, head = self.raise_to(30, "past-floor")
        got, incomplete, _ = self.scan(base, head, 6)
        self.assertEqual(incomplete, [])
        self.assertEqual([(f["rule"], f["effect"], f["detail"]) for f in got], [
            ("budget-loosened", "ci-policy:test-weakening", "raises timeout `timeout-minutes` 2 -> 30")])

    def test_step_level_raise_and_lowering(self):
        d = self.repo.d
        path = ".github/workflows/gate.yml"
        text = wf("  gate:\n    runs-on: x\n    steps:\n      - run: a\n        timeout-minutes: %s\n")
        before = self.repo.case({path: text % 20})
        git(d, "checkout", "-q", "-b", "step-raise", before)
        pathlib.Path(d, path).write_text(text % 4)
        git(d, "commit", "-q", "-am", "lower")
        self.assertEqual(self.scan(before, git(d, "rev-parse", "HEAD"), 6)[0], [])  # a lower timeout loosens nothing
        git(d, "checkout", "-q", "-b", "step-raise-2", before)
        pathlib.Path(d, path).write_text(text % 40)
        git(d, "commit", "-q", "-am", "raise")
        got = self.scan(before, git(d, "rev-parse", "HEAD"), 6)[0]
        self.assertEqual([f["detail"] for f in got], ["raises timeout `timeout-minutes` 20 -> 40"])


if __name__ == "__main__":
    unittest.main()
