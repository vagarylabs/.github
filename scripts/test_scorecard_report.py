#!/usr/bin/env python3
"""Tests for scripts/scorecard_report.py and the workflow that embeds it. Stdlib only; no network, no token.

  python3 -m unittest discover -s scripts -p 'test_scorecard*.py' -v
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import scorecard_report as sr  # noqa: E402

FIX = os.path.join(HERE, "scorecard_fixtures")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "scorecard-weekly.yml")


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = sr.main(argv)
    return rc, out.getvalue(), err.getvalue()


class Report(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.bulk = os.path.join(self.d, "bulk.json")
        shutil.copy(os.path.join(FIX, "bulk.json"), self.bulk)
        self.rc = os.path.join(self.d, "bulk.rc")
        with open(self.rc, "w") as fh:
            fh.write("0\n")

    def report(self, *extra, result=None, repo="vagarylabs/bulk", rc=True):
        argv = ["report", "--result", result or self.bulk, "--repo", repo, *extra]
        return run(argv + (["--rc", self.rc] if rc else []))

    def test_states_scores_and_reasons_of_the_real_bulk_result(self):
        rc, out, _ = self.report()
        self.assertEqual(rc, 0)
        self.assertIn("vagarylabs/bulk, Scorecard v5.6.0: score 6.7/10.", out)
        self.assertIn("| CII-Best-Practices | 0 | FAIL | no effort to earn an OpenSSF best practices badge detected |", out)
        self.assertIn("| Signed-Releases | - | UNMEASURED | no releases found |", out)  # -1 in the real result
        self.assertIn("| License | 10 | PASS |", out)
        self.assertIn("6 failing (below 5/10), 1 UNMEASURED", out)

    def test_unmeasured_is_never_failing_whatever_the_threshold(self):
        out_json = os.path.join(self.d, "s.json")
        rc, _, _ = self.report("--fail-below", "10", "--json-out", out_json)
        self.assertEqual(rc, 0)
        with open(out_json) as fh:
            s = json.load(fh)
        self.assertEqual(s["unmeasured"], ["Signed-Releases"])
        self.assertNotIn("Signed-Releases", s["failing"])
        self.assertEqual(len(s["failing"]) + len(s["unmeasured"]) + len(s["passing"]), 18)

    def test_a_check_without_a_numeric_score_is_unmeasured(self):
        with open(self.bulk) as fh:
            d = json.load(fh)
        d["checks"][0].pop("score")
        d["checks"][1]["score"] = True  # a bool is not a score
        with open(self.bulk, "w") as fh:
            json.dump(d, fh)
        rows = {r[0]: r[2] for r in sr.classify(d, 5)}
        self.assertEqual((rows["Binary-Artifacts"], rows["Branch-Protection"]), ("UNMEASURED", "UNMEASURED"))

    def test_threshold_moves_the_failing_list(self):
        _, low, _ = self.report("--fail-below", "1")
        _, high, _ = self.report("--fail-below", "10")
        self.assertIn("| Branch-Protection | 3 | PASS |", low)
        self.assertIn("| Branch-Protection | 3 | FAIL |", high)

    def test_a_void_is_a_failure_never_a_pass(self):
        for name, setup, why in (
                ("missing", lambda: os.remove(self.bulk), "no result file"),
                ("junk", lambda: write(self.bulk, "{not json"), "result is not valid JSON"),
                ("noscore", lambda: write(self.bulk, '{"checks": []}'), "result has no score or checks"),
                ("rc", lambda: write(self.rc, "2\n"), "scorecard exited 2"),
                ("norc", lambda: os.remove(self.rc), "no exit status file")):
            with self.subTest(name):
                self.setUp()
                setup()
                out_json = os.path.join(self.d, "s.json")
                rc, out, _ = self.report("--json-out", out_json)
                self.assertEqual(rc, 1)
                self.assertIn(f"vagarylabs/bulk: no usable result ({why}). A void is not a pass.", out)
                with open(out_json) as fh:
                    self.assertEqual(json.load(fh), {"repo": "vagarylabs/bulk", "error": why})

    def test_a_result_for_another_repository_is_refused(self):
        rc, out, _ = self.report(repo="vagarylabs/tldv_downloader")
        self.assertEqual(rc, 1)
        self.assertIn("result names a different repository", out)

    def test_repo_and_threshold_are_validated(self):
        for argv in (("--repo", "bulk"), ("--repo", "vagarylabs/../x"), ("--fail-below", "11")):
            with self.subTest(argv):
                rc, _, err = run(["report", "--result", self.bulk, "--repo", "vagarylabs/bulk", *argv])
                self.assertEqual(rc, 2)
                self.assertIn("--repo must be OWNER/NAME", err)

    def test_summary_file_is_appended_and_cells_are_escaped(self):
        with open(self.bulk) as fh:
            d = json.load(fh)
        d["checks"][0]["reason"] = "a | b " + "x" * 400
        with open(self.bulk, "w") as fh:
            json.dump(d, fh)
        sm = os.path.join(self.d, "summary.md")
        with open(sm, "w") as fh:
            fh.write("existing\n")
        self.report("--summary", sm)
        with open(sm) as fh:
            t = fh.read()
        self.assertTrue(t.startswith("existing\n"))
        line = next(l for l in t.splitlines() if l.startswith("| Binary-Artifacts |"))
        self.assertIn("a \\| b", line)
        self.assertLess(len(line), 220)


class Workflow(unittest.TestCase):
    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.text = fh.read()
        self.lines = self.text.splitlines()

    def test_embedded_helper_is_byte_identical_to_the_script(self):
        start = next(i for i, l in enumerate(self.lines) if "<<'PY'" in l)
        end = next(i for i in range(start + 1, len(self.lines)) if self.lines[i] == "          PY")
        embedded = "\n".join(l[10:] if l.startswith("          ") else l for l in self.lines[start + 1:end]) + "\n"
        with open(os.path.join(HERE, "scorecard_report.py"), encoding="utf-8") as fh:
            self.assertEqual(embedded, fh.read())

    def test_root_u1_scores_only_the_calling_repository_with_its_own_read_token(self):
        # HOST: one repository, the caller's; AUTH: its own GITHUB_TOKEN, contents: read only; no App, no secret.
        self.assertIn("GITHUB_AUTH_TOKEN: ${{ github.token }}", self.text)
        self.assertEqual(re.findall(r"--repo=\"github\.com/\$\{REPO\}\"", self.text), ['--repo="github.com/${REPO}"'])
        self.assertEqual(self.text.count("REPO: ${{ github.repository }}"), 2)
        self.assertNotRegex(self.text, r"(?m)^    secrets:|secrets\.|create-github-app-token|sibling-repo-read|repositories:")
        perms = re.findall(r"(?m)^( *)permissions:[ \t]*\n((?:\1  [a-z-]+:[^\n]*\n)+)", self.text)
        self.assertEqual(len(perms), 2)
        for _, block in perms:
            self.assertEqual(block.split(), ["contents:", "read"])

    def test_maintainer_annotations_never_reach_the_report(self):
        # trusted/tests/test_judge_configs.py classifies scorecard as NOT a judge because the tree's scorecard.yml
        # annotations are shown only with --show-annotations; this workflow must never pass it.
        self.assertNotIn("--show-annotations", self.text)
        self.assertNotIn("annotation", sr.render("o/r", {"score": 1, "checks": [], "scorecard": {}}, "", 5).lower())

    def test_filing_nothing_and_triggered_only_by_a_caller(self):
        self.assertNotRegex(self.text, r"(?m)^\s*(contents|issues|pull-requests|id-token|packages|checks|statuses):\s*write")
        self.assertNotRegex(self.text, r"(?m)^  (pull_request|pull_request_target|push|schedule):")
        self.assertRegex(self.text, r"(?m)^  workflow_call:")
        self.assertNotRegex(self.text, r"gh (issue|pr) |/issues")

    def test_pin_in_workflow_env_equals_release_assets_lock(self):
        env = dict(re.findall(r'^      (SCORECARD_[A-Z0-9]+): "?([^"\n]+)"?$', self.text, re.M))
        with open(os.path.join(ROOT, "release-assets.lock")) as fh:
            lock = [l.split() for l in fh if l.startswith("scorecard ")]
        self.assertEqual(len(lock), 1)
        tool, version, url, sha = lock[0]
        self.assertEqual((env["SCORECARD_VERSION"], env["SCORECARD_URL"], env["SCORECARD_SHA256"]), (version, url, sha))
        self.assertRegex(sha, r"^[0-9a-f]{64}$")
        self.assertTrue(url.startswith("https://github.com/ossf/scorecard/releases/download/v%s/" % version))

    def test_lock_entry_has_its_source_comment(self):
        with open(os.path.join(ROOT, "release-assets.lock")) as fh:
            t = fh.read().splitlines()
        i = next(k for k, l in enumerate(t) if l.startswith("scorecard "))
        self.assertTrue(t[i - 1].startswith("# source: https://github.com/ossf/scorecard/releases/download/v5.6.0/scorecard_checksums.txt"))

    def test_every_uses_is_a_40_hex_sha_with_an_exact_label(self):
        exact = re.compile(r"^v\d+\.\d+\.\d+$")
        internal = re.compile(r"^\.github #\d+ merge$")
        n = 0
        for l in self.lines:
            m = re.match(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*(?:#\s*(.*))?$", l)
            if not m:
                continue
            n += 1
            ref, label = m.group(1), (m.group(2) or "").strip()
            name, _, sha = ref.rpartition("@")
            self.assertRegex(sha, r"^[0-9a-f]{40}$", l)
            self.assertTrue(internal.match(label) if name.startswith("vagarylabs/.github") else exact.match(label), l)
        self.assertGreaterEqual(n, 2)

    def test_no_expression_inside_a_run_block(self):
        in_run, indent = False, 0
        for l in self.lines:
            if in_run:
                if l.strip() and len(l) - len(l.lstrip()) <= indent:
                    in_run = False
                else:
                    self.assertNotIn("${{", l)
                    continue
            m = re.match(r"^(\s*)(?:-\s+)?run:\s*\|", l)
            if m:
                in_run, indent = True, len(m.group(1)) + (2 if l.lstrip().startswith("-") else 0)

    def test_timeouts_meet_the_org_floor(self):
        found = [int(m.group(1)) for m in re.finditer(r"timeout-minutes:\s*(\d+)", self.text)]
        self.assertGreaterEqual(len(found), 3)
        for t in found:
            self.assertGreaterEqual(t, 6)


if __name__ == "__main__":
    unittest.main()
