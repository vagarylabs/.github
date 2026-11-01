"""Tests for open-pr-trial.py, against a real bare origin that holds refs/pull/N/head refs."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("open_pr_trial", HERE / "open-pr-trial.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
ENV = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}, "GIT_CONFIG_GLOBAL": os.devnull,
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@invalid"}


def g(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True, text=True).stdout.strip()


class Trial(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.origin, self.clone, seed = t / "origin.git", t / "clone", t / "seed"
        g(t, "init", "-q", "--bare", "-b", "main", str(self.origin))
        g(t, "init", "-q", "-b", "main", str(seed))
        (seed / "shared.txt").write_text("base\n")
        g(seed, "add", "-A")
        g(seed, "commit", "-q", "-m", "base")
        g(seed, "remote", "add", "origin", str(self.origin))
        g(seed, "push", "-q", "origin", "main")
        base = g(seed, "rev-parse", "HEAD")
        # Three PRs off main: one green, one the gate reds, one that conflicts with the candidate.
        for n, (path, text) in {1: ("ok.txt", "fine\n"), 2: ("RED", "planted\n"), 3: ("shared.txt", "pr-3\n")}.items():
            g(seed, "checkout", "-q", "-B", f"pr-{n}", base)
            (seed / path).write_text(text)
            g(seed, "add", "-A")
            g(seed, "commit", "-q", "-m", f"pr {n}")
            g(seed, "push", "-q", "origin", f"HEAD:refs/pull/{n}/head")
        g(t, "clone", "-q", str(self.origin), str(self.clone))
        # The candidate: the gate's own branch, which also edits shared.txt (so PR 3 conflicts).
        g(self.clone, "checkout", "-q", "-b", "gate")
        (self.clone / "shared.txt").write_text("gate\n")
        g(self.clone, "add", "-A")
        g(self.clone, "commit", "-q", "-m", "the gate")
        self.prs = Path(self.tmp.name) / "prs.json"
        self.prs.write_text(json.dumps([{"number": n, "user": {"login": f"owner{n}"}, "title": f"pr {n}",
                                         "head": {"sha": ""}} for n in (3, 1, 2)]))

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *extra):
        out = Path(self.tmp.name) / "rows.json"
        cmd = 'test ! -e RED && test "$TRIAL_PR" -gt 0 && test -n "$TRIAL_BASE"'
        old = dict(os.environ)
        os.environ.update(ENV)
        try:
            rc = T.main(["--clone", str(self.clone), "--candidate", "gate", "--cmd", cmd, "--prs-json", str(self.prs),
                         "--json", str(out), *extra])
        finally:
            os.environ.clear()
            os.environ.update(old)
        return rc, json.loads(out.read_text())

    def test_each_pr_is_merged_without_a_commit_and_judged(self):
        refs_before = g(self.clone, "for-each-ref")
        head_before = g(self.clone, "rev-parse", "HEAD")
        rc, data = self.run_tool()
        self.assertEqual(rc, 1, "a RED PR makes the run red")
        got = {r["number"]: (r["result"], r["author"]) for r in data["rows"]}
        self.assertEqual(got, {1: ("GREEN", "owner1"), 2: ("RED", "owner2"), 3: ("CONFLICT", "owner3")})
        self.assertEqual(data["candidate"], head_before)
        self.assertIn("shared.txt", next(r for r in data["rows"] if r["number"] == 3)["detail"])
        self.assertEqual(g(self.clone, "for-each-ref"), refs_before, "nothing is written to --clone")
        self.assertEqual(g(self.clone, "rev-parse", "HEAD"), head_before)
        self.assertEqual(g(self.clone, "status", "--porcelain"), "")

    def test_only_and_a_clean_run(self):
        rc, data = self.run_tool("--only", "1,3")
        self.assertEqual(rc, 0, "GREEN and CONFLICT only: a conflict is the PR's own pre-existing work")
        self.assertEqual(sorted(r["number"] for r in data["rows"]), [1, 3])

    def test_an_unfetchable_pr_is_an_error(self):
        self.prs.write_text(json.dumps([{"number": 9, "user": {"login": "x"}, "title": "gone", "head": {"sha": ""}}]))
        rc, data = self.run_tool()
        self.assertEqual((rc, data["rows"][0]["result"]), (1, "ERROR"))

    def test_a_bad_candidate_is_a_usage_error(self):
        self.assertEqual(T.main(["--clone", str(self.clone), "--candidate", "nope", "--cmd", "true",
                                 "--prs-json", str(self.prs)]), 2)


if __name__ == "__main__":
    unittest.main()
