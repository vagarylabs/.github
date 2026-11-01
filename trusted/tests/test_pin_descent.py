"""pin-descent (K2 D8): a test-bounds pin the merge lands moves only forward along .github main.

Real git, no network: a local `.github` source (main c0 -> c1 -> c2, and a side commit s1 main never merged) stands in
for https://github.com/vagarylabs/.github, and a consumer repository holds each case's base and head. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_pin_descent.py' -v
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402

MANIFEST = ROOT / "trusted" / "manifest.json"
WORKFLOW = ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml"


def git(cwd, *args):
    return subprocess.run(("git",) + args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def workflow(*refs, uses="vagarylabs/.github/actions/test-bounds"):
    steps = "".join("      - uses: %s@%s # .github #1 merge\n" % (uses, r) for r in refs)
    return "name: t\non: pull_request\njobs:\n  a:\n    runs-on: x\n    steps:\n" + steps


def manifest(mode="enforce"):
    m = classify.validate_manifest(json.loads(MANIFEST.read_text()))
    m["pin_descent"] = {"mode": mode}
    return m


class PinDescent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        src = cls.src_dir = t / "dotgithub"
        src.mkdir()
        git(src, "init", "-q", "-b", "main")
        git(src, "config", "user.email", "t@example.invalid")
        git(src, "config", "user.name", "t")
        git(src, "config", "uploadpack.allowFilter", "true")
        shas = []
        for i in range(3):
            (src / "check.py").write_text("V = %d\n" % i)
            git(src, "add", "-A")
            git(src, "commit", "-q", "-m", "c%d" % i)
            shas.append(git(src, "rev-parse", "HEAD"))
        cls.c0, cls.c1, cls.c2 = shas
        git(src, "checkout", "-q", "-b", "side", cls.c1)
        (src / "check.py").write_text("V = 'side'\n")
        git(src, "commit", "-q", "-am", "s1")
        cls.s1 = git(src, "rev-parse", "HEAD")
        git(src, "checkout", "-q", "main")
        cls.source = "file://" + str(src)
        cls.nowhere = "file://" + str(t / "no-such-repo")
        c = cls.consumer = t / "consumer"
        c.mkdir()
        git(c, "init", "-q", "-b", "main")
        git(c, "config", "user.email", "t@example.invalid")
        git(c, "config", "user.name", "t")
        (c / "README.md").write_text("r\n")
        git(c, "add", "-A")
        git(c, "commit", "-q", "-m", "root")
        cls.root = git(c, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def commit(self, parent, files):
        """A consumer commit on parent: files maps a path to its text, or to None to delete it."""
        c = self.consumer
        git(c, "checkout", "-q", "--detach", parent)
        for path, text in files.items():
            p = c / path
            if text is None:
                p.unlink()
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
        git(c, "add", "-A")
        git(c, "commit", "-q", "--allow-empty", "-m", "c")
        return git(c, "rev-parse", "HEAD")

    def judge(self, base, head, mode="enforce", source=None, event="pull_request", live=None):
        """On pull_request the base branch's live tip is origin/main in the checkout: `live`, or the event's base."""
        out = io.StringIO()
        cwd = os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        git(self.consumer, "update-ref", "refs/remotes/origin/main", live or base)
        try:
            os.chdir(self.consumer)
            with contextlib.redirect_stdout(out):
                code = classify.run_pin_descent(manifest(mode), "vagarylabs/consumer", base, head, event,
                                                "main" if event == "pull_request" else None,
                                                source=source or self.source)
        finally:
            os.chdir(cwd)
        return code, out.getvalue()

    def pr(self, base_files, head_files, source=None, mode="enforce"):
        """A base with base_files, and a PR head on it that applies head_files."""
        base = self.commit(self.root, base_files)
        return self.judge(base, self.commit(base, head_files), mode, source)

    F = ".github/workflows/f.yml"
    G = ".github/workflows/g.yml"

    # --- the five root planted ---

    def test_a_backward_pin_is_refused(self):
        code, out = self.pr({self.F: workflow(self.c2)}, {self.F: workflow(self.c1)})
        self.assertEqual(code, 1, out)
        self.assertIn("does not descend from the base pin(s) `%s`" % self.c2, out)
        self.assertIn("::error file=%s,line=7,title=test-bounds pin::" % self.F, out)

    def test_a_pin_main_never_merged_is_refused(self):
        code, out = self.pr({self.F: workflow(self.c1)}, {self.F: workflow(self.s1)})
        self.assertEqual(code, 1, out)
        self.assertIn("is not on .github main", out)

    def test_an_added_pin_on_main_passes_after_the_fetch(self):
        code, out = self.pr({}, {self.F: workflow(self.c1)})
        self.assertEqual(code, 0, out)
        self.assertIn(".github main is at `%s` (3 commits" % self.c2, out)
        self.assertIn("the base runs no test-bounds pin; the merge lands 1 test-bounds pin, 1 of them new.", out)

    def test_an_added_pin_main_never_merged_is_refused(self):
        code, out = self.pr({}, {self.F: workflow(self.s1)})
        self.assertEqual(code, 1, out)
        self.assertIn("is not on .github main", out)

    def test_a_removed_pin_passes_and_fetches_nothing(self):
        code, out = self.pr({self.F: workflow(self.c1)}, {self.F: None}, source=self.nowhere)
        self.assertEqual(code, 0, out)
        self.assertIn("nothing fetched, nothing to judge", out)

    def test_a_fetch_failure_on_a_pin_changing_pr_is_red_and_names_both_attempts(self):
        with mock.patch.object(classify, "_pd_pause") as pause:
            code, out = self.pr({self.F: workflow(self.c1)}, {self.F: workflow(self.c2)}, source=self.nowhere)
        self.assertEqual(code, 1, out)
        self.assertIn("INCOMPLETE: .github main could not be read (attempt 1: git clone exit", out)
        self.assertIn("; attempt 2: git clone exit", out)
        self.assertIn("::error title=test-bounds pin::INCOMPLETE", out)
        pause.assert_called_once_with(classify.PD_RETRY_PAUSE_SECONDS)

    # --- the rest of the class ---

    def test_a_forward_pin_passes(self):
        code, out = self.pr({self.F: workflow(self.c0)}, {self.F: workflow(self.c2)})
        self.assertEqual(code, 0, out)
        self.assertIn("descends from every pin the base runs", out)

    def test_a_pr_that_leaves_the_pin_alone_fetches_nothing(self):
        code, out = self.pr({self.F: workflow(self.c1)}, {"README.md": "changed\n", self.G: "name: g\n"},
                            source=self.nowhere)
        self.assertEqual(code, 0, out)
        self.assertIn("nothing fetched", out)

    def test_a_pin_the_pr_never_touched_is_judged_as_the_merge_lands_it(self):
        # The PR branched when g.yml pinned c0; main has since moved it to c1. The PR adds f.yml at c2 and never
        # touches g.yml, so its head still reads c0 there. The merge lands c1 in g.yml, so only c2 is new.
        mb = self.commit(self.root, {self.G: workflow(self.c0)})
        base = self.commit(mb, {self.G: workflow(self.c1)})
        head = self.commit(mb, {self.F: workflow(self.c2)})
        code, out = self.judge(base, head)
        self.assertEqual(code, 0, out)
        self.assertIn("the merge lands 2 test-bounds pins, 1 of them new", out)

    def test_pull_request_judges_the_live_base_not_the_events(self):
        # The event's base b0 pinned c0; main has since moved that pin to c2 (b1). The PR, branched from b0, adds a
        # workflow at c1. Against the stale b0 that is forward (c0 -> c1) and would pass; against the live tip it lands
        # beside c2 and does not descend from it, so it is refused.
        b0 = self.commit(self.root, {self.F: workflow(self.c0)})
        b1 = self.commit(b0, {self.F: workflow(self.c2)})
        head = self.commit(b0, {self.G: workflow(self.c1)})
        code, out = self.judge(b0, head, live=b1)
        self.assertEqual(code, 1, out)
        self.assertIn("Judged: the live tip `%s` of `main` (the event's base `%s` is its ancestor)" % (b1, b0), out)
        self.assertIn("does not descend from the base pin(s) `%s`" % self.c2, out)
        self.assertEqual(self.judge(b0, head, live=b0)[0], 0)

    def test_merge_group_judges_the_group_commit_itself(self):
        base = self.commit(self.root, {self.F: workflow(self.c1)})
        group = self.commit(base, {self.F: workflow(self.c0)})
        code, out = self.judge(base, group, event="merge_group")
        self.assertEqual(code, 1, out)
        self.assertIn("against the group commit `%s`'s own tree" % group, out)
        forward = self.commit(base, {self.F: workflow(self.c2)})
        self.assertEqual(self.judge(base, forward, event="merge_group")[0], 0)
        # a group whose base is not its ancestor is refused before any pin is read
        stray = self.commit(self.root, {"README.md": "stray\n"})
        with self.assertRaises(classify.IntegrityError):
            self.judge(base, stray, event="merge_group")

    def test_a_new_pin_must_descend_from_every_base_pin(self):
        code, out = self.pr({self.F: workflow(self.c0), self.G: workflow(self.c2)}, {self.F: workflow(self.c1)})
        self.assertEqual(code, 1, out)
        self.assertIn("does not descend from the base pin(s) `%s`" % self.c2, out)
        self.assertNotIn("`%s`, `%s`" % (self.c0, self.c2), out.split("REFUSED", 1)[1])

    def test_a_ref_that_is_not_an_exact_commit_is_refused_without_a_fetch(self):
        for ref in ("main", "v1", self.c2[:12]):
            with self.subTest(ref=ref):
                code, out = self.pr({self.F: workflow(self.c1)}, {self.F: workflow(ref)}, source=self.nowhere)
                self.assertEqual(code, 1, out)
                self.assertIn("is not an exact commit", out)
                self.assertNotIn("INCOMPLETE", out)

    def test_the_owner_matches_case_insensitively_and_an_uppercase_sha_is_read(self):
        code, out = self.pr({self.F: workflow(self.c2)},
                            {self.F: workflow(self.c1.upper(), uses="VagaryLabs/.GitHub/actions/test-bounds")})
        self.assertEqual(code, 1, out)
        self.assertIn("does not descend", out)

    def test_a_pin_this_reader_cannot_read_is_refused_never_skipped(self):
        for line in ("      - { uses: vagarylabs/.github/actions/test-bounds@%s }\n" % self.c0,
                     "x: &tb vagarylabs/.github/actions/test-bounds@%s\n" % self.c0,
                     "      - uses: >-\n          vagarylabs/.github/actions/test-bounds@%s\n" % self.c0):
            with self.subTest(line=line):
                code, out = self.pr({self.F: workflow(self.c2)}, {self.G: line}, source=self.nowhere)
                self.assertEqual(code, 1, out)
                self.assertIn("is not a plain `uses:` line", out)

    def test_the_same_unreadable_line_in_the_base_is_not_new(self):
        line = "x: &tb vagarylabs/.github/actions/test-bounds@%s\n" % self.c0
        code, out = self.pr({self.G: line}, {"README.md": "x\n"}, source=self.nowhere)
        self.assertEqual(code, 0, out)

    def test_a_commented_pin_is_not_a_pin(self):
        code, out = self.pr({self.F: workflow(self.c2)},
                            {self.G: "# was: vagarylabs/.github/actions/test-bounds@%s\n" % self.c0},
                            source=self.nowhere)
        self.assertEqual(code, 0, out)

    def test_a_composite_action_pin_is_read(self):
        code, out = self.pr({self.F: workflow(self.c2)},
                            {"actions/x/action.yml": "runs:\n  using: composite\n  steps:\n"
                             "    - uses: vagarylabs/.github/actions/test-bounds@%s\n" % self.c1})
        self.assertEqual(code, 1, out)
        self.assertIn("actions/x/action.yml:4", out)

    def test_a_base_pin_off_main_refuses_every_new_pin(self):
        code, out = self.pr({self.F: workflow(self.s1)}, {self.F: workflow(self.c2)})
        self.assertEqual(code, 1, out)
        self.assertIn("cannot be judged against the base pin(s) `%s`" % self.s1, out)

    def test_report_mode_lists_and_passes(self):
        code, out = self.pr({self.F: workflow(self.c2)}, {self.F: workflow(self.c1)}, mode="report")
        self.assertEqual(code, 0, out)
        self.assertIn("::warning file=%s,line=7,title=test-bounds pin::" % self.F, out)
        self.assertIn("Report-only", out)

    def test_the_retry_recovers_a_first_attempt_that_failed(self):
        # The source appears during the pause between the attempts: the second, real clone succeeds.
        late = pathlib.Path(self.tmp.name) / "late-source"
        shutil.rmtree(late, ignore_errors=True)
        with mock.patch.object(classify, "_pd_pause", side_effect=lambda s: shutil.copytree(self.src_dir, late)):
            code, out = self.pr({self.F: workflow(self.c1)}, {self.F: workflow(self.c2)}, source="file://%s" % late)
        self.assertEqual(code, 0, out)
        self.assertIn(".github main is at `%s`" % self.c2, out)

    def test_a_clone_past_its_deadline_is_killed_and_incomplete(self):
        dest = pathlib.Path(self.tmp.name) / "deadline.git"
        with self.assertRaises(classify.PinFetchIncomplete) as ctx:
            classify.clone_dotgithub_main(str(dest), self.source, attempts=2, seconds=0.0001, pause=0)
        self.assertEqual(str(ctx.exception).count("no clone within"), 2, str(ctx.exception))

    def test_the_clone_holds_commits_only_and_reads_never_fetch_lazily(self):
        dest = pathlib.Path(self.tmp.name) / "commits-only.git"
        classify.clone_dotgithub_main(str(dest), self.source, pause=0)
        tip, shas = classify.main_commits(str(dest))
        self.assertEqual((tip, shas), (self.c2, {self.c0, self.c1, self.c2}))
        self.assertTrue(classify.descends(str(dest), self.c0, self.c2))
        self.assertFalse(classify.descends(str(dest), self.c2, self.c0))
        # a tree the commits-only clone lacks stays absent: no lazy fetch from the source
        tree = git(self.src_dir, "rev-parse", "%s^{tree}" % self.c2)
        self.assertNotEqual(classify._pd_git(str(dest), "cat-file", "-e", tree).returncode, 0)
        # and the side commit was never cloned, so it is absent too
        self.assertNotIn(self.s1, shas)
        self.assertNotEqual(classify._pd_git(str(dest), "cat-file", "-e", self.s1).returncode, 0)

    def test_descends_refuses_to_answer_for_a_commit_it_lacks(self):
        dest = pathlib.Path(self.tmp.name) / "lacks.git"
        classify.clone_dotgithub_main(str(dest), self.source, pause=0)
        with self.assertRaises(classify.PinFetchIncomplete):
            classify.descends(str(dest), self.s1, self.c2)

    # --- wiring ---

    def test_the_cli_runs_the_mode_and_requires_a_base_and_an_event(self):
        base = self.commit(self.root, {self.F: workflow(self.c1)})
        head = self.commit(base, {"README.md": "y\n"})
        git(self.consumer, "update-ref", "refs/remotes/origin/main", base)
        argv = ["pin-descent", "--manifest", str(MANIFEST), "--repo", "vagarylabs/consumer", "--head", head]
        cwd = os.getcwd()
        out = io.StringIO()
        try:
            os.chdir(self.consumer)
            with contextlib.redirect_stdout(out):
                ok = classify.main(argv + ["--base", base, "--event", "pull_request", "--base-ref", "main"])
                no_base = classify.main(argv + ["--event", "pull_request", "--base-ref", "main"])
                no_event = classify.main(argv + ["--base", base])
        finally:
            os.chdir(cwd)
        self.assertEqual((ok, no_base, no_event), (0, 2, 2), out.getvalue())
        self.assertIn("--base is required in pin-descent mode", out.getvalue())
        self.assertIn("pin-descent needs --event pull_request or merge_group", out.getvalue())

    def test_the_manifest_enforces_and_its_shape_is_checked(self):
        self.assertEqual(json.loads(MANIFEST.read_text())["pin_descent"], {"mode": "enforce"})
        for bad in (None, {"mode": "off"}, {"mode": "enforce", "x": 1}, "enforce"):
            m = json.loads(MANIFEST.read_text())
            if bad is None:
                del m["pin_descent"]
            else:
                m["pin_descent"] = bad
            with self.subTest(bad=bad), self.assertRaises(classify.IntegrityError):
                classify.validate_manifest(m)

    def test_the_one_integrity_job_runs_the_mode_on_its_full_history_checkout(self):
        text = WORKFLOW.read_text()
        job = text.split("\n  trusted-workflow-integrity:\n", 1)[1]
        step = job.split("- name: Check that a new test-bounds pin descends", 1)[1].split("\n      - name: ", 1)[0]
        head = step.split("run: |", 1)[0]
        self.assertIn("if: ${{ !cancelled() }}", head)
        self.assertIn("EVENT: ${{ github.event_name }}", head)
        self.assertIn("BASE_REF: ${{ github.event.pull_request.base.ref }}", head)
        self.assertIn('python3 -I "$d/classify.py" pin-descent --manifest "$d/manifest.json"', step)
        self.assertIn('--repo "$REPO" --base "$BASE" --head "$HEAD_SHA" --event="$EVENT" --base-ref="$BASE_REF"', step)
        self.assertNotIn("TRUSTED_CLASSIFY_PY", step)  # it runs the bytes the job's first step wrote
        self.assertIn("fetch-depth: 0", job)
        self.assertEqual(text.count("pin-descent --manifest"), 1)


if __name__ == "__main__":
    unittest.main()
