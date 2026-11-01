"""B1 (R4 of .github #69): the protected-paths judge classifies what the merge LANDS, never merge-base..head.

`git merge-base` names ONE common ancestor. When base and head have two or more (a criss-cross: a head that merges two
PR heads main already merged), the diff from that one ancestor can miss a change the merge makes. On real .github
commits a head that merged #60's and #62's heads, deleted sign-image.yml and added a README line passed the judge, and
merging it deleted the signer. classify.run_protected now diffs BASE against the tree `git merge-tree --write-tree`
writes, and fails closed (exit 2) on a conflict, an old git or any other merge-tree failure.

Each case is built from real git objects in a throwaway repository and judged by classify.main, as the workflow runs
it. Commit dates are fixed, so git's choice among several merge bases is fixed, and every criss-cross test first
asserts its precondition: two merge bases, and the ONE that `git merge-base` picks gives a diff that misses the signer
change. Without that the case would quietly be a single-merge-base case the old code also blocked.
RealCommitTests replays the real-commit case on the .github history itself; it needs those commits in the local object
store, so it skips in a shallow CI checkout. The reconstruction (CrissCrossTests) runs everywhere.
"""
import contextlib
import io
import json
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
REPO = "vagarylabs/.github"
SIGNER = ".github/workflows/sign-image.yml"
SIGNER_TESTS = "trusted/tests/test_sign_image.py"


class Repo:
    """A throwaway repository. Every git call carries the next fixed date, so commit order (and with it the merge base
    `git merge-base` picks among several) never depends on the wall clock. fixed_dates=False keeps the real clock, for
    commits made on top of real history (dates older than their parents would be clock skew)."""

    def __init__(self, d, fixed_dates=True):
        self.d = d
        self.tick = 0
        self.fixed_dates = fixed_dates
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args):
        self.tick += 1
        env = dict(os.environ)
        if self.fixed_dates:
            date = "2026-01-01T00:%02d:%02dZ" % divmod(self.tick, 60)
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        r = subprocess.run(("git",) + args, cwd=self.d, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError("git %s: %s" % (" ".join(args), r.stderr))
        return r.stdout.strip()

    def write(self, files):
        for p, text in files.items():
            path = pathlib.Path(self.d, p)
            if text is None:
                self.git("rm", "-q", p)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            self.git("add", p)

    def commit(self, msg, files):
        self.write(files)
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def branch(self, name, at):
        self.git("checkout", "-q", "-B", name, at)

    def merge(self, other, msg):
        self.git("merge", "-q", "--no-ff", "-m", msg, other)
        return self.git("rev-parse", "HEAD")

    def rev(self, ref):
        return self.git("rev-parse", ref)


def judge(d, base, head, repo=REPO):
    """classify.main protected-paths, as the workflow runs it: (exit code, stdout)."""
    out, cwd = io.StringIO(), os.getcwd()
    os.environ.pop("GITHUB_STEP_SUMMARY", None)
    try:
        os.chdir(d)
        with contextlib.redirect_stdout(out):
            code = classify.main(["protected-paths", "--manifest", str(MANIFEST), "--repo", repo,
                                  "--base", base, "--head", head])
    finally:
        os.chdir(cwd)
    return code, out.getvalue()


def without_judged_line(text):
    return [line for line in text.splitlines() if not line.startswith("Judged: ")]


def in_repo(d, fn, *args):
    cwd = os.getcwd()
    try:
        os.chdir(d)
        return fn(*args)
    finally:
        os.chdir(cwd)


def single_base_paths(d, base, head):
    """What the judge read BEFORE B1: the diff from the ONE merge base `git merge-base` picks."""
    return in_repo(d, lambda: [p for _, p in classify.changed_paths(classify.resolve(base, head), head)])


def old_judge(d, base, head):
    """The pre-B1 judge (one merge base), the revert mutant run in-suite: (exit code, stdout)."""
    def landing_as_before(b, h):
        return classify.git("merge-base", b, h).strip()  # stands in for the tree; changed_as_before diffs it to head
    real_changed = classify.changed_paths

    def changed_as_before(_base, mb):
        return real_changed(mb, head)
    with mock.patch.object(classify, "landing_tree", landing_as_before), \
            mock.patch.object(classify, "changed_paths", changed_as_before):
        return judge(d, base, head)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Repo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def judge(self, base, head):
        return judge(self.r.d, base, head)

    def assert_criss_cross(self, base, head, picked):
        bases = self.r.git("merge-base", "--all", base, head).split()
        self.assertEqual(len(bases), 2, "precondition: a criss-cross has two merge bases")
        self.assertEqual(self.r.git("merge-base", base, head), picked, "precondition: git picks this one")
        self.assertNotIn(SIGNER, single_base_paths(self.r.d, base, head),
                         "precondition: the single-merge-base diff misses the signer change")

    def landed_signer(self, base, head):
        """The signer on base after a real `git merge --no-ff` of head (None when the merge deletes it)."""
        self.r.branch("landing", base)
        self.r.merge(head, "land")
        r = subprocess.run(["git", "cat-file", "-e", "landing:" + SIGNER], cwd=self.r.d, capture_output=True)
        return self.r.git("show", "landing:" + SIGNER) if r.returncode == 0 else None


class CrissCrossTests(Fixture):
    def build_deletion(self):
        """The real .github shape: #62 adds the signer, #60 touches something else, main merges #60 then #62, and the
        head merges #60's and #62's heads (a "sync"), deletes the signer and its tests, and adds a README line."""
        r = self.r
        r.commit("C0", {"README.md": "r0\n", "actions/test-bounds/check.py": "A = 1\n"})
        r.branch("pr62", "main")
        q2 = r.commit("#62: the shared signer", {SIGNER: "name: sign-image\n", SIGNER_TESTS: "# t\n"})
        r.branch("pr60", "main")
        q1 = r.commit("#60: test-bounds", {"actions/test-bounds/check.py": "A = 2\n"})  # newer: git picks it
        r.branch("main", "main")
        r.merge("pr60", "Merge #60")
        base = r.merge("pr62", "Merge #62")
        r.branch("attack", q1)
        r.merge(q2, "sync")
        head = r.commit("docs: one README line", {SIGNER: None, SIGNER_TESTS: None, "README.md": "r0\none line\n"})
        return base, head, q1

    def test_a_criss_cross_head_that_deletes_the_signer_is_red(self):
        base, head, q1 = self.build_deletion()
        self.assert_criss_cross(base, head, q1)
        self.assertIsNone(self.landed_signer(base, head))  # the merge really deletes it
        code, out = self.judge(base, head)
        self.assertEqual(code, 1, out)
        self.assertIn("::error title=protected paths::BLOCKING", out)
        self.assertIn("- `%s` D (authority-binding, ci-judge)" % SIGNER, out)
        self.assertIn("2 merge bases", out)

    def test_the_single_merge_base_judge_passed_it(self):
        # The revert mutant, in-suite: with one merge base the same head was green. This is B1.
        base, head, _ = self.build_deletion()
        code, out = old_judge(self.r.d, base, head)
        self.assertEqual(code, 0, out)
        self.assertNotIn("BLOCKING", out)

    def test_a_criss_cross_rollback_of_the_signer_is_red(self):
        # An older, weaker signer comes back: C0 holds A, the door changed it to M, the head resolves it to A.
        r = self.r
        r.commit("C0", {SIGNER: "signer A (old, weaker)\n", "README.md": "r0\n"})
        r.branch("q2", "main")
        q2 = r.commit("Q2: the door", {SIGNER: "signer M (current)\n"})
        r.branch("q1", "main")
        q1 = r.commit("Q1", {"README.md": "r1\n"})
        r.branch("main", "main")
        r.merge("q1", "P1")
        base = r.merge("q2", "P2")
        r.branch("attack", q1)
        r.merge(q2, "sync")
        head = r.commit("H: README", {SIGNER: "signer A (old, weaker)\n", "README.md": "r1\nr2\n"})
        self.assert_criss_cross(base, head, q1)
        self.assertEqual(self.landed_signer(base, head), "signer A (old, weaker)")
        self.assertEqual(old_judge(r.d, base, head)[0], 0)
        code, out = self.judge(base, head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)

    def test_a_three_pr_chain_cannot_land_arbitrary_signer_bytes(self):
        # Reviewer's E2: PR-alpha (EVIL then reverted) and PR-alpha' (from the EVIL commit, README only) are net zero
        # and stay green; PR-attack (a merge of both, the signer set to EVIL) is red.
        r = self.r
        r.commit("C0", {SIGNER: "signer CURRENT\n", "README.md": "r0\n"})
        r.branch("alpha", "main")
        a1 = r.commit("a1", {SIGNER: "signer EVIL\n"})
        a2 = r.commit("a2", {SIGNER: "signer CURRENT\n", "README.md": "r0\nra\n"})
        main = r.rev("main")
        self.assertEqual(self.judge(main, a2)[0], 0, "PR-alpha is net zero on the signer")
        r.branch("main", "main")
        r.merge("alpha", "merge PR-alpha")
        r.branch("alphap", a1)
        a1p = r.commit("a1p", {"README2": "rp\n"})
        main = r.rev("main")
        self.assertEqual(self.judge(main, a1p)[0], 0, "PR-alpha' is net zero on the signer")
        r.branch("main", "main")
        base = r.merge("alphap", "merge PR-alpha'")
        self.assertEqual(r.git("show", "main:" + SIGNER), "signer CURRENT")
        r.branch("attack", a1p)
        r.merge(a2, "sync")
        head = r.commit("docs: README2 line", {SIGNER: "signer EVIL\n", "README2": "rp\nrx\n"})
        self.assert_criss_cross(base, head, a1p)
        self.assertEqual(self.landed_signer(base, head), "signer EVIL")
        self.assertEqual(old_judge(r.d, base, head)[0], 0)
        code, out = self.judge(base, head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)


class SingleMergeBaseControlTests(Fixture):
    """A PR with one merge base is judged exactly as before: the same rows, exit code and message."""

    def build(self, files):
        r = self.r
        r.commit("C0", {SIGNER: "name: sign-image\n", "README.md": "r0\n", ".github/workflows/ci.yml": "name: ci\n",
                        "other.txt": "o\n"})
        r.branch("pr", "main")
        head = r.commit("pr", files)
        r.branch("main", "main")
        base = r.commit("main moves on", {"other.txt": "o2\n"})  # the base is ahead: still one merge base
        self.assertEqual(len(r.git("merge-base", "--all", base, head).split()), 1)
        return base, head

    def assert_as_before(self, base, head):
        entry = classify.repo_entry(classify.validate_manifest(json.loads(MANIFEST.read_text())), REPO)
        before = in_repo(self.r.d, lambda: classify.changed_paths(classify.resolve(base, head), head))
        now = in_repo(self.r.d, lambda: classify.changed_paths(base, classify.landing_tree(base, head)))
        self.assertEqual(classify.classify(entry, now), classify.classify(entry, before))
        old_code, old_out = old_judge(self.r.d, base, head)
        code, out = self.judge(base, head)
        self.assertEqual(code, old_code, out)
        self.assertEqual(without_judged_line(out), without_judged_line(old_out))
        self.assertIn("(git merge-tree --write-tree; 1 merge base).", out)
        return code, out

    def test_an_unprotected_change_passes_as_before(self):
        code, out = self.assert_as_before(*self.build({"README.md": "r1\n"}))
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)

    def test_a_report_only_change_reports_as_before(self):
        code, out = self.assert_as_before(*self.build({".github/workflows/ci.yml": "name: ci\non: push\n"}))
        self.assertEqual(code, 0, out)
        self.assertIn("INTERIM report-only", out)

    def test_a_signer_change_is_red_as_before(self):
        code, out = self.assert_as_before(*self.build({SIGNER: "changed\n"}))
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING", out)

    def test_a_head_already_in_the_base_changes_nothing(self):
        r = self.r
        r.commit("C0", {SIGNER: "s\n"})
        head = r.commit("x", {SIGNER: "s2\n"})
        base = r.commit("y", {"README.md": "r\n"})
        code, out = self.judge(base, head)
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)


class RenameAndRetargetTests(Fixture):
    def test_renaming_the_signer_is_red(self):
        r = self.r
        r.commit("C0", {SIGNER: "name: sign-image\n", "README.md": "r0\n"})
        r.branch("pr", "main")
        r.git("mv", SIGNER, ".github/workflows/sign-image-v2.yml")
        head = r.commit("rename", {})
        code, out = self.judge(r.rev("main"), head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` D (authority-binding, ci-judge)" % SIGNER, out)  # --no-renames: a D and an A
        self.assertIn("- `.github/workflows/sign-image-v2.yml` A (ci-judge)", out)

    def test_renaming_another_file_onto_the_signer_is_red(self):
        r = self.r
        r.commit("C0", {SIGNER: "name: sign-image\n", "evil.yml": "name: evil\n"})
        r.branch("pr", "main")
        r.git("mv", "-f", "evil.yml", SIGNER)
        head = r.commit("swap", {})
        code, out = self.judge(r.rev("main"), head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)

    def test_the_verdict_follows_the_base_after_a_retarget(self):
        # A PR opened against a scratch branch that already holds a signer change is green there and red against main:
        # the judge reads the base sha of the event it runs for. Whether GitHub re-runs the required check after a
        # retarget (an `edited` event) is live state for root (N7), not a unit-test fact.
        r = self.r
        main = r.commit("C0", {SIGNER: "signer CURRENT\n", "README.md": "r0\n"})
        r.branch("scratch", "main")
        scratch = r.commit("scratch: the signer changes", {SIGNER: "signer EVIL\n"})
        r.branch("pr", "scratch")
        head = r.commit("pr: README", {"README.md": "r1\n"})
        code, out = self.judge(scratch, head)
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)
        code, out = self.judge(main, head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)


class FailClosedTests(Fixture):
    def assert_conflict_fails_closed(self, path):
        r = self.r
        root = r.commit("C0", {SIGNER: "s0\n", "README.md": "r0\n"})
        r.branch("pr", root)
        head = r.commit("pr", {path: "head\n"})
        r.branch("main", "main")
        base = r.commit("main", {path: "base\n"})
        code, out = self.judge(base, head)
        self.assertEqual(code, 2, out)
        self.assertIn("::error title=trusted protected-paths::merge CONFLICT", out)
        self.assertIn("(%s)" % path, out)
        self.assertIn("fails closed", out)

    def test_a_conflict_on_an_unprotected_path_fails_closed(self):
        self.assert_conflict_fails_closed("README.md")

    def test_a_conflict_on_the_signer_fails_closed(self):
        self.assert_conflict_fails_closed(SIGNER)

    def test_unrelated_histories_fail_closed(self):
        r = self.r
        base = r.commit("C0", {SIGNER: "s\n"})
        r.git("checkout", "-q", "--orphan", "other")
        r.git("rm", "-rfq", ".")
        head = r.commit("unrelated", {"README.md": "x\n"})
        code, out = self.judge(base, head)
        self.assertEqual(code, 2, out)
        self.assertIn("::error title=trusted protected-paths::", out)

    def test_a_ref_merge_tree_cannot_read_is_a_failure_not_a_conflict(self):
        # merge-tree exits 1 for this too, with no tree on stdout: it must not read as a conflict, nor as clean.
        base = self.r.commit("C0", {"README.md": "r\n"})
        with self.assertRaises(classify.IntegrityError) as cm:
            in_repo(self.r.d, classify.landing_tree, base, "f" * 40)
        self.assertIn("failed (exit 1)", str(cm.exception))
        self.assertNotIn("CONFLICT", str(cm.exception))

    def test_an_old_git_fails_closed_with_a_named_error(self):
        base = self.r.commit("C0", {SIGNER: "s\n"})
        head = self.r.commit("x", {SIGNER: "s2\n"})
        for version in ("git version 2.37.3", "git version 1.9.0"):
            real = classify.git

            def fake(*args, _v=version):
                return _v + "\n" if args == ("version",) else real(*args)
            with self.subTest(version=version), mock.patch.object(classify, "git", fake):
                code, out = self.judge(base, head)
                self.assertEqual(code, 2, out)
                self.assertIn("has no `git merge-tree --write-tree` (needs >= 2.38)", out)
                self.assertIn("no merge-base fallback", out)

    def test_the_git_version_is_parsed_or_refused(self):
        for text, want in (("git version 2.50.1 (Apple Git-155)", (2, 50)), ("git version 2.43.0", (2, 43)),
                           ("git version 2.56.0", (2, 56)), ("git version 2.38.0.windows.1", (2, 38))):
            with self.subTest(text=text), mock.patch.object(classify, "git", lambda *a, _t=text: _t + "\n"):
                self.assertEqual(classify.git_version(), want)
        with mock.patch.object(classify, "git", lambda *a: "hub version 9\n"), \
                self.assertRaises(classify.IntegrityError) as cm:
            classify.git_version()
        self.assertIn("needs git >= 2.38", str(cm.exception))
        self.assertGreaterEqual(classify.git_version(), classify.MERGE_TREE_MIN_GIT)  # the git these tests run


class RealCommitTests(unittest.TestCase):
    """The reviewer's case on the real .github history: base = main at fa7d4abc (#62 merged after #60), head = a merge of
    #60's head bb329839 and #62's head 56828234, minus sign-image.yml and its tests, plus a README line. The head is
    built in a throwaway repository that borrows this repository's objects (alternates) and writes only its own."""
    BASE = "fa7d4abc662434c1ee57f1d24a1973dfac79c320"
    PR60 = "bb32983971298841e113cda0fcb45b0d8326bd26"
    PR62 = "56828234b15053d56f0cde9b3ec4349f3c321dd3"

    def setUp(self):
        r = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=ROOT,
                           capture_output=True, text=True)
        objects = pathlib.Path(r.stdout.strip(), "objects")
        missing = [s for s in (self.BASE, self.PR60, self.PR62)
                   if r.returncode != 0 or subprocess.run(["git", "cat-file", "-e", s + "^{commit}"], cwd=ROOT,
                                                          capture_output=True).returncode != 0]
        if missing:
            self.skipTest("the .github commits %s are not in this checkout's object store (a shallow clone)"
                          % ", ".join(s[:8] for s in missing))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Repo(self.tmp.name, fixed_dates=False)
        pathlib.Path(self.tmp.name, ".git", "objects", "info", "alternates").write_text(str(objects) + "\n")

    def test_the_real_commit_case_is_red(self):
        r = self.r
        r.git("checkout", "-q", "--detach", self.PR60)
        r.merge(self.PR62, "sync")
        readme = pathlib.Path(r.d, "README.md").read_text()
        head = r.commit("docs: one README line", {SIGNER: None, SIGNER_TESTS: None, "README.md": readme + "one line\n"})
        bases = r.git("merge-base", "--all", self.BASE, head).split()
        self.assertEqual(sorted(bases), sorted([self.PR60, self.PR62]))
        self.assertEqual(r.git("merge-base", self.BASE, head), self.PR60)
        self.assertNotIn(SIGNER, single_base_paths(r.d, self.BASE, head))
        tree = r.git("merge-tree", "--write-tree", self.BASE, head)
        self.assertNotIn(SIGNER, r.git("ls-tree", "-r", "--name-only", tree).split("\n"))  # the merge deletes it
        self.assertEqual(old_judge(r.d, self.BASE, head)[0], 0)  # B1: the single-merge-base judge passed it
        code, out = judge(r.d, self.BASE, head)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` D (authority-binding, ci-judge)" % SIGNER, out)
        self.assertIn("- `%s` D (authority-binding)" % SIGNER_TESTS, out)


if __name__ == "__main__":
    unittest.main()
