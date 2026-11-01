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
BASE_IS_LIVE = object()


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
        r = subprocess.run(("git",) + args, cwd=self.d, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True)
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


def judge(d, base, head, repo=REPO, live=BASE_IS_LIVE, event="pull_request", base_ref="main"):
    """classify.main protected-paths, as the workflow runs it: (exit code, stdout). On pull_request the checkout's
    refs/remotes/origin/main is the live base: by default the event's base; `live` sets another tip, None removes it."""
    out, cwd = io.StringIO(), os.getcwd()
    os.environ.pop("GITHUB_STEP_SUMMARY", None)
    ref = "refs/remotes/origin/main"
    if live is BASE_IS_LIVE:
        live = base
    if live is None:
        subprocess.run(["git", "update-ref", "-d", ref], cwd=d, capture_output=True)
    else:
        subprocess.run(["git", "update-ref", ref, live], cwd=d, check=True, capture_output=True)
    args = ["protected-paths", "--manifest", str(MANIFEST), "--repo", repo, "--base", base, "--head", head]
    if event is not None:
        args += ["--event", event]
    if base_ref is not None:
        args += ["--base-ref=" + base_ref]  # the template's form: a value with a leading dash stays a value
    try:
        os.chdir(d)
        with contextlib.redirect_stdout(out):
            code = classify.main(args)
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


def old_judge_worktree(d, base, head):
    """The pre-N1 judge, run in-suite: ONE merge, with .gitattributes read from the working tree."""
    def landing_from_worktree(b, h):
        out = classify.git("merge-tree", "--write-tree", "-z", "--name-only", "--no-messages", b, h)
        return out.split("\0")[0]
    with mock.patch.object(classify, "landing_tree", landing_from_worktree):
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


CUR = "L1 current\nk2\nk3\nk4\nL5 current\nk6\n"
EVIL = "L1 EVIL\nk2\nk3\nk4\nL5 EVIL\nk6\n"


def build_p8(r, attrs):
    """Reviewer's P8 (delta R4 of .github #69): PR-1 and PR-2 are each net zero on the signer, each with a sibling
    commit off an EVIL one; PR-3 merges those siblings, sets the signer to EVIL and adds `attrs` ({path: text}, the
    .gitattributes that steer a working-tree merge). Returns (main after PR-1 and PR-2, PR-3's head)."""
    m0 = r.commit("C0", {SIGNER: CUR, "README.md": "r0\n"})
    r.branch("a1", m0)
    a1 = r.commit("a1: evil signer (never lands alone)", {SIGNER: EVIL})
    r.branch("q1", a1)
    q1 = r.commit("q1: line 5 back", {SIGNER: CUR.replace("L1 current", "L1 EVIL")})
    p1 = r.commit("pr1 head: signer back to current", {SIGNER: CUR, "README.md": "r0 pr1\n"})
    r.branch("q2", a1)
    q2 = r.commit("q2: line 1 back", {SIGNER: CUR.replace("L5 current", "L5 EVIL")})
    p2 = r.commit("pr2 head: signer back to current", {SIGNER: CUR, "README2": "pr2\n"})
    r.branch("main", m0)
    r.merge(p1, "merge PR-1")
    base = r.merge(p2, "merge PR-2")
    r.branch("attack", q1)
    r.merge(q2, "sync q1 q2")
    head = r.commit("docs: attributes", dict(attrs, **{SIGNER: EVIL}))
    return base, head


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
        # 2.41 and 2.42 have --attr-source, but merge-tree segfaulted with it until 2.43.0 (git RelNotes 2.43.0)
        for version in ("git version 2.37.3", "git version 1.9.0", "git version 2.41.0", "git version 2.42.2"):
            real = classify.git

            def fake(*args, _v=version):
                return _v + "\n" if args == ("version",) else real(*args)
            with self.subTest(version=version), mock.patch.object(classify, "git", fake):
                code, out = self.judge(base, head)
                self.assertEqual(code, 2, out)
                self.assertIn("cannot run `git --attr-source=<tree> merge-tree --write-tree` (needs >= 2.43)", out)
                self.assertIn("no merge-base fallback", out)

    def test_the_git_version_is_parsed_or_refused(self):
        for text, want in (("git version 2.50.1 (Apple Git-155)", (2, 50)), ("git version 2.43.0", (2, 43)),
                           ("git version 2.56.0", (2, 56)), ("git version 2.38.0.windows.1", (2, 38))):
            with self.subTest(text=text), mock.patch.object(classify, "git", lambda *a, _t=text: _t + "\n"):
                self.assertEqual(classify.git_version(), want)
        with mock.patch.object(classify, "git", lambda *a: "hub version 9\n"), \
                self.assertRaises(classify.IntegrityError) as cm:
            classify.git_version()
        self.assertIn("needs git >= 2.43", str(cm.exception))
        self.assertGreaterEqual(classify.git_version(), classify.MERGE_TREE_MIN_GIT)  # the git these tests run


class LiveBaseTests(Fixture):
    """N2 (delta R4 of .github #69): on pull_request the judge diffs against the base branch's LIVE tip
    (origin/<base.ref> in the checkout), not the event's base.sha, which was seen 47 minutes stale on #69."""

    def build_door_then_rollback(self, head_contains_live_tip):
        r = self.r
        m0 = r.commit("C0", {SIGNER: "signer S0 (old, weak)\n", "README.md": "r0\n"})
        r.branch("door", "main")
        x = r.commit("door: fix the signer", {SIGNER: "signer S1 (security fix)\n"})
        r.branch("main", "main")
        m1 = r.merge("door", "door merges (root lift and restore)")
        # P10 (strict on): the head contains the live tip. P3 (strict off): it holds only the door commit.
        r.branch("attack", m1 if head_contains_live_tip else x)
        head = r.commit("docs (and the old signer)", {SIGNER: "signer S0 (old, weak)\n", "README.md": "r0 docs\n"})
        self.assertEqual(self.landed_signer(m1, head), "signer S0 (old, weak)")  # the merge rolls the fix back
        return m0, m1, head

    def test_a_stale_event_base_is_judged_at_the_live_tip(self):
        for contains in (True, False):
            with self.subTest(head_contains_live_tip=contains):
                self.tearDown()
                self.setUp()
                m0, m1, head = self.build_door_then_rollback(contains)
                # precondition: at the stale event base the same head is green (what the judge read before N2)
                code, out = judge(self.r.d, m0, head, live=m0)
                self.assertEqual(code, 0, out)
                code, out = judge(self.r.d, m0, head, live=m1)
                self.assertEqual(code, 1, out)
                self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)
                self.assertIn("Judged: the live tip `%s` of `main` (the event's base `%s` is its ancestor)" % (m1, m0),
                              out)

    def test_an_event_base_that_is_not_an_ancestor_of_the_live_tip_fails_closed(self):
        r = self.r
        m0 = r.commit("C0", {"README.md": "r0\n"})
        r.branch("elsewhere", "main")
        other = r.commit("a branch the event base is not on", {"x": "x\n"})
        r.branch("main", "main")
        base = r.commit("main", {"y": "y\n"})
        head = r.commit("pr", {"README.md": "r1\n"})
        code, out = judge(r.d, base, head, live=other)
        self.assertEqual(code, 2, out)
        self.assertIn("is not an ancestor of main's live tip %s" % other, out)
        self.assertEqual(judge(r.d, base, head, live=base)[0], 0)  # control: the same PR at its own live tip
        self.assertNotEqual(m0, other)

    def test_a_missing_live_tip_fails_closed(self):
        base = self.r.commit("C0", {"README.md": "r0\n"})
        head = self.r.commit("pr", {"README.md": "r1\n"})
        code, out = judge(self.r.d, base, head, live=None)
        self.assertEqual(code, 2, out)
        self.assertIn("refs/remotes/origin/main is not in this checkout", out)

    def test_a_hostile_or_missing_base_ref_fails_closed(self):
        base = self.r.commit("C0", {"README.md": "r0\n"})
        head = self.r.commit("pr", {"README.md": "r1\n"})
        for ref in ("../x", "-x", "main\n", "a..b", "", None, "refs/heads/main extra"):
            with self.subTest(ref=ref):
                code, out = judge(self.r.d, base, head, base_ref=ref)
                self.assertEqual(code, 2, out)
                self.assertIn("needs the base branch name (--base-ref)", out)

    def test_the_event_is_required(self):
        base = self.r.commit("C0", {"README.md": "r0\n"})
        head = self.r.commit("pr", {"README.md": "r1\n"})
        code, out = judge(self.r.d, base, head, event=None)
        self.assertEqual(code, 2, out)
        self.assertIn("protected-paths needs --event pull_request or merge_group", out)


class AttributeTests(Fixture):
    """N1 (delta R4 of .github #69): the job's working tree is the PR head, so its .gitattributes could pick the merge
    driver. The judge merges three times, attributes from an empty tree, the base and the head, and fails closed (exit
    2) unless all three are clean and agree. The worktree is detached at the head, as actions/checkout leaves it, so the
    pre-N1 judge (attributes from the working tree) would read the head's attributes."""
    DEPENDS = "depends on .gitattributes"

    def at_head(self, head):
        self.r.git("checkout", "-q", "--detach", head)

    def signer_in(self, tree):
        return self.r.git("show", "%s:%s" % (tree, SIGNER)) + "\n"

    def worktree_merge(self, base, head, *opts):
        out = self.r.git(*(opts + ("merge-tree", "--write-tree", "--no-messages", base, head)))
        return out.split("\n")[0]

    def assert_fails_closed(self, base, head):
        code, out = self.judge(base, head)
        self.assertEqual(code, 2, out)
        self.assertIn("::error title=trusted protected-paths::the merge of head %s into base %s %s"
                      % (head, base, self.DEPENDS), out)
        return out

    def test_p8_a_head_side_merge_driver_cannot_hide_new_signer_bytes(self):
        variants = {"merge=binary": {".gitattributes": "%s merge=binary\n" % SIGNER},
                    "the binary macro": {".gitattributes": "%s binary\n" % SIGNER},
                    "-merge": {".gitattributes": "%s -merge\n" % SIGNER},
                    "a nested .gitattributes": {".github/workflows/.gitattributes": "*.yml merge=binary\n"}}
        for name, attrs in variants.items():
            with self.subTest(variant=name):
                self.tearDown()
                self.setUp()
                base, head = build_p8(self.r, attrs)
                self.at_head(head)
                self.assertEqual(len(self.r.git("merge-base", "--all", base, head).split()), 2)
                # precondition: the working-tree merge (what the judge computed before N1) keeps main's signer, while
                # an attribute-free merge lands EVIL
                self.assertEqual(self.signer_in(self.worktree_merge(base, head)), CUR)
                empty = self.r.git("mktree")
                self.assertEqual(self.signer_in(self.worktree_merge(base, head, "--attr-source=" + empty)), EVIL)
                self.assertEqual(old_judge_worktree(self.r.d, base, head)[0], 0)  # the pre-N1 judge was green
                self.assert_fails_closed(base, head)

    def build_main_attribute(self, drop_it):
        """P9 / P12: main already carries `sign-image.yml merge=binary` (an unprotected path); PR-3 keeps it (P9) or
        deletes it (P12)."""
        r = self.r
        r.commit("C0", {SIGNER: CUR, "README.md": "r0\n"})
        a1 = r.commit("main: .gitattributes", {".gitattributes": "%s merge=binary\n" % SIGNER})
        r.branch("q1", a1)
        q1 = r.commit("q1", {SIGNER: CUR.replace("L1 current", "L1 EVIL")})
        p1 = r.commit("pr1 head", {SIGNER: CUR})
        r.branch("q2", a1)
        q2 = r.commit("q2", {SIGNER: CUR.replace("L5 current", "L5 EVIL")})
        p2 = r.commit("pr2 head", {SIGNER: CUR})
        r.branch("main", "main")
        r.merge(p1, "merge PR-1")
        base = r.merge(p2, "merge PR-2")
        r.branch("attack", q1)
        try:
            r.merge(q2, "sync")
        except AssertionError:  # main's binary driver makes the sync conflict: resolve it to EVIL
            r.commit("sync", {SIGNER: EVIL})
        files = {SIGNER: EVIL, "README3": "x\n"}
        if drop_it:
            files[".gitattributes"] = None
        head = r.commit("pr3 head", files)
        self.at_head(head)
        self.assertEqual(len(r.git("merge-base", "--all", base, head).split()), 2)
        return base, head

    def test_p9_main_carrying_the_driver_fails_closed(self):
        base, head = self.build_main_attribute(drop_it=False)
        self.assert_fails_closed(base, head)

    def test_p12_a_pr_deleting_mains_driver_fails_closed(self):
        base, head = self.build_main_attribute(drop_it=True)
        self.assertEqual(old_judge_worktree(self.r.d, base, head)[0], 0)  # the pre-N1 judge was green here
        self.assert_fails_closed(base, head)

    def test_a_head_side_union_cannot_turn_a_conflict_clean(self):
        r = self.r
        root = r.commit("C0", {"README.md": "r0\n"})
        r.branch("pr", root)
        head = r.commit("pr", {"README.md": "head\n", ".gitattributes": "README.md merge=union\n"})
        r.branch("main", "main")
        base = r.commit("main", {"README.md": "base\n"})
        self.at_head(head)
        self.assertEqual(old_judge_worktree(r.d, base, head)[0], 0)  # union made it clean and green before N1
        code, out = self.judge(base, head)
        self.assertEqual(code, 2, out)
        self.assertIn("merge CONFLICT (attributes from an empty tree)", out)

    def test_innocuous_attributes_keep_the_normal_verdict(self):
        r = self.r
        r.commit("C0", {SIGNER: "signer\n", "README.md": "r0\n", ".gitattributes": "*.png binary\n"})
        r.branch("pr", "main")
        readme = r.commit("pr: README", {"README.md": "r1\n"})
        self.at_head(readme)
        code, out = self.judge(r.rev("main"), readme)
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)
        r.branch("pr2", "main")
        signer = r.commit("pr: signer", {SIGNER: "changed\n"})
        self.at_head(signer)
        code, out = self.judge(r.rev("main"), signer)
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING", out)


class EscapeTests(Fixture):
    """LOW (c), delta R4 of .github #69: a PR chooses its path names, and the judge prints them to stdout, where a line
    starting with `::` is a workflow command (`::stop-commands::<token>` would silence the ::error annotation). Every
    printed path is escaped; the exit code never depended on it."""
    HOSTILE = ".github/workflows/x\n::stop-commands::tok.yml"
    SHOWN = ".github/workflows/x\\x0a::stop-commands::tok.yml"

    def assert_no_injected_command(self, out):
        for line in out.splitlines():
            self.assertFalse(line.lstrip().startswith("::stop-commands"), line)
            self.assertFalse(line.lstrip().startswith("::") and "tok.yml" in line and "%0A" not in line
                             and "\\x0a" not in line, line)

    def test_a_hostile_path_cannot_inject_a_workflow_command(self):
        r = self.r
        base = r.commit("C0", {SIGNER: "signer\n", "README.md": "r0\n"})
        r.branch("pr", base)
        head = r.commit("pr", {self.HOSTILE: "x\n", SIGNER: "changed\n"})
        code, out = self.judge(base, head)
        self.assertEqual(code, 1, out)
        self.assert_no_injected_command(out)
        self.assertIn("- `%s` A (ci-judge)" % self.SHOWN, out)
        errors = [l for l in out.splitlines() if l.startswith("::error title=protected paths::BLOCKING")]
        self.assertEqual(len(errors), 1, out)
        # integrity mode prints the same paths
        out2 = io.StringIO()
        cwd = os.getcwd()
        try:
            os.chdir(r.d)
            with contextlib.redirect_stdout(out2):
                self.assertEqual(classify.main(["integrity", "--manifest", str(MANIFEST), "--repo", REPO,
                                                "--base", base, "--head", head]), 0)
        finally:
            os.chdir(cwd)
        self.assert_no_injected_command(out2.getvalue())
        self.assertIn(self.SHOWN, out2.getvalue())

    def test_a_hostile_workflow_name_cannot_inject_from_sibling_read(self):
        # The same class in sibling-read mode (trusted-workflow-integrity), which reads the head's workflow files.
        r = self.r
        base = r.commit("C0", {"README.md": "r0\n"})
        head = r.commit("pr", {self.HOSTILE: "name: x\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                                             "      - uses: actions/create-github-app-token@v1\n"
                                             "      - run: git clone https://github.com/vagarylabs/other\n"})
        out = io.StringIO()
        cwd = os.getcwd()
        try:
            os.chdir(r.d)
            with contextlib.redirect_stdout(out):
                self.assertEqual(classify.main(["sibling-read", "--manifest", str(MANIFEST), "--repo", REPO,
                                                "--base", base, "--head", head]), 0)
        finally:
            os.chdir(cwd)
        text = out.getvalue()
        self.assert_no_injected_command(text)
        self.assertIn("::warning file=.github/workflows/x%0A%3A%3Astop-commands%3A%3Atok.yml,line=8,", text)
        self.assertIn("- `%s` job `a` line 8" % self.SHOWN, text)

    def test_a_hostile_conflicted_path_stays_on_the_error_line(self):
        r = self.r
        root = r.commit("C0", {self.HOSTILE: "r0\n"})
        r.branch("pr", root)
        head = r.commit("pr", {self.HOSTILE: "head\n"})
        r.branch("main", "main")
        base = r.commit("main", {self.HOSTILE: "base\n"})
        code, out = self.judge(base, head)
        self.assertEqual(code, 2, out)
        self.assert_no_injected_command(out)
        errors = [l for l in out.splitlines() if l.startswith("::error title=trusted protected-paths::merge CONFLICT")]
        self.assertEqual(len(errors), 1, out)
        self.assertIn(self.SHOWN, errors[0])


class MergeGroupTests(Fixture):
    """Root's D2 direction: the binding judge runs in a merge queue. On merge_group the group commit IS what lands, so
    its own tree is classified against the queue base and no merge is computed."""

    def judge_group(self, base, group):
        def no_merge(*args):
            raise AssertionError("merge_group computed a merge")
        with mock.patch.object(classify, "landing_tree", no_merge):
            return judge(self.r.d, base, group, event="merge_group", base_ref=None, live=None)

    def group_commit(self, base, head):
        """The queue's commit: base with head merged in (a real attribute-free `git merge --no-ff`)."""
        self.r.branch("gh-readonly-queue/main/pr-1", base)
        return self.r.merge(head, "Merge pull request #1")

    def test_a_group_whose_tree_changes_the_signer_is_red(self):
        r = self.r
        base = r.commit("C0", {SIGNER: "signer\n", "README.md": "r0\n"})
        r.branch("pr", base)
        head = r.commit("pr", {SIGNER: "changed\n"})
        group = self.group_commit(base, head)
        code, out = self.judge_group(base, group)
        self.assertEqual(code, 1, out)
        self.assertIn("::error title=protected paths::BLOCKING", out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)
        self.assertIn("Judged: the merge-group base `%s` against the group commit `%s`'s own tree" % (base, group), out)

    def test_a_group_that_touches_nothing_protected_is_green(self):
        r = self.r
        base = r.commit("C0", {SIGNER: "signer\n", "README.md": "r0\n"})
        r.branch("pr", base)
        head = r.commit("pr", {"README.md": "r1\n"})
        code, out = self.judge_group(base, self.group_commit(base, head))
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)

    def test_the_group_tree_is_judged_whatever_the_attributes_say(self):
        # P8 as a group commit: the steering .gitattributes cannot change a tree that is already written.
        base, head = build_p8(self.r, {".gitattributes": "%s merge=binary\n" % SIGNER})
        group = self.group_commit(base, head)
        self.assertEqual(self.r.git("show", "%s:%s" % (group, SIGNER)) + "\n", EVIL)  # what the queue lands
        code, out = self.judge_group(base, group)
        self.assertEqual(code, 1, out)
        self.assertIn("- `%s` M (authority-binding, ci-judge)" % SIGNER, out)

    def test_a_base_that_is_not_in_the_group_commit_fails_closed(self):
        r = self.r
        base = r.commit("C0", {"README.md": "r0\n"})
        r.branch("other", base)
        other = r.commit("other", {"x": "x\n"})
        r.branch("main", base)
        group = r.commit("not built on other", {"y": "y\n"})
        code, out = self.judge_group(other, group)
        self.assertEqual(code, 2, out)
        self.assertIn("merge group: the base %s is not an ancestor of the group commit %s" % (other, group), out)


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
            why = ("the .github commits %s are not in this checkout's object store (a shallow clone?)"
                   % ", ".join(s[:8] for s in missing))
            if os.environ.get("TRUSTED_REQUIRE_REAL_COMMITS") == "1":
                self.fail(why + "; TRUSTED_REQUIRE_REAL_COMMITS=1, and ci.yml's trusted-tests checks out full history")
            self.skipTest(why + "; set TRUSTED_REQUIRE_REAL_COMMITS=1 to make this a failure, as CI does")
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


class CiRunsTheRealCommitCaseTests(unittest.TestCase):
    """LOW (a), delta R4 of .github #69: at checkout depth 1 RealCommitTests always skipped in CI."""

    def test_trusted_tests_checks_out_full_history_and_requires_the_commits(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        job = ci.split("\n  trusted-tests:\n", 1)[1].split("\n  no-hosted-runners-guard:\n", 1)[0]
        self.assertIn("\n          fetch-depth: 0\n", job)
        self.assertIn('\n          TRUSTED_REQUIRE_REAL_COMMITS: "1"\n', job)
        self.assertIn("python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v", job)

    def test_a_missing_commit_fails_only_when_required(self):
        for env, failed, skipped in (({"TRUSTED_REQUIRE_REAL_COMMITS": "1"}, 1, 0), ({}, 0, 1)):
            with self.subTest(env=env), mock.patch.object(RealCommitTests, "PR62", "0" * 40), \
                    mock.patch.dict(os.environ, env, clear=False):
                if not env:
                    os.environ.pop("TRUSTED_REQUIRE_REAL_COMMITS", None)
                result = unittest.TestResult()
                RealCommitTests("test_the_real_commit_case_is_red").run(result)
                self.assertEqual((len(result.failures), len(result.skipped), result.testsRun), (failed, skipped, 1))


if __name__ == "__main__":
    unittest.main()
