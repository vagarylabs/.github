"""Tests for the trusted ruleset workflows: manifest, classifier, renderer and workflow invariants.

Plain unittest, stdlib only, light (one throwaway git repo). Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402
import inline_scripts  # noqa: E402
import render  # noqa: E402

MANIFEST = ROOT / "trusted" / "manifest.json"
FIXTURE = ROOT / "trusted" / "tests" / "fixtures" / "vps-ansible-c0ff73ea.paths"
WORKFLOWS = {n: ROOT / ".github" / "workflows" / (n + ".yml")
             for n in ("trusted-secret-scan", "trusted-workflow-integrity", "trusted-protected-paths")}


def judge_witnessed(pattern):
    """True when the F14 judge-config list (test_judge_configs) declares a path this pattern matches: that path is its
    witness, so a typo in it still fails a test, and it may protect a judge's file the repository does not have yet."""
    from test_judge_configs import JUDGES, REPO_JUDGES
    declared = [x for paths in JUDGES.values() for x in paths] + [x for paths in REPO_JUDGES.values() for x in paths]
    return any(classify.fnmatch.fnmatchcase(x, pattern) for x in declared)


def manifest():
    return classify.validate_manifest(json.loads(MANIFEST.read_text()))


class ManifestTests(unittest.TestCase):
    def test_valid(self):
        manifest()

    def test_rejects_bad_shapes(self):
        for bad in ({}, {"version": 2}, {"version": 1, "default": {"protected": [], "ratchet_files": []}},
                    {"version": 1, "default": {"protected": [{"class": "x", "patterns": []}], "ratchet_files": []}},
                    {"version": 1, "default": {"protected": [{"class": "x", "patterns": ["a"]}]}}):
            with self.assertRaises(classify.IntegrityError):
                classify.validate_manifest(bad)

    def test_every_vps_ansible_pattern_matches_a_real_path(self):
        # A pattern that matches nothing fails OPEN silently; bind each one to a real path of vps-ansible c0ff73ea's
        # tree. This repository is PUBLIC and vps-ansible is private, so the fixture is NOT the tree: it is one real
        # path per pattern (all already named in test_required_vps_ansible_paths_are_protected), each present in
        # c0ff73ea (`git -C <vps-ansible> cat-file -e c0ff73ea:<path>`). A pattern added later needs its witness
        # path added here, which this assertion forces. (The full tree was published before 2026-10-23 and remains
        # in this repository's history; only further exposure is stopped.)
        paths = FIXTURE.read_text().split()
        self.assertEqual(paths, sorted(paths))
        # A judge-config pattern (F14) with no file in vps-ansible yet is witnessed by test_judge_configs' declared
        # path instead, which it must match; one that has a real file here (.gitleaks.toml) keeps its real witness.
        entry = manifest()["repos"]["vagarylabs/vps-ansible"]
        real = lambda pat: any(classify.fnmatch.fnmatchcase(x, pat) for x in paths)
        own = [pat for p in entry["protected"] for pat in p["patterns"] if real(pat) or not judge_witnessed(pat)]
        self.assertEqual(len(paths), len(own))
        for p in entry["protected"]:
            for pat in p["patterns"]:
                if judge_witnessed(pat) and not real(pat):
                    continue
                with self.subTest(pattern=pat):
                    self.assertTrue(any(classify.fnmatch.fnmatchcase(x, pat) for x in paths))
        for rf in entry["ratchet_files"]:
            self.assertIn(rf, paths)

    def test_required_vps_ansible_paths_are_protected(self):
        entry = manifest()["repos"]["vagarylabs/vps-ansible"]
        expect = {
            "scripts/test-ci-hosted-routing.py": "ci-judge",
            ".github/workflows/secret-scan.yml": "ci-judge",
            ".gitleaks.toml": "ci-judge",
            "roles/release_policy/tasks/main.yml": "iac",
            "scripts/test-core-release-runner.py": "release",
            "playbooks/build-cell-voice-release-runner.yml": "release",
            "scripts/build-controller/source-delivery-binding.json": "authority-binding",
            "scripts/build-controller/github-apps.json": "authority-binding",
        }
        for path, cls in expect.items():
            with self.subTest(path=path):
                self.assertIn(cls, classify.classes_for(entry, path))
        self.assertEqual(classify.classes_for(entry, "docs/runbooks/x.md"), set())

    def test_every_vagaris_pattern_matches_a_real_path(self):
        # Bound to vagaris 8c518807's tree, like vps-ansible above. This repo is PUBLIC and vagaris is private, so
        # the fixture is NOT the whole tree: it is exactly the vagaris paths the entry's non-default patterns match,
        # generated by `git -C <vagaris> ls-tree -r --name-only 8c518807c2 -- docker/docker-compose.override.yml`.
        # The default ci-judge patterns are carried VERBATIM (root 2026-10-23); `.github/actions/**` has no match
        # in vagaris today and stays so a future action is covered the day it lands.
        paths = (ROOT / "trusted" / "tests" / "fixtures" / "vagaris-8c518807.paths").read_text().split()
        self.assertEqual(paths, ["docker/docker-compose.override.yml"])
        default = {pat for p in manifest()["default"]["protected"] for pat in p["patterns"]}
        entry = manifest()["repos"]["vagarylabs/vagaris"]
        for p in entry["protected"]:
            for pat in p["patterns"]:
                if pat in default or judge_witnessed(pat):
                    continue
                with self.subTest(pattern=pat):
                    self.assertTrue(any(classify.fnmatch.fnmatchcase(x, pat) for x in paths))

    def test_vagaris_keeps_the_default_and_protects_tenant_zero_identity(self):
        # D16 §7 (spine, root 2026-10-23): VAGARIS_PROVIDER_COMPANY_ID is a literal in
        # docker/docker-compose.override.yml and names tenant zero, which holds GitHub source access and
        # execution-grant provider authority. A change to it is an authority change.
        entry = manifest()["repos"]["vagarylabs/vagaris"]
        default = {pat for p in manifest()["default"]["protected"] for pat in p["patterns"]}
        ci_judge = {pat for p in entry["protected"] if p["class"] == "ci-judge" for pat in p["patterns"]}
        self.assertLessEqual(default, ci_judge)
        expect = {
            "docker/docker-compose.override.yml": "authority-binding",
            ".github/workflows/pr.yml": "ci-judge",
            ".gitleaks.toml": "ci-judge",
            ".github/actions/setup/action.yml": "ci-judge",
        }
        for path, cls in expect.items():
            with self.subTest(path=path):
                self.assertIn(cls, classify.classes_for(entry, path))
        self.assertEqual(classify.classes_for(entry, "docker/docker-compose.yml"), set())
        self.assertEqual(classify.classes_for(entry, "server/src/index.ts"), set())

    def test_the_shared_signer_and_its_tests_are_protected_in_dotgithub(self):
        # D2 (root, R4 of .github #62): the signing trust root is whoever can merge sign-image.yml to main of this
        # repository, so the workflow and its tests are a protected path (authority-binding) on top of the default
        # ci-judge patterns, which this profile carries verbatim. A GitHub required approval cannot be the control:
        # every agent acts as the one VagaryLabs-Main account. This repository is where the paths live, so they must
        # exist here, not only in a fixture.
        m = manifest()
        entry = classify.repo_entry(m, "vagarylabs/.github")
        self.assertIsNot(entry, m["default"])
        default = {pat for p in m["default"]["protected"] for pat in p["patterns"]}
        ci_judge = {pat for p in entry["protected"] if p["class"] == "ci-judge" for pat in p["patterns"]}
        self.assertLessEqual(default, ci_judge)
        for path in (".github/workflows/sign-image.yml", "trusted/tests/test_sign_image.py"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
                self.assertIn("authority-binding", classify.classes_for(entry, path))
        # The signer, then the judge's own files (root ruling B2a, R4 of .github #69), and nothing else: the manifest
        # patterns and classify.BLOCKING_PATHS are the same list, so neither mechanism can drift from the other.
        binding = [pat for p in entry["protected"] if p["class"] == "authority-binding" for pat in p["patterns"]]
        self.assertEqual(binding, [".github/workflows/sign-image.yml", "trusted/tests/test_sign_image.py"]
                         + list(SignerBlockingTests.JUDGE))
        self.assertEqual(set(binding), classify.BLOCKING_PATHS)
        # nothing else this repository holds becomes authority-binding
        for other in ("trusted/tests/test_weakening.py", "trusted/inline_scripts.py", "README.md",
                      "trusted/templates/trusted-secret-scan.yml.in"):
            self.assertEqual(classify.classes_for(entry, other), set(), other)
        integrity = ".github/workflows/trusted-workflow-integrity.yml"
        self.assertEqual(classify.classes_for(entry, integrity), {"ci-judge"})
        # a PR that edits the signer is classified, with the class the protected-paths check reports
        rows = classify.classify(entry, [("M", ".github/workflows/sign-image.yml"), ("M", "README.md")])
        self.assertEqual(rows, [("M", ".github/workflows/sign-image.yml", ["authority-binding", "ci-judge"])])

    def test_unlisted_repo_gets_default(self):
        entry = classify.repo_entry(manifest(), "vagarylabs/vagaris")
        self.assertEqual(classify.classes_for(entry, ".github/workflows/ci.yml"), {"ci-judge"})
        self.assertEqual(classify.classes_for(entry, "server/src/app.ts"), set())


class DecisionTests(unittest.TestCase):
    def test_verifier_is_not_yet_available(self):
        self.assertEqual(classify.verify_vagaris_approval("r", "0" * 40, ["iac"]), "not-yet-available")
        self.assertTrue(classify.INTERIM_REPORT_ONLY)

    def test_interim_reports_without_blocking(self):
        code, msg = classify.protected_decision(["iac"], "not-yet-available", interim=True)
        self.assertEqual(code, 0)
        self.assertIn("INTERIM", msg)

    def test_fail_closed_after_switch(self):
        for verdict in ("not-yet-available", "missing", "denied", "anything-else"):
            with self.subTest(verdict=verdict):
                self.assertEqual(classify.protected_decision(["iac"], verdict, interim=False)[0], 1)
        self.assertEqual(classify.protected_decision(["iac"], "verified", interim=False)[0], 0)
        self.assertEqual(classify.protected_decision([], "not-required", interim=False)[0], 0)


class SignerBlockingTests(unittest.TestCase):
    """D2: a change to the shared signer, or to the protected-paths judge's own files (B2a), blocks, whatever
    INTERIM_REPORT_ONLY says.

    WHAT THESE PROVE LOCALLY: the decision LOGIC of classify.py (which paths block, that the blocking ignores the
    interim flag, that a diff cannot argue its way out by also editing the workflow or the classifier, that only a
    "verified" verdict opens the in-band door). WHAT THEY CANNOT PROVE: that the copy of classify.py that runs in CI
    is not the PR's. Every test here runs the classifier from THIS checkout. Only the org/repo ruleset's `workflows`
    rule, pinned to a vagarylabs/.github main sha, makes the workflow bytes (and the classifier inlined in them) the
    trusted ones; that is a live-state fact for root to verify on the ruleset, not a unit-test fact. Likewise (b) proves
    the wiring of the FUTURE in-band door with a stub; today verify_vagaris_approval returns "not-yet-available" and
    the legitimate door is out-of-band (root lifts the ruleset, merges with R4, restores the pin).
    """
    SIGNER = ".github/workflows/sign-image.yml"
    TESTS = "trusted/tests/test_sign_image.py"
    REPO = "vagarylabs/.github"
    # Root ruling B2a: the workflow whose pinned bytes run, every file it is rendered from, render.py, and this file
    # (it holds the drift tests: WorkflowTests.test_generated_workflows_are_current and
    # test_inline_copies_are_byte_identical).
    JUDGE = (".github/workflows/trusted-protected-paths.yml", "trusted/templates/trusted-protected-paths.yml.in",
             "trusted/templates/_shas.yml.in", "trusted/templates/_resolve_shas.yml.in", "trusted/classify.py",
             "trusted/manifest.json", "trusted/render.py", "trusted/tests/test_trusted.py",
             "trusted/tests/test_merge_result.py")

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = cls.tmp.name
        git(cls.d, "init", "-q", "-b", "main")
        git(cls.d, "config", "user.email", "t@example.invalid")
        git(cls.d, "config", "user.name", "t")
        cls.write({cls.SIGNER: "name: sign-image\n", cls.TESTS: "# t\n", "README.md": "r\n",
                   ".github/workflows/trusted-protected-paths.yml": "name: p\n", "trusted/classify.py": "X = 1\n"})
        git(cls.d, "add", "-A")
        git(cls.d, "commit", "-q", "-m", "base")
        cls.base = git(cls.d, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def write(cls, files):
        for p, text in files.items():
            pathlib.Path(cls.d, p).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(cls.d, p).write_text(text)

    def head_with(self, files):
        git(self.d, "checkout", "-q", "-B", "pr", self.base)
        self.write(files)
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "pr")
        return git(self.d, "rev-parse", "HEAD")

    def check(self, head):
        out, cwd = io.StringIO(), os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        try:
            os.chdir(self.d)
            git(self.d, "update-ref", "refs/remotes/origin/main", self.base)  # the live base, as the checkout has it
            with contextlib.redirect_stdout(out):
                code = classify.main(["protected-paths", "--manifest", str(MANIFEST), "--repo", self.REPO,
                                      "--base", self.base, "--head", head, "--event", "pull_request",
                                      "--base-ref", "main"])
        finally:
            os.chdir(cwd)
        return code, out.getvalue()

    def test_a_signer_diff_is_red_under_the_interim_flag(self):
        self.assertTrue(classify.INTERIM_REPORT_ONLY)  # the repo-wide interim is untouched
        for path in (self.SIGNER, self.TESTS):
            with self.subTest(path=path):
                code, out = self.check(self.head_with({path: "changed\n"}))
                self.assertEqual(code, 1, out)
                self.assertIn("::error title=protected paths::BLOCKING", out)
                self.assertIn(path, out)

    def test_b_a_verified_approval_passes_the_future_in_band_door(self):
        # Proves the wiring only: with verify_vagaris_approval stubbed to "verified" the same diff passes. The real
        # verifier does not exist yet (G-23 seam), so today this door cannot open.
        head = self.head_with({self.SIGNER: "changed\n"})
        with mock.patch.object(classify, "verify_vagaris_approval", return_value="verified"):
            code, out = self.check(head)
        self.assertEqual(code, 0, out)
        for verdict in ("not-yet-available", "missing", "denied"):
            with self.subTest(verdict=verdict), mock.patch.object(classify, "verify_vagaris_approval",
                                                                  return_value=verdict):
                self.assertEqual(self.check(head)[0], 1)

    def test_c_unrelated_and_other_protected_paths_are_not_blocked(self):
        code, out = self.check(self.head_with({"README.md": "x\n", "docs/a.md": "y\n"}))
        self.assertEqual(code, 0, out)
        self.assertIn("no protected class touched", out)
        # another ci-judge path in this repo stays report-only under the interim
        code, out = self.check(self.head_with({".github/workflows/ci.yml": "name: ci\n"}))
        self.assertEqual(code, 0, out)
        self.assertIn("INTERIM report-only", out)

    def test_d_a_diff_that_also_edits_the_judge_is_still_red(self):
        # LOGIC ONLY: the verdict is a function of the changed PATHS, so editing the workflow or the classifier in the
        # same diff cannot lower it. That the PR's own copy of those files is not the one RUN is proven only by the
        # ruleset pin (see the class docstring), not here.
        head = self.head_with({self.SIGNER: "changed\n",
                               ".github/workflows/trusted-protected-paths.yml": "name: p\non: nothing\n",
                               "trusted/classify.py": "X = 2  # always pass\n"})
        code, out = self.check(head)
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING", out)

    def test_e_a_diff_to_any_one_of_the_judges_files_is_red(self):
        # B2a: the judge's bytes change only through the door, so a re-pin cannot adopt a judge change unseen.
        for path in self.JUDGE:
            with self.subTest(path=path):
                code, out = self.check(self.head_with({path: "changed\n"}))
                self.assertEqual(code, 1, out)
                self.assertIn("::error title=protected paths::BLOCKING: %s change the shared signer or the "
                              "protected-paths judge itself" % path, out)

    def test_the_blocking_set_is_exactly_the_signer_and_the_judge(self):
        self.assertEqual(classify.BLOCKING_PATHS, {self.SIGNER, self.TESTS} | set(self.JUDGE))
        entry = classify.repo_entry(manifest(), self.REPO)
        self.assertEqual(classify.blocking_rows(classify.classify(
            entry, [("M", self.SIGNER), ("M", "trusted/classify.py"), ("M", "README.md"),
                    ("M", ".github/workflows/ci.yml")])),
            [("M", self.SIGNER, ["authority-binding", "ci-judge"]),
             ("M", "trusted/classify.py", ["authority-binding"])])
        # a path outside the set never blocks even if some profile classes it authority-binding
        self.assertEqual(classify.blocking_rows([("M", "docker/docker-compose.override.yml", ["authority-binding"])]), [])

    def test_the_blocking_set_names_every_file_the_judge_is_rendered_from(self):
        # A new INCLUDE or INLINE in the judge's template must join the blocking set (and the manifest), or the next
        # re-pin adopts its bytes unseen. Every path in the set is a real file of this repository.
        inputs, todo = set(), [render.TEMPLATES / "trusted-protected-paths.yml.in"]
        while todo:
            t = todo.pop()
            inputs.add(str(t.relative_to(ROOT)))
            for line in t.read_text(encoding="utf-8").splitlines():
                m = render.DIRECTIVE.match(line)
                if m and m["kind"] == "INCLUDE":
                    todo.append(render.TEMPLATES / m["path"])
                elif m:
                    inputs.add(m["path"])
        # plus the regression tests of what the judge classifies (B1, N1, N2, merge_group)
        inputs |= {str(WORKFLOWS["trusted-protected-paths"].relative_to(ROOT)), "trusted/render.py",
                   str(pathlib.Path(__file__).resolve().relative_to(ROOT)), "trusted/tests/test_merge_result.py"}
        self.assertEqual(inputs, set(self.JUDGE))
        self.assertLessEqual(inputs, classify.BLOCKING_PATHS)
        for path in classify.BLOCKING_PATHS:
            self.assertTrue((ROOT / path).is_file(), path)
        # this file holds the drift tests that bind the inline copies to their sources
        self.assertTrue(callable(getattr(WorkflowTests, "test_generated_workflows_are_current")))
        self.assertTrue(callable(getattr(WorkflowTests, "test_inline_copies_are_byte_identical")))

    def test_mutant_that_drops_the_blocking_turns_the_red_assertions_green(self):
        # The discriminator: with blocking_rows neutered, the signer diff passes (code 0), so test (a) and (d) above,
        # which assert code 1, would fail. A mutant of the blocking therefore cannot go unnoticed.
        head = self.head_with({self.SIGNER: "changed\n"})
        self.assertEqual(self.check(head)[0], 1)
        with mock.patch.object(classify, "blocking_rows", lambda rows: []):
            self.assertEqual(self.check(head)[0], 0)
        with mock.patch.object(classify, "BLOCKING_CLASS", "no-such-class"):
            self.assertEqual(self.check(head)[0], 0)


class RatchetTests(unittest.TestCase):
    def test_constant_diff_without_execution(self):
        base = classify.ratchet_constants("A = 1\nB = 'x'\nC: str = 'c'\ndef f():\n    D = 2\n", "b")
        head = classify.ratchet_constants("A = 2\nC: str = 'c'\nE = (1,)\nraise SystemExit(9)\n", "h")
        self.assertEqual(classify.diff_constants(base, head),
                         {"added": ["E"], "removed": ["B"], "changed": ["A"]})

    def test_unparsable_is_integrity_error(self):
        with self.assertRaises(classify.IntegrityError):
            classify.ratchet_constants("A = (\n", "h")


def git(cwd, *args):
    return subprocess.run(("git",) + args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class EndToEndTests(unittest.TestCase):
    """One throwaway repo: base commit, then a PR head that edits a workflow, a role and the ratchet."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.d = cls.tmp.name
        git(d, "init", "-q", "-b", "main")
        git(d, "config", "user.email", "t@example.invalid")
        git(d, "config", "user.name", "t")
        files = {".github/workflows/ci.yml": "name: ci\n", "roles/a/tasks/main.yml": "- x\n",
                 "scripts/test-ci-hosted-routing.py": "PIN = 'a'\nKEEP = 1\n", "README.md": "r\n"}
        for p, t in files.items():
            pathlib.Path(d, p).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(d, p).write_text(t)
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "base")
        cls.base = git(d, "rev-parse", "HEAD")
        pathlib.Path(d, ".github/workflows/ci.yml").write_text("name: ci\non: push\n")
        pathlib.Path(d, "roles/a/tasks/main.yml").unlink()
        pathlib.Path(d, "scripts/test-ci-hosted-routing.py").write_text("PIN = 'b'\nKEEP = 1\nNEW = 2\n")
        pathlib.Path(d, "README.md").write_text("changed\n")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "head")
        cls.head = git(d, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_mode(self, mode, base=None, head=None):
        out = io.StringIO()
        cwd = os.getcwd()
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        extra = []
        if mode == "protected-paths":  # the live base, as the checkout has it
            git(self.d, "update-ref", "refs/remotes/origin/main", base or self.base)
            extra = ["--event", "pull_request", "--base-ref", "main"]
        try:
            os.chdir(self.d)
            with contextlib.redirect_stdout(out):
                code = classify.main([mode, "--manifest", str(MANIFEST), "--repo", "vagarylabs/vps-ansible",
                                      "--base", base or self.base, "--head", head or self.head] + extra)
        finally:
            os.chdir(cwd)
        return code, out.getvalue()

    def test_integrity_reports_against_base(self):
        code, out = self.run_mode("integrity")
        self.assertEqual(code, 0, out)
        self.assertIn("PROTECTED-PATH CHANGE `.github/workflows/ci.yml` M (ci-judge)", out)
        self.assertIn("PROTECTED-PATH CHANGE `roles/a/tasks/main.yml` D (iac)", out)
        self.assertIn("RATCHET CONSTANT CHANGED `PIN`", out)
        self.assertIn("RATCHET CONSTANT ADDED `NEW`", out)
        self.assertNotIn("KEEP", out)
        self.assertNotIn("README", out)

    def test_protected_paths_interim_passes_with_report(self):
        code, out = self.run_mode("protected-paths")
        self.assertEqual(code, 0, out)
        self.assertIn("::notice title=protected paths::INTERIM report-only", out)
        self.assertIn("ci-judge, iac", out)

    def test_protected_paths_fails_closed_after_switch(self):
        old = classify.INTERIM_REPORT_ONLY
        classify.INTERIM_REPORT_ONLY = False
        try:
            code, out = self.run_mode("protected-paths")
        finally:
            classify.INTERIM_REPORT_ONLY = old
        self.assertEqual(code, 1, out)

    def test_no_protected_change_passes(self):
        code, out = self.run_mode("protected-paths", head=self.base)
        self.assertEqual(code, 0)
        self.assertIn("no protected class touched", out)

    def test_bad_or_unknown_sha_is_integrity_error(self):
        for bad in ("HEAD", "main", "f" * 40):
            with self.subTest(sha=bad):
                self.assertEqual(self.run_mode("integrity", head=bad)[0], 2)


class WorkflowTests(unittest.TestCase):
    def test_generated_workflows_are_current(self):
        # The inline classifier/manifest are byte-identical copies of the trusted/ sources.
        self.assertEqual(render.main(["--check"]), 0)

    def test_inline_copies_are_byte_identical(self):
        # Every copy: trusted-workflow-integrity carries two (its integrity and timeout-floor jobs).
        src = (ROOT / "trusted" / "classify.py").read_text()
        # trusted-workflow-integrity: integrity, timeout-floor and workflow-lint (C1) each write the trusted bytes.
        for name, copies in (("trusted-workflow-integrity", 3), ("trusted-protected-paths", 1)):
            text = WORKFLOWS[name].read_text()
            found = list(re.finditer(
                r"\n( *)cat > \"\$d/classify.py\" <<'TRUSTED_CLASSIFY_PY'\n(.*?)\n\1TRUSTED_CLASSIFY_PY\n", text, re.S))
            self.assertEqual(len(found), copies, name)
            for m in found:
                indent = m.group(1)
                body = "\n".join(l[len(indent):] if l.startswith(indent) else l for l in m.group(2).split("\n"))
                self.assertEqual(body + "\n", src, name)

    def test_invariants(self):
        for name, path in WORKFLOWS.items():
            text = path.read_text()
            with self.subTest(workflow=name):
                self.assertNotIn("pull_request_target", text)
                self.assertNotIn("secrets.", text)
                self.assertNotIn("vars.", text)
                self.assertIn("\non:\n  pull_request:\n  merge_group:\n", text)
                self.assertIn("\npermissions:\n  contents: read\n  pull-requests: read\n\njobs:", text)
                jobs = re.findall(r"\n    runs-on: (.*)\n", text)
                self.assertTrue(jobs)
                bridge = "[self-hosted, Linux, X64, vl-light]"
                if name == "trusted-protected-paths":
                    # the ONE hosted exception: only in the public vagarylabs/.github, the bridge everywhere else
                    self.assertEqual(jobs, ['${{ fromJSON(github.repository == \'vagarylabs/.github\' && \'"ubuntu-latest"\' || \'["self-hosted","Linux","X64","vl-light"]\') }}'])
                    self.assertEqual(text.count("ubuntu-latest"), 2)  # the runs-on line, and its comment
                else:
                    self.assertNotIn("ubuntu-latest", text)
                    self.assertEqual(set(jobs), {bridge})
                # D2: trusted-protected-paths judges vagarylabs/.github too (no guard); the others still skip it.
                guards = 0 if name == "trusted-protected-paths" else len(jobs)
                self.assertEqual(text.count("if: github.repository != 'vagarylabs/.github'"), guards)
                self.assertEqual(text.count("persist-credentials: false"), len(jobs))
                for use in re.findall(r"uses: (\S+)", text):
                    self.assertRegex(use, r"@[0-9a-f]{40}$")

    def actionlint_job(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        return ci.split("\n  actionlint:\n", 1)[1].split("\n  planner-tests:\n", 1)[0]

    def test_ci_reports_the_inline_script_sizes_and_never_re_enables_shellcheck_for_them(self):
        job = self.actionlint_job()
        # Each workflow's largest INLINE run script is printed to the step summary on every run, next to the limit.
        self.assertIn('python3 -I trusted/inline_scripts.py sizes "${inline[@]}"', job)
        self.assertIn('>> "$GITHUB_STEP_SUMMARY"', job)
        # The two inline-classifier workflows stay off actionlint's shellcheck integration (the deadlock), and the
        # warning that says so stays with them, with what was reproduced and what is inferred.
        self.assertIn('"$lint" -color -shellcheck= "${inline[@]}"', job)
        self.assertIn("Do NOT re-enable the shellcheck", job)
        self.assertIn("REPRODUCED on 1.7.12 only", job)
        self.assertIn("On 1.7.7 the hang is INFERRED", job)
        self.assertNotIn("coverage is equal", job)

    def test_the_required_actionlint_job_gates_the_trust_root_scripts_on_shellcheck(self):
        # The required job runs the shellcheck test itself, by its exact name, with a missing shellcheck a failure.
        job = self.actionlint_job()
        self.assertIn("TRUSTED_REQUIRE_SHELLCHECK=1 python3 -m unittest -v \\\n"
                      "            test_trusted.WorkflowTests.test_inline_workflow_run_scripts_pass_shellcheck", job)
        test = getattr(WorkflowTests, "test_inline_workflow_run_scripts_pass_shellcheck")
        self.assertTrue(callable(test))

    def test_missing_shellcheck_fails_only_when_required(self):
        for env, failed, skipped in (({"TRUSTED_REQUIRE_SHELLCHECK": "1"}, 1, 0), ({}, 0, 1)):
            with self.subTest(env=env), mock.patch.object(shutil, "which", return_value=None), \
                    mock.patch.dict(os.environ, env, clear=False):
                if not env:
                    os.environ.pop("TRUSTED_REQUIRE_SHELLCHECK", None)
                result = unittest.TestResult()
                WorkflowTests("test_inline_workflow_run_scripts_pass_shellcheck").run(result)
                self.assertEqual((len(result.failures), len(result.skipped), result.testsRun), (failed, skipped, 1))

    def test_inline_script_sizes_are_the_largest_inline_run_scripts(self):
        names = [str(WORKFLOWS[n].relative_to(ROOT)) for n in ("trusted-workflow-integrity", "trusted-protected-paths")]
        r = subprocess.run([sys.executable, "-I", str(ROOT / "trusted" / "inline_scripts.py"), "sizes"] + names,
                           cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in names:
            size = inline_scripts.largest((ROOT / name).read_text())
            self.assertGreater(size, len((ROOT / "trusted" / "classify.py").read_bytes()))  # the inline copy, not the source
            self.assertIn("- `%s`: largest inline run script %d bytes (the shellcheck stdin pipe buffer is 65536)"
                          % (name, size), r.stdout)

    def test_ci_scans_this_repo_with_the_timeout_floor(self):
        # The ruleset's trusted job skips this repo, so the floor sees it only through this self-scan.
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("\n  timeout-floor-self-scan:\n", ci)
        job = ci.split("\n  timeout-floor-self-scan:\n", 1)[1].split("\n  trusted-tests:\n", 1)[0]
        self.assertIn("python3 -I trusted/classify.py timeout-floor --manifest trusted/manifest.json", job)
        self.assertIn('--repo "$GITHUB_REPOSITORY"', job)
        # The head commit alone: the mode reads only the head tree (the PR head, not the default merge commit).
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}\n          fetch-depth: 1\n", job)
        self.assertNotIn("fetch-depth: 0", job)
        self.assertNotIn("--base", job)
        self.assertNotIn("vagarylabs/.github'", job)  # no repository guard: this job exists for this repo

    def test_inline_workflow_run_scripts_pass_shellcheck(self):
        # ci.yml lints these two with actionlint -shellcheck=: actionlint fills shellcheck's stdin before starting it,
        # and their classifier run scripts are over the 64 KiB pipe buffer. This is that shellcheck pass on the same
        # scripts (inline_scripts.run_scripts), through a pipe that is read while it is written. The REQUIRED actionlint
        # job runs this test with TRUSTED_REQUIRE_SHELLCHECK=1, so shellcheck gates the trust-root scripts there and a
        # missing shellcheck fails it; elsewhere (trusted-tests, a laptop) a missing shellcheck skips.
        sc = shutil.which("shellcheck")
        if not sc:
            if os.environ.get("TRUSTED_REQUIRE_SHELLCHECK") == "1":
                self.fail("shellcheck is not on PATH and TRUSTED_REQUIRE_SHELLCHECK=1: the trust-root run scripts "
                          "must be shellchecked")
            self.skipTest("shellcheck is not on PATH")
        sizes = []
        for name in ("trusted-workflow-integrity", "trusted-protected-paths"):
            scripts = inline_scripts.run_scripts(WORKFLOWS[name].read_text())
            self.assertGreaterEqual(len(scripts), 3, name)
            for i, script in enumerate(scripts):
                self.assertNotIn("$" + "{{", script)
                sizes.append(len(script.encode()))
                with self.subTest(workflow=name, script=i):
                    r = subprocess.run([sc, "--norc", "--shell=bash", "-"], input=script, capture_output=True, text=True,
                                       timeout=120)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertGreater(max(sizes), 65536)  # the reason for the split in ci.yml; drop it if this ever fails

    def test_tool_pins_match_release_assets_lock(self):
        lock = {}
        for line in (ROOT / "release-assets.lock").read_text().splitlines():
            if line and not line.startswith("#"):
                tool, version, _url, sha = line.split()
                lock[(tool, version)] = sha
        text = WORKFLOWS["trusted-secret-scan"].read_text()
        for tool in ("GITLEAKS", "TRUFFLEHOG"):
            v = re.search(tool + r'_VERSION: "([^"]+)"', text).group(1)
            s = re.search(tool + r'_SHA256: "([0-9a-f]{64})"', text).group(1)
            self.assertEqual(lock[(tool.lower(), v)], s, tool)


if __name__ == "__main__":
    unittest.main()
