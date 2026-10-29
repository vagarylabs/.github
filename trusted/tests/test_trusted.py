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
        try:
            os.chdir(self.d)
            with contextlib.redirect_stdout(out):
                code = classify.main([mode, "--manifest", str(MANIFEST), "--repo", "vagarylabs/vps-ansible",
                                      "--base", base or self.base, "--head", head or self.head])
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
        for name, copies in (("trusted-workflow-integrity", 2), ("trusted-protected-paths", 1)):
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
                self.assertNotIn("ubuntu-latest", text)
                self.assertNotIn("vars.", text)
                self.assertIn("\non:\n  pull_request:\n  merge_group:\n", text)
                self.assertIn("\npermissions:\n  contents: read\n  pull-requests: read\n\njobs:", text)
                jobs = re.findall(r"\n    runs-on: (.*)\n", text)
                self.assertTrue(jobs)
                self.assertEqual(set(jobs), {"[self-hosted, Linux, X64, vl-light]"})
                self.assertEqual(text.count("if: github.repository != 'vagarylabs/.github'"), len(jobs))
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
