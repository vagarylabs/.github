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
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402
import render  # noqa: E402

MANIFEST = ROOT / "trusted" / "manifest.json"
FIXTURE = ROOT / "trusted" / "tests" / "fixtures" / "vps-ansible-c0ff73ea.paths"
WORKFLOWS = {n: ROOT / ".github" / "workflows" / (n + ".yml")
             for n in ("trusted-secret-scan", "trusted-workflow-integrity", "trusted-protected-paths",
                       "trusted-code-scan")}


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
        # A pattern that matches nothing fails OPEN silently; bind each one to vps-ansible c0ff73ea's tree.
        paths = FIXTURE.read_text().split()
        self.assertGreater(len(paths), 2000)
        entry = manifest()["repos"]["vagarylabs/vps-ansible"]
        for p in entry["protected"]:
            for pat in p["patterns"]:
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
        src = (ROOT / "trusted" / "classify.py").read_text()
        for name in ("trusted-workflow-integrity", "trusted-protected-paths"):
            text = WORKFLOWS[name].read_text()
            m = re.search(r"\n( *)cat > \"\$d/classify.py\" <<'TRUSTED_CLASSIFY_PY'\n(.*?)\n\1TRUSTED_CLASSIFY_PY\n",
                          text, re.S)
            self.assertIsNotNone(m, name)
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

    def test_tool_pins_match_release_assets_lock(self):
        lock = {}
        for line in (ROOT / "release-assets.lock").read_text().splitlines():
            if line and not line.startswith("#"):
                tool, version, _url, sha = line.split()
                lock[(tool, version)] = sha
        for wf, tool, name in (("trusted-secret-scan", "GITLEAKS", "gitleaks"),
                               ("trusted-secret-scan", "TRUFFLEHOG", "trufflehog"),
                               ("trusted-code-scan", "OSV", "osv-scanner")):
            text = WORKFLOWS[wf].read_text()
            v = re.search(tool + r'_VERSION: "([^"]+)"', text).group(1)
            s = re.search(tool + r'_SHA256: "([0-9a-f]{64})"', text).group(1)
            self.assertEqual(lock[(name, v)], s, tool)


if __name__ == "__main__":
    unittest.main()
