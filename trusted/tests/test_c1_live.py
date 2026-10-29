"""Live vectors for C1 workflow-lint (root's R4 of #41, B1): the REAL zizmor and actionlint, run with the exact flags the
rendered trusted-workflow-integrity.yml uses, cannot be quietened by anything a PR controls:
- a `.github/zizmor.yml` that disables a rule;
- an inline `# zizmor: ignore[...]` comment;
- a `.gitignore` that lists the bad workflow;
- a `.github/actionlint.yaml` that ignores everything.

A workflow zizmor cannot parse fails the run, and the trusted actionlint config knows the org's runner labels. ci.yml's
actionlint job fetches both tools (release-assets.lock) and runs this file with C1_REQUIRE_TOOLS=1, so there a missing
binary is a failure, not a skip. Elsewhere it runs when C1_ZIZMOR / C1_ACTIONLINT name the binaries.
"""
import json
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml"
INJECTION = ("name: t\non: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n"
             "    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n")
UNDEFINED = ("name: t\non: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n"
             "    steps:\n      - run: echo \"${{ steps.missing.outputs.x }}\"\n")


def tool_flags(tool):
    """The flags the rendered workflow passes to `tool`, joined across shell line continuations."""
    run = WORKFLOW.read_text().split("- name: Run zizmor and actionlint over the head tree", 1)[1]
    text = re.sub(r"\\\n\s*", " ", run)
    m = re.search(r'timeout 120 "\$t/%s" (.*?) >' % tool, text)
    if not m:
        raise AssertionError("no %s invocation in %s" % (tool, WORKFLOW.name))
    return shlex.split(m.group(1))


def binary(env):
    path = os.environ.get(env)
    if path and pathlib.Path(path).is_file():
        return path
    if os.environ.get("C1_REQUIRE_TOOLS") == "1":
        raise AssertionError("%s does not name a binary and C1_REQUIRE_TOOLS=1" % env)
    return None


class LiveVectors(unittest.TestCase):
    def setUp(self):
        self.zizmor, self.actionlint = binary("C1_ZIZMOR"), binary("C1_ACTIONLINT")
        if not (self.zizmor and self.actionlint):
            self.skipTest("C1_ZIZMOR / C1_ACTIONLINT not set (ci.yml's actionlint job runs these with C1_REQUIRE_TOOLS=1)")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def repo(self, files):
        root = pathlib.Path(tempfile.mkdtemp(dir=self.temp.name))
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        subprocess.run(["git", "init", "-q", str(root)], check=True, env=env)
        subprocess.run(["git", "-C", str(root), "add", "-A", "-f"], check=True, env=env)
        return root

    def zizmor_run(self, root):
        env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        out = subprocess.run([self.zizmor, *tool_flags("zizmor"), "."], cwd=root, capture_output=True, text=True,
                             env=env, timeout=120)
        return out.returncode, (json.loads(out.stdout) if out.returncode == 0 else None)

    def actionlint_run(self, root):
        flags = [str(ROOT / "trusted" / "actionlint.yaml") if f == "$d/actionlint.yaml" else f
                 for f in tool_flags("actionlint")]
        out = subprocess.run([self.actionlint, *flags], cwd=root, capture_output=True, text=True, timeout=120)
        return out.returncode, json.loads(out.stdout or "null")

    def idents(self, root):
        rc, doc = self.zizmor_run(root)
        self.assertEqual(rc, 0, "zizmor failed")
        return [f["ident"] for f in doc]

    def test_zizmor_finds_the_injection_whatever_the_pr_configures(self):
        bad = {".github/workflows/bad.yml": INJECTION}
        self.assertIn("template-injection", self.idents(self.repo(bad)), "control: the injection is a finding")
        for why, extra in (
                ("a .github/zizmor.yml disabling the rule", {".github/zizmor.yml": "rules:\n  template-injection:\n    disable: true\n"}),
                ("a zizmor.yml at the root", {"zizmor.yml": "rules:\n  template-injection:\n    disable: true\n"}),
                ("an inline ignore comment", {".github/workflows/bad.yml": INJECTION.replace(
                    'title }}"', 'title }}" # zizmor: ignore[template-injection]')}),
                ("a .gitignore listing the workflow", {".gitignore": ".github/workflows/bad.yml\n"})):
            with self.subTest(why):
                self.assertIn("template-injection", self.idents(self.repo({**bad, **extra})), why)

    def test_a_workflow_zizmor_cannot_parse_fails_the_run(self):
        # Beside a parsable workflow, an unparsable one would be skipped quietly; --strict-collection fails the run.
        rc, _ = self.zizmor_run(self.repo({".github/workflows/ok.yml": INJECTION, ".github/workflows/bad.yml": "name: t\non: [\n"}))
        self.assertNotEqual(rc, 0, "--strict-collection: an unparsable input is a failure, never a skipped file")

    def test_actionlint_reads_only_the_trusted_config(self):
        bad = {".github/workflows/bad.yml": UNDEFINED}
        rc, doc = self.actionlint_run(self.repo(bad))
        self.assertEqual(rc, 1)
        self.assertTrue(doc, "control: the undefined step output is a finding")
        ignore_all = {".github/actionlint.yaml": "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n      - \".*\"\n"}
        rc, doc = self.actionlint_run(self.repo({**bad, **ignore_all}))
        self.assertEqual(rc, 1, "the PR's .github/actionlint.yaml must not ignore the finding")
        self.assertTrue(doc)

    def test_the_org_runner_labels_are_known_and_an_unregistered_one_is_a_finding(self):
        wf = ("name: t\non: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: [self-hosted, Linux, X64, %s]\n"
              "    timeout-minutes: 10\n    steps:\n      - run: echo hi\n")
        rc, doc = self.actionlint_run(self.repo({".github/workflows/ok.yml": wf % "vl-light"}))
        self.assertEqual((rc, doc), (0, []), "vl-light is a registered org label")
        rc, doc = self.actionlint_run(self.repo({".github/workflows/dead.yml": wf % "vl-c1-capped"}))
        self.assertEqual(rc, 1)
        self.assertEqual([e["kind"] for e in doc], ["runner-label"])

    def test_a_clean_workflow_is_clean_in_both(self):
        clean = {".github/workflows/ok.yml": UNDEFINED.replace("${{ steps.missing.outputs.x }}", "hi")}
        root = self.repo(clean)
        self.assertEqual(self.idents(root), [])
        self.assertEqual(self.actionlint_run(root), (0, []))


if __name__ == "__main__":
    unittest.main()
