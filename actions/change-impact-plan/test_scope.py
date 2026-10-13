"""Immutable scope controls; real Git objects, no provider credentials or network."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import plan as P


class FrozenScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "candidate"
        self.root.mkdir()
        self.git("init", "-q")
        self.cfg = {"schema": 1, "workspace": {"type": "declared", "packages": {
            "server": {"dir": "server", "deps": []}, "ui": {"dir": "ui", "deps": []}}},
            "hub_packages": ["server"], "inert_globs": ["docs/**"],
            "jobs": {"server_tests": "full_only", "ui_tests": {"packages": ["ui"]}}}
        for directory in ("server", "ui", "docs", ".github"):
            (self.root / directory).mkdir()
        self.config = self.root / ".github/ci-plan.json"
        self.config.write_text(json.dumps(self.cfg))
        for name in ("server/a.py", "ui/a.ts", "docs/readme.md"):
            (self.root / name).write_text("before\n")
        self.git("add", ".")
        self.base = self.git("commit-tree", self.git("write-tree"), input=b"base\n")
        self.make_candidate("server/a.py", "runtime change\n")

    def git(self, *args, input=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(["git", *args], cwd=self.root, env=env,
                                       input=input, stderr=subprocess.PIPE).decode().strip()

    def make_candidate(self, path, text):
        self.git("reset", "--hard", self.base)
        (self.root / path).write_text(text)
        self.git("add", "--", path)
        tree = self.git("write-tree")
        self.head = self.git("commit-tree", tree, "-p", self.base, input=b"head\n")
        self.candidate = self.git("commit-tree", tree, "-p", self.base, "-p", self.head, input=b"merge\n")
        self.git("reset", "--hard", self.candidate)

    def scope(self, **changes):
        args = dict(event="pull_request", base=self.base, head=self.head,
                    candidate=self.candidate, repository="fixture/repo")
        args.update(changes)
        return P.immutable_scope(self.root, **args)

    def cli_plan(self, **changes):
        scope = dict(event="pull_request", base=self.base, head=self.head, candidate=self.candidate)
        scope.update(changes)
        # A sparse, trusted-base policy checkout is separate from candidate files.
        policy = Path(self.temp.name) / "base"
        policy.mkdir(exist_ok=True)
        (policy / ".github").mkdir(exist_ok=True)
        (policy / ".github/ci-plan.json").write_text(json.dumps(self.cfg))
        stale_paths = Path(self.temp.name) / "ci-plan-paths.txt"
        stale_paths.write_text("docs/readme.md\n")
        output = Path(self.temp.name) / "plan.json"
        arguments = ["--config", ".github/ci-plan.json", "--root", str(policy),
                     "--scope-root", str(self.root), "--repository", "fixture/repo",
                     "--paths-file", str(stale_paths), "--tested-root", str(self.root),
                     "--out-json", str(output)]
        for key, value in scope.items():
            arguments += ["--" + key, value]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(arguments), 0)
        return json.loads(output.read_text())

    def test_invalid_matrix_reference_publishes_no_plan_or_reduction_outputs(self):
        self.make_candidate("ui/a.ts", "UI change\n")
        self.cfg["matrices"] = {"tests": [{"include": {"group": "missing"},
                                           "rule": {"packages": ["undeclared"]}}]}
        policy = Path(self.temp.name) / "policy"
        (policy / ".github").mkdir(parents=True)
        (policy / ".github/ci-plan.json").write_text(json.dumps(self.cfg))
        plan_file, github_output = Path(self.temp.name) / "new-plan.json", Path(self.temp.name) / "github-output"
        args = ["--config", ".github/ci-plan.json", "--root", str(policy), "--scope-root", str(self.root),
                "--repository", "fixture/repo", "--event", "pull_request", "--base", self.base,
                "--head", self.head, "--candidate", self.candidate, "--out-json", str(plan_file),
                "--github-output", str(github_output)]
        with self.assertRaisesRegex(ValueError, "undeclared package"), contextlib.redirect_stdout(io.StringIO()):
            P.main(args)
        self.assertFalse(plan_file.exists())
        self.assertFalse(github_output.exists())


    def test_same_count_later_push_cannot_replace_frozen_candidate_scope(self):
        old_head, old_candidate = self.head, self.candidate
        self.git("update-ref", "refs/heads/mutable-pr", self.head)
        self.make_candidate("docs/readme.md", "later one-file docs change\n")
        self.git("update-ref", "refs/heads/mutable-pr", self.head)
        self.head, self.candidate = old_head, old_candidate
        self.git("reset", "--hard", old_candidate)
        result = self.cli_plan()
        self.assertEqual(result["mode"], "full")
        self.assertTrue(result["jobs"]["server_tests"]["run"])
        self.assertEqual(result["evidence"]["changed_packages"], ["server"])
        self.assertEqual(result["observation"]["candidate"], old_candidate)

    def test_odd_paths_are_lossless_and_hash_has_no_newline_collision(self):
        name = "ui/ odd\nname.ts "
        self.make_candidate(name, "change\n")
        self.assertEqual(self.scope()["paths"], [name])
        result = self.cli_plan()
        self.assertEqual(result["mode"], "reduced")
        expected = P.hashlib.sha256(json.dumps([name], separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result["inputs"]["paths_sha256"], expected)
        split = P.hashlib.sha256(json.dumps(name.splitlines(), separators=(",", ":")).encode()).hexdigest()
        self.assertNotEqual(expected, split)

    def test_missing_or_mismatched_objects_cannot_authorize_reduction(self):
        for change in ({"base": ""}, {"base": "0" * 40}, {"base": "f" * 40},
                       {"head": self.base}, {"candidate": self.head}, {"repository": ""},
                       {"event": "pull_request_target"}):
            value = self.scope(**change)
            self.assertEqual(value["status"], "unknown", change)
            self.assertIsNone(value["paths"])
        self.assertEqual(self.cli_plan(head=self.base)["mode"], "full")

    def test_merge_group_and_push_bind_candidate(self):
        for event in ("merge_group", "push"):
            self.assertEqual(self.scope(event=event, head=self.candidate)["status"], "known")
            self.assertEqual(self.scope(event=event)["status"], "unknown")
            self.assertEqual(self.cli_plan(event=event, head=self.candidate)["mode"], "full")

    def test_candidate_policy_edit_cannot_reduce_its_own_plan(self):
        malicious = {**self.cfg, "inert_globs": ["server/**", ".github/**"], "hub_packages": []}
        self.make_candidate(".github/ci-plan.json", json.dumps(malicious))
        result = self.cli_plan()
        self.assertEqual(result["mode"], "full")
        self.assertTrue(result["jobs"]["server_tests"]["run"])
        self.assertEqual(result["validity"]["config_sha256"],
                         P.hashlib.sha256(json.dumps(self.cfg).encode()).hexdigest())

    def test_git_failure_does_not_emit_credential_stderr(self):
        error = subprocess.CalledProcessError(1, ["git"], stderr=b"SECRET_REMOTE_TOKEN")
        with patch.object(P.subprocess, "check_output", side_effect=error):
            value = self.scope()
        self.assertEqual(value["status"], "unknown")
        self.assertNotIn("SECRET_REMOTE_TOKEN", json.dumps(value))

    def test_replace_refs_cannot_reinterpret_candidate_or_base(self):
        expected = self.scope()
        # A replacement candidate keeps the same claimed parents, but substitutes
        # a harmless docs tree. The real candidate still changes server/a.py.
        self.git("reset", "--hard", self.base)
        (self.root / "docs/readme.md").write_text("replacement tree\n")
        self.git("add", ".")
        replacement = self.git("commit-tree", self.git("write-tree"), "-p", self.base,
                               "-p", self.head, input=b"replacement\n")
        self.git("reset", "--hard", self.candidate)
        self.git("replace", self.candidate, replacement)
        self.assertEqual(self.scope(), expected)
        self.git("replace", "-d", self.candidate)
        # Replacing the base with the candidate's tree would erase the diff.
        replacement = self.git("commit-tree", self.git("rev-parse", self.candidate + "^{tree}"),
                               input=b"replacement base\n")
        self.git("replace", self.base, replacement)
        self.assertEqual(self.scope(), expected)

    def test_foreign_git_environment_cannot_redirect_observation(self):
        expected = self.scope()
        foreign = Path(self.temp.name) / "foreign.git"
        self.git("init", "--bare", "-q", str(foreign))
        with patch.dict(os.environ, {
            "GIT_DIR": str(foreign), "GIT_WORK_TREE": str(foreign),
            "GIT_OBJECT_DIRECTORY": str(foreign / "objects"),
            "GIT_INDEX_FILE": str(foreign / "index"), "GIT_COMMON_DIR": str(foreign),
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.abbrev", "GIT_CONFIG_VALUE_0": "1",
        }):
            self.assertEqual(self.scope(), expected)

    def test_summary_write_failure_publishes_no_reduction_outputs(self):
        self.make_candidate("ui/a.ts", "UI change\n")
        output = Path(self.temp.name) / "github-output"
        args = ["--config", ".github/ci-plan.json", "--root", str(self.root),
                "--scope-root", str(self.root), "--repository", "fixture/repo",
                "--event", "pull_request", "--base", self.base, "--head", self.head,
                "--candidate", self.candidate, "--github-output", str(output),
                "--summary", str(self.root)]  # A directory cannot be an appendable summary.
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            P.main(args)
        self.assertFalse(output.exists())

    def test_plan_id_binds_candidate_and_repository(self):
        first = self.cli_plan()
        second = self.cli_plan()
        self.assertEqual(first["plan_id"], second["plan_id"])
        identity = self.scope()
        value = P.plan(cfg=self.cfg, root=self.root, config_path=self.config,
                       paths=identity["paths"], event="pull_request", base=self.base,
                       head=self.head, expected_count=None, scope={**identity, "repository": "different/repo"})
        self.assertNotEqual(first["plan_id"], value["plan_id"])


class ActionContract(unittest.TestCase):
    def test_action_has_no_mutable_path_api_or_stale_receipt_input(self):
        text = (Path(__file__).parent / "action.yml").read_text()
        self.assertNotIn("/pulls/", text)
        self.assertNotIn("--paths-file", text)
        self.assertNotIn("--receipt", text)
        self.assertIn("--scope-root", text)
        self.assertIn("mktemp -d", text)
        self.assertIn("Remove attempt-local inputs", text)
        self.assertIn("github.event.merge_group.head_sha", text)
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertLess(text.index("    - name: Assess immutable readers"), text.index("    - name: Plan\n"))
        self.assertNotIn("--fallback-config", text)

    def test_reader_failure_or_disable_widens_before_any_plan_output(self):
        action = (Path(__file__).parent / "action.yml").read_text()
        step = action.split("    - name: Assess immutable readers against the trusted base policy\n", 1)[1].split("    - name: Plan\n", 1)[0]
        body = textwrap.dedent(step.split("      run: |\n", 1)[1])
        self.assertIn('--force-full-reason "$FORCE_FULL_REASON"', action)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base/.github").mkdir(parents=True)
            # A malformed graph causes the REAL checker to refuse; not a fake
            # pass or a simulation of GitHub's scheduler.
            (root / "base/.github/ci-plan.json").write_text('{"workspace":{"type":"unsupported"}}')
            for enabled in ("true", "false"):
                output = root / (enabled + "-output")
                env = dict(os.environ, CONFIG=".github/ci-plan.json", STATE=str(root),
                           GITHUB_WORKSPACE=str(root), CANDIDATE_ROOT=".", CANDIDATE="a" * 40,
                           EDGE_CHECK=enabled, GITHUB_ACTION_PATH=str(Path(__file__).parent), GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-eu", "-c", body], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                reason = output.read_text().strip().split("=", 1)[1]
                self.assertTrue(reason)
                cfg = {"workspace": {"type": "declared", "packages": {"ui": {"dir": "ui"}}},
                       "jobs": {"server": "full_only"}}
                full = P.plan(cfg=cfg, root=root, config_path=root / "base/.github/ci-plan.json",
                              paths=["ui/a.ts"], event="pull_request", base="b", head="h", expected_count=None,
                              forced_full_reason=reason)
                self.assertEqual(full["mode"], "full")
                self.assertTrue(full["jobs"]["server"]["run"])


if __name__ == "__main__":
    unittest.main()
