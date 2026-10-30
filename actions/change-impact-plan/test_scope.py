"""Immutable scope controls; real Git objects, no provider credentials or network."""
import contextlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import plan as P
import edges as E


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
            "jobs": {"server_tests": "full_only", "ui_tests": {"packages": ["ui"]}}, "test_jobs": {"ui_tests": ["ui"]}}
        for directory in ("server", "ui", "docs", ".github"):
            (self.root / directory).mkdir()
        self.config = self.root / ".github/ci-plan.json"
        self.config.write_text(json.dumps(self.cfg))
        # ui/a.test.ts: 1.7.0 refuses to narrow on an empty test inventory, so the fixture owns one test file.
        for name in ("server/a.py", "ui/a.ts", "ui/a.test.ts", "docs/readme.md"):
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
        # A separate trusted-base policy checkout at the exact base, verified by the planner (v1.4).
        number = getattr(self, "policy_number", 0) + 1
        self.policy_number = number
        policy = Path(self.temp.name) / f"policy-{number}"
        self.git("clone", "--quiet", "--no-checkout", "--no-hardlinks", str(self.root), str(policy))
        self.git("-C", str(policy), "reset", "--quiet", "--hard", self.base)
        stale_paths = Path(self.temp.name) / "ci-plan-paths.txt"
        stale_paths.write_text("docs/readme.md\n")
        output = Path(self.temp.name) / "plan.json"
        arguments = ["--config", ".github/ci-plan.json", "--root", str(policy),
                     "--scope-root", str(self.root), "--repository", "fixture/repo",
                     "--paths-file", str(stale_paths), "--tested-root", str(self.root),
                     "--out-json", str(output), "--repository-id", "101", "--repository-owner-id", "202"]
        if (policy / ".github/ci-plan.json").is_file():
            assessment = Path(self.temp.name) / f"readers-pr-{self.policy_number}.json"
            with contextlib.redirect_stdout(io.StringIO()):
                E.main(["check", "--config", str(policy / ".github/ci-plan.json"), "--repo", str(self.root),
                        "--manifest-root", str(policy), "--revision", scope["candidate"], "--out-json", str(assessment)])
            arguments += ["--reader-assessment", str(assessment)]
        for key, value in scope.items():
            arguments += ["--" + key, value]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(arguments), 0)
        return json.loads(output.read_text())

    def invalid_matrix_args(self):
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
        return args, plan_file, github_output

    def commit_tree(self, files: dict) -> str:
        """A candidate on self.base whose tree changes `files` (path -> text, or None to delete); returns the PR head."""
        self.git("reset", "--hard", self.base)
        for path, text in files.items():
            target = self.root / path
            if text is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
        self.git("add", "-A")
        tree = self.git("write-tree")
        self.head = self.git("commit-tree", tree, "-p", self.base, input=b"head\n")
        self.candidate = self.git("commit-tree", tree, "-p", self.base, "-p", self.head, input=b"merge\n")
        self.git("reset", "--hard", self.candidate)
        return self.head

    def test_the_f29_deadlock_ends_full_never_red_forever(self):
        # root's F29 vector: (1) a change REMOVING ui's declaration entry is now RED in its own run (judged by its own
        # config); (2) were such a removal on main anyway (an override), the change RESTORING it plans FULL and lands.
        removed = json.loads(json.dumps(self.cfg)); removed["test_jobs"] = {}
        self.commit_tree({".github/ci-plan.json": json.dumps(removed)})
        with self.assertRaisesRegex(ValueError, "the tests of ui"):
            self.cli_plan()
        self.base = self.head  # the wedged base: its declaration has the gap
        self.commit_tree({".github/ci-plan.json": json.dumps(self.cfg), "ui/a.test.ts": "it('restored', () => {});\n"})
        rec = self.cli_plan()
        self.assertEqual(rec["mode"], "full")
        self.assertIn("(F29)", rec["reason"])
        self.assertEqual(rec["config_check"]["candidate_errors"], [])

    def test_a_change_introducing_an_incomplete_declaration_is_red(self):
        # The base declares nothing; the change adds a declaration that leaves ui's tests uncovered. The inventory is read
        # because the CANDIDATE declares, so the change is red before it lands (else it would wedge main, F29).
        bare = json.loads(json.dumps(self.cfg)); del bare["test_jobs"]
        self.commit_tree({".github/ci-plan.json": json.dumps(bare)})
        self.base = self.head
        incomplete = json.loads(json.dumps(bare)); incomplete["test_jobs"] = {"server_tests": ["server"]}
        self.commit_tree({".github/ci-plan.json": json.dumps(incomplete)})
        with self.assertRaisesRegex(ValueError, "the tests of ui"):
            self.cli_plan()

    def test_a_new_package_with_its_tests_and_its_declaration_lands_in_one_change(self):
        # The base's graph does not know the package, so its tests are outside every package there (the base cannot
        # narrow: FULL); the candidate's own graph and declaration cover them, so the change is not red.
        grown = json.loads(json.dumps(self.cfg))
        grown["workspace"]["packages"]["api"] = {"dir": "api", "deps": []}
        grown["jobs"]["api_tests"] = {"packages": ["api"]}
        grown["test_jobs"]["api_tests"] = ["api"]
        self.commit_tree({".github/ci-plan.json": json.dumps(grown), "api/a.py": "x = 1\n", "api/test_a.py": "def test_a(): pass\n"})
        rec = self.cli_plan()
        self.assertEqual(rec["mode"], "full")
        self.assertEqual(rec["config_check"]["candidate_errors"], [])
        # Without its declaration the same change is red: the candidate's graph owns the tests and nothing runs them.
        undeclared = json.loads(json.dumps(grown)); del undeclared["test_jobs"]["api_tests"]
        self.commit_tree({".github/ci-plan.json": json.dumps(undeclared), "api/a.py": "x = 1\n", "api/test_a.py": "def test_a(): pass\n"})
        with self.assertRaisesRegex(ValueError, "the tests of api"):
            self.cli_plan()

    def test_a_change_repairing_an_invalid_base_config_plans_full_instead_of_red(self):
        # F29 (root's ruling, 2026-10-30): the base's config is broken, the candidate's own config is valid; red would
        # wedge main forever (the fix itself is judged by the broken base), so the plan is FULL and the fix can land.
        self.make_candidate("ui/a.ts", "UI change\n")
        args, plan_file, _ = self.invalid_matrix_args()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(args), 0)
        rec = json.loads(plan_file.read_text())
        self.assertEqual(rec["mode"], "full")
        self.assertIn("this change's own config is valid and complete, so it plans FULL and can land (F29)", rec["reason"])
        self.assertEqual(rec["config_check"]["red_decided_by"], "candidate")
        self.assertEqual(rec["config_check"]["candidate_errors"], [])
        self.assertTrue(any("undeclared package" in e for e in rec["config_check"]["base_errors"]))

    def test_invalid_matrix_reference_publishes_no_plan_or_reduction_outputs(self):
        # The candidate's OWN config is the invalid one, so the change is red before it can land.
        invalid = json.loads(json.dumps(self.cfg))
        invalid["matrices"] = {"tests": [{"include": {"group": "missing"}, "rule": {"packages": ["undeclared"]}}]}
        self.make_candidate(".github/ci-plan.json", json.dumps(invalid))
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

    def test_the_test_inventory_is_read_from_the_candidate_commit(self):
        # 1.7.0: the candidate adds a ui test file the base does not have; the plan's inventory holds it, so it was read
        # from the candidate's tree (the scope root at the candidate), not from the trusted-base policy checkout.
        self.make_candidate("ui/a.test.ts", "it('runs', () => {});\n")
        with patch.object(P, "candidate_test_files", wraps=P.candidate_test_files) as read:
            result = self.cli_plan()
        # This fixture's policy clone holds the candidate commit too, so pin the root the inventory is read from.
        self.assertEqual([(call.args[0], call.args[1]) for call in read.call_args_list], [(self.root, self.candidate)])
        self.assertEqual(result["mode"], "reduced", result["reason"])
        self.assertEqual(result["test_inventory"]["files"], 1)
        self.assertEqual(result["test_inventory"]["packages"]["ui"]["covered_by"], ["ui_tests"])

    def test_a_candidate_test_file_no_unit_runs_is_red_before_any_plan_is_published(self):
        self.make_candidate("docs/check.test.ts", "it('runs', () => {});\n")
        with self.assertRaisesRegex(ValueError, r"1 test file\(s\) outside every package run in no always-unit's "
                                    r"declared paths, e\.g\. docs/check\.test\.ts"):
            self.cli_plan()


    def canonical_plan(self, target=None, observation_changes=None, final_target=None, context_changes=None,
                       policy_change=None, checkout="success", with_readers=False, reader_change=None):
        target = target or self.base
        number = getattr(self, "policy_number", 0) + 1
        self.policy_number = number
        policy = Path(self.temp.name) / f"canonical-policy-{number}"
        self.git("clone", "--quiet", "--no-checkout", "--no-hardlinks", str(self.root), str(policy))
        self.git("-C", str(policy), "reset", "--hard", target)
        if policy_change:
            policy_change(policy)
        context = dict(repository="fixture/repo", event_repository="fixture/repo", target_ref="refs/heads/main",
                       server_url="https://github.com", candidate=self.candidate, run_id="41", run_attempt="1")
        with patch.object(P, "canonical_target", return_value=target):
            observation = P.resolve_target_observation(**context)
        observation.update(observation_changes or {})
        context.update(context_changes or {})
        observation_file = Path(self.temp.name) / f"target-{number}.json"
        observation_file.write_text(json.dumps(observation))
        output = Path(self.temp.name) / f"canonical-plan-{number}.json"
        args = ["--config", ".github/ci-plan.json", "--root", str(policy), "--scope-root", str(self.root),
                "--event", "merge_group", "--base", self.base, "--head", self.candidate, "--out-json", str(output),
                "--target-observation", str(observation_file), "--policy-checkout-outcome", checkout]
        for key, value in context.items():
            args += ["--" + key.replace("_", "-"), value]
        if with_readers and (policy / ".github/ci-plan.json").is_file():
            assessment_file = Path(self.temp.name) / f"readers-{number}.json"
            with contextlib.redirect_stdout(io.StringIO()):
                E.main(["check", "--config", str(policy / ".github/ci-plan.json"), "--repo", str(self.root),
                        "--manifest-root", str(policy), "--revision", self.candidate, "--out-json", str(assessment_file)])
            if reader_change:
                record = json.loads(assessment_file.read_text())
                reader_change(record)
                record["assessment_sha256"] = P.canonical_digest({k: v for k, v in record.items() if k != "assessment_sha256"})
                assessment_file.write_text(json.dumps(record))
            args += ["--reader-assessment", str(assessment_file)]
        remote = final_target if final_target is not None else target
        with patch.object(P, "canonical_target", side_effect=remote if isinstance(remote, Exception) else None,
                          return_value=None if isinstance(remote, Exception) else remote) as final_read, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(args), 0)
        return json.loads(output.read_text()), final_read.call_count

    def test_cumulative_impact_is_known_but_legacy_jobs_remain_full(self):
        target = self.base
        prefix = self.candidate
        self.base = prefix
        self.make_candidate("docs/readme.md", "docs tail\n")
        result, _ = self.canonical_plan(target, with_readers=True)
        impact = result["impact"]
        self.assertEqual(result["mode"], "full")
        self.assertTrue(result["requires_full_caller_roster"])
        self.assertTrue(all(job["run"] for job in result["jobs"].values()))
        self.assertEqual(impact["schema"], 1)
        self.assertEqual(impact["status"], "known")
        self.assertIs(impact["selection_authority"], False)
        self.assertEqual(impact["affected_packages"], ["server"])
        self.assertEqual(impact["affected_hubs"], ["server"])
        self.assertEqual(impact["identity"]["diff_base"], target)
        self.assertNotEqual(impact["identity"]["diff_base"], prefix)
        self.assertEqual(impact["readers"]["status"], "matched")
        self.assertEqual(impact["readers"]["coverage"], "supported-static-readers-only")
        self.assertFalse(result["reuse"]["reused"])

    def test_no_reader_assessment_is_unknown_not_empty_impact(self):
        result, _ = self.canonical_plan()
        self.assertEqual(result["impact"]["status"], "unknown")
        self.assertIsNone(result["impact"]["affected_packages"])
        self.assertEqual(result["mode"], "full")

    def test_rehashed_reader_identity_or_roster_tampering_is_unknown(self):
        for key, value in (("revision", self.head), ("policy_config_sha256", "0" * 64),
                           ("graph_sha256", "0" * 64), ("scanner_source_sha256", "0" * 64),
                           ("deps", {}), ("deps", None), ("readers", []), ("failures", None),
                           # 1.5.0: `imports` maps each imported path to a sorted, non-empty list of known packages.
                           ("imports", None), ("imports", []), ("imports", {"scripts/x.mjs": []}),
                           ("imports", {"scripts/x.mjs": ["not-a-package"]}), ("imports", {"scripts/x.mjs": ["ui", "server"]})):
            with self.subTest(key=key):
                result, _ = self.canonical_plan(with_readers=True, reader_change=lambda record: record.update({key: value}))
                self.assertEqual(result["impact"]["status"], "unknown")
                self.assertIsNone(result["impact"]["affected_packages"])
                self.assertTrue(all(job["run"] for job in result["jobs"].values()))

    def test_rehashed_reader_directory_deletion_or_unexpected_keys_cannot_claim_known_impact(self):
        self.git("reset", "--hard", self.base)
        self.cfg["edge_scan"] = {"reader_dirs": ["scripts"], "reader_job": "server_tests"}
        self.config.write_text(json.dumps(self.cfg)); self.git("add", ".")
        self.base = self.git("commit-tree", self.git("write-tree"), "-p", self.base, input=b"trusted reader directory\n")
        self.make_candidate("ui/a.ts", "UI change\n")
        result, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["impact"]["status"], "known")
        for reader_map in ({}, {"scripts": [], "unexpected": []}, {"scripts": None},
                           {"scripts": [], "<unmapped>": ["ui"]}):
            with self.subTest(reader_map=reader_map):
                # canonical_plan recomputes the real assessment hash after this mutation.
                result, _ = self.canonical_plan(with_readers=True,
                    reader_change=lambda record: record.update(readers=reader_map))
                self.assertEqual(result["impact"]["status"], "unknown")
                self.assertIsNone(result["impact"]["affected_packages"])
                self.assertEqual(result["mode"], "full")
                self.assertTrue(all(job["run"] for job in result["jobs"].values()))
        result, _ = self.canonical_plan(with_readers=True,
            reader_change=lambda record: record["readers"].update({"<unmapped>": []}))
        self.assertEqual(result["impact"]["status"], "known")

    def test_cumulative_impact_uses_real_declared_reader_reverse_closure(self):
        self.git("reset", "--hard", self.base)
        self.cfg["workspace"]["packages"]["server"]["deps"] = ["ui"]
        self.config.write_text(json.dumps(self.cfg))
        (self.root / "server/a.py").write_text('open("../ui/a.ts")\n')
        self.git("add", ".")
        self.base = self.git("commit-tree", self.git("write-tree"), "-p", self.base, input=b"trusted reader edge\n")
        self.make_candidate("ui/a.ts", "changed UI\n")
        result, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["impact"]["affected_packages"], ["server", "ui"])
        self.assertEqual(result["impact"]["status"], "known")
        # Remove the real declaration, retaining the actual read: the SAME edge scanner refuses it.
        self.git("reset", "--hard", self.base)
        self.cfg["workspace"]["packages"]["server"]["deps"] = []
        self.config.write_text(json.dumps(self.cfg)); self.git("add", ".")
        self.base = self.git("commit-tree", self.git("write-tree"), "-p", self.base, input=b"missing declared edge\n")
        self.make_candidate("ui/a.ts", "changed UI again\n")
        result, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["impact"]["status"], "unknown")
        self.assertEqual(result["impact"]["readers"]["status"], "unmatched")
        self.assertIsNone(result["impact"]["affected_packages"])

    def test_global_unmapped_and_moved_target_never_claim_empty_known_impact(self):
        for path in (".github/ci-plan.json", "unmapped.txt"):
            text = self.config.read_text() + "\n" if path.endswith("ci-plan.json") else "unknown\n"
            self.make_candidate(path, text)
            result, _ = self.canonical_plan(with_readers=True)
            impact = result["impact"]
            self.assertEqual(impact["status"], "unknown")
            self.assertIsNone(impact["affected_packages"])
            self.assertTrue(impact["global_inputs"] or impact["unmapped_inputs"])
        result, _ = self.canonical_plan(with_readers=True, final_target=self.head)
        self.assertEqual(result["impact"]["status"], "unknown")
        self.assertIsNone(result["impact"]["affected_packages"])

    def test_only_proven_inert_cumulative_paths_can_have_known_empty_impact(self):
        self.make_candidate("docs/readme.md", "docs only\n")
        result, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["impact"]["status"], "known")
        self.assertEqual(result["impact"]["affected_packages"], [])
        self.assertEqual(result["mode"], "full")
        self.git("reset", "--hard", self.base)
        self.config.unlink(); self.git("add", "-A")
        self.base = self.git("commit-tree", self.git("write-tree"), "-p", self.base, input=b"no trusted policy\n")
        self.make_candidate("docs/readme.md", "no policy tail\n")
        result, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["impact"]["status"], "unknown")
        self.assertIsNone(result["impact"]["affected_packages"])

    def test_impact_is_in_plan_id_domain_and_stable_for_same_inputs(self):
        result, _ = self.canonical_plan(with_readers=True)
        same, _ = self.canonical_plan(with_readers=True)
        self.assertEqual(result["plan_id"], same["plan_id"])
        for key, value in (("affected_packages", []), ("graph", {"sha256": "0" * 64}),
                           ("readers", {"status": "unknown"}), ("identity", {}), ("status", "unknown")):
            altered = json.loads(json.dumps(result)); altered["impact"][key] = value
            P.bind_plan_id(altered)
            self.assertNotEqual(altered["plan_id"], result["plan_id"])

    def test_action_passes_same_attempt_reader_assessment_without_reuse_activation(self):
        action = Path(P.__file__).with_name("action.yml").read_text()
        self.assertIn('--out-json "$STATE/readers.json"', action)
        self.assertIn('--reader-assessment "$STATE/readers.json"', action)
        self.assertNotIn('--receipt ', action)

    def test_canonical_target_includes_runtime_prefix_when_event_base_is_docs_predecessor(self):
        target = self.base
        prefix = self.candidate
        self.base = prefix
        self.make_candidate("docs/readme.md", "docs tail\n")
        result, reads = self.canonical_plan(target)
        self.assertEqual(reads, 1, "final lookup must independently re-resolve")
        self.assertEqual(result["mode"], "full")
        self.assertEqual(result["inputs"]["changed_paths"], 2)
        self.assertEqual(result["inputs"]["base"], prefix)
        self.assertEqual(result["observation"]["diff_base"], target)
        self.assertEqual(result["observation"]["target_rechecked_sha"], target)
        self.assertEqual(result["observation"]["scope_kind"], "canonical-target-cumulative")
        self.assertEqual(result["observation"]["target_source"], "canonical-git-ls-remote")
        self.assertEqual(result["observation"]["status"], "known")

    def test_target_policy_not_predecessor_or_candidate_config_is_used(self):
        target = self.base
        # A VALID but narrower candidate config (server_tests removed): F29 lets it decide only RED vs FULL, never the
        # plan's selection, which stays the trusted target's (F14).
        malicious = json.loads(json.dumps(self.cfg)); malicious["jobs"] = {"ui_tests": {"packages": ["ui"]}}
        self.make_candidate(".github/ci-plan.json", json.dumps(malicious))
        self.base = self.candidate
        self.make_candidate("docs/readme.md", "docs tail\n")
        result, _ = self.canonical_plan(target)
        expected_blob = self.git("rev-parse", target + ":.github/ci-plan.json")
        self.assertEqual(result["observation"]["policy_blob"], expected_blob)
        self.assertEqual(result["observation"]["policy_revision"], target)
        self.assertTrue(result["jobs"]["server_tests"]["run"])

    def test_target_observation_identity_replay_and_forgery_are_unknown_full(self):
        for change in ({"repository": "foreign/repo"}, {"target_ref": "refs/heads/other"},
                       {"run_id": "40"}, {"run_attempt": "2"}, {"candidate": self.head},
                       {"source_sha256": "0" * 64}, {"target_sha": "0" * 40}, {"target_sha": "f" * 40}):
            with self.subTest(change=change):
                result, reads = self.canonical_plan(observation_changes=change)
                self.assertEqual(result["mode"], "full")
                self.assertEqual(result["observation"]["status"], "unknown")
                self.assertEqual(reads, 0)
                self.assertTrue(result["requires_full_caller_roster"])

    def test_moved_or_unreadable_final_target_discards_known_scope_without_repinning(self):
        for answer in (self.candidate, subprocess.CalledProcessError(1, ["git"], stderr=b"PRIVATE_TOKEN")):
            result, reads = self.canonical_plan(final_target=answer)
            self.assertEqual(reads, 1)
            self.assertEqual(result["mode"], "full")
            self.assertEqual(result["observation"]["status"], "unknown")
            self.assertEqual(result["jobs"], {})
            self.assertNotIn("PRIVATE_TOKEN", json.dumps(result))

    def test_failed_or_tampered_policy_checkout_never_supplies_a_plan(self):
        result, _ = self.canonical_plan(checkout="failure", policy_change=lambda root:
                                      (root / ".github/ci-plan.json").write_text("{ malformed partial policy"))
        self.assertEqual(result["observation"]["status"], "unknown")
        self.assertEqual(result["jobs"], {})
        result, _ = self.canonical_plan(policy_change=lambda root:
                                      (root / ".github/ci-plan.json").write_text('{"schema":1,"jobs":{}}'))
        self.assertEqual(result["observation"]["status"], "unknown")
        self.assertEqual(result["jobs"], {})

    def test_canonical_git_reader_is_isolated_and_rejects_ambiguous_or_queue_refs(self):
        def fake_git(command, **kwargs):
            self.assertNotIn("GIT_DIR", kwargs["env"])
            self.assertNotIn("GIT_WORK_TREE", kwargs["env"])
            self.assertNotIn("PRIVATE_TOKEN", " ".join(command))
            if "init" in command:
                self.assertIn("--bare", command); self.assertIn("--template=", command)
                return b""
            return (self.base + "\trefs/heads/main\n").encode()
        with patch.dict(os.environ, GIT_DIR="/foreign", GIT_WORK_TREE="/foreign", GH_TOKEN="PRIVATE_TOKEN"), \
                patch.object(P.subprocess, "check_output", side_effect=fake_git):
            self.assertEqual(P.canonical_target("fixture/repo", "refs/heads/main", "https://github.com"), self.base)
        for answer in (b"", (self.base + "\trefs/heads/main\n") .encode() * 2,
                       ("0" * 40 + "\trefs/heads/main\n").encode()):
            with patch.object(P.subprocess, "check_output", return_value=answer):
                with self.assertRaises(ValueError):
                    P.canonical_target("fixture/repo", "refs/heads/main", "https://github.com")
        with patch.object(P.subprocess, "check_output") as git:
            for ref in ("refs/heads/gh-readonly-queue/main/pr-1", "refs/tags/main", "refs/heads/../main"):
                with self.assertRaises(ValueError):
                    P.canonical_target("fixture/repo", ref, "https://github.com")
            git.assert_not_called()


    def test_known_docs_cumulative_scope_and_missing_policy_still_run_full(self):
        self.make_candidate("docs/readme.md", "docs only\n")
        result, _ = self.canonical_plan()
        self.assertEqual(result["observation"]["status"], "known")
        self.assertEqual(result["inputs"]["changed_paths"], 1)
        self.assertEqual(result["mode"], "full")
        self.git("reset", "--hard", self.base)
        self.config.unlink(); self.git("add", "-A")
        self.base = self.git("commit-tree", self.git("write-tree"), "-p", self.base, input=b"no policy\n")
        self.make_candidate("docs/readme.md", "tail without policy\n")
        result, _ = self.canonical_plan()
        self.assertEqual(result["observation"]["status"], "known")
        self.assertIsNone(result["observation"]["policy_blob"])
        self.assertTrue(result["requires_full_caller_roster"])
        self.assertEqual(result["jobs"], {})

    def test_diverged_target_and_wrong_policy_head_or_candidate_head_are_unknown(self):
        foreign = self.git("commit-tree", self.git("rev-parse", self.base + "^{tree}"), input=b"foreign root\n")
        result, _ = self.canonical_plan(target=foreign)
        self.assertEqual(result["observation"]["status"], "unknown")
        result, _ = self.canonical_plan(policy_change=lambda root: self.git("-C", str(root), "reset", "--hard", self.candidate))
        self.assertEqual(result["observation"]["status"], "unknown")
        self.git("reset", "--hard", self.head)
        result, _ = self.canonical_plan()
        self.assertEqual(result["observation"]["status"], "unknown")

    def test_isolated_real_cli_does_not_import_consumer_pythonpath_or_git_environment(self):
        poison = Path(self.temp.name) / "python-poison"; poison.mkdir()
        marker = Path(self.temp.name) / "consumer-imported"
        (poison / "json.py").write_text(f"from pathlib import Path; Path({str(marker)!r}).touch(); raise RuntimeError('PRIVATE_IMPORT')\n")
        output = Path(self.temp.name) / "isolated-plan.json"
        args = [sys.executable, "-I", P.__file__, "--config", ".github/ci-plan.json", "--root", str(self.root),
                "--scope-root", str(self.root), "--repository", "fixture/repo", "--event", "pull_request",
                "--base", self.base, "--head", self.head, "--candidate", self.candidate, "--out-json", str(output)]
        env = dict(os.environ, PYTHONPATH=str(poison), GIT_DIR="/foreign", GIT_WORK_TREE="/foreign")
        result = subprocess.run(args, cwd=poison, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(output.read_text())["observation"]["status"], "known")

    def test_action_snapshots_before_policy_checkout_and_isolates_python(self):
        action = Path(P.__file__).with_name("action.yml").read_text()
        self.assertLess(action.index("name: Freeze canonical target"), action.index("name: Base commit manifests"))
        self.assertIn("ref: ${{ steps.target.outputs.policy_ref }}", action)
        self.assertIn("continue-on-error: true", action)
        self.assertIn('--policy-checkout-outcome "$POLICY_OUTCOME"', action)
        self.assertIn('--target-observation "$STATE/target.json"', action)
        self.assertIn('python3 -I "$GITHUB_ACTION_PATH/plan.py"', action)
        self.assertIn('python3 -I "$GITHUB_ACTION_PATH/edges.py"', action)


    def test_absent_first_snapshot_and_skipped_checkout_are_unknown_full(self):
        with patch.object(P, "canonical_target", side_effect=subprocess.CalledProcessError(1, ["git"], stderr=b"PRIVATE_TOKEN")):
            observation = P.resolve_target_observation(repository="fixture/repo", event_repository="fixture/repo",
                target_ref="refs/heads/main", server_url="https://github.com", candidate=self.candidate,
                run_id="41", run_attempt="1")
        self.assertEqual(observation["status"], "unknown")
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(observation))
        result, reads = self.canonical_plan(observation_changes={"status": "unknown"})
        self.assertEqual(result["observation"]["status"], "unknown")
        self.assertEqual(reads, 0)
        result, reads = self.canonical_plan(checkout="skipped")
        self.assertEqual(result["observation"]["status"], "unknown")
        self.assertEqual(result["jobs"], {})


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

    def test_merge_group_requires_canonical_evidence_and_push_still_binds_candidate(self):
        self.assertEqual(self.scope(event="merge_group", head=self.candidate)["status"], "unknown")
        self.assertIsNone(self.scope(event="merge_group", head=self.candidate)["paths"])
        self.assertEqual(self.scope(event="push", head=self.candidate)["status"], "known")
        for event in ("merge_group", "push"):
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



class ConfigOutsideFullTriggers(unittest.TestCase):
    """F14 and F29 end to end through main(), with the plan config at a path no full trigger matches (root's #57 RC).
    At .github/ci-plan.json every config change is FULL by the builtin .github/** trigger, which hides whether selection
    reads the base or the candidate. Ported from the R4 reviewer's harness (vectors a1-a10)."""

    CFG = {"schema": 1, "workspace": {"type": "declared", "packages": {
        "server": {"dir": "server", "deps": []}, "ui": {"dir": "ui", "deps": []}}},
        "hub_packages": ["server"], "inert_globs": ["docs/**"],
        "jobs": {"server_tests": "full_only", "ui_tests": {"packages": ["ui"]}}, "test_jobs": {"ui_tests": ["ui"]}}
    FILES = {"server/a.py": "before\n", "ui/a.ts": "before\n", "ui/a.test.ts": "before\n", "docs/readme.md": "before\n"}

    def fixture(self, cfg, files=None, config_rel="ui/ci-plan.json", text=None):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp, self.config_rel, self.runs = Path(self.temp.name), config_rel, 0
        self.root = self.tmp / "candidate"
        self.root.mkdir()
        self.git("init", "-q")
        tree = dict(self.FILES if files is None else files)
        tree[config_rel] = text if text is not None else json.dumps(cfg)
        for path, body in tree.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text(body)
        self.git("add", "-A")
        self.base = self.git("commit-tree", self.git("write-tree"), input=b"base\n")
        self.git("reset", "-q", "--hard", self.base)

    def git(self, *args, input=None, cwd=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(["git", *args], cwd=cwd or self.root, env=env, input=input,
                                       stderr=subprocess.PIPE).decode().strip()

    def change(self, files):
        """The candidate merge(base, head), head = base plus `files` (path -> text, or None to delete)."""
        self.git("reset", "-q", "--hard", self.base)
        for path, body in files.items():
            if body is None:
                (self.root / path).unlink()
            else:
                (self.root / path).parent.mkdir(parents=True, exist_ok=True)
                (self.root / path).write_text(body)
        self.git("add", "-A")
        tree = self.git("write-tree")
        self.head = self.git("commit-tree", tree, "-p", self.base, input=b"head\n")
        self.candidate = self.git("commit-tree", tree, "-p", self.base, "-p", self.head, input=b"merge\n")
        self.git("reset", "-q", "--hard", self.candidate)

    def run_plan(self):
        """main() against a trusted-base policy checkout; the published plan, or the ValueError of a RED change."""
        self.runs += 1
        policy = self.tmp / f"policy-{self.runs}"
        self.git("clone", "--quiet", "--no-checkout", "--no-hardlinks", str(self.root), str(policy))
        self.git("-C", str(policy), "reset", "--quiet", "--hard", self.base)
        out = self.tmp / f"plan-{self.runs}.json"
        args = ["--config", self.config_rel, "--root", str(policy), "--scope-root", str(self.root),
                "--repository", "fixture/repo", "--tested-root", str(self.root), "--out-json", str(out),
                "--repository-id", "101", "--repository-owner-id", "202", "--event", "pull_request",
                "--base", self.base, "--head", self.head, "--candidate", self.candidate]
        if (policy / self.config_rel).is_file():
            # As action.yml's readers step: a reader check that fails (a broken base config can crash it) forces FULL;
            # it never stops the plan, so the candidate still decides RED.
            readers = self.tmp / f"readers-{self.runs}.json"
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    E.main(["check", "--config", str(policy / self.config_rel), "--repo", str(self.root),
                            "--manifest-root", str(policy), "--revision", self.candidate, "--out-json", str(readers)])
                args += ["--reader-assessment", str(readers)]
            except (Exception, SystemExit):  # noqa: BLE001 - any failure, exactly as the step's `if ! edges.py check`
                args += ["--force-full-reason", "reader closure unproven; full validation required"]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(P.main(args), 0)
        except ValueError as exc:
            self.assertFalse(out.exists(), "a RED change publishes no plan")
            return exc
        return json.loads(out.read_text())

    def assert_red(self, pattern):
        result = self.run_plan()
        self.assertIsInstance(result, ValueError, result if isinstance(result, ValueError) else result["reason"])
        self.assertRegex(str(result), pattern)

    def assert_mode(self, mode, reason, run):
        result = self.run_plan()
        self.assertIsInstance(result, dict, str(result))
        self.assertEqual((result["mode"], sorted(k for k, v in result["jobs"].items() if v["run"])), (mode, run),
                         result["reason"])
        self.assertRegex(result["reason"], reason)
        return result

    def land(self):
        self.base = self.head

    def test_a_glob_only_the_candidate_adds_never_fills_the_inventory_the_base_narrows_by_f14(self):
        # Root's #57 RC 1 (a1). The tree holds no conventional test file, so the base's inventory is empty.
        files = {"server/a.py": "before\n", "ui/a.ts": "before\n", "ui/check.sh": "run\n", "docs/readme.md": "before\n"}
        globbed = json.loads(json.dumps(self.CFG)); globbed["test_globs"] = ["ui/a.ts"]
        empty = "the candidate's test inventory is empty while a declaration exists: refused as unproven"
        self.fixture(self.CFG, files)
        self.change({"ui/a.ts": "x\n"})
        self.assert_mode("full", empty, ["server_tests", "ui_tests"])
        # The candidate's glob makes ui/a.ts a test of ui (covered, so not red), but cannot narrow its own plan.
        self.change({"ui/ci-plan.json": json.dumps(globbed), "ui/a.ts": "x\n"})
        self.assert_mode("full", empty, ["server_tests", "ui_tests"])
        # Positive control: the same glob on the BASE fills the inventory, and the same change narrows.
        self.fixture(globbed, files)
        self.change({"ui/a.ts": "x\n"})
        self.assert_mode("reduced", "affected: ui", ["ui_tests"])

    def test_a_glob_the_candidate_adds_is_an_obligation_and_a_glob_it_drops_still_binds_it(self):
        # The union of both configs' globs decides RED: an extra glob only adds obligations.
        self.fixture(self.CFG)
        added = json.loads(json.dumps(self.CFG)); added["test_globs"] = ["docs/*.check.sh"]
        self.change({"ui/ci-plan.json": json.dumps(added), "docs/x.check.sh": "run\n"})
        self.assert_red(r"1 test file\(s\) outside every package .*docs/x\.check\.sh")
        # The base's glob still binds the change that drops it (M12): ui's check files lose their unit in the same change.
        base = json.loads(json.dumps(self.CFG)); base["test_globs"] = ["ui/*.check.sh"]
        self.fixture(base, {**self.FILES, "ui/x.check.sh": "run\n"})
        dropped = json.loads(json.dumps(self.CFG)); dropped["test_jobs"] = {}
        self.change({"ui/ci-plan.json": json.dumps(dropped), "ui/a.test.ts": None})
        self.assert_red(r"the tests of ui \(1 file\(s\), e\.g\. ui/x\.check\.sh\)")

    def test_a_narrower_candidate_config_cannot_narrow_its_own_plan(self):
        # a9 (kills selection reading the candidate's config): the candidate drops the hub and changes the hub's code.
        self.fixture(self.CFG)
        unhubbed = json.loads(json.dumps(self.CFG)); unhubbed["hub_packages"] = []
        self.change({"ui/ci-plan.json": json.dumps(unhubbed), "server/a.py": "x\n"})
        result = self.assert_mode("full", "hub package affected: server", ["server_tests", "ui_tests"])
        self.assertEqual(result["config_check"], {"red_decided_by": "candidate", "base_errors": [], "candidate_errors": []})

    def test_a_narrower_candidate_graph_cannot_narrow_its_own_plan(self):
        # a10 (kills selection reading the candidate's graph): ui depends on lib; the candidate drops the edge, lib changes.
        cfg = {"schema": 1, "workspace": {"type": "declared", "packages": {
            "lib": {"dir": "lib", "deps": []}, "ui": {"dir": "ui", "deps": ["lib"]}}},
            "hub_packages": [], "inert_globs": ["docs/**"],
            "jobs": {"lib_tests": {"packages": ["lib"]}, "ui_tests": {"packages": ["ui"]}},
            "test_jobs": {"lib_tests": ["lib"], "ui_tests": ["ui"]}}
        self.fixture(cfg, {"lib/a.py": "x\n", "lib/test_a.py": "def test(): pass\n", "ui/a.ts": "x\n",
                           "ui/a.test.ts": "it()\n"}, config_rel="lib/ci-plan.json")
        cut = json.loads(json.dumps(cfg)); cut["workspace"]["packages"]["ui"]["deps"] = []
        self.change({"lib/ci-plan.json": json.dumps(cut), "lib/a.py": "y\n"})
        self.assert_mode("reduced", "affected: lib, ui", ["lib_tests", "ui_tests"])

    def test_a_malformed_candidate_config_is_red_and_a_change_repairing_a_malformed_base_plans_full(self):
        # Root's #57 RC 2 (a2): a JSON typo, or a config that is not an object, is red BEFORE it lands ...
        for text, words in ((json.dumps(self.CFG)[:-1], "the plan config is not valid JSON"),
                            ("[]", "the plan config is a JSON list, not an object")):
            with self.subTest(text=text[:12]):
                self.fixture(self.CFG)
                self.change({"ui/ci-plan.json": text})
                self.assert_red(words)
                # ... and were one on the base anyway, the valid repair plans FULL with no job list, so the caller runs
                # its complete roster (F29), instead of being red forever.
                self.fixture(None, text=text)
                self.change({"ui/ci-plan.json": json.dumps(self.CFG)})
                result = self.assert_mode("full", ".", [])
                self.assertTrue(result["requires_full_caller_roster"])
                self.assertEqual(result["config_check"], {"red_decided_by": "candidate", "base_errors": [
                    result["config_check"]["base_errors"][0]], "candidate_errors": []})
                self.assertIn(words, result["config_check"]["base_errors"][0])
                # An unrelated change on that base is still red: only the repair can land.
                self.change({"ui/a.ts": "x\n"})
                self.assert_red(words)

    def test_a_value_of_the_wrong_json_type_is_a_message_never_a_traceback(self):
        # Root's #57 RC 3 and 4 (a3, a5). Each broken config is red with a message as the candidate. As the base, its
        # valid repair plans FULL, and the base's error is the candidate's message: one rule reads both. (None: the
        # base's own error is that message; a string: the base never reaches the config check, and this is the reason.)
        def broken(**fields):
            cfg = json.loads(json.dumps(self.CFG)); cfg.update(fields)
            return json.dumps(cfg)
        cases = [
            (broken(jobs=["ui_tests"], test_jobs={}), r"the plan config has a value of the wrong type \(AttributeError", None),
            (broken(workspace="declared"), "the plan config's workspace is a JSON str, not an object",
             "workspace graph unreadable: workspace is a JSON str, not an object"),
            (broken(matrices={"m": [{"rule": "always"}]}), "invalid matrix entry", None),
            ('{"schema":1,"x":' + "[" * 100000 + "]" * 100000 + "}", "the plan config nests too deeply to parse", None),
            (broken(matrices=["general"]), "invalid job or matrix selection policy", None),
            # Fields only selection reads: a list extra_edges crashed classify_paths on the base (every change red, the
            # repair included), and a string hub_packages iterated as characters, so the hub never matched.
            (broken(extra_edges=["ui/**"]), "extra_edges must map a non-empty glob to a list of package names", None),
            (broken(hub_packages="server"), "hub_packages must be a list of non-empty strings", None),
            (broken(workspace={"type": "declared", "packages": {"server": {"deps": []}, "ui": {"dir": "ui", "deps": []}}}),
             "the plan config's workspace cannot be read: KeyError: 'dir'", "workspace graph unreadable: 'dir'"),
        ]
        for text, red, repaired in cases:
            with self.subTest(red=red):
                self.fixture(self.CFG)
                self.change({"ui/ci-plan.json": text})
                self.assert_red(red)
                self.fixture(None, text=text)
                self.change({"ui/ci-plan.json": json.dumps(self.CFG)})
                result = self.run_plan()
                self.assertIsInstance(result, dict, str(result))
                self.assertEqual((result["mode"], result["jobs"] == {} or all(j["run"] for j in result["jobs"].values())),
                                 ("full", True))
                if repaired is None:
                    self.assertEqual(result["config_check"]["red_decided_by"], "candidate")
                    self.assertEqual(result["config_check"]["candidate_errors"], [])
                    self.assertRegex("; ".join(result["config_check"]["base_errors"]), red)
                else:
                    self.assertEqual(result["reason"], repaired)
        # A base whose workspace cannot be read plans FULL, but a change whose own config is broken is still red.
        self.fixture(None, text=broken(workspace="declared"))
        self.change({"ui/ci-plan.json": "[]"})
        self.assert_red("the plan config is a JSON list, not an object")

    def test_a_config_at_another_schema_is_red_as_the_candidate_and_full_as_the_base(self):
        # Root's #57 RC 2 (a6): a schema this planner does not read is refused like a malformed config. As the candidate
        # it is red (it escapes no validation, at any config path); as the base, a schema-1 repair plans FULL and an
        # unrelated change, still at schema 2, stays red.
        later = json.loads(json.dumps(self.CFG)); later["schema"] = 2; later["test_jobs"] = {}
        self.fixture(self.CFG)
        self.change({"ui/ci-plan.json": json.dumps(later)})
        self.assert_red(r"plan config schema 2 is not 1")
        self.fixture(later)
        self.change({"ui/ci-plan.json": json.dumps(self.CFG)})
        self.assert_mode("full", "plan config schema 2 is not 1", [])
        self.change({"ui/a.ts": "x\n"})
        self.assert_red(r"plan config schema 2 is not 1")

    def test_a_pnpm_graph_narrows_by_the_base_and_reds_by_the_candidates_own_edges(self):
        # pnpm: the graph comes from the tree (pnpm-workspace.yaml, manifests) plus the config's extra_deps. A manifest
        # edit is a builtin full trigger (**/package.json), so the config's extra_deps is the one route by which a
        # candidate's graph could be narrower than the base's.
        cfg = {"schema": 1, "workspace": {"type": "pnpm", "extra_deps": {"b": ["a"]}}, "hub_packages": [],
               "inert_globs": ["docs/**"], "jobs": {"a_tests": {"packages": ["a"]}, "b_tests": {"packages": ["b"]}},
               "test_jobs": {"a_tests": ["a"], "b_tests": ["b"]}}
        files = {"pnpm-workspace.yaml": "packages:\n  - 'pkgs/*'\n", "package.json": '{"name": "root"}\n',
                 "pkgs/a/package.json": '{"name": "a"}\n', "pkgs/a/x.test.ts": "it()\n",
                 "pkgs/b/package.json": '{"name": "b"}\n', "pkgs/b/y.test.ts": "it()\n"}
        self.fixture(cfg, files, config_rel="pkgs/b/ci-plan.json")
        self.change({"pkgs/a/x.test.ts": "it('x')\n"})
        self.assert_mode("reduced", "affected: a, b", ["a_tests", "b_tests"])
        # The candidate drops the b -> a edge and changes a: the base's graph still has the edge (the M2 shape, pnpm).
        cut = json.loads(json.dumps(cfg)); del cut["workspace"]["extra_deps"]
        self.change({"pkgs/b/ci-plan.json": json.dumps(cut), "pkgs/a/x.test.ts": "it('x')\n"})
        self.assert_mode("reduced", "affected: a, b", ["a_tests", "b_tests"])
        # An extra_deps entry naming no package is the config's error: red.
        ghost = json.loads(json.dumps(cfg)); ghost["workspace"]["extra_deps"] = {"b": ["ghost"]}
        self.change({"pkgs/b/ci-plan.json": json.dumps(ghost)})
        self.assert_red("the plan config's workspace cannot be read: ValueError: extra_deps for b contains an undeclared")
        # A manifest that does not parse is the tree's defect (pnpm install refuses it): the base decides, never red.
        self.change({"pkgs/b/package.json": '{"name": "b",'})
        result = self.assert_mode("full", r"pkgs/b/package\.json matches full trigger", ["a_tests", "b_tests"])
        self.assertEqual(result["config_check"]["red_decided_by"], "base")

    def test_a_change_removing_the_config_has_nothing_of_its_own_to_validate(self):
        # Absent is not unreadable: git lists the candidate's tree and the path is not in it. On a broken base the
        # removal plans FULL and can land; the base decides nothing it cannot read.
        gapped = json.loads(json.dumps(self.CFG)); gapped["test_jobs"] = {}
        self.fixture(gapped)
        self.change({"ui/ci-plan.json": None})
        result = self.assert_mode("full", r"this change removes it, so it plans FULL and can land \(F29\)",
                                  ["server_tests", "ui_tests"])
        self.assertEqual(result["config_check"]["candidate_errors"], [])
        self.fixture(None, text="[]")
        self.change({"ui/ci-plan.json": None})
        self.assertEqual(self.assert_mode("full", ".", [])["config_check"]["red_decided_by"], "candidate")
        self.fixture(self.CFG)
        self.change({"ui/ci-plan.json": None, "ui/a.ts": "x\n"})
        self.assert_mode("reduced", "affected: ui", ["ui_tests"])

    def test_a_change_introducing_a_config_is_judged_by_it(self):
        # No config on the base: nothing narrows, but a change that introduces a broken one is red before it lands.
        self.fixture(None, text="{}")
        self.git("rm", "-q", "--cached", "ui/ci-plan.json")
        (self.root / "ui/ci-plan.json").unlink()
        self.base = self.git("commit-tree", self.git("write-tree"), input=b"no config\n")
        self.change({"ui/ci-plan.json": "[]"})
        self.assert_red("the plan config is a JSON list, not an object")
        self.change({"ui/ci-plan.json": json.dumps(self.CFG)})
        self.assert_mode("full", "no plan config on the base commit", [])


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
            for enabled, checkout in (("true", "success"), ("false", "success"), ("true", "failure")):
                output = root / (enabled + "-" + checkout + "-output")
                env = dict(os.environ, CONFIG=".github/ci-plan.json", STATE=str(root),
                           GITHUB_WORKSPACE=str(root), CANDIDATE_ROOT=".", CANDIDATE="a" * 40,
                           EDGE_CHECK=enabled, POLICY_OUTCOME=checkout, POLICY_REF="", GITHUB_ACTION_PATH=str(Path(__file__).parent), GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-eu", "-c", body], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                reason = output.read_text().strip().split("=", 1)[1]
                self.assertTrue(reason)
                if checkout == "failure":
                    self.assertIn("policy checkout unavailable", reason)
                cfg = {"workspace": {"type": "declared", "packages": {"ui": {"dir": "ui"}}},
                       "jobs": {"server": "full_only"}}
                full = P.plan(cfg=cfg, root=root, config_path=root / "base/.github/ci-plan.json",
                              paths=["ui/a.ts"], event="pull_request", base="b", head="h", expected_count=None,
                              forced_full_reason=reason)
                self.assertEqual(full["mode"], "full")
                self.assertTrue(full["jobs"]["server"]["run"])


if __name__ == "__main__":
    unittest.main()
