"""Immutable scope controls; real Git objects, no provider credentials or network."""
import contextlib
import io
import json
import os
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
        malicious = json.loads(json.dumps(self.cfg)); malicious["jobs"] = {}
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
