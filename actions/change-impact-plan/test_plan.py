"""Planner tests: python3 -m unittest discover -s actions/change-impact-plan

The fixture workspace carries the SHAPE of vagarylabs/vagaris (2026-10-03, origin/main 5b2ea3ea0): the cli
depends on the server, the server on db, shared and the adapters, ui on shared and the adapters. The path
lists in the GREEN and RED cases are the real changed files of vagaris PR #397, so the proof uses what a
production PR supplies rather than hand-picked paths.
"""
import json
import tempfile
import unittest
from pathlib import Path

import edges as E
import plan as P

PR397 = """cli/src/__tests__/context-commands.test.ts
cli/src/__tests__/principal-class-credential.test.ts
cli/src/client/context.ts
cli/src/commands/client/auth.ts
cli/src/commands/client/common.ts
cli/src/commands/client/context.ts
cli/src/commands/client/feature-claim.test.ts
cli/src/commands/client/feature.ts
cli/src/utils/error-codes.ts
docs/cli/context.md
docs/cli/control-plane-commands.md
docs/cli/login.md
docs/cli/reference.md""".splitlines()

CONFIG = {
    "schema": 1,
    "workspace": {"type": "pnpm"},
    "inert_globs": ["docs/**", "doc/**"],
    "hub_packages": ["@v/server", "@v/db", "@v/shared"],
    "jobs": {
        "build": "any_package",
        "canary_dry_run": "full_only",
        "e2e": {"packages": ["@v/ui"]},
    },
    # 1.7.0: which packages' test files each unit executes. The hub packages' tests run in the full plan any change to
    # them gets; every other test-owning package is run by a unit a change to it selects.
    "test_jobs": {"e2e": ["@v/ui"]},
    "matrices": {
        "general_tests": [
            {"include": {"group": "general-server-a"}, "rule": "full_only", "tests": "*"},
            {"include": {"group": "general-workspaces-a"}, "rule": {"packages": ["@v/ui", "@v/cli"]},
             "tests": ["@v/ui", "@v/cli"]},
            {"include": {"group": "general-workspaces-b"}, "rule": {"any_except": ["@v/server", "@v/ui", "@v/cli"]},
             "tests": ["@v/adapter-utils", "@v/adapter-claude", "@v/tooling"]},
        ]
    },
}

# The fixture candidate's tracked test files (1.7.0's inventory): one or two per test-owning package.
TEST_FILES = ["cli/src/__tests__/context-commands.test.ts", "cli/src/commands/client/feature-claim.test.ts",
              "packages/db/src/d.test.ts", "packages/tooling/src/t.test.ts", "server/src/__tests__/s.test.ts",
              "ui/src/app.test.tsx"]

PACKAGES = {
    "packages/shared": ("@v/shared", []),
    "packages/db": ("@v/db", ["@v/shared"]),
    "packages/adapter-utils": ("@v/adapter-utils", []),
    "packages/adapters/claude-local": ("@v/adapter-claude", ["@v/adapter-utils"]),
    "packages/plugins/sandbox-providers/x": ("@v/sandbox-x", []),
    "packages/tooling": ("@v/tooling", []),
    "server": ("@v/server", ["@v/db", "@v/shared", "@v/adapter-claude"]),
    "ui": ("@v/ui", ["@v/shared", "@v/adapter-claude"]),
    "cli": ("@v/cli", ["@v/server", "@v/db"]),
}


def complete_scope(root: Path, cfg_path: Path, cfg, paths, *, event="pull_request", base="b" * 40,
                   candidate="c" * 40):
    """Source facts exactly as main() records them for a verified checkout: known immutable scope, base policy
    verified byte-for-byte, provider identity, observed representation. Planner 1.4 refuses to narrow without
    them, so selection tests supply them explicitly; the P3 vectors in test_source.py remove them one by one."""
    manifests = sorted(m.relative_to(root).as_posix() for m in root.rglob("package.json"))
    metadata = [".github/ci-plan.json"] if cfg_path.is_file() else []
    metadata += [p for p in ("pnpm-workspace.yaml", "pnpm-lock.yaml") if (root / p).is_file()]
    metadata += sorted(w.relative_to(root).as_posix() for w in (root / ".github/workflows").glob("*") if w.is_file()) \
        if (root / ".github/workflows").is_dir() else []
    return {"schema": 1, "event": event, "repository": "fixture/repo", "base": base, "head": "h" * 40,
            "candidate": candidate, "tree": "e" * 40, "paths": paths, "status": "known",
            "repository_id": "101", "repository_owner_id": "202", "policy_status": "verified",
            "policy_revision": base, "policy_path": ".github/ci-plan.json",
            "policy_sha256": P.sha256_file(cfg_path), "policy_paths": sorted(set(manifests + metadata)),
            "representation": {"rung": "required_history", "sparse": {"enabled": False, "paths": []},
                               "clone_filter": "none", "history_depth": 0}}


def bound_readers(root: Path, cfg_path: Path, cfg, candidate="c" * 40):
    """A matched assessment from the REAL edges.py assess(), bound to this candidate, policy and graph."""
    if cfg is None:
        return None
    try:
        pkgs = E.workspace_graph(root, cfg)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    reader_dirs = (cfg.get("edge_scan") or {}).get("reader_dirs") or []
    deps = {name: set(info["deps"]) for name, info in pkgs.items()}
    return E.assess(pkgs, cfg, deps, {d: set() for d in reader_dirs}, revision=candidate, config_path=cfg_path)


def make_repo(tmp: Path, config=CONFIG) -> Path:
    (tmp / "pnpm-workspace.yaml").write_text(
        "packages:\n  - packages/*\n  - packages/adapters/*\n  # comment\n"
        '  - "!packages/plugins/sandbox-providers/**"\n  - server\n  - ui\n  - cli\n'
        "onlyBuiltDependencies:\n  - esbuild\n")
    (tmp / "package.json").write_text(json.dumps({"name": "root", "private": True}))
    (tmp / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    for d, (name, deps) in PACKAGES.items():
        (tmp / d).mkdir(parents=True, exist_ok=True)
        (tmp / d / "package.json").write_text(json.dumps(
            {"name": name, "dependencies": {x: "workspace:*" for x in deps}, "devDependencies": {"vitest": "^3"}}))
    (tmp / ".github" / "workflows").mkdir(parents=True)
    (tmp / ".github" / "workflows" / "pr.yml").write_text("name: PR\n")
    if config is not None:
        (tmp / ".github" / "ci-plan.json").write_text(json.dumps(config))
    return tmp


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._td.name))

    def tearDown(self):
        self._td.cleanup()

    def run_plan(self, paths, event="pull_request", expected=None, root=None, readers=None, test_files=TEST_FILES):
        root = root or self.root
        cfg_path = root / ".github" / "ci-plan.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else None
        return P.plan(cfg=cfg, root=root, config_path=cfg_path, paths=paths, event=event,
                      base="b" * 40, head="h" * 40, expected_count=expected,
                      scope=complete_scope(root, cfg_path, cfg, paths, event=event),
                      reader_assessment=readers if readers is not None else bound_readers(root, cfg_path, cfg),
                      test_files=test_files)

    def backstopped(self, flagged):
        """A matched assessment from the REAL assess() whose backstop flags `flagged`: a ui file names its basename."""
        cfg_path = self.root / ".github" / "ci-plan.json"
        cfg = json.loads(cfg_path.read_text())
        pkgs = E.workspace_graph(self.root, cfg)
        reader_dirs = (cfg.get("edge_scan") or {}).get("reader_dirs") or []
        deps = {name: set(info["deps"]) for name, info in pkgs.items()}
        return E.assess(pkgs, cfg, deps, {d: set() for d in reader_dirs}, revision="c" * 40, config_path=cfg_path,
                        mentions={flagged: [["ui/src/run.ts", "@v/ui", False, flagged]]})

    # Root's ruling on the backstop's consequence (2026-10-29): PER PATH. A flagged path is a full trigger for a change
    # that touches it; every other path keeps its mapping; the flagged set is bound into the assessment's digest.
    def test_a_backstop_flagged_path_plans_full_and_only_that_path(self):
        readers = self.backstopped("cli/src/client/context.ts")
        self.assertEqual(readers["backstop_full"], ["cli/src/client/context.ts"])
        self.assertEqual(readers["failures"], [], "a backstop hit fails nothing: its consequence is per path")
        rec = self.run_plan(PR397, readers=readers)
        self.assertEqual(rec["mode"], "full")
        self.assertIn("cli/src/client/context.ts is named by a file the reader scan did not attribute (backstop)",
                      rec["reason"])
        self.assertEqual(rec["impact"]["status"], "unknown", "a flagged input's modeled impact is unknown")
        other = self.run_plan(PR397, readers=self.backstopped("ui/src/elsewhere.ts"))
        self.assertEqual(other["mode"], "reduced", "a flagged path the change does not touch narrows nothing away")
        self.assertEqual(other["affected_packages"], ["@v/cli"])

    def test_the_flagged_set_is_bound_and_must_be_well_formed(self):
        readers = self.backstopped("cli/src/client/context.ts")
        for name, edit, rehash in (("dropped after binding", lambda r: r.update(backstop_full=[]), False),
                                   ("unsorted, rebound", lambda r: r.update(backstop_full=["z", "a"]), True),
                                   ("a non-string, rebound", lambda r: r.update(backstop_full=[1]), True),
                                   ("missing, rebound", lambda r: r.pop("backstop_full"), True)):
            with self.subTest(name):
                r = json.loads(json.dumps(readers))
                edit(r)
                if rehash:
                    r["assessment_sha256"] = P.canonical_digest({k: v for k, v in r.items() if k != "assessment_sha256"})
                rec = self.run_plan(PR397, readers=r)
                self.assertEqual(rec["mode"], "full", "an assessment whose flagged set is not the bound, well-formed one "
                                 "cannot narrow anything")

    def test_selection_without_source_facts_fails_closed(self):
        """Library callers that supply no observed scope cannot obtain a reduced plan (unknown never narrows)."""
        cfg_path = self.root / ".github" / "ci-plan.json"
        rec = P.plan(cfg=json.loads(cfg_path.read_text()), root=self.root, config_path=cfg_path, paths=PR397,
                     event="pull_request", base="b" * 40, head="h" * 40, expected_count=None)
        self.assertEqual(rec["mode"], "full")
        self.assertIn("source answer not complete", rec["reason"])
        self.assertIsNone(rec["source_answer"])
        self.assertEqual(rec["source_answer_meta"]["decision"], "FULL")
        self.assertTrue(rec["jobs"]["canary_dry_run"]["run"])

    def included(self, rec, name="general_tests"):
        return [e["group"] for e in rec["matrices"][name]["include"]]

    def test_every_job_and_matrix_package_reference_is_validated_before_reduction(self):
        for collection in ("jobs", "matrices"):
            for kind in ("packages", "any_except"):
                for paths in (["docs/readme.md"], ["cli/src/main.ts"]):
                    with self.subTest(collection=collection, kind=kind, paths=paths):
                        cfg = json.loads(json.dumps(CONFIG))
                        invalid = {kind: ["@v/does-not-exist"]}
                        if collection == "jobs":
                            cfg["jobs"]["invalid"] = invalid
                        else:
                            cfg["matrices"]["general_tests"].append({"include": {"group": "invalid"}, "rule": invalid})
                        (self.root / ".github/ci-plan.json").write_text(json.dumps(cfg))
                        with self.assertRaisesRegex(ValueError, "undeclared package"):
                            self.run_plan(paths)

    def test_valid_package_rules_retain_positive_and_negative_selection(self):
        cfg = json.loads(json.dumps(CONFIG))
        cfg["jobs"]["cli_direct"] = {"packages": ["@v/cli"]}
        cfg["jobs"]["ui_direct"] = {"packages": ["@v/ui"]}
        cfg["jobs"]["non_cli"] = {"any_except": ["@v/cli"]}
        (self.root / ".github/ci-plan.json").write_text(json.dumps(cfg))
        result = self.run_plan(["cli/src/main.ts"])
        self.assertEqual(result["mode"], "reduced")
        self.assertTrue(result["jobs"]["cli_direct"]["run"])
        self.assertFalse(result["jobs"]["ui_direct"]["run"])
        self.assertFalse(result["jobs"]["non_cli"]["run"])
        self.assertIn("general-workspaces-a", self.included(result))

    def test_malformed_rules_fail_instead_of_silently_omitting_obligations(self):
        for rule in ({"packages": "@v/cli"}, {"any_except": [None]},
                     {"packages": ["@v/cli"], "any_except": []}, {"typo": []}, "not_a_rule"):
            with self.subTest(rule=rule):
                cfg = json.loads(json.dumps(CONFIG))
                cfg["jobs"]["invalid"] = rule
                (self.root / ".github/ci-plan.json").write_text(json.dumps(cfg))
                with self.assertRaises(ValueError):
                    self.run_plan(["docs/readme.md"])


    def test_graph_digest_is_order_independent_but_binds_declared_edges_and_directories(self):
        graph = P.discover_pnpm_packages(self.root)
        self.assertEqual(P.graph_digest(graph), P.graph_digest(dict(reversed(list(graph.items())))))
        modified = {name: {"dir": row["dir"], "deps": set(row["deps"])} for name, row in graph.items()}
        modified["@v/server"]["deps"].add("@v/ui")
        self.assertNotEqual(P.graph_digest(graph), P.graph_digest(modified))
        modified = {name: {"dir": row["dir"], "deps": set(row["deps"])} for name, row in graph.items()}
        modified["@v/cli"]["dir"] = "moved-cli"
        self.assertNotEqual(P.graph_digest(graph), P.graph_digest(modified))

    def test_legacy_pr_selection_remains_distinct_from_unqualified_impact(self):
        result = self.run_plan(PR397)
        self.assertEqual(result["mode"], "reduced")
        self.assertEqual(result["affected_packages"], ["@v/cli"])
        self.assertEqual(result["impact"]["status"], "unknown")
        self.assertIsNone(result["impact"]["affected_packages"])
        self.assertIs(result["impact"]["selection_authority"], False)

    # The two proofs the cc:root report asks for.
    def test_green_cli_only_diff_is_reduced(self):
        rec = self.run_plan(PR397)
        self.assertEqual(rec["mode"], "reduced", rec["reason"])
        self.assertEqual(rec["affected_packages"], ["@v/cli"])
        self.assertEqual(self.included(rec), ["general-workspaces-a"])
        self.assertFalse(rec["jobs"]["canary_dry_run"]["run"])
        self.assertFalse(rec["jobs"]["e2e"]["run"])
        self.assertTrue(rec["jobs"]["build"]["run"])
        self.assertEqual(len(rec["evidence"]["inert"]), 4)

    def test_red_server_file_in_cli_diff_is_full(self):
        rec = self.run_plan(PR397 + ["server/src/routes/feature.ts"])
        self.assertEqual(rec["mode"], "full")
        self.assertIn("@v/server", rec["reason"])
        self.assertEqual(self.included(rec), ["general-server-a", "general-workspaces-a", "general-workspaces-b"])
        self.assertTrue(all(j["run"] for j in rec["jobs"].values()))

    # FULL triggers: never a silent skip.
    def test_transitive_dependency_of_server_is_full(self):
        rec = self.run_plan(["packages/adapter-utils/src/x.ts"])
        self.assertEqual(rec["mode"], "full")
        self.assertIn("@v/server", rec["reason"])

    def test_builtin_full_triggers(self):
        for p in [".github/workflows/pr.yml", "pnpm-lock.yaml", "cli/package.json",
                  "packages/db/src/migrations/0250_x.sql", "pnpm-workspace.yaml", "docker/Dockerfile.ci", ".nvmrc"]:
            with self.subTest(p=p):
                rec = self.run_plan(["cli/src/a.ts", p])
                self.assertEqual(rec["mode"], "full")
                self.assertEqual(rec["evidence"]["full_triggers"][0]["path"], p)

    def test_unmapped_path_is_full(self):
        for p in ["scripts/check-x.mjs", "vitest.config.ts", "tests/e2e/a.spec.ts", "README.md", "docker/compose.yml"]:
            with self.subTest(p=p):
                rec = self.run_plan(["cli/src/a.ts", p])
                self.assertEqual(rec["mode"], "full")
                self.assertIn(p, rec["reason"])

    def test_excluded_workspace_dir_is_unmapped(self):
        rec = self.run_plan(["packages/plugins/sandbox-providers/x/src/a.ts"])
        self.assertEqual(rec["mode"], "full")

    def test_markdown_inside_a_package_is_not_inert(self):
        rec = self.run_plan(["packages/tooling/SKILL.md"])
        self.assertEqual(rec["mode"], "reduced")
        self.assertEqual(rec["affected_packages"], ["@v/tooling"])
        self.assertEqual(self.included(rec), ["general-workspaces-b"])

    def test_non_pr_events_are_full(self):
        for ev in ["push", "merge_group", "schedule", "workflow_dispatch"]:
            with self.subTest(ev=ev):
                self.assertEqual(self.run_plan(PR397, event=ev)["mode"], "full")

    def test_empty_or_truncated_lists_are_full(self):
        self.assertEqual(self.run_plan([])["mode"], "full")
        rec = self.run_plan(PR397, expected=300)
        self.assertEqual(rec["mode"], "full")
        self.assertIn("truncated", rec["reason"])

    def test_missing_config_is_full(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_repo(Path(td), config=None)
            rec = self.run_plan(PR397, root=root)
        self.assertEqual(rec["mode"], "full")
        self.assertIn("no plan config", rec["reason"])

    def test_adoption_pr_cannot_take_its_full_roster_from_candidate_config(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "base").mkdir()
            root = make_repo(Path(td) / "base", config=None)
            head_cfg = Path(td) / "head-ci-plan.json"
            head_cfg.write_text(json.dumps(CONFIG))
            paths = Path(td) / "paths.txt"
            paths.write_text("\n".join(PR397))
            out = Path(td) / "out"
            P.main(["--config", ".github/ci-plan.json", "--root", str(root), "--fallback-config", str(head_cfg),
                    "--paths-file", str(paths), "--event", "pull_request", "--github-output", str(out)])
            kv = dict(line.split("=", 1) for line in out.read_text().splitlines())
        self.assertEqual(kv["mode"], "full")
        self.assertEqual(json.loads(kv["run"]), {})
        self.assertEqual(json.loads(kv["matrices"]), {})
        self.assertTrue(json.loads(kv["plan"])["requires_full_caller_roster"])

    def test_unknown_or_malformed_base_never_uses_candidate_roster(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github").mkdir()
            base = root / ".github/ci-plan.json"
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps({"schema": 1, "jobs": {"only_candidate_job": "always"}}))
            output = root / "output"
            args = ["--config", ".github/ci-plan.json", "--root", str(root),
                    "--fallback-config", str(candidate), "--event", "pull_request",
                    "--github-output", str(output)]
            base.write_text('{"schema": 999}')
            self.assertEqual(P.main(args), 0)
            value = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(json.loads(value["run"]), {})
            self.assertTrue(json.loads(value["plan"])["requires_full_caller_roster"])
            output.unlink()
            base.write_text("{malformed")
            with self.assertRaises(json.JSONDecodeError):
                P.main(args)
            self.assertFalse(output.exists())
            base.unlink()
            candidate.write_text("{malformed")
            self.assertEqual(P.main(args), 0)
            value = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(json.loads(value["run"]), {})
            self.assertEqual(value["mode"], "full")

    def test_docs_only_runs_no_package_work(self):
        rec = self.run_plan(["docs/cli/login.md"])
        self.assertEqual(rec["mode"], "reduced")
        self.assertEqual(rec["affected_packages"], [])
        self.assertEqual(self.included(rec), [])
        self.assertFalse(rec["jobs"]["build"]["run"])

    def test_ui_change_runs_e2e(self):
        rec = self.run_plan(["ui/src/App.tsx"])
        self.assertEqual(rec["mode"], "reduced")
        self.assertTrue(rec["jobs"]["e2e"]["run"])
        self.assertEqual(self.included(rec), ["general-workspaces-a"])

    def test_skips_carry_reasons_and_plan_id_is_stable(self):
        a, b = self.run_plan(PR397), self.run_plan(list(reversed(PR397)))
        self.assertEqual(a["plan_id"], b["plan_id"])
        for j in a["jobs"].values():
            self.assertTrue(j["reason"])
        for s in a["matrices"]["general_tests"]["skipped"]:
            self.assertTrue(s["reason"])
        self.assertNotEqual(a["plan_id"], self.run_plan(PR397 + ["cli/src/b.ts"])["plan_id"])

    def test_validity_predicate_binds_lockfile_and_workflows(self):
        before = self.run_plan(PR397)
        (self.root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\nchanged: 1\n")
        after = self.run_plan(PR397)
        self.assertNotEqual(before["validity"]["lockfiles_sha256"], after["validity"]["lockfiles_sha256"])
        self.assertNotEqual(before["plan_id"], after["plan_id"])
        (self.root / ".github" / "workflows" / "pr.yml").write_text("name: PR2\n")
        self.assertNotEqual(after["validity"]["workflows_sha256"], self.run_plan(PR397)["validity"]["workflows_sha256"])

    def test_extra_edges_map_runtime_reads(self):
        cfg = dict(CONFIG, extra_edges={"fixtures/cli/**": ["@v/cli"]})
        (self.root / ".github" / "ci-plan.json").write_text(json.dumps(cfg))
        rec = self.run_plan(["fixtures/cli/a.json"])
        self.assertEqual(rec["mode"], "reduced")
        self.assertEqual(rec["affected_packages"], ["@v/cli"])
        cfg["extra_edges"] = {"fixtures/**": ["@v/nope"]}
        (self.root / ".github" / "ci-plan.json").write_text(json.dumps(cfg))
        self.assertEqual(self.run_plan(["fixtures/a.json"])["mode"], "full")

    def test_config_cannot_remove_builtin_triggers(self):
        # Without a test declaration (so the 1.7.0 inventory does not apply), an all-inert config still plans FULL on a
        # builtin trigger.
        cfg = json.loads(json.dumps(CONFIG))
        cfg["inert_globs"] = ["**"]
        del cfg["test_jobs"]
        for entry in cfg["matrices"]["general_tests"]:
            entry.pop("tests")
        (self.root / ".github" / "ci-plan.json").write_text(json.dumps(cfg))
        self.assertEqual(self.run_plan(["pnpm-lock.yaml"])["mode"], "full")
        # With a declaration, an inert glob over the test files is itself refused: a change to one would run nothing.
        (self.root / ".github" / "ci-plan.json").write_text(json.dumps(dict(CONFIG, inert_globs=["**"])))
        with self.assertRaisesRegex(ValueError, "inside a package match inert_globs"):
            self.run_plan(["pnpm-lock.yaml"])

    # Reuse of an identical tree's full run (push only).
    def tested(self, tree="t" * 40):
        return P.tested_identity(self.root, tree)

    def receipt(self, **over):
        r = {"mode": "full", "run_id": 123, "tested": self.tested()}
        r.update(over)
        return r

    def test_push_reuses_a_full_run_of_the_identical_tree(self):
        rec = P.plan(cfg=CONFIG, root=self.root, config_path=self.root / ".github/ci-plan.json", paths=[],
                     event="push", base="b", head="h", expected_count=None, tested=self.tested(), receipt=self.receipt())
        self.assertEqual(rec["mode"], "reused")
        self.assertIn("run 123", rec["reason"])
        self.assertFalse(any(j["run"] for j in rec["jobs"].values()))
        self.assertEqual(rec["matrices"]["general_tests"]["include"], [])

    def test_reuse_refused_when_the_predicate_breaks(self):
        cases = {
            "other tree": self.receipt(tested=dict(self.tested(), tree="u" * 40)),
            "reduced run": self.receipt(mode="reduced"),
            "lockfile": self.receipt(tested=dict(self.tested(), lockfiles_sha256={"pnpm-lock.yaml": "0"})),
            "workflows": self.receipt(tested=dict(self.tested(), workflows_sha256="0")),
            "planner": self.receipt(tested=dict(self.tested(), planner_version="0.9")),
        }
        for name, receipt in cases.items():
            with self.subTest(name):
                rec = P.plan(cfg=CONFIG, root=self.root, config_path=self.root / ".github/ci-plan.json", paths=[],
                             event="push", base="b", head="h", expected_count=None, tested=self.tested(), receipt=receipt)
                self.assertEqual(rec["mode"], "full")
                self.assertFalse(rec["reuse"]["reused"])

    def test_only_push_events_reuse(self):
        for ev in ["schedule", "release", "workflow_dispatch", "merge_group", "pull_request"]:
            with self.subTest(ev=ev):
                rec = P.plan(cfg=CONFIG, root=self.root, config_path=self.root / ".github/ci-plan.json", paths=PR397,
                             event=ev, base="b", head="h", expected_count=None, tested=self.tested(), receipt=self.receipt())
                self.assertNotEqual(rec["mode"], "reused")

    def test_glob(self):
        r = P.glob_to_regex
        self.assertTrue(r("**/package.json").match("package.json"))
        self.assertTrue(r("**/package.json").match("a/b/package.json"))
        self.assertFalse(r("docs/*").match("docs/a/b.md"))
        self.assertTrue(r("docs/**").match("docs/a/b.md"))
        self.assertFalse(r("docs/**").match("docsx/a.md"))

    def test_legacy_path_file_cannot_reduce_without_immutable_scope(self):
        with tempfile.TemporaryDirectory() as td:
            paths = Path(td) / "paths.txt"
            paths.write_text("\n".join(PR397))
            out = Path(td) / "out"
            P.main(["--config", ".github/ci-plan.json", "--root", str(self.root), "--paths-file", str(paths),
                    "--event", "pull_request", "--base", "b", "--head", "h", "--github-output", str(out),
                    "--summary", str(Path(td) / "s.md")])
            kv = dict(line.split("=", 1) for line in out.read_text().splitlines())
            self.assertEqual(kv["mode"], "full")
            self.assertTrue(json.loads(kv["run"])["canary_dry_run"])
            self.assertEqual(len(json.loads(kv["matrices"])["general_tests"]), 3)
            self.assertIn("immutable scope checkout is required", (Path(td) / "s.md").read_text())


class TestInventory(unittest.TestCase):
    """1.7.0 (S6, root's conditions 2026-10-30): a narrowed plan needs a declaration of which packages' test files each
    unit executes, and that declaration must leave no test file of the candidate unrun by every unit its change selects."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._td.name))
        self.cfg_path = self.root / ".github" / "ci-plan.json"

    def tearDown(self):
        self._td.cleanup()

    def plan_with(self, cfg, test_files=TEST_FILES, paths=PR397, event="pull_request"):
        self.cfg_path.write_text(json.dumps(cfg))
        return P.plan(cfg=cfg, root=self.root, config_path=self.cfg_path, paths=paths, event=event,
                      base="b" * 40, head="h" * 40, expected_count=None,
                      scope=complete_scope(self.root, self.cfg_path, cfg, paths, event=event),
                      reader_assessment=bound_readers(self.root, self.cfg_path, cfg), test_files=test_files)

    def config(self, **changes):
        cfg = json.loads(json.dumps(CONFIG))
        cfg.update(changes)
        return cfg

    def test_a_complete_declaration_narrows_and_records_the_inventory(self):
        rec = self.plan_with(self.config())
        self.assertEqual(rec["mode"], "reduced", rec["reason"])
        inventory = rec["test_inventory"]
        self.assertEqual(inventory["files"], len(TEST_FILES))
        self.assertEqual(inventory["packages"]["@v/cli"]["covered_by"], ['general_tests{"group":"general-workspaces-a"}'])
        self.assertEqual(inventory["packages"]["@v/server"]["covered_by"], "full plan (a change to it affects a hub)")
        self.assertEqual(inventory["gaps"], [])
        other = self.plan_with(self.config(), test_files=TEST_FILES + ["cli/src/new.test.ts"])
        self.assertNotEqual(other["plan_id"], rec["plan_id"], "the inventory is bound into the plan id")

    def test_no_declaration_never_narrows_and_says_why(self):
        cfg = self.config()
        del cfg["test_jobs"]
        for entry in cfg["matrices"]["general_tests"]:
            entry.pop("tests")
        for paths in (PR397, ["docs/cli/context.md"]):
            rec = self.plan_with(cfg, paths=paths)
            self.assertEqual(rec["mode"], "full")
            self.assertIn("no test_jobs declaration", rec["reason"])
            self.assertIsNone(rec["test_inventory"])

    def test_an_unreadable_inventory_never_narrows(self):
        rec = self.plan_with(self.config(), test_files=None)
        self.assertEqual(rec["mode"], "full")
        self.assertEqual(rec["reason"], "the candidate's test inventory could not be read")

    def test_a_test_owning_package_no_selected_unit_runs_is_red(self):
        cfg = self.config()
        cfg["matrices"]["general_tests"][1]["tests"] = ["@v/ui"]  # @v/cli's tests are now declared nowhere
        with self.assertRaisesRegex(ValueError, r"the tests of @v/cli \(2 file\(s\), e\.g\. cli/src/__tests__/context-commands"
                                    r"\.test\.ts\) run in no unit a change to @v/cli selects"):
            self.plan_with(cfg)
        with self.assertRaisesRegex(ValueError, "the tests of @v/cli"):
            self.plan_with(cfg, event="merge_group")  # red on every event, not only where it would narrow

    def test_a_unit_whose_rule_never_selects_the_package_does_not_cover_it(self):
        cfg = self.config()
        cfg["matrices"]["general_tests"][1]["tests"] = ["@v/ui"]
        cfg["test_jobs"] = {"e2e": ["@v/ui", "@v/cli"], "canary_dry_run": ["@v/cli"]}  # e2e: {packages: [ui]}; canary: full_only
        with self.assertRaisesRegex(ValueError, "the tests of @v/cli"):
            self.plan_with(cfg)
        cfg["test_jobs"]["build"] = ["@v/cli"]  # any_package: a change to cli selects it
        self.assertEqual(self.plan_with(cfg)["mode"], "reduced")

    def test_a_unit_selected_through_a_dependent_covers_the_package(self):
        # A change to @v/tooling also affects every package that depends on it; a unit that a dependent selects runs
        # then too. With @v/cli depending on @v/tooling, workspaces-a ({packages: [ui, cli]}) covers tooling's tests.
        cfg = self.config(workspace={"type": "pnpm", "extra_deps": {"@v/cli": ["@v/tooling"]}})
        cfg["matrices"]["general_tests"][1]["tests"] = ["@v/ui", "@v/cli", "@v/tooling"]
        cfg["matrices"]["general_tests"][2]["tests"] = ["@v/adapter-utils", "@v/adapter-claude"]
        rec = self.plan_with(cfg)
        self.assertEqual(rec["test_inventory"]["packages"]["@v/tooling"]["covered_by"],
                         ['general_tests{"group":"general-workspaces-a"}'])
        del cfg["workspace"]["extra_deps"]
        with self.assertRaisesRegex(ValueError, "the tests of @v/tooling"):
            self.plan_with(cfg)

    def test_a_package_whose_change_reaches_a_hub_is_covered_by_the_full_plan(self):
        rec = self.plan_with(self.config(), test_files=TEST_FILES + ["packages/shared/src/x.test.ts"])
        self.assertEqual(rec["test_inventory"]["packages"]["@v/shared"]["covered_by"], "full plan (a change to it affects a hub)")

    def test_a_test_file_outside_every_package_needs_an_always_units_path(self):
        files = TEST_FILES + ["scripts/check-thing.test.mjs", "tests/e2e/flow.spec.ts"]
        with self.assertRaisesRegex(ValueError, r"2 test file\(s\) outside every package run in no always-unit's declared "
                                    r"paths, e\.g\. scripts/check-thing\.test\.mjs, tests/e2e/flow\.spec\.ts"):
            self.plan_with(self.config(), test_files=files)
        cfg = self.config(jobs={**CONFIG["jobs"], "policy": "always"})
        cfg["test_jobs"] = {"e2e": ["@v/ui"], "policy": ["path:scripts/**", "path:tests/**"]}
        rec = self.plan_with(cfg, test_files=files)
        self.assertEqual(rec["mode"], "reduced", rec["reason"])
        self.assertEqual(rec["test_inventory"]["unowned"], {"files": 2, "uncovered": 0})
        cfg["test_jobs"]["policy"] = ["path:scripts/**"]
        with self.assertRaisesRegex(ValueError, r"1 test file\(s\) outside every package .* tests/e2e/flow\.spec\.ts"):
            self.plan_with(cfg, test_files=files)
        cfg["test_jobs"]["policy"] = "*"
        self.assertEqual(self.plan_with(cfg, test_files=files)["mode"], "reduced", '"*" on an always unit covers everything')

    def test_a_path_entry_on_a_unit_a_narrowed_plan_can_skip_is_refused(self):
        cfg = self.config()
        cfg["test_jobs"] = {"e2e": ["@v/ui", "path:scripts/**"]}
        with self.assertRaisesRegex(ValueError, r'e2e declares path:scripts/\*\*, but a path entry needs a unit whose rule is "always"'):
            self.plan_with(cfg)

    def test_a_declaration_must_name_real_jobs_and_packages(self):
        for test_jobs, message in (({"nope": ["@v/ui"]}, r"test_jobs names undeclared job\(s\) \['nope'\]"),
                                   ({"e2e": ["@v/missing"]}, "names undeclared package '@v/missing'"),
                                   ({"e2e": "@v/ui"}, 'must be "\\*" or a list'),
                                   ({"e2e": ["path:"]}, "declares an empty path entry"),
                                   (["e2e"], "test_jobs must map a job")):
            with self.assertRaisesRegex(ValueError, message):
                self.plan_with(self.config(test_jobs=test_jobs))
        with self.assertRaisesRegex(ValueError, "test_globs must be a list"):
            self.plan_with(self.config(test_globs="**/*.check.ts"))

    def test_test_globs_add_to_the_conventions_and_never_remove(self):
        self.assertTrue(P.is_test_file("ui/src/app.test.tsx", []))
        self.assertTrue(P.is_test_file("server/tests/helpers/fixture.ts", []), "code under tests/ is test code")
        self.assertTrue(P.is_test_file("services/a/test_api.py", []))
        self.assertFalse(P.is_test_file("ui/src/app.tsx", []))
        self.assertFalse(P.is_test_file("ui/node_modules/x/a.test.js", []))
        self.assertFalse(P.is_test_file("server/tests/data.json", []), "a fixture that is not code is not a test file")
        self.assertTrue(P.is_test_file("ui/src/app.check.ts", ["**/*.check.ts"]))
        self.assertTrue(P.is_test_file("ui/src/app.test.tsx", ["**/*.check.ts"]), "an extra glob removes nothing")

    def test_a_test_file_inside_a_package_that_an_inert_glob_matches_is_red(self):
        # root's #56 R4 blocker 1: a changed inert path selects nothing, so its tests would never run.
        cfg = self.config(inert_globs=["docs/**", "doc/**", "ui/src/*.test.tsx"])
        with self.assertRaisesRegex(ValueError, r"1 test file\(s\) inside a package match inert_globs, so a change to one runs "
                                    r"nothing, e\.g\. ui/src/app\.test\.tsx \(ui/src/\*\.test\.tsx\)"):
            self.plan_with(cfg, paths=["ui/src/app.test.tsx"])
        # A test file outside every package may match an inert glob: its always-unit runs on every plan.
        cfg = self.config(jobs={**CONFIG["jobs"], "policy": "always"}, inert_globs=["docs/**", "doc/**"])
        cfg["test_jobs"] = {"e2e": ["@v/ui"], "policy": ["path:docs/**"]}
        rec = self.plan_with(cfg, test_files=TEST_FILES + ["docs/examples/snippet.test.ts"])
        self.assertEqual(rec["mode"], "reduced", rec["reason"])

    def test_go_tests_are_inventoried_and_owe_coverage(self):
        # root's #56 R4 blocker 2: core's runner gate counts *_test.go; the inventory must too (both halves of the predicate).
        self.assertTrue(P.is_test_file("services/tts/internal/synth_test.go", []))
        self.assertFalse(P.is_test_file("services/tts/internal/synth.go", []), "Go source is not a test file")
        self.assertTrue(P.is_test_file("services/tts/test/helpers.go", []), "Go code under test/ is test code")
        with self.assertRaisesRegex(ValueError, r"the tests of @v/tooling \(1 file\(s\), e\.g\. packages/tooling/pkg/x_test\.go\)"):
            cfg = self.config()
            cfg["matrices"]["general_tests"][2]["tests"] = ["@v/adapter-utils", "@v/adapter-claude"]
            self.plan_with(cfg, test_files=[f for f in TEST_FILES if "tooling" not in f] + ["packages/tooling/pkg/x_test.go"])

    def test_an_empty_inventory_with_a_declaration_never_narrows(self):
        rec = self.plan_with(self.config(), test_files=[])
        self.assertEqual(rec["mode"], "full")
        self.assertEqual(rec["reason"], "the candidate's test inventory is empty while a declaration exists: refused as unproven")

    def test_node_modules_is_a_path_segment(self):
        self.assertFalse(P.is_test_file("ui/node_modules/x/a.test.js", []))
        self.assertFalse(P.is_test_file("node_modules/x/a.test.js", []))
        self.assertTrue(P.is_test_file("ui/foo_node_modules/x.test.ts", []), "a directory merely ending in node_modules")

    def test_selection_rules_are_monotone_so_closure_coverage_holds_for_every_plan(self):
        # The coverage check judges a unit against the package's own closure; a plan affecting the package has a
        # superset of it. Every rule kind that matches a set matches each superset.
        import itertools
        universe = sorted(name for name, _ in PACKAGES.values())
        rules = ["always", "full_only", "any_package", {"packages": ["@v/ui"]}, {"any_except": ["@v/server", "@v/ui"]}]
        for rule in rules:
            for size in range(0, 4):
                for subset in itertools.combinations(universe, size):
                    if not P.rule_matches(rule, set(subset))[0]:
                        continue
                    for extra in universe:
                        self.assertTrue(P.rule_matches(rule, set(subset) | {extra})[0], (rule, subset, extra))


if __name__ == "__main__":
    unittest.main()
