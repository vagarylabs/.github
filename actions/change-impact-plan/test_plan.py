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
    "matrices": {
        "general_tests": [
            {"include": {"group": "general-server-a"}, "rule": "full_only"},
            {"include": {"group": "general-workspaces-a"}, "rule": {"packages": ["@v/ui", "@v/cli"]}},
            {"include": {"group": "general-workspaces-b"}, "rule": {"any_except": ["@v/server", "@v/ui", "@v/cli"]}},
        ]
    },
}

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

    def run_plan(self, paths, event="pull_request", expected=None, root=None):
        root = root or self.root
        cfg_path = root / ".github" / "ci-plan.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else None
        return P.plan(cfg=cfg, root=root, config_path=cfg_path, paths=paths, event=event,
                      base="b" * 40, head="h" * 40, expected_count=expected)

    def included(self, rec, name="general_tests"):
        return [e["group"] for e in rec["matrices"][name]["include"]]

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

    def test_adoption_pr_uses_head_config_only_to_list_the_full_suite(self):
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
        self.assertTrue(all(json.loads(kv["run"]).values()))
        self.assertEqual(len(json.loads(kv["matrices"])["general_tests"]), 3)

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
        cfg = dict(CONFIG, inert_globs=["**"])
        (self.root / ".github" / "ci-plan.json").write_text(json.dumps(cfg))
        self.assertEqual(self.run_plan(["pnpm-lock.yaml"])["mode"], "full")

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

    def test_github_output_shape(self):
        with tempfile.TemporaryDirectory() as td:
            paths = Path(td) / "paths.txt"
            paths.write_text("\n".join(PR397))
            out = Path(td) / "out"
            P.main(["--config", ".github/ci-plan.json", "--root", str(self.root), "--paths-file", str(paths),
                    "--event", "pull_request", "--base", "b", "--head", "h", "--github-output", str(out),
                    "--summary", str(Path(td) / "s.md")])
            kv = dict(line.split("=", 1) for line in out.read_text().splitlines())
            self.assertEqual(kv["mode"], "reduced")
            self.assertEqual(json.loads(kv["run"])["canary_dry_run"], False)
            self.assertEqual(json.loads(kv["matrices"])["general_tests"], [{"group": "general-workspaces-a"}])
            self.assertIn("skipped by plan", (Path(td) / "s.md").read_text())


if __name__ == "__main__":
    unittest.main()
