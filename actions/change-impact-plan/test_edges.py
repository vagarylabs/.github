"""edges.py tests: a read in code is an edge, a read in a comment or Markdown is not, and check fails on an
undeclared read (the RED case) while a declared one passes."""
import io
import json
import os
from unittest.mock import patch
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import edges as E

CFG = {
    "schema": 1,
    "workspace": {"type": "declared", "packages": {
        "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []},
    }},
    "edge_scan": {"roots": ["services"], "reader_dirs": ["scripts"], "reader_job": "root"},
    "jobs": {"root": {"packages": []}},
}


class EdgesTest(unittest.TestCase):
    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
        self._td = tempfile.TemporaryDirectory()
        self.repo = Path(self._td.name)
        for d in ("services/a", "services/b", "scripts", ".github"):
            (self.repo / d).mkdir(parents=True)
        (self.repo / "services/a/app.py").write_text("x = 1\n# reads services/b only in a comment\n")
        (self.repo / "services/a/README.md").write_text("see services/b\n")
        (self.repo / "services/b/app.py").write_text("y = 2\n")
        (self.repo / "scripts/run.sh").write_text("cd services/b\n")
        self.write_cfg(CFG)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def tearDown(self):
        self._td.cleanup()

    def write_cfg(self, cfg):
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))

    def run_check(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
        return rc, buf.getvalue()

    def test_comments_and_markdown_are_not_reads(self):
        deps, readers = E.scan(self.repo, CFG)
        self.assertEqual(deps, {"a": set(), "b": set()})
        self.assertEqual(readers, {"scripts": {"b"}})

    def test_undeclared_reader_fails_then_declared_passes(self):
        rc, out = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("scripts/ reads b", out)
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)

    def test_planted_code_read_is_red(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        (self.repo / "services/a/app.py").write_text('DATA = "services/b/data.json"\n')
        rc, out = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("undeclared read: a reads b", out)
        cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)

    def test_nearby_github_host_text_cannot_hide_a_local_reader(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        for host in ("github.com", "github.com.invalid", "evilgithub.com"):
            with self.subTest(host=host):
                (self.repo / "services/a/app.py").write_text(f'url = "{host}"; DATA = "services/b/app.py"\n')
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 1, "nearby host text must not suppress the local read")
                cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 0)
                cfg["workspace"]["packages"]["a"]["deps"] = []


    def test_unmapped_reader_is_unknown_not_an_empty_success(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        (self.repo / "other-tests").mkdir()
        (self.repo / "other-tests/read.py").write_text('input = "services/a/app.py"\n')
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        rc, output = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("unmapped source readers", output)

    def test_external_readers_require_an_actual_mapped_obligation(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"] = {"packages": ["b"]}
        cfg["edge_scan"].pop("reader_job")
        self.write_cfg(cfg)
        rc, output = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("no valid declared reader job", output)
        cfg["edge_scan"]["reader_job"] = "missing"
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 1)
        cfg["edge_scan"]["reader_job"] = "root"
        cfg["jobs"]["root"] = "full_only"
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 1)
        for rule in ("always", {"packages": ["b"]}):
            cfg["jobs"]["root"] = rule
            self.write_cfg(cfg)
            self.assertEqual(self.run_check()[0], 0)

    def test_component_joins_and_relative_paths_are_reads(self):
        (self.repo / "services/c").mkdir(parents=True)
        (self.repo / "services/c/test").mkdir()
        shapes = {
            "pathlib join": 'P = ROOT / "services" / "b" / "app.py"\n',
            "os.path.join": 'P = os.path.join(ROOT, "services", "b")\n',
            "relative URL": 'const p = new URL("../../b/app.py", import.meta.url)\n',
            "go relative read": 'right, e := os.ReadFile("../../b/app.py")\n',
        }
        cfg = json.loads(json.dumps(CFG))
        cfg["workspace"]["packages"]["c"] = {"dir": "services/c", "deps": []}
        for name, line in shapes.items():
            with self.subTest(name):
                (self.repo / "services/c/test/x.src").write_text(line)
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                deps, _ = E.scan(self.repo, cfg)
                self.assertEqual(deps["c"], {"b"}, name)
        (self.repo / "services/c/test/x.src").write_text('local = "../fixtures/a.json"\n')
        deps, _ = E.scan(self.repo, cfg)
        self.assertEqual(deps["c"], set(), "a relative path inside its own package is not a cross-package read")


    def pnpm_fixture(self):
        packages = {"server": "server", "cli": "cli", "ui": "ui",
                    "sdk": "packages/plugins/sdk", "plugin": "packages/plugins/plugin"}
        (self.repo / "pnpm-workspace.yaml").write_text('packages:\n  - "server"\n  - "cli"\n  - "ui"\n  - "packages/plugins/*"\n')
        for name, directory in packages.items():
            path = self.repo / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
        (self.repo / "server/test.ts").write_text('import "../cli/a.js";\n')
        (self.repo / "cli/test.ts").write_text('import "../packages/plugins/sdk/index.js";\n')
        (self.repo / "ui/test.ts").write_text('import "../server/index.js";\n')
        nested = self.repo / "packages/plugins/plugin/src"
        nested.mkdir()
        (nested / "odd:name\nfile.ts").write_text('import "../../sdk/index.js";\n')
        cfg = {"schema": 1, "workspace": {"type": "pnpm"},
               "edge_scan": {"roots": ["server", "cli", "ui", "packages"]}, "jobs": {}}
        self.write_cfg(cfg)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        return cfg

    def test_pnpm_nested_packages_and_cross_surface_test_readers_are_accounted(self):
        cfg = self.pnpm_fixture()
        deps, _ = E.scan(self.repo, cfg)
        expected = {"server": {"cli"}, "cli": {"sdk"}, "ui": {"server"}, "plugin": {"sdk"}, "sdk": set()}
        self.assertEqual(deps, expected)
        self.assertEqual(self.run_check()[0], 1)
        cfg["workspace"]["extra_deps"] = {name: sorted(values) for name, values in expected.items() if values}
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)
        # Planner and checker share the same graph, including test-only cross-package reads.
        graph = E.workspace_graph(self.repo, cfg)
        import plan
        self.assertEqual(plan.reverse_closure(graph, {"sdk"}), {"sdk", "plugin", "cli", "server", "ui"})

    def test_complete_nested_component_joins_preserve_reader_ownership(self):
        cfg = self.pnpm_fixture()
        cfg["edge_scan"].update(reader_dirs=["scripts"], reader_job="root")
        cfg["workspace"]["extra_deps"] = {"server": ["cli"], "cli": ["sdk"], "ui": ["server"], "plugin": ["sdk"]}
        cfg["jobs"]["root"] = {"packages": []}
        for expression in (
            'path.join(root, "packages", "plugins", "sdk", "index.js")',
            'ROOT / "packages" / "plugins" / "sdk" / "index.js"',
            'os.path.join(ROOT, "packages", "plugins/sdk", "index.js")',
        ):
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.write_cfg(cfg)
                self.assertEqual(E.scan(self.repo, cfg)[1]["scripts"], {"sdk"})
                self.assertEqual(self.run_check()[0], 1, "undeclared SDK reader must be red")
                cfg["jobs"]["root"]["packages"] = ["sdk"]
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 0)
                cfg["jobs"]["root"]["packages"] = []

    def test_computed_or_unowned_component_joins_read_every_package_beneath_their_literal_prefix(self):
        """A computed component cannot be resolved statically, so the join reads EVERY package under its literal
        prefix: an over-approximation, which only runs more. A literal path no package owns reads the packages beneath
        it; with none beneath it, it is unowned content, whose change is unmapped and plans FULL, so it needs no edge.
        A `..` component still refuses."""
        cfg = self.pnpm_fixture()
        cfg["edge_scan"].update(reader_dirs=["scripts"], reader_job="root")
        cases = {
            'path.join(root, "packages", "plugins")': {"sdk", "plugin"},
            'path.join(root, "packages", "plugins", "missing", "index.js")': set(),
            'path.join(root, "packages", pluginName, "index.js")': {"sdk", "plugin"},
            'path.join(root, "packages", "plugins", "sdk", selectedFile)': {"sdk"},
            'ROOT / "packages" / pluginName': {"sdk", "plugin"},
            'ROOT / "server" / name': {"server"},
            'os.path.join(ROOT, "server")': {"server"},
        }
        for expression, expected in cases.items():
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.assertEqual(E.scan(self.repo, cfg)[1]["scripts"], expected)
        for expression in ('ROOT / "packages" / ".." / "server"', 'path.join(root, "packages", "../server")'):
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                with self.assertRaisesRegex(ValueError, "workspace-root reader expression"):
                    E.scan(self.repo, cfg)

    def test_a_root_literal_listed_by_comma_outside_a_path_call_is_metadata(self):
        """Outside a path-construction call a `,` lists values, so a root literal there is metadata: never a read and
        never a refusal (a refusal plans FULL for every change). Controls: the same literal inside a path call or after
        a pathlib `/` (or a bare join imported from node:path) IS a read, and a list naming two roots, or a one-element
        tuple of one, is a walker's root list, read as every package under each."""
        cfg = json.loads(json.dumps(CFG))
        cfg["edge_scan"]["roots"] = ["services", "apps"]
        cfg["workspace"]["packages"]["web"] = {"dir": "apps/web", "deps": []}
        (self.repo / "apps/web").mkdir(parents=True)
        (self.repo / "apps/web/page.tsx").write_text("export default 1\n")
        metadata = (
            "{ key: 'services', label: 'Capabilities', icon: Server },",
            '"policy_id": "services",',
            "const tabs = ['services', 'providers', 'upstreams'];",
            'record = make("services", version="1", digest=value)',
            "VALUES ('apps', 'dns_iac', NULL),",
            '"services"',
            'count = manifest["services"][0]',
        )
        for line in metadata:
            with self.subTest(line=line):
                (self.repo / "services/a/app.py").write_text(line + "\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.assertEqual(E.scan(self.repo, cfg)[0]["a"], set(), line)
        reads = {
            'P = os.path.join(ROOT, "services", "b")': {"b"},
            'P = ROOT / "services" / name': {"b"},
            'for root in ("services", "apps"):': {"b", "web"},
            'walk(ROOT / "apps")': {"web"},
            'P = Path(ROOT, "apps", name)': {"web"},
            "const p = join(ROOT, 'services', cap, 'dist');": {"b"},
            'for root in ("services",):': {"b"},
        }
        for line, expected in reads.items():
            with self.subTest(line=line):
                (self.repo / "services/a/app.py").write_text(line + "\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.assertEqual(E.scan(self.repo, cfg)[0]["a"], expected, line)


    def test_reader_scan_uses_immutable_revision_not_later_working_tree(self):
        cfg = self.pnpm_fixture()
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "frozen source"], check=True)
        revision = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        (self.repo / "server/test.ts").write_text("// later working-tree edit removes the reader\n")
        deps, _ = E.scan(self.repo, cfg, revision=revision)
        self.assertEqual(deps["server"], {"cli"})
        self.assertEqual(E.scan(self.repo, cfg)[0]["server"], set())
        with self.assertRaises(ValueError):
            E.scan(self.repo, cfg, revision="main")

    def test_unknown_declared_edge_and_duplicate_pnpm_name_are_not_ignored(self):
        cfg = self.pnpm_fixture()
        cfg["workspace"]["extra_deps"] = {"server": ["missing"]}
        with self.assertRaises(ValueError):
            E.workspace_graph(self.repo, cfg)
        cfg["workspace"].pop("extra_deps")
        (self.repo / "cli/package.json").write_text('{"name":"server"}')
        with self.assertRaises(ValueError):
            E.workspace_graph(self.repo, cfg)


if __name__ == "__main__":
    unittest.main()
