"""edges.py tests: a read in code is an edge, a read in a comment or Markdown is not, and check fails on an
undeclared read (the RED case) while a declared one passes."""
import base64
import io
import json
import re
import os
from unittest.mock import patch
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import datetime
import edges as E
from plan import backstop_full, classify_paths, rule_matches

# Root's ruling on #33 round 3: computed_imports and unresolved_names are a registry, each entry with a reason and a
# review_by at most 30 days after today(). The suite pins today(); fixtures that are not about the review get REVIEW.
E.today = lambda: datetime.date(2026, 10, 29)
REVIEW = {"reason": "test fixture: reviewed with its case", "review_by": "2026-11-20"}


def reviewed_cfg(cfg: dict) -> dict:
    """The config with REVIEW on every declaration that carries neither field (the registry tests pass both)."""
    cfg = json.loads(json.dumps(cfg))
    es = cfg.get("edge_scan") or {}
    for kind in ("computed_imports", "unresolved_names"):
        if isinstance(es.get(kind), list):
            es[kind] = [{**REVIEW, **d} if isinstance(d, dict) and not ({"reason", "review_by"} & set(d)) else d
                        for d in es[kind]]
    return cfg

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

    def always_cfg(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"] = "always"
        cfg["edge_scan"]["always_reader_dirs"] = ["scripts"]
        return cfg

    def test_always_reader_dirs_are_left_out_of_the_scan(self):
        """A directory whose files run only in `always` jobs cannot change a selection (no plan skips an `always` job),
        so a construct the scanner cannot read there no longer refuses, which planned every change FULL. The same
        construct anywhere else still refuses under the same config, and an undeclared directory still refuses."""
        refusing = 'p = os.path.join(ROOT, "services", "..", "b")\n'
        (self.repo / "scripts/gate.py").write_text(refusing)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        undeclared = json.loads(json.dumps(CFG))
        undeclared["jobs"]["root"] = "always"
        with self.assertRaises(ValueError):
            E.scan(self.repo, undeclared)  # control: not declared always-only, the parent step refuses
        cfg = self.always_cfg()
        self.assertEqual(E.scan(self.repo, cfg), ({"a": set(), "b": set()}, {"scripts": set()}))
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)
        # The same through an immutable revision, as action.yml runs `check --revision`.
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "commit", "-qm", "always", "--no-gpg-sign"], check=True)
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(E.scan(self.repo, cfg, revision=head)[1], {"scripts": set()})
        # FAIL-CLOSED ELSEWHERE: the same construct in a package still refuses under the same config.
        (self.repo / "services/a/gate.py").write_text(refusing)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaises(ValueError):
            E.scan(self.repo, cfg)

    def test_always_reader_dirs_refuse_every_declaration_that_could_hide_a_selecting_read(self):
        cases = {
            "the reader job selects (not always)": lambda c: c["jobs"].update(root={"packages": []}),
            "no reader job": lambda c: c["edge_scan"].pop("reader_job"),
            "a reader job that does not exist": lambda c: c["edge_scan"].update(reader_job="missing"),
            "not a declared reader directory": lambda c: c["edge_scan"].update(reader_dirs=[]),
            "a nested path": lambda c: c["edge_scan"].update(always_reader_dirs=["scripts/sub"], reader_dirs=["scripts/sub"]),
            "a parent step": lambda c: c["edge_scan"].update(always_reader_dirs=[".."], reader_dirs=[".."]),
            "a glob": lambda c: c["edge_scan"].update(always_reader_dirs=["scr*"], reader_dirs=["scr*"]),
            "a scan root": lambda c: c["edge_scan"].update(always_reader_dirs=["services"], reader_dirs=["services"]),
            # A root that holds no package yet: only the root check catches it (files under it are unmapped readers).
            "a scan root holding no package": lambda c: c["edge_scan"].update(
                roots=["services", "tools"], always_reader_dirs=["tools"], reader_dirs=["tools"]),
            "a directory holding a workspace package": lambda c: c["workspace"]["packages"].update(
                tool={"dir": "scripts/tool", "deps": []}),
            "an empty list": lambda c: c["edge_scan"].update(always_reader_dirs=[]),
            "not a list": lambda c: c["edge_scan"].update(always_reader_dirs="scripts"),
            "a repeated directory": lambda c: c["edge_scan"].update(always_reader_dirs=["scripts", "scripts"]),
        }
        self.assertEqual(E.scan(self.repo, self.always_cfg())[1], {"scripts": set()}, "control: the safe declaration scans")
        for why, mutate in cases.items():
            with self.subTest(why):
                cfg = self.always_cfg()
                mutate(cfg)
                with self.assertRaises(ValueError):
                    E.scan(self.repo, cfg)
        # 1.5.0: a package that imports a file in the directory runs it in every job that runs the package, so the
        # directory is not always-only, whatever the config says (cli, 2026-10-27: vagaris server imports scripts/).
        (self.repo / "services/a/uses.mjs").write_text('import { h } from "../../scripts/helper.mjs";\n')
        (self.repo / "scripts/helper.mjs").write_text("export const h = 1;\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaisesRegex(ValueError, "always_reader_dirs"):
            E.scan(self.repo, self.always_cfg())

    def test_a_change_inside_an_always_reader_dir_still_plans_full(self):
        """Leaving the directory out of the scan scopes its READS only; its own files stay unmapped."""
        import plan
        cfg = self.always_cfg()
        pkgs = E.workspace_graph(self.repo, cfg)
        evidence = plan.classify_paths(["scripts/gate.py"], cfg, pkgs)["evidence"]
        self.assertEqual(evidence["unmapped"], ["scripts/gate.py"])

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
            "pathlib join": ('P = ROOT / "services" / "b" / "app.py"\n', "py"),
            "os.path.join": ('P = os.path.join(ROOT, "services", "b")\n', "py"),
            "relative URL": ('const p = new URL("../../b/app.py", import.meta.url)\n', "js"),
            "go relative read": ('right, e := os.ReadFile("../../b/app.py")\n', "go"),
        }
        cfg = json.loads(json.dumps(CFG))
        cfg["workspace"]["packages"]["c"] = {"dir": "services/c", "deps": []}
        for name, (line, ext) in shapes.items():
            with self.subTest(name):
                for old in (self.repo / "services/c/test").glob("x.*"):
                    old.unlink()
                (self.repo / f"services/c/test/x.{ext}").write_text(line)
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                deps, _ = E.scan(self.repo, cfg)
                self.assertEqual(deps["c"], {"b"}, name)
        for old in (self.repo / "services/c/test").glob("x.*"):
            old.unlink()
        (self.repo / "services/c/test/x.py").write_text('local = "../fixtures/a.json"\n')
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
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

    def test_a_root_literal_is_metadata_only_with_positive_evidence(self):
        """Root's principle (2026-10-26): METADATA needs POSITIVE evidence (an object key or value, a subscript key, a
        comparison, a .sql file, or a literal list that is assigned, an object value or compared); EVERYTHING ELSE
        REFUSES, which plans FULL. Controls: the same literal in a path call or after a pathlib `/` IS a read, and a
        walker's root list reads every package under each root."""
        cfg = json.loads(json.dumps(CFG))
        cfg["edge_scan"]["roots"] = ["services", "apps"]
        cfg["workspace"]["packages"]["web"] = {"dir": "apps/web", "deps": []}
        (self.repo / "apps/web").mkdir(parents=True)
        (self.repo / "apps/web/page.tsx").write_text("export default 1\n")

        def scan(src, ext):
            for old in (self.repo / "services/a").glob("probe.*"):
                old.unlink()
            (self.repo / f"services/a/probe.{ext}").write_text(src + "\n")
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            return E.scan(self.repo, cfg)[0]["a"]

        # Round 4 (root, 2026-10-26): "reads nothing" only for ratified positive-evidence metadata.
        metadata = (
            ("{ key: 'services', label: 'Capabilities', icon: Server },", "js"),  # an object value
            ('{\n  "policy_id": "services",\n  "version": "1"\n}', "json"),
            ("INSERT INTO t VALUES ('apps', 'dns_iac', NULL);", "sql"),
            ('count = manifest["services"][0]', "py"),  # a subscript key
            # JSX closing tags are not regex literals: `</h2><p>{a}</p>` must not swallow a brace.
            ("export const V = ({ ok, a }) => <section>{ok ? <div><h2>{a}</h2><p>{a}</p></div> : null}</section>;\n"
             "const tabs = [{ key: 'services', label: 'Services' }];", "tsx"),
        )
        for src, ext in metadata:
            with self.subTest(metadata=src):
                self.assertEqual(scan(src, ext), set(), src)
        refused = (
            ('record = make("services", version="1", digest=value)', "py"),  # a direct call argument (root, H2)
            ('policy_ref = dict(policy_id="services", version="1")', "py"),
            ('shutil.copytree("services", "dist", dirs_exist_ok=True)', "py"),
            ('"services"', "py"),
            ('kind = "services"', "py"),
            ('def walk(root="services"):\n    pass', "py"),
            ("const p = web ? 'apps' : 'services';", "js"),
            ("const o = { dir: web ? other : 'services' };", "js"),  # a ternary branch is not an object value
            ("spawn('pytest', ['-q'], { cwd: 'services' });", "js"),  # an exec call's options are its argv's context
            ('const r = /"services"/;', "js"),  # a root inside a regex literal is not a token the classifier reads
            ('broken = (]\nTABS = ["services", "docs"]', "py"),  # a file whose brackets do not close is untrusted
            ('TABS = ["services", "docs"]\nbroken = (', "py"),
            ('p = os.path.join(ROOT, "services" + "/../../packages/shared")', "py"),  # not alone: `..` hides inside
            ('name = ("services", "docs")[i]', "py"),  # a subscripted collection is one root value, not a label list
            ("- 'services'", "yaml"),
            ('p = getattr(getattr(Path(ROOT, "services", name), "parent"), "parent") / "x"', "py"),  # rule 7 (T32)
            ('p = Path(ROOT, "services", name)\nq = p.parent.parent / "packages" / "shared"', "py"),  # rule 7 (T31)
            ("const p = `${root}/services/${up ? '..' : name}/x`;", "js"),  # H3.2: '..' in a substitution
            ('cd services\npytest ../packages/shared', "sh"),  # rule 7, raw: a `..` after a cd into a root path
            ('pytest services/b/../../packages/shared', "sh"),  # rule 7, raw: a root path and `..` on one line
            ("`${up}/..${sep}services/b`", "ts"),  # H3.2: a `..` step between substitutions
            ("f'{base}/..{os.sep}services/b'", "py"),  # H3.2 in an f-string
            ('"""\n>>> open(os.path.join(ROOT, "services", name))\n"""', "py"),  # a doctest is executed code
        )
        for src, ext in refused:
            with self.subTest(refused=src):
                with self.assertRaisesRegex(ValueError, "workspace-root reader expression"):
                    scan(src, ext)
        reads = {
            ('P = os.path.join(ROOT, "services", "b")', "py"): {"b"},
            ('P = ROOT / "services" / name', "py"): {"b"},
            ('for root in ("services", "apps"):\n    pass', "py"): {"b", "web"},
            ('walk(ROOT / "apps")', "py"): {"web"},
            ('P = Path(ROOT, "apps", name)', "py"): {"web"},
            ("const p = join(ROOT, 'services', cap, 'dist');", "js"): {"b"},
            ('for root in ("services",):\n    pass', "py"): {"b"},
            ("for (const root of ['services', 'docs']) walk(root);", "js"): {"b"},
            ("for (const [dir, job] of [['services', 'build'], ['docs', 'docs']]) run(dir, job);", "js"): {"b"},
            # A root named inside a string (prose, SQL, a glob, an f-string) is a walker read beneath it, not metadata.
            ('log.info("Walks the \'services\' tree")', "py"): {"b"},
            ('cur.execute("INSERT INTO t VALUES (\'services\')")', "py"): {"b"},
            ('for m in glob.glob("services/*/migrations"):\n    pass', "py"): {"b"},
            ('p = f"{ROOT}/services/{name}/x.json"', "py"): {"b"},
            ("const p = `${root}/services/${name}`;", "js"): {"b"},
            ('p = os.path.join(ROOT, "services", "{a,b}", "x")', "py"): {"b"},  # a brace glob is computed, not a name
            # Round 4: no rule turns a mention into nothing. Each of these reads beneath the root (wide).
            ("const tabs = ['services', 'providers', 'upstreams'];", "js"): {"b"},  # rule 8: no list exemption
            ("useQuery({\n  queryKey: ['monitoring', 'services'],\n  queryFn: load,\n});", "js"): {"b"},
            ('if kind == "services":\n    pass', "py"): {"b"},  # a comparison selects a value (H3.4)
            ("if (obligation === 'services') run();", "js"): {"b"},
            ('if part not in ("services", "docs"):\n    pass', "py"): {"b"},
            ('ctxs = {c for c in contexts if c.split("/", 1)[0] == "services"}', "py"): {"b"},
            ('"""A sweep across all of `services/` for the SDK copies."""', "py"): {"b"},  # docstrings are read (H3.6)
            ("'use strict';\nconst url = '/:org/services/:service';", "js"): {"b"},  # any root segment (H3.5)
            ('NOTE = "copied from backend/services/ in vagary-platform"', "py"): {"b"},
            ("SRC = b'name: services\\non: push\\n'", "py"): {"b"},  # a backslash always separates (H3.7)
            ('p = "{}/services/{}/x.json".format(ROOT, name)', "py"): {"b"},  # a placeholder prefix (P01)
            ('p = "services/b" + suffix', "py"): {"b"},  # a concatenated last component is partial (T21)
            ("pytest services/ -q", "sh"): {"b"},  # an unparsed file's root segment (T40)
            ('cd "$(dirname "$0")/.."  # services/r\npytest services/ -q', "sh"): {"b"},  # an anchor names no root
            ("`usage <item...> ${x} services/b`", "ts"): {"b"},  # an ellipsis in a template is not a `..` step
        }
        for (src, ext), expected in reads.items():
            with self.subTest(read=src):
                self.assertEqual(scan(src, ext), expected, src)


    # The independent review of 1.4.1 (root, 2026-10-26): 60 adversarial reader lines against this graph. A result
    # is SOUND when it reads every truth package or REFUSES (which plans FULL); it must never read less.
    REVIEW_CFG = {"schema": 1, "workspace": {"type": "declared", "packages": {
        "r": {"dir": "services/r", "deps": []}, "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []}, "nest": {"dir": "services/b/worker", "deps": []},
        "b2": {"dir": "services/b2", "deps": []}, "web": {"dir": "apps/web", "deps": []},
        "shared": {"dir": "packages/shared", "deps": []}}},
        "edge_scan": {"roots": ["services", "apps"], "reader_dirs": [], "reader_job": "root"},
        "jobs": {"root": {"packages": []}}}
    REVIEW_VECTORS = json.loads(Path(__file__).with_name("test_edges_review_vectors.json").read_text())["cases"]

    def review_scan(self, src, ext):
        repo = Path(self._td.name) / ("review-" + str(abs(hash(src)))[:10])
        for d in ("services/r", "services/a", "services/b/worker", "services/b2", "apps/web", "packages/shared"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        (repo / "services/r" / ("x." + ext)).write_text(src + "\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        try:
            return sorted(E.scan(repo, self.REVIEW_CFG)[0]["r"])
        except ValueError:
            return "REFUSE"

    def vector_scan(self, repo, case, revision=False):
        """One reviewer input in the fixture repo, through the working tree or (as action.yml runs `edges.py check
        --revision`) through an immutable commit whose working tree has since changed."""
        subprocess.run(["git", "-C", str(repo), "rm", "-rq", "--cached", "--ignore-unmatch", "services/r"], check=True)
        for f in sorted((repo / "services/r").rglob("*"), reverse=True):
            if f.is_file() and f.name != "keep.txt":
                f.unlink()
        rel = case.get("file") or "services/r/x." + case["ext"]
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        # `src_hex` holds raw bytes a JSON string cannot (an invalid UTF-8 byte, R7V14).
        (repo / rel).write_bytes(bytes.fromhex(case["src_hex"]) if "src_hex" in case else case["src"].encode("utf-8"))
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        cfg = {**self.REVIEW_CFG, **(case.get("cfg") or {})}
        rev = None
        if revision:
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid",
                            "commit", "-qm", "vector", "--no-gpg-sign"], check=True)
            rev = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            (repo / rel).write_text("# the working tree differs from the scanned revision\n")
        try:
            return sorted(E.scan(repo, cfg, revision=rev)[0]["r"])
        except ValueError:
            return "REFUSE"

    def vector_repo(self, name):
        repo = Path(self._td.name) / name
        for d in ("services/r", "services/a", "services/b/worker", "services/b2", "apps/web", "packages/shared", ".github"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        return repo

    def judge(self, label, case, got):
        truth, expect = case["truth"], case["expect"]
        if expect == "refuse":
            self.assertEqual(got, "REFUSE", label)
        elif expect == "residual":
            # A named residual reads less than its truth by ruling; its reading when pinned is recorded so that one
            # reading even less (or more) fails here until the pin is re-derived on purpose.
            self.assertEqual(got, case["reads"], f"{label}: a residual's reading moved from its pin")
        else:
            self.assertTrue(got == "REFUSE" or set(truth) <= set(got), f"{label}: read {got}, truth {truth}")
            if expect == "read":
                self.assertNotEqual(got, "REFUSE", f"{label}: a resolvable read must not refuse")

    def test_review_vectors_read_their_truth_or_refuse(self):
        """Every input of root's three independent reviews, spine's own probes and the round-4 rule-7 vectors: none may
        read less than its truth without refusing, and those resolvable today must keep reading. Exempt: A12/N08/N11
        (object values and keys, the ratified metadata), T19/T36/T37 (lexical limits), M5/M6/V48 (a literal root read
        does not start taint: measured +11 vagary-core refusals) and V45-V47 (heads by tuple slicing, a regex or
        os.path.split), and the fifth and sixth reviews' inputs outside README rule 4's closed list, all named
        residuals."""
        repo = self.vector_repo("vectors")
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            with self.subTest(label):
                self.judge(label, case, self.vector_scan(repo, case))
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c["expect"] == "residual" and "reads" not in c),
                         [], "every residual vector pins its reading")
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c["expect"] == "residual"),
                         [
                          "A12_dict_value_as_path", "M5_py_literal_join_then_parent_parent",
                          "M6_py_literal_slash_then_parents", "N08_dict_values_walked", "N11_dict_key_walked",
                          "R5V01_py_subprocess_module_alias", "R5V02_py_from_subprocess_import_run",
                          "R5V03_py_command_string_via_variable", "R5V04_py_asyncio_create_subprocess_shell",
                          "R5V07_js_execaCommand", "R5V08_js_child_process_destructured_alias",
                          "R5V17_yaml_key_is_project_dir", "R5V24_py_dirname_alias_inline_comment",
                          "R5V25_py_dirname_alias_tuple", "R5V26_js_require_dirname_alias",
                          "R5V27_py_parent_name_concat_dots", "R5V28_py_parent_name_joined_dots",
                          "R5V29_py_parent_name_path_dotdot", "R5V30_py_parent_name_fstring",
                          "R5V31_py_parent_name_in_substitution", "R5V32_py_adjacent_dot_literals_in_subst",
                          "R5V33_py_joined_dots_in_subst", "R5V35_py_cached_property",
                          "R5V36_py_property_with_comment", "R5V37_py_function_ref_via_assignment",
                          "R5V38_py_getattr_literal_method", "R5V39_py_factory_closure", "R5V40_py_deque_appendleft",
                          "R5V41_js_object_assign", "R6V02_yml_key_still_metadata_control", "R6V03_uppercase_YML_ext",
                          "R6V18_pkg_husky_hooks_not_scripts", "R6V24_chdir_then_path_cwd_parent",
                          "R6V25_chdir_then_fstring_dotdot_end", "T19_partial_split_root",
                          "T36_computed_prefix_not_repo_root",
                          "T37_fstring_computed_prefix_not_root", "V45_py_parts_slice_head", "V46_py_regex_head",
                          "V47_py_split_head_contract", "V48_py_literal_read_then_parent"])

    def test_the_action_path_reads_the_scanned_revision(self):
        """action.yml runs `edges.py check --revision <candidate>`: the classifier reads the committed bytes, never a
        later working tree. The round-2 cases whose lines span or shift, plus positive controls that must READ."""
        repo = self.vector_repo("revision")
        for label in ("N10_py_ternary_in_join", "N12_fstring_sql_with_nested_join", "N26_subprocess_multiline_list_own_line",
                      "N27_subprocess_list_opened_own_line", "N31_js_spawn_multiline", "N42_parent_after_Path_call",
                      "N52_formfeed_above_multiline_join", "N53_u2028_in_js_string_above_join",
                      "X01_formfeed_index_overrun_crash", "X02_lone_cr_above_multiline_join",
                      "A01_multiline_join_computed", "A02_multiline_join_literal", "A03_multiline_args_same_line",
                      "W07_multiline_roots"):
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.judge(label, case, self.vector_scan(repo, case, revision=True))
        for label in ("A01_multiline_join_computed", "A02_multiline_join_literal", "N52_formfeed_above_multiline_join"):
            with self.subTest(precision=label):
                self.assertNotEqual(self.vector_scan(repo, self.REVIEW_VECTORS[label], revision=True), "REFUSE")
        # Controls: metadata stays metadata, and a keyword named `parents` is not a parent step.
        self.assertEqual(self.review_scan("{ key: 'services', label: 'Capabilities', icon: Server },", "js"), [])
        self.assertEqual(self.review_scan('(Path(tmp) / "services" / "a" / sub).mkdir(parents=True)', "py"), ["a"])

    def test_round5_precision_narrowings_read_exactly(self):
        """Each round-5 narrowing is a positive-evidence shape, so it must read EXACTLY this, not merely its truth: a
        wide read here means the narrowing was lost (the must-read vectors alone accept an over-read)."""
        for label, want in (("R5R01_py_dot_separator_in_substitution", ["b"]),
                            ("R5R02_yaml_compose_services_key", []),
                            ("R5R03_py_database_execute_not_a_command", []),
                            ("R5R04_py_def_default_cwd_not_a_process_cwd", ["b", "nest"])):
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.assertEqual(self.vector_scan(self.vector_repo("exact-" + label[:5]), case), want)

    def test_reader_scan_greps_bytes_whatever_the_callers_locale(self):
        """R7V14: under a UTF-8 locale `git grep -E` stops matching a line at an invalid UTF-8 byte, which hid a root
        mention after it. The scan pins LC_ALL=C; the caller's locale is set to C.UTF-8 here, so a scan that inherited
        it would read nothing."""
        case = self.REVIEW_VECTORS["R7V14_pkg_invalid_utf8_byte_before_script"]
        with patch.dict(os.environ, {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}):
            self.assertEqual(self.vector_scan(self.vector_repo("locale"), case), ["a", "b", "b2", "nest"])

    def test_round7_package_json_and_toml_read_exactly(self):
        """Round 7's reads, pinned exactly (a must-read vector accepts an over-read): a BOM-prefixed package.json reads
        its script; every string script is read, the second included; a non-string or nested value is skipped, and an
        empty or absent `scripts` reads nothing, without refusing; a TOML key reads like any bare word."""
        svc = ["a", "b", "b2", "nest"]
        for label, want in (("R6V15_pkg_utf8_bom", svc),
                            ("R6V16_pkg_two_scripts_second_reads", svc + ["web"]),
                            ("R6V10_pkg_nested_scripts_object", []),
                            ("R6V11_pkg_non_string_values", svc),
                            ("R7T09_pkg_empty_scripts", []),
                            ("R7T10_pkg_bom_no_scripts", []),
                            ("R6V30_toml_key_precision", svc),
                            ("R7T12_toml_colon_key_reads", svc)):
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.assertEqual(self.vector_scan(self.vector_repo("exact7-" + label[:6]), case), want)

    def test_an_unowned_path_a_glob_maps_or_inerts_refuses(self):
        """F6: an unowned path is safe to leave unread only because its change is unmapped and plans FULL. When a
        caller's inert_globs or extra_edges covers it, that is no longer true, so the read refuses."""
        sources = (('p = os.path.join(ROOT, "services", "fixtures", "seed.json")', "py"),
                   ('p = "services/fixtures/seed.json"', "py"),  # the literal form, read through a string
                   ("const p = 'services/fixtures/seed.json';", "js"))
        for src, ext in sources:
            self.assertEqual(self.review_scan(src, ext), [])
        for key, value in (("inert_globs", ["services/fixtures/**"]), ("extra_edges", {"services/fixtures/**": ["a"]})):
            for src, ext in sources:
                with self.subTest(key=key, src=src):
                    self.REVIEW_CFG = {**type(self).REVIEW_CFG, key: value}
                    self.assertEqual(self.review_scan(src, ext), "REFUSE")
        self.REVIEW_CFG = type(self).REVIEW_CFG

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


IMPORT_CFG = {
    "schema": 1,
    "workspace": {"type": "declared", "packages": {
        "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []},
        "c": {"dir": "services/c", "deps": []},
        "tp": {"dir": "tools/pkg", "deps": []},
    }},
    "edge_scan": {"roots": ["services"], "reader_dirs": ["scripts", "tools"], "reader_job": "root",
                  "exclude": ["*.md", "docs", ".github", "vendor"]},
    "jobs": {"root": "always"},
}


class ImportAttributionTest(unittest.TestCase):
    """1.5.0: a package is credited with the reads of the files outside every package it imports (cli, 2026-10-27).
    Before it, a relative path resolving outside every package was dropped, so deps(a) missed what scripts/x.mjs read."""

    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.repo = Path(self._td.name)
        for d in ("services/a", "services/b", "services/c", "tools/pkg", "scripts", ".github"):
            (self.repo / d).mkdir(parents=True)
        for d in ("services/b", "services/c", "tools/pkg"):
            (self.repo / d / "app.py").write_text("x = 1\n")
        (self.repo / "services/a/app.py").write_text("x = 1\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)

    def files(self, **files):
        for path, text in files.items():
            target = self.repo / path.replace("__", "/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def scan(self, cfg=None):
        report = {}
        deps, readers = E.scan(self.repo, reviewed_cfg(cfg or IMPORT_CFG), report=report)
        return deps, readers, report

    def test_one_hop_import_credits_the_imported_files_reads(self):
        self.files(**{"services__a__t.test.mjs": 'import { x } from "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'export const x = () => readFileSync("services/b/data.json");\n'})
        deps, readers, report = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(readers["scripts"], {"b"}, "the reader job keeps its credit: nothing is ever narrower")
        self.assertEqual(report["imports"], {"scripts/x.mjs": ["a"]})

    def test_a_dot_slash_import_inside_a_reached_file_is_followed_though_the_grep_never_sees_it(self):
        # y.mjs is reached only through `./y.mjs`, a line with no root and no `../`: only the whole-file read finds it.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'import { y } from "./y.mjs";\nexport { y };\n',
                      "scripts__y.mjs": 'export const y = "services/c/z.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"c"})
        self.assertEqual(sorted(report["imports"]), ["scripts/x.mjs", "scripts/y.mjs"])

    def test_cycles_terminate_and_two_importers_are_both_credited(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "services__b__t.mjs": 'import "../../scripts/y.mjs";\n',
                      "scripts__x.mjs": 'import "./y.mjs";\nconst p = "services/c/q.json";\n',
                      "scripts__y.mjs": 'import "./x.mjs";\n'})
        deps, _, report = self.scan()
        self.assertEqual((deps["a"], deps["b"]), ({"c"}, {"c"}))
        self.assertEqual(report["imports"], {"scripts/x.mjs": ["a", "b"], "scripts/y.mjs": ["a", "b"]})

    def test_extensionless_require_python_sibling_and_shell_source_resolve(self):
        self.files(**{"services__a__t.cjs": 'const m = require("../../scripts/m");\n',
                      "scripts__m.js": 'module.exports = 1;\nrequire("./run.py");\n',
                      "scripts__run.py": "import helper\n",
                      "scripts__helper.py": 'P = "services/b/x.json"\n',
                      "services__c__t.mjs": 'import "../../scripts/r.sh";\n',
                      "scripts__r.sh": '#!/bin/bash\nsource "$(dirname "$0")/lib.sh"\n',
                      "scripts__lib.sh": "cat services/a/data.txt\n"})
        deps, _, _ = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(deps["c"], {"a"})

    def test_a_symlinked_file_or_directory_resolves_to_its_target(self):
        self.files(**{"tools__real.mjs": 'export const r = "services/b/x.json";\n',
                      "services__a__t.mjs": 'import "../../scripts/link.mjs";\nimport "../../scripts/dirlink/real.mjs";\n'})
        os.symlink("../tools/real.mjs", self.repo / "scripts/link.mjs")
        os.symlink("../tools", self.repo / "scripts/dirlink")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertIn("tools/real.mjs", report["imports"])

    def test_a_directory_target_reads_its_files_and_a_nested_package_is_a_dep(self):
        self.files(**{"services__a__t.mjs": 'const dir = new URL("../../tools/", import.meta.url);\n',
                      "tools__z.mjs": 'export const z = "services/c/z.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"c", "tp"}, "tools/pkg is package tp: an edge to it is a dep, not a closure file")
        self.assertNotIn("tools/pkg/app.py", report["imports"])

    def test_data_targets_are_credited_markdown_is_edge_only_and_a_data_route_is_followed(self):
        # Root's round 3 of #33, B1: a reached data file's ./ route is a route (a compose volume, a tsconfig `files`), so
        # its ./more.mjs is followed and what more.mjs reads (c) is credited too. A .md file stays edge-only.
        self.files(**{"services__a__t.mjs": 'read("../../scripts/data.json"); read("../../scripts/notes.md");\n',
                      "scripts__data.json": '{"dir": "services/b/x", "next": "./more.mjs"}\n',
                      "scripts__more.mjs": 'export const m = "services/c/m.json";\n',
                      "scripts__notes.md": "see services/c\n"})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b", "c"}, "the data file is credited, and so is the module its ./more.mjs names")
        self.assertEqual(sorted(report["imports"]), ["scripts/data.json", "scripts/more.mjs", "scripts/notes.md"])

    def test_fail_closed_on_an_excluded_or_always_only_code_target(self):
        self.files(**{"services__a__t.mjs": 'import "../../vendor/v.mjs";\n', "vendor__v.mjs": "export {};\n"})
        with self.assertRaisesRegex(ValueError, "excludes"):
            self.scan()
        (self.repo / "services/a/t.mjs").write_text('import "../../scripts/s.mjs";\n')
        self.files(**{"scripts__s.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["always_reader_dirs"] = ["scripts"]
        with self.assertRaisesRegex(ValueError, "always_reader_dirs"):
            self.scan(cfg)

    def test_a_refusal_inside_a_reached_file_refuses(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'export const p = path.join(ROOT, "services", "..", "b");\n'})
        with self.assertRaises(ValueError):
            self.scan()

    def test_a_shorthand_method_named_require_or_import_is_a_definition_not_a_call(self):
        # Spine (core's console vm sandboxes, 2026-10-27): `{ ..., require(name) { ... } }` defines a method.
        for body in ("vm.runInNewContext(code, { module, require(name) { return stubs[name]; } });\n",
                     "const sandbox = {\n  require(spec) {\n    throw new Error(spec);\n  },\n};\n",
                     "class Box { static require(name) { return name; } import(x) { return x; } }\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__vm.test.mjs": body})
                self.scan()
        # Controls: a real computed call inside that method body stays a site, and ASI keeps `= require(name)` a call.
        controls = {"inner call": "const require_ = createRequire(import.meta.url);\n"
                                  "const s = { require(name) { return require_(name); } };\n",
                    "asi": "const x = require(name)\n{ x(); }\n"}
        for why, body in controls.items():
            with self.subTest(why):
                self.files(**{"services__a__vm.test.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
                    self.scan()

    def test_a_non_file_url_scheme_import_names_no_file(self):
        for body in ("await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);\n",
                     "await import('data:text/javascript,' + src);\n",
                     "await import(`node:${name}`);\n",
                     "await import(`https://cdn.example/${pkg}`);\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__sync.mjs": body})
                self.scan()
        # Controls: a file: URL and a bare substitution still refuse.
        for body in ("await import(`file:${p}`);\n", "await import(`${p}`);\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__sync.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()

    def test_computed_imports_refuse_unless_declared_and_an_escape_refuses_even_declared(self):
        self.files(**{"services__a__load.mjs": "export const load = (name) => import(name);\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": "name", "reach": "external"}]
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for escaping in ('import(path.join(here, "..", name))', 'import("../../" + name)', "import(`../../scripts/${n}.mjs`)",
                         'require(join(root, "scripts", n))'):
            with self.subTest(escaping):
                (self.repo / "services/a/load.mjs").write_text(f"export const load = () => {escaping};\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                expr = escaping[escaping.index("(") + 1:-1]
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": expr, "reach": "external"}]
                # `"../../"` alone resolves to the repository root, which refuses first (D5, N4): either way, never mapped.
                with self.assertRaisesRegex(ValueError, "steps outside its package|the repository root or above it"):
                    self.scan(cfg)

    def test_a_parent_step_inside_the_package_needs_a_package_declaration_and_an_escape_never_passes(self):
        # vagary-core identity's contract-drift test: `import(\`../dist/${m}\`)` stays inside its own package.
        f = "services/a/test/drift.mjs"
        self.files(**{"services__a__test__drift.mjs": "export const d = (m) => import(`../dist/${m}`);\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": "`../dist/${m}`", "reach": "external"}]
        with self.assertRaisesRegex(ValueError, 'must be declared reach "package"'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "package"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for escaping in ("import(`../../x/${m}`)", "import(`${base}/../x`)", "import(`../dist/${m}/../../../scripts/y.mjs`)",
                         "require(path.resolve(__dirname, '..', '..', 'scripts', x))",
                         "require(path.join(__dirname, x, '..', '..', '..', 'scripts', 'y.mjs'))"):
            with self.subTest(escaping):
                (self.repo / f).write_text(f"export const d = () => {escaping};\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": escaping[escaping.index("(") + 1:-1],
                                                         "reach": "package"}]
                with self.assertRaisesRegex(ValueError, "steps outside its package"):
                    self.scan(cfg)

    def test_an_all_literal_path_anchored_at_the_file_is_a_literal_import(self):
        # vagary-core webhook-egress's ssrf test: require(path.resolve(__dirname, '..', 'dist', 'ssrf.js')).
        self.files(**{
            "services__a__test__ssrf.test.mjs": "const { v } = require(path.resolve(__dirname, '..', 'dist', 'ssrf.js'));\n"
                                                "const here = dirname(fileURLToPath(import.meta.url));\n"
                                                "const x = await import(pathToFileURL(join(here, '..', '..', '..', "
                                                "'scripts', 'x.mjs')).href);\n",
            "scripts__x.mjs": 'export const x = "services/b/x.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"}, "the anchored literal chain to scripts/x.mjs is an edge, and its reads credit a")
        self.assertIn("scripts/x.mjs", report["imports"])

    def test_every_module_loader_form_is_held_to_the_declaration_rule(self):
        forms = {"require.resolve": "const p = require.resolve(name);\n",
                 "import.meta.resolve": "const p = import.meta.resolve(name);\n",
                 "createRequire(...)(x)": "const m = createRequire(import.meta.url)(name);\n",
                 "a createRequire binding": "const r = createRequire(import.meta.url);\nconst m = r(name);\n",
                 "module.require": "const m = module.require(name);\n"}
        for why, body in forms.items():
            with self.subTest(why):
                self.files(**{"services__a__load.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
                    self.scan()
        self.files(**{"services__a__load.mjs": "const m = registry.require(name);\n"})
        self.assertEqual(self.scan()[2]["computed_imports_unused"], [], "control: an object's own `require` is no loader")

    def test_a_literal_under_a_typescript_cast_is_a_literal_and_a_cast_name_is_not(self):
        # vagary-core's services/*/src/observability.ts load `import("@opentelemetry/sdk-node" as string)`: a literal.
        self.files(**{"services__a__obs.ts": 'const m = await import("redis" as string);\n'})
        self.assertEqual(self.scan()[2]["computed_imports_unused"], [])
        (self.repo / "services/a/obs.ts").write_text("const m = await import(name as string);\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name as string`"):
            self.scan()

    def test_a_declared_reach_list_is_an_edge_and_a_stale_declaration_fails_check(self):
        self.files(**{"services__a__load.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "scripts__x.mjs": 'export const x = "services/b/x.json";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [
            {"file": "services/a/load.mjs", "expr": "pathToFileURL(f).href", "reach": ["scripts/x.mjs"]},
            {"file": "services/a/gone.mjs", "expr": "x", "reach": "package"}]
        deps, _, report = self.scan(cfg)
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(report["computed_imports_unused"], ["services/a/gone.mjs: x"])
        assessment = E.assess(E.workspace_graph(self.repo, cfg), cfg, deps, {"scripts": set(), "tools": set()},
                              revision=None, config_path=Path(__file__),
                              computed_unused=report["computed_imports_unused"])
        self.assertIn("stale computed_imports entry: services/a/gone.mjs: x matches no import call", assessment["failures"])

    def test_check_fails_on_an_undeclared_import_edge_until_extra_edges_maps_it(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))

        def check(c):
            (self.repo / ".github/ci-plan.json").write_text(json.dumps(c))
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
            return rc, buf.getvalue()

        rc, out = check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("undeclared import edge: a imports scripts/x.mjs", out)
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        self.assertEqual(check(cfg)[0], 0)
        import plan
        pkgs = E.workspace_graph(self.repo, cfg)
        selected = plan.classify_paths(["scripts/x.mjs"], cfg, pkgs)
        self.assertEqual((selected["evidence"]["unmapped"], sorted(selected["affected"])), ([], ["a"]),
                         "a change to the imported file selects its importer, not FULL")

    def test_every_git_grep_of_the_scan_refuses_typed_when_it_cannot_read(self):
        # Root's carry-over from #47 (556963a): no grep site of the scan may fail by a bare SystemExit. Each `git grep` the
        # scan runs on this tree is made to exit 128 in turn (git 2.56's unreadable-blob status); every one refuses typed,
        # and the labels cover 1.5.2's own sites: the shell and Python listings and the Python import grep.
        self.files(**{
            "services__a__test__conftest.py": "import os, sys\n"
                                              'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts"))\n',
            "services__a__test__test_x.py": "import helper\n",
            "scripts__helper.py": 'P = "services/b/x.json"\n',
            "scripts__run.sh": "echo checking\n",  # the shell listing reads every *.sh, whatever it holds
            "services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        head = self._commit(self.repo, "head")
        cfg = reviewed_cfg({**IMPORT_CFG, "extra_edges": {"scripts/x.mjs": ["a"]}})
        real = subprocess.run
        greps = []

        def counting(argv, *args, **kwargs):
            if "grep" in argv[:6]:
                greps.append(argv)
            return real(argv, *args, **kwargs)

        with patch.object(E.subprocess, "run", counting):
            E.scan(self.repo, cfg, revision=head)  # control: every grep reads, and the scan completes
        self.assertGreaterEqual(len(greps), 5)
        labels = set()
        for k in range(len(greps)):
            seen = []

            def failing(argv, *args, **kwargs):
                if "grep" in argv[:6]:
                    seen.append(argv)
                    if len(seen) == k + 1:
                        return subprocess.CompletedProcess(argv, 128, b"", b"fatal: planted\n")
                return real(argv, *args, **kwargs)

            with patch.object(E.subprocess, "run", failing), self.assertRaises(ValueError, msg=f"grep #{k}") as caught:
                E.scan(self.repo, cfg, revision=head)
            message = str(caught.exception)
            self.assertIn("(git grep exit 128: fatal: planted)", message, f"grep #{k}")
            labels.add(re.search(r"reader closure unproven: (.*?) could not read the scanned tree", message).group(1))
        self.assertLessEqual({"the reader scan's shell listing", "the reader scan's Python listing",
                              "the reader scan's Python import grep", "the reader scan"}, labels)

    def test_python_sys_path_entries_credit_what_the_package_imports_by_name(self):
        # 1.5.2. The entry sits in conftest.py, and the import in another test file: sys.path is process-wide.
        self.files(**{
            "services__a__test__conftest.py": "import os, sys\n"
                                              'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts"))\n',
            "services__a__test__test_x.py": "import helper\n",
            "scripts__helper.py": 'P = "services/b/x.json"\n',
            "scripts__unused.py": 'Q = "services/c/q.json"\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"}, "only a module the package imports by name is credited")
        self.assertIn("scripts/helper.py", report["imports"])
        self.assertNotIn("scripts/unused.py", report["imports"])

    def test_a_sys_path_entry_into_another_package_is_a_dep_and_into_its_own_is_nothing(self):
        self.files(**{"services__a__t.py": "import sys\nfrom pathlib import Path\n"
                                            'APP = Path(__file__).resolve().parent / "app"\n'
                                            'OTHER = Path(__file__).resolve().parents[1] / "b" / "app"\n'
                                            "sys.path.insert(0, str(APP))\nsys.path.insert(0, str(OTHER))\n"})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_an_unresolved_sys_path_entry_refuses_when_it_may_leave_its_package(self):
        for entry in ('os.environ.get("X", "../scripts")', 'os.path.join(ROOT, "scripts")', 'os.path.join(REPO, "services", "b")'):
            with self.subTest(entry):
                self.files(**{"services__a__t.py": f"import os, sys\nsys.path.insert(0, {entry})\n"})
                with self.assertRaisesRegex(ValueError, "sys.path entry"):
                    self.scan()
        self.files(**{"services__a__t.py": "import os, sys\nsys.path.insert(0, os.getcwd())\n"})
        self.assertEqual(self.scan()[0]["a"], set(), "control: no parent step, no top-level name: a documented residual")

    def test_every_sys_path_form_and_an_unparseable_file(self):
        entry = 'os.path.join(os.path.dirname(__file__), "..", "..", "scripts")'
        for form in ("sys.path.append(E)", "sys.path.extend([E])", "sys.path += [E]", "sys.path[0:0] = [E]"):
            with self.subTest(form):
                self.files(**{"services__a__t.py": f"import os, sys\n{form.replace('E', entry)}\nimport helper\n",
                              "scripts__helper.py": 'P = "services/b/x.json"\n'})
                self.assertEqual(self.scan()[0]["a"], {"b"})
        self.files(**{"services__a__t.py": "import sys\nsys.path.insert(0, 'x'\n"})
        with self.assertRaisesRegex(ValueError, "does not parse"):
            self.scan()

    def test_pytest_pythonpath_is_a_sys_path_entry_from_the_config_pytest_would_pick(self):
        # Root-level configs with no `../` in them, so only rule 6 can see the entry (a package file's `../` path is a
        # rule-1 edge on its own). A root pyproject.toml puts scripts/ on every package's path.
        self.files(**{"pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["scripts"]\n',
                      "services__a__test_x.py": "import helper\n",
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # In one directory pytest.ini wins over pyproject.toml, even with no [pytest] section.
        self.files(**{"pytest.ini": "# empty: still the config\n"})
        self.assertEqual(self.scan()[0]["a"], set())
        # An entry into package c is a dep of every other Python package the config serves.
        (self.repo / "pytest.ini").unlink()
        self.files(**{"pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["services/c/app"]\n'})
        deps = self.scan()[0]
        self.assertEqual((deps["a"], deps["b"], deps["c"]), ({"c"}, {"c"}, set()))
        # The NEAREST config wins: a's own pytest.ini (an entry inside a) shadows the root's entry into c for a only.
        self.files(**{"services__a__pytest.ini": "[pytest]\npythonpath = sub\n"})
        deps = self.scan()[0]
        self.assertEqual((deps["a"], deps["b"]), (set(), {"c"}))
        (self.repo / "services/a/pytest.ini").unlink()
        # The package's own unreadable setup.cfg is the one pytest would read, so it refuses.
        self.files(**{"services__a__setup.cfg": "[tool:pytest\npythonpath = x\n"})
        with self.assertRaisesRegex(ValueError, "does not parse"):
            self.scan()

    def test_python_loaders_by_computed_name_or_path_are_held_to_the_declaration_rule(self):
        self.files(**{"services__a__load.py": "import importlib\nm = importlib.import_module(name)\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py", "expr": "name", "reach": "external"}]
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for why, body in (("__import__", "m = __import__(name)\n"), ("runpy.run_module", "import runpy\nrunpy.run_module(name)\n"),
                          ("exec(open(p).read())", "exec(open(p).read())\n")):
            with self.subTest(why):
                self.files(**{"services__a__load.py": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
        # A path from __file__ with literal parts is a literal load: an edge, credited, with no declaration.
        self.files(**{"services__a__load.py": "import os, importlib.util\nspec = importlib.util.spec_from_file_location("
                                               '"m", os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "m.py"))\n',
                      "scripts__m.py": 'P = "services/b/m.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # An unevaluated path naming a parent step or an outside top-level directory refuses even when declared.
        for escaping in ('runpy.run_path(os.path.join(ROOT, "scripts", "x.py"))', 'runpy.run_path("../../x.py")'):
            with self.subTest(escaping):
                self.files(**{"services__a__load.py": f"import os, runpy\n{escaping}\n"})
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py",
                                                         "expr": escaping[escaping.index("(") + 1:-1], "reach": "package"}]
                with self.assertRaisesRegex(ValueError, "may leave its package"):
                    self.scan(cfg)

    def test_python_loaders_get_fix_1_and_fix_2_shape(self):
        # Root's R4 of #33 carried into 1.5.2's Python loaders: an unowned file's loaders are checked and select its
        # own unit, a literal load naming no tracked file refuses, and reach "package" refuses outside every package.
        self.files(**{"scripts__x.py": "import importlib\nm = importlib.import_module(name)\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        self.files(**{"scripts__x.py": "import os, importlib.util\nspec = importlib.util.spec_from_file_location("
                                       '"m", os.path.join(os.path.dirname(__file__), "..", "services", "b", "m.py"))\n',
                      "services__b__m.py": "M = 1\n",
                      "services__a__run.sh": "#!/bin/bash\npython3 ../../scripts/x.py\n"})
        deps, readers, report = self.scan()
        self.assertEqual(readers["scripts"], {"b"}, "x.py's own unit, the scripts/ reader job, loads b")
        self.assertEqual(deps["a"], {"b"}, "a runs x.py, so a is credited with what it loads")
        self.assertEqual(report["unowned_callers"], {"scripts/x.py": {"unit": "scripts", "reaches": ["b"]}})
        self.files(**{"services__a__load.py": "import os, runpy\nrunpy.run_path(os.path.join(os.path.dirname(__file__), "
                                               '"..", "..", "scripts", "gone.py"))\n'})
        with self.assertRaisesRegex(ValueError, "a reaches scripts/gone.py, which names no tracked file"):
            self.scan()
        (self.repo / "services/a/load.py").unlink()
        self.files(**{"scripts__x.py": "import importlib\nm = importlib.import_module(name)\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/x.py", "expr": "name", "reach": "package"}]
        with self.assertRaisesRegex(ValueError, 'declared reach "package", but scripts/x.py is outside every package'):
            self.scan(cfg)

    def test_an_unowned_caller_loading_an_unowned_path_declares_it_and_a_parent_step_still_escapes(self):
        # Spine's A2 census (2026-10-28): scripts/identity-products-apply.py's `HERE / file` and
        # scripts/test_contract_drift.py's `_mod.ROOT / "scripts/gen-capability-docs.py"`. The caller is outside every
        # package, so the load leaves no package: it is a load to declare (reach as paths), not an escape.
        cases = {"evaluated prefix": 'from pathlib import Path\nimport runpy\nHERE = Path(__file__).parent\n'
                                     'runpy.run_path(str(HERE / file))\n',
                 "unevaluated prefix": 'import runpy\nrunpy.run_path(str(_mod.ROOT / "scripts/gen.py"))\n'}
        for why, body in cases.items():
            with self.subTest(why):
                self.files(**{"scripts__apply.py": body, "scripts__gen.py": "G = 1\n"})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
                expr = "str(HERE / file)" if why == "evaluated prefix" else 'str(_mod.ROOT / "scripts/gen.py")'
                cfg = json.loads(json.dumps(IMPORT_CFG))
                cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/apply.py", "expr": expr, "reach": ["scripts/gen.py"]}]
                self.scan(cfg)
                (self.repo / "scripts/apply.py").unlink()
        # Controls: an unowned caller whose prefix has a package beneath it (the repo root via `..`, or services/) still
        # escapes, and package code reaching an unowned path still escapes, declared or not.
        for body in ('from pathlib import Path\nimport runpy\nHERE = Path(__file__).parent\nrunpy.run_path(str(HERE / ".." / file))\n',
                     'from pathlib import Path\nimport runpy\nROOT = Path(__file__).parents[1]\nrunpy.run_path(str(ROOT / "services" / name))\n'):
            with self.subTest(body=body):
                self.files(**{"scripts__apply.py": body})
                with self.assertRaisesRegex(ValueError, "may leave its package"):
                    self.scan()
                (self.repo / "scripts/apply.py").unlink()
        self.files(**{"services__a__load.py": 'import runpy\nrunpy.run_path(str(_mod.ROOT / "scripts/gen.py"))\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py", "expr": 'str(_mod.ROOT / "scripts/gen.py")',
                                                 "reach": ["scripts/gen.py"]}]
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan(cfg)

    def test_pathlib_edits_evaluate_and_the_floor_judges_the_evaluated_prefix(self):
        # vagary-core's evidence app vendors a package INSIDE itself: PACKAGE / "scripts/..." is its own subdirectory,
        # not the top-level scripts/ (spine, 2026-10-27; a rewrite to the repo-root copy would have broken the service).
        self.files(**{"services__a__app__contract.py": "import importlib.util\nfrom pathlib import Path\n"
                                                        'PACKAGE = Path(__file__).with_name("_vendored")\n'
                                                        'spec = importlib.util.spec_from_file_location("m", PACKAGE / "scripts/x.py")\n',
                      "services__a__app___vendored__scripts__x.py": 'P = "services/b/x.json"\n'})
        deps, _, report = self.scan()
        self.assertEqual(report["computed_imports_unused"], [])
        self.assertNotIn("services/a/app/_vendored/scripts/x.py", report["imports"], "inside the importing package: no edge")
        # The same shape with a prefix that does not evaluate still refuses: nothing says where "scripts" is.
        self.files(**{"services__a__app__contract.py": "import importlib.util\n"
                                                        'spec = importlib.util.spec_from_file_location("m", PKG / "scripts/x.py")\n'})
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan()
        # An evaluated prefix OUTSIDE the package (the repo root's scripts/) with a computed tail refuses, even declared.
        cfg = json.loads(json.dumps(IMPORT_CFG))
        root_tail = 'ROOT / "scripts" / x'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        "ROOT = Path(__file__).resolve().parents[3]\n"
                                                        f"runpy.run_path({root_tail})\n"})
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": root_tail, "reach": "package"}]
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan(cfg)
        # An evaluated in-package prefix with a computed tail is declarable, as reach "package" only.
        inside_tail = 'PACKAGE / "scripts" / x'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        'PACKAGE = Path(__file__).with_name("_vendored")\n'
                                                        f"runpy.run_path({inside_tail})\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": inside_tail, "reach": "external"}]
        with self.assertRaisesRegex(ValueError, 'must be declared reach "package"'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "package"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        # An evaluated prefix inside ANOTHER package with a computed tail is declarable, and a dep on that package.
        other_tail = 'PLANE / (name + ".py")'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        'PLANE = Path(__file__).resolve().parents[2] / "c" / "app"\n'
                                                        f"runpy.run_path({other_tail})\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": other_tail, "reach": "external"}]
        self.assertIn("c", self.scan(cfg)[0]["a"], "the prefix's package c is a dep (only the vendored file reads b)")
        # joinpath evaluates too: a sys.path entry into package b through it is a dep.
        self.files(**{"services__a__app__contract.py": "import sys\nfrom pathlib import Path\n"
                                                        'sys.path.insert(0, str(Path(__file__).resolve().parents[2].joinpath("b", "app")))\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_a_loop_over_a_literal_is_literal_names_and_anything_short_of_it_refuses(self):
        # vagary-core's observability.py: `for mod_name, cls in ((<const>, <const>), ...): import_module(mod_name)`.
        loads = {
            "a literal tuple of pairs": 'for mod_name, cls in (("redis", "R"), ("dns", "D")):\n    m = importlib.import_module(mod_name)\n',
            "a module-level name bound once": 'MODS = ("redis", "dns")\nfor m in MODS:\n    importlib.import_module(m)\n',
            "a comprehension": 'mods = [importlib.import_module(m) for m in ("redis",)]\n',
        }
        for why, body in loads.items():
            with self.subTest(why):
                self.files(**{"services__a__load.py": "import importlib\n" + body})
                self.assertEqual(self.scan()[2]["computed_imports_unused"], [], "no declaration needed")
        refused = {
            "the literal mutated after binding": 'MODS = ["redis"]\nMODS.append(x)\nfor m in MODS:\n    importlib.import_module(m)\n',
            "the loop variable rebound in the body": 'for m in ("redis",):\n    m = other\n    importlib.import_module(m)\n',
            "an f-string argument": 'for m in ("redis",):\n    importlib.import_module(f"x.{m}")\n',
            "an iterable from a call": 'for m in sorted(("redis",)):\n    importlib.import_module(m)\n',
            "a name bound twice": 'MODS = ("a",)\nMODS = ("b",)\nfor m in MODS:\n    importlib.import_module(m)\n',
        }
        for why, body in refused.items():
            with self.subTest(why):
                self.files(**{"services__a__load.py": "import importlib\n" + body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
        # The names resolve by name like any import: through a sys.path entry they are edges, and credited.
        self.files(**{"services__a__load.py": "import importlib, os, sys\n"
                                               'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))\n'
                                               'for m in ("helper",):\n    importlib.import_module(m)\n',
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_a_literal_loader_name_resolves_through_a_sys_path_entry(self):
        self.files(**{"services__a__t.py": "import os, sys\n"
                                            'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))\n'
                                            'mod = __import__("helper")\n',
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # A reached Python file's own computed loader is held to the same rule.
        self.files(**{"scripts__helper.py": 'import importlib\nP = "services/b/x.json"\nm = importlib.import_module(name)\n'})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`.* in scripts/helper.py"):
            self.scan()
    def check(self, cfg):
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(reviewed_cfg(cfg)))
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
        return rc, buf.getvalue()

    def test_root_r4_counterexample_a_js_specifier_of_a_ts_file_is_never_dropped(self):
        # root's R4 of #33 (2026-10-27): c imported scripts/x.ts as ../../scripts/x.js and was DROPPED, so the mapping
        # check requested ({"scripts/x.ts": ["a"]}) passed and a change to x.ts selected only a, narrower than FULL.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.ts";\n',
                      "services__c__t.mjs": 'import { x } from "../../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n"})
        self.assertEqual(self.scan()[2]["imports"], {"scripts/x.ts": ["a", "c"]})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1, "the narrowing mapping no longer passes")
        self.assertIn("undeclared import edge: c imports scripts/x.ts", out)
        cfg["extra_edges"] = {"scripts/x.ts": ["a", "c"]}
        self.assertEqual(self.check(cfg)[0], 0)
        import plan
        selected = plan.classify_paths(["scripts/x.ts"], cfg, E.workspace_graph(self.repo, cfg))
        self.assertEqual(sorted(selected["affected"]), ["a", "c"])

    def test_every_typescript_source_form_resolves(self):
        cases = {"x.jsx": "scripts/x.tsx", "x.mjs": "scripts/x.mts", "x.cjs": "scripts/x.cts", "y.js": "scripts/y.d.ts"}
        for spec, source in cases.items():
            with self.subTest(spec):
                self.files(**{"services__a__t.mjs": f'import "../../scripts/{spec}";\n',
                              source.replace("/", "__"): "export {};\n"})
                self.assertIn(source, self.scan()[2]["imports"])

    def test_a_path_that_names_nothing_refuses_and_an_untracked_path_in_a_package_maps_to_it(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/gone.js";\n'})
        with self.assertRaisesRegex(ValueError, "services/a/t.mjs names scripts/gone.js, which is no tracked file or directory"):
            self.scan()
        # A build output in a package (untracked dist/) stands for that package: a dep, never dropped. tools/run.mjs
        # names it as ./pkg/dist/index.js, a line with no root and no ../, so only the whole-file read sees it.
        self.files(**{"services__a__t.mjs": 'import "../../tools/run.mjs";\n',
                      "tools__run.mjs": 'export { p } from "./pkg/dist/index.js";\n'})
        self.assertEqual(self.scan()[0]["a"], {"tp"})

    def test_spine_control_an_unowned_caller_selects_its_own_unit_and_credits_its_importers(self):
        # spine's binding control for fix 2 (2026-10-27): a root-level scripts/x.mjs loads services/b/src/y.ts through
        # a declared computed import. Touching y must select x's unit (the reader job), and a package that imports x
        # is credited with b. Before fix 2 an unowned caller's computed import credited nothing.
        decl = [{"file": "scripts/x.mjs", "expr": "pathToFileURL(f).href", "reach": ["services/b/src/y.ts"]}]
        self.files(**{"scripts__x.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "services__b__src__y.ts": "export const y = 1;\n",
                      "services__a__t.mjs": 'import { load } from "../../scripts/x.mjs";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = decl
        cfg["jobs"] = {"root": {"packages": []}}
        deps, readers, report = self.scan(cfg)
        self.assertEqual(readers["scripts"], {"b"}, "x's own unit, the scripts/ reader job, reads b")
        self.assertEqual(deps["a"], {"b"}, "a reaches x, so a is credited with what x loads")
        self.assertEqual(report["unowned_callers"], {"scripts/x.mjs": {"unit": "scripts", "reaches": ["b"]}})
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("scripts/ reads b, but job 'root' does not list it", out)
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
        # scripts/x.mjs sits in the reader directory scripts/, so a change to it must still run that job (D5, N3): the
        # mapping names b, which the root job lists, beside its importer a.
        cfg["extra_edges"] = {"scripts/x.mjs": ["a", "b"]}
        self.assertEqual(self.check(cfg)[0], 0)
        import plan
        affected = plan.classify_paths(["services/b/src/y.ts"], cfg, E.workspace_graph(self.repo, cfg))["affected"]
        self.assertEqual(plan.rule_matches(cfg["jobs"]["root"], affected)[0], True, "touching y selects x's unit")

    def test_an_unowned_caller_outside_every_reader_dir_maps_to_unmapped_and_plans_full(self):
        self.files(**{"x.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "services__b__src__y.ts": "export const y = 1;\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "x.mjs", "expr": "pathToFileURL(f).href",
                                                 "reach": ["services/b/src/y.ts"]}]
        _, readers, report = self.scan(cfg)
        self.assertEqual(readers["<unmapped>"], {"b"})
        self.assertEqual(report["unowned_callers"], {"x.mjs": {"unit": "<unmapped>", "reaches": ["b"]}})
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1, "no unit runs x.mjs, so check fails and the plan is FULL, never a drop")
        self.assertIn("unmapped source readers require a declared obligation: b", out)

    def test_an_unowned_files_undeclared_computed_import_refuses(self):
        self.files(**{"scripts__x.mjs": "export const load = (name) => import(name);\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()

    def test_reach_package_outside_every_package_refuses(self):
        # Root's R4 of #33, fix 4: reach "package" for a file outside every package names and credits nothing.
        self.files(**{"scripts__x.mjs": "export const load = (name) => import(name);\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/x.mjs", "expr": "name", "reach": "package"}]
        with self.assertRaisesRegex(ValueError, 'declared reach "package", but scripts/x.mjs is outside every package'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "external"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [], "control: another reach is accepted")

    def test_root_r4_an_escape_can_never_be_declared_away(self):
        # Root's R4 of #33, fix 3: a parent step after the join's closing bracket, and nested dirname() calls, escape.
        f = "services/a/load.mjs"
        cfg = json.loads(json.dumps(IMPORT_CFG))
        for escaping in ('import(path.join(__dirname, "lib") + "/../../../scripts/x.mjs")',
                         'import(path.join(dirname(dirname(__dirname)), "x", n))',
                         'import(join(path.dirname(here), "lib", n))'):
            for reach in ("package", "external"):
                with self.subTest(escaping, reach=reach):
                    self.files(**{"services__a__load.mjs": f"export const load = (n, here) => {escaping};\n"})
                    cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": escaping[escaping.index("(") + 1:-1],
                                                             "reach": reach}]
                    with self.assertRaisesRegex(ValueError, "steps outside its package|the repository root or above it"):
                        self.scan(cfg)
        # Controls: the file's own directory is the anchor, not a step up, and a literal tail without `..` is no escape.
        for fine in ('import(path.join(dirname(fileURLToPath(import.meta.url)), "lib", n))',
                     'import(path.join(path.dirname(__filename), "lib", n))',
                     'import(path.join(__dirname, "lib") + ".mjs")'):
            with self.subTest(fine):
                self.files(**{"services__a__load.mjs": f"export const load = (n) => {fine};\n"})
                cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": fine[fine.index("(") + 1:-1],
                                                         "reach": "external"}]
                self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])

    def test_an_anchored_literal_join_followed_by_a_computed_tail_is_no_literal_import(self):
        # Kills root's m3 (`if not rest:`): the chain closes, then `+ name` is computed, so it must be declared.
        self.files(**{"services__a__load.mjs": 'export const load = (name) => import(path.join(__dirname, "lib") + name);\n'})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()

    def test_check_fails_on_an_imported_path_that_inert_globs_hides(self):
        # The end-to-end selection census (2026-10-27): vagaris's candidate config makes docs/** inert, and the server
        # imports docs/docs.json, so a change to it selected NOTHING though check had asked for extra_edges.
        self.files(**{"services__a__t.mjs": 'import data from "../../scripts/data/x.json";\n',
                      "scripts__data__x.json": "{}\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["extra_edges"] = {"scripts/data/x.json": ["a"]}
        cfg["inert_globs"] = ["scripts/data/**"]
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("inert import: scripts/data/x.json is imported by a, but inert_globs 'scripts/data/**'", out)
        import plan
        self.assertEqual(plan.classify_paths(["scripts/data/x.json"], cfg, E.workspace_graph(self.repo, cfg))["affected"],
                         set(), "the hole itself: inert wins over extra_edges")
        cfg["inert_globs"] = ["scripts/data/*.md"]
        self.assertEqual(self.check(cfg)[0], 0, "control: a glob that leaves the import out is accepted")

    def test_a_trailing_slash_exclude_names_its_directory(self):
        # Root's R4 of #33 (non-blocking): `vendor/` never matched in excluded(), though git's pathspec excludes it.
        self.files(**{"services__a__t.mjs": 'import "../../third/x.mjs";\n', "third__x.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["exclude"] = ["*.md", "docs", ".github", "third/"]
        with self.assertRaisesRegex(ValueError, "a reaches third/x.mjs, code the scan excludes"):
            self.scan(cfg)

    def test_d5_every_route_that_resolves_to_nothing_refuses_in_any_position(self):
        # Root's delta R4 of #33, D5 (N1): a scan that cannot run a line cannot tell a module position from data, so a
        # name that resolves to no tracked file refuses wherever it stands: every spelling below plans [a] at 7b83bf159e
        # although the file it loads is a's dependency. node_modules stays external.
        spellings = {
            "timeout": "timeout 300 node ../../tools/dist/x.js\n",
            "npx tsx": "npx tsx ../../tools/dist/x.js\n",
            "env -i": "env -i node ../../tools/dist/x.js\n",
            "node --import": "node --import ../../tools/dist/x.js main.js\n",
            "pnpm exec": "pnpm exec node ../../tools/dist/x.js\n",
            "xargs": "printf a | xargs node ../../tools/dist/x.js\n",
            "nohup": "nohup node ../../tools/dist/x.js &\n",
            "heredoc import": "node --input-type=module <<'EOF'\nimport \"../../tools/dist/x.js\";\nEOF\n",
            "find pattern": "find . ! -path '../../tools/dist/x.js'\n",
        }
        for why, body in spellings.items():
            with self.subTest(why):
                self.files(**{"services__a__run.sh": "#!/bin/bash\n" + body})
                with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                    self.scan()
        for why, js in {"fork": 'fork("../../tools/dist/x.js");', "Worker": 'new Worker("../../tools/dist/x.js");',
                        "spawn": 'spawn(process.execPath, ["../../tools/dist/x.js"]);'}.items():
            with self.subTest(why):
                self.files(**{"services__a__run.sh": "#!/bin/bash\n", "services__a__w.mjs": js + "\n"})
                with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                    self.scan()
        with self.subTest("package.json script"):
            self.files(**{"services__a__w.mjs": "export {};\n",
                          "services__a__package.json": '{"scripts": {"t": "node ../../tools/dist/x.js"}}\n'})
            with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                self.scan()
        self.files(**{"services__a__package.json": '{"scripts": {"t": "node ../../node_modules/.bin/vitest"}}\n'})
        self.scan()  # an installed binary is external

    def test_d5_a_declared_unresolved_name_names_nothing_or_stands_for_its_paths(self):
        self.files(**{"services__a__run.sh": "#!/bin/bash\nnode ../../tools/dist/x.js\ncat ../../tools/out/r.txt\n",
                      "tools__x.ts": 'export const p = "services/b/p.json";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        # Root's round 3 of #33, F09: reach "none" for a CODE name says it runs nothing, so it refuses.
        cfg["edge_scan"]["unresolved_names"] = [{"file": "services/a/run.sh", "name": "tools/dist/x.js", "reach": "none"},
                                                {"file": "services/a/run.sh", "name": "tools/out/r.txt", "reach": "none"}]
        with self.assertRaisesRegex(ValueError, r"names tools/dist/x.js, a code file, with reach \"none\""):
            self.scan(cfg)
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/x.ts"]
        deps, _, report = self.scan(cfg)
        self.assertEqual(report["unresolved_data_names"], ["tools/dist/x.js", "tools/out/r.txt"],
                         "both names resolve to nothing; the data one may reach nothing, the code one reaches its source")
        deps, _, report = self.scan(cfg)
        self.assertEqual(deps["a"], {"b"}, "a build output declared as its source is an edge to that source")
        self.assertEqual(report["imports"]["tools/x.ts"], ["a"])
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/also-gone.ts"]  # a declared reach that names nothing
        with self.assertRaisesRegex(ValueError, "reaches tools/also-gone.ts, which names no tracked file or directory"):
            self.scan(cfg)
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/x.ts"]
        cfg["edge_scan"]["unresolved_names"].append({"file": "services/a/run.sh", "name": "tools/gone.txt", "reach": "none"})
        self.assertIn("unresolved_names services/a/run.sh: tools/gone.txt", self.scan(cfg)[2]["computed_imports_unused"])
        cfg["edge_scan"]["unresolved_names"] = [{"file": "services/a/run.sh", "name": "tools/dist/x.js", "reach": "some"}]
        with self.assertRaisesRegex(ValueError, "unresolved_names entries must be"):
            self.scan(cfg)

    def test_the_declaration_lists_are_a_reviewed_registry_that_fails_toward_full(self):
        # Root's ruling on #33 round 3: a reason, and a review_by within 30 days of today(); otherwise the scan refuses.
        self.files(**{"services__a__run.sh": "#!/bin/bash\ncat ../../tools/out/r.txt\n",
                      "services__a__load.mjs": "export const l = (name) => import(name);\n"})
        names = {"file": "services/a/run.sh", "name": "tools/out/r.txt", "reach": "none"}
        loads = {"file": "services/a/load.mjs", "expr": "name", "reach": "external"}
        good = {"reason": "a report the test writes, never run", "review_by": "2026-11-28"}
        for kind, entry in (("unresolved_names", names), ("computed_imports", loads)):
            other = ("computed_imports", loads) if kind == "unresolved_names" else ("unresolved_names", names)
            for why, review, message in (
                    ("no reason", {"reason": " ", "review_by": "2026-11-20"}, "has no reason"),
                    ("expired", {"reason": "r", "review_by": "2026-10-28"}, "expired on 2026-10-28"),
                    ("too far", {"reason": "r", "review_by": "2026-11-29"}, "more than 30 days out"),
                    ("not a date", {"reason": "r", "review_by": "soon"}, "is not an ISO date")):
                with self.subTest(kind=kind, why=why):
                    cfg = json.loads(json.dumps(IMPORT_CFG))
                    cfg["edge_scan"][kind] = [{**entry, **review}]
                    cfg["edge_scan"][other[0]] = [{**other[1], **good}]
                    with self.assertRaisesRegex(ValueError, rf"edge_scan.{kind} registry review: .*{message}"):
                        E.scan(self.repo, cfg)
            cfg = json.loads(json.dumps(IMPORT_CFG))
            cfg["edge_scan"]["unresolved_names"] = [{**names, **good}]
            cfg["edge_scan"]["computed_imports"] = [{**loads, **good}]
            E.scan(self.repo, cfg)  # control: both reviewed, the last day of the window included
            cfg["edge_scan"][kind] = [entry]
            with self.assertRaisesRegex(ValueError, rf"edge_scan.{kind} entries must be"):
                E.scan(self.repo, cfg)  # an entry without the two fields is malformed

    def test_b2_anchored_segment_chains_are_parent_steps_in_every_position(self):
        # Root's round 3 of #33, B2: each spelling resolves like the relative path written out, pinned exactly.
        cases = {
            ('const d = path.join(__dirname, "..", "..", "lib", "x.mjs"); fork(d);', "mjs"): ["../../lib/x.mjs"],
            ('export default { test: { dir: path.join(__dirname, "..", "..") } };', "mjs"): ["../.."],
            ('const here = dirname(fileURLToPath(import.meta.url));\nnew Worker(path.resolve(here, "..", "s", "w.mjs"));',
             "mjs"): ["../s/w.mjs"],
            ('const a = join(import.meta.dirname, "..", "x.mjs");', "mjs"): ["../x.mjs"],
            ('x = os.path.join(os.path.dirname(__file__), "..", "lib")', "py"): ["../lib"],
            ('x = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")', "py"): ["../.."],
            ('HERE = os.path.dirname(__file__)\nx = os.path.join(HERE, "..", "w.py")', "py"): ["../w.py"],
            ('ROOT = Path(__file__).resolve().parents[2]', "py"): ["../.."],  # 1.5.2: the alias's own binding is no use
            ('w = Path(__file__).parent / ".." / "w.py"', "py"): ["../w.py"],
            ('w = Path(__file__).parent.parent / "w.py"', "py"): ["../w.py"],
            ('REPO = Path(__file__).resolve().parents[1]\ns = REPO / "scripts" / "x.sh"', "py"): ["..", "../scripts/x.sh"],
        }
        for (src, ext), want in cases.items():
            with self.subTest(src):
                self.assertEqual(E.anchored_chains(E.Source(src, ext)), want)
        for src, ext in (('d = path.join(__dirname, "lib", "x.mjs");', "mjs"), ('d = path.join(base, "..", "x");', "mjs"),
                         ('p = Path(__file__).parent / "w.py"', "py"), ('p = os.path.join(base, "..")', "py")):
            with self.subTest(control=src):
                self.assertEqual(E.anchored_chains(E.Source(src, ext)), [], "no parent step from the anchor: no chain")
        # In a scan: a Python root base by parents[N] refuses as a root climb when it is used other than joined with
        # string literals (1.5.2, root's ruling b); a bound base nobody uses reaches nothing.
        self.files(**{"services__a__t.py": "import subprocess\nfrom pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\n"
                                           "subprocess.run(['make'], cwd=ROOT)\n"})
        with self.assertRaisesRegex(ValueError, r"services/a/t.py names \.\./\.\., the repository root or above it"):
            self.scan()
        self.files(**{"services__a__t.py": "from pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\n"})
        self.scan()

    def test_one_batch_reader_serves_a_scans_revision_reads_byte_for_byte(self):
        # perf: one `git cat-file --batch` per scan, not one `git show` per file; the bytes are git show's exactly.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\r\n",
                      "scripts__bin.txt": "caf\u00e9\n"})
        (self.repo / "scripts/raw.txt").write_bytes(b"ok \xff\xfe\n")
        (self.repo / "scripts/x.mjs\r").write_text("CR TWIN\n")  # N1: --batch would drop the CR and read x.mjs
        os.symlink("x.mjs", self.repo / "scripts/link.mjs")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit",
                        "-qm", "r", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        shown = lambda path: subprocess.run(["git", "-C", str(self.repo), "show", f"{rev}:{path}"], capture_output=True,
                                            check=True).stdout.decode("utf-8", errors="replace")
        real_popen, real_run, spawned, shows = subprocess.Popen, subprocess.run, [], []
        def counting(*a, **k):
            spawned.append(a[0])
            return real_popen(*a, **k)
        def run_counting(*a, **k):
            if "show" in a[0]:
                shows.append(a[0])
            return real_run(*a, **k)
        paths = ("scripts/x.mjs", "scripts/bin.txt", "scripts/raw.txt", "scripts/link.mjs", "scripts/x.mjs", "scripts/x.mjs\r")
        expected = {path: shown(path) for path in paths}  # before the counters go on
        with patch.object(E.subprocess, "Popen", counting), patch.object(E.subprocess, "run", run_counting), \
                E.batch_reads(self.repo, rev, env):
            for path in paths[:-1]:
                self.assertEqual(E.read_source(self.repo, path, rev, env), expected[path], path)
            self.assertEqual(len([c for c in spawned if "cat-file" in c]), 1, "one reader for every read")
            self.assertEqual(shows, [], "no per-file git show while the reader serves")
            self.assertEqual(E.read_source(self.repo, "scripts/x.mjs\r", rev, env), "CR TWIN\n", "a CR name is its own blob")
            self.assertEqual(len(shows), 1, "a CR cannot go through --batch: it falls back to git show")
            with self.assertRaisesRegex(ValueError, "cannot read scripts/gone.mjs at the scanned revision"):
                E.read_source(self.repo, "scripts/gone.mjs", rev, env)  # missing: falls back to git show, which refuses
            with self.assertRaisesRegex(ValueError, "cannot read scripts/a\nb at the scanned revision"):
                E.read_source(self.repo, "scripts/a\nb", rev, env)  # a newline cannot go through --batch
            # N2 (framing): the reads AFTER a refused name are still the reader's, byte for byte. Sent to --batch, the
            # newline name would be two requests, and every later read would get the previous one's answer.
            served = len(shows)
            for path in ("scripts/bin.txt", "scripts/raw.txt", "scripts/x.mjs"):
                self.assertEqual(E.read_source(self.repo, path, rev, env), expected[path], path)
            self.assertEqual(len(shows), served, "after a refused name the reader still serves every read")
            E._BLOB_READERS[(str(self.repo), rev)].proc.kill()
            E._BLOB_READERS[(str(self.repo), rev)].proc.wait()
            self.assertEqual(E.read_source(self.repo, "scripts/x.mjs", rev, env), expected["scripts/x.mjs"],
                             "a dead reader falls back to git show")
        self.assertNotIn((str(self.repo), rev), E._BLOB_READERS, "the reader closes with its scan")
        deps, _ = E.scan(self.repo, reviewed_cfg(IMPORT_CFG), revision=rev)  # a whole scan through the reader
        self.assertIn("a", deps)

    def test_the_backstop_counts_base_and_head_mentions(self):
        # Root's per-path ruling, condition (1): the flagged set is computed over BASE and HEAD. A PR that deletes the
        # only reader of tools/worker.mjs while changing it still plans that path FULL, since the deleted reader ran
        # it at the base; a reader the PR adds is a HEAD mention. The planner config is the BASE copy either way
        # (action.yml): the base tree is data like the head, and it can only add FULL paths, never remove one.
        def commit(message):
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid",
                            "commit", "-qm", message, "--no-gpg-sign"], check=True)
            return subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/worker.mjs": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        runner = 'import { execFileSync } from "node:child_process";\nexecFileSync(process.execPath, ["tools/worker.mjs"]);\n'
        self.files(**{"services__a__t.mjs": 'import "../../tools/worker.mjs";\n', "tools__worker.mjs": "export {};\n",
                      "services__c__t.test.mjs": runner})
        base = commit("base: c runs tools/worker.mjs")
        (self.repo / "services/c/t.test.mjs").unlink()
        (self.repo / "tools/worker.mjs").write_text("export const changed = 1;\n")
        head = commit("head: the PR deletes c's runner and changes worker.mjs")

        def flagged(*extra):
            out = self.repo / ".git" / "readers.json"
            with redirect_stdout(io.StringIO()):
                rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo), "--revision", head,
                             "--out-json", str(out), *extra])
            return rc, json.loads(out.read_text())["backstop_full"]

        self.assertEqual(flagged(), (0, []), "control: HEAD alone no longer names the deleted reader")
        self.assertEqual(flagged("--base-revision", base), (0, ["tools/worker.mjs"]), "BASE: the deleted reader counts")
        (self.repo / "services/c/t.test.mjs").write_text(runner)
        head = commit("head: the PR adds the reader back")
        self.assertEqual(flagged()[1], ["tools/worker.mjs"], "a reader the PR adds is a HEAD mention")
        with self.assertRaisesRegex(ValueError, "base revision must be an immutable commit"):
            flagged("--base-revision", "main")

    def _commit(self, repo, message):
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit", "-qm",
                        message, "--no-gpg-sign"], check=True)
        return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

    def _flagged(self, repo, head, *extra):
        out = Path(tempfile.mkdtemp()) / "readers.json"
        with redirect_stdout(io.StringIO()):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(repo), "--revision", head,
                         "--out-json", str(out), *extra])
        return rc, json.loads(out.read_text())["backstop_full"]

    def test_the_subjects_are_both_trees_a_deleted_or_moved_p_still_counts(self):
        # Root's condition on the base-only reduction: the SUBJECT side is BASE ∪ HEAD. The PR deletes (or renames) mapped
        # tools/old.mjs; an UNCHANGED file of package c still runs it by name, so the head pass must test that mention.
        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/**": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        self.files(**{"services__a__t.mjs": 'import "../../tools/old.mjs";\n', "tools__old.mjs": "export {};\n",
                      "services__c__run.test.mjs": 'import { execFileSync } from "node:child_process";\n'
                                                   'execFileSync(process.execPath, ["tools/old.mjs"]);\n'})
        base = self._commit(self.repo, "base")
        for how in ("delete", "rename"):
            with self.subTest(how):
                subprocess.run(["git", "-C", str(self.repo), "checkout", "-q", base], check=True)
                (self.repo / "services/a/t.mjs").write_text("export {};\n")
                if how == "delete":
                    (self.repo / "tools/old.mjs").unlink()
                else:
                    (self.repo / "tools/old.mjs").rename(self.repo / "tools/new.mjs")
                head = self._commit(self.repo, how)
                self.assertNotIn("tools/old.mjs", self._flagged(self.repo, head)[1], "control: HEAD alone has no old.mjs")
                self.assertIn("tools/old.mjs", self._flagged(self.repo, head, "--base-revision", base)[1],
                              "a P only BASE maps, named by an unchanged file, is a subject")

    def test_a_blobless_candidate_reads_the_base_side_from_the_sparse_base_checkout(self):
        # vagaris checks out `filter: blob:none`, so its candidate holds no base blobs (and the scan never fetches). The
        # base pass reads the PR's deleted and modified files from the action's sparse base checkout instead.
        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/worker.mjs": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        runner = 'import { execFileSync } from "node:child_process";\nexecFileSync(process.execPath, ["tools/worker.mjs"]);\n'
        self.files(**{"services__a__t.mjs": 'import "../../tools/worker.mjs";\n', "tools__worker.mjs": "export {};\n",
                      "services__c__t.test.mjs": runner})
        base = self._commit(self.repo, "base")
        (self.repo / "services/c/t.test.mjs").unlink()
        (self.repo / "tools/worker.mjs").write_text("export const changed = 1;\n")
        head = self._commit(self.repo, "head")
        subprocess.run(["git", "-C", str(self.repo), "config", "uploadpack.allowFilter", "true"], check=True)
        work = Path(tempfile.mkdtemp())
        cand, basechk = work / "cand", work / "base"
        url = "file://" + str(self.repo)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(cand)], check=True)
        subprocess.run(["git", "-C", str(cand), "checkout", "-q", head], check=True)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(basechk)], check=True)
        subprocess.run(["git", "-C", str(basechk), "sparse-checkout", "set", "--no-cone", "/.github/ci-plan.json",
                        "/services/c/t.test.mjs", "/tools/worker.mjs"], check=True)
        subprocess.run(["git", "-C", str(basechk), "checkout", "-q", base], check=True)
        with self.assertRaisesRegex(ValueError, "the base tree's changed files could not be read"):
            self._flagged(cand, head, "--base-revision", base)  # control: the candidate holds no base blobs
        self.assertEqual(self._flagged(cand, head, "--base-revision", base, "--base-repo", str(basechk)),
                         (0, ["tools/worker.mjs"]))

    def test_a_grep_that_cannot_read_a_blob_refuses_instead_of_missing(self):
        # git grep exits 1 ("no match") when a blob is absent (a partial clone, no lazy fetch) and prints only
        # `unable to read`. Every grep of the scan treats that as a refusal, never as a clean miss.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        head = self._commit(self.repo, "head")
        subprocess.run(["git", "-C", str(self.repo), "config", "uploadpack.allowFilter", "true"], check=True)
        cand = Path(tempfile.mkdtemp()) / "cand"
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "file://" + str(self.repo), str(cand)],
                       check=True)
        subprocess.run(["git", "-C", str(cand), "sparse-checkout", "set", "--no-cone", "/scripts/"], check=True)
        subprocess.run(["git", "-C", str(cand), "checkout", "-q", head], check=True)  # services/a/t.mjs: no blob
        with self.assertRaisesRegex(ValueError, "reader closure unproven: the reader scan could not read the scanned tree"):
            E.scan(cand, reviewed_cfg(IMPORT_CFG), revision=head)
        deps, _ = E.scan(self.repo, reviewed_cfg(IMPORT_CFG), revision=head)  # control: every blob present
        self.assertIn("a", deps)

    def test_both_unreadable_signals_refuse_typed_whatever_the_git_version(self):
        # git 2.50 prints `unable to read` and exits 1; git 2.56 exits 128 (#47's planner-tests, 2026-10-29). Both are a
        # typed refusal with git's first stderr line; 0 (a match) and 1 with a clean stderr (no match) are not.
        run = lambda rc, err=b"": subprocess.CompletedProcess(["git", "grep"], rc, b"", err)
        for out, detail in ((run(1, b"error: 'HEAD:a.mjs': unable to read 1234\n"), "git grep exit 1: error: 'HEAD:a.mjs': unable to read 1234"),
                            (run(128, b"fatal: missing blob object 'abcd'\n"), "git grep exit 128: fatal: missing blob object 'abcd'"),
                            (run(2), "git grep exit 2")):
            with self.assertRaises(ValueError) as caught:
                E.grep_read_everything(out, "the reader scan")
            self.assertEqual(str(caught.exception), "unresolved (reader closure unproven: the reader scan could not read "
                                                    f"the scanned tree ({detail}))")
        for out in (run(0), run(1)):
            E.grep_read_everything(out, "the reader scan")  # control: a match, and a clean miss, are read

    def test_a_grep_git_cannot_run_on_its_revision_refuses_typed_not_a_crash(self):
        # Root's control, the local rc-128 path: real git grep on a revision that does not exist exits 128, as git 2.56
        # does for an unreadable blob. The pass refuses typed with git's own line; it never crashes into FULL.
        self.files(**{"a.mjs": "export const x = 1;\n"})
        self._commit(self.repo, "head")
        out = subprocess.run(["git", "-C", str(self.repo), "grep", "--no-color", "-I", "-e", "x", "f" * 40, "--"],
                             capture_output=True, env={**os.environ, "LC_ALL": "C"})
        self.assertEqual(out.returncode, 128)
        with self.assertRaisesRegex(ValueError, r"reader closure unproven: the reader scan could not read the scanned tree "
                                                r"\(git grep exit 128: fatal: "):
            E.grep_read_everything(out, "the reader scan")

    def test_base_paths_name_exactly_the_deleted_and_modified_files_for_the_sparse_base_checkout(self):
        # The action adds these patterns to its sparse base checkout; each must check out exactly its own file, whatever
        # characters the name holds (gitignore syntax), and an added file is not one (the base has no such file).
        names = ["services/a/x.mjs", "odd/*star?[x].txt", "odd/!bang", "odd/#hash", "odd/trail  ", "odd/back\\slash",
                 "odd/sp ace.js", "gone.mjs"]
        self.files(**{n.replace("/", "__"): "v1\n" for n in names + ["kept.txt", "odd/starXx].txt"]})
        base = self._commit(self.repo, "base")
        for n in names[:-1]:
            (self.repo / n).write_text("v2\n")
        (self.repo / "gone.mjs").unlink()
        (self.repo / "added.mjs").write_text("new\n")
        head = self._commit(self.repo, "head")
        self.assertEqual(E.base_paths(self.repo, base, head), sorted(names))
        out = Path(tempfile.mkdtemp()) / "out"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(["base-paths", "--repo", str(self.repo), "--base-revision", base, "--revision", head,
                                     "--github-output", str(out)]), 0)
        lines = out.read_text().split("\n")
        self.assertTrue(lines[0].startswith("paths<<EOF_") and lines[-2] == lines[0][len("paths<<"):])
        patterns = lines[1:-2]
        chk = Path(tempfile.mkdtemp()) / "chk"
        subprocess.run(["git", "clone", "-q", "--no-checkout", str(self.repo), str(chk)], check=True)
        subprocess.run(["git", "-C", str(chk), "sparse-checkout", "set", "--no-cone", "--stdin"],
                       input="\n".join(patterns) + "\n", text=True, check=True)
        subprocess.run(["git", "-C", str(chk), "checkout", "-q", base], check=True)
        present = sorted(str(p.relative_to(chk)) for p in chk.rglob("*") if p.is_file() and ".git" not in p.parts)
        self.assertEqual(present, sorted(names), "each pattern checks out exactly its own file")

    def test_a_pass_that_times_out_is_a_typed_refusal(self):
        # F18 (root, 2026-10-29): census part 2 of #33 round 4 timed the directory pass out on vagary-core, and the
        # TimeoutExpired escaped `check` uncaught. Any pass's timeout is now a refusal (FULL), named as one.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        real = subprocess.run
        def slow_grep(*a, **k):
            if "grep" in a[0]:
                raise subprocess.TimeoutExpired(a[0], k.get("timeout", 0))
            return real(*a, **k)
        with patch.object(E.subprocess, "run", slow_grep):
            with self.assertRaisesRegex(ValueError, r"reader closure unproven: timeout: `git grep` ran over its \d+ s limit"):
                E.scan(self.repo, reviewed_cfg(IMPORT_CFG))

    def test_the_action_judges_the_candidate_with_the_base_config_only(self):
        # A PR cannot use its own new registry entries: action.yml runs `check` with the BASE copy of the config and the
        # base manifests, never the candidate's (root's ruling on #33 round 3).
        text = (Path(__file__).with_name("action.yml")).read_text()
        call = text.split('"$GITHUB_ACTION_PATH/edges.py" check', 1)[1].split("; then", 1)[0]
        self.assertIn('--config "$STATE/base/$CONFIG"', call)
        self.assertIn('--manifest-root "$STATE/base"', call)
        self.assertIn('--repo "$GITHUB_WORKSPACE/$CANDIDATE_ROOT" --revision "$CANDIDATE"', call)
        # The backstop's BASE side: the base revision, read from the sparse base checkout that holds the PR's deleted and
        # modified files (base-paths), never from the candidate, which may hold no base blobs.
        self.assertIn('--base-revision "$POLICY_REF" --base-repo "$STATE/base"', call)
        self.assertIn("${{ steps.changed.outputs.paths }}", text.split("name: Base commit manifests and plan config", 1)[1]
                      .split("    - name:", 1)[0])
        self.assertIn('edges.py" base-paths --repo "$GITHUB_WORKSPACE/$CANDIDATE_ROOT"', text)
        self.assertEqual(text.count('edges.py" check'), 1, "one check call, so no other path reads a candidate config")

    def test_d5_a_leading_slash_is_stripped_so_a_cwd_concat_escapes(self):
        # N2: `process.cwd() + "/scripts/x.mjs"` names scripts/, a top-level directory outside every package.
        for expr in ('process.cwd() + "/scripts/x.mjs"', 'path.join(process.cwd(), "/scripts/x.mjs")'):
            for reach in ("package", "external", ["scripts/x.mjs"]):
                with self.subTest(expr, reach=reach):
                    self.files(**{"services__a__load.mjs": f"export const load = () => import({expr});\n",
                                  "scripts__x.mjs": "export {};\n"})
                    cfg = json.loads(json.dumps(IMPORT_CFG))
                    cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": expr, "reach": reach}]
                    with self.assertRaisesRegex(ValueError, "steps outside its package"):
                        self.scan(cfg)

    def test_d5_a_reader_directory_reacher_keeps_its_job_selected_or_the_path_unmapped(self):
        # N3: test/foo.test.mjs (reader dir test/, job root) imports scripts/x.mjs, as package a does. Mapping
        # scripts/x.mjs to [a] alone selected a and skipped the root job that runs foo.test.mjs.
        self.files(**{"test__foo.test.mjs": 'import "../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n",
                      "services__a__t.mjs": 'import "../../scripts/x.mjs";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "tools", "test"]
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        _, _, report = self.scan(cfg)
        # test/ reaches it, and scripts/ holds it (a reader-dir file may itself be an executor its job runs).
        self.assertEqual(report["unit_imports"]["scripts/x.mjs"], ["scripts", "test"])
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.mjs is reached from test/, which reader job 'root' runs", out)
        for rule in ({"packages": ["a"]}, "always", "any_package"):
            with self.subTest(rule=rule):
                cfg["jobs"] = {"root": rule}
                rc, out = self.check(cfg)
                self.assertNotIn("narrowed import", out)
        # Unmapped, the path plans FULL, which runs every job: no narrowing (the package importer's own rule still asks).
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        cfg["extra_edges"] = {}
        self.assertNotIn("narrowed import", self.check(cfg)[1])
        # A reacher in no reader directory runs in no declared job: nothing it reaches may be mapped.
        self.files(**{"misc__run.mjs": 'import "../scripts/x.mjs";\n'})
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        cfg["jobs"] = {"root": "always"}
        self.assertIn("is reached by a file outside every package and every reader directory", self.check(cfg)[1])

    def test_d5_a_relative_path_at_or_above_the_repository_root_refuses(self):
        # N4: a vitest alias "@root" -> "../.." (or baseUrl "../..") reaches every file; it was dropped.
        for spec in ('alias: { "@root": "../.." }', 'baseUrl: "../../.."', 'root: "../../"'):
            with self.subTest(spec):
                self.files(**{"services__a__vitest.config.mjs": f"export default {{ {spec} }};\n"})
                with self.assertRaisesRegex(ValueError, "the repository root or above it"):
                    self.scan()
                self.files(**{"services__a__vitest.config.mjs": "export default {};\n"})

    def test_d5_an_importing_file_type_the_scan_does_not_parse_refuses_when_reached(self):
        # N5: .mdx, .astro, .vue and .svelte files import modules; the closure treated them as inert data.
        for ext in ("mdx", "astro", "vue", "svelte"):
            with self.subTest(ext):
                self.files(**{f"tools__page.{ext}": 'import X from "./x.mjs";\n', "tools__x.mjs": "export {};\n",
                              "services__a__t.mjs": f'import "../../tools/page.{ext}";\n'})
                with self.assertRaisesRegex(ValueError, f"tools/page.{ext}, a .{ext} file that can import modules"):
                    self.scan()
                self.files(**{"services__a__t.mjs": "export {};\n"})

    # ── Root's regression vectors for the delta at 7b83bf159e (lanes/root/reviews/dotgithub-33.md), each EXACT. Common
    # fixture: packages a, b and c under services/; the reader job root has {packages: [b]}.
    def root_b_cfg(self):
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "test", "tools"]
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        return cfg

    def test_root_vector_r1_a_reader_dir_executor_keeps_root_selected(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.js";\n', "test__foo.test.mjs": 'import "../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n"})
        cfg = self.root_b_cfg()
        _, _, report = self.scan(cfg)
        self.assertEqual(report["imports"]["scripts/x.ts"], ["a"])
        self.assertEqual(report["unit_imports"]["scripts/x.ts"], ["scripts", "test"])
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}  # exactly the mapping the package importer asks for
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.ts is reached from scripts/, which reader job 'root' runs", out)
        self.assertIn("narrowed import: scripts/x.ts is reached from test/, which reader job 'root' runs", out)
        cfg["extra_edges"] = {"scripts/x.ts": ["a", "b"]}  # a mapping that runs root: no narrowing
        self.assertNotIn("narrowed import", self.check(cfg)[1])

    def test_root_vector_r1b_an_executor_beside_the_module_keeps_root_selected(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.js";\n', "test__foo.test.mjs": 'import "../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n", "scripts__x.test.mjs": 'import "./x.js";\n'})
        cfg = self.root_b_cfg()
        _, _, report = self.scan(cfg)
        self.assertEqual(report["unit_imports"]["scripts/x.ts"], ["scripts", "test"])
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.ts is reached from scripts/", out)

    def test_root_vector_b3c_a_leading_slash_escape_refuses_under_every_reach(self):
        for reach in ("external", "package", "fixture"):
            with self.subTest(reach=reach):
                self.files(**{"services__a__t.mjs": 'export const l = () => import(process.cwd() + "/scripts/x.mjs");\n',
                              "services__c__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
                cfg = self.root_b_cfg()
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/t.mjs",
                                                         "expr": 'process.cwd() + "/scripts/x.mjs"', "reach": reach}]
                with self.assertRaisesRegex(ValueError, r'steps outside its package: `process.cwd\(\) \+ "/scripts/x.mjs"`'):
                    self.scan(cfg)

    def test_root_vector_n1_every_spelling_of_a_build_output_load_refuses(self):
        spellings = ["timeout 300 node ../dist/x.js", "npx tsx ../dist/x.js", "env -i node ../dist/x.js",
                     "node --import ./reg.mjs ../dist/x.js", "pnpm exec node ../dist/x.js", "xargs node ../dist/x.js",
                     "nohup node ../dist/x.js", "node --input-type=module <<'EOF'\nimport \"../dist/x.js\";\nEOF"]
        for line in spellings:
            with self.subTest(line):
                self.files(**{"services__a__package.json": '{"scripts": {"test": "bash ../../tools/run.sh"}}\n',
                              "tools__run.sh": "#!/bin/bash\n" + line + "\n", "tools__reg.mjs": "export {};\n",
                              "scripts__x.ts": "export const x = 1;\n", "services__c__t.mjs": 'import "../../scripts/x.js";\n'})
                with self.assertRaisesRegex(ValueError, r"\(tools/run.sh names dist/x.js, which is no tracked file or directory"):
                    self.scan(self.root_b_cfg())
        self.files(**{"tools__run.sh": "#!/bin/bash\n", "services__a__package.json": "{}\n"})
        for js in ('fork("../../dist/x.js");', 'new Worker("../../dist/x.js");', 'spawn(process.execPath, ["../../dist/x.js"]);'):
            with self.subTest(js):
                self.files(**{"services__a__w.mjs": js + "\n"})
                with self.assertRaisesRegex(ValueError, r"\(services/a/w.mjs names dist/x.js, which is no tracked file or directory"):
                    self.scan(self.root_b_cfg())
        self.files(**{"services__a__w.mjs": "export {};\n"})

    def test_root_vector_r8_a_root_alias_or_base_url_refuses(self):
        for name, body in (("vitest.config.mjs", 'export default { resolve: { alias: { "@root": path.resolve(__dirname, "../..") } } };\n'),
                           ("tsconfig.json", '{"compilerOptions": {"baseUrl": "../.."}}\n')):
            with self.subTest(name):
                self.files(**{f"services__a__{name}": body, "services__a__t.test.mjs": 'import "@root/scripts/x.js";\n',
                              "scripts__x.ts": "export const x = 1;\n", "services__c__t.mjs": 'import "../../scripts/x.js";\n'})
                with self.assertRaisesRegex(ValueError, r"services/a/" + re.escape(name) + r" names \.\./\.\., the repository root or above it"):
                    self.scan(self.root_b_cfg())
                (self.repo / "services/a" / name).unlink()
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def test_root_vector_n5_an_unparsed_importing_page_refuses(self):
        for ext in ("mdx", "astro", "vue", "svelte"):
            with self.subTest(ext):
                self.files(**{"services__a__t.mjs": f'import "../../tools/content/page.{ext}";\n',
                              f"tools__content__page.{ext}": 'import W from "./widget.js";\n',
                              "tools__content__widget.ts": "export const w = 1;\n",
                              "services__c__t.mjs": 'import "../../tools/content/widget.js";\n'})
                with self.assertRaisesRegex(ValueError, rf"a reaches tools/content/page.{ext}, a .{ext} file that can import modules"):
                    self.scan(self.root_b_cfg())
                (self.repo / f"tools/content/page.{ext}").unlink()
                self.files(**{"services__a__t.mjs": "export {};\n"})

    # ── 1.5.2: a shell script's relative paths resolve where it has `cd`'d to (spine's A2 census, FALSE-POSITIVES item 3)
    def test_shell_cd_to_its_own_directory_moves_where_relative_paths_resolve(self):
        base = {"scripts__ci-test-pg.sh": "#!/bin/bash\necho pg\n", "scripts__x.sh": "#!/bin/bash\n"}
        cases = {
            # spine's 22 runners: cd up from test/, then a path written relative to the package directory.
            "runner": ('cd "$(dirname "$0")/.."\nPGPORT="$(bash ../../scripts/ci-test-pg.sh port)"\n', "scripts/ci-test-pg.sh"),
            "same line": ('cd "$(dirname "$0")/.." && bash ../../scripts/ci-test-pg.sh wait\n', "scripts/ci-test-pg.sh"),
            "BASH_SOURCE": ('cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "conditional": ('[ -d .git ] && cd "$(dirname "$0")/.."\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "before the cd": ('bash ../../../scripts/x.sh\ncd "$(dirname "$0")/.."\n', "scripts/x.sh"),
            "identity control": ('bash "$(dirname "$0")/../../../scripts/ci-test-pg.sh" wait\n', "scripts/ci-test-pg.sh"),
            "heredoc text": ('cat <<EOF\ncd /tmp\nEOF\nbash ../../../scripts/x.sh\n', "scripts/x.sh"),
            # vagary-core social-distribution's runner: a trailing comment after the cd is no part of its argument.
            "trailing comment": ('cd "$(dirname "$0")/.."          # services/a\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "a comment's cd": ('echo start  # cd /tmp\nbash ../../../scripts/x.sh\n', "scripts/x.sh"),
        }
        for why, (body, target) in cases.items():
            with self.subTest(why):
                self.files(**base, **{"services__a__test__run.sh": "#!/bin/bash\n" + body})
                _, _, report = self.scan()
                self.assertIn("a", report["imports"].get(target, []), why)

    def test_shell_a_cd_the_scan_cannot_follow_refuses_later_relative_paths(self):
        for why, body in {"computed": 'cd "$WORKDIR"\nbash ../x.sh\n', "literal": "cd ../x.sh.d\nbash ./x.sh\n",
                          "absolute": "cd /opt/app\nbash ../x.sh\n", "no argument": "cd\nbash ../x.sh\n",
                          "dash": "cd -\nbash ../x.sh\n",
                          "a quoted #": 'cd "../#tools"\nbash ../x.sh\n'}.items():
            with self.subTest(why):
                self.files(**{"services__a__test__run.sh": "#!/bin/bash\n" + body, "services__a__x.sh": "#!/bin/bash\n",
                              "services__a__x.sh.d__keep.txt": "k\n"})
                with self.assertRaisesRegex(ValueError, "after a `cd` the scan cannot follow"):
                    self.scan()
        # A relative path BEFORE such a cd still resolves from the file's directory.
        self.files(**{"services__a__test__run.sh": "#!/bin/bash\nbash ../../../scripts/x.sh\ncd \"$WORKDIR\"\necho done\n",
                      "scripts__x.sh": "#!/bin/bash\n"})
        self.assertIn("a", self.scan()[2]["imports"]["scripts/x.sh"])

    def test_shell_whole_file_pass_reads_the_scanned_revision(self):
        # action.yml runs `check --revision`: the whole-file shell pass lists the commit's shell files (ls-tree takes no
        # glob and no `:!` exclude, exit 128), and reads the committed bytes, never a later working tree.
        self.files(**{"services__a__test__run.sh": '#!/bin/bash\ncd "$(dirname "$0")/.."\nbash ./x.sh\n',
                      "services__a__x.sh": "#!/bin/bash\n", "scripts__x.sh": "#!/bin/bash\n",
                      "docs__note.sh": "cd /tmp\nbash ./y.sh\n"})  # excluded (docs): it would refuse if listed
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit",
                        "-qm", "r", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        (self.repo / "services/a/test/run.sh").write_text("#!/bin/bash\ncd /tmp\nbash ./x.sh\n")  # the working tree differs
        report = {}
        E.scan(self.repo, IMPORT_CFG, revision=rev, report=report)
        with self.assertRaisesRegex(ValueError, "after a `cd` the scan cannot follow"):
            E.scan(self.repo, IMPORT_CFG)

    def test_shell_any_other_cd_names_the_directory_its_next_commands_run_in(self):
        # R5V14: only a cd to the script's own directory is modelled (shell_cwd_spans); any other cd's argument is read.
        self.files(**{"services__a__test__run.sh": "#!/bin/bash\n(cd ../../b && make)\n", "services__b__Makefile": "all:\n"})
        self.assertIn("b", self.scan()[0]["a"])
        # A `../` after a computed prefix resolves from the file's directory, as in any other file: naming nothing refuses.
        self.files(**{"services__a__test__run.sh": '#!/bin/bash\nfor d in x; do (cd "$d/../../packages/b" && make); done\n'})
        with self.assertRaisesRegex(ValueError, "which is no tracked file or directory"):
            self.scan()

    def test_shell_a_reached_unowned_script_resolves_after_its_own_cd(self):
        # tools/run.sh (outside every package) is reached from a; it cds to the repo root, then runs ./scripts/x.sh.
        self.files(**{"services__a__t.mjs": 'import "../../tools/run.sh";\n',
                      "tools__run.sh": '#!/bin/bash\ncd "$(dirname "$0")/.."\nbash ./scripts/x.sh\n',
                      "scripts__x.sh": '#!/bin/bash\ncat services/b/data.json\n', "services__b__data.json": "{}\n"})
        deps, _, report = self.scan()
        self.assertIn("a", report["imports"]["scripts/x.sh"])

    def test_an_unowned_js_caller_declares_a_top_level_literal_after_a_computed_base(self):
        # spine's FALSE-POSITIVES item 4: e2e/adr179/journeys.mjs imports join(identityDir, 'test', 'x.mjs'), where 'test'
        # is a top-level reader directory. From outside every package that is a load to declare, not an escape.
        expr = "pathToFileURL(join(identityDir, 'test', 'webauthn-authenticator.mjs')).href"
        self.files(**{"e2e__adr179__journeys.mjs": f"export const load = (identityDir) => import({expr});\n",
                      "services__identity__test__webauthn-authenticator.mjs": "export {};\n", "test__keep.txt": "k\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["workspace"]["packages"]["identity"] = {"dir": "services/identity", "deps": []}
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "tools", "e2e", "test"]
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"] = [{"file": "e2e/adr179/journeys.mjs", "expr": expr,
                                                 "reach": ["services/identity/test/webauthn-authenticator.mjs"]}]
        _, readers, _ = self.scan(cfg)
        self.assertIn("identity", readers["e2e"])
        # The same expression in a PACKAGE still escapes, declared or not; so does a parent step from outside.
        self.files(**{"services__a__load.mjs": f"export const load = (identityDir) => import({expr});\n"})
        cfg["edge_scan"]["computed_imports"].append({"file": "services/a/load.mjs", "expr": expr, "reach": "external"})
        with self.assertRaisesRegex(ValueError, "steps outside its package"):
            self.scan(cfg)

    def test_an_untracked_name_under_a_directory_reached_whole_adds_nothing(self):
        # spine's FALSE-POSITIVES item 5: a's package.json depends on file:../../shared/sdk, which reaches that directory
        # whole; the SDK's own test imports its untracked build output ../dist/server.js. Every tracked file the build
        # compiles dist/ from is already credited, so the name adds nothing.
        self.files(**{"services__a__package.json": '{"dependencies": {"sdk": "file:../../shared/sdk"}}\n',
                      "services__a__x.mjs": "export {};\n",
                      "shared__sdk__src__server.ts": "export const s = 1;\n",
                      "shared__sdk__test__app.mjs": 'import "../dist/server.js";\n'})
        _, _, report = self.scan()
        self.assertIn("a", report["imports"]["shared/sdk/src/server.ts"])
        # Reached only through the test file, the name still stands for shared/sdk, the directory it shares with its namer.
        self.files(**{"services__a__package.json": '{"name": "a"}\n', "services__a__t.mjs": 'import "../../shared/sdk/test/app.mjs";\n'})
        _, _, report = self.scan()
        self.assertIn("a", report["imports"]["shared/sdk/src/server.ts"])
        # A name sharing only a top-level directory with its namer refuses: shared/dist/x.js from shared/tools/run.mjs.
        self.files(**{"shared__tools__run.mjs": 'import "../dist/x.js";\n', "services__a__u.mjs": 'import "../../shared/tools/run.mjs";\n'})
        with self.assertRaisesRegex(ValueError, "names shared/dist/x.js, which is no tracked file or directory"):
            self.scan()

    def test_adversarial_forms_aimed_at_the_rule(self):
        self.files(**{
            # CRLF: the whole-file read must still find the ./ import.
            "services__a__t.mjs": 'import "../../scripts/crlf.mjs";\r\n',
            "scripts__crlf.mjs": 'import "./tail.mjs";\r\nexport {};\r\n',
            "scripts__tail.mjs": 'export const t = "services/b/t.json";\r\n',
            # A top-level directory whose name extends a package directory's: outside every package, so an edge.
            "services__b__t.mjs": 'import "../../services-x/u.mjs";\n',
            "services-x__u.mjs": 'export const u = "services/c/u.json";\n',
            # The root package.json is a file outside every package: a data target.
            "services__c__t.mjs": 'read("../../package.json");\n',
            "package.json": '{"scripts": {"t": "pytest services/a"}}\n',
        })
        deps, _, report = self.scan()
        self.assertEqual((deps["a"], deps["b"], deps["c"]), ({"b"}, {"c"}, {"a"}))
        self.assertIn("services-x/u.mjs", report["imports"])


class VectorHarness:
    """Root's method for a vector: commit the fixture; run the real `check --revision`; apply check's own remedies (the
    importers it names, a package the reader job lists, leaving an <unmapped> path unmapped, the backstop's owner or
    full_globs, a declared dep) until rc 0; then judge the change with the real plan.classify_paths + rule_matches."""

    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)

    REMEDIES = (
        (r"undeclared import edge: (\S+) imports (\S+) ", lambda c, m: E_add(c, m.group(2), m.group(1))),
        (r"narrowed import: (\S+) is reached from \S+/, which reader job", lambda c, m: E_add(c, m.group(1), c["jobs"]["root"]["packages"][0])
         if isinstance(c["jobs"]["root"], dict) else False),
        (r"narrowed import: (\S+) is reached by a file outside every package and every reader",
         lambda c, m: c.setdefault("extra_edges", {}).pop(m.group(1), None) is not None),
        (r"unattributed mention: \S+ \(package (\S+)\) names \S+, but the mapping for (\S+) selects",
         lambda c, m: E_add(c, m.group(2), m.group(1))),
        (r"unattributed mention: \S+, outside every package, names \S+ by a route the scan did not record, so whatever "
         r"runs \S+ may run (\S+) ", lambda c, m: E_list_add(c.setdefault("full_globs", []), m.group(1))),
        (r"inert mention: \S+ names \S+, but inert_globs '[^']*' makes a change to (\S+) select nothing",
         lambda c, m: E_list_add(c.setdefault("full_globs", []), m.group(1))),
        (r"undeclared read: (\S+) reads (\S+) ", lambda c, m: E_list_add(c["workspace"]["packages"][m.group(1)]["deps"], m.group(2))),
        (r"\S+/ reads (\S+), but job '(\S+)' does not list it",
         lambda c, m: isinstance(c["jobs"][m.group(2)], dict) and E_list_add(c["jobs"][m.group(2)]["packages"], m.group(1))),
    )

    def run_case(self, case):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        repo = Path(td.name)
        for d in ("services/a", "services/b", "services/c", ".github"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        for path, text in case["files"].items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text)
        for path, data in case.get("binary", {}).items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(base64.b64decode(data))
        for path, target in case.get("symlinks", {}).items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, repo / path)
        cfg = {**json.loads(json.dumps(self.CASES["base_config"])), **json.loads(json.dumps(case["cfg_set"]))}
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        for path in case.get("gitlinks", []):  # a submodule commit; its contents are never in this repository's tree
            subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"160000,{'5' * 40},{path}"],
                           check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit", "-qm",
                        "v", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        for _ in range(16):
            (repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
            buf = io.StringIO()
            out_json = repo / ".git" / "readers.json"
            try:
                with redirect_stdout(buf):
                    rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(repo), "--revision", rev,
                                 "--out-json", str(out_json)])
            except ValueError as err:
                return {"verdict": "REFUSE", "refusal": str(err)}
            fails = [line[5:] for line in buf.getvalue().splitlines() if line.startswith("FAIL ")]
            # Per path (root's ruling): a backstop hit plans that path FULL and fails nothing; its one declaration remedy
            # (map P to the mentioning package too) still narrows it back out, so it is applied like check's own.
            narrowed = False
            for line in buf.getvalue().splitlines():
                m = re.match(r"BACKSTOP (\S+) plans FULL: \S+ \(package (\S+)\) names \S+, but the mapping for \S+ selects", line)
                if m:
                    narrowed = bool(E_add(cfg, m.group(1), m.group(2))) or narrowed
            if rc == 0 and not narrowed:
                break
            progressed = narrowed
            for f in fails:
                for pattern, remedy in self.REMEDIES:
                    m = re.match(pattern, f)
                    if m:
                        progressed = bool(remedy(cfg, m)) or progressed
                        break
            if not progressed:
                return {"verdict": "STUCK", "fails": fails}
        pkgs = E.workspace_graph(repo, cfg)
        self.assertTrue(pkgs, "no packages: the judgment would be vacuous")
        sel = classify_paths([case["change"]], cfg, pkgs)
        if sel["error"] or sel["evidence"]["full_triggers"] or sel["evidence"]["unmapped"]:
            return {"verdict": "FULL"}
        # The backstop's consequence is per path (root's ruling, 2026-10-29): plan.py plans FULL for a changed path in
        # the bound assessment's backstop_full, exactly as it does for a full trigger.
        if case["change"] in (backstop_full(json.loads(out_json.read_text())) or []):
            return {"verdict": "FULL", "backstop": True}
        return {"verdict": "SELECT", "jobs": sorted(j for j, rule in cfg["jobs"].items()
                                                     if rule == "always" or rule_matches(rule, sel["affected"])[0])}



class RoundThreeVectorsTest(VectorHarness, unittest.TestCase):
    """Root's round 3 of #33: every fresh vector and correct-plan control, run by root's method and pinned EXACT
    (test_edges_round3_vectors.json)."""

    CASES = json.loads((Path(__file__).with_name("test_edges_round3_vectors.json")).read_text())

    def test_every_round3_vector_refuses_plans_full_or_selects_its_runner_exactly_as_pinned(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                want = {k: case[k] for k in ("verdict", "jobs", "refusal", "backstop") if k in case}
                self.assertEqual(got, want, name)
                if case["kind"] == "drop-vector" and got["verdict"] == "SELECT" and case.get("must_run"):
                    self.assertIn(case["must_run"], got["jobs"], f"{name} drops its runner")

    def test_the_drop_vectors_cover_every_round3_class(self):
        kinds = {c["kind"] for c in self.CASES["cases"].values()}
        self.assertEqual(kinds, {"drop-vector", "correct-plan control"})
        names = sorted(self.CASES["cases"])
        for prefix in ("F10b", "F10 ", "F15", "F13b", "F12", "F01", "F02", "F03", "F04", "F05", "L1", "F09", "F08", "F11"):
            self.assertTrue(any(n.startswith(prefix) for n in names), prefix)


class RoundFourVectorsTest(VectorHarness, unittest.TestCase):
    """Root's R4 of #33 round 3 (lanes/root/reviews/dotgithub-33.md, head 70ed2e7): the reviewer's fresh vectors, pinned
    EXACT by the same method (test_edges_round4_vectors.json). Each drop-vector must REFUSE, plan FULL or select its
    runner: B1 (T1, T1b, T1c, a runner one hop or more out), B2 (T4, a gitlink), B3 (T3, T3b, a symlink alias or a
    symlink in a package), B4 (T2, an inert glob), and a runner that names only a directory (T10b-T10f; three precision
    controls: a package's own test/, a sibling path, bare words at the root). A residual is a spelling no recorded route or token sees (README,
    "Not closed"): it is pinned as the drop it is, so the README cannot claim more than the scan does."""

    CASES = json.loads((Path(__file__).with_name("test_edges_round4_vectors.json")).read_text())

    def test_every_round4_vector_refuses_plans_full_or_selects_its_runner_exactly_as_pinned(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                self.assertEqual(got, {k: case[k] for k in ("verdict", "jobs", "refusal", "backstop") if k in case}, name)
                runs = got["verdict"] != "SELECT" or case["must_run"] in got["jobs"]
                self.assertEqual(runs, case["kind"] != "residual", f"{name}: {case['kind']}")

    def test_the_drop_vectors_cover_every_round4_blocker_and_the_readme_lists_every_residual(self):
        names = sorted(self.CASES["cases"])
        for prefix in ("T1 ", "T1b", "T1c", "T2 ", "T3 ", "T3b", "T4 ", "T10b", "T10c", "T10d", "T10e", "T10f"):
            self.assertTrue(any(n.startswith(prefix) and self.CASES["cases"][n]["kind"] == "drop-vector" for n in names),
                            prefix)
        readme = (Path(__file__).with_name("README.md")).read_text()
        for name, case in self.CASES["cases"].items():
            if case["kind"] == "residual":
                self.assertIn(case["residual"], readme, f"{name}: the README must list it")


class RulingsOf152Test(VectorHarness, unittest.TestCase):
    """1.5.2, root's rulings (a), (b), (c) and the nested-lockfile ruling (test_edges_152_rulings_vectors.json), pinned
    EXACT: each drop-vector refuses, plans FULL or selects its runner; each control selects exactly its jobs."""

    CASES = json.loads((Path(__file__).with_name("test_edges_152_rulings_vectors.json")).read_text())

    def test_every_ruling_vector_is_pinned_exactly(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                self.assertEqual(got, {k: case[k] for k in ("verdict", "jobs", "refusal") if k in case}, name)
                if case["kind"] == "drop-vector" and got["verdict"] == "SELECT":
                    self.assertIn(case["must_run"], got["jobs"], f"{name} drops its runner")

    def test_each_ruling_has_vectors(self):
        names = sorted(self.CASES["cases"])
        for prefix in ("A1", "A2", "A3", "A4", "A5", "A6", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11",
                       "C1", "C2", "C3", "C4", "C5", "C6"):
            self.assertTrue(any(n.startswith(prefix + " ") for n in names), prefix)

def E_add(cfg, path, name):
    targets = cfg.setdefault("extra_edges", {}).setdefault(path, [])
    return E_list_add(targets, name)


def E_list_add(values, item):
    if item in values:
        return False
    values.append(item)
    return True


if __name__ == "__main__":
    unittest.main()
