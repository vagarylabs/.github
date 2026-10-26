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
        (repo / rel).write_bytes(case["src"].encode("utf-8"))
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
        elif expect != "residual":
            self.assertTrue(got == "REFUSE" or set(truth) <= set(got), f"{label}: read {got}, truth {truth}")
            if expect == "read":
                self.assertNotEqual(got, "REFUSE", f"{label}: a resolvable read must not refuse")

    def test_review_vectors_read_their_truth_or_refuse(self):
        """Every input of root's three independent reviews, spine's own probes and the round-4 rule-7 vectors: none may
        read less than its truth without refusing, and those resolvable today must keep reading. Exempt: A12/N08/N11
        (object values and keys, the ratified metadata) and T19/T36/T37 (lexical limits, named residuals)."""
        repo = self.vector_repo("vectors")
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            with self.subTest(label):
                self.judge(label, case, self.vector_scan(repo, case))
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c["expect"] == "residual"),
                         ["A12_dict_value_as_path", "N08_dict_values_walked", "N11_dict_key_walked",
                          "T19_partial_split_root", "T36_computed_prefix_not_repo_root",
                          "T37_fstring_computed_prefix_not_root"])

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


if __name__ == "__main__":
    unittest.main()
