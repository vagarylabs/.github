"""Tests for classify.py's C1 admission modes (root, 2026-10-29): `pins` (every `uses:` names a commit with its exact
release; a first-party one names its merge PR) and `workflow-lint` (zizmor and actionlint over the head tree, as data).
Report-only first; a tool that did not run is INCOMPLETE, never clean. Stdlib only. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402

SHA = "11d5960a326750d5838078e36cf38b85af677262"


class PinVerdict(unittest.TestCase):
    def test_each_failing_form_has_its_class(self):
        for value, cls in (("actions/checkout@v4", "tag_ref"),
                           ("actions/checkout@main", "tag_ref"),
                           ("actions/checkout", "tag_ref"),
                           ("actions/checkout@11d5960 # v4.4.0", "short_sha"),
                           (f"actions/checkout@{SHA}", "no_label"),
                           (f"actions/checkout@{SHA} #", "no_label"),
                           (f"actions/checkout@{SHA} # v4", "major_only"),
                           (f"actions/checkout@{SHA} # v4.4", "minor_only"),
                           (f"actions/checkout@{SHA} # main", "bad_label"),
                           (f"vagarylabs/.github/actions/x@{SHA}", "wrong_internal"),
                           (f"vagarylabs/.github/actions/x@{SHA} # v1.2.3", "wrong_internal"),
                           (f"vagarylabs/.github/actions/x@{SHA} # vagaris #40 merge", "wrong_internal"),
                           ("vagarylabs/.github/.github/workflows/secret-scan.yml@main", "tag_ref"),
                           ("docker://alpine:3.20", "docker_tag"),
                           ("docker://alpine@sha256:abc", "docker_tag")):
            with self.subTest(value):
                self.assertEqual(classify.pin_verdict(value)[0], cls)

    def test_each_passing_form_passes(self):
        for value in (f"actions/checkout@{SHA} # v4.4.0",
                      f"actions/setup-node@{SHA} # v4.1.0-rc.1",
                      f"actions/setup-node@{SHA}   #   v4.1.0",
                      f"'actions/checkout@{SHA}' # v4.4.0",
                      f'"actions/checkout@{SHA}" # v4.4.0',
                      f"github/codeql-action/upload-sarif@{SHA} # v4.38.3",
                      f"vagarylabs/.github/actions/x@{SHA} # .github #40 merge",
                      f"vagarylabs/vagaris/.github/workflows/y.yml@{SHA} # vagaris #12 merge",
                      "docker://alpine@sha256:" + "a" * 64,
                      "./.github/actions/setup", "."):
            with self.subTest(value):
                self.assertIsNone(classify.pin_verdict(value)[0])

    def test_findings_skip_comment_lines_and_report_line_numbers(self):
        text = ("jobs:\n  a:\n    steps:\n      # - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n"
                f"      - uses: actions/setup-node@{SHA} # v4.1.0\n        uses: actions/cache@v3\n")
        self.assertEqual([(line, cls) for line, cls, _, _ in classify.pin_findings(text)],
                         [(5, "tag_ref"), (7, "tag_ref")])


class PinsManifest(unittest.TestCase):
    def manifest(self, pins):
        m = json.loads((ROOT / "trusted" / "manifest.json").read_text())
        m["pins"] = pins
        return m

    def test_pins_is_required_and_its_exemptions_are_exact(self):
        good = {"repo": "*", "file": "*", "uses": "x/y@main", "reason": "why", "record": "rec"}
        self.assertEqual(classify.validate_manifest(self.manifest({"mode": "report", "exemptions": [good]}))["pins"]["mode"],
                         "report")
        for bad in (None, {}, {"mode": "warn", "exemptions": []}, {"mode": "report"},
                    {"mode": "report", "exemptions": [dict(good, reason=" ")]},
                    {"mode": "report", "exemptions": [dict(good, extra="x")]},
                    {"mode": "report", "exemptions": [{k: v for k, v in good.items() if k != "record"}]}):
            with self.subTest(bad=bad):
                m = self.manifest(bad)
                if bad is None:
                    del m["pins"]
                with self.assertRaises(classify.IntegrityError):
                    classify.validate_manifest(m)

    def test_workflow_lint_is_required_and_closed(self):
        m = json.loads((ROOT / "trusted" / "manifest.json").read_text())
        for bad in ({}, {"mode": "warn"}, {"mode": "report", "x": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(classify.IntegrityError):
                    classify.validate_manifest(dict(m, workflow_lint=bad))

    def test_the_committed_manifest_starts_report_only_with_root_s_exemptions(self):
        m = classify.validate_manifest(json.loads((ROOT / "trusted" / "manifest.json").read_text()))
        self.assertEqual((m["pins"]["mode"], m["workflow_lint"]["mode"]), ("report", "report"))
        uses = {e["uses"] for e in m["pins"]["exemptions"]}
        self.assertIn("vagarylabs/vagaris/.github/workflows/change-review-reviewer.yml@main", uses)
        self.assertIn("vagarylabs/.github/.github/workflows/secret-scan.yml@main", uses)
        self.assertIn("vagarylabs/.github/.github/workflows/issue-triage.yml@main", uses)


class PinsMode(unittest.TestCase):
    def run_mode(self, mode, files, exemptions=(), repo="vagarylabs/x"):
        m = {"pins": {"mode": mode, "exemptions": list(exemptions)}}
        out = io.StringIO()
        with mock.patch.object(classify, "resolve_head"), \
                mock.patch.object(classify, "git", return_value="\n".join(files)), \
                mock.patch.object(classify, "blob", side_effect=lambda sha, path: files[path]), \
                mock.patch.object(classify, "summary", side_effect=lambda lines: out.write("\n".join(lines) + "\n")), \
                contextlib.redirect_stdout(out):
            code = classify.run_pins(m, repo, None, "a" * 40)
        return code, out.getvalue()

    def test_report_lists_and_enforce_refuses(self):
        files = {".github/workflows/w.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
                 "README.md": "uses: actions/checkout@v4\n"}
        code, out = self.run_mode("report", files)
        self.assertEqual(code, 0)
        self.assertIn("::warning file=.github/workflows/w.yml,line=4,title=action pin::tag_ref", out)
        self.assertNotIn("README.md", out, "only workflows and composite actions are read")
        code, out = self.run_mode("enforce", files)
        self.assertEqual(code, 1)
        self.assertIn("::error file=.github/workflows/w.yml", out)

    def test_a_clean_tree_passes_in_enforce(self):
        files = {".github/workflows/w.yml": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA} # v4.4.0\n",
                 "act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: ./local\n"}
        code, out = self.run_mode("enforce", files)
        self.assertEqual(code, 0)
        self.assertIn("Every `uses:` is pinned", out)

    def test_an_exemption_names_one_use_exactly_and_a_stale_one_is_reported(self):
        line = "      - uses: vagarylabs/.github/.github/workflows/secret-scan.yml@main\n"
        files = {".github/workflows/s.yml": "jobs:\n  a:\n" + line}
        org = {"repo": "*", "file": "*", "uses": "vagarylabs/.github/.github/workflows/secret-scan.yml@main",
               "reason": "until releases", "record": "rec"}
        code, out = self.run_mode("enforce", files, [org])
        self.assertEqual(code, 0, out)
        self.assertIn("EXEMPT", out)
        near = dict(org, uses="vagarylabs/.github/.github/workflows/secret-scan.yml@main2")
        self.assertEqual(self.run_mode("enforce", files, [near])[0], 1, "an exemption matches the exact value only")
        other_repo = dict(org, repo="vagarylabs/y")
        self.assertEqual(self.run_mode("enforce", files, [other_repo])[0], 1, "another repo's exemption does not apply")
        mine = dict(org, repo="vagarylabs/x", file=".github/workflows/gone.yml")
        code, out = self.run_mode("report", files, [mine])
        self.assertIn("STALE EXEMPTION", out)


ZIZMOR = [{"ident": "artipacked", "desc": "credential persistence", "determinations": {"severity": "Medium"},
           "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "./.github/workflows/w.yml"}}},
                          "concrete": {"location": {"start_point": {"row": 56}}}}]},
          {"ident": "template-injection", "desc": "code injection", "determinations": {"severity": "High"},
           "locations": [{"symbolic": {"key": {"Local": {"given_path": ".github/workflows/w.yml"}}},
                          "concrete": {"location": {"start_point": {"row": 9}}}}]}]
ACTIONLINT = [{"kind": "expression", "filepath": ".github/workflows/w.yml", "line": 3, "message": "undefined"}]


class WorkflowLintMode(unittest.TestCase):
    def run_mode(self, mode, zizmor, zrc, actionlint, arc):
        m = {"workflow_lint": {"mode": mode}}
        with tempfile.TemporaryDirectory() as td:
            z, a = pathlib.Path(td, "z.json"), pathlib.Path(td, "a.json")
            z.write_text(zizmor if isinstance(zizmor, str) else json.dumps(zizmor))
            a.write_text(actionlint if isinstance(actionlint, str) else json.dumps(actionlint))
            out = io.StringIO()
            with mock.patch.object(classify, "summary", side_effect=lambda lines: out.write("\n".join(lines) + "\n")), \
                    contextlib.redirect_stdout(out):
                code = classify.run_workflow_lint(m, "vagarylabs/x", "a" * 40, str(z), zrc, str(a), arc)
        return code, out.getvalue()

    def test_findings_are_reported_with_their_place_and_counted(self):
        code, out = self.run_mode("report", ZIZMOR, 0, ACTIONLINT, 1)
        self.assertEqual(code, 0)
        self.assertIn("::warning file=.github/workflows/w.yml,line=57,title=zizmor artipacked::", out)
        self.assertIn("::warning file=.github/workflows/w.yml,line=10,title=zizmor template-injection::", out)
        self.assertIn("::warning file=.github/workflows/w.yml,line=3,title=actionlint expression::undefined", out)
        self.assertIn("zizmor: 2 findings", out)
        self.assertIn("actionlint: 1 findings", out)
        self.assertEqual(self.run_mode("enforce", ZIZMOR, 0, ACTIONLINT, 1)[0], 1)

    def test_a_tool_that_did_not_run_is_incomplete_never_clean(self):
        for why, args in (("zizmor exited 2", ([], 2, [], 0)), ("actionlint exited 3", ([], 0, [], 3)),
                          ("zizmor output did not parse", ("{not json", 0, [], 0)),
                          ("actionlint output did not parse", ([], 0, "[{", 1))):
            with self.subTest(why):
                code, out = self.run_mode("report", *args)
                self.assertEqual(code, 0, "report-only")
                self.assertIn("INCOMPLETE: " + why, out)
                self.assertEqual(self.run_mode("enforce", *args)[0], 1, "an incomplete scan refuses in enforce")

    def test_clean_runs_pass_in_enforce(self):
        code, out = self.run_mode("enforce", [], 0, "", 0)
        self.assertEqual(code, 0, out)


class WorkflowWiring(unittest.TestCase):
    def test_the_fetched_tools_are_the_release_assets_lock_lines(self):
        lock = {}
        for line in (ROOT / "release-assets.lock").read_text().splitlines():
            if line and not line.startswith("#"):
                tool, version, url, sha = line.split()
                lock[(tool, version)] = (url, sha)
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        steps = re.findall(r"uses: vagarylabs/\.github/actions/fetch-release-asset@(\w+) # \.github #\d+ merge\n"
                           r"\s+with:\n\s+tool: (\S+)\n\s+version: (\S+)\n\s+url: (\S+)\n\s+sha256: (\S+)\n", wf)
        self.assertEqual(sorted((t, v) for _, t, v, _, _ in steps), [("actionlint", "1.7.7"), ("zizmor", "1.31.1")])
        for sha, tool, version, url, digest in steps:
            with self.subTest(tool):
                self.assertEqual(lock[(tool, version)], (url, digest))
                self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_the_tools_run_offline_and_their_exit_codes_reach_the_classifier(self):
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        self.assertIn('"$t/zizmor" --no-exit-codes --no-online-audits --format json . ', wf)
        self.assertIn("--zizmor-rc \"$zrc\"", wf)
        self.assertIn("--actionlint-rc \"$arc\"", wf)
        self.assertIn('classify.py" pins --manifest "$d/manifest.json"', wf)


if __name__ == "__main__":
    unittest.main()
