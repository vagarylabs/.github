"""Tests for classify.py's C1 admission modes (root, 2026-10-29): `pins` (every `uses:` names a commit with its exact
release; a first-party one names its merge PR) and `workflow-lint` (zizmor and actionlint over the head tree, as data).
Report-only first; a tool that did not run is INCOMPLETE, never clean. Stdlib only. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import json
import os
import pathlib
import re
import subprocess
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
                           (f"VagaryLabs/.github/actions/x@{SHA} # v1.2.3", "wrong_internal"),
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
                mock.patch.object(classify, "git", return_value="\0".join(files) + "\0"), \
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

    def test_a_name_git_would_quote_is_still_read(self):
        # The listing is NUL-separated: a non-ASCII or quoted workflow name is read, not skipped (root, #41 non-blocking).
        files = {'.github/workflows/caf\u00e9 "x".yml': "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"}
        code, out = self.run_mode("enforce", files)
        self.assertEqual(code, 1)
        self.assertIn("tag_ref", out)

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
    def run_mode(self, mode, zizmor, zrc, actionlint, arc, zfetch="success", afetch="success",
                 listing=".github/workflows/w.yml\0README.md\0"):
        m = {"workflow_lint": {"mode": mode}}
        with tempfile.TemporaryDirectory() as td:
            z, a = pathlib.Path(td, "z.json"), pathlib.Path(td, "a.json")
            z.write_text(zizmor if isinstance(zizmor, str) else json.dumps(zizmor))
            a.write_text(actionlint if isinstance(actionlint, str) else json.dumps(actionlint))
            out = io.StringIO()
            with mock.patch.object(classify, "resolve_head"), mock.patch.object(classify, "git", return_value=listing), \
                    mock.patch.object(classify, "summary", side_effect=lambda lines: out.write("\n".join(lines) + "\n")), \
                    contextlib.redirect_stdout(out):
                code = classify.run_workflow_lint(m, "vagarylabs/x", "a" * 40, str(z), zrc, str(a), arc, zfetch, afetch)
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
                          ("actionlint output did not parse", ([], 0, "[{", 1)),
                          ("zizmor timed out", ([], 124, [], 0)), ("actionlint exited 127", ([], 0, [], 127))):
            with self.subTest(why):
                code, out = self.run_mode("report", *args)
                self.assertEqual(code, 0, "report-only")
                self.assertIn("INCOMPLETE: " + why, out)
                self.assertEqual(self.run_mode("enforce", *args)[0], 1, "an incomplete scan refuses in enforce")

    def test_clean_runs_pass_in_enforce(self):
        code, out = self.run_mode("enforce", [], 0, [], 0)
        self.assertEqual(code, 0, out)

    def test_an_output_without_the_tool_s_shape_is_incomplete(self):
        # Root's R4 of #41, B3: an empty file, {}, null, [1, 2] or a wrapped list is not a clean run.
        for z in ("", "{}", "null", "[1, 2]", '{"findings": []}', '[{"ident": "x"}]', "3"):
            with self.subTest(zizmor=z):
                code, out = self.run_mode("report", z, 0, [], 0)
                self.assertEqual(code, 0)
                self.assertIn("INCOMPLETE: zizmor", out)
                self.assertNotIn("zizmor: 0 findings", out)
                self.assertEqual(self.run_mode("enforce", z, 0, [], 0)[0], 1)
        for a, rc in (("", 0), ("{}", 0), ("null", 0), ("[]", 1), ('[{"kind": "x"}]', 1), (json.dumps(ACTIONLINT), 0)):
            with self.subTest(actionlint=a, rc=rc):
                code, out = self.run_mode("report", [], 0, a, rc)
                self.assertIn("INCOMPLETE: actionlint", out)
                self.assertEqual(self.run_mode("enforce", [], 0, a, rc)[0], 1)

    def test_a_failed_fetch_is_incomplete_and_green_in_report(self):
        # Root's R4 of #41, B2: in mode report the required check stays green; enforce refuses an incomplete scan.
        for zf, af in (("failure", "success"), ("success", "failure"), ("cancelled", "skipped")):
            with self.subTest(zizmor=zf, actionlint=af):
                code, out = self.run_mode("report", [], 0, [], 0, zf, af)
                self.assertEqual(code, 0)
                self.assertIn("was not fetched", out)
                self.assertEqual(self.run_mode("enforce", [], 0, [], 0, zf, af)[0], 1)

    def test_a_head_with_nothing_to_audit_is_clean_without_the_tools(self):
        code, out = self.run_mode("enforce", "", 3, "", 2, "failure", "failure", listing="README.md\0src/a.py\0")
        self.assertEqual(code, 0, out)
        self.assertIn("Nothing to audit", out)


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

    def test_the_tools_read_no_pr_config_and_their_exit_codes_reach_the_classifier(self):
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        self.assertIn('timeout 120 "$t/zizmor" --no-exit-codes --offline --no-config --no-ignores --collect=all '
                      '--strict-collection', wf)
        self.assertIn('timeout 120 "$t/actionlint" -config-file "$d/actionlint.yaml" -shellcheck= -pyflakes=', wf)
        for arg in ('--zizmor-rc "$zrc"', '--zizmor-fetch "$Z_FETCH"', '--actionlint-rc "$arc"',
                    '--actionlint-fetch "$A_FETCH"', 'classify.py" pins --manifest "$d/manifest.json"'):
            self.assertIn(arg, wf)
        # The trusted actionlint config is inlined from trusted/actionlint.yaml, never read from the PR.
        self.assertIn("cat > \"$d/actionlint.yaml\" <<'TRUSTED_ACTIONLINT_YAML'", wf)

    def test_the_trusted_actionlint_config_is_inlined_byte_for_byte(self):
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        body = wf.split("<<'TRUSTED_ACTIONLINT_YAML'\n", 1)[1].split("\n          TRUSTED_ACTIONLINT_YAML", 1)[0]
        src = (ROOT / "trusted" / "actionlint.yaml").read_text().rstrip("\n")
        self.assertEqual("\n".join(l[10:] for l in body.split("\n")), src)
        self.assertIn("vl-light", src)

    def rendered_run_step(self, mode):
        """The workflow-lint run step's script exactly as rendered, with the inlined manifest's workflow_lint mode set."""
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        step = wf.split("- name: Run zizmor and actionlint over the head tree", 1)[1].split("        run: |\n", 1)[1]
        body = []
        for line in step.split("\n"):
            if line.strip() and not line.startswith("          "):
                break
            body.append(line[10:])
        script = "\n".join(body)
        head, rest = script.split("<<'TRUSTED_MANIFEST_JSON'\n", 1)
        doc, tail = rest.split("\nTRUSTED_MANIFEST_JSON\n", 1)
        m = json.loads(doc)
        m["workflow_lint"]["mode"] = mode
        return head + "<<'TRUSTED_MANIFEST_JSON'\n" + json.dumps(m).replace("$", "\\u0024") + "\nTRUSTED_MANIFEST_JSON\n" + tail

    def test_the_rendered_step_ends_incomplete_not_red_when_both_fetches_fail(self):
        # Root's delta R4 of #41, B2: the cold-cache case, both fetches failed, so no tool and no $RUNNER_TEMP/workflow-lint.
        # The rendered step itself, run as the runner runs it: green with INCOMPLETE x2 in report, refused in enforce.
        for mode, want in (("report", 0), ("enforce", 1)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                ws, temp = pathlib.Path(td, "ws"), pathlib.Path(td, "temp")
                (ws / "head" / ".github" / "workflows").mkdir(parents=True)
                temp.mkdir()
                (ws / "head" / ".github" / "workflows" / "w.yml").write_text("on: push\njobs: {}\n")
                env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
                g = lambda *a: subprocess.run(["git", "-C", str(ws / "head"), *a], check=True, capture_output=True,
                                              text=True, env=env).stdout.strip()
                g("init", "-q")
                g("add", "-A")
                g("-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit", "-qm", "h", "--no-gpg-sign")
                step = pathlib.Path(td, "step.sh")
                step.write_text(self.rendered_run_step(mode))
                summary = pathlib.Path(td, "summary.md")
                out = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(step)], cwd=ws,
                                     capture_output=True, text=True, timeout=120,
                                     env=dict(env, RUNNER_TEMP=str(temp), REPO="vagarylabs/x", HEAD_SHA=g("rev-parse", "HEAD"),
                                              Z_FETCH="failure", A_FETCH="failure", GITHUB_STEP_SUMMARY=str(summary)))
                self.assertEqual(out.returncode, want, out.stdout + out.stderr)
                text = summary.read_text()
                self.assertIn("INCOMPLETE: zizmor was not fetched (step outcome failure)", text)
                self.assertIn("INCOMPLETE: actionlint was not fetched (step outcome failure)", text)

    def test_report_mode_cannot_go_red_on_a_fetch_and_every_step_is_bounded(self):
        # Root's R4 of #41, B2: each fetch is bounded and continue-on-error (its outcome goes to classify.py), each
        # tool run is under `timeout`, and the job's timeout covers the sum.
        wf = (ROOT / ".github" / "workflows" / "trusted-workflow-integrity.yml").read_text()
        job = wf.split("\n  workflow-lint:\n", 1)[1]
        self.assertIn("timeout-minutes: 20", job.split("steps:", 1)[0])
        for step in ("fetch_zizmor", "fetch_actionlint"):
            block = job.split("id: %s\n" % step, 1)[1].split("\n      - ", 1)[0]
            with self.subTest(step):
                self.assertIn("continue-on-error: true", block)
                self.assertIn("timeout-minutes: 5", block)
                self.assertIn('max-time: "90"', block)
        run = job.split("- name: Run zizmor and actionlint over the head tree", 1)[1]
        self.assertIn("if: ${{ !cancelled() }}", run.split("run: |", 1)[0])
        self.assertIn("timeout-minutes: 6", run.split("run: |", 1)[0])


if __name__ == "__main__":
    unittest.main()
