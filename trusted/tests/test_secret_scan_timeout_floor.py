"""secret-scan.yml's two jobs take their timeout from a workflow_call input, `${{ inputs.timeout-minutes }}`, which
the trusted timeout-floor check cannot read statically. Their manifest exemptions hold only while this test does
(root, 2026-10-27): an exemption alone would let someone lower the input's default to 2 unseen.

(a) the input's declared default is at or over the floor (manifest timeout_floor.minutes);
(b) every caller of secret-scan.yml in this repo passes no timeout-minutes, or a literal at or over the floor.
Callers in other repos are outside what this repo can see; the floor check itself reads those as literals there."""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
SECRET_SCAN = "secret-scan.yml"


def floor_minutes():
    return json.loads((ROOT / "trusted" / "manifest.json").read_text())["timeout_floor"]["minutes"]


def _code_lines(text):
    """Lines with their indentation, comment-only lines dropped (the workflow's usage example is a comment)."""
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def input_default(text, name):
    """The `default:` of workflow_call input <name>, as written (None when absent)."""
    lines = _code_lines(text)
    for i, line in enumerate(lines):
        if re.match(r"^\s*%s:\s*$" % re.escape(name), line):
            indent = len(line) - len(line.lstrip())
            for nxt in lines[i + 1:]:
                if len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                m = re.match(r"^\s*default:\s*(\S.*?)\s*$", nxt)
                if m:
                    return m.group(1).strip("'\"")
            return None
    return None


def callers(workflows):
    """{workflow file: timeout-minutes it passes to secret-scan.yml, or None} for every job that calls it."""
    found = {}
    for path, text in workflows.items():
        lines = _code_lines(text)
        for i, line in enumerate(lines):
            if not re.match(r"^\s*uses:\s*\S*\.github/workflows/%s(@\S+)?\s*$" % re.escape(SECRET_SCAN), line):
                continue
            indent = len(line) - len(line.lstrip())
            passed = None
            for nxt in lines[i + 1:]:
                if len(nxt) - len(nxt.lstrip()) < indent:
                    break
                m = re.match(r"^\s*timeout-minutes:\s*(\S.*?)\s*$", nxt)
                if m and len(nxt) - len(nxt.lstrip()) > indent:  # under the call's `with:`
                    passed = m.group(1).strip("'\"")
            found[path] = passed
    return found


def problems(secret_scan_text, workflows, floor):
    out = []
    default = input_default(secret_scan_text, "timeout-minutes")
    if default is None or not default.isdigit() or int(default) < floor:
        out.append("secret-scan.yml's timeout-minutes input defaults to %r, not a number >= the %d-minute floor"
                   % (default, floor))
    for path, passed in sorted(callers(workflows).items()):
        if passed is not None and (not passed.isdigit() or int(passed) < floor):
            out.append("%s passes timeout-minutes %r to secret-scan.yml, not a literal >= the %d-minute floor"
                       % (path, passed, floor))
    return out


def tree():
    return {p.name: p.read_text() for p in sorted(WORKFLOWS.glob("*.y*ml"))}


class SecretScanTimeoutInput(unittest.TestCase):
    """Cited by the manifest exemptions for secret-scan.yml's gitleaks and trufflehog jobs."""

    def test_the_input_default_and_every_visible_caller_meet_the_floor(self):
        workflows = tree()
        self.assertIn(SECRET_SCAN, workflows)
        self.assertTrue(callers(workflows), "control: the sweep's call to secret-scan.yml is found")
        self.assertEqual(problems(workflows[SECRET_SCAN], workflows, floor_minutes()), [])

    def test_controls_go_red(self):
        workflows, floor = tree(), floor_minutes()
        text = workflows[SECRET_SCAN]
        default = input_default(text, "timeout-minutes")
        self.assertIsNotNone(default, "control: the input's default is read")
        lowered = re.sub(r"(timeout-minutes:\n(?:\s+\w[^\n]*\n)*?\s+default:\s*)%s" % re.escape(default), r"\g<1>2",
                         text, count=1)
        self.assertNotEqual(lowered, text, "the mutation did not apply")
        self.assertTrue(problems(lowered, workflows, floor), "a default of 2 passed")
        call = ("jobs:\n  scan:\n    uses: vagarylabs/.github/.github/workflows/secret-scan.yml@main\n"
                "    with:\n      timeout-minutes: %s\n")
        for value in ("3", "${{ inputs.t }}"):
            with self.subTest(caller_passes=value):
                self.assertTrue(problems(text, {"x.yml": call % value}, floor), value)
        self.assertEqual(problems(text, {"x.yml": call % str(floor)}, floor), [])
        self.assertEqual(problems(text, {"x.yml": call.split("    with:")[0]}, floor), [])  # passes none


if __name__ == "__main__":
    unittest.main()
