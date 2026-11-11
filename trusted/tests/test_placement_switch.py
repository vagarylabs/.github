"""R1 L10: the trusted workflows' placement is a two-way switch on the org variable TRUSTED_LIGHT_RUNNER, resolved
by the same evaluator scripts/no_hosted_runners.py applies to every runs-on expression. `hosted` selects ubuntu-latest;
no variable, any other value, or an attempt to pass a label list keeps the bridge light label. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_placement_switch.py' -v
"""
import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("no_hosted_runners", ROOT / "scripts" / "no_hosted_runners.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

WORKFLOWS = ("trusted-workflow-integrity.yml", "trusted-secret-scan.yml", "trusted-protected-paths.yml")
BRIDGE = ["self-hosted", "Linux", "X64", "vl-light"]
PRIVATE = "vagarylabs/vagary-core"


def expressions(name):
    text = (ROOT / ".github" / "workflows" / name).read_text()
    found = re.findall(r"\n    runs-on: \$\{\{ (.*) \}\}\n", text)
    assert found, name
    return found


def place(expr, repo, variables):
    ctx = {"vars": variables, "github": {"repository": repo, "event": {"repository": {"private": repo != "vagarylabs/.github"}}}}
    return guard.evaluate(expr, ctx)


class PlacementSwitch(unittest.TestCase):
    def test_every_trusted_job_reads_the_switch(self):
        for name in WORKFLOWS:
            for expr in expressions(name):
                with self.subTest(workflow=name):
                    self.assertIn("vars.TRUSTED_LIGHT_RUNNER == 'hosted'", expr)

    def test_no_variable_is_the_bridge_in_a_private_target(self):
        for name in WORKFLOWS:
            for expr in expressions(name):
                with self.subTest(workflow=name):
                    self.assertEqual(place(expr, PRIVATE, {}), BRIDGE)

    def test_hosted_selects_ubuntu_latest_in_a_private_target(self):
        for name in WORKFLOWS:
            for expr in expressions(name):
                with self.subTest(workflow=name):
                    self.assertEqual(place(expr, PRIVATE, {"TRUSTED_LIGHT_RUNNER": "hosted"}), "ubuntu-latest")

    def test_any_other_value_is_the_bridge_a_label_cannot_be_injected(self):
        # GitHub compares strings case-insensitively and never trims: HOSTED is hosted, "Hosted " (space) is the bridge.
        for value in ("HOSTED", "Hosted ", "ubuntu-latest", '["ubuntu-latest"]', '["self-hosted","attacker"]', "", "true", "vl-light"):
            for name in WORKFLOWS:
                for expr in expressions(name):
                    with self.subTest(workflow=name, value=value):
                        got = place(expr, PRIVATE, {"TRUSTED_LIGHT_RUNNER": value})
                        self.assertEqual(got, "ubuntu-latest" if value.lower() == "hosted" else BRIDGE)

    def test_the_public_source_repo_stays_hosted_only_for_protected_paths(self):
        for name in WORKFLOWS:
            for expr in expressions(name):
                with self.subTest(workflow=name):
                    got = place(expr, "vagarylabs/.github", {})
                    self.assertEqual(got, "ubuntu-latest" if name == "trusted-protected-paths.yml" else BRIDGE)

    def test_the_switch_resolves_to_exactly_two_placements(self):
        outcomes = set()
        for name in WORKFLOWS:
            for expr in expressions(name):
                for repo in (PRIVATE, "vagarylabs/.github"):
                    for variables in ({}, {"TRUSTED_LIGHT_RUNNER": "hosted"}, {"TRUSTED_LIGHT_RUNNER": '["x"]'}):
                        outcomes.add(repr(place(expr, repo, variables)))
        self.assertEqual(outcomes, {repr(BRIDGE), repr("ubuntu-latest")})


if __name__ == "__main__":
    unittest.main()
