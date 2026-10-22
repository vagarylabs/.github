"""Routing pin for the org-required trusted-* workflows (root, 2026-10-22).

On merge_group the trusted checks take the bridge merge-queue pool (vl-mq), so a queue candidate's
trusted-gitleaks / trusted-trufflehog / integrity / protected-paths jobs never wait behind PR light
traffic while a vl-mq runner sits idle (#705's group waited >5 min). Every other event stays on
vl-light. Both runner lists are LITERALS, with no `vars.` reference: a trusted judge must not be movable
by a repository variable (test_trusted.test_invariants pins that), so the caller's MQ_RUNS_ON is NOT read.
Every repository the trusted ruleset targets can use vl-mq runners (vl-bridge group; runners 1-2, 1-3, 1-8
carry self-hosted, Linux, X64, vl-mq, verified 2026-10-22).
"""
import json
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("trusted-*.yml"))
LIGHT = ["self-hosted", "Linux", "X64", "vl-light"]
MQ = ["self-hosted", "Linux", "X64", "vl-mq"]
PATTERN = re.compile(r"\$\{\{ github\.event_name == '(\w+)' && fromJSON\('(.+?)'\) \|\| fromJSON\('(.+?)'\) \}\}")


def evaluate(expr, event):
    """Evaluate exactly the pinned literal shape: `event == X && fromJSON(A) || fromJSON(B)`."""
    m = PATTERN.fullmatch(expr)
    if not m:
        raise ValueError("runs-on is not the pinned literal merge-queue routing expression")
    wanted, on_match, otherwise = m.group(1), json.loads(m.group(2)), json.loads(m.group(3))
    return on_match if event == wanted else otherwise


def runs_on_values(path):
    doc = yaml.safe_load(path.read_text())
    return {job: spec.get("runs-on") for job, spec in doc["jobs"].items()}


class TrustedRunsOn(unittest.TestCase):
    def test_every_trusted_job_routes_merge_group_to_vl_mq_and_the_rest_to_vl_light(self):
        self.assertEqual(len(WORKFLOWS), 3, [w.name for w in WORKFLOWS])
        seen = 0
        for wf in WORKFLOWS:
            for job, runs_on in runs_on_values(wf).items():
                seen += 1
                self.assertEqual(evaluate(runs_on, "merge_group"), MQ, f"{wf.name}:{job}")
                for event in ("pull_request", "push", "workflow_dispatch"):
                    self.assertEqual(evaluate(runs_on, event), LIGHT, f"{wf.name}:{job}:{event}")
                self.assertNotIn("vars.", runs_on, f"{wf.name}:{job}")
        self.assertEqual(seen, 4)

    def test_control_a_hardcoded_light_runner_or_a_variable_is_refused(self):
        with self.assertRaises(ValueError):
            evaluate("[self-hosted, Linux, X64, vl-light]", "merge_group")
        with self.assertRaises(ValueError):
            evaluate("${{ github.event_name == 'merge_group' && vars.MQ_RUNS_ON && fromJSON(vars.MQ_RUNS_ON) "
                     "|| fromJSON('[\"self-hosted\",\"Linux\",\"X64\",\"vl-light\"]') }}", "merge_group")


if __name__ == "__main__":
    unittest.main()
