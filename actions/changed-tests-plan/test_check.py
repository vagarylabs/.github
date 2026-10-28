"""check.py: the changed_tests v1 plan validator and grader (stdlib unittest; no network, milliseconds)."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402

HEAD = "1" * 40
OTHER = "2" * 40
BASE = "a" * 40
SELECTED = {
    "version": 1, "head_sha": HEAD, "base_sha": BASE, "mode": "selected", "whole_groups": ["db"],
    "partitions": {"server": ["server/src/__tests__/a.test.ts"], "other": []},
    "e2e": True, "deleted_tests": ["server/src/__tests__/old.test.ts"],
    "source_paths": ["server/src/a.ts"], "reasons": ["a.test.ts changed"],
}
NONE = {"version": 1, "head_sha": HEAD, "base_sha": BASE, "mode": "none", "whole_groups": [], "partitions": {}, "e2e": False,
        "deleted_tests": [], "source_paths": ["README.md"], "reasons": ["docs only"]}


def plan(**changes):
    p = copy.deepcopy(SELECTED)
    p.update(changes)
    return p


class ShapeTests(unittest.TestCase):
    def test_valid_plans(self):
        self.assertEqual(check.validate(SELECTED), [])
        self.assertEqual(check.validate(NONE), [])

    def test_every_required_key(self):
        for key in check.load_schema()["required"]:
            p = plan()
            del p[key]
            self.assertTrue(any(key in e for e in check.validate(p)), key)

    def test_closed_shape(self):
        self.assertIn("plan: unknown key 'extra'", check.validate(plan(extra=1)))

    def test_version_is_exactly_integer_one(self):
        for bad in (2, "1", True, 1.0):
            self.assertTrue(check.validate(plan(version=bad)), repr(bad))

    def test_mode_and_types(self):
        self.assertTrue(check.validate(plan(mode="some")))
        self.assertTrue(check.validate(plan(e2e="true")))
        self.assertTrue(check.validate(plan(e2e=1)))
        self.assertTrue(check.validate(plan(whole_groups="db")))
        self.assertTrue(check.validate(plan(partitions={"server": "a.test.ts"})))

    def test_commits_are_bound_and_exact(self):
        for key in ("head_sha", "base_sha"):
            for bad in ("1" * 39, "A" * 40, "g" * 40, "1" * 40 + "\n", 1):
                self.assertTrue(check.validate(plan(**{key: bad})), (key, bad))
            p = plan()
            del p[key]
            self.assertIn(f"plan: missing required key {key!r}", check.validate(p))

    def test_names_and_uniqueness(self):
        self.assertTrue(check.validate(plan(whole_groups=["Db"])))
        self.assertTrue(check.validate(plan(whole_groups=["db\n"])))
        self.assertTrue(check.validate(plan(whole_groups=["db", "db"])))
        self.assertTrue(check.validate(plan(partitions={"Server": ["a.test.ts"]})))
        self.assertTrue(check.validate(plan(partitions={"server": ["a.test.ts", "a.test.ts"]})))


class CrossFieldTests(unittest.TestCase):
    def test_none_listing_work_is_refused(self):
        for work in ({"whole_groups": ["db"]}, {"partitions": {"server": ["a.test.ts"]}}, {"e2e": True}):
            p = copy.deepcopy(NONE)
            p.update(work)
            self.assertIn("plan: mode 'none' lists work", check.validate(p), work)

    def test_none_with_empty_partition_lists_is_fine(self):
        p = copy.deepcopy(NONE)
        p["partitions"] = {"server": []}
        self.assertEqual(check.validate(p), [])

    def test_selected_without_work_is_refused(self):
        p = plan(whole_groups=[], partitions={"server": []}, e2e=False)
        self.assertIn("plan: mode 'selected' lists no work", check.validate(p))

    def test_paths_are_repository_relative(self):
        for bad in ("/abs/a.test.ts", "a\\b.test.ts", "a/../b.test.ts", "./a.test.ts", "a//b.test.ts",
                    "dir/", "a\x00.test.ts"):
            errors = check.validate(plan(partitions={"server": [bad]}))
            self.assertTrue(errors, repr(bad))
            errors = check.validate(plan(source_paths=[bad]))
            self.assertTrue(errors, repr(bad))

    def test_a_deleted_test_is_never_planned(self):
        p = plan(deleted_tests=["server/src/__tests__/a.test.ts"])
        self.assertIn("plan: deleted test 'server/src/__tests__/a.test.ts' is also planned to run", check.validate(p))


class TierTests(unittest.TestCase):
    def test_fast_requires_a_plan(self):
        self.assertEqual(check.check_tier(None, "fast"), ["fast tier without a changed_tests plan"])
        self.assertEqual(check.check_tier(SELECTED, "fast"), [])
        self.assertTrue(check.check_tier(plan(version=2), "fast"))

    def test_full_allows_no_plan_or_none(self):
        self.assertEqual(check.check_tier(None, "full"), [])
        self.assertEqual(check.check_tier(NONE, "full"), [])

    def test_head_binding(self):
        self.assertEqual(check.check_tier(SELECTED, "fast", HEAD), [])
        self.assertEqual(check.check_tier(SELECTED, "fast", OTHER), [f"plan was computed for head {HEAD}, not {OTHER}"])
        self.assertEqual(check.check_tier(NONE, "full", OTHER), [f"plan was computed for head {HEAD}, not {OTHER}"])
        self.assertEqual(check.check_tier(SELECTED, "fast", "main"), ["--head 'main' is not a 40-hex commit"])

    def test_selected_plan_outside_the_fast_tier_is_refused(self):
        self.assertEqual(check.check_tier(SELECTED, "full"), ["a selected changed_tests plan outside the fast tier"])


class GradeTests(unittest.TestCase):
    LANES = {"server": "success", "db": "success", "e2e": "success", "other": "skipped"}
    ALL_GREEN = {"head_sha": HEAD, "lanes": LANES}

    @classmethod
    def at(cls, head=HEAD, **lanes):
        return {"head_sha": head, "lanes": dict(cls.LANES, **lanes)}

    def test_required_lanes(self):
        # `other` lists nothing, so it is not required.
        self.assertEqual(check.required_lanes(SELECTED), ["db", "e2e", "server"])
        self.assertEqual(check.required_lanes(NONE), [])

    def test_every_required_lane_green_passes(self):
        self.assertEqual(check.grade(SELECTED, self.ALL_GREEN), [])

    def test_a_planted_failing_lane_is_refused(self):
        for lane in ("server", "db", "e2e"):
            for outcome in ("failure", "skipped", "cancelled", "neutral"):
                results = self.at(**{lane: outcome})
                self.assertEqual(check.grade(SELECTED, results),
                                 [f"required changed-tests lane {lane!r} concluded {outcome}"], (lane, outcome))

    def test_a_missing_required_lane_is_refused(self):
        results = self.at()
        del results["lanes"]["e2e"]
        self.assertEqual(check.grade(SELECTED, results),
                         ["required changed-tests lane 'e2e' concluded nothing (missing)"])

    def test_none_needs_no_lane(self):
        self.assertEqual(check.grade(NONE, {"head_sha": HEAD, "lanes": {}}), [])

    def test_green_results_from_another_head_never_grade_the_plan(self):
        self.assertEqual(check.grade(SELECTED, self.at(head=OTHER)),
                         [f"results ran at head {OTHER}, but the plan is for head {HEAD}"])

    def test_results_without_a_head_are_refused(self):
        self.assertTrue(check.grade(SELECTED, {"lanes": self.LANES}))
        self.assertTrue(check.grade(SELECTED, self.LANES))
        self.assertTrue(check.grade(SELECTED, {"head_sha": HEAD[:-1], "lanes": self.LANES}))
        self.assertTrue(check.grade(SELECTED, {"head_sha": HEAD, "lanes": self.LANES, "extra": 1}))

    def test_an_invalid_plan_never_grades_green(self):
        self.assertTrue(check.grade(plan(mode="none"), self.ALL_GREEN))

    def test_malformed_results_are_refused(self):
        self.assertTrue(check.grade(SELECTED, ["server"]))
        self.assertTrue(check.grade(SELECTED, {"head_sha": HEAD, "lanes": {"server": True}}))


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", str(HERE / "check.py"), *args], capture_output=True, text=True)

    def write(self, directory, name, value):
        path = Path(directory, name)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return str(path)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            good = self.write(d, "good.json", SELECTED)
            bad = self.write(d, "bad.json", plan(mode="none"))
            torn = self.write(d, "torn.json", "{")
            green = self.write(d, "green.json", GradeTests.ALL_GREEN)
            red = self.write(d, "red.json", GradeTests.at(server="failure"))
            stale = self.write(d, "stale.json", GradeTests.at(head=OTHER))
            self.assertEqual(self.run_cli("plan", "--tier", "fast", good).returncode, 0)
            self.assertEqual(self.run_cli("plan", "--tier", "fast", bad).returncode, 1)
            self.assertEqual(self.run_cli("plan", "--tier", "fast", torn).returncode, 1)
            self.assertEqual(self.run_cli("plan", "--tier", "fast", str(Path(d, "absent.json"))).returncode, 1)
            self.assertEqual(self.run_cli("plan", "--tier", "full", str(Path(d, "absent.json"))).returncode, 0)
            self.assertEqual(self.run_cli("grade", "--plan", good, "--results", green).returncode, 0)
            out = self.run_cli("grade", "--plan", good, "--results", red)
            self.assertEqual(out.returncode, 1)
            self.assertIn("REFUSE: required changed-tests lane 'server' concluded failure", out.stdout)
            self.assertEqual(self.run_cli("grade", "--plan", good, "--results", stale).returncode, 1)
            self.assertEqual(self.run_cli("plan", "--tier", "fast", "--head", HEAD, good).returncode, 0)
            self.assertEqual(self.run_cli("plan", "--tier", "fast", "--head", OTHER, good).returncode, 1)
            self.assertEqual(self.run_cli("bogus").returncode, 2)


class SchemaIsTheSourceTests(unittest.TestCase):
    def test_the_validator_reads_the_schema_file(self):
        # Pin that check.py takes the shape from schema-v1.json: a schema that drops `reasons` from `required`
        # must stop the validator requiring it.
        schema = check.load_schema()
        schema["required"] = [k for k in schema["required"] if k != "reasons"]
        p = plan()
        del p["reasons"]
        self.assertEqual(check.validate(p, schema), [])
        self.assertTrue(check.validate(p))


if __name__ == "__main__":
    unittest.main()
