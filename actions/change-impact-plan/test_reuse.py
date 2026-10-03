"""reuse.run_usable: a receipt binds to the merged head, this repo and this workflow; everything else refused."""
import unittest

from reuse import run_usable

REPO = "vagarylabs/vagaris"
GOOD = {"repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
        "path": ".github/workflows/pr.yml", "event": "pull_request", "conclusion": "success", "head_sha": "h" * 40}
PARENTS = ["b" * 40, "h" * 40]


class ReuseTest(unittest.TestCase):
    def check(self, run=None, parents=PARENTS):
        return run_usable(dict(GOOD, **(run or {})), repo=REPO, workflow_path=".github/workflows/pr.yml", parents=parents)

    def test_bound_run_is_usable(self):
        self.assertIsNone(self.check())

    def test_refusals(self):
        cases = {
            "fork head": ({"head_repository": {"full_name": "someone/vagaris"}}, PARENTS),
            "other workflow": ({"path": ".github/workflows/e2e.yml"}, PARENTS),
            "push run": ({"event": "push"}, PARENTS),
            "failed run": ({"conclusion": "failure"}, PARENTS),
            "different head (another PR's receipt)": ({"head_sha": "x" * 40}, PARENTS),
            "squash merge (one parent)": (None, ["b" * 40]),
        }
        for name, (run, parents) in cases.items():
            with self.subTest(name):
                self.assertIsNotNone(self.check(run, parents))


if __name__ == "__main__":
    unittest.main()
