"""The no-hosted-runners guard exempts EXACTLY one hosted case: repository vagarylabs/.github, workflow
trusted-protected-paths.yml, job trusted-protected-paths (the public repo's own judge job, hosted per the 10-21 rule that
public repos stay GitHub-hosted). Plain unittest, stdlib only. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_no_hosted_exemption.py' -v
"""
import importlib.util
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("no_hosted_runners", ROOT / "scripts" / "no_hosted_runners.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

REPO, FILE, JOB = "vagarylabs/.github", "trusted-protected-paths.yml", "trusted-protected-paths"
HOSTED = "    runs-on: ubuntu-latest\n"


def scan(repo, fname, job, runs_on=HOSTED, text=None, private=True):
    with tempfile.TemporaryDirectory() as d:
        w = pathlib.Path(d) / ".github" / "workflows"
        w.mkdir(parents=True)
        (w / fname).write_text(text if text is not None else "jobs:\n  %s:\n%s" % (job, runs_on))
        return guard.check(d, {}, private, repo=repo)[0]


class Exemption(unittest.TestCase):
    def test_the_named_triple_is_the_only_exemption(self):
        self.assertEqual(guard.HOSTED_EXEMPT, (REPO, ".github/workflows/" + FILE, JOB))

    def test_i_admits_exactly_that_repo_and_job(self):
        self.assertEqual(scan(REPO, FILE, JOB), [])

    def test_i_the_real_workflow_is_clean_in_dotgithub_and_resolves_to_the_bridge_elsewhere(self):
        text = (ROOT / ".github" / "workflows" / FILE).read_text()
        self.assertEqual(scan(REPO, FILE, JOB, text=text), [])
        # In a private target the same expression is the bridge label, never hosted: no exemption is needed there.
        self.assertEqual(scan("vagarylabs/vagary-core", FILE, JOB, text=text), [])
        # and the exemption is not what makes it pass there: hosted in that context is refused
        self.assertEqual(len(scan("vagarylabs/vagary-core", FILE, JOB)), 1)

    def test_ii_negative_every_other_hosted_case_still_fails(self):
        cases = [("vagarylabs/vagary-core", FILE, JOB), ("vagarylabs/vagary-voice", FILE, JOB),
                 (REPO, FILE, "other-job"), (REPO, "ci.yml", JOB), (REPO, "ci.yml", "other-job"),
                 ("vagarylabs/.github-x", FILE, JOB), ("vagarylabs/.github2", FILE, JOB), ("", FILE, JOB)]
        for repo, fname, job in cases:
            with self.subTest(repo=repo, file=fname, job=job):
                self.assertEqual(len(scan(repo, fname, job)), 1)

    def test_ii_negative_the_job_added_to_a_file_with_other_hosted_jobs(self):
        text = "jobs:\n  %s:\n%s  extra:\n%s" % (JOB, HOSTED, HOSTED)
        found = scan(REPO, FILE, JOB, text=text)
        self.assertEqual(len(found), 1)
        self.assertIn("[extra]", found[0])

    def test_mutant_widening_the_exemption_turns_the_negatives_red(self):
        # Each widening makes a negative case pass when it must fail, so test_ii would go red.
        def drop_job(repo, rel, job):
            return (repo, str(rel)) == (REPO, ".github/workflows/" + FILE)

        def drop_repo(repo, rel, job):
            return (str(rel), job) == (".github/workflows/" + FILE, JOB)

        for name, mutant in (("drops the job match", drop_job), ("drops the repository match", drop_repo)):
            with self.subTest(mutant=name), mock.patch.object(guard, "hosted_exempt", mutant):
                widened = [scan(REPO, FILE, "other-job"), scan("vagarylabs/vagary-core", FILE, JOB)]
                self.assertNotEqual([len(x) for x in widened], [1, 1], "the negative cases must be red under the mutant")

    def test_the_embedded_copy_in_the_workflow_carries_the_exemption(self):
        text = (ROOT / ".github" / "workflows" / "no-hosted-runners.yml").read_text()
        self.assertIn('HOSTED_EXEMPT = ("vagarylabs/.github", ".github/workflows/trusted-protected-paths.yml", '
                      '"trusted-protected-paths")', text)


if __name__ == "__main__":
    unittest.main()
