"""The no-hosted-runners guard exempts EXACTLY three hosted cases, all in repository vagarylabs/.github: workflow
trusted-protected-paths.yml job trusted-protected-paths (the public repo's own judge job), and workflow
trusted-secret-scan.yml jobs trusted-gitleaks and trusted-trufflehog (F-16, root 2026-11-22), each hosted per the 10-21
rule that public repos stay GitHub-hosted. Plain unittest, stdlib only. Run:
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
SCAN_FILE, SCAN_JOBS = "trusted-secret-scan.yml", ("trusted-gitleaks", "trusted-trufflehog")
TRIPLES = ((REPO, ".github/workflows/" + FILE, JOB),) + tuple(
    (REPO, ".github/workflows/" + SCAN_FILE, j) for j in SCAN_JOBS)
HOSTED = "    runs-on: ubuntu-latest\n"


def scan(repo, fname, job, runs_on=HOSTED, text=None, private=True):
    with tempfile.TemporaryDirectory() as d:
        w = pathlib.Path(d) / ".github" / "workflows"
        w.mkdir(parents=True)
        (w / fname).write_text(text if text is not None else "jobs:\n  %s:\n%s" % (job, runs_on))
        return guard.check(d, {}, private, repo=repo)[0]


class Exemption(unittest.TestCase):
    def test_the_named_triples_are_the_only_exemptions(self):
        # Exactly these three, in this order: a fourth entry, a dropped one or a widened one turns this red.
        self.assertEqual(guard.HOSTED_EXEMPT, TRIPLES)

    def test_i_admits_exactly_those_repo_and_jobs(self):
        self.assertEqual(scan(REPO, FILE, JOB), [])
        for job in SCAN_JOBS:
            with self.subTest(job=job):
                self.assertEqual(scan(REPO, SCAN_FILE, job), [])

    def test_i_the_real_workflow_is_clean_in_dotgithub_and_resolves_to_the_bridge_elsewhere(self):
        text = (ROOT / ".github" / "workflows" / FILE).read_text()
        self.assertEqual(scan(REPO, FILE, JOB, text=text), [])
        # In a private target the same expression is the bridge label, never hosted: no exemption is needed there.
        self.assertEqual(scan("vagarylabs/vagary-core", FILE, JOB, text=text), [])
        # and the exemption is not what makes it pass there: hosted in that context is refused
        self.assertEqual(len(scan("vagarylabs/vagary-core", FILE, JOB)), 1)

    def test_i_the_real_secret_scan_workflow_is_clean_in_dotgithub_and_the_bridge_elsewhere(self):
        text = (ROOT / ".github" / "workflows" / SCAN_FILE).read_text()
        self.assertEqual(scan(REPO, SCAN_FILE, SCAN_JOBS[0], text=text), [])
        self.assertEqual(scan("vagarylabs/vagary-core", SCAN_FILE, SCAN_JOBS[0], text=text), [])
        for job in SCAN_JOBS:
            with self.subTest(job=job):
                self.assertEqual(len(scan("vagarylabs/vagary-core", SCAN_FILE, job)), 1)

    def test_ii_negative_every_other_hosted_case_still_fails(self):
        cases = [("vagarylabs/vagary-core", FILE, JOB), ("vagarylabs/vagary-voice", FILE, JOB),
                 (REPO, FILE, "other-job"), (REPO, "ci.yml", JOB), (REPO, "ci.yml", "other-job"),
                 ("vagarylabs/.github-x", FILE, JOB), ("vagarylabs/.github2", FILE, JOB), ("", FILE, JOB),
                 # F-16: the scan file with any other job, a scan job in another file, a scan job in another repo
                 (REPO, SCAN_FILE, "other-job"), (REPO, SCAN_FILE, JOB), (REPO, FILE, SCAN_JOBS[0]),
                 (REPO, "ci.yml", SCAN_JOBS[1]), ("vagarylabs/vagary-core", SCAN_FILE, SCAN_JOBS[0]),
                 ("vagarylabs/.github-x", SCAN_FILE, SCAN_JOBS[1])]
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
            return (repo, str(rel)) in {(r, f) for r, f, _ in TRIPLES}

        def drop_repo(repo, rel, job):
            return (str(rel), job) in {(f, j) for _, f, j in TRIPLES}

        for name, mutant in (("drops the job match", drop_job), ("drops the repository match", drop_repo)):
            with self.subTest(mutant=name), mock.patch.object(guard, "hosted_exempt", mutant):
                widened = [scan(REPO, FILE, "other-job"), scan("vagarylabs/vagary-core", FILE, JOB),
                           scan(REPO, SCAN_FILE, "other-job"), scan("vagarylabs/vagary-core", SCAN_FILE, SCAN_JOBS[0])]
                self.assertNotEqual([len(x) for x in widened], [1, 1, 1, 1],
                                    "the negative cases must be red under the mutant")

    def test_the_embedded_copy_in_the_workflow_carries_the_exemption(self):
        text = (ROOT / ".github" / "workflows" / "no-hosted-runners.yml").read_text()
        self.assertIn("HOSTED_EXEMPT = (\n", text)
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                self.assertIn('("%s", "%s", "%s"),' % triple, text)
        self.assertIn("return (repo, str(rel), job) in HOSTED_EXEMPT", text)


if __name__ == "__main__":
    unittest.main()
