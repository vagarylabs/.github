"""full-run-reuse: a push reuses only a merge group's FULL run of the SAME commit; everything else runs the suite."""
import io
import json
import unittest
import zipfile

from reuse import evaluate, lookup, workflow_path

REPO = "vagarylabs/vagary-core"
SHA = "a" * 40
PATH = ".github/workflows/services.yml"
RUN_ID, ATTEMPT = 4242, 2
ENV = {"REPO": REPO, "SHA": SHA, "EVENT": "push", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main",
       "WORKFLOW_REF": f"{REPO}/{PATH}@refs/heads/main", "VERDICT_JOB": "build",
       "VOID_STEPS": json.dumps(["Obsolete merge-group candidate (nothing verified)"])}
RUN = {"id": RUN_ID, "run_attempt": ATTEMPT, "event": "merge_group", "head_sha": SHA, "path": PATH,
       "repository": {"full_name": REPO}, "status": "in_progress", "conclusion": None}
RECEIPT = {"schema": 2, "mode": "full", "event": "merge_group", "repository": REPO, "workflow_path": PATH,
           "head_sha": SHA, "run_id": RUN_ID, "run_attempt": ATTEMPT, "job": "build"}
VOID = "Obsolete merge-group candidate (nothing verified)"


def zipped(receipt):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("receipt.json", json.dumps(receipt))
    return buf.getvalue()


class FakeApi:
    """The four reads the lookup makes, each overridable; any other URL is a test bug."""

    def __init__(self, runs=None, jobs=None, total=None, artifacts=None, receipt=RECEIPT, fail=None):
        self.runs = [RUN] if runs is None else runs
        self.jobs = jobs if jobs is not None else [
            {"name": "services (identity)", "status": "completed", "conclusion": "success",
             "steps": [{"name": VOID, "conclusion": "skipped"}]},
            {"name": "build", "status": "completed", "conclusion": "success", "steps": []},
            {"name": "slow-cases upload", "status": "in_progress", "conclusion": None, "steps": []},
        ]
        self.total = len(self.jobs) if total is None else total
        self.artifacts = [{"name": f"ci-full-run-receipt-a{ATTEMPT}", "expired": False,
                           "archive_download_url": "https://blob.example/receipt.zip"}] if artifacts is None else artifacts
        self.receipt, self.fail, self.calls = receipt, fail, []

    def __call__(self, path, raw=False):
        self.calls.append(path)
        if self.fail and self.fail in path:
            raise OSError("connection reset")
        if path.startswith(f"/repos/{REPO}/actions/workflows/services.yml/runs?event=merge_group&head_sha={SHA}"):
            return {"workflow_runs": self.runs}
        if path.startswith(f"/repos/{REPO}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs"):
            page = int(path.rsplit("page=", 1)[1])
            return {"total_count": self.total, "jobs": self.jobs if page == 1 else []}
        if path.startswith(f"/repos/{REPO}/actions/runs/{RUN_ID}/artifacts?name=ci-full-run-receipt-a{ATTEMPT}"):
            return {"artifacts": self.artifacts}
        if path == "https://blob.example/receipt.zip" and raw:
            return zipped(self.receipt)
        raise AssertionError(f"unexpected read {path}")


def check(api, **env):
    return lookup(dict(ENV, **env), api)


class Accepts(unittest.TestCase):
    def test_a_full_receipt_of_the_same_commit_is_reused(self):
        run_id, log = check(FakeApi())
        self.assertEqual(run_id, str(RUN_ID))
        self.assertEqual(log, [f"run {RUN_ID}: ACCEPTED"])

    def test_the_run_may_still_be_in_progress_when_the_verdict_job_has_succeeded(self):
        # The queue merges on the REQUIRED checks; non-required jobs (uploads) can still be running at push time.
        self.assertEqual(RUN["status"], "in_progress")
        self.assertEqual(check(FakeApi())[0], str(RUN_ID))

    def test_the_newest_acceptable_run_wins(self):
        older = dict(RUN, id=1, head_sha="b" * 40)
        api = FakeApi(runs=[older, RUN])
        self.assertEqual(check(api)[0], str(RUN_ID))


class Refuses(unittest.TestCase):
    def refused(self, api, **env):
        run_id, log = check(api, **env)
        self.assertEqual(run_id, "", log)
        return log

    def test_not_a_push_to_the_default_branch(self):
        for env in ({"EVENT": "merge_group"}, {"EVENT": "pull_request"}, {"REF": "refs/heads/release"}):
            with self.subTest(env):
                self.assertEqual(self.refused(FakeApi(), **env), ["not a push to the default branch"])

    def test_a_malformed_pushed_sha(self):
        self.assertEqual(self.refused(FakeApi(), SHA="A" * 40), ["pushed sha is not 40 hex"])

    def test_no_merge_group_run(self):
        self.assertEqual(self.refused(FakeApi(runs=[])), ["no merge_group run of this commit"])

    def test_run_binding(self):
        for field, value, reason in [
            ("event", "pull_request", "event pull_request"),
            ("head_sha", "b" * 40, "different commit"),
            ("path", ".github/workflows/console.yml", "is not"),
            ("repository", {"full_name": "someone/vagary-core"}, "another repository"),
            ("run_attempt", 0, "no id or attempt"),
        ]:
            with self.subTest(field):
                log = self.refused(FakeApi(runs=[dict(RUN, **{field: value})]))
                self.assertIn(reason, log[0])

    def test_the_verdict_job(self):
        build = {"name": "build", "status": "completed", "conclusion": "success", "steps": []}
        for name, jobs, reason in [
            ("missing", [], "appears 0 times"),
            ("twice", [build, dict(build)], "appears 2 times"),
            ("still running", [dict(build, status="in_progress", conclusion=None)], "in_progress"),
            ("failed", [dict(build, conclusion="failure")], "failure"),
            ("skipped", [dict(build, conclusion="skipped")], "skipped"),
        ]:
            with self.subTest(name):
                self.assertIn(reason, self.refused(FakeApi(jobs=jobs))[0])

    def test_an_executed_void_step_voids_the_run(self):
        jobs = [{"name": "build", "status": "completed", "conclusion": "success",
                 "steps": [{"name": VOID, "conclusion": "success"}]}]
        self.assertIn("void step", self.refused(FakeApi(jobs=jobs))[0])

    def test_a_job_listing_past_what_was_read_is_unresolvable(self):
        self.assertIn("unresolvable: ValueError", self.refused(FakeApi(total=250))[0])

    def test_the_receipt_artifact(self):
        good = {"name": f"ci-full-run-receipt-a{ATTEMPT}", "expired": False, "archive_download_url": "https://blob.example/receipt.zip"}
        for name, arts, reason in [
            ("missing", [], "0 unexpired"),
            ("expired", [dict(good, expired=True)], "0 unexpired"),
            ("another attempt's", [dict(good, name="ci-full-run-receipt-a1")], "0 unexpired"),
            ("two", [good, dict(good)], "2 unexpired"),
        ]:
            with self.subTest(name):
                self.assertIn(reason, self.refused(FakeApi(artifacts=arts))[0])

    def test_every_receipt_field_binds(self):
        for key, value in [("schema", 1), ("mode", "affected"), ("event", "pull_request"), ("repository", "x/y"),
                           ("workflow_path", ".github/workflows/console.yml"), ("head_sha", "b" * 40),
                           ("run_id", 1), ("run_attempt", 1)]:
            with self.subTest(key):
                self.assertIn(f"receipt {key}", self.refused(FakeApi(receipt=dict(RECEIPT, **{key: value})))[0])
        missing = {k: v for k, v in RECEIPT.items() if k != "mode"}
        self.assertIn("receipt mode", self.refused(FakeApi(receipt=missing))[0])

    def test_api_errors_are_reported_by_type_only(self):
        for where in ("/jobs", "/artifacts", "blob.example"):
            with self.subTest(where):
                log = self.refused(FakeApi(fail=where))
                self.assertEqual(log, [f"run {RUN_ID}: unresolvable: OSError"])
        log = self.refused(FakeApi(fail="/workflows/"))
        self.assertEqual(log, ["lookup unresolvable: OSError"])

    def test_a_corrupt_receipt_zip_is_unresolvable(self):
        api = FakeApi()
        def corrupt(path, raw=False):
            return b"not a zip" if raw else api(path, raw)
        self.assertIn("unresolvable: BadZipFile", lookup(ENV, corrupt)[1][0])


class Configuration(unittest.TestCase):
    def test_a_missing_or_malformed_configuration_is_an_error_not_a_miss(self):
        for env in ({"VERDICT_JOB": ""}, {"VOID_STEPS": "{}"}, {"VOID_STEPS": '[""]'},
                    {"WORKFLOW_REF": f"someone/else/{PATH}@refs/heads/main"}, {"WORKFLOW_REF": f"{REPO}/README.md@main"}):
            with self.subTest(env):
                with self.assertRaises(ValueError):
                    check(FakeApi(), **env)

    def test_workflow_path_is_bound_to_this_repository(self):
        self.assertEqual(workflow_path(f"{REPO}/{PATH}@refs/heads/main", REPO), PATH)
        with self.assertRaises(ValueError):
            workflow_path(f"{REPO}x/{PATH}@refs/heads/main", REPO)


if __name__ == "__main__":
    unittest.main()
