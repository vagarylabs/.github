"""full-run-reuse: a push reuses only the NEWEST merge-group run of the SAME commit, and only when that run, every
non-ignored job and every required check passed with a FULL receipt; everything else runs the suite."""
import io
import json
import unittest
import zipfile

from reuse import POLL_SECONDS, lookup, workflow_path

REPO = "vagarylabs/vagary-core"
SHA = "a" * 40
PATH = ".github/workflows/services.yml"
RUN_ID, ATTEMPT = 4242, 2
VOID = "Obsolete merge-group candidate (nothing verified)"
ENV = {"REPO": REPO, "SHA": SHA, "EVENT": "push", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main",
       "WORKFLOW_REF": f"{REPO}/{PATH}@refs/heads/main", "VERDICT_JOB": "build", "VOID_STEPS": json.dumps([VOID]),
       "IGNORE_JOBS": json.dumps(["slow-cases upload"]), "EVENT_CONDITIONAL_STEPS": "[]", "WAIT_MINUTES": "10"}
RUN = {"id": RUN_ID, "run_attempt": ATTEMPT, "event": "merge_group", "head_sha": SHA, "path": PATH,
       "repository": {"full_name": REPO}, "status": "completed", "conclusion": "success"}
RECEIPT = {"schema": 2, "mode": "full", "event": "merge_group", "repository": REPO, "workflow_path": PATH,
           "head_sha": SHA, "run_id": RUN_ID, "run_attempt": ATTEMPT, "job": "build"}
REQUIRED = ["build", "services (identity)", "policy"]


def job(id_, name, status="completed", conclusion="success", steps=()):
    return {"id": id_, "name": name, "status": status, "conclusion": conclusion, "steps": list(steps)}


def jobs_ok():
    return [job(1, "policy"), job(2, "services (identity)", steps=[{"name": VOID, "conclusion": "skipped"}]),
            job(3, "build"), job(4, "advisory docs", conclusion="skipped"), job(5, "slow-cases upload", "in_progress", None)]


def zipped(receipt):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("receipt.json", receipt if isinstance(receipt, str) else json.dumps(receipt))
    return buf.getvalue()


class FakeApi:
    """The reads the lookup makes, each overridable; any other URL is a test bug."""

    def __init__(self, runs=None, jobs=None, total=None, artifacts=None, receipt=RECEIPT, fail=None, rules=None,
                 polls=None, pages=None):
        self.runs = [RUN] if runs is None else runs
        self.jobs = jobs_ok() if jobs is None else jobs
        self.total = len(self.jobs) if total is None else total
        self.pages = pages  # explicit {page: [jobs]} for pagination tests
        self.artifacts = [{"name": f"ci-full-run-receipt-a{ATTEMPT}", "expired": False,
                           "archive_download_url": "https://blob.example/receipt.zip"}] if artifacts is None else artifacts
        self.receipt, self.fail, self.calls = receipt, fail, []
        self.rules = [{"type": "required_status_checks", "parameters": {"required_status_checks": [
            {"context": c} for c in REQUIRED]}}, {"type": "merge_queue", "parameters": {}}] if rules is None else rules
        self.polls = list(polls or [])  # successive GET /actions/runs/<id> bodies

    def __call__(self, path, raw=False):
        self.calls.append(path)
        if self.fail and self.fail in path:
            raise OSError("connection reset")
        if path == f"/repos/{REPO}/rules/branches/main":
            return self.rules
        if path.startswith(f"/repos/{REPO}/actions/workflows/services.yml/runs?event=merge_group&head_sha={SHA}"):
            return {"workflow_runs": self.runs}
        if path.startswith(f"/repos/{REPO}/actions/runs/") and path.count("/") == 6:
            return self.polls.pop(0)
        if "/attempts/" in path and "/jobs" in path:
            page = int(path.rsplit("page=", 1)[1])
            if self.pages is not None:
                return {"total_count": self.total, "jobs": self.pages.get(page, [])}
            return {"total_count": self.total, "jobs": self.jobs if page == 1 else []}
        if path.startswith(f"/repos/{REPO}/actions/runs/") and "/artifacts?name=ci-full-run-receipt-a" in path:
            return {"artifacts": self.artifacts}
        if path == "https://blob.example/receipt.zip" and raw:
            return zipped(self.receipt)
        raise AssertionError(f"unexpected read {path}")


def check(api, sleep=None, now=None, **env):
    clock = [0.0]
    def fake_sleep(seconds): clock[0] += seconds
    return lookup(dict(ENV, **env), api, sleep=sleep or fake_sleep, now=now or (lambda: clock[0]))


class Accepts(unittest.TestCase):
    def test_a_passing_full_run_of_the_same_commit_is_reused(self):
        run_id, log = check(FakeApi())
        self.assertEqual(run_id, str(RUN_ID))
        self.assertEqual(log[0], f"newest run {RUN_ID}: ACCEPTED")

    def test_an_in_progress_run_is_polled_until_it_completes(self):
        # Non-required jobs can outlive the merge; the reader waits (bounded) instead of accepting an unfinished run.
        running = dict(RUN, status="in_progress", conclusion=None)
        api = FakeApi(runs=[running], polls=[running, RUN])
        self.assertEqual(check(api)[0], str(RUN_ID))
        self.assertEqual(sum(1 for c in api.calls if c == f"/repos/{REPO}/actions/runs/{RUN_ID}"), 2)

    def test_the_newest_run_is_the_one_evaluated(self):
        older = dict(RUN, id=1)
        self.assertEqual(check(FakeApi(runs=[older, RUN]))[0], str(RUN_ID))


class Refuses(unittest.TestCase):
    def refused(self, api, **kw):
        run_id, log = check(api, **kw)
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
                self.assertIn(reason, self.refused(FakeApi(runs=[dict(RUN, **{field: value})]))[0])

    def test_the_run_must_be_completed_and_successful(self):
        # B1: the verdict job alone proves nothing about the other required checks.
        for conclusion in ("failure", "cancelled", "skipped", "neutral", "timed_out", "action_required", None):
            with self.subTest(conclusion):
                self.assertIn("not completed/success", self.refused(FakeApi(runs=[dict(RUN, conclusion=conclusion)]))[0])

    def test_a_run_still_running_after_the_wait_is_refused(self):
        running = dict(RUN, status="in_progress", conclusion=None)
        polls = [running] * (10 * 60 // POLL_SECONDS + 2)
        self.assertIn("in_progress/None", self.refused(FakeApi(runs=[running], polls=polls))[0])
        # wait-minutes 0: no poll at all.
        api = FakeApi(runs=[running])
        self.assertIn("in_progress/None", self.refused(api, WAIT_MINUTES="0")[0])
        self.assertNotIn(f"/repos/{REPO}/actions/runs/{RUN_ID}", api.calls)

    def test_the_vagaris_shape_verify_green_while_required_policy_failed(self):
        # Live: vagaris merge_group runs 41076107629 and 41018844709 had `verify` success with `policy` failed. Even
        # with a run reported success (re-run attempt quirks), a failed required check refuses.
        jobs = jobs_ok(); jobs[0] = job(1, "policy", conclusion="failure")
        self.assertIn("required check 'policy' is completed/failure", self.refused(FakeApi(jobs=jobs))[0])

    def test_every_non_ignored_job_must_pass(self):
        for conclusion, status in (("failure", "completed"), ("cancelled", "completed"), ("timed_out", "completed"),
                                   (None, "in_progress"), (None, "queued"), ("action_required", "completed")):
            with self.subTest(conclusion=conclusion, status=status):
                jobs = jobs_ok() + [job(9, "e2e", status, conclusion)]
                self.assertIn("job 'e2e' is", self.refused(FakeApi(jobs=jobs))[0])

    def test_a_required_check_must_be_success_not_merely_passing(self):
        for conclusion in ("skipped", "neutral", "cancelled"):
            with self.subTest(conclusion):
                jobs = jobs_ok(); jobs[1] = job(2, "services (identity)", conclusion=conclusion)
                self.assertIn("required check 'services (identity)'", self.refused(FakeApi(jobs=jobs))[0])

    def test_the_verdict_job(self):
        for name, verdict, reason in [
            ("missing", None, "appears 0 times"),
            ("twice", [job(3, "build"), job(30, "build")], "appears 2 times"),
            ("cancelled", [job(3, "build", conclusion="cancelled")], "required check 'build'"),
            ("running", [job(3, "build", "in_progress", None)], "required check 'build'"),
        ]:
            with self.subTest(name):
                jobs = [j for j in jobs_ok() if j["name"] != "build"] + (verdict or [])
                self.assertIn(reason, self.refused(FakeApi(jobs=jobs))[0])

    def test_a_void_step_voids_the_run_whatever_its_conclusion(self):
        for conclusion in ("success", "failure", "cancelled"):
            with self.subTest(conclusion):
                jobs = jobs_ok(); jobs[1] = job(2, "services (identity)", steps=[{"name": VOID, "conclusion": conclusion}])
                self.assertIn("void step", self.refused(FakeApi(jobs=jobs))[0])

    def test_a_refused_newest_run_never_falls_through_to_an_older_one(self):
        # B2: a re-run group leaves several runs for one commit; only the newest is evidence.
        older_good = dict(RUN, id=1)
        newest_failed = dict(RUN, id=RUN_ID + 1, conclusion="failure")
        log = self.refused(FakeApi(runs=[older_good, newest_failed]))
        self.assertIn(f"newest run {RUN_ID + 1}", log[0])
        self.assertIn("1 older run(s) of this commit are never considered", log[0])

    def test_a_read_error_on_the_newest_run_never_falls_through(self):
        # Probe P11: a network error on the newest run, an older run's `policy` failed: FULL, not the older run.
        older = dict(RUN, id=1)
        newest = dict(RUN, id=RUN_ID)
        self.assertEqual(self.refused(FakeApi(runs=[older, newest], fail="/attempts/")),
                         ["lookup unresolvable: OSError"])

    def test_job_pages_are_counted_by_unique_id(self):
        page1, page2 = jobs_ok()[:3], jobs_ok()[:2]  # page 2 repeats ids 1 and 2
        self.assertIn("unresolvable", self.refused(FakeApi(pages={1: page1, 2: page2}, total=5))[0])
        self.assertIn("unresolvable", self.refused(FakeApi(total=250))[0])

    def test_the_receipt_artifact(self):
        good = {"name": f"ci-full-run-receipt-a{ATTEMPT}", "expired": False, "archive_download_url": "https://blob.example/receipt.zip"}
        for name, arts, reason in [
            ("missing", [], "0 unexpired"), ("expired", [dict(good, expired=True)], "0 unexpired"),
            ("another attempt's", [dict(good, name="ci-full-run-receipt-a1")], "0 unexpired"), ("two", [good, dict(good)], "2 unexpired"),
        ]:
            with self.subTest(name):
                self.assertIn(reason, self.refused(FakeApi(artifacts=arts))[0])

    def test_every_receipt_field_binds(self):
        for key, value in [("schema", 1), ("mode", "affected"), ("event", "pull_request"), ("repository", "x/y"),
                           ("workflow_path", ".github/workflows/console.yml"), ("head_sha", "b" * 40),
                           ("run_id", 1), ("run_attempt", 1)]:
            with self.subTest(key):
                self.assertIn(f"receipt {key}", self.refused(FakeApi(receipt=dict(RECEIPT, **{key: value})))[0])

    def test_a_malformed_receipt_or_response_is_full_never_a_crash(self):
        # L1: each of these used to raise past the handler.
        for receipt in ("[1, 2]", "null", '"text"', "{", "{}"):
            with self.subTest(receipt=receipt):
                self.assertTrue(self.refused(FakeApi(receipt=receipt)))
        for runs in ([{"id": "x"}], [None], "not-a-list"):
            with self.subTest(runs=runs):
                self.assertEqual(self.refused(FakeApi(runs=runs)), ["lookup unresolvable: ValueError"])
        self.assertIn("unresolvable", self.refused(FakeApi(jobs=[{"name": "build"}]))[0])  # a job with no id

    def test_unreadable_required_checks_are_full(self):
        self.assertEqual(self.refused(FakeApi(fail="/rules/branches/")), ["required checks unreadable: OSError"])
        self.assertEqual(self.refused(FakeApi(rules={"not": "a list"})), ["required checks unreadable: ValueError"])

    def test_api_errors_are_reported_by_type_only(self):
        for where in ("/attempts/", "/artifacts", "blob.example", "/workflows/"):
            with self.subTest(where):
                self.assertEqual(self.refused(FakeApi(fail=where)), ["lookup unresolvable: OSError"])


class Configuration(unittest.TestCase):
    def test_a_missing_or_malformed_configuration_is_an_error_not_a_miss(self):
        for env in ({"VERDICT_JOB": ""}, {"VOID_STEPS": "{}"}, {"VOID_STEPS": '[""]'}, {"IGNORE_JOBS": "x"},
                    {"EVENT_CONDITIONAL_STEPS": ""}, {"EVENT_CONDITIONAL_STEPS": "{}"}, {"WAIT_MINUTES": "31"},
                    {"WAIT_MINUTES": "-1"}, {"WORKFLOW_REF": f"someone/else/{PATH}@refs/heads/main"},
                    {"WORKFLOW_REF": f"{REPO}/README.md@main"}):
            with self.subTest(env):
                with self.assertRaises(ValueError):
                    check(FakeApi(), **env)

    def test_a_required_check_can_never_be_ignored(self):
        with self.assertRaises(ValueError):
            check(FakeApi(), IGNORE_JOBS=json.dumps(["policy"]))

    def test_workflow_path_is_bound_to_this_repository(self):
        self.assertEqual(workflow_path(f"{REPO}/{PATH}@refs/heads/main", REPO), PATH)
        with self.assertRaises(ValueError):
            workflow_path(f"{REPO}x/{PATH}@refs/heads/main", REPO)


if __name__ == "__main__":
    unittest.main()
