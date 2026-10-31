"""full-run-receipt: only a merge group's declared-FULL run gets a receipt, and the reader accepts exactly what it writes."""
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
import zipfile

from receipt import build_receipt, main

REPO = "vagarylabs/vagaris"
SHA = "c" * 40
ENV = {"FULL": "true", "EVENT": "merge_group", "WORKFLOW_REF": f"{REPO}/.github/workflows/pr.yml@refs/heads/main",
       "HEAD_SHA": SHA, "REPO": REPO, "JOB": "verify", "GITHUB_RUN_ID": "777", "GITHUB_RUN_ATTEMPT": "3"}


def load_reader():
    path = pathlib.Path(__file__).resolve().parent.parent / "full-run-reuse" / "reuse.py"
    spec = importlib.util.spec_from_file_location("full_run_reuse", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Writes(unittest.TestCase):
    def test_a_full_merge_group_run_gets_a_receipt_bound_to_its_commit_run_and_attempt(self):
        self.assertEqual(build_receipt(ENV), {
            "schema": 2, "mode": "full", "event": "merge_group", "repository": REPO,
            "workflow_path": ".github/workflows/pr.yml", "head_sha": SHA, "run_id": 777, "run_attempt": 3, "job": "verify"})

    def test_nothing_unless_merge_group_and_full_is_exactly_true(self):
        for env in ({"EVENT": "pull_request"}, {"EVENT": "push"}, {"FULL": "false"}, {"FULL": ""}, {"FULL": "True"},
                    {"FULL": "1"}, {"FULL": "true "}):
            with self.subTest(env):
                self.assertIsNone(build_receipt(dict(ENV, **env)))

    def test_an_unbindable_identity_is_an_error_not_a_receipt(self):
        for env in ({"WORKFLOW_REF": f"someone/else/.github/workflows/pr.yml@refs/heads/main"},
                    {"WORKFLOW_REF": f"{REPO}/scripts/x.yml@refs/heads/main"}, {"WORKFLOW_REF": f"{REPO}/.github/workflows/pr.yml"},
                    {"HEAD_SHA": "C" * 40}, {"HEAD_SHA": "c" * 39}, {"GITHUB_RUN_ATTEMPT": "0"}):
            with self.subTest(env):
                with self.assertRaises(ValueError):
                    build_receipt(dict(ENV, **env))

    def test_main_writes_the_file_and_the_attempt_named_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            old = dict(os.environ)
            try:
                os.environ.update(ENV, RUNNER_TEMP=tmp, GITHUB_OUTPUT=out)
                self.assertEqual(main(), 0)
            finally:
                os.environ.clear(); os.environ.update(old)
            self.assertEqual(open(out).read(), "written=a3\n")
            self.assertEqual(json.load(open(os.path.join(tmp, "ci-full-run", "receipt.json")))["run_attempt"], 3)


class ReaderAcceptsWhatTheWriterWrites(unittest.TestCase):
    """Positive control across the pair: a receipt from this writer passes the reader's receipt check unchanged."""

    def test_round_trip(self):
        reader = load_reader()
        receipt = build_receipt(ENV)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("receipt.json", json.dumps(receipt, sort_keys=True))
        run = {"id": 777, "run_attempt": 3, "event": "merge_group", "head_sha": SHA, "path": ".github/workflows/pr.yml",
               "repository": {"full_name": REPO}, "status": "completed", "conclusion": "success"}
        jobs = {"total_count": 1, "jobs": [{"id": 9, "name": "verify", "status": "completed", "conclusion": "success", "steps": []}]}

        def get(path, raw=False):
            if "/jobs?" in path:
                return jobs if path.endswith("page=1") else {"total_count": 1, "jobs": []}
            if "/artifacts?" in path:
                return {"artifacts": [{"name": "ci-full-run-receipt-a3", "expired": False, "archive_download_url": "https://b/z"}]}
            if raw:
                return buf.getvalue()
            raise AssertionError(path)

        self.assertIsNone(reader.evaluate(get, run, repo=REPO, sha=SHA, path=".github/workflows/pr.yml",
                                          verdict_job="verify", void_steps=[], ignore_jobs=[], required={"verify"}))


if __name__ == "__main__":
    unittest.main()
