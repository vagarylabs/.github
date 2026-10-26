"""Planner 1.4 source answer (SCION SRC-03; P2-06/P7-13 P3 vectors). Real Git objects, no network, no credentials.

Every incomplete input must yield exactly the FULL plan's obligations, and a complete control must still narrow.
The provider witness is exercised through an injected transport; the planted token and body never leak.
Set SOURCE_CONTEXT_SCHEMA to a local copy of vagary-core contracts/source/v1/source-context.schema.json (pinned in
plan.SOURCE_CONTRACT) to also validate the emitted envelope against the real SRC-01 schema; the schema lives in a
private repository and is not copied here.
"""
import contextlib
import hashlib
import http.server
import threading
import time
import io
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import edges as E
import plan as P

TOKEN = "example-token-not-real.example.invalid"
PLANTED = "PLANTED-PROVIDER-BODY-MARKER"


class SourceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "candidate"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "uploadpack.allowfilter", "true")
        self.cfg = {"schema": 1, "workspace": {"type": "declared", "packages": {
            "server": {"dir": "server", "deps": []}, "ui": {"dir": "ui", "deps": []}}},
            "hub_packages": ["server"], "inert_globs": ["docs/**"],
            "jobs": {"server_tests": "full_only", "ui_tests": {"packages": ["ui"]}},
            "matrices": {"suite": [{"include": {"group": "ui"}, "rule": {"packages": ["ui"]}},
                                   {"include": {"group": "server"}, "rule": "full_only"}]}}
        for directory in ("server", "ui", "docs", ".github/workflows"):
            (self.root / directory).mkdir(parents=True)
        files = {"server/a.py": "before\n", "ui/a.ts": "before\n", "docs/readme.md": "before\n",
                 "ui/package.json": '{"name": "ui"}\n', ".github/workflows/ci.yml": "name: ci\n"}
        for name, text in files.items():
            (self.root / name).write_text(text)
        self.commit_base(self.cfg)
        self.make_candidate("ui/a.ts", "ui change\n")

    def git(self, *args, cwd=None, input=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(["git", *args], cwd=cwd or self.root, env=env,
                                       input=input, stderr=subprocess.PIPE).decode().strip()

    def commit_base(self, cfg, parent=None):
        if parent:
            self.git("reset", "-q", "--hard", parent)
        (self.root / ".github/ci-plan.json").write_text(json.dumps(cfg))
        self.git("add", "-A")
        self.base = self.git("commit-tree", self.git("write-tree"), *(["-p", parent] if parent else []), input=b"base\n")

    def make_candidate(self, path, text):
        self.git("reset", "-q", "--hard", self.base)
        (self.root / path).write_text(text)
        self.git("add", "--", path)
        tree = self.git("write-tree")
        self.head = self.git("commit-tree", tree, "-p", self.base, input=b"head\n")
        self.candidate = self.git("commit-tree", tree, "-p", self.base, "-p", self.head, input=b"merge\n")
        self.git("reset", "-q", "--hard", self.candidate)

    def policy(self, revision=None, change=None):
        number = getattr(self, "number", 0) + 1
        self.number = number
        policy = Path(self.temp.name) / f"policy-{number}"
        self.git("clone", "--quiet", "--no-checkout", "--no-hardlinks", str(self.root), str(policy))
        self.git("-C", str(policy), "reset", "--quiet", "--hard", revision or self.base)
        if change:
            change(policy)
        return policy

    def run_cli(self, *, readers=True, ids=True, policy_change=None, policy_revision=None, reader_change=None,
                extra=(), scope_root=None, transport=None, token=TOKEN):
        policy = self.policy(policy_revision, policy_change)
        output = Path(self.temp.name) / f"plan-{self.number}.json"
        args = ["--config", ".github/ci-plan.json", "--root", str(policy), "--scope-root", str(scope_root or self.root),
                "--repository", "fixture/repo", "--event", "pull_request", "--base", self.base, "--head", self.head,
                "--candidate", self.candidate, "--out-json", str(output), *extra]
        if ids:
            args += ["--repository-id", "101", "--repository-owner-id", "202"]
        if readers and (policy / ".github/ci-plan.json").is_file():
            assessment = Path(self.temp.name) / f"readers-{self.number}.json"
            with contextlib.redirect_stdout(io.StringIO()):
                E.main(["check", "--config", str(policy / ".github/ci-plan.json"), "--repo", str(self.root),
                        "--manifest-root", str(policy), "--revision", self.candidate, "--out-json", str(assessment)])
            if reader_change:
                record = json.loads(assessment.read_text())
                reader_change(record)
                record["assessment_sha256"] = P.canonical_digest({k: v for k, v in record.items() if k != "assessment_sha256"})
                assessment.write_text(json.dumps(record))
            args += ["--reader-assessment", str(assessment)]
        env = {"GH_TOKEN": token} if token is not None else {}
        with patch.dict(os.environ, env), patch.object(P, "https_transport", transport or self.no_network), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(args), 0)
        return json.loads(output.read_text())

    @staticmethod
    def no_network(*args, **kwargs):
        raise AssertionError("the provider must not be called unless the witness is requested")

    def full_obligations(self, paths):
        policy = self.policy()
        cfg = json.loads((policy / ".github/ci-plan.json").read_text())
        rec = P.plan(cfg=cfg, root=policy, config_path=policy / ".github/ci-plan.json", paths=paths,
                     event="pull_request", base=self.base, head=self.head, expected_count=None,
                     forced_full_reason="control: complete caller roster")
        return self.obligations(rec)

    @staticmethod
    def obligations(rec):
        jobs = sorted(name for name, job in rec["jobs"].items() if job["run"])
        matrices = sorted(json.dumps([name, entry], sort_keys=True)
                          for name, matrix in rec["matrices"].items() for entry in matrix["include"])
        return jobs, matrices

    def compare_body(self, files=None, commits=None, **changes):
        commits = commits if commits is not None else [{"sha": self.head}, {"sha": self.candidate}]
        body = {"base_commit": {"sha": self.base}, "merge_base_commit": {"sha": self.base}, "status": "ahead",
                "ahead_by": len(commits), "behind_by": 0, "total_commits": len(commits), "commits": commits,
                "files": files if files is not None else [{"filename": "ui/a.ts", "status": "modified",
                                                           "patch": PLANTED}]}
        body.update(changes)
        return body

    def transport(self, body=None, status=200, headers=None, raw=None, calls=None):
        def send(url, headers_sent, timeout, max_bytes):
            if calls is not None:
                calls.append((url, headers_sent, timeout, max_bytes))
            payload = raw if raw is not None else json.dumps(body if body is not None else self.compare_body()).encode()
            return status, dict(headers or {}), payload
        return send


class SourceAnswerVectors(SourceFixture):
    def test_complete_control_narrows_and_emits_the_envelope_without_authorization(self):
        rec = self.run_cli()
        self.assertEqual(rec["mode"], "reduced", rec["reason"])
        (jobs, matrices), (all_jobs, all_matrices) = self.obligations(rec), self.full_obligations(["ui/a.ts"])
        self.assertTrue(set(jobs) < set(all_jobs) and set(matrices) < set(all_matrices), "the control must narrow")
        meta, envelope = rec["source_answer_meta"], rec["source_answer"]
        self.assertEqual(meta["decision"], "IMPACT_INPUT")
        self.assertEqual(meta["reason_codes"], [])
        self.assertIsNone(meta["authorization"])
        self.assertIs(meta["selection_authority"], False)
        self.assertNotIn("authorization", envelope)
        self.assertEqual(envelope["analyzer"], {"id": "ci.change-impact-plan", "version": P.PLANNER_VERSION})
        self.assertEqual(P.PLANNER_VERSION, "1.5.0")
        self.assertEqual(envelope["revisions"], {"object_format": "sha1", "base_sha": self.base, "head_sha": self.candidate})
        self.assertEqual(envelope["repository"], {"provider": "github", "organization_id": "github-owner:202",
                                                  "repository_id": "101"})
        self.assertEqual(envelope["completeness"], {"status": "complete", "truncated": False, "index": "complete",
                                                    "build_metadata": "complete", "dependency_closure": "complete",
                                                    "missing_paths": []})
        self.assertEqual(envelope["representation"], {
            "rung": "required_history", "sparse": {"enabled": False, "paths": []}, "clone_filter": "none",
            "history_depth": 0, "materialized_paths": [".github/ci-plan.json", ".github/workflows/ci.yml", "ui/package.json"]})
        self.assertRegex(envelope["request_digest"], r"^[0-9a-f]{64}$")

    def test_p3_incomplete_inputs_force_exactly_the_full_obligations(self):
        def delete(path):
            return lambda policy: (policy / path).unlink()

        def add_manifest(policy):
            (policy / "server/package.json").write_text('{"name": "server"}\n')

        cases = {
            "truncated path list": (dict(extra=["--expected-count", "5"]), "incomplete_source"),
            "absent reader index": (dict(readers=False), "incomplete_index"),
            "unbound reader index": (dict(reader_change=lambda r: r.update(graph_sha256="0" * 64)), "incomplete_index"),
            "sparse policy missing a manifest": (dict(policy_change=delete("ui/package.json")), "incomplete_build_metadata"),
            "sparse policy missing a workflow": (dict(policy_change=delete(".github/workflows/ci.yml")), "incomplete_build_metadata"),
            "policy with an untracked manifest": (dict(policy_change=add_manifest), "incomplete_build_metadata"),
            "policy at the wrong revision": (dict(policy_revision="CANDIDATE"), "incomplete_build_metadata"),
            "missing provider identity": (dict(ids=False), "identity_unavailable"),
        }
        full = self.full_obligations(["ui/a.ts"])
        for name, (options, code) in cases.items():
            with self.subTest(name):
                if options.get("policy_revision") == "CANDIDATE":
                    options = dict(options, policy_revision=self.candidate)
                rec = self.run_cli(**options)
                self.assertEqual(rec["mode"], "full", rec["reason"])
                self.assertEqual(self.obligations(rec), full)
                self.assertEqual(rec["source_answer_meta"]["decision"], "FULL")
                self.assertIn(code, rec["source_answer_meta"]["reason_codes"])
                self.assertNotEqual(rec["source_answer_meta"]["completeness"]["status"], "complete")
        truncated = self.run_cli(extra=["--expected-count", "5"])["source_answer"]["completeness"]
        self.assertEqual((truncated["status"], truncated["truncated"]), ("partial", True))
        self.assertEqual(self.run_cli(readers=False)["source_answer"]["completeness"]["index"], "absent")
        self.assertIsNone(self.run_cli(ids=False)["source_answer"])

    def test_analyzer_mismatch_in_base_policy_forces_full(self):
        self.commit_base(dict(self.cfg, analyzer={"id": "ci.change-impact-plan", "version": "1.3.0"}), parent=self.base)
        self.make_candidate("ui/a.ts", "ui change\n")
        rec = self.run_cli()
        self.assertEqual(rec["mode"], "full")
        self.assertEqual(self.obligations(rec), self.full_obligations(["ui/a.ts"]))
        self.assertIn("analyzer_mismatch", rec["source_answer_meta"]["reason_codes"])
        self.assertEqual(rec["source_answer"]["completeness"]["status"], "unknown")
        self.commit_base(dict(self.cfg, analyzer=dict(P.ANALYZER)), parent=self.base)
        self.make_candidate("ui/a.ts", "ui change\n")
        self.assertEqual(self.run_cli()["mode"], "reduced", "a matching analyzer pin is the positive control")

    def test_source_answer_is_bound_into_plan_id_and_deterministic(self):
        first, second = self.run_cli(), self.run_cli()
        self.assertEqual(first["plan_id"], second["plan_id"])
        for key, value in (("source_answer", None), ("source_answer_meta", {"decision": "FULL"})):
            altered = json.loads(json.dumps(first))
            altered[key] = value
            P.bind_plan_id(altered)
            self.assertNotEqual(altered["plan_id"], first["plan_id"])


class Representation(SourceFixture):
    def clone(self, *options):
        number = getattr(self, "clones", 0) + 1
        self.clones = number
        target = Path(self.temp.name) / f"clone-{number}"
        self.git("clone", "--quiet", *options, "file://" + str(self.root), str(target), cwd=self.temp.name)
        return target

    def test_blob_none_and_shallow_depth_are_recorded_independently(self):
        self.assertEqual(P.observe_representation(self.root), {
            "rung": "required_history", "sparse": {"enabled": False, "paths": []}, "clone_filter": "none", "history_depth": 0})
        blobless = self.clone("--filter=blob:none")
        self.assertEqual(P.observe_representation(blobless)["clone_filter"], "blob:none")
        self.assertEqual(P.observe_representation(blobless)["history_depth"], 0)
        shallow = self.clone("--depth", "2")
        self.assertEqual(P.observe_representation(shallow)["history_depth"], 2)
        self.assertEqual(P.observe_representation(shallow)["clone_filter"], "none")
        both = self.clone("--depth", "1", "--filter=blob:none")
        self.assertEqual((P.observe_representation(both)["history_depth"], P.observe_representation(both)["clone_filter"]),
                         (1, "blob:none"))

    def test_blob_none_candidate_is_recorded_in_the_plan_and_still_narrows(self):
        blobless = self.clone("--filter=blob:none")
        rec = self.run_cli(scope_root=blobless)
        self.assertEqual(rec["source_answer"]["representation"]["clone_filter"], "blob:none")
        self.assertEqual(rec["mode"], "reduced", rec["reason"])

    def test_sparse_patterns_are_recorded_and_unrepresentable_ones_are_unobserved(self):
        sparse = self.clone()
        self.git("sparse-checkout", "set", "--no-cone", "/ui/", cwd=sparse)
        observed = P.observe_representation(sparse)
        self.assertEqual(observed["sparse"], {"enabled": True, "paths": ["ui"]})
        self.assertEqual(observed["clone_filter"], "none", "sparse is not partial clone")
        self.git("sparse-checkout", "set", "--no-cone", "/ui/", "!/ui/a.ts", cwd=sparse)
        self.assertIsNone(P.observe_representation(sparse))

    def test_unobservable_representation_forces_full(self):
        with patch.object(P, "observe_representation", return_value=None):
            rec = self.run_cli()
        self.assertEqual(rec["mode"], "full")
        self.assertIn("representation_unobserved", rec["source_answer_meta"]["reason_codes"])
        self.assertIsNone(rec["source_answer"])


class ProviderWitness(SourceFixture):
    WITNESS = ["--source-query", "witness"]

    def witness(self, **transport_options):
        calls = []
        rec = self.run_cli(extra=self.WITNESS, transport=self.transport(calls=calls, **transport_options))
        text = json.dumps(rec)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(PLANTED, text)
        return rec, calls

    def test_agreeing_complete_answer_changes_nothing(self):
        rec, calls = self.witness()
        self.assertEqual(rec["mode"], "reduced", rec["reason"])
        self.assertEqual(rec["source_answer_meta"]["provider_witness"]["status"], "complete")
        self.assertEqual(len(calls), 1)
        url, headers, timeout, max_bytes = calls[0]
        self.assertEqual(url, f"https://api.github.com/repos/fixture/repo/compare/{self.base}...{self.candidate}?per_page=100")
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        self.assertEqual((timeout, max_bytes), (P.PROVIDER_TIMEOUT_SECONDS, P.PROVIDER_MAX_BYTES))
        self.assertEqual(self.run_cli()["source_answer_meta"]["provider_witness"], None, "off by default; no call")

    def test_incomplete_or_disagreeing_answers_force_exactly_full(self):
        many = [{"filename": f"ui/f{i}.ts", "status": "modified"} for i in range(P.PROVIDER_FILE_CEILING)]
        commits = [{"sha": "1" * 40}] * P.PROVIDER_COMMIT_BOUND + [{"sha": None}]
        cases = {
            "extra path": (dict(body=self.compare_body(files=[{"filename": "ui/a.ts", "status": "modified"},
                                                               {"filename": "server/a.py", "status": "modified"}])), "provider_mismatch"),
            "missing path": (dict(body=self.compare_body(files=[])), "provider_mismatch"),
            "file ceiling": (dict(body=self.compare_body(files=many)), "provider_file_ceiling"),
            "commit bound": (dict(body=self.compare_body(commits=commits)), "provider_commit_bound"),
            "pagination": (dict(headers={"Link": '<https://api.github.com/x?page=2>; rel="next"'}), "provider_paginated"),
            "throttled 429": (dict(status=429, raw=PLANTED.encode()), "provider_throttled"),
            "secondary limit 403": (dict(status=403, headers={"X-RateLimit-Remaining": "0"}), "provider_throttled"),
            "server error": (dict(status=502, raw=PLANTED.encode()), "provider_unavailable"),
            "malformed json": (dict(raw=b"{" + PLANTED.encode()), "provider_malformed"),
            "base mismatch": (dict(body=self.compare_body(base_commit={"sha": self.head})), "provider_mismatch"),
            "merge base moved": (dict(body=self.compare_body(merge_base_commit={"sha": self.head})), "provider_mismatch"),
            "head mismatch": (dict(body=self.compare_body(commits=[{"sha": self.candidate}, {"sha": self.head}])), "provider_mismatch"),
            "rename without origin": (dict(body=self.compare_body(files=[{"filename": "ui/a.ts", "status": "renamed"}])), "provider_malformed"),
            "unsafe path": (dict(body=self.compare_body(files=[{"filename": "../ui/a.ts", "status": "modified"}])), "provider_malformed"),
        }
        full = self.full_obligations(["ui/a.ts"])
        for name, (options, code) in cases.items():
            with self.subTest(name):
                rec, _ = self.witness(**options)
                self.assertEqual(rec["mode"], "full", rec["reason"])
                self.assertEqual(self.obligations(rec), full)
                self.assertIn(code, rec["source_answer_meta"]["reason_codes"])
                self.assertEqual(rec["source_answer_meta"]["decision"], "FULL")

    def test_response_cap_transport_failure_and_missing_token_are_not_answers(self):
        with patch.object(P, "PROVIDER_MAX_BYTES", 64):
            rec, _ = self.witness()
        self.assertIn("provider_response_cap", rec["source_answer_meta"]["reason_codes"])
        self.assertTrue(rec["source_answer"]["completeness"]["truncated"])

        def broken(*args):
            raise OSError("connection reset " + TOKEN)
        rec = self.run_cli(extra=self.WITNESS, transport=broken)
        self.assertEqual(rec["mode"], "full")
        self.assertIn("provider_unavailable", rec["source_answer_meta"]["reason_codes"])
        self.assertNotIn(TOKEN, json.dumps(rec))
        rec = self.run_cli(extra=self.WITNESS, transport=self.transport(), token="")
        self.assertIn("provider_token_unavailable", rec["source_answer_meta"]["reason_codes"])
        self.assertEqual(rec["mode"], "full")

    def test_nonstring_file_status_is_malformed_and_preserves_full_obligations(self):
        full = self.full_obligations(["ui/a.ts"])
        for status in ([], {}, ["modified"], None, True, 1):
            with self.subTest(status=status):
                rec, _ = self.witness(body=self.compare_body(files=[{"filename": "ui/a.ts", "status": status}]))
                self.assertEqual(rec["mode"], "full")
                self.assertEqual(self.obligations(rec), full)
                self.assertIn("provider_malformed", rec["source_answer_meta"]["reason_codes"])

    def test_renamed_paths_include_the_origin_like_a_no_renames_diff(self):
        result = P.provider_compare("fixture/repo", self.base, self.candidate, token=TOKEN, api_url="https://api.github.com",
                                    transport=self.transport(body=self.compare_body(files=[
                                        {"filename": "ui/b.ts", "previous_filename": "ui/a.ts", "status": "renamed"}])))
        self.assertEqual((result["status"], result["paths"]), ("complete", ["ui/a.ts", "ui/b.ts"]))
        for bad in ("http://api.github.com", "https://api.github.com/evil?x=", "https://user@api.github.com"):
            self.assertEqual(P.provider_compare("fixture/repo", self.base, self.candidate, token=TOKEN, api_url=bad,
                                                transport=self.no_network)["reason"], "provider_request_invalid")
        self.assertEqual(P.provider_compare("fixture/repo", "main", self.candidate, token=TOKEN,
                                            api_url="https://api.github.com", transport=self.no_network)["reason"],
                         "provider_request_invalid")

    def test_seeded_cap_fuzz_never_yields_a_smaller_answer(self):
        rng = random.Random(20261015)
        for iteration in range(400):
            files = rng.randint(P.PROVIDER_FILE_CEILING - 4, P.PROVIDER_FILE_CEILING + 3)
            commits = rng.randint(P.PROVIDER_COMMIT_BOUND - 3, P.PROVIDER_COMMIT_BOUND + 3)
            paged = rng.random() < 0.2
            rows = [{"filename": f"ui/f{i}.ts", "status": "modified"} for i in range(files)]
            history = [{"sha": "%040x" % (i + 1)} for i in range(commits - 1)] + [{"sha": self.candidate}]
            body = self.compare_body(files=rows, commits=history)
            result = P.provider_compare("fixture/repo", self.base, self.candidate, token=TOKEN,
                                        api_url="https://api.github.com",
                                        transport=self.transport(body=body, headers={"Link": "x"} if paged else None))
            within = files < P.PROVIDER_FILE_CEILING and commits <= P.PROVIDER_COMMIT_BOUND and not paged
            with self.subTest(iteration=iteration, files=files, commits=commits, paged=paged):
                if within:
                    self.assertEqual(result["status"], "complete")
                    self.assertEqual(len(result["paths"]), files)
                else:
                    self.assertEqual(result["status"], "partial")
                    self.assertIsNone(result["paths"])
        # A sample through the whole planner: any non-complete witness gives the FULL obligations.
        full = self.full_obligations(["ui/a.ts"])
        for files in (P.PROVIDER_FILE_CEILING - 1, P.PROVIDER_FILE_CEILING, P.PROVIDER_FILE_CEILING + 1):
            rows = [{"filename": "ui/a.ts", "status": "modified"}] + [
                {"filename": f"ui/x{i}.ts", "status": "added"} for i in range(files - 1)]
            rec, _ = self.witness(body=self.compare_body(files=rows))
            self.assertEqual(rec["mode"], "full")
            self.assertEqual(self.obligations(rec), full)
            expected = "provider_mismatch" if files < P.PROVIDER_FILE_CEILING else "provider_file_ceiling"
            self.assertIn(expected, rec["source_answer_meta"]["reason_codes"])


class RealTransport(unittest.TestCase):
    """The stdlib transport itself, against a localhost server: no redirect, byte cap, whole-request deadline."""

    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def handler(self, status, body=b"", headers=None, drip=0.0):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for index in range(0, len(body), 1 if drip else len(body) or 1):
                        self.wfile.write(body[index:index + (1 if drip else len(body))])
                        self.wfile.flush()
                        if drip:
                            time.sleep(drip)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass
        return Handler

    def test_redirect_is_not_followed(self):
        target = self.serve(self.handler(200, b"followed " + PLANTED.encode()))
        base = self.serve(self.handler(302, b"", {"Location": target + "/elsewhere"}))
        status, _, body = P.https_transport(base + "/compare", {}, 5, 1024)
        self.assertEqual((status, body), (302, b""))

    def test_body_over_the_cap_returns_exactly_cap_plus_one(self):
        url = self.serve(self.handler(200, b"x" * 5000))
        status, _, body = P.https_transport(url + "/compare", {}, 5, 1000)
        self.assertEqual((status, len(body)), (200, 1001))
        status, _, body = P.https_transport(url + "/compare", {}, 5, 10000)
        self.assertEqual(len(body), 5000)

    def test_throttle_status_and_headers_come_back_without_a_body(self):
        url = self.serve(self.handler(429, PLANTED.encode(), {"Retry-After": "60"}))
        status, headers, body = P.https_transport(url + "/compare", {}, 5, 1024)
        self.assertEqual((status, headers.get("retry-after"), body), (429, "60", b""))

    def test_slow_drip_exceeds_the_whole_request_deadline(self):
        url = self.serve(self.handler(200, b"0123456789", drip=0.15))
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            P.https_transport(url + "/compare", {}, 0.5, 1024)
        self.assertLess(time.monotonic() - started, 1.2)
        result = P.provider_compare("fixture/repo", "a" * 40, "b" * 40, token=TOKEN, api_url="https://api.github.com",
                                    transport=lambda *args: P.https_transport(url + "/compare", {}, 0.5, 1024))
        self.assertEqual((result["status"], result["reason"]), ("unknown", "provider_deadline"))

    def test_trickled_status_line_and_headers_exceed_the_whole_request_deadline(self):
        """Each header line arrives inside the per-read timeout, but the whole answer arrives after the deadline:
        it must be refused, never accepted as a complete (if tiny) body."""
        def trickle(pause):
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    lines = [b"HTTP/1.0 200 OK\r\n"] + [b"X-Pad-%d: 1\r\n" % i for i in range(6)] \
                        + [b"Content-Length: 2\r\n\r\n{}"]
                    try:
                        for line in lines:
                            self.wfile.write(line)
                            self.wfile.flush()
                            time.sleep(pause)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

                def log_message(self, *args):
                    pass
            return Handler
        self.assertEqual(P.https_transport(self.serve(trickle(0.01)) + "/compare", {}, 0.5, 1024)[::2], (200, b"{}"),
                         "positive control: the same answer inside the deadline is read")
        url = self.serve(trickle(0.15))
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            P.https_transport(url + "/compare", {}, 0.5, 1024)
        self.assertLess(time.monotonic() - started, 2.0)

    def tracked_worker(self, injected_code=None):
        real, workers = subprocess.Popen, []
        def create(argv, **kwargs):
            self.assertNotIn(TOKEN, repr(argv))
            self.assertNotIn("GH_TOKEN", kwargs["env"])
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            if injected_code:
                code = ("import importlib.util,sys,socket,ssl,time; "
                        f"spec=importlib.util.spec_from_file_location('worker',{str(Path(P.__file__).resolve())!r}); "
                        "p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p); "
                        + injected_code + "; sys.exit(p._provider_http_worker())")
                argv = [sys.executable, "-I", "-c", code]
            worker = real(argv, **kwargs)
            workers.append(worker)
            return worker
        return create, workers

    def test_deadline_cancels_and_reaps_dns_connect_and_tls_workers(self):
        url = self.serve(self.handler(200, b"{}"))
        phases = {
            "DNS": "socket.getaddrinfo=lambda *a,**k: time.sleep(5)",
            "connect": "socket.create_connection=lambda *a,**k: time.sleep(5)",
            "TLS": "ssl.SSLContext.wrap_socket=lambda *a,**k: time.sleep(5)",
        }
        for phase, code in phases.items():
            with self.subTest(phase=phase):
                create, workers = self.tracked_worker(code)
                with patch.dict(os.environ, {"GH_TOKEN": TOKEN, "GITHUB_TOKEN": TOKEN}), patch.object(P.subprocess, "Popen", create):
                    with self.assertRaises(TimeoutError):
                        P.https_transport(url.replace("http:", "https:") if phase == "TLS" else url,
                                          {"Authorization": "Bearer " + TOKEN}, 0.3, 1024)
                self.assertEqual(len(workers), 1)
                self.assertLess(workers[0].returncode, 0, "deadline must kill, not leave request work alive")
                self.assertIsNotNone(workers[0].poll())
                self.assertTrue(workers[0].stdin.closed and workers[0].stdout.closed)

    def test_status_and_headers_cannot_extend_absolute_deadline(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    # Each byte arrives before the socket inactivity timer, but the status is incomplete.
                    for byte in b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}":
                        self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(0.03)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        url = self.serve(Handler)
        create, workers = self.tracked_worker()
        with patch.object(P.subprocess, "Popen", create), self.assertRaises(TimeoutError):
            P.https_transport(url, {}, 0.1, 1024)
        self.assertEqual(len(workers), 1)
        self.assertLess(workers[0].returncode, 0)

    def test_worker_failure_does_not_reflect_credentials_or_provider_error(self):
        create, workers = self.tracked_worker("socket.getaddrinfo=lambda *a,**k: (_ for _ in ()).throw(OSError('" + TOKEN + "'))")
        with patch.object(P.subprocess, "Popen", create), self.assertRaises(ValueError) as caught:
            P.https_transport("http://127.0.0.1:1", {"Authorization": "Bearer " + TOKEN}, 5, 1024)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertEqual(workers[0].returncode, 2)

    def test_supervisor_bounds_child_output_and_reaps_on_interruption(self):
        real, workers = subprocess.Popen, []
        def oversized(argv, **kwargs):
            proc = real([sys.executable, "-I", "-c", "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*200000)"], **kwargs)
            workers.append(proc)
            return proc
        with patch.object(P.subprocess, "Popen", oversized), self.assertRaises(ValueError):
            P.https_transport("http://127.0.0.1:1", {}, 5, 10)
        self.assertIsNotNone(workers[0].poll())
        self.assertTrue(workers[0].stdin.closed and workers[0].stdout.closed)

    def test_interruption_kills_and_reaps_the_owned_worker(self):
        create, workers = self.tracked_worker("socket.create_connection=lambda *a,**k: time.sleep(5)")
        with patch.object(P.subprocess, "Popen", create), \
                patch.object(P.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            P.https_transport("http://127.0.0.1:1", {}, 5, 1024)
        self.assertEqual(len(workers), 1)
        self.assertIsNotNone(workers[0].poll())
        self.assertTrue(workers[0].stdin.closed and workers[0].stdout.closed)

    def test_selector_constructor_failure_starts_no_worker(self):
        with patch.object(P.selectors, "DefaultSelector", side_effect=OSError("fixture selector failure")), \
                patch.object(P.subprocess, "Popen", side_effect=AssertionError("worker must not start")), \
                self.assertRaises(OSError):
            P.https_transport("http://127.0.0.1:1", {}, 5, 1024)

    def test_spawn_failure_closes_preallocated_selector(self):
        selector = P.selectors.DefaultSelector()
        with patch.object(P.selectors, "DefaultSelector", return_value=selector), \
                patch.object(P.subprocess, "Popen", side_effect=OSError("fixture spawn failure")), \
                self.assertRaises(OSError):
            P.https_transport("http://127.0.0.1:1", {}, 5, 1024)
        self.assertFalse(selector.get_map())

    def test_postspawn_registration_failure_reaps_real_worker(self):
        create, workers = self.tracked_worker()
        with patch.object(P.subprocess, "Popen", create), \
                patch.object(P.selectors.DefaultSelector, "register", side_effect=OSError("fixture register failure")), \
                self.assertRaises(OSError):
            P.https_transport("http://127.0.0.1:1", {}, 5, 1024)
        self.assertEqual(len(workers), 1)
        self.assertIsNotNone(workers[0].poll())
        self.assertTrue(workers[0].stdin.closed and workers[0].stdout.closed)

    def test_invalid_request_bounds_do_not_start_worker(self):
        for timeout, limit in [(0, 1), (float('nan'), 1), (True, 1), (16, 1), (1, -1), (1, P.PROVIDER_MAX_BYTES + 1)]:
            with patch.object(P.subprocess, "Popen", side_effect=AssertionError("worker started")), self.assertRaises(ValueError):
                P.https_transport("http://127.0.0.1:1", {}, timeout, limit)
        with patch.object(P.subprocess, "Popen", side_effect=AssertionError("worker started")), self.assertRaises(ValueError):
            P.https_transport("http://127.0.0.1:1", {"Authorization": "x" * 70000}, 1, 1)



class ContractShape(SourceFixture):
    """Field names and enums SRC-01 defines; the full schema check runs when a local copy is supplied."""
    REQUIRED = {"schema_version", "repository", "revisions", "request_digest", "analyzer", "representation", "completeness"}

    def test_pin_and_envelope_shape(self):
        self.assertEqual(P.SOURCE_CONTRACT["omitted"], ["authorization"])
        self.assertRegex(P.SOURCE_CONTRACT["revision"], r"^[0-9a-f]{40}$")
        self.assertRegex(P.SOURCE_CONTRACT["sha256"], r"^[0-9a-f]{64}$")
        envelope = self.run_cli()["source_answer"]
        self.assertEqual(set(envelope), self.REQUIRED)
        self.assertEqual(set(envelope["completeness"]), {"status", "truncated", "index", "build_metadata",
                                                         "dependency_closure", "missing_paths"})
        self.assertEqual(set(envelope["representation"]), {"rung", "sparse", "clone_filter", "history_depth",
                                                           "materialized_paths"})
        self.assertIn(envelope["representation"]["clone_filter"], ("none", "blob:none", "blob:limit", "not_applicable"))

    def test_envelope_validates_against_the_pinned_src01_schema_when_supplied(self):
        location = os.environ.get("SOURCE_CONTEXT_SCHEMA")
        if not location:
            self.skipTest("SOURCE_CONTEXT_SCHEMA not set (the SRC-01 schema is private to vagary-core)")
        raw = Path(location).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), P.SOURCE_CONTRACT["sha256"], "not the pinned SRC-01 bytes")
        schema = json.loads(raw)
        for options in ({}, {"extra": ["--expected-count", "5"]}, {"readers": False},
                        {"policy_change": lambda policy: (policy / "ui/package.json").unlink()}):
            with self.subTest(options=sorted(options)):
                envelope = self.run_cli(**options)["source_answer"]
                errors = validate(schema, envelope, schema)
                # The only refusal of the producer envelope is the authorization the planner must never fill.
                self.assertEqual(errors, ["$: missing required authorization"])
        # Positive control: the subset validator does refuse a malformed envelope.
        broken = json.loads(json.dumps(envelope))
        broken["representation"]["clone_filter"] = "tree:0"
        broken["revisions"]["head_sha"] = "main"
        broken["completeness"].update(truncated=True, status="complete")
        self.assertTrue({"$.representation.clone_filter: enum", "$.revisions.head_sha: pattern",
                         "$.completeness.status: const"} <= set(validate(schema, broken, schema)))

    def test_action_wires_provider_identity_and_keeps_the_witness_off_by_default(self):
        action = Path(P.__file__).with_name("action.yml").read_text()
        for text in ("REPOSITORY_ID: ${{ github.repository_id }}", "REPOSITORY_OWNER_ID: ${{ github.repository_owner_id }}",
                     '--repository-id "$REPOSITORY_ID" --repository-owner-id "$REPOSITORY_OWNER_ID"',
                     '--source-query "$SOURCE_QUERY"', "SOURCE_QUERY: ${{ inputs.source-query }}"):
            self.assertIn(text, action)
        source_query = action.split("  source-query:\n", 1)[1].split("\noutputs:", 1)[0]
        self.assertIn('default: "off"', source_query)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            P.main(["--config", "x", "--root", str(self.root), "--event", "pull_request", "--source-query", "on"])


def validate(node, value, root, where="$"):
    """The JSON Schema subset SRC-01 uses (2020-12): enough to check the producer envelope without a dependency."""
    if "$ref" in node:
        target = root
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        return validate(target, value, root, where)
    errors = []
    kinds = node.get("type")
    if kinds is not None:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        checks = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
                  "string": lambda v: isinstance(v, str), "boolean": lambda v: isinstance(v, bool),
                  "integer": lambda v: type(v) is int, "null": lambda v: v is None}
        if not any(checks[kind](value) for kind in kinds):
            return [f"{where}: type"]
    if "const" in node and value != node["const"]:
        errors.append(f"{where}: const")
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{where}: enum")
    if isinstance(value, str):
        if len(value) < node.get("minLength", 0) or len(value) > node.get("maxLength", len(value)):
            errors.append(f"{where}: length")
        if "pattern" in node and not re.search(node["pattern"], value):
            errors.append(f"{where}: pattern")
    if type(value) is int and "minimum" in node and value < node["minimum"]:
        errors.append(f"{where}: minimum")
    if isinstance(value, list):
        if len(value) > node.get("maxItems", len(value)):
            errors.append(f"{where}: maxItems")
        if node.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{where}: uniqueItems")
        for index, item in enumerate(value):
            if "items" in node:
                errors += validate(node["items"], item, root, f"{where}[{index}]")
    if isinstance(value, dict):
        for key in node.get("required", []):
            if key not in value:
                errors.append(f"{where}: missing required {key}")
        properties = node.get("properties", {})
        for key, item in value.items():
            if key in properties:
                errors += validate(properties[key], item, root, f"{where}.{key}")
            elif node.get("additionalProperties") is False:
                errors.append(f"{where}: unexpected {key}")
    for part in node.get("allOf", []):
        if "if" in part and not validate(part["if"], value, root, where):
            errors += validate(part.get("then", {}), value, root, where)
        elif "if" not in part:
            errors += validate(part, value, root, where)
    return errors


if __name__ == "__main__":
    unittest.main()
