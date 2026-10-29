#!/usr/bin/env python3
"""Tests for client.py against a fake GitHub OIDC / STS / IAM / broker / GitHub API. Stdlib only, no network, no real
credential: every value below is a fixture string.

Run: python3 -m unittest discover -s actions/broker-source-read -p 'test_*.py' -v
"""
from __future__ import annotations

import http.client
import importlib.util
import io
import json
import os
import pathlib
import re
import socketserver
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("broker_source_read_client", HERE / "client.py")
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

PROVIDER = "projects/121438167237/locations/global/workloadIdentityPools/github/providers/github-vagaris-source-read"
SA = "ci-src-vagaris@vl-build-prod.iam.gserviceaccount.com"
BROKER = "https://broker.example.run.app"
API = "https://api.github.example"
# The job's RUNNER_TEMP for every test: client.py writes and revokes token files only strictly inside it. A real
# directory, removed when the run ends; every test path sits under it unless the test is about leaving it.
_RUNNER_TEMP = tempfile.TemporaryDirectory(prefix="bsr-runner-temp-")
RT = _RUNNER_TEMP.name
CREDS = {"oidc": "fixture-oidc-value", "access": "fixture-access-value", "id": "fixture-id-value",
         "bearer": "fixture-request-bearer"}
ENV = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token?api-version=2.0",
       "ACTIONS_ID_TOKEN_REQUEST_TOKEN": CREDS["bearer"], "GITHUB_API_URL": API, "RUNNER_TEMP": RT}


def tmpdir():
    """A fresh directory inside RUNNER_TEMP."""
    return tempfile.TemporaryDirectory(dir=RT)


def install_token(repo: str) -> str:
    return "fixture-install-" + repo.replace("/", "-")


NULL = object()   # in Fake(echo=...): send the field as a JSON null (None deletes it)


class Fake:
    """Answers each leg and records every call.

    broker:  {repo: [status, ...]} answered in order before a 200.
    echo:    {repo: dict} fields that REPLACE the 200 body's defaults (None deletes the field; NULL sends a JSON null).
             The default 200 carries no `revocable` and no `cached`: an older broker, so every test that does not set
             them exercises the legacy per-purpose rule.
    ready:   {repo: [status, ...]} readiness answers before a 200.
    delete:  [status, ...] DELETE answers in order; then 204.
    """

    def __init__(self, broker=None, echo=None, ready=None, delete=None, sts=200, purpose_perms=None):
        self.calls, self.broker = [], {k: list(v) for k, v in (broker or {}).items()}
        self.echo, self.ready = echo or {}, {k: list(v) for k, v in (ready or {}).items()}
        self.delete, self.sts, self.purpose_perms = list(delete or []), sts, purpose_perms

    def __call__(self, method, url, headers, data=None, timeout=30):
        self.calls.append((method, url, dict(headers), data))
        if url.startswith("https://oidc.example/"):
            return 200, {"value": CREDS["oidc"]}
        if url == client.STS_URL:
            return (200, {"access_token": CREDS["access"]}) if self.sts == 200 else \
                (self.sts, {"error": "invalid_grant", "error_description": "condition not met"})
        if url.startswith("https://iamcredentials.googleapis.com/"):
            return 200, {"token": CREDS["id"]}
        if url == BROKER + "/v1/source/read":
            req = json.loads(data)
            repo, purpose = req["repository"], req["purpose"]
            queue = self.broker.get(repo) or []
            if queue:
                status = queue.pop(0)
                return status, {"schema": "source_read/v1",
                                "reason": "rate limited" if status == 429 else "repository not granted"}
            body = {"schema": "source_read/v1", "repository": repo, "token": install_token(repo),
                    "expires_at": "2027-01-01T00:00:00Z", "request_id": "req-1",
                    "permissions": dict(self.purpose_perms or client.PURPOSES[purpose]["permissions"])}
            for k, v in (self.echo.get(repo) or {}).items():
                if v is None:
                    body.pop(k, None)
                else:
                    body[k] = None if v is NULL else v
            return 200, body
        if method == "GET" and url.startswith(API + "/repos/"):
            repo = url[len(API + "/repos/"):]
            queue = self.ready.get(repo) or []
            return (queue.pop(0) if queue else 200), {}
        if method == "DELETE" and url == API + "/installation/token":
            return (self.delete.pop(0) if self.delete else 204), {}
        raise AssertionError(f"unexpected call {method} {url}")

    def deletes(self):
        return [c[2]["Authorization"] for c in self.calls if c[0] == "DELETE"]

    def broker_calls(self):
        return [json.loads(c[3]) for c in self.calls if c[1] == BROKER + "/v1/source/read"]


class Clock:
    def __init__(self):
        self.t, self.sleeps = 0.0, []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def mint_args(purpose="build_checkout", repos="vagarylabs/vagary-core", **kw):
    argv = ["mint", "--purpose", purpose, "--repositories", repos, "--provider", kw.pop("provider", PROVIDER),
            "--service-account", kw.pop("sa", SA), "--audience", kw.pop("audience", BROKER)]
    for k, v in kw.items():
        argv += ["--" + k.replace("_", "-"), str(v)]
    return argv


def run(argv, fake, env=None):
    """(rc, stdout, stderr, clock) for one main() call with the fake and a fake clock."""
    out, err, clock = io.StringIO(), io.StringIO(), Clock()
    saved, sys.stderr = sys.stderr, err
    try:
        rc = client.main(argv, dict(ENV if env is None else env), fake, clock.sleep, clock, out=out)
    finally:
        sys.stderr = saved
    return rc, out.getvalue(), err.getvalue(), clock


def leaked(text: str, secrets) -> list[str]:
    """Every secret that appears in a printed line OTHER than its own ::add-mask:: registration."""
    lines = [l for l in text.splitlines() if not l.startswith("::add-mask::")]
    return sorted({s for s in secrets for l in lines if s in l})


ALL_SECRETS = [*CREDS.values(), *(install_token(r) for r in
                                  ("vagarylabs/vagary-core", "vagarylabs/a", "vagarylabs/b", "vagarylabs/c"))]


class ChainTests(unittest.TestCase):
    def test_chain_audiences_and_exact_broker_request(self):
        with tmpdir() as td:
            fake = Fake()
            rc, out, err, clock = run(mint_args(token_file=f"{td}/t"), fake)
            self.assertEqual(rc, 0, err)
            oidc_q = urllib.parse.parse_qs(urllib.parse.urlsplit(fake.calls[0][1]).query)
            self.assertEqual(oidc_q["audience"], ["https://iam.googleapis.com/" + PROVIDER])
            sts = urllib.parse.parse_qs(fake.calls[1][3].decode())
            self.assertEqual(sts["audience"], ["//iam.googleapis.com/" + PROVIDER])
            self.assertEqual(sts["subject_token"], [CREDS["oidc"]])
            self.assertIn(SA, fake.calls[2][1])
            self.assertEqual(json.loads(fake.calls[2][3]), {"audience": BROKER, "includeEmail": True})
            self.assertEqual(fake.broker_calls(), [{"repository": "vagarylabs/vagary-core", "purpose": "build_checkout"}])
            self.assertEqual(fake.calls[3][2]["Authorization"], f"Bearer {CREDS['id']}")
            self.assertEqual(clock.sleeps, [])
            self.assertEqual(pathlib.Path(f"{td}/t").read_text(), install_token("vagarylabs/vagary-core"))

    def test_provider_forms_derive_the_same_audiences(self):
        for form in (PROVIDER, "//iam.googleapis.com/" + PROVIDER):
            self.assertEqual(client.provider_resource(form), PROVIDER)
        for bad in ("https://iam.googleapis.com/" + PROVIDER, PROVIDER + "/x", "projects/x/locations/global/"
                    "workloadIdentityPools/github/providers/p", ""):
            fake = Fake()
            rc, _, err, _ = run(mint_args(provider=bad, token_file=f"{RT}/nonexistent/t"), fake)
            self.assertEqual((rc, fake.calls), (2, []), bad)
            self.assertNotIn("RUNNER_TEMP", err, bad)

    def test_bad_inputs_refused_before_any_call(self):
        cases = [mint_args(sa="someone@gmail.com", token_file=f"{RT}/x/t"),
                 mint_args(audience="http://broker.example", token_file=f"{RT}/x/t"),
                 mint_args(audience=BROKER + "/v1/source/read", token_file=f"{RT}/x/t"),
                 mint_args(repos="vagary-core", token_file=f"{RT}/x/t"),
                 mint_args(repos="vagarylabs/a vagarylabs/A", token_dir=f"{RT}/x/d"),
                 mint_args(repos="vagarylabs/a vagarylabs/b", token_file=f"{RT}/x/t"),
                 mint_args(),                                            # no destination
                 mint_args(purpose="image_pull", github_output="token"),  # revocable needs a file
                 mint_args(purpose="image_pull", token_file=f"{RT}/x/t", github_output="token"),  # and no output
                 mint_args(token_file=f"{RT}/x/t", token_dir=f"{RT}/x/d"),
                 mint_args(token_file=f"{RT}/x/t", readiness_seconds=0)]
        for argv in cases:
            fake = Fake()
            rc, _, err, _ = run(argv, fake, env={**ENV, "GITHUB_OUTPUT": f"{RT}/x/o"})
            self.assertEqual((rc, fake.calls), (2, []), argv)
            self.assertNotIn("RUNNER_TEMP", err, argv)

    def test_missing_id_token_permission_is_named_before_any_call(self):
        fake = Fake()
        rc, _, err, _ = run(mint_args(token_file=f"{RT}/x/t"), fake, env={"GITHUB_API_URL": API, "RUNNER_TEMP": RT})
        self.assertEqual((rc, fake.calls), (1, []))
        self.assertIn("id-token: write", err)

    def test_sts_refusal_names_the_leg_and_is_not_retried(self):
        fake = Fake(sts=400)
        rc, _, err, clock = run(mint_args(token_file=f"{RT}/x/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("sts: HTTP 400", err)
        self.assertEqual(clock.sleeps, [])


class UnknownPurposeTests(unittest.TestCase):
    def test_unknown_purpose_refused_with_zero_calls(self):
        # The broker's own non-CI purposes are unknown here too: the table holds only what CI may ask for.
        for purpose in ("canon_sync", "agent_context", "self_converge", "deployment_reconcile", "contents_write", "",
                        "build_checkout "):
            for argv in (mint_args(purpose=purpose, token_file=f"{RT}/x/t"),
                         ["revoke", "--purpose", purpose, "--token-file", f"{RT}/x/t"]):
                fake = Fake()
                rc, _, err, _ = run(argv, fake)
                self.assertEqual((rc, fake.calls), (2, []), (purpose, argv[0]))
                self.assertIn("unknown purpose", err, (purpose, argv[0]))

    def test_table_mirrors_the_broker_exactly(self):
        # Literal copy of source_delivery_broker.py (origin/main 8d3c29dd) :196, :207-208, :211.
        self.assertEqual(client.PURPOSES, {
            "build_checkout": {"permissions": {"contents": "read", "metadata": "read"}, "revocable": False},
            "image_pull": {"permissions": {"packages": "read", "metadata": "read"}, "revocable": True},
            "repository_census": {"permissions": {"pull_requests": "read", "checks": "read", "metadata": "read"},
                                  "revocable": True}})
        self.assertNotIn("write", json.dumps(client.PURPOSES))


class EchoCheckTests(unittest.TestCase):
    """For EVERY purpose: the exact set passes; wider, narrower, missing, a raised level, a wrong repository or schema
    each revokes that token and fails, with nothing written."""

    def variants(self, purpose):
        want = client.PURPOSES[purpose]["permissions"]
        first = sorted(want)[0]
        extra = "contents" if "contents" not in want else "pull_requests"
        return {
            "wider": {"permissions": {**want, extra: "read"}},
            "narrower": {"permissions": {k: v for k, v in want.items() if k != first}},
            "missing": {"permissions": None},
            "raised level": {"permissions": {**want, first: "write"}},
            "malformed": {"permissions": ["metadata"]},
            "other repository": {"repository": "vagarylabs/other"},
            "schema": {"schema": "source_read/v2"},
        }

    def test_exact_set_passes_for_each_purpose(self):
        for purpose in client.PURPOSES:
            with tmpdir() as td:
                fake = Fake()
                rc, _, err, _ = run(mint_args(purpose=purpose, token_file=f"{td}/t"), fake)
                self.assertEqual(rc, 0, (purpose, err))
                self.assertEqual(fake.deletes(), [], purpose)

    def test_every_mismatch_revokes_and_fails(self):
        repo = "vagarylabs/vagary-core"
        for purpose in client.PURPOSES:
            for name, change in self.variants(purpose).items():
                with tmpdir() as td:
                    fake = Fake(echo={repo: change})
                    out_file = pathlib.Path(td) / "gh-out"
                    out_file.write_text("")
                    rc, out, err, _ = run(mint_args(purpose=purpose, token_file=f"{td}/t"), fake,
                                          env={**ENV, "GITHUB_OUTPUT": str(out_file)})
                    self.assertEqual(rc, 1, (purpose, name))
                    self.assertIn("echo check failed", err, (purpose, name))
                    # An ABSENT echo revokes only a revocable token (AbsentEchoTests); every other mismatch revokes.
                    revoked = name != "missing" or client.PURPOSES[purpose]["revocable"]
                    self.assertEqual(fake.deletes(), [f"token {install_token(repo)}"] if revoked else [],
                                     (purpose, name))
                    self.assertFalse(pathlib.Path(f"{td}/t").exists(), (purpose, name))
                    self.assertEqual(out_file.read_text(), "", (purpose, name))
                    # the token was masked before the revoke, and never printed otherwise
                    self.assertIn(f"::add-mask::{install_token(repo)}", out)
                    self.assertEqual(leaked(out + err, ALL_SECRETS), [], (purpose, name))

    def test_a_failed_revoke_on_mismatch_still_fails_and_says_so(self):
        fake = Fake(echo={"vagarylabs/vagary-core": {"permissions": None}}, delete=[500] * 10)
        rc, _, err, _ = run(mint_args(token_file=f"{RT}/x/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("NOT revoked", err)


class RetryTests(unittest.TestCase):
    def test_429_then_200_uses_the_backoff(self):
        with tmpdir() as td:
            fake = Fake(broker={"vagarylabs/vagary-core": [429, 503]})
            rc, _, err, clock = run(mint_args(token_file=f"{td}/t"), fake)
            self.assertEqual(rc, 0, err)
            self.assertEqual(clock.sleeps, [2, 5])

    def test_persistent_429_and_5xx_fail_after_a_bounded_retry(self):
        for status in (429, 500, 502, 503):
            fake = Fake(broker={"vagarylabs/vagary-core": [status] * 20})
            rc, _, err, clock = run(mint_args(token_file=f"{RT}/x/t"), fake)
            self.assertEqual(rc, 1, status)
            self.assertIn(f"HTTP {status}", err)
            self.assertEqual(clock.sleeps, list(client.BACKOFF), status)
            self.assertEqual(len(fake.broker_calls()), len(client.BACKOFF) + 1, status)

    def test_transport_errors_are_retried_and_bounded(self):
        class Down(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if url == BROKER + "/v1/source/read":
                    self.calls.append((method, url, dict(headers), data))
                    raise urllib.error.URLError("refused")
                return super().__call__(method, url, headers, data, timeout)
        fake = Down()
        rc, _, err, clock = run(mint_args(token_file=f"{RT}/x/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("transport URLError", err)
        self.assertEqual(len(clock.sleeps), len(client.BACKOFF))

    def test_a_refusal_is_not_retried(self):
        fake = Fake(broker={"vagarylabs/vagary-core": [403]})
        rc, _, err, clock = run(mint_args(token_file=f"{RT}/x/t"), fake)
        self.assertEqual((rc, clock.sleeps), (1, []))
        self.assertIn("HTTP 403 (repository not granted)", err)


class RawServer:
    """A 127.0.0.1 server that reads each request whole, answers it with the same raw bytes, then closes the
    connection: a cut body or a garbled status line exactly as a dropped connection delivers it to urllib."""

    def __init__(self, response: bytes):
        self.response, self.hits = response, 0
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                outer.hits += 1
                self.request.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = self.request.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                head, _, body = data.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
                while m and len(body) < int(m.group(1)):
                    chunk = self.request.recv(65536)
                    if not chunk:
                        break
                    body += chunk
                self.request.sendall(outer.response)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/source/read"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class TransportTests(unittest.TestCase):
    """A connection dropped mid-answer, or a garbled status line, is a transport error like a refused connection:
    retried with the bounded backoff, then the client's named failure (LegFailed) in the same `<leg>: transport <Type>`
    shape. Never a traceback, and never the exception's text (IncompleteRead carries the partial body)."""

    PARTIAL = b'{"schema": "source_read/v1", "token": "' + install_token("vagarylabs/partial").encode()
    CUT = b"Content-Type: application/json\r\nContent-Length: 400\r\nConnection: close\r\n\r\n" + PARTIAL

    def setUp(self):
        # Straight to 127.0.0.1: no environment or system proxy in between.
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
        self.addCleanup(urllib.request.install_opener, None)

    def drive(self, response: bytes):
        sleeps = []
        with RawServer(response) as srv:
            with self.assertRaises(client.LegFailed) as cm:
                client._call("broker source.read vagarylabs/partial (image_pull)", "POST", srv.url,
                             {"Content-Type": "application/json"}, b'{"repository": "vagarylabs/partial"}',
                             client._http, sleeps.append)
        self.assertEqual((srv.hits, sleeps), (len(client.BACKOFF) + 1, list(client.BACKOFF)))
        self.assertNotIn(install_token("vagarylabs/partial"), str(cm.exception))
        return str(cm.exception)

    def test_positive_control_the_raw_server_delivers_a_whole_answer(self):
        body = b'{"ok": true}'
        with RawServer(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body) \
                as srv:
            answer = client._call("control", "POST", srv.url, {}, b"{}", client._http, [].append)
        self.assertEqual((answer, srv.hits), ((200, {"ok": True}), 1))

    def test_a_200_cut_mid_body_is_a_retried_named_transport_failure(self):
        self.assertEqual(self.drive(b"HTTP/1.1 200 OK\r\n" + self.CUT),
                         "broker source.read vagarylabs/partial (image_pull): transport IncompleteRead")

    def test_a_5xx_cut_mid_body_is_a_retried_named_transport_failure(self):
        # urlopen raises HTTPError first; the cut is then hit by HTTPError.read() in _http's handler.
        self.assertEqual(self.drive(b"HTTP/1.1 503 Service Unavailable\r\n" + self.CUT),
                         "broker source.read vagarylabs/partial (image_pull): transport IncompleteRead")

    def test_a_garbled_status_line_is_a_retried_named_transport_failure(self):
        self.assertEqual(self.drive(b"garbage\r\n\r\n"),
                         "broker source.read vagarylabs/partial (image_pull): transport BadStatusLine")

    def test_a_dropped_broker_answer_through_main_exits_1_without_a_traceback(self):
        class Cut(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if url == BROKER + "/v1/source/read":
                    self.calls.append((method, url, dict(headers), data))
                    raise http.client.IncompleteRead(TransportTests.PARTIAL, 300)
                return super().__call__(method, url, headers, data, timeout)
        with tmpdir() as td:
            rc, out, err, clock = run(mint_args(purpose="image_pull", token_file=f"{td}/t"), Cut())
            self.assertEqual(rc, 1)
            self.assertIn("broker source.read vagarylabs/vagary-core (image_pull): transport IncompleteRead", err)
            self.assertEqual(clock.sleeps, list(client.BACKOFF))
            self.assertNotIn("Traceback", err)
            self.assertNotIn(install_token("vagarylabs/partial"), out + err)
            self.assertFalse(pathlib.Path(f"{td}/t").exists())

    def test_a_dropped_readiness_answer_is_retried_in_the_bound_then_fails_and_revokes(self):
        for exc in (http.client.IncompleteRead(b"{}", 10), http.client.BadStatusLine("garbage"),
                    http.client.LineTooLong("header line")):
            class Cut(Fake):
                def __call__(self, method, url, headers, data=None, timeout=30):
                    if method == "GET" and url.startswith(API + "/repos/"):
                        self.calls.append((method, url, dict(headers), data))
                        raise exc
                    return super().__call__(method, url, headers, data, timeout)
            fake = Cut()
            rc, _, err, clock = run(mint_args(purpose="image_pull", token_file=f"{RT}/x/t", readiness_seconds=5), fake)
            self.assertEqual(rc, 1, exc)
            self.assertIn(f"(last answer transport {type(exc).__name__},", err)
            self.assertLessEqual(sum(clock.sleeps), 5)
            self.assertEqual(fake.deletes(), [f"token {install_token('vagarylabs/vagary-core')}"], exc)

    def test_an_unexpected_exception_exits_1_naming_its_type_only(self):
        class Boom(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if url == BROKER + "/v1/source/read":
                    raise RuntimeError(f"boom {install_token('vagarylabs/vagary-core')}")
                return super().__call__(method, url, headers, data, timeout)
        rc, out, err, _ = run(mint_args(token_file=f"{RT}/x/t"), Boom())
        self.assertEqual(rc, 1)
        self.assertIn("unexpected RuntimeError", err)
        self.assertNotIn("boom", err)
        self.assertEqual(leaked(out + err, ALL_SECRETS), [])


class ReadinessTests(unittest.TestCase):
    def test_404_then_200_succeeds(self):
        with tmpdir() as td:
            fake = Fake(ready={"vagarylabs/vagary-core": [404, 404]})
            rc, _, err, clock = run(mint_args(token_file=f"{td}/t"), fake)
            self.assertEqual(rc, 0, err)
            self.assertEqual(clock.sleeps, [1.0, 2.0])
            gets = [c for c in fake.calls if c[0] == "GET" and c[1].startswith(API)]
            self.assertEqual({c[2]["Authorization"] for c in gets}, {f"token {install_token('vagarylabs/vagary-core')}"})

    def test_persistent_404_fails_within_the_bound_and_revokes_a_revocable_token(self):
        fake = Fake(ready={"vagarylabs/vagary-core": [404] * 100})
        rc, _, err, clock = run(mint_args(purpose="image_pull", token_file=f"{RT}/x/t", readiness_seconds=20), fake)
        self.assertEqual(rc, 1)
        self.assertIn("cannot see it after 20 s", err)
        self.assertLessEqual(sum(clock.sleeps), 20)
        self.assertEqual(fake.deletes(), [f"token {install_token('vagarylabs/vagary-core')}"])

    def test_persistent_404_does_not_revoke_a_cached_build_checkout_token(self):
        fake = Fake(ready={"vagarylabs/vagary-core": [404] * 100})
        rc, _, _, _ = run(mint_args(token_file=f"{RT}/x/t", readiness_seconds=10), fake)
        self.assertEqual((rc, fake.deletes()), (1, []))


class OutputTests(unittest.TestCase):
    def test_token_file_is_0600_and_github_output_is_masked_first(self):
        with tmpdir() as td:
            gh_out = pathlib.Path(td) / "gh-out"
            gh_out.write_text("")
            fake = Fake()
            rc, out, err, _ = run(mint_args(token_file=f"{td}/sub/t", github_output="token"), fake,
                                  env={**ENV, "GITHUB_OUTPUT": str(gh_out)})
            tok = install_token("vagarylabs/vagary-core")
            self.assertEqual(rc, 0, err)
            self.assertEqual(stat.S_IMODE(pathlib.Path(f"{td}/sub/t").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(pathlib.Path(f"{td}/sub").stat().st_mode), 0o700)
            self.assertEqual(gh_out.read_text(), f"token={tok}\ncached=unknown\n")
            masks = [l for l in out.splitlines() if l.startswith("::add-mask::")]
            # every credential of the chain is masked, in the order received, the install token last
            self.assertEqual(masks, [f"::add-mask::{v}" for v in (CREDS["oidc"], CREDS["access"], CREDS["id"], tok)])

    def test_token_dir_one_0600_file_per_repository(self):
        with tmpdir() as td:
            d = pathlib.Path(td) / "tokens"
            rc, out, err, _ = run(mint_args(repos="vagarylabs/a,vagarylabs/b\nvagarylabs/c", token_dir=str(d)), Fake())
            self.assertEqual(rc, 0, err)
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["vagarylabs__a", "vagarylabs__b", "vagarylabs__c"])
            self.assertEqual({stat.S_IMODE(p.stat().st_mode) for p in d.iterdir()}, {0o600})
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
            self.assertEqual((d / "vagarylabs__b").read_text(), install_token("vagarylabs/b"))

    def test_token_dir_is_all_or_nothing_and_revokes_minted_revocable_tokens(self):
        with tmpdir() as td:
            d = pathlib.Path(td) / "tokens"
            fake = Fake(broker={"vagarylabs/c": [403]})
            rc, _, err, _ = run(mint_args(purpose="image_pull", repos="vagarylabs/a vagarylabs/b vagarylabs/c",
                                          token_dir=str(d)), fake)
            self.assertEqual(rc, 1)
            self.assertFalse(d.exists() and any(d.iterdir()))
            self.assertEqual(fake.deletes(), [f"token {install_token('vagarylabs/a')}",
                                              f"token {install_token('vagarylabs/b')}"])

    def test_a_malformed_token_is_refused_unprinted(self):
        for bad in ("two\nlines-of-token", "has space token", "short"):
            fake = Fake(echo={"vagarylabs/vagary-core": {"token": bad}})
            rc, out, err, _ = run(mint_args(token_file=f"{RT}/x/t"), fake)
            self.assertEqual(rc, 1, bad)
            self.assertNotIn(bad.split()[0], out + err.replace("vagarylabs/vagary-core", ""), bad)


class Sentinel(Exception):
    """A failure no code path expects, so it can only reach the test as the original exception."""


class RevokeOnFailureTests(unittest.TestCase):
    """Once a token is received, ANY failure revokes it first (revocable purposes; a failed echo check whatever the
    purpose), then raises the ORIGINAL failure, never a revoke error in its place."""

    TOKEN = install_token("vagarylabs/vagary-core")

    def mint_direct(self, purpose, fake, deliver):
        """(the exception mint() raised, stderr). Every caller's deliver fails, so mint() must raise."""
        clock, err = Clock(), io.StringIO()
        saved, sys.stderr = sys.stderr, err
        try:
            client.mint(purpose, ["vagarylabs/vagary-core"], PROVIDER, SA, BROKER, API, 60, dict(ENV), fake,
                        clock.sleep, clock, io.StringIO(), deliver=deliver)
        except BaseException as exc:          # noqa: BLE001 -- returned to the test, which asserts its identity
            return exc, err.getvalue()
        finally:
            sys.stderr = saved
        self.fail("mint() returned although delivery failed")

    def test_a_failure_in_delivery_revokes_first_then_raises_the_original_object(self):
        for purpose, revoked in (("image_pull", True), ("repository_census", True), ("build_checkout", False)):
            fake, original = Fake(), Sentinel("the write failed")
            seen_at_failure = []

            def deliver(tokens, cached, said):
                self.assertEqual((tokens, cached, said), ({"vagarylabs/vagary-core": self.TOKEN},
                                                          {"vagarylabs/vagary-core": "unknown"},
                                                          {"vagarylabs/vagary-core": None}))
                seen_at_failure.append(list(fake.deletes()))
                raise original
            exc, err = self.mint_direct(purpose, fake, deliver)
            self.assertIs(exc, original, purpose)
            self.assertEqual(seen_at_failure, [[]], purpose)          # nothing revoked before the failure
            self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"] if revoked else [], purpose)
            self.assertEqual("that token was revoked" in err, revoked, (purpose, err))

    def test_a_failing_revoke_never_replaces_the_original(self):
        class DeleteBlowsUp(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if method == "DELETE":
                    self.calls.append((method, url, dict(headers), data))
                    raise RuntimeError("revoke exploded")
                return super().__call__(method, url, headers, data, timeout)
        for fake, why in ((Fake(delete=[500] * 20), "NOT revoked (revoke: HTTP 500)"),
                          (DeleteBlowsUp(), "NOT revoked (unexpected RuntimeError)")):
            original = Sentinel("the write failed")

            def deliver(tokens, cached, said):
                raise original
            exc, err = self.mint_direct("image_pull", fake, deliver)
            self.assertIs(exc, original, why)
            self.assertGreaterEqual(len(fake.deletes()), 1, why)      # the revoke was attempted
            self.assertIn(why, err)

    def test_through_main_a_write_error_revokes_and_names_it(self):
        for purpose, revoked in (("image_pull", True), ("build_checkout", False)):
            with tmpdir() as td:
                (pathlib.Path(td) / "file").write_text("a regular file where a directory is needed")
                fake = Fake()
                rc, out, err, _ = run(mint_args(purpose=purpose, token_file=f"{td}/file/t"), fake)
                self.assertEqual(rc, 1, purpose)
                self.assertRegex(err, r"writing the token failed \((FileExistsError|NotADirectoryError)\)")
                self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"] if revoked else [], purpose)
                self.assertNotIn("could not be removed", err, purpose)  # never written, so nothing to remove
                self.assertEqual(leaked(out + err, ALL_SECRETS), [], purpose)

    def test_through_main_an_unexpected_write_failure_revokes_and_names_the_original(self):
        def boom(path, token):
            raise Sentinel(f"carrying {token}")
        with tmpdir() as td, mock.patch.object(client, "_write_secret", boom):
            fake = Fake()
            rc, out, err, _ = run(mint_args(purpose="image_pull", token_file=f"{td}/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("unexpected Sentinel", err)
        self.assertIn("the mint failed (Sentinel) after vagarylabs/vagary-core's token was obtained; that token was "
                      "revoked", err)
        self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"])
        self.assertEqual(leaked(out + err, ALL_SECRETS), [])

    def test_through_main_a_failing_revoke_is_reported_and_the_original_still_named(self):
        def boom(path, token):
            raise Sentinel("write")
        with tmpdir() as td, mock.patch.object(client, "_write_secret", boom):
            fake = Fake(delete=[500] * 20)
            rc, _, err, _ = run(mint_args(purpose="image_pull", token_file=f"{td}/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("unexpected Sentinel", err)
        self.assertIn("::warning::broker-source-read: the mint failed (Sentinel)", err)
        self.assertIn("NOT revoked (revoke: HTTP 500)", err)

    def test_through_main_an_unexpected_revoke_error_on_an_echo_mismatch_keeps_the_echo_failure(self):
        class DeleteBlowsUp(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if method == "DELETE":
                    self.calls.append((method, url, dict(headers), data))
                    raise RuntimeError("revoke exploded")
                return super().__call__(method, url, headers, data, timeout)
        wrong = {**client.PURPOSES["build_checkout"]["permissions"], "contents": "write"}   # a PRESENT wrong echo
        fake = DeleteBlowsUp(echo={"vagarylabs/vagary-core": {"permissions": wrong}})
        rc, _, err, _ = run(mint_args(token_file=f"{RT}/x/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("echo check failed: permissions differ from build_checkout's set", err)
        self.assertIn("the token was NOT revoked (unexpected RuntimeError)", err)
        self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"])

    def test_an_interrupt_after_a_token_is_obtained_still_revokes_and_propagates(self):
        def interrupted(path, token):
            raise KeyboardInterrupt
        with tmpdir() as td, mock.patch.object(client, "_write_secret", interrupted):
            fake = Fake()
            with self.assertRaises(KeyboardInterrupt):
                run(mint_args(purpose="image_pull", token_file=f"{td}/t"), fake)
            self.assertFalse(pathlib.Path(f"{td}/t").exists())
        self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"])

    def test_a_token_is_recorded_the_moment_it_is_masked(self):
        # A failure between receiving the token and its echo check still revokes it.
        def broken_check(body, repository, purpose):
            raise Sentinel("check broke")
        with mock.patch.object(client, "echo_problems", broken_check):
            fake = Fake()
            rc, _, err, _ = run(mint_args(purpose="repository_census", token_file=f"{RT}/x/t"), fake)
        self.assertEqual(rc, 1)
        self.assertIn("unexpected Sentinel", err)
        self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"])

    def test_a_later_repository_failing_revokes_the_earlier_ones(self):
        class SecondBlowsUp(Fake):
            def __call__(self, method, url, headers, data=None, timeout=30):
                if url == BROKER + "/v1/source/read" and json.loads(data)["repository"] == "vagarylabs/b":
                    raise RuntimeError("second")
                return super().__call__(method, url, headers, data, timeout)
        with tmpdir() as td:
            fake = SecondBlowsUp()
            rc, _, err, _ = run(mint_args(purpose="image_pull", repos="vagarylabs/a vagarylabs/b",
                                          token_dir=f"{td}/d"), fake)
            self.assertEqual(rc, 1)
            self.assertIn("unexpected RuntimeError", err)
            self.assertEqual(fake.deletes(), [f"token {install_token('vagarylabs/a')}"])
            self.assertFalse(pathlib.Path(f"{td}/d").exists())


class AbsentEchoTests(unittest.TestCase):
    """An ABSENT permissions echo is the broker saying nothing, not saying something wrong. It still fails the step
    (fail closed), but a token that is not revocable is the broker's SHARED cache entry for this caller, so it is never
    revoked: platform #1205's CI (run 40756204707, 2026-10-28 19:47Z) revoked ci-src-vagary-platform@'s shared
    build_checkout token exactly this way against a broker that predated the echo. A PRESENT but wrong echo, or any
    other problem beside the absence, still revokes."""

    REPO = "vagarylabs/vagary-core"

    def mint(self, purpose, echo):
        with tmpdir() as td:
            fake = Fake(echo={self.REPO: echo})
            rc, out, err, _ = run(mint_args(purpose=purpose, token_file=f"{td}/t"), fake)
            return rc, out, err, fake, pathlib.Path(f"{td}/t").exists()

    def test_the_1205_shape_an_absent_echo_on_a_cached_purpose_fails_and_never_deletes(self):
        self.assertFalse(client.PURPOSES["build_checkout"]["revocable"], "control: build_checkout is the cached purpose")
        rc, out, err, fake, written = self.mint("build_checkout", {"permissions": None})
        self.assertEqual(rc, 1, err)
        self.assertIn("echo check failed: no permissions echoed", err)
        self.assertIn("NOT revoked", err)
        self.assertEqual(fake.deletes(), [])
        self.assertFalse(written)
        self.assertEqual(leaked(out + err, ALL_SECRETS), [])

    def test_an_absent_echo_when_the_broker_says_not_revocable_never_deletes(self):
        for purpose in client.PURPOSES:
            rc, _, err, fake, written = self.mint(purpose, {"permissions": None, "revocable": False})
            self.assertEqual((rc, fake.deletes(), written), (1, [], False), (purpose, err))

    def test_an_absent_echo_on_a_revocable_token_still_revokes(self):
        for purpose in client.PURPOSES:
            for echo in ({"permissions": None, "revocable": True},
                         *([{"permissions": None}] if client.PURPOSES[purpose]["revocable"] else [])):
                rc, _, err, fake, written = self.mint(purpose, echo)
                self.assertEqual(rc, 1, (purpose, echo))
                self.assertEqual(fake.deletes(), [f"token {install_token(self.REPO)}"], (purpose, echo, err))
                self.assertFalse(written)

    def test_an_absent_echo_beside_another_problem_still_revokes_a_shared_token(self):
        for other in ({"repository": "vagarylabs/other"}, {"schema": "source_read/v2"}):
            rc, _, err, fake, _ = self.mint("build_checkout", {"permissions": None, **other})
            self.assertEqual(rc, 1, other)
            self.assertEqual(fake.deletes(), [f"token {install_token(self.REPO)}"], (other, err))

    def test_a_present_but_wrong_echo_on_a_shared_token_still_revokes(self):
        want = client.PURPOSES["build_checkout"]["permissions"]
        rc, _, err, fake, _ = self.mint("build_checkout", {"permissions": {**want, "contents": "write"}})
        self.assertEqual(rc, 1)
        self.assertEqual(fake.deletes(), [f"token {install_token(self.REPO)}"], err)


class CachedEchoTests(unittest.TestCase):
    """`cached` repeats the broker's word, in the step output and the log line: true or false when its reply carries a
    JSON boolean `cached`, unknown otherwise. Today's reply has no such field, so today it is unknown; never
    inferred (not from expires_at, not from the purpose)."""

    def mint(self, fake, env_extra=None, **kw):
        with tmpdir() as td:
            gh_out = pathlib.Path(td) / "gh-out"
            gh_out.write_text("")
            kw.setdefault("token_file", f"{td}/t")
            rc, out, err, _ = run(mint_args(**kw), fake, env={**ENV, "GITHUB_OUTPUT": str(gh_out), **(env_extra or {})})
            self.assertEqual(rc, 0, err)
            outputs = dict(l.split("=", 1) for l in gh_out.read_text().splitlines())
        return outputs, err

    def test_no_cached_field_is_unknown_for_every_purpose(self):
        for purpose in client.PURPOSES:
            outputs, err = self.mint(Fake(), purpose=purpose)
            self.assertEqual(outputs, {"cached": "unknown"}, purpose)
            self.assertIn(f"vagarylabs/vagary-core minted for {purpose} (", err)
            self.assertIn("; cached: unknown (the broker's reply does not say); revocable: ", err)

    def test_an_expiry_or_a_purpose_never_stands_in_for_it(self):
        # A token about to expire (the shape of a cache hit) and a never-cached purpose both stay unknown.
        for purpose in ("build_checkout", "image_pull"):
            outputs, _ = self.mint(Fake(echo={"vagarylabs/vagary-core": {"expires_at": "2026-01-01T00:00:01Z"}}),
                                   purpose=purpose)
            self.assertEqual(outputs["cached"], "unknown", purpose)

    def test_a_boolean_cached_field_is_echoed(self):
        for value, word in ((True, "true"), (False, "false")):
            outputs, err = self.mint(Fake(echo={"vagarylabs/vagary-core": {"cached": value}}))
            self.assertEqual(outputs, {"cached": word})
            self.assertIn(f"; cached: {word}; revocable: ", err)

    def test_a_cached_field_that_is_not_a_json_boolean_is_unknown(self):
        for value in ("true", "yes", 1, 0, {}, []):
            outputs, _ = self.mint(Fake(echo={"vagarylabs/vagary-core": {"cached": value}}))
            self.assertEqual(outputs, {"cached": "unknown"}, value)

    def test_several_repositories_give_their_common_value_or_mixed(self):
        repos = "vagarylabs/a vagarylabs/b"
        for echo, want in (({}, "unknown"),
                           ({"vagarylabs/a": {"cached": True}, "vagarylabs/b": {"cached": True}}, "true"),
                           ({"vagarylabs/a": {"cached": True}, "vagarylabs/b": {"cached": False}}, "mixed"),
                           ({"vagarylabs/a": {"cached": False}}, "mixed")):
            with tmpdir() as td:
                outputs, err = self.mint(Fake(echo=echo), repos=repos, token_file="", token_dir=f"{td}/d")
            self.assertEqual(outputs, {"cached": want}, echo)
            self.assertEqual(len(re.findall(r"minted for build_checkout .*; cached: ", err)), 2)

    def test_the_token_output_and_the_cached_output_share_the_file(self):
        outputs, _ = self.mint(Fake(echo={"vagarylabs/vagary-core": {"cached": True}}), github_output="token")
        self.assertEqual(outputs, {"token": install_token("vagarylabs/vagary-core"), "cached": "true"})

    def test_without_github_output_the_log_line_still_says(self):
        with tmpdir() as td:
            env = {k: v for k, v in ENV.items() if k != "GITHUB_OUTPUT"}
            rc, _, err, _ = run(mint_args(token_file=f"{td}/t"), Fake(), env=env)
        self.assertEqual(rc, 0, err)
        self.assertIn("; cached: unknown (the broker's reply does not say);", err)


class BrokerRevocableTests(unittest.TestCase):
    """Whether a token is revoked follows the broker: its `revocable` decides when the reply carries a JSON boolean
    (revoke iff true), in the failure path AND in revoke mode (through the record mint keeps under RUNNER_TEMP). Only
    when the field is ABSENT does the purpose's legacy rule apply. A present non-boolean is refused: revoked, then
    the step fails."""

    REPO = "vagarylabs/vagary-core"
    TOKEN = install_token(REPO)

    def failing_mint(self, purpose, echo):
        """A mint that obtains the token, then fails its readiness wait: what the failure path revokes."""
        fake = Fake(echo={self.REPO: echo}, ready={self.REPO: [404] * 50})
        rc, _, err, _ = run(mint_args(purpose=purpose, token_file=f"{RT}/x/t", readiness_seconds=3), fake)
        self.assertEqual(rc, 1, err)
        return fake.deletes(), err

    def lifecycle(self, purpose, echo):
        """mint then revoke, as a job runs them: (DELETEs by revoke, mint stderr, revoke stdout+stderr)."""
        with tmpdir() as td:
            f = f"{td}/t"
            rc, _, merr, _ = run(mint_args(purpose=purpose, token_file=f), Fake(echo={self.REPO: echo}))
            self.assertEqual(rc, 0, merr)
            record = client.revocable_record(f, ENV)
            # a record exactly when the broker said, holding what it said
            self.assertEqual(record.read_text() if record.exists() else None,
                             None if "revocable" not in echo else str(echo["revocable"]).lower(), (purpose, echo))
            fake = Fake()
            rc, rout, rerr, _ = run(["revoke", "--purpose", purpose, "--token-file", f], fake)
            self.assertEqual(rc, 0, rerr)
            self.assertFalse(pathlib.Path(f).exists())
            self.assertFalse(client.revocable_record(f, ENV).exists())       # the record goes with the file
        return fake.deletes(), merr, rout + rerr

    def test_revocable_true_on_build_checkout_is_revoked(self):
        deletes, err = self.failing_mint("build_checkout", {"revocable": True})
        self.assertEqual(deletes, [f"token {self.TOKEN}"])
        self.assertIn("that token was revoked", err)
        deletes, merr, rlog = self.lifecycle("build_checkout", {"revocable": True})
        self.assertEqual(deletes, [f"token {self.TOKEN}"])
        self.assertIn("revocable: true (the broker says)", merr)
        self.assertIn("revoked (the broker said revocable)", rlog)

    def test_revocable_false_is_not_revoked_even_for_a_revocable_purpose(self):
        for purpose in client.PURPOSES:
            deletes, _ = self.failing_mint(purpose, {"revocable": False})
            self.assertEqual(deletes, [], purpose)
            deletes, merr, rlog = self.lifecycle(purpose, {"revocable": False})
            self.assertEqual(deletes, [], purpose)
            self.assertIn("revocable: false (the broker says)", merr)
            self.assertIn("the broker marked this token not revocable", rlog)

    def test_an_absent_field_keeps_the_legacy_per_purpose_rule(self):
        for purpose in client.PURPOSES:
            legacy = client.PURPOSES[purpose]["revocable"]
            want = [f"token {self.TOKEN}"] if legacy else []
            deletes, _ = self.failing_mint(purpose, {})
            self.assertEqual(deletes, want, purpose)
            deletes, merr, rlog = self.lifecycle(purpose, {})
            self.assertEqual(deletes, want, purpose)
            self.assertIn(f"revocable: {str(legacy).lower()} ({purpose}'s rule: the broker's reply does not say)", merr)
        self.assertEqual({p for p in client.PURPOSES if client.PURPOSES[p]["revocable"]},
                         {"image_pull", "repository_census"})                 # both branches of the rule are covered

    def test_a_non_boolean_revocable_is_refused_revoked_and_nothing_is_written(self):
        for purpose in ("build_checkout", "image_pull"):
            for value in ("true", "yes", 1, 0, NULL, {}, []):
                with tmpdir() as td:
                    fake = Fake(echo={self.REPO: {"revocable": value}})
                    rc, out, err, _ = run(mint_args(purpose=purpose, token_file=f"{td}/t"), fake)
                    self.assertEqual(rc, 1, (purpose, value))
                    self.assertIn("echo check failed: revocable is present but not a JSON boolean; the token was "
                                  "revoked", err)
                    self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"], (purpose, value))
                    self.assertEqual(list(pathlib.Path(td).iterdir()), [], (purpose, value))
                    self.assertEqual(leaked(out + err, ALL_SECRETS), [])

    def test_an_echo_mismatch_is_revoked_even_when_the_broker_says_not_revocable(self):
        # A PRESENT wrong echo (an ABSENT one on a non-revocable token is AbsentEchoTests: never revoked).
        wrong = {**client.PURPOSES["image_pull"]["permissions"], "packages": "write"}
        fake = Fake(echo={self.REPO: {"revocable": False, "permissions": wrong}})
        rc, _, err, _ = run(mint_args(purpose="image_pull", token_file=f"{RT}/x/t"), fake)
        self.assertEqual((rc, fake.deletes()), (1, [f"token {self.TOKEN}"]))
        self.assertIn("echo check failed: permissions differ from image_pull's set", err)

    def test_each_token_of_a_dir_follows_its_own_answer(self):
        with tmpdir() as td:
            d = pathlib.Path(td) / "d"
            echo = {"vagarylabs/a": {"revocable": True}, "vagarylabs/b": {"revocable": False}}   # c: absent
            rc, _, err, _ = run(mint_args(repos="vagarylabs/a vagarylabs/b vagarylabs/c", token_dir=str(d)),
                                Fake(echo=echo))
            self.assertEqual(rc, 0, err)
            # the consumer's view of the dir is unchanged: one token file per repository, nothing else
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["vagarylabs__a", "vagarylabs__b", "vagarylabs__c"])
            fake = Fake()
            rc, _, err, _ = run(["revoke", "--purpose", "build_checkout", "--token-dir", str(d)], fake)
            self.assertEqual(rc, 0, err)
            self.assertEqual(fake.deletes(), [f"token {install_token('vagarylabs/a')}"])
            self.assertFalse(d.exists())

    def test_a_revocable_token_with_no_file_to_revoke_from_is_refused_and_revoked(self):
        with tmpdir() as td:
            gh_out = pathlib.Path(td) / "gh-out"
            gh_out.write_text("")
            fake = Fake(echo={self.REPO: {"revocable": True}})
            rc, _, err, _ = run(mint_args(github_output="token"), fake, env={**ENV, "GITHUB_OUTPUT": str(gh_out)})
            self.assertEqual(rc, 1)
            self.assertIn("the broker marks this token revocable, and revoke reads a token from its file", err)
            self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"])
            self.assertEqual(gh_out.read_text(), "")
            # with a file as well, github-output is allowed: revoke reads the file
            fake = Fake(echo={self.REPO: {"revocable": True}})
            rc, _, err, _ = run(mint_args(github_output="token", token_file=f"{td}/t"), fake,
                                env={**ENV, "GITHUB_OUTPUT": str(gh_out)})
            self.assertEqual((rc, fake.deletes()), (0, []), err)

    def test_a_malformed_record_is_revoked_then_fails_that_file(self):
        for content in ("maybe", ""):
            with tmpdir() as td:
                f = f"{td}/t"
                rc, _, err, _ = run(mint_args(token_file=f), Fake(echo={self.REPO: {"revocable": False}}))
                self.assertEqual(rc, 0, err)
                client.revocable_record(f, ENV).write_text(content)
                fake = Fake()
                rc, _, err, _ = run(["revoke", "--purpose", "build_checkout", "--token-file", f], fake)
                self.assertEqual(rc, 1, content)
                self.assertEqual(fake.deletes(), [f"token {self.TOKEN}"], content)
                self.assertIn("revoke t: its revocable record is malformed; the token was revoked", err)
                self.assertFalse(pathlib.Path(f).exists() or client.revocable_record(f, ENV).exists())


class RevokeTests(unittest.TestCase):
    def write(self, path: pathlib.Path, token: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token)
        path.chmod(0o600)

    def test_revoke_reads_the_file_never_argv(self):
        with tmpdir() as td:
            f = pathlib.Path(td) / "t"
            self.write(f, "fixture-file-token")
            fake = Fake()
            rc, out, err, _ = run(["revoke", "--purpose", "image_pull", "--token-file", str(f)], fake)
            self.assertEqual(rc, 0, err)
            self.assertEqual(fake.deletes(), ["token fixture-file-token"])
            self.assertFalse(f.exists())
            self.assertIn("::add-mask::fixture-file-token", out)
            # there is no argv form: a token argument is a usage error with no call
            fake = Fake()
            rc, _, _, _ = run(["revoke", "--purpose", "image_pull", "--token", "fixture-argv-token"], fake)
            self.assertEqual((rc, fake.calls), (2, []))

    def test_401_and_404_mean_already_gone(self):
        for status in (401, 404):
            with tmpdir() as td:
                f = pathlib.Path(td) / "t"
                self.write(f, "fixture-file-token")
                rc, _, err, _ = run(["revoke", "--purpose", "repository_census", "--token-file", str(f)],
                                    Fake(delete=[status]))
                self.assertEqual(rc, 0, status)
                self.assertIn("already gone", err)
                self.assertFalse(f.exists())

    def test_revoke_5xx_is_retried_then_fails_loud_and_still_removes_the_file(self):
        with tmpdir() as td:
            f = pathlib.Path(td) / "t"
            self.write(f, "fixture-file-token")
            fake = Fake(delete=[503] * 20)
            rc, _, err, clock = run(["revoke", "--purpose", "image_pull", "--token-file", str(f)], fake)
            self.assertEqual(rc, 1)
            self.assertEqual(len(fake.deletes()), len(client.BACKOFF) + 1)
            self.assertFalse(f.exists())
            rc, _, _, _ = run(["revoke", "--purpose", "image_pull", "--token-file", str(f)],
                              Fake(delete=[403]))
            self.assertEqual(rc, 0)   # file already gone: nothing to revoke

    def test_build_checkout_is_not_revoked_but_its_file_is_removed(self):
        with tmpdir() as td:
            f = pathlib.Path(td) / "t"
            self.write(f, "fixture-file-token")
            fake = Fake()
            rc, out, _, _ = run(["revoke", "--purpose", "build_checkout", "--token-file", str(f)], fake)
            self.assertEqual((rc, fake.deletes()), (0, []))
            self.assertFalse(f.exists())
            self.assertIn("cached by the broker", out)

    def test_token_dir_revokes_each_file_then_removes_the_dir(self):
        with tmpdir() as td:
            d = pathlib.Path(td) / "tokens"
            self.write(d / "vagarylabs__a", "fixture-token-a")
            self.write(d / "vagarylabs__b", "fixture-token-b")
            fake = Fake()
            rc, _, err, _ = run(["revoke", "--purpose", "image_pull", "--token-dir", str(d)], fake)
            self.assertEqual(rc, 0, err)
            self.assertEqual(sorted(fake.deletes()), ["token fixture-token-a", "token fixture-token-b"])
            self.assertFalse(d.exists())

    def three_files(self, td) -> pathlib.Path:
        d = pathlib.Path(td) / "tokens"
        for n in ("a", "b", "c"):
            self.write(d / f"vagarylabs__{n}", f"fixture-token-{n}")
        return d

    def revoke_dir(self, d, fake):
        return run(["revoke", "--purpose", "image_pull", "--token-dir", str(d)], fake)

    def test_one_unreadable_or_vanished_file_is_reported_and_the_rest_are_still_revoked(self):
        real_read = pathlib.Path.read_text

        def unreadable(path, *a, **kw):
            if path.name == "vagarylabs__b":
                raise PermissionError(13, "Permission denied")   # chmod 000 proves nothing when CI runs as root
            return real_read(path, *a, **kw)

        def vanished(path, *a, **kw):
            if path.name == "vagarylabs__b":
                os.unlink(path)                                   # gone between the listing and the read
            return real_read(path, *a, **kw)
        for fault, why in ((unreadable, "PermissionError"), (vanished, "FileNotFoundError")):
            with tmpdir() as td:
                d, fake = self.three_files(td), Fake()
                with mock.patch.object(pathlib.Path, "read_text", fault):
                    rc, _, err, _ = self.revoke_dir(d, fake)
                self.assertEqual(rc, 1, why)
                self.assertEqual(fake.deletes(), ["token fixture-token-a", "token fixture-token-c"], why)
                self.assertIn(f"revoke vagarylabs__b: the token file could not be read ({why})", err)
                self.assertIn("revoke: 1 of 3 token file(s) failed: vagarylabs__b", err)
                self.assertFalse(d.exists(), why)                 # every file removed, then the directory

    def test_a_token_file_that_is_not_utf8_is_reported_and_the_rest_are_still_revoked(self):
        with tmpdir() as td:
            d, fake = self.three_files(td), Fake()
            (d / "vagarylabs__b").write_bytes(b"\xff\xfe-not-utf-8")
            rc, _, err, _ = self.revoke_dir(d, fake)
            self.assertEqual(rc, 1)
            self.assertEqual(fake.deletes(), ["token fixture-token-a", "token fixture-token-c"])
            self.assertIn("revoke vagarylabs__b: the token file could not be read (UnicodeDecodeError)", err)
            self.assertFalse(d.exists())

    def test_a_file_that_cannot_be_removed_is_reported_and_the_rest_are_still_revoked(self):
        real_unlink = pathlib.Path.unlink

        def stuck(path, *a, **kw):
            if path.name == "vagarylabs__b":
                raise PermissionError(1, "Operation not permitted")
            return real_unlink(path, *a, **kw)
        with tmpdir() as td:
            d, fake = self.three_files(td), Fake()
            with mock.patch.object(pathlib.Path, "unlink", stuck):
                rc, _, err, _ = self.revoke_dir(d, fake)
            self.assertEqual(rc, 1)
            self.assertEqual(fake.deletes(), [f"token fixture-token-{n}" for n in "abc"])   # b's token was revoked too
            self.assertIn("revoke vagarylabs__b: the file could not be removed (PermissionError)", err)
            self.assertIn("revoke: 1 of 3 token file(s) failed: vagarylabs__b", err)
            self.assertEqual([p.name for p in d.iterdir()], ["vagarylabs__b"])

    def test_a_directory_that_cannot_be_listed_fails_named_without_a_traceback(self):
        with tmpdir() as td:
            d = self.three_files(td)
            with mock.patch.object(pathlib.Path, "iterdir", side_effect=PermissionError(13, "Permission denied")):
                rc, _, err, _ = self.revoke_dir(d, Fake())
            self.assertEqual(rc, 1)
            self.assertIn("cannot be listed (PermissionError)", err)
            self.assertNotIn("unexpected", err)

    def test_no_file_is_nothing_to_revoke(self):
        fake = Fake()
        rc, _, err, _ = run(["revoke", "--purpose", "image_pull", "--token-file", f"{RT}/nonexistent/t"], fake)
        self.assertEqual((rc, fake.calls), (0, []))
        self.assertIn("nothing to revoke", err)

    def test_a_symlink_is_refused_and_not_followed(self):
        with tmpdir() as td:
            target = pathlib.Path(td) / "elsewhere"
            self.write(target, "fixture-other-token")
            link = pathlib.Path(td) / "t"
            link.symlink_to(target)
            fake = Fake()
            rc, _, _, _ = run(["revoke", "--purpose", "image_pull", "--token-file", str(link)], fake)
            self.assertEqual((rc, fake.deletes()), (1, []))
            self.assertTrue(target.exists())


class RunnerTempTests(unittest.TestCase):
    """Every token path is absolute and strictly inside RUNNER_TEMP once resolved, in both modes, or the step exits 2
    naming RUNNER_TEMP before any call, and writes or removes nothing."""

    def refused(self, argv, env=None, gh_output=None):
        fake = Fake()
        env = dict(ENV if env is None else env)
        if gh_output is not None:
            env["GITHUB_OUTPUT"] = gh_output
        rc, out, err, _ = run(argv, fake, env=env)
        self.assertEqual((rc, fake.calls), (2, []), (argv, err))
        self.assertIn("RUNNER_TEMP", err, argv)
        return out + err

    def test_unset_or_relative_runner_temp_is_refused_in_both_modes(self):
        with tmpdir() as td:
            for env in ({k: v for k, v in ENV.items() if k != "RUNNER_TEMP"}, {**ENV, "RUNNER_TEMP": ""},
                        {**ENV, "RUNNER_TEMP": "relative/temp"}):
                self.refused(mint_args(token_file=f"{td}/t"), env=env)
                self.refused(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=f"{td}/d"), env=env)
                self.write_token(pathlib.Path(td) / "kept")
                self.refused(["revoke", "--purpose", "image_pull", "--token-file", f"{td}/kept"], env=env)
                self.assertTrue((pathlib.Path(td) / "kept").exists())
            self.assertEqual(sorted(p.name for p in pathlib.Path(td).iterdir()), ["kept"])

    def test_an_absolute_path_outside_is_refused_and_nothing_is_written_or_removed(self):
        with tempfile.TemporaryDirectory() as outside:   # NOT under RT
            self.refused(mint_args(token_file=f"{outside}/t"))
            self.refused(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=f"{outside}/d"))
            self.assertEqual(list(pathlib.Path(outside).iterdir()), [])
            victim = pathlib.Path(outside) / "victim"
            self.write_token(victim)
            self.refused(["revoke", "--purpose", "image_pull", "--token-file", str(victim)])
            self.refused(["revoke", "--purpose", "image_pull", "--token-dir", outside])
            self.assertTrue(victim.exists())

    def test_dotdot_is_refused_even_when_it_would_land_inside(self):
        with tmpdir() as td:
            escaped = pathlib.Path(RT).parent / (pathlib.Path(RT).name + "-escaped-t")   # unique per run
            for path in (f"{RT}/../{escaped.name}", f"{td}/sub/../t", f"{td}/.."):
                self.refused(mint_args(token_file=path))
                self.refused(["revoke", "--purpose", "image_pull", "--token-file", path])
            self.assertEqual(list(pathlib.Path(td).iterdir()), [])
            self.assertFalse(escaped.exists())

    def test_a_symlink_leading_out_is_refused(self):
        with tmpdir() as td, tempfile.TemporaryDirectory() as outside:
            link = pathlib.Path(td) / "link"
            link.symlink_to(outside, target_is_directory=True)
            self.refused(mint_args(token_file=f"{link}/t"))                                       # via a parent
            self.refused(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=str(link)))       # the dir itself
            self.refused(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=f"{link}/d"))
            self.assertEqual(list(pathlib.Path(outside).iterdir()), [])
            victim = pathlib.Path(outside) / "victim"
            self.write_token(victim)
            final = pathlib.Path(td) / "t"
            final.symlink_to(victim)                                                              # the file itself
            self.refused(mint_args(token_file=str(final)))
            self.refused(["revoke", "--purpose", "image_pull", "--token-file", str(final)])
            self.refused(["revoke", "--purpose", "image_pull", "--token-file", f"{link}/victim"])
            self.assertEqual(victim.read_text(), "fixture-file-token")

    def test_runner_temp_itself_is_not_a_token_path(self):
        self.refused(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=RT))
        self.refused(["revoke", "--purpose", "image_pull", "--token-dir", RT])
        self.assertTrue(pathlib.Path(RT).is_dir())

    def test_github_output_outside_runner_temp_is_refused_when_the_token_goes_there(self):
        with tempfile.TemporaryDirectory() as outside:
            gh_out = pathlib.Path(outside) / "gh-out"
            gh_out.write_text("")
            with tmpdir() as td:
                self.refused(mint_args(token_file=f"{td}/t", github_output="token"), gh_output=str(gh_out))
            self.assertEqual(gh_out.read_text(), "")

    def test_positive_control_a_runner_temp_reached_through_a_symlink_is_inside(self):
        # The comparison is realpath to realpath: RUNNER_TEMP given as a symlink is the same directory, not an escape.
        with tmpdir() as td:
            real = pathlib.Path(td) / "real-temp"
            real.mkdir()
            alias = pathlib.Path(td) / "alias-temp"
            alias.symlink_to(real, target_is_directory=True)
            env = {**ENV, "RUNNER_TEMP": str(alias)}
            rc, _, err, _ = run(mint_args(token_file=f"{real}/t"), Fake(), env=env)
            self.assertEqual(rc, 0, err)
            rc, _, err, _ = run(mint_args(repos="vagarylabs/a vagarylabs/b", token_dir=f"{alias}/d"), Fake(), env=env)
            self.assertEqual(rc, 0, err)
            self.assertEqual(sorted(p.name for p in real.iterdir()), ["d", "t"])
            rc, _, err, _ = run(["revoke", "--purpose", "image_pull", "--token-dir", f"{alias}/d"], Fake(), env=env)
            self.assertEqual(rc, 0, err)
            self.assertFalse((real / "d").exists())

    @staticmethod
    def write_token(path: pathlib.Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture-file-token")
        path.chmod(0o600)


class NoTokenPrintedTests(unittest.TestCase):
    def test_positive_control_the_scanner_finds_a_planted_leak(self):
        planted = f"::add-mask::{CREDS['id']}\nbroker said {install_token('vagarylabs/a')} oops\n"
        self.assertEqual(leaked(planted, ALL_SECRETS), [install_token("vagarylabs/a")])
        self.assertEqual(leaked(f"::add-mask::{CREDS['id']}\n", ALL_SECRETS), [])

    def test_no_credential_in_any_printed_line_across_paths(self):
        paths = [
            (mint_args(token_file="T/t"), Fake()),
            (mint_args(repos="vagarylabs/a vagarylabs/b", token_dir="T/d"), Fake()),
            (mint_args(purpose="image_pull", token_file="T/t"), Fake(echo={"vagarylabs/vagary-core": {"permissions": None}})),
            (mint_args(token_file="T/t"), Fake(broker={"vagarylabs/vagary-core": [429] * 20})),
            (mint_args(token_file="T/t"), Fake(sts=401)),
            (mint_args(purpose="image_pull", token_file="T/t", readiness_seconds=5),
             Fake(ready={"vagarylabs/vagary-core": [404] * 50})),
        ]
        for argv, fake in paths:
            with tmpdir() as td:
                argv = [a.replace("T/", td + "/") for a in argv]
                rc, out, err, _ = run(argv, fake)
                self.assertEqual(leaked(out + err, ALL_SECRETS), [], argv)
                # and nothing reaches the network in a URL or a query string except the OIDC audience
                for method, url, _, _ in fake.calls:
                    self.assertFalse(any(s in url for s in ALL_SECRETS), url)


class ActionTests(unittest.TestCase):
    """action.yml: the inputs cli and the consumers use, and no input or token interpolated into a run script."""

    text = (HERE / "action.yml").read_text()

    def test_inputs(self):
        block = self.text.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
        names = re.findall(r"^  ([a-z_-]+):$", block, re.M)
        self.assertEqual(names, ["mode", "purpose", "repository", "provider", "service_account", "audience",
                                 "token-file", "token-dir", "output", "readiness-seconds"])

    def test_outputs(self):
        block = self.text.split("\noutputs:\n", 1)[1].split("\nruns:\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_-]+):$", block, re.M), ["token", "cached"])
        self.assertIn("value: ${{ steps.mint.outputs.cached }}", block)

    def test_no_expression_inside_a_run_script(self):
        in_run, bad = False, []
        for line in self.text.splitlines():
            if re.match(r"^\s+run: \|", line):
                in_run = True
                continue
            if in_run and re.match(r"^\s{4}- |^\s{6}[a-z-]+:", line):
                in_run = False
            if in_run and "${{" in line:
                bad.append(line)
        self.assertEqual(bad, [])

    def test_client_runs_isolated_and_mode_is_checked(self):
        self.assertIn('python3 -I "$GITHUB_ACTION_PATH/client.py"', self.text)
        self.assertIn("mint|revoke", self.text)
        # The header comment names the retired path to explain it; no line of the action itself uses it.
        code = "\n".join(l for l in self.text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("create-github-app-token", code)
        self.assertNotIn("SOURCE_READ_APP", code)
        self.assertNotIn("private-key", code)


if __name__ == "__main__":
    unittest.main()
