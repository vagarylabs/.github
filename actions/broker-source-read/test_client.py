#!/usr/bin/env python3
"""Tests for client.py against a fake GitHub OIDC / STS / IAM / broker / GitHub API. Stdlib only, no network, no real
credential: every value below is a fixture string.

Run: python3 -m unittest discover -s actions/broker-source-read -p 'test_*.py' -v
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import re
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse

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


class Fake:
    """Answers each leg and records every call.

    broker:  {repo: [status, ...]} answered in order before a 200.
    echo:    {repo: dict} fields that REPLACE the 200 body's defaults (None deletes the field).
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
                    body[k] = v
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
                    self.assertEqual(fake.deletes(), [f"token {install_token(repo)}"], (purpose, name))
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
            self.assertEqual(gh_out.read_text(), f"token={tok}\n")
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
