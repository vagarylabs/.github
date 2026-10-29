#!/usr/bin/env python3
"""broker-source-read: read-only GitHub installation tokens minted by the Source & Delivery broker for THIS job's
GitHub OIDC identity. No App key sits in Actions secrets. This replaces actions/create-github-app-token with
SOURCE_READ_APP_ID / SOURCE_READ_APP_PRIVATE_KEY: the internal Source Access App is retired (operator ruling
2026-10-14; source-access move plan row C4). Stdlib only.

mint    The chain, every leg keyless and short-lived:
          1. A GitHub OIDC token for the job (`permissions: id-token: write`), audience = the WIF provider.
          2. Google STS exchanges it at that provider for a federated access token.
          3. iamcredentials generateIdToken for the service account, audience = the broker, email included.
          4. POST <broker>/v1/source/read {"repository", "purpose"}: one token per repository.
        Every credential is masked (`::add-mask::`) the moment it is received. Each broker answer is then checked
        before its token is used: the schema is source_read/v1, the repository is echoed, and the echoed
        `permissions` EQUAL the purpose's expected set (PURPOSES, mirroring the broker). Wider, narrower or malformed:
        the token is revoked and the step fails. Missing (an older broker sends no echo): the step fails, and the
        token is revoked only if it is revocable, because a non-revocable one is the broker's shared cache entry.
        Then a readiness probe: GET <api>/repos/<owner>/<name>
        must answer 200 within --readiness-seconds, because a fresh installation token is not visible everywhere at
        once (vagaris #825, core #920).
        All or nothing: on any failure nothing is written, and every token already minted for a revocable purpose is
        revoked FIRST, then the original failure is raised; a failed revoke is reported, never raised in its place.
        That holds for every failure after a token is received, a write error or an interrupt included.
        The token goes to a 0600 file (--token-file, one repository; --token-dir, one file `<owner>__<name>` per
        repository) and/or, masked, to $GITHUB_OUTPUT (--github-output NAME, one repository). Never printed, never
        logged, never in argv. Every one of those paths must be absolute and strictly inside $RUNNER_TEMP once
        resolved (no `..`, no symlink leading out); RUNNER_TEMP unset is refused. Both modes, before any call.
        `cached`: whether the broker says it handed back a token from its cache, in the log line and (when
        $GITHUB_OUTPUT is set) the step output `cached`: true, false, or unknown when the reply does not say (see
        cached_echo).
        `revocable`: whether this token is revoked after use (and on any failure) is the broker's word when its reply
        carries a JSON boolean `revocable`; only when the field is absent (an older broker) is it the purpose's rule
        (PURPOSES). A present non-boolean is refused like any echo mismatch: revoked, then the step fails. The broker's
        word is recorded under $RUNNER_TEMP (revocable_record) so revoke mode follows it.
revoke  Reads each token from its 0600 file (never argv). When the token is revocable (the broker's word recorded at
        mint; without a record, the purpose's rule) it calls DELETE <api>/installation/token: 204 is revoked; 401 or
        404 means the token is already gone. The file is removed either way. Without a record, a build_checkout token
        is NOT revoked (see PURPOSES): an older broker caches it per caller. Each file
        is handled on its own: one that cannot be read (unreadable, vanished), revoked or removed is reported, the rest
        are still revoked, and the exit is 1 at the end.

Failure is loud and never a pass. Any leg that does not succeed exits 1 and names the leg and the HTTP status. 429,
5xx and transport errors (a refused or dropped connection, a body cut short, a garbled status line) are retried with a
bounded backoff (the broker allows 30 mints per minute per caller); a final 429 is a failure, so the consuming gate
reports CANNOT-DETERMINE. Usage errors, including an unknown purpose, exit 2 before any network call. Nothing ends in
a traceback: an unexpected exception exits 1 naming its type only.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

# What a dropped or garbled connection raises. urllib wraps a failure to SEND in URLError, but not one while reading the
# answer: http.client raises IncompleteRead (a body cut short; also from HTTPError.read() on a 4xx/5xx body),
# BadStatusLine or LineTooLong (a garbled status or header line), and RemoteDisconnected (an OSError). Every leg treats
# them alike: retried with the bounded backoff, then a LegFailed naming the TYPE only. IncompleteRead carries the
# partial body, which can hold a credential, so no exception's text is ever printed.
TRANSPORT_ERRORS = (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError)

# The purposes a CI job may ask POST /v1/source/read for, each with EXACTLY the permission set the broker mints. This
# mirrors vps-ansible scripts/build-controller/source_delivery_broker.py (origin/main 8d3c29dd):
# SOURCE_READ_PERMISSIONS (:196), SOURCE_READ_PURPOSE_PERMISSIONS (:207-208), SOURCE_READ_UNCACHED_PURPOSES (:211)
# and source_read_permissions() (:1009). The broker's other purposes (canon_sync, deployment_reconcile,
# agent_context, self_converge) belong to build cells and services, not CI, and are refused here before any call.
#
# `revocable` is the broker's UNCACHED set, and it is now only the FALLBACK for a broker whose reply carries no
# `revocable` field (revocable_echo): a reply that carries one decides for itself. Such an older broker caches a
# build_checkout token per caller: Minter's cache scope includes holder = the caller's sub (:606-611), and every job of
# one CI service account shares that sub, so they share one token for up to about 55 minutes. Revoking it would revoke
# it under every concurrent and later job of that caller. A token whose echo check FAILS is revoked whatever its
# purpose and whatever the broker says, because a wrong token is wrong for every holder. The one exception is an echo
# that is merely ABSENT on a non-revocable token: that is no evidence of a wrong token, and the token is shared.
PURPOSES = {
    "build_checkout": {"permissions": {"contents": "read", "metadata": "read"}, "revocable": False},
    "image_pull": {"permissions": {"packages": "read", "metadata": "read"}, "revocable": True},
    "repository_census": {"permissions": {"pull_requests": "read", "checks": "read", "metadata": "read"},
                          "revocable": True},
}
SCHEMA = "source_read/v1"
STS_URL = "https://sts.googleapis.com/v1/token"
IAM_URL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateIdToken"
BACKOFF = (2, 5, 10, 20, 30)          # seconds between attempts; 6 attempts span about 67 s
GITHUB_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
USER_AGENT = "vagarylabs-broker-source-read"

PROVIDER_RE = re.compile(r"(?://iam\.googleapis\.com/)?(projects/[0-9]+/locations/global/workloadIdentityPools/"
                         r"[a-z0-9-]+/providers/[a-z0-9-]+)")
SERVICE_ACCOUNT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com")
AUDIENCE_RE = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?")
API_RE = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._/-]*)?")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
OUTPUT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
TOKEN_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}__[A-Za-z0-9._-]{1,100}")
# A credential is one run of printable, non-space ASCII. Anything else is refused unprinted: a newline would split an
# `::add-mask::` line and leave the rest of the value unmasked.
CREDENTIAL_RE = re.compile(r"[\x21-\x7e]{8,16384}")


class LegFailed(RuntimeError):
    """One leg did not succeed. The message names the leg and the status, never a credential."""


class Usage(ValueError):
    """A usage error, found before any network call (exit 2)."""


class OutsideRunnerTemp(Usage):
    """RUNNER_TEMP is unset, or a token path is not strictly inside it once resolved (exit 2, before any call)."""


def inside_runner_temp(value: str, what: str, env: dict) -> pathlib.Path:
    """`value` when it is an absolute path strictly inside $RUNNER_TEMP with every symlink resolved; else
    OutsideRunnerTemp. The runner empties RUNNER_TEMP after every job, so a token kept there cannot outlive the job,
    and revoke (which removes what it reads) cannot be pointed at a file elsewhere. Both sides are compared as
    realpaths, so a symlink anywhere in the path cannot lead out, while a RUNNER_TEMP that is itself reached through a
    symlink is not an escape. A `..` component is refused outright, never resolved."""
    root = env.get("RUNNER_TEMP") or ""
    if not root:
        raise OutsideRunnerTemp(f"RUNNER_TEMP is not set, so the {what} cannot be confined to the job's temp directory")
    if not os.path.isabs(root):
        raise OutsideRunnerTemp("RUNNER_TEMP must be an absolute path")
    if not os.path.isabs(value):
        raise OutsideRunnerTemp(f"RUNNER_TEMP: the {what} must be an absolute path inside it, not {value[:200]!r}")
    if ".." in pathlib.PurePosixPath(value).parts:
        raise OutsideRunnerTemp(f"RUNNER_TEMP: the {what} must not contain '..': {value[:200]!r}")
    real_root, real = os.path.realpath(root), os.path.realpath(value)
    if real == real_root or os.path.commonpath([real_root, real]) != real_root:
        raise OutsideRunnerTemp(f"RUNNER_TEMP: the {what} {value[:200]!r} resolves to {real[:200]!r}, which is not "
                                "inside RUNNER_TEMP")
    return pathlib.Path(value)


def _http(method: str, url: str, headers: dict, data: bytes | None, timeout: float = 30) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as err:
        raw, status = err.read(), err.code
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        body = {}
    return status, body if isinstance(body, dict) else {}


def _call(leg: str, method: str, url: str, headers: dict, data: bytes | None, http: Callable,
          sleep: Callable[[float], None], ok: tuple[int, ...] = (200,)) -> tuple[int, dict]:
    """(status, body) of the first answer in `ok`, retrying 429, 5xx and transport errors a bounded number of times;
    any other answer, or the last retried one, raises LegFailed."""
    last = "no attempt"
    for attempt in range(len(BACKOFF) + 1):
        try:
            status, body = http(method, url, headers, data)
        except TRANSPORT_ERRORS as err:
            last = f"transport {type(err).__name__}"
        else:
            if status in ok:
                return status, body
            # A broker refusal carries a non-secret `reason`; STS/IAM carry `error` / `error.status`.
            reason = body.get("reason") or body.get("error_description") or body.get("error") or body.get("message")
            if isinstance(reason, dict):
                reason = reason.get("status") or reason.get("message")
            last = f"HTTP {status}" + (f" ({str(reason)[:160]})" if reason else "")
            if status != 429 and status < 500:
                break
        if attempt < len(BACKOFF):
            sleep(BACKOFF[attempt])
    raise LegFailed(f"{leg}: {last}")


def mask(value: object, what: str, out) -> str:
    """Register one credential with the runner's masker before anything else is done with it."""
    if not isinstance(value, str) or not CREDENTIAL_RE.fullmatch(value):
        raise LegFailed(f"{what}: the credential is missing or not a single printable token (not printed)")
    print(f"::add-mask::{value}", file=out, flush=True)
    return value


def provider_resource(provider: str) -> str:
    """The provider as `projects/<n>/locations/global/workloadIdentityPools/<pool>/providers/<id>`."""
    m = PROVIDER_RE.fullmatch(provider.strip())
    if not m:
        raise Usage("provider must be projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<id>"
                    " (optionally prefixed //iam.googleapis.com/)")
    return m.group(1)


def github_oidc(resource: str, env: dict, http: Callable, sleep: Callable, out) -> str:
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise LegFailed("github-oidc: ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN absent; the job needs "
                        "`permissions: id-token: write`")
    audience = "https://iam.googleapis.com/" + resource
    sep = "&" if "?" in url else "?"
    _, body = _call("github-oidc", "GET", f"{url}{sep}audience={urllib.parse.quote(audience, safe='')}",
                    {"Authorization": f"bearer {bearer}"}, None, http, sleep)
    return mask(body.get("value"), "github-oidc", out)


def federated_access_token(resource: str, oidc: str, http: Callable, sleep: Callable, out) -> str:
    form = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": "//iam.googleapis.com/" + resource,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": oidc,
    }).encode()
    _, body = _call("sts", "POST", STS_URL, {"Content-Type": "application/x-www-form-urlencoded"}, form, http, sleep)
    return mask(body.get("access_token"), "sts", out)


def broker_id_token(service_account: str, audience: str, access: str, http: Callable, sleep: Callable, out) -> str:
    _, body = _call("generate-id-token", "POST", IAM_URL.format(sa=service_account),
                    {"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
                    json.dumps({"audience": audience, "includeEmail": True}).encode(), http, sleep)
    return mask(body.get("token"), "generate-id-token", out)


# The one echo problem that is the broker saying nothing rather than something wrong (mint: no revoke for a shared token).
NO_PERMISSIONS_ECHO = "no permissions echoed"


def echo_problems(body: dict, repository: str, purpose: str) -> list[str]:
    """What is wrong with a broker 200 for this repository and purpose; empty when it is exactly right."""
    problems = []
    if body.get("schema") != SCHEMA:
        problems.append(f"schema {str(body.get('schema'))[:40]!r} is not {SCHEMA}")
    if str(body.get("repository", "")).lower() != repository.lower():
        problems.append("the broker echoed a different repository")
    want, got = PURPOSES[purpose]["permissions"], body.get("permissions")
    if got is None:
        problems.append(NO_PERMISSIONS_ECHO)
    elif not isinstance(got, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in got.items()):
        problems.append("permissions echo is malformed")
    elif got != want:
        wider = sorted(f"{k}:{v}" for k, v in got.items() if want.get(k) != v)
        narrower = sorted(f"{k}:{v}" for k, v in want.items() if got.get(k) != v)
        problems.append(f"permissions differ from {purpose}'s set (unexpected {wider or 'none'}, "
                        f"missing {narrower or 'none'})"[:400])
    if "revocable" in body and not isinstance(body["revocable"], bool):
        problems.append("revocable is present but not a JSON boolean")
    return problems


def cached_echo(body: dict) -> str:
    """The broker's own word on whether this token came from its cache: 'true' or 'false' when the reply carries a JSON
    boolean `cached`, else 'unknown'. Never inferred: expires_at cannot stand in for it (a cache hit minted a second
    ago looks fresh), nor can the purpose.

    The broker at vps-ansible origin/main 2aac710f does not say: source_read() answers {schema, repository, token,
    permissions, expires_at, request_id} (source_delivery_broker.py:1083-1085), and Minter.token() returns a cache hit
    as (token, granted, expires) (:616-618), the same shape as a fresh mint (:658). Root's decision on .github #38 (as
    relayed, not verified here) is that the next broker release echoes `"cached": <bool>` and `"revocable": <bool>` in
    every 200; this passes that through, and stays 'unknown' for an older broker."""
    value = body.get("cached")
    return "true" if value is True else "false" if value is False else "unknown"


def revocable_said(body: dict) -> bool | None:
    """The broker's own `revocable` when its reply carries a JSON boolean; None when the field is absent (an older
    broker) or not a boolean (which echo_problems refuses). bool only: isinstance(1, bool) is False."""
    value = body.get("revocable")
    return value if isinstance(value, bool) else None


def revocable_echo(body: dict, purpose: str) -> bool:
    """Whether this token is revoked after use and on any failure: the broker's word when its reply carries a JSON
    boolean `revocable`; the purpose's rule (PURPOSES) only when the field is ABSENT. A present non-boolean is unclear,
    so True: it is revoked (echo_problems then fails the step)."""
    if "revocable" not in body:
        return PURPOSES[purpose]["revocable"]
    said = revocable_said(body)
    return True if said is None else said


REVOCABLE_RECORDS = ".broker-source-read-revocable"


def revocable_record(token_path: str | pathlib.Path, env: dict) -> pathlib.Path:
    """Where mint records the broker's `revocable` for one token file, so revoke mode follows the broker:
    <RUNNER_TEMP>/.broker-source-read-revocable/<sha256 of the token file's realpath>, holding `true` or `false`.
    Outside the token file (a consumer reads that as the raw token) and outside token-dir (one file per repository).
    Written only when the reply carried a boolean; no record means the purpose's rule. Mint and revoke run in one job,
    and the runner empties RUNNER_TEMP only at job start and end."""
    key = hashlib.sha256(os.path.realpath(token_path).encode("utf-8", "surrogateescape")).hexdigest()
    return pathlib.Path(env["RUNNER_TEMP"]) / REVOCABLE_RECORDS / key


def _recorded_revocable(record: pathlib.Path) -> tuple[bool | None, str]:
    """(the recorded `revocable`, a problem). (None, '') with no record. An unreadable or malformed record is (True,
    problem): what is unclear is revoked, then that file fails."""
    try:
        text = record.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as err:
        return True, f"its revocable record cannot be read ({type(err).__name__})"
    if text in ("true", "false"):
        return text == "true", ""
    return True, "its revocable record is malformed"


def cached_output(cached: dict[str, str]) -> str:
    """The step output for several repositories: their common value, or 'mixed'."""
    values = set(cached.values())
    return values.pop() if len(values) == 1 else "mixed"


def revoke_token(token: str, api: str, http: Callable, sleep: Callable) -> str:
    """DELETE <api>/installation/token with the token itself: 'revoked' (204) or 'already gone' (401/404); any other
    answer, after the bounded retry, raises LegFailed."""
    status, _ = _call("revoke", "DELETE", api.rstrip("/") + "/installation/token",
                      {"Authorization": f"token {token}", **GITHUB_HEADERS}, None, http, sleep, ok=(204, 401, 404))
    return "revoked" if status == 204 else "already gone"


def _revoke_noting(token: str, api: str, http: Callable, sleep: Callable) -> str:
    """revoke_token's outcome in words, never an exception: it runs while another failure is on its way out, and a
    failing revoke must never replace that failure."""
    try:
        return revoke_token(token, api, http, sleep)
    except LegFailed as err:
        return f"NOT revoked ({err}); it expires within the hour"
    except Exception as err:                       # noqa: BLE001 -- the type only, as in main()
        return f"NOT revoked (unexpected {type(err).__name__}); it expires within the hour"


def wait_ready(tokens: dict[str, str], api: str, bound: float, http: Callable, sleep: Callable,
               clock: Callable[[], float]) -> dict[str, int]:
    """GET <api>/repos/<owner>/<name> with each token until it answers 200, within ONE wall-clock bound for all.
    {repository: attempts}, or LegFailed naming the repository and the last answer."""
    deadline, attempts = clock() + bound, {}
    for repo, token in tokens.items():
        n, delay, last = 0, 1.0, ""
        while True:
            n += 1
            remaining = deadline - clock()
            try:
                status, _ = http("GET", f"{api.rstrip('/')}/repos/{repo}", {"Authorization": f"token {token}",
                                                                            **GITHUB_HEADERS},
                                 None, max(1.0, min(10.0, remaining)))
                last = f"HTTP {status}"
            except TRANSPORT_ERRORS as err:
                status, last = 0, f"transport {type(err).__name__}"
            if status == 200:
                attempts[repo] = n
                break
            remaining = deadline - clock()
            if remaining <= 0:
                raise LegFailed(f"readiness {repo}: the token cannot see it after {bound:g} s (last answer {last}, "
                                f"{n} attempt(s)): grant or installation scope?")
            sleep(min(delay, remaining))
            delay = min(delay * 2, 8.0)
    return attempts


def mint(purpose: str, repositories: list[str], resource: str, service_account: str, audience: str, api: str,
         readiness: float, env: dict, http: Callable, sleep: Callable, clock: Callable, out,
         deliver: Callable[[dict[str, str], dict[str, str], dict[str, bool | None]], None]
         = lambda tokens, cached, said: None) -> dict[str, str]:
    """{repository: token}, every one echo-checked, visible and handed to `deliver` (which writes them) with
    {repository: cached_echo} and {repository: revocable_said}; or the failure.

    Each token is recorded the moment it is received and masked, with whether it is revocable (revocable_echo). From
    then on ANY failure (an echo mismatch, a readiness timeout, a transport error, a write error in `deliver`, an
    unexpected exception, an interrupt) first revokes, then re-raises THE ORIGINAL exception unchanged; a failing
    revoke is reported, never raised in its place.
      - A token whose echo check failed is revoked whatever its purpose and whatever the broker says: it is wrong for
        every holder. A present non-boolean `revocable` is such a failure. EXCEPT when the ONLY problem is an absent
        permissions echo and the token is not revocable: the step still fails, and the shared token is left alone.
      - Every other token is revoked when it is revocable: the broker's `revocable` when the reply carries it, else
        the purpose's rule. Under that rule an older broker's build_checkout token is not revoked: it is the broker's
        cached token for this caller (Minter's cache scope; SOURCE_READ_UNCACHED_PURPOSES), shared by every job of the
        caller, so revoking it would revoke it under all of them. It is not orphaned: the broker holds it, and it
        expires within the hour.
    A token whose value is malformed (mask refuses it) is never sent anywhere, revoke included."""
    oidc = github_oidc(resource, env, http, sleep, out)
    access = federated_access_token(resource, oidc, http, sleep, out)
    id_token = broker_id_token(service_account, audience, access, http, sleep, out)
    obtained: dict[str, str] = {}
    revocable: dict[str, bool] = {}
    said: dict[str, bool | None] = {}
    cached: dict[str, str] = {}
    try:
        for repo in repositories:
            leg = f"broker source.read {repo} ({purpose})"
            _, body = _call(leg, "POST", audience + "/v1/source/read",
                            {"Authorization": f"Bearer {id_token}", "Content-Type": "application/json"},
                            json.dumps({"repository": repo, "purpose": purpose}).encode(), http, sleep)
            obtained[repo] = mask(body.get("token"), leg, out)
            revocable[repo], said[repo] = revocable_echo(body, purpose), revocable_said(body)
            problems = echo_problems(body, repo, purpose)
            if problems:
                tok = obtained.pop(repo)
                if problems == [NO_PERMISSIONS_ECHO] and not revocable[repo]:
                    # An ABSENT echo is not evidence of a wrong token: a broker older than the echo sends none. A
                    # token that is not revocable is the broker's SHARED cache entry for this caller, so revoking it
                    # would revoke it under every concurrent and later job of that caller (platform #1205,
                    # 2026-10-28 19:47Z). Fail closed, and leave it to the broker.
                    raise LegFailed(f"{leg}: echo check failed: {NO_PERMISSIONS_ECHO}; the token was NOT revoked: "
                                    f"{purpose} is not revocable here, so the broker shares it across this caller's "
                                    f"jobs")
                outcome = _revoke_noting(tok, api, http, sleep)
                raise LegFailed(f"{leg}: echo check failed: {'; '.join(problems)}; the token was {outcome}")
            cached[repo] = cached_echo(body)
        wait_ready(obtained, api, readiness, http, sleep, clock)
        deliver(obtained, cached, said)
    except BaseException as err:
        for repo, tok in obtained.items():
            if revocable.get(repo, PURPOSES[purpose]["revocable"]):
                outcome = _revoke_noting(tok, api, http, sleep)
                print(f"{'::warning::' if outcome.startswith('NOT') else ''}broker-source-read: the mint failed "
                      f"({type(err).__name__}) after {repo}'s token was obtained; that token was {outcome}",
                      file=sys.stderr, flush=True)
        raise
    return obtained


def _write_secret(path: pathlib.Path, token: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)


def _parse_repositories(text: str) -> list[str]:
    repos = [r.strip().removesuffix(".git").strip("/") for r in re.split(r"[\s,]+", text or "") if r.strip()]
    if not repos:
        raise Usage("repository is required: owner/name (several, separated by spaces, commas or newlines)")
    bad = [r for r in repos if not REPOSITORY_RE.fullmatch(r)]
    if bad:
        raise Usage(f"repositories must be owner/name, not {bad[0]!r}")
    if len({r.lower() for r in repos}) != len(repos):
        raise Usage("a repository is listed twice")
    return repos


def _api(env: dict) -> str:
    api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    if not API_RE.fullmatch(api):
        raise Usage("GITHUB_API_URL must be an https URL")
    return api


def _purpose(value: str) -> str:
    if value not in PURPOSES:
        raise Usage(f"unknown purpose {value[:40]!r}: one of {', '.join(sorted(PURPOSES))}")
    return value


def run_mint(a, env: dict, http: Callable, sleep: Callable, clock: Callable, out) -> int:
    purpose = _purpose(a.purpose)
    repos = _parse_repositories(a.repositories)
    resource = provider_resource(a.provider)
    if not SERVICE_ACCOUNT_RE.fullmatch(a.service_account.strip()):
        raise Usage("service_account must be <name>@<project>.iam.gserviceaccount.com")
    audience = a.audience.strip().rstrip("/")
    if not AUDIENCE_RE.fullmatch(audience):
        raise Usage("audience must be the broker's https origin, with no path")
    api = _api(env)
    if not (a.token_file or a.token_dir or a.github_output):
        raise Usage("say where the token goes: token-file, token-dir and/or github-output")
    if a.token_file and a.token_dir:
        raise Usage("token-file and token-dir are exclusive")
    if (a.token_file or a.github_output) and len(repos) != 1:
        raise Usage("token-file and github-output take exactly one repository; use token-dir for several")
    if PURPOSES[purpose]["revocable"] and (a.github_output or not (a.token_file or a.token_dir)):
        raise Usage(f"{purpose} tokens are revoked after use, which reads them from a file: give token-file or "
                    "token-dir, and no github-output")
    if a.github_output:
        if not OUTPUT_NAME_RE.fullmatch(a.github_output):
            raise Usage("github-output must be an output name")
        if not env.get("GITHUB_OUTPUT"):
            raise Usage("GITHUB_OUTPUT is not set")
    if not 1 <= a.readiness_seconds <= 600:
        raise Usage("readiness-seconds must be between 1 and 600")
    # Every place the token is written: strictly inside RUNNER_TEMP. The runner keeps its GITHUB_OUTPUT file there too
    # (actions/runner 4197182e: runner.temp is WellKnownDirectory.Temp, TempDirectoryManager.cs:24,31, emptied at
    # job start and end, :35,:54; file commands live in <Temp>/_runner_file_commands, FileCommandManager.cs:21,32),
    # so it is held to the same rule when the token goes to it.
    if a.token_file:
        inside_runner_temp(a.token_file, "token-file", env)
    if a.token_dir:
        inside_runner_temp(a.token_dir, "token-dir", env)
    if a.github_output:
        inside_runner_temp(env["GITHUB_OUTPUT"], "GITHUB_OUTPUT file the token is written to", env)

    def deliver(tokens: dict[str, str], cached: dict[str, str], said: dict[str, bool | None]) -> None:
        """Write every token (each after its revocable record, when the broker said), then the step outputs, all or
        nothing: on any failure each file already written is removed again, then the failure goes on to mint(), which
        revokes and re-raises it. An OSError becomes LegFailed naming its type. Last, one log line per repository."""
        if not (a.token_file or a.token_dir):
            sure = [r for r in repos if said[r] is True]
            if sure:
                # Revoke mode reads a token from its file, so a revocable token with no file could never be revoked.
                raise LegFailed(f"{sure[0]}: the broker marks this token revocable, and revoke reads a token from its "
                                "file: give token-file or token-dir, not github-output alone")
        written: list[pathlib.Path] = []

        def write(path: pathlib.Path, repo: str) -> None:
            if said[repo] is not None:
                written.append(revocable_record(path, env))
                _write_secret(written[-1], "true" if said[repo] else "false")
            written.append(path)
            _write_secret(path, tokens[repo])
        try:
            if a.token_file:
                write(pathlib.Path(a.token_file), repos[0])
            if a.token_dir:
                d = pathlib.Path(a.token_dir)
                d.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(d, 0o700)
                for repo in tokens:
                    write(d / repo.replace("/", "__"), repo)
            if env.get("GITHUB_OUTPUT"):
                with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
                    if a.github_output:
                        fh.write(f"{a.github_output}={tokens[repos[0]]}\n")
                    fh.write(f"cached={cached_output(cached)}\n")
        except BaseException as err:
            for p in written:
                try:
                    p.unlink()
                except (FileNotFoundError, NotADirectoryError):
                    pass                           # never written (a missing or non-directory parent)
                except OSError as gone:
                    print(f"::warning::broker-source-read: {p.name} could not be removed after the failure "
                          f"({type(gone).__name__}); the runner empties RUNNER_TEMP when the job ends", file=sys.stderr)
            if isinstance(err, OSError):
                raise LegFailed(f"writing the token failed ({type(err).__name__})") from None
            raise
        perms = ",".join(f"{k}:{v}" for k, v in sorted(PURPOSES[purpose]["permissions"].items()))
        for repo in repos:
            c = cached[repo] + ("" if cached[repo] != "unknown" else " (the broker's reply does not say)")
            r = (str(said[repo]).lower() + " (the broker says)" if said[repo] is not None else
                 str(PURPOSES[purpose]["revocable"]).lower() + f" ({purpose}'s rule: the broker's reply does not say)")
            print(f"broker-source-read: {repo} minted for {purpose} ({perms}); cached: {c}; revocable: {r}; echo "
                  "checked; visible", file=sys.stderr)

    mint(purpose, repos, resource, a.service_account.strip(), audience, api, a.readiness_seconds, env, http, sleep,
         clock, out, deliver)
    return 0


def _token_files(a, env: dict) -> list[pathlib.Path]:
    if bool(a.token_file) == bool(a.token_dir):
        raise Usage("revoke reads exactly one of token-file or token-dir")
    if a.token_file:
        return [inside_runner_temp(a.token_file, "token-file", env)]
    d = inside_runner_temp(a.token_dir, "token-dir", env)
    try:
        if not (d.exists() or d.is_symlink()):
            return []
        if d.is_symlink() or not d.is_dir():
            raise LegFailed(f"revoke: {d} is not a directory")
        files = sorted(d.iterdir())
    except OSError as err:
        raise LegFailed(f"revoke: {d} cannot be listed ({type(err).__name__})") from None
    stray = [p.name for p in files if not TOKEN_FILE_RE.fullmatch(p.name)]
    if stray:
        raise LegFailed(f"revoke: {d} holds a file that is not a token file: {stray[0]!r}")
    return files


def _present(path: pathlib.Path) -> bool:
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return True                                # cannot tell: the per-file handler reports it


def run_revoke(a, env: dict, http: Callable, sleep: Callable, out) -> int:
    """Each file on its own: one that cannot be read (unreadable, vanished, not UTF-8), revoked or removed is
    reported as it happens, the remaining files are still revoked and removed, and the exit is 1 at the end."""
    purpose = _purpose(a.purpose)
    api = _api(env)
    files = _token_files(a, env)
    failed: list[str] = []
    present = [p for p in files if _present(p)]
    if not present:
        print("broker-source-read: no token file, so nothing to revoke (the mint did not write one)", file=sys.stderr)
    for path in present:
        record = revocable_record(path, env)
        try:
            if path.is_symlink() or not path.is_file():
                raise LegFailed(f"revoke {path.name}: not a regular file")
            token = mask(path.read_text(encoding="utf-8").strip(), f"revoke {path.name}", out)
            recorded, problem = _recorded_revocable(record)
            if recorded if recorded is not None else PURPOSES[purpose]["revocable"]:
                by = " (the broker said revocable)" if recorded is not None else ""
                print(f"broker-source-read: {path.name}: {revoke_token(token, api, http, sleep)}{by}", file=sys.stderr)
            elif recorded is False:
                print(f"::notice::broker-source-read: {path.name}: the broker marked this token not revocable, so it "
                      "is not revoked (it expires within the hour); the file is removed", file=out, flush=True)
            else:
                print(f"::notice::broker-source-read: {path.name}: a {purpose} token is cached by the broker and "
                      "shared by every job of this caller, so it is not revoked (it expires within the hour); the "
                      "file is removed", file=out, flush=True)
            if problem:
                raise LegFailed(f"revoke {path.name}: {problem}; the token was revoked")
        except LegFailed as err:
            print(f"::error::broker-source-read: {err}", file=sys.stderr)
            failed.append(path.name)
        except (OSError, ValueError) as err:       # ValueError: UnicodeDecodeError, a file that is not UTF-8
            print(f"::error::broker-source-read: revoke {path.name}: the token file could not be read "
                  f"({type(err).__name__}); the remaining files are still revoked", file=sys.stderr)
            failed.append(path.name)
        finally:
            for gone, what in ((path, "the file"), (record, "its revocable record")):
                try:
                    gone.unlink(missing_ok=True)
                except OSError as err:
                    print(f"::error::broker-source-read: revoke {path.name}: {what} could not be removed "
                          f"({type(err).__name__})", file=sys.stderr)
                    if path.name not in failed:
                        failed.append(path.name)
    if a.token_dir:
        try:
            pathlib.Path(a.token_dir).rmdir()
        except OSError:
            pass
    if failed:
        print(f"::error::broker-source-read: revoke: {len(failed)} of {len(present)} token file(s) failed: "
              f"{', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str], env: dict | None = None, http: Callable = _http,
         sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic, out=None) -> int:
    env = dict(os.environ) if env is None else env
    out = sys.stdout if out is None else out
    p = argparse.ArgumentParser(prog="client.py", description=__doc__.split("\n", 1)[0])
    sub = p.add_subparsers(dest="mode", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--purpose", required=True)
    m.add_argument("--repositories", required=True, metavar="OWNER/NAME[,...]")
    m.add_argument("--provider", required=True)
    m.add_argument("--service-account", required=True)
    m.add_argument("--audience", required=True, help="the broker's https origin")
    m.add_argument("--token-file", default="")
    m.add_argument("--token-dir", default="")
    m.add_argument("--github-output", default="", metavar="NAME")
    m.add_argument("--readiness-seconds", type=float, default=60.0)
    r = sub.add_parser("revoke")
    r.add_argument("--purpose", required=True)
    r.add_argument("--token-file", default="")
    r.add_argument("--token-dir", default="")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        if a.mode == "mint":
            return run_mint(a, env, http, sleep, clock, out)
        return run_revoke(a, env, http, sleep, out)
    except Usage as err:
        print(f"::error::broker-source-read: {err}", file=sys.stderr)
        return 2
    except LegFailed as err:
        print(f"::error::broker-source-read failed at {err}", file=sys.stderr)
        return 1
    except Exception as err:                       # noqa: BLE001 -- the type only: a message may carry a credential
        print(f"::error::broker-source-read failed: unexpected {type(err).__name__} (message withheld; it may carry "
              "a credential)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
