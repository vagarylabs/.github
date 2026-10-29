#!/usr/bin/env python3
"""Change-impact planner: decide which CI work a change can affect, deterministically.

This is a DETERMINISTIC cognitive operator (cognition-ladder ruling, 2026-10-01): the same inputs always
give the same plan. Determinism does not establish completeness of a declared dependency graph.
The decision record carries a validity predicate. When the
predicate's inputs change, the record is stale and the plan must be recomputed. Anything it cannot decide
for certain becomes mode=full. It never skips silently: every skipped job carries a reason and the plan id.

Inputs
  --config        the repo's plan config (JSON), read from the BASE commit, so a change cannot weaken its own plan
  --root          a checkout of the BASE commit holding at least the manifests the config needs
  --paths-file    changed paths, one per line (a rename lists both names)
  --expected-count  the number of changed files the host reports; a different count means truncation -> full
  --event / --base / --head
Outputs
  --out-json      the decision record (also printed)
  --github-output appends plan, mode, plan_id, run (job -> bool) and matrices (name -> include list)

Method (version PLANNER_VERSION)
  1. Not a pull request, no config, no paths, or a truncated list => full.
  2. Any path matching a BUILTIN full trigger (workflows, CI config, lockfiles, manifests, workspace files,
     migrations) or a config `full_globs` => full. Config cannot remove a builtin trigger.
  3. Paths matching `inert_globs` affect no package. Each other path maps to the package whose directory
     is its longest prefix, or to the packages listed in `extra_edges` for a glob it matches. A path that
     maps to nothing => full (unknown impact).
  4. affected = changed packages + every package that depends on one, transitively (reverse closure of
     the workspace graph read from the manifests).
  5. Any `hub_packages` member affected => full.
  6. Otherwise each job and matrix entry runs iff its rule matches the affected set.
  Canonical entrypoint v1.3 observes the frozen candidate with Git.
  Its information-only cumulative impact record reuses this same graph computation;
  supported reader assessment and modeled impact never grant qualification or activation. Legacy --paths-file and
  --receipt inputs never authorize reduced/reused execution. The historical receipt comparison
  helper is retained for compatibility tests; the action/CLI do not admit run-result reuse.

Source answer (v1.4)
  Every record carries `source_answer`: the SRC-01 source-context envelope (vagary-core contracts/source/v1)
  for the change the planner observed, WITHOUT `authorization`. A CI job token is not a source-access grant,
  so the planner never fills that field; a consumer must acquire the canonical authorize() result itself.
  Completeness is derived, never asserted: an unknown or moved scope, a truncated path list, an absent or
  unbound reader assessment, unverified build metadata (including a sparse policy checkout missing a tracked
  manifest, lockfile, workflow or config), an analyzer the base policy does not accept, missing provider
  identity, an unobservable checkout representation, or a provider witness that is truncated, capped,
  throttled, malformed or disagrees with Git all make it partial/unknown, and the plan is then FULL.
  The optional provider witness (--source-query witness) asks the provider's compare API at the pinned
  SHAs, with finite caps; it can only widen a plan, never narrow one.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PLANNER_VERSION = "1.5.1"
OPERATOR_ID = "ci.change-impact-plan"
ANALYZER = {"id": OPERATOR_ID, "version": PLANNER_VERSION}

# The envelope shape follows SRC-01 as reviewed in vagary-core #794 (unmerged at this revision). The schema
# file is private to that repository and is not copied here; consumers validate against their vendored copy.
SOURCE_CONTRACT = {"repository": "vagarylabs/vagary-core", "path": "contracts/source/v1/source-context.schema.json",
                   "revision": "fb01fe28a617ef38f6dbf85b0bdac8821a40bd65",
                   "sha256": "bb4ca00940eb3da6fd31b4893c8c9c352d7fc9ade357603548fb64c4c72f92df",
                   "omitted": ["authorization"]}
# Same character rules as the SRC-01 path pattern: relative, no dot segments, no backslash or control bytes.
SAFE_PATH = re.compile(r"(?!/)(?!.*(?:^|/)\.\.?(?:/|$))(?![\s\S]*[\\\x00-\x1f\x7f])[\s\S]{1,4096}")
NUMERIC_ID = re.compile(r"[1-9][0-9]{0,19}")

# Provider witness caps. They mirror the existing vagaris reader (server/src/services/acquisition-connectors/
# github-api-client.ts readComparisonFiles/parseGitComparison): GitHub returns at most 300 files for a whole
# comparison and gives no total, so 300 cannot prove completeness; more than 100 commits, or any pagination,
# is outside the complete bounded read. Reaching any cap is incomplete, never a smaller answer.
PROVIDER_FILE_CEILING = 300
PROVIDER_COMMIT_BOUND = 100
PROVIDER_MAX_BYTES = 8 * 1024 * 1024
PROVIDER_TIMEOUT_SECONDS = 15
PROVIDER_CAPS = {"file_ceiling": PROVIDER_FILE_CEILING, "commit_bound": PROVIDER_COMMIT_BOUND,
                 "max_bytes": PROVIDER_MAX_BYTES, "timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
                 "max_requests": 1, "pagination": "refused"}
PROVIDER_FILE_STATUSES = {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}


def canonical_coordinates(repository: str, target_ref: str, server_url: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(p in (".", "..") for p in repository.split("/")):
        raise ValueError("invalid canonical repository")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?", server_url):
        raise ValueError("invalid canonical server")
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*", target_ref) or ".." in target_ref or "//" in target_ref \
        or target_ref.endswith("/") or target_ref.startswith("refs/heads/gh-readonly-queue/") \
        or any(part.startswith(".") or part.endswith(".lock") for part in target_ref.split("/")):
        raise ValueError("invalid canonical target ref")


def canonical_target(repository: str, target_ref: str, server_url: str) -> str:
    """Resolve exactly one trusted HTTPS ref without candidate Git configuration or logged credentials."""
    canonical_coordinates(repository, target_ref, server_url)
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    options = [("core.hooksPath", os.devnull), ("credential.helper", ""), ("http.followRedirects", "false")]
    token = os.environ.get("GH_TOKEN", "")
    if token:
        credential = base64.b64encode(("x-access-token:" + token).encode()).decode()
        options.append((f"http.{server_url}/.extraheader", "AUTHORIZATION: basic " + credential))
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_COUNT=str(len(options)))
    for number, (key, value) in enumerate(options):
        env[f"GIT_CONFIG_KEY_{number}"] = key
        env[f"GIT_CONFIG_VALUE_{number}"] = value
    with tempfile.TemporaryDirectory(prefix="ci-canonical-target-") as empty:
        # An explicit empty bare repository prevents parent-repository discovery through TMPDIR.
        subprocess.check_output(["git", "--no-replace-objects", "init", "--bare", "--template=", empty],
                                env=env, stderr=subprocess.PIPE, timeout=5)
        raw = subprocess.check_output(["git", "--no-replace-objects", "-C", empty, "ls-remote", "--refs",
            "--exit-code", server_url + "/" + repository + ".git", target_ref],
            env=env, stderr=subprocess.PIPE, timeout=15).decode("ascii")
    lines = raw.splitlines()
    if len(lines) != 1 or lines[0].split("\t")[1:] != [target_ref]:
        raise ValueError("ambiguous canonical target")
    sha = lines[0].split("\t")[0]
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or sha == "0" * 40:
        raise ValueError("invalid canonical target SHA")
    return sha


def target_context(repository, event_repository, target_ref, server_url, candidate, run_id, run_attempt):
    canonical_coordinates(repository, target_ref, server_url)
    if repository != event_repository or not re.fullmatch(r"[0-9a-f]{40}", candidate) or candidate == "0" * 40 \
        or not str(run_id).isdigit() or int(run_id) < 1 or not str(run_attempt).isdigit() or int(run_attempt) < 1:
        raise ValueError("invalid target context")
    return {"schema": 2, "scope_kind": "canonical-target-cumulative", "target_source": "canonical-git-ls-remote",
            "repository": repository, "target_ref": target_ref, "server_url": server_url,
            "candidate": candidate, "run_id": str(run_id), "run_attempt": str(run_attempt),
            "source_sha256": sha256_file(Path(__file__))}


def resolve_target_observation(**context):
    result = {"schema": 2, "status": "unknown", "reason": "canonical target snapshot unavailable"}
    try:
        result.update(target_context(**context))
        result.update(status="known", target_sha=canonical_target(context["repository"], context["target_ref"], context["server_url"]))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    return result


# ---------- provider witness (rung 1: an authorized query at pinned revisions, no files materialized) ----------

class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never follow a provider-supplied location


PROVIDER_HEADER_BYTES = 65536
PROVIDER_REAP_SECONDS = 1


def _provider_http_worker():
    """One isolated urllib request. Credentials arrive only on the private stdin pipe.

    The parent owns the absolute deadline, including DNS/connect/TLS/HTTP headers.
    Socket timeouts here are an additional inactivity bound, not that deadline.
    """
    try:
        raw = sys.stdin.buffer.read(PROVIDER_HEADER_BYTES + 1)
        if len(raw) > PROVIDER_HEADER_BYTES:
            raise ValueError("request too large")
        url, headers, timeout, max_bytes = json.loads(raw)
        if not isinstance(url, str) or not isinstance(headers, dict) or type(max_bytes) is not int \
                or not 0 <= max_bytes <= PROVIDER_MAX_BYTES or not 0 < timeout <= PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("invalid request")
        opener = urllib.request.build_opener(_RefuseRedirect)
        request = urllib.request.Request(url, headers=headers, method="GET")
        body = b""
        try:
            with opener.open(request, timeout=timeout) as response:
                chunks, size = [], 0
                while size <= max_bytes:
                    chunk = response.read1(min(65536, max_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                status, response_headers, body = response.status, dict(response.headers), b"".join(chunks)
        except urllib.error.HTTPError as error:
            try:
                status, response_headers = error.code, dict(error.headers or {})
            finally:
                error.close()
        metadata = json.dumps([status, {k.lower(): v for k, v in response_headers.items()}]).encode()
        if len(metadata) > PROVIDER_HEADER_BYTES:
            raise ValueError("response headers too large")
        sys.stdout.buffer.write(metadata + b"\n" + body)
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        # No URL, token, provider response or exception text goes to logs.
        return 2


def https_transport(url: str, headers: dict, timeout: float, max_bytes: int) -> tuple[int, dict, bytes]:
    """One cancellable GET; parent deadline covers process startup and every HTTP phase.

    POSIX runner transport (selectors on pipes). A body over the cap returns
    max_bytes+1 bytes. Catchable exceptions/interruptions kill and reap the owned
    worker. Abrupt parent termination requires runner process-group cleanup.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= PROVIDER_TIMEOUT_SECONDS \
            or type(max_bytes) is not int or not 0 <= max_bytes <= PROVIDER_MAX_BYTES:
        raise ValueError("invalid provider bounds")
    deadline = time.monotonic() + timeout
    payload = json.dumps([url, headers, timeout, max_bytes]).encode()
    if len(payload) > PROVIDER_HEADER_BYTES:
        raise ValueError("provider request headers too large")
    env = {key: value for key, value in os.environ.items() if key not in ("GH_TOKEN", "GITHUB_TOKEN")}
    selector = selectors.DefaultSelector()
    worker = None
    try:
        worker = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--provider-http-worker"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        output, sent = bytearray(), 0
        bound = PROVIDER_HEADER_BYTES + 1 + max_bytes + 1
        os.set_blocking(worker.stdin.fileno(), False)
        os.set_blocking(worker.stdout.fileno(), False)
        selector.register(worker.stdin, selectors.EVENT_WRITE)
        selector.register(worker.stdout, selectors.EVENT_READ)
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("provider request deadline exceeded")
            for key, _ in selector.select(left):
                if key.fileobj is worker.stdin:
                    try:
                        sent += os.write(worker.stdin.fileno(), payload[sent:sent + 4096])
                    except BrokenPipeError:
                        raise ValueError("provider worker unavailable") from None
                    if sent == len(payload):
                        selector.unregister(worker.stdin)
                        worker.stdin.close()
                else:
                    chunk = os.read(worker.stdout.fileno(), min(65536, bound + 1 - len(output)))
                    if not chunk:
                        selector.unregister(worker.stdout)
                    else:
                        output.extend(chunk)
                        if len(output) > bound:
                            raise ValueError("provider response exceeded bound")
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("provider request deadline exceeded")
        try:
            result = worker.wait(timeout=left)
        except subprocess.TimeoutExpired:
            raise TimeoutError("provider request deadline exceeded") from None
        if result:
            raise ValueError("provider request unavailable")
        metadata, separator, body = bytes(output).partition(b"\n")
        if not separator or len(metadata) > PROVIDER_HEADER_BYTES or len(body) > max_bytes + 1:
            raise ValueError("invalid provider response framing")
        status, response_headers = json.loads(metadata)
        if type(status) is not int or not isinstance(response_headers, dict):
            raise ValueError("invalid provider response framing")
        return status, response_headers, body
    finally:
        try:
            selector.close()
        finally:
            if worker is not None:
                if worker.poll() is None:
                    worker.kill()
                try:
                    worker.wait(timeout=PROVIDER_REAP_SECONDS)
                except subprocess.TimeoutExpired:
                    raise OSError("provider worker reap unavailable") from None
                finally:
                    worker.stdin.close()
                    worker.stdout.close()


def _comparison_matches(body: dict, base: str, head: str) -> bool:
    """Port of vagaris parseGitComparison: the answer must establish exactly the requested commits."""
    sha = re.compile(r"[0-9a-f]{40}")
    commits = body.get("commits")
    ahead, behind, total = body.get("ahead_by"), body.get("behind_by"), body.get("total_commits")
    merge_base = (body.get("merge_base_commit") or {}).get("sha") if isinstance(body.get("merge_base_commit"), dict) else None
    base_commit = (body.get("base_commit") or {}).get("sha") if isinstance(body.get("base_commit"), dict) else None
    if base_commit != base or not isinstance(merge_base, str) or not sha.fullmatch(merge_base) \
            or body.get("status") not in ("ahead", "behind", "identical", "diverged") \
            or type(ahead) is not int or ahead < 0 or type(behind) is not int or behind < 0 \
            or not isinstance(commits, list) or type(total) is not int or total != len(commits) \
            or total > PROVIDER_COMMIT_BOUND or ahead != total \
            or any(not isinstance(c, dict) or not isinstance(c.get("sha"), str) or not sha.fullmatch(c["sha"]) for c in commits):
        return False
    if ahead > 0 and commits[-1]["sha"] != head:
        return False
    status = body["status"]
    if status == "identical" and (base != head or ahead or behind):
        return False
    if status == "ahead" and (ahead < 1 or behind != 0 or merge_base != base):
        return False
    if status == "behind" and (behind < 1 or ahead != 0 or merge_base != head):
        return False
    if status == "diverged" and (ahead < 1 or behind < 1):
        return False
    # The planner diffs base..candidate. Only a comparison whose merge base IS the base names that file set.
    return merge_base == base


def provider_compare(repository: str, base: str, head: str, *, token: str, api_url: str,
                     transport=https_transport) -> dict:
    """Ask the provider which paths differ between two pinned SHAs. complete | partial | unknown; a partial or
    unknown answer carries no paths. Provider bodies and transport errors are never echoed."""
    request = {"operation": "compare", "repository": repository, "base_sha": base, "head_sha": head}
    result = {"status": "unknown", "reason": "provider_unavailable", "paths": None,
              "request_digest": canonical_digest(request), "caps": PROVIDER_CAPS}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(p in (".", "..") for p in repository.split("/")) \
            or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/api/v3)?", api_url or "") \
            or not all(re.fullmatch(r"[0-9a-f]{40}", value or "") for value in (base, head)):
        result["reason"] = "provider_request_invalid"
        return result
    if not token or any(ch.isspace() or ord(ch) < 32 for ch in token):
        result["reason"] = "provider_token_unavailable"
        return result
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": OPERATOR_ID + "/" + PLANNER_VERSION, "Authorization": "Bearer " + token}
    try:
        status, response_headers, body = transport(f"{api_url}/repos/{repository}/compare/{base}...{head}?per_page=100",
                                                   headers, PROVIDER_TIMEOUT_SECONDS, PROVIDER_MAX_BYTES)
    except TimeoutError:
        result["reason"] = "provider_deadline"
        return result
    except (OSError, ValueError, http.client.HTTPException):
        return result
    response_headers = {str(k).lower(): v for k, v in (response_headers or {}).items()}
    if status == 429 or (status == 403 and (response_headers.get("x-ratelimit-remaining") == "0"
                                            or "retry-after" in response_headers)):
        result["reason"] = "provider_throttled"
        return result
    if status != 200 or not isinstance(body, (bytes, bytearray)):
        return result
    if len(body) > PROVIDER_MAX_BYTES:
        result.update(status="partial", reason="provider_response_cap")
        return result
    try:
        answer = json.loads(body)
    except (ValueError, UnicodeError):
        result["reason"] = "provider_malformed"
        return result
    if not isinstance(answer, dict) or not isinstance(answer.get("files"), list):
        result["reason"] = "provider_malformed"
        return result
    if len(answer["files"]) >= PROVIDER_FILE_CEILING:
        result.update(status="partial", reason="provider_file_ceiling")
        return result
    if type(answer.get("total_commits")) is int and answer["total_commits"] > PROVIDER_COMMIT_BOUND:
        result.update(status="partial", reason="provider_commit_bound")
        return result
    if "link" in response_headers:
        result.update(status="partial", reason="provider_paginated")
        return result
    if not _comparison_matches(answer, base, head):
        result["reason"] = "provider_mismatch"
        return result
    if answer["status"] in ("identical", "behind") and answer["files"]:
        result["reason"] = "provider_mismatch"
        return result
    paths, seen = set(), set()
    for row in answer["files"]:
        name = row.get("filename") if isinstance(row, dict) else None
        previous = row.get("previous_filename") if isinstance(row, dict) else None
        if not isinstance(name, str) or not SAFE_PATH.fullmatch(name) or name in seen \
                or not isinstance(row.get("status"), str) or row["status"] not in PROVIDER_FILE_STATUSES \
                or (previous is not None and (not isinstance(previous, str) or not SAFE_PATH.fullmatch(previous))) \
                or (row.get("status") == "renamed" and (previous is None or previous == name)):
            result["reason"] = "provider_malformed"
            return result
        seen.add(name)
        paths.add(name)
        if row.get("status") == "renamed":
            paths.add(previous)  # Git's --no-renames diff lists the old name as a deletion
    result.update(status="complete", reason=None, paths=sorted(paths))
    return result


def git_policy(root: Path, *args) -> str:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), *args],
                                   env=env, stderr=subprocess.PIPE, timeout=5).decode().strip()


def verify_target_policy(git, root: Path, target: str, config: str) -> dict:
    if not config or config.startswith("/") or any(part in ("", ".", "..") for part in config.split("/")) or "\n" in config or "\r" in config:
        raise ValueError("invalid policy path")
    metadata = {config, "pnpm-workspace.yaml", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"}
    tracked = {}
    for entry in git("ls-tree", "-r", "-z", target).split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if path in metadata or path == "package.json" or path.endswith("/package.json") or path.startswith(".github/workflows/"):
            mode, kind, blob = header.decode("ascii").split()
            if mode not in ("100644", "100755") or kind != "blob":
                raise ValueError("policy metadata is not a regular blob")
            local = root / path
            if local.is_symlink() or not local.is_file() or not local.resolve().is_relative_to(root.resolve()):
                raise ValueError("policy metadata checkout incomplete")
            data = local.read_bytes()
            if data != git("cat-file", "blob", blob):
                raise ValueError("policy metadata differs from target")
            tracked[path] = (blob, hashlib.sha256(data).hexdigest())
    actual_manifests = {path.relative_to(root).as_posix() for path in root.rglob("package.json")}
    if actual_manifests != {path for path in tracked if path == "package.json" or path.endswith("/package.json")}:
        raise ValueError("unexpected policy metadata")
    # The metadata the planner actually read; recorded as the envelope's materialized inputs.
    paths = sorted(tracked)
    if config not in tracked:
        if (root / config).exists():
            raise ValueError("untracked policy config")
        return {"policy_blob": None, "policy_sha256": None, "policy_paths": paths}
    blob, digest = tracked[config]
    return {"policy_blob": blob, "policy_sha256": digest, "policy_paths": paths}


def git_observe(root: Path, *args, ok=(0,)) -> tuple[int, bytes]:
    """Read-only Git query under the same isolated environment; returns (exit code, stdout)."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    done = subprocess.run(["git", "--no-replace-objects", "-C", str(root), *args],
                          env=env, capture_output=True, timeout=5)
    if done.returncode not in ok:
        raise ValueError("git observation failed")
    return done.returncode, done.stdout


def shallow_depth(root: Path, limit: int = 100000) -> int:
    """Generations fetched below HEAD in a shallow repository (git fetch --depth semantics)."""
    _, raw = git_observe(root, "rev-list", "--parents", "--max-count=" + str(limit + 1), "HEAD")
    rows = raw.decode("ascii").split("\n")
    rows = [row.split() for row in rows if row]
    if not rows or len(rows) > limit:
        raise ValueError("history too large to observe")
    parents = {row[0]: row[1:] for row in rows}
    head = rows[0][0]
    distance, frontier = {head: 0}, [head]
    while frontier:
        following = []
        for commit in frontier:
            for parent in parents.get(commit, ()):
                if parent in parents and parent not in distance:
                    distance[parent] = distance[commit] + 1
                    following.append(parent)
        frontier = following
    if len(distance) != len(parents):
        raise ValueError("unreachable shallow history")
    return max(distance.values()) + 1


def observe_representation(root: Path) -> dict | None:
    """How the candidate checkout was materialized: history depth, clone filter and sparse patterns.
    These dimensions are independent (sparse is not partial clone). Anything unrepresentable is None."""
    try:
        _, shallow = git_observe(root, "rev-parse", "--is-shallow-repository")
        shallow = shallow.decode("ascii").strip()
        if shallow == "true":
            depth = shallow_depth(root)
        elif shallow == "false":
            depth = 0
        else:
            return None
        code, filters = git_observe(root, "config", "--get-regexp", r"^remote\..*\.partialclonefilter$", ok=(0, 1))
        values = {line.split(" ", 1)[1].strip() if " " in line else "" for line in filters.decode("utf-8").splitlines() if line}
        promisor, _ = git_observe(root, "config", "--get", "extensions.partialclone", ok=(0, 1))
        if not values:
            if promisor == 0:
                return None
            clone_filter = "none"
        elif values == {"blob:none"}:
            clone_filter = "blob:none"
        elif all(re.fullmatch(r"blob:limit=[0-9]+[kmg]?", value) for value in values):
            clone_filter = "blob:limit"
        else:
            return None
        code, sparse = git_observe(root, "config", "--bool", "--get", "core.sparseCheckout", ok=(0, 1))
        patterns = []
        if code == 0 and sparse.decode("ascii").strip() == "true":
            _, location = git_observe(root, "rev-parse", "--git-path", "info/sparse-checkout")
            path = Path(location.decode("utf-8").strip())
            path = path if path.is_absolute() else root / path
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                value = line[1:] if line.startswith("/") else line
                value = value[:-1] if value.endswith("/") else value
                if line.startswith("!") or not SAFE_PATH.fullmatch(value):
                    return None
                patterns.append(value)
        return {"rung": "required_history", "sparse": {"enabled": bool(patterns), "paths": sorted(set(patterns))},
                "clone_filter": clone_filter, "history_depth": depth}
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None


def immutable_scope(root: Path, *, event: str, base: str, head: str,
                    candidate: str, repository: str, target_observation: dict | None = None,
                    target_ref: str = "", server_url: str = "", event_repository: str = "",
                    policy_root: Path | None = None, config: str = ".github/ci-plan.json",
                    run_id: str = "", run_attempt: str = "", policy_checkout_outcome: str = "",
                    repository_id: str = "", repository_owner_id: str = "") -> dict:
    """Observe the frozen integration tree. Mutable refs and PR APIs are not inputs."""
    result = {"schema": 1, "event": event, "repository": repository,
              "base": base, "head": head, "candidate": candidate,
              "tree": None, "paths": None, "status": "unknown",
              "repository_id": repository_id if NUMERIC_ID.fullmatch(repository_id or "") else None,
              "repository_owner_id": repository_owner_id if NUMERIC_ID.fullmatch(repository_owner_id or "") else None,
              "policy_status": "unverified", "representation": None}

    def git(*args):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("GIT_")}
        environment.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
                           GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(root), *args],
            stderr=subprocess.PIPE, timeout=5, env=environment)

    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("missing repository identity")
        for revision in (base, head, candidate):
            if not re.fullmatch(r"[0-9a-f]{40}", revision) or revision == "0" * 40:
                raise ValueError("missing immutable revision")
            git("cat-file", "-e", revision + "^{commit}")
        if git("rev-parse", "HEAD").decode().strip() != candidate:
            raise ValueError("checkout differs from candidate")
        # Read the object itself: a shallow graft must not erase its parent binding.
        headers = git("cat-file", "-p", candidate).split(b"\n\n", 1)[0].splitlines()
        parents = [line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")]
        if event == "pull_request":
            if parents != [base, head]:
                raise ValueError("event base/head differ from candidate parents")
        elif event == "merge_group":
            if head != candidate:
                raise ValueError("merge group head differs from candidate")
            expected = target_context(repository, event_repository, target_ref, server_url, candidate, run_id, run_attempt)
            observation = target_observation or {}
            if not isinstance(observation, dict) or policy_checkout_outcome != "success":
                raise ValueError("canonical policy checkout unavailable")
            if observation.get("status") != "known" or any(observation.get(key) != value for key, value in expected.items()):
                raise ValueError("canonical target observation missing or replayed")
            target = observation.get("target_sha", "")
            if not isinstance(target, str) or not re.fullmatch(r"[0-9a-f]{40}", target) or target == "0" * 40:
                raise ValueError("canonical target SHA invalid")
            git("cat-file", "-e", target + "^{commit}")
            git("merge-base", "--is-ancestor", base, candidate)
            git("merge-base", "--is-ancestor", target, candidate)
            if policy_root is None or git_policy(policy_root, "rev-parse", "HEAD") != target:
                raise ValueError("canonical policy checkout mismatch")
            policy = verify_target_policy(git, policy_root, target, config)
            result.update(schema=2, scope_kind="canonical-target-cumulative", target_source="canonical-git-ls-remote", server_url=server_url, event_base=base, target_ref=target_ref, target_sha=target, diff_base=target,
                          policy_revision=target, policy_path=config, run_id=str(run_id), run_attempt=str(run_attempt),
                          source_sha256=expected["source_sha256"], policy_status="verified", **policy)
            base = target
        elif event == "push":
            if head != candidate:
                raise ValueError("push head differs from candidate")
        else:
            raise ValueError("unsupported event")
        if event in ("pull_request", "push"):
            # The base policy checkout is sparse. Verify it against the base tree exactly as merge_group does,
            # so a checkout missing one tracked manifest/lockfile/workflow cannot shrink the graph unnoticed.
            # A failure keeps the observed scope but leaves build metadata unverified, which forces FULL.
            try:
                if policy_root is None or policy_checkout_outcome not in ("", "success") \
                        or git_policy(policy_root, "rev-parse", "HEAD") != base:
                    raise ValueError("base policy checkout unavailable")
                policy = verify_target_policy(git, policy_root, base, config)
                result.update(policy_status="verified", policy_revision=base, policy_path=config, **policy)
            except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
                result.update(policy_status="unverified", policy_reason=type(error).__name__)
        result["representation"] = observe_representation(root)
        raw = git("diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, candidate, "--")
        if raw and not raw.endswith(b"\0"):
            raise ValueError("incomplete path output")
        paths = [value.decode("utf-8") for value in raw.split(b"\0") if value]
        result.update(status="known", paths=paths,
                      tree=git("rev-parse", candidate + "^{tree}").decode("ascii").strip())
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        # Git stderr may contain credential-bearing remote URLs.
        result["reason"] = "immutable scope unavailable: " + type(error).__name__
    return result

# Paths that can change how CI itself, the dependency graph or the database behaves. Always full.
BUILTIN_FULL_GLOBS = [
    ".github/**",
    "**/package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package-lock.json",
    "yarn.lock",
    "npm-shrinkwrap.json",
    ".npmrc",
    ".nvmrc",
    ".node-version",
    ".tool-versions",
    "turbo.json",
    "nx.json",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "**/requirements*.txt",
    "**/migrations/**",
    "**/alembic/**",
    "**/prisma/**",
    "**/Dockerfile*",
]

# Every lockfile kind. At the root each is a builtin full trigger (above, where listed). Nested (root's ruling,
# 2026-10-29), it is its package's dependency input: it selects exactly its owning package and that package's reverse
# dependents, and a nested lockfile that maps to no package, or to several, plans FULL.
LOCKFILE_NAMES = frozenset({"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock",
                            "bun.lockb", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
                            "composer.lock"})

RULE_KINDS = ("always", "full_only", "any_package", "{packages: [..]}", "{any_except: [..]}")


def glob_to_regex(pattern: str) -> re.Pattern:
    """`**` crosses directories, `*` and `?` do not. A pattern without a slash matches at any depth only
    when written as `**/name`; a bare name matches the root only."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def first_match(path: str, globs: list[str]) -> str | None:
    for g in globs:
        if glob_to_regex(g).match(path):
            return g
    return None


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def sha256_tree(root: Path, rel_dir: str) -> str | None:
    base = root / rel_dir
    if not base.is_dir():
        return None
    h = hashlib.sha256()
    for p in sorted(x for x in base.rglob("*") if x.is_file()):
        h.update(str(p.relative_to(root)).encode() + b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


# ---------- workspace graph ----------

def read_pnpm_workspace_patterns(root: Path) -> list[str]:
    """Reads the `packages:` list of pnpm-workspace.yaml without a YAML dependency (the runner has none)."""
    text = (root / "pnpm-workspace.yaml").read_text()
    patterns, in_packages = [], False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw.startswith((" ", "\t", "-")):
            in_packages = line.strip() == "packages:"
            continue
        if in_packages:
            m = re.match(r"^\s*-\s*(.+?)\s*$", line)
            if m:
                patterns.append(m.group(1).strip().strip("'\""))
    if not patterns:
        raise ValueError("pnpm-workspace.yaml has no packages list")
    return patterns


def discover_pnpm_packages(root: Path, extra_deps: dict | None = None) -> dict[str, dict]:
    patterns = read_pnpm_workspace_patterns(root)
    include = [p for p in patterns if not p.startswith("!")]
    exclude = [p[1:] for p in patterns if p.startswith("!")]
    pkgs: dict[str, dict] = {}
    for manifest in sorted(root.rglob("package.json")):
        rel_dir = manifest.parent.relative_to(root).as_posix()
        if rel_dir == "." or "node_modules" in rel_dir.split("/"):
            continue
        if not any(glob_to_regex(p).match(rel_dir) for p in include):
            continue
        if any(glob_to_regex(p).match(rel_dir) or rel_dir.startswith(p.rstrip("/*") + "/") for p in exclude):
            continue
        data = json.loads(manifest.read_text())
        name = data.get("name")
        if not name:
            raise ValueError(f"{rel_dir}/package.json has no name")
        if name in pkgs:
            raise ValueError(f"duplicate workspace package name {name}")
        deps = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update((data.get(key) or {}).keys())
        pkgs[name] = {"dir": rel_dir, "deps": deps}
    for info in pkgs.values():
        info["deps"] = {d for d in info["deps"] if d in pkgs}
    extra = extra_deps or {}
    if set(extra) - set(pkgs):
        raise ValueError("extra_deps names an undeclared workspace package")
    for name, dependencies in extra.items():
        if not isinstance(dependencies, list) or any(not isinstance(dep, str) or dep not in pkgs for dep in dependencies):
            raise ValueError(f"extra_deps for {name} contains an undeclared dependency")
        pkgs[name]["deps"].update(dependencies)
    return pkgs


def declared_packages(cfg: dict) -> dict[str, dict]:
    """For repos without a JS workspace: `workspace.packages = {name: {"dir": "x", "deps": [..]}}`."""
    pkgs = {}
    extra = cfg.get("extra_deps") or {}
    for name, spec in (cfg.get("packages") or {}).items():
        pkgs[name] = {"dir": spec["dir"].rstrip("/"), "deps": set(spec.get("deps") or []) | set(extra.get(name) or [])}
    unknown_extra = set(extra) - set(pkgs)
    if unknown_extra:
        raise ValueError(f"extra_deps names undeclared package(s) {sorted(unknown_extra)}")
    for name, info in pkgs.items():
        unknown = info["deps"] - set(pkgs)
        if unknown:
            raise ValueError(f"package {name} depends on undeclared {sorted(unknown)}")
    return pkgs


def reverse_closure(pkgs: dict[str, dict], seeds: set[str]) -> set[str]:
    dependents: dict[str, set[str]] = {n: set() for n in pkgs}
    for name, info in pkgs.items():
        for d in info["deps"]:
            dependents[d].add(name)
    seen, stack = set(seeds), list(seeds)
    while stack:
        for nxt in dependents.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def owner_package(path: str, pkgs: dict[str, dict]) -> str | None:
    best, best_len = None, -1
    for name, info in pkgs.items():
        d = info["dir"]
        if (path == d or path.startswith(d + "/")) and len(d) > best_len:
            best, best_len = name, len(d)
    return best


# ---------- planning ----------

def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def graph_digest(pkgs: dict[str, dict]) -> str:
    return canonical_digest({"schema": 1, "packages": [
        {"name": name, "dir": info["dir"], "deps": sorted(info["deps"])}
        for name, info in sorted(pkgs.items())]})


def classify_paths(paths: list[str], cfg: dict, pkgs: dict[str, dict]) -> dict:
    """One path/owner/reverse-closure computation for legacy selection and informational impact."""
    evidence = {"full_triggers": [], "unmapped": [], "inert": [], "changed_packages": []}
    result = {"evidence": evidence, "affected": set(), "hubs": [], "error": None}
    full_globs = BUILTIN_FULL_GLOBS + list(cfg.get("full_globs") or [])
    evidence["full_triggers"] = [{"path": path, "rule": rule} for path in paths
                                 if (rule := first_match(path, full_globs))]
    if evidence["full_triggers"]:
        return result
    changed: set[str] = set()
    for path in paths:
        nested_lockfile = "/" in path and path.rsplit("/", 1)[1] in LOCKFILE_NAMES
        if not nested_lockfile and first_match(path, list(cfg.get("inert_globs") or [])):
            evidence["inert"].append(path)
            continue
        owners = set()
        for glob, targets in (cfg.get("extra_edges") or {}).items():
            if glob_to_regex(glob).match(path):
                owners.update(targets)
        owner = owner_package(path, pkgs)
        if owner:
            owners.add(owner)
        unknown = owners - set(pkgs)
        if unknown:
            result["error"] = f"extra_edges for {path} name unknown package(s) {sorted(unknown)}"
            return result
        if nested_lockfile and len(owners) != 1:
            evidence["full_triggers"].append({"path": path, "rule": f"nested lockfile maps to {len(owners)} packages, "
                                                                   "not exactly one"})
            continue
        if not owners:
            evidence["unmapped"].append(path)
        changed |= owners
    if evidence["full_triggers"]:
        return result
    evidence["changed_packages"] = sorted(changed)
    if not evidence["unmapped"]:
        result["affected"] = reverse_closure(pkgs, changed)
        result["hubs"] = sorted(result["affected"] & set(cfg.get("hub_packages") or []))
    return result


def reader_assessment_check(readers, *, revision, policy_hash, pkgs: dict, cfg: dict, scanner_sha) -> dict:
    """The one validator for a supported-reader assessment (edges.py check --out-json). It must bind the exact
    candidate, trusted policy bytes, workspace graph and scanner source. Used by the impact record and by the
    source answer's index completeness. state: matched | unmatched | invalid | absent."""
    out = {"state": "invalid", "reason": "reader_assessment_unproven", "status": None, "sha256": None}
    if readers is None:
        out["state"] = "absent"
        return out
    if not isinstance(readers, dict):
        return out
    expected = {"schema": 1, "revision": revision, "policy_config_sha256": policy_hash,
                "graph_sha256": graph_digest(pkgs), "scanner_source_sha256": scanner_sha,
                "coverage": "supported-static-readers-only"}
    supplied_hash = readers.get("assessment_sha256")
    payload = {key: value for key, value in readers.items() if key != "assessment_sha256"}
    if type(readers.get("schema")) is not int or any(readers.get(key) != value for key, value in expected.items()) or supplied_hash != canonical_digest(payload) \
            or readers.get("status") not in ("matched", "unmatched") \
            or not isinstance(readers.get("failures"), list) or not isinstance(readers.get("stale"), list) \
            or any(not isinstance(row, str) for row in readers["failures"] + readers["stale"]) \
            or any(not isinstance(readers.get(key), dict) or any(not isinstance(name, str)
                   or not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                   or values != sorted(set(values)) for name, values in readers[key].items()) for key in ("deps", "readers", "imports")):
        return out
    # `imports` (1.5.0): each imported path outside every package, with the packages that reach it.
    if set(readers["deps"]) != set(pkgs) or any(set(values) - set(pkgs) for values in readers["deps"].values()) \
            or any(set(values) - set(pkgs) for values in readers["readers"].values()) \
            or any(not values or set(values) - set(pkgs) for values in readers["imports"].values()):
        return out
    edge_scan = cfg.get("edge_scan") or {}
    directories = edge_scan.get("reader_dirs", []) if isinstance(edge_scan, dict) else None
    if not isinstance(directories, list) or any(not isinstance(name, str) or not name or name == "<unmapped>"
                                              for name in directories) or len(set(directories)) != len(directories):
        return out
    expected_readers, observed_readers = set(directories), set(readers["readers"])
    if observed_readers not in (expected_readers, expected_readers | {"<unmapped>"}):
        return out
    if readers["status"] == "matched" and readers["readers"].get("<unmapped>"):
        out.update(state="unmatched", reason="reader_assessment_unmatched")
        return out
    out.update(status=readers["status"], sha256=supplied_hash)
    if readers["status"] != "matched" or readers["failures"]:
        out.update(state="unmatched", reason="reader_assessment_unmatched")
        return out
    out.update(state="matched", reason=None)
    return out


def impact_record(record: dict, cfg: dict | None, pkgs: dict, assessment: dict | None,
                  readers, unknown_reason: str | None) -> dict:
    """Input-bound modeled impact; it never grants qualification, job selection, or reuse authority."""
    observation, validity = record["observation"], record["validity"]
    evidence = (assessment or {}).get("evidence", {})
    graph_sha = graph_digest(pkgs) if cfg is not None and assessment is not None else None
    identity = {key: observation.get(key) for key in ("event", "repository", "candidate", "tree",
        "target_ref", "target_sha", "diff_base", "policy_revision", "policy_blob", "policy_sha256",
        "run_id", "run_attempt")}
    identity.update(paths_sha256=record["inputs"]["paths_sha256"])
    identity.update({key: validity[key] for key in
        ("planner_source_sha256", "reader_source_sha256", "action_source_sha256")})
    result = {"schema": 1, "status": "unknown", "selection_authority": False,
        "reason": "cumulative_scope_unproven", "changed_packages": None, "affected_packages": None,
        "affected_hubs": None, "global_inputs": evidence.get("full_triggers", []),
        "unmapped_inputs": evidence.get("unmapped", []), "inert_inputs": evidence.get("inert", []),
        "graph": {"sha256": graph_sha, "package_count": len(pkgs) if graph_sha else None},
        "readers": {"status": "unavailable", "sha256": None, "coverage": "supported-static-readers-only"},
        "identity": identity}
    # The existing immutable_scope and final canonical-target read establish this context.
    # A direct/legacy planner call without that evidence cannot claim a known cumulative impact.
    if (unknown_reason or cfg is None or assessment is None or observation.get("status") != "known"
            or observation.get("schema") != 2 or observation.get("event") != "merge_group"
            or observation.get("scope_kind") != "canonical-target-cumulative"
            or observation.get("target_sha") != observation.get("policy_revision")
            or observation.get("target_sha") != observation.get("diff_base")):
        return result
    if any(not isinstance(observation.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", observation[key])
           or observation[key] == "0" * 40 for key in ("candidate", "tree", "target_sha", "policy_revision", "diff_base")) \
            or observation.get("target_source") != "canonical-git-ls-remote":
        return result
    policy_hash = observation.get("policy_sha256")
    if not isinstance(policy_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", policy_hash) \
            or policy_hash != validity.get("config_sha256") or not isinstance(observation.get("policy_blob"), str) \
            or not re.fullmatch(r"[0-9a-f]{40}", observation["policy_blob"]):
        result["reason"] = "trusted_policy_unproven"
        return result
    check = reader_assessment_check(readers, revision=observation.get("candidate"), policy_hash=policy_hash,
                                    pkgs=pkgs, cfg=cfg, scanner_sha=validity["reader_source_sha256"])
    if check["status"] is not None:
        result["readers"].update(status=check["status"], sha256=check["sha256"])
    if check["reason"]:
        result["reason"] = check["reason"]
        return result
    if evidence.get("full_triggers") or evidence.get("unmapped") or assessment["error"]:
        result["reason"] = "global_or_unmapped_inputs"
        return result
    result.update(status="known", reason="modeled_cumulative_impact_not_qualification",
                  changed_packages=evidence["changed_packages"], affected_packages=sorted(assessment["affected"]),
                  affected_hubs=assessment["hubs"])
    return result



def source_record(scope: dict | None, cfg: dict | None, pkgs: dict, paths: list[str], expected_count: int | None,
                  assessment: dict | None, readers, config_path: Path) -> tuple[dict | None, dict]:
    """The SRC-01 source answer for the observed change, minus `authorization`, plus why it is (in)complete.
    Every input that is missing, unbound or truncated lowers completeness; nothing here can raise it."""
    scope = scope or {}
    reasons, level = [], {"value": "complete"}

    def degrade(to: str, code: str) -> None:
        reasons.append(code)
        if to == "unknown" or level["value"] == "unknown":
            level["value"] = "unknown"
        else:
            level["value"] = "partial"

    known = scope.get("status") == "known"
    if not known:
        degrade("unknown", "scope_unknown")
    truncated = expected_count is not None and expected_count > len(paths)
    if truncated:
        degrade("partial", "incomplete_source")
    provider = scope.get("provider")
    if provider is not None and not isinstance(provider, dict):
        provider = {"status": "unknown", "reason": "provider_malformed"}
    if provider is not None:
        if provider.get("status") not in ("complete", "partial"):
            degrade("unknown", provider.get("reason") or "provider_unavailable")
        elif provider["status"] == "partial":
            truncated = True
            degrade("partial", provider.get("reason") or "provider_partial")
        elif not known or sorted(set(provider.get("paths") or [])) != sorted(set(paths)):
            degrade("unknown", "provider_mismatch")
    policy_ok = cfg is not None and scope.get("policy_status") == "verified" \
        and scope.get("policy_sha256") is not None and scope.get("policy_sha256") == sha256_file(config_path)
    build_metadata = "complete" if policy_ok and known else "unknown"
    index = "unknown"
    if known and cfg is not None:
        state = reader_assessment_check(readers, revision=scope.get("candidate"), policy_hash=scope.get("policy_sha256"),
                                        pkgs=pkgs, cfg=cfg, scanner_sha=sha256_file(Path(__file__).with_name("edges.py")))["state"]
        index = {"matched": "complete", "unmatched": "partial", "absent": "absent"}.get(state, "unknown")
    computed = assessment is not None and not assessment.get("error") \
        and not assessment["evidence"]["unmapped"] and not assessment["evidence"]["full_triggers"]
    closure = "complete" if index == "complete" and computed else ("partial" if index == "partial" else "unknown")
    for field, value in (("index", index), ("build_metadata", build_metadata), ("dependency_closure", closure)):
        if value != "complete":
            degrade("partial" if value == "partial" else "unknown", "incomplete_" + field)
    declared = (cfg or {}).get("analyzer")
    if declared is not None and declared != ANALYZER:
        degrade("unknown", "analyzer_mismatch")
    base, head = scope.get("diff_base") or scope.get("base"), scope.get("candidate")
    object_format = next((name for name, size in (("sha1", 40), ("sha256", 64))
                          if all(isinstance(v, str) and re.fullmatch("[0-9a-f]{%d}" % size, v) for v in (base, head))), None)
    repository_id, owner_id = scope.get("repository_id"), scope.get("repository_owner_id")
    identity_ok = object_format is not None and all(isinstance(v, str) and NUMERIC_ID.fullmatch(v) for v in (repository_id, owner_id))
    if not identity_ok:
        degrade("unknown", "identity_unavailable")
    representation = scope.get("representation")
    materialized = sorted(set(scope.get("policy_paths") or [])) if policy_ok else []
    if not isinstance(representation, dict) or any(not SAFE_PATH.fullmatch(path) for path in materialized):
        representation = None
        degrade("unknown", "representation_unobserved")
    status = "partial" if truncated else level["value"]  # SRC-01: a truncated answer must say partial
    completeness = {"status": status, "truncated": truncated, "index": index, "build_metadata": build_metadata,
                    "dependency_closure": closure, "missing_paths": []}
    envelope = None
    if identity_ok and representation is not None:
        envelope = {
            "schema_version": 1,
            "repository": {"provider": "github", "organization_id": "github-owner:" + owner_id,
                           "repository_id": repository_id},
            "revisions": {"object_format": object_format, "base_sha": base, "head_sha": head},
            "request_digest": canonical_digest({"operation": "changed-paths", "analyzer": ANALYZER,
                                                "event": scope.get("event"), "repository_id": repository_id,
                                                "base_sha": base, "head_sha": head,
                                                "policy_path": scope.get("policy_path")}),
            "analyzer": dict(ANALYZER),
            "representation": {**representation, "materialized_paths": materialized},
            "completeness": completeness,
        }
    meta = {"contract": SOURCE_CONTRACT, "authorization": None,
            "authorization_note": "absent by design: a CI job token is not a source-access grant; "
                                  "a consumer must acquire the canonical authorize() result before use",
            "decision": "FULL" if status != "complete" else "IMPACT_INPUT",
            "reason_codes": sorted(set(reasons)), "completeness": completeness,
            "selection_authority": False, "qualification_authority": False,
            "provider_witness": None if provider is None else {
                key: provider.get(key) for key in ("status", "reason", "request_digest", "caps")}}
    return envelope, meta


def validate_selection_rules(cfg: dict, pkgs: dict[str, dict]) -> None:
    """A misspelled obligation cannot become a successful empty package intersection."""
    def validate(rule):
        if isinstance(rule, str) and rule in ("always", "full_only", "any_package"):
            return
        if not isinstance(rule, dict) or len(rule) != 1 or not set(rule) <= {"packages", "any_except"}:
            raise ValueError("invalid selection rule")
        references = next(iter(rule.values()))
        if not isinstance(references, list) or any(not isinstance(name, str) or name not in pkgs for name in references):
            raise ValueError("selection rule references undeclared package")

    jobs, matrices = cfg.get("jobs", {}), cfg.get("matrices", {})
    if not isinstance(jobs, dict) or not isinstance(matrices, dict):
        raise ValueError("invalid job or matrix selection policy")
    for rule in jobs.values():
        validate(rule)
    for entries in matrices.values():
        if not isinstance(entries, list):
            raise ValueError("invalid matrix selection policy")
        for entry in entries:
            if not isinstance(entry, dict) or "include" not in entry or not isinstance(entry["include"], dict):
                raise ValueError("invalid matrix entry")
            validate(entry.get("rule", "always"))


def rule_matches(rule, affected: set[str]) -> tuple[bool, str]:
    if rule == "always":
        return True, "always runs"
    if rule == "full_only":
        return False, "runs only in a full plan"
    if rule == "any_package":
        return (bool(affected), "a package is affected" if affected else "no package is affected")
    if isinstance(rule, dict) and "packages" in rule:
        hit = sorted(affected & set(rule["packages"]))
        if hit:
            return True, "affected: " + ", ".join(hit)
        return False, "none of " + ", ".join(sorted(rule["packages"])) + " is affected"
    if isinstance(rule, dict) and "any_except" in rule:
        hit = sorted(affected - set(rule["any_except"]))
        if hit:
            return True, "affected: " + ", ".join(hit)
        return False, "no affected package outside " + ", ".join(sorted(rule["any_except"]))
    raise ValueError(f"unknown rule {rule!r}; expected one of {RULE_KINDS}")


def validity_predicate(root: Path, config_path: Path, cfg: dict, base: str, head: str) -> dict:
    lockfiles = {}
    for lf in ("pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"):
        h = sha256_file(root / lf)
        if h:
            lockfiles[lf] = h
    return {
        "planner_version": PLANNER_VERSION,
        "planner_source_sha256": sha256_file(Path(__file__)),
        "action_source_sha256": sha256_file(Path(__file__).with_name("action.yml")),
        "reader_source_sha256": sha256_file(Path(__file__).with_name("edges.py")),
        "config_sha256": sha256_file(config_path),
        "lockfiles_sha256": lockfiles,
        "workflows_sha256": sha256_tree(root, ".github/workflows"),
        "base": base,
        "head": head,
        "holds_while": "planner/action source, config, lockfiles, base workflows and bound event candidate observation are unchanged",
    }


def tested_identity(tested_root: Path | None, tree: str) -> dict | None:
    """What a FULL run actually tested: the tree it checked out, plus the lockfile and workflow hashes of
    that same tree. Tree equality already implies the rest; the hashes are carried so a receipt names its
    own validity predicate explicitly."""
    if not tree or tested_root is None or not tested_root.is_dir():
        return None
    lockfiles = {}
    for lf in ("pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"):
        h = sha256_file(tested_root / lf)
        if h:
            lockfiles[lf] = h
    return {"tree": tree, "lockfiles_sha256": lockfiles,
            "workflows_sha256": sha256_tree(tested_root, ".github/workflows"), "planner_version": PLANNER_VERSION}


def reuse_verdict(receipt: dict | None, tested: dict | None, event: str) -> tuple[bool, str]:
    """A push may reuse a successful FULL run that tested the identical tree. Any other event never does
    (schedule, release, dispatch and merge_group always run in full)."""
    if event != "push":
        return False, f"event {event} never reuses a run"
    if not receipt:
        return False, "no full-run receipt for this tree"
    if not tested:
        return False, "the tested tree could not be identified"
    if receipt.get("mode") != "full":
        return False, "the receipt is not from a full plan"
    for key in ("tree", "lockfiles_sha256", "workflows_sha256", "planner_version"):
        if receipt.get("tested", {}).get(key) != tested.get(key):
            return False, f"receipt {key} differs from this tree's"
    return True, f"run {receipt.get('run_id')} passed the full suite on identical tree {tested['tree'][:12]}"


def bind_plan_id(record: dict) -> None:
    identity = json.dumps({"v": record["validity"], "p": record["inputs"]["paths_sha256"],
                           "e": record["inputs"]["event"], "observation": record["observation"],
                           "jobs": record["jobs"], "matrices": record["matrices"], "impact": record["impact"],
                           "source": record["source_answer"], "source_meta": record["source_answer_meta"]}, sort_keys=True)
    record["plan_id"] = hashlib.sha256(identity.encode()).hexdigest()[:12]


def plan(*, cfg: dict | None, root: Path, config_path: Path, paths: list[str] | None, event: str,
         base: str, head: str, expected_count: int | None, forced_full_reason: str | None = None,
         tested: dict | None = None, receipt: dict | None = None, scope: dict | None = None,
         reader_assessment: dict | None = None) -> dict:
    if paths is not None and (not isinstance(paths, list) or any(
            not isinstance(p, str) or not p or "\0" in p or p.startswith("/")
            or any(part in (".", "..") for part in p.split("/")) for p in paths)):
        forced_full_reason = "invalid lossless path input"
        paths = []
    paths = sorted(set(paths or []))
    record = {
        "operator": OPERATOR_ID,
        "planner_version": PLANNER_VERSION,
        "method": "deterministic: glob rules + workspace reverse-dependency closure",
        "confidence": 1.0,
        "inputs": {
            "event": event,
            "base": base,
            "head": head,
            "changed_paths": len(paths),
            "paths_sha256": hashlib.sha256(json.dumps(paths, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest(),
        },
        "evidence": {"full_triggers": [], "unmapped": [], "inert": [], "changed_packages": []},
        "affected_packages": [],
        "tested": tested,
        "observation": {key: value for key, value in (scope or {}).items() if key != "paths"},
        "requires_full_caller_roster": cfg is None,
    }

    pkgs, assessment = {}, None
    impact_unknown = forced_full_reason or ("paths_unavailable" if not paths else None)
    if expected_count is not None and expected_count > len(paths):
        impact_unknown = "truncated_paths"

    def finish(mode: str, reason: str, affected: set[str] | None = None) -> dict:
        record["mode"] = mode
        record["requires_full_caller_roster"] = mode == "full"
        record["reason"] = reason
        record["affected_packages"] = sorted(affected or [])
        jobs, matrices = {}, {}
        cfg_jobs = (cfg or {}).get("jobs") or {}
        cfg_mats = (cfg or {}).get("matrices") or {}
        for job, rule in sorted(cfg_jobs.items()):
            if mode == "reused":
                jobs[job] = {"run": False, "reason": f"reused: {reason}"}
            elif mode == "full":
                jobs[job] = {"run": True, "reason": f"full plan: {reason}"}
            else:
                run, why = rule_matches(rule, affected or set())
                jobs[job] = {"run": run, "reason": why}
        for name, entries in sorted(cfg_mats.items()):
            inc, skipped = [], []
            for entry in entries:
                if mode == "reused":
                    skipped.append({"entry": entry["include"], "reason": f"reused: {reason}"})
                    continue
                if mode == "full":
                    inc.append(entry["include"])
                    continue
                run, why = rule_matches(entry.get("rule", "always"), affected or set())
                (inc if run else skipped).append(entry["include"] if run else {"entry": entry["include"], "reason": why})
            matrices[name] = {"include": inc, "skipped": skipped}
        record["jobs"] = jobs
        record["matrices"] = matrices
        record["validity"] = validity_predicate(root, config_path, cfg or {}, base, head)
        record["impact"] = impact_record(record, cfg, pkgs, assessment, reader_assessment, impact_unknown)
        record["source_answer"], record["source_answer_meta"] = source_record(
            scope, cfg, pkgs, paths, expected_count, assessment, reader_assessment, config_path)
        bind_plan_id(record)
        return record

    reuse, why = reuse_verdict(receipt, tested, event)
    record["reuse"] = {"reused": reuse, "reason": why}

    ws = (cfg or {}).get("workspace") or {"type": "none"}
    try:
        if ws.get("type") == "pnpm":
            pkgs = discover_pnpm_packages(root, ws.get("extra_deps"))
        elif ws.get("type") == "declared":
            pkgs = declared_packages(ws)
        elif ws.get("type") == "none":
            pkgs = {}
        else:
            raise ValueError(f"unknown workspace type {ws.get('type')!r}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return finish("full", f"workspace graph unreadable: {exc}")

    if cfg is not None:
        validate_selection_rules(cfg, pkgs)
        if event in ("pull_request", "pull_request_target", "merge_group") and not impact_unknown:
            assessment = classify_paths(paths, cfg, pkgs)

    if reuse and cfg is not None and not forced_full_reason:
        return finish("reused", why)
    if forced_full_reason:
        return finish("full", forced_full_reason)
    if cfg is None:
        return finish("full", "no plan config on the base commit")
    if event not in ("pull_request", "pull_request_target"):
        return finish("full", f"event {event} always runs the full suite")
    if not paths:
        return finish("full", "no changed paths could be read")
    if expected_count is not None and expected_count > len(paths):
        return finish("full", f"changed-file list looks truncated ({len(paths)} read, {expected_count} reported)")

    record["evidence"] = assessment["evidence"]
    triggers = record["evidence"]["full_triggers"]
    if triggers:
        return finish("full", f"{triggers[0]['path']} matches full trigger {triggers[0]['rule']}"
                      + (f" (+{len(triggers) - 1} more)" if len(triggers) > 1 else ""))
    if assessment["error"]:
        return finish("full", assessment["error"])
    if record["evidence"]["unmapped"]:
        u = record["evidence"]["unmapped"]
        return finish("full", f"{u[0]} maps to no package (unknown impact)" + (f" (+{len(u) - 1} more)" if len(u) > 1 else ""))
    affected, hubs = assessment["affected"], assessment["hubs"]
    if hubs:
        return finish("full", "hub package affected: " + ", ".join(hubs), affected)
    # Unknown never narrows: a reduced plan needs a complete source answer (scope, policy, readers, identity).
    _, source_meta = source_record(scope, cfg, pkgs, paths, expected_count, assessment, reader_assessment, config_path)
    if source_meta["decision"] != "IMPACT_INPUT":
        return finish("full", "source answer not complete: " + ", ".join(source_meta["reason_codes"]), affected)
    if not affected:
        return finish("reduced", "only inert paths changed", affected)
    return finish("reduced", "affected: " + ", ".join(sorted(affected)), affected)


def summary_markdown(rec: dict) -> str:
    lines = [f"### change-impact plan `{rec['plan_id']}`: **{rec['mode']}**", "", f"{rec['reason']}", ""]
    lines.append(f"operator `{rec['operator']}` v{rec['planner_version']}, confidence {rec['confidence']}, "
                 f"{rec['inputs']['changed_paths']} path(s), base `{rec['inputs']['base'][:12]}` head `{rec['inputs']['head'][:12]}`")
    meta = rec.get("source_answer_meta") or {}
    completeness = meta.get("completeness") or {}
    lines.append("")
    lines.append(f"source answer: {completeness.get('status')} -> {meta.get('decision')}"
                 + (" (" + ", ".join(meta.get("reason_codes") or []) + ")" if meta.get("reason_codes") else ""))
    if rec["affected_packages"]:
        lines.append("")
        lines.append("affected: " + ", ".join(f"`{p}`" for p in rec["affected_packages"]))
    lines += ["", "| job | runs | reason |", "|---|---|---|"]
    for job, j in rec["jobs"].items():
        lines.append(f"| {job} | {'yes' if j['run'] else 'skipped by plan'} | {j['reason']} |")
    for name, m in rec["matrices"].items():
        for e in m["include"]:
            lines.append(f"| {name} {json.dumps(e)} | yes | |")
        for s in m["skipped"]:
            lines.append(f"| {name} {json.dumps(s['entry'])} | skipped by plan | {s['reason']} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--resolve-target", action="store_true", help="internal pre-checkout target snapshot")
    ap.add_argument("--target-observation", default="")
    ap.add_argument("--policy-checkout-outcome", default="")
    ap.add_argument("--target-ref", default="")
    ap.add_argument("--server-url", default="")
    ap.add_argument("--event-repository", default="")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--run-attempt", default="")
    ap.add_argument("--root", required=True)
    ap.add_argument("--fallback-config", help="deprecated compatibility input; never read")
    ap.add_argument("--paths-file")
    ap.add_argument("--reader-assessment", help="attempt-local supported-reader assessment; information only")
    ap.add_argument("--force-full-reason", help="trusted reader assessment can only widen obligations")
    ap.add_argument("--scope-root", help="existing checkout of the exact event candidate")
    ap.add_argument("--repository", default="")
    ap.add_argument("--repository-id", default="", help="provider-stable repository id (github.repository_id)")
    ap.add_argument("--repository-owner-id", default="", help="provider-stable owner id (github.repository_owner_id)")
    ap.add_argument("--source-query", choices=("off", "witness"), default="off",
                    help="witness: also ask the provider compare API at the pinned SHAs; it can only widen")
    ap.add_argument("--api-url", default="https://api.github.com")
    ap.add_argument("--candidate", default="")
    ap.add_argument("--expected-count", type=int)
    ap.add_argument("--event", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="")
    ap.add_argument("--tree", default="", help="tree SHA of the commit this run tests")
    ap.add_argument("--tested-root", help="checkout of the tested commit (lockfiles + workflows)")
    ap.add_argument("--receipt", help="a full-run receipt found for --tree (push events only)")
    ap.add_argument("--out-json")
    ap.add_argument("--github-output")
    ap.add_argument("--summary")
    a = ap.parse_args(argv)

    context = dict(repository=a.repository, event_repository=a.event_repository, target_ref=a.target_ref,
                   server_url=a.server_url, candidate=a.candidate, run_id=a.run_id, run_attempt=a.run_attempt)
    if a.resolve_target:
        observation = resolve_target_observation(**context) if a.event == "merge_group" else {"status": "not_applicable"}
        policy_ref = observation.get("target_sha", "") if a.event == "merge_group" else a.base
        if a.out_json:
            Path(a.out_json).write_text(json.dumps(observation, sort_keys=True) + "\n")
        if a.github_output:
            with open(a.github_output, "a") as output:
                output.write(f"policy_ref={policy_ref}\n")
        return 0

    root = Path(a.root)
    config_path = root / a.config
    cfg, forced = None, a.force_full_reason or None
    # The candidate cannot supply even a supposedly full roster. In an adoption
    # PR, the caller must run its existing complete roster and verify every lane.
    # --fallback-config remains accepted for callers migrating from v1.1, but is
    # deliberately not read (including malformed/empty candidate files).
    # Legacy line-delimited paths and receipts cannot authorize reduced execution.
    # The canonical action supplies a checkout, never a caller-asserted path list.
    target_observation = None
    if a.target_observation:
        try:
            target_observation = json.loads(Path(a.target_observation).read_text())
        except (OSError, ValueError):
            pass
    scope = immutable_scope(Path(a.scope_root), event=a.event, base=a.base, head=a.head,
                            candidate=a.candidate, repository=a.repository, target_observation=target_observation,
                            target_ref=a.target_ref, server_url=a.server_url, event_repository=a.event_repository,
                            policy_root=root, config=a.config, run_id=a.run_id, run_attempt=a.run_attempt,
                            policy_checkout_outcome=a.policy_checkout_outcome, repository_id=a.repository_id,
                            repository_owner_id=a.repository_owner_id) if a.scope_root else {
        "status": "unknown", "reason": "immutable scope checkout is required"}
    if scope["status"] != "known":
        forced = forced or scope["reason"]
    elif a.source_query == "witness":
        scope["provider"] = provider_compare(a.repository, scope.get("diff_base") or scope["base"], scope["candidate"],
                                             token=os.environ.get("GH_TOKEN", ""), api_url=a.api_url,
                                             transport=https_transport)
    if config_path.is_file() and a.policy_checkout_outcome in ("", "success") \
        and (a.event != "merge_group" or scope["status"] == "known"):
        cfg = json.loads(config_path.read_text())
        if cfg.get("schema") != 1:
            cfg, forced = None, f"plan config schema {cfg.get('schema')!r} is not 1"
    readers = None
    if a.reader_assessment:
        try:
            readers = json.loads(Path(a.reader_assessment).read_text())
        except (OSError, ValueError, UnicodeError):
            pass
    paths = scope.get("paths")
    rec = plan(cfg=cfg, root=root, config_path=config_path, paths=paths, event=a.event, base=a.base,
               head=a.head, expected_count=a.expected_count, forced_full_reason=forced,
               tested=tested_identity(Path(a.tested_root) if a.tested_root else None, scope.get("tree") or ""),
               receipt=None, scope=scope, reader_assessment=readers)
    if a.event == "merge_group" and scope["status"] == "known":
        try:
            rechecked = canonical_target(a.repository, a.target_ref, a.server_url)
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            rechecked = None
        scope["target_rechecked_sha"] = rechecked
        if rechecked != scope["target_sha"]:
            scope.update(status="unknown", paths=None, diff_base=None, policy_revision=None, policy_blob=None, policy_sha256=None,
                         policy_paths=None, policy_status="unverified",
                         reason="canonical target changed or unavailable before output")
            rec = plan(cfg=None, root=root, config_path=config_path, paths=None, event=a.event, base=a.base,
                       head=a.head, expected_count=a.expected_count, forced_full_reason=scope["reason"],
                       tested=rec.get("tested"), receipt=None, scope=scope, reader_assessment=readers)
        else:
            rec["observation"] = {key: value for key, value in scope.items() if key != "paths"}
            bind_plan_id(rec)
    text = json.dumps(rec, indent=2, sort_keys=True)
    print(text)
    if a.out_json:
        Path(a.out_json).write_text(text + "\n")
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(summary_markdown(rec))
    # Publish last. The caller must still require this step/job to succeed:
    # filesystem failures can interrupt even a final output write.
    if a.github_output:
        run = {k: v["run"] for k, v in rec["jobs"].items()}
        mats = {k: v["include"] for k, v in rec["matrices"].items()}
        with open(a.github_output, "a") as fh:
            fh.write(f"plan={json.dumps(rec, sort_keys=True, separators=(',', ':'))}\n")
            fh.write(f"mode={rec['mode']}\nplan_id={rec['plan_id']}\n")
            fh.write(f"tested={json.dumps(rec.get('tested'), sort_keys=True, separators=(',', ':'))}\n")
            fh.write(f"run={json.dumps(run, separators=(',', ':'))}\n")
            fh.write(f"matrices={json.dumps(mats, separators=(',', ':'))}\n")
    return 0


if __name__ == "__main__":
    sys.exit(_provider_http_worker() if sys.argv[1:] == ["--provider-http-worker"] else main())
