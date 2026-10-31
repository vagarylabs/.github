#!/usr/bin/env python3
"""Reuse a merge group's FULL run for the push to main that fast-forwards to the SAME commit (K4a).

  reuse.py lookup    env: GH_TOKEN REPO SHA EVENT REF DEFAULT_BRANCH WORKFLOW_REF VERDICT_JOB VOID_STEPS
                          GITHUB_OUTPUT [GITHUB_STEP_SUMMARY] [API_URL]

A merge queue merges by fast-forwarding the default branch to the exact commit its merge_group run tested, so that
run already validated the push's tree, lockfiles and workflow bytes. Evidence is accepted only when ALL hold, read
from the API at lookup time (never from a job output):
  - the event is a push to the default branch, and SHA is 40 hex;
  - a merge_group run of THIS workflow file in THIS repository has head_sha == SHA;
  - in that run's LATEST attempt, the declared verdict job (the required aggregate) is completed with conclusion
    success, exactly once. The run as a whole may still be in progress: non-required jobs can outlive the merge;
  - no job of that attempt executed a declared void step (a step that runs only when the job verified nothing);
  - that attempt uploaded exactly one unexpired `ci-full-run-receipt-a<attempt>` artifact (written by
    actions/full-run-receipt inside the verdict job, before it reported), and the receipt says schema 2, mode full,
    event merge_group, this repository, this workflow path, head SHA, this run id and this attempt.
Anything missing, ambiguous, paginated past what was read, or unreadable yields no reuse, so the push runs its full
suite. An empty result is never green. Errors are reported by type only (an error body can carry a URL with a token).

Pull-request runs are NOT evidence: they tested the PR merged onto an older main. A merge-group run tested the exact
commit main now points to, so it is the only binding this reader admits.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import zipfile

SHA = re.compile(r"[0-9a-f]{40}")
RECEIPT_SCHEMA = 2
PAGE = 100


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    # An artifact zip redirects to blob storage; the token must not follow it there.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


def http_getter(token: str, api: str):
    opener = urllib.request.build_opener(_NoAuthOnRedirect)

    def get(path: str, raw: bool = False):
        url = path if path.startswith("https://") else api + path
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                   "Accept": "application/vnd.github+json",
                                                   "X-GitHub-Api-Version": "2022-11-28"})
        with opener.open(req, timeout=30) as r:
            return r.read() if raw else json.load(r)
    return get


def workflow_path(workflow_ref: str, repo: str) -> str:
    """`owner/repo/.github/workflows/x.yml@refs/heads/main` -> `.github/workflows/x.yml`, bound to THIS repo."""
    prefix = repo + "/"
    if not workflow_ref.startswith(prefix) or "@" not in workflow_ref:
        raise ValueError("workflow_ref is not this repository's")
    path = workflow_ref[len(prefix):].rsplit("@", 1)[0]
    if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
        raise ValueError("workflow_ref does not name a workflow file")
    return path


def all_jobs(get, repo: str, run_id: int, attempt: int) -> list[dict]:
    jobs, page = [], 1
    while True:
        body = get(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page={PAGE}&page={page}")
        batch = body.get("jobs") or []
        jobs.extend(batch)
        total = body.get("total_count")
        if not isinstance(total, int):
            raise ValueError("job listing has no total_count")
        if len(jobs) >= total or not batch:
            break
        page += 1
    if len(jobs) != total:
        raise ValueError("job listing incomplete")
    return jobs


def evaluate(get, run: dict, *, repo: str, sha: str, path: str, verdict_job: str, void_steps: list[str]) -> str | None:
    """None when `run` is acceptable evidence for SHA, else the reason it is not."""
    if run.get("event") != "merge_group":
        return f"event {run.get('event')}"
    if run.get("head_sha") != sha:
        return "run tested a different commit"
    if run.get("path") != path:
        return f"workflow {run.get('path')} is not {path}"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "another repository"
    run_id, attempt = run.get("id"), run.get("run_attempt")
    if not isinstance(run_id, int) or not isinstance(attempt, int) or attempt < 1:
        return "run has no id or attempt"
    jobs = all_jobs(get, repo, run_id, attempt)
    verdicts = [job for job in jobs if job.get("name") == verdict_job]
    if len(verdicts) != 1:
        return f"verdict job {verdict_job!r} appears {len(verdicts)} times in attempt {attempt}"
    if verdicts[0].get("status") != "completed" or verdicts[0].get("conclusion") != "success":
        return f"verdict job is {verdicts[0].get('status')}/{verdicts[0].get('conclusion')}"
    for job in jobs:
        for step in job.get("steps") or []:
            if step.get("name") in void_steps and step.get("conclusion") != "skipped":
                return f"job {job.get('name')!r} ran void step {step.get('name')!r}: nothing was verified"
    name = f"ci-full-run-receipt-a{attempt}"
    arts = get(f"/repos/{repo}/actions/runs/{run_id}/artifacts?name={urllib.parse.quote(name)}&per_page={PAGE}")
    live = [a for a in (arts.get("artifacts") or []) if a.get("name") == name and not a.get("expired")]
    if len(live) != 1:
        return f"{len(live)} unexpired {name} artifact(s)"
    with zipfile.ZipFile(io.BytesIO(get(live[0]["archive_download_url"], raw=True))) as z:
        receipt = json.loads(z.read("receipt.json"))
    expected = {"schema": RECEIPT_SCHEMA, "mode": "full", "event": "merge_group", "repository": repo,
                "workflow_path": path, "head_sha": sha, "run_id": run_id, "run_attempt": attempt}
    for key, value in expected.items():
        if receipt.get(key) != value:
            return f"receipt {key} is {receipt.get(key)!r}, not {value!r}"
    return None


def lookup(env: dict, get) -> tuple[str, list[str]]:
    """(run id or '', log lines). Raises ValueError on a configuration error (the step fails red, never reuses)."""
    verdict_job = env.get("VERDICT_JOB", "")
    if not verdict_job:
        raise ValueError("verdict-job is required: the name of the required aggregate job")
    void_steps = json.loads(env.get("VOID_STEPS") or "[]")
    if not isinstance(void_steps, list) or not all(isinstance(s, str) and s for s in void_steps):
        raise ValueError("void-steps must be a JSON list of step names")
    repo, sha = env.get("REPO", ""), env.get("SHA", "")
    path = workflow_path(env.get("WORKFLOW_REF", ""), repo)
    if env.get("EVENT") != "push" or env.get("REF") != "refs/heads/" + env.get("DEFAULT_BRANCH", ""):
        return "", ["not a push to the default branch"]
    if not SHA.fullmatch(sha):
        return "", ["pushed sha is not 40 hex"]
    log = []
    try:
        workflow_file = urllib.parse.quote(path.rsplit("/", 1)[1])
        runs = get(f"/repos/{repo}/actions/workflows/{workflow_file}/runs?event=merge_group&head_sha={sha}&per_page=20")
        candidates = sorted(runs.get("workflow_runs") or [], key=lambda r: r.get("id", 0), reverse=True)
        for run in candidates:
            try:
                reason = evaluate(get, run, repo=repo, sha=sha, path=path, verdict_job=verdict_job, void_steps=void_steps)
            except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as error:
                reason = "unresolvable: " + type(error).__name__
            log.append(f"run {run.get('id')}: {reason or 'ACCEPTED'}")
            if reason is None:
                return str(run["id"]), log
    except (OSError, KeyError, TypeError, ValueError) as error:
        log.append("lookup unresolvable: " + type(error).__name__)
    return "", log or ["no merge_group run of this commit"]


def main() -> int:
    env = dict(os.environ)
    get = http_getter(env.get("GH_TOKEN", ""), env.get("API_URL") or "https://api.github.com")
    try:
        run_id, log = lookup(env, get)
    except ValueError as error:
        print(f"full-run-reuse: configuration error: {error}", file=sys.stderr)
        return 2
    print("\n".join(log))
    with open(env["GITHUB_OUTPUT"], "a") as out:
        out.write(f"reused_run={run_id}\n")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Merge-group reuse\n")
            summary.write(f"Reused merge_group run {run_id} (same commit, verdict job succeeded, FULL receipt).\n" if run_id
                          else "No merge-group evidence for this commit; the full suite runs.\n")
            summary.write("```\n" + "\n".join(log) + "\n```\n")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["lookup"]:
        raise SystemExit("usage: reuse.py lookup")
    sys.exit(main())
