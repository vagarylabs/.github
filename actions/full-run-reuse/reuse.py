#!/usr/bin/env python3
"""Reuse a merge group's FULL run for the push to main that fast-forwards to the SAME commit (K4a).

  reuse.py lookup    env: GH_TOKEN REPO SHA EVENT REF DEFAULT_BRANCH WORKFLOW_REF VERDICT_JOB VOID_STEPS IGNORE_JOBS
                          EVENT_CONDITIONAL_STEPS WAIT_MINUTES GITHUB_OUTPUT [GITHUB_STEP_SUMMARY] [API_URL]

A merge queue merges by fast-forwarding the default branch to the exact commit its merge_group run tested, so that
run already validated the push's tree, lockfiles and workflow bytes. Evidence is accepted only when ALL hold, read
from the API at lookup time (never from a job output):
  - the event is a push to the default branch, and SHA is 40 hex;
  - the NEWEST merge_group run of THIS workflow file in THIS repository with head_sha == SHA is the only candidate.
    A refused or unreadable newest run means the full suite runs: an older run of the same commit never stands in
    (root's #59 R4, B2);
  - that run is completed with conclusion success. A run still in progress is polled up to WAIT_MINUTES, then refused;
  - in its LATEST attempt every job is completed with conclusion success, skipped or neutral, except the jobs the
    consumer names in IGNORE_JOBS (reviewed, advisory). Every job that reports one of the default branch's REQUIRED
    checks (read from the ruleset) must be success, and a required check may never be ignored (#59 R4, B1);
  - the declared verdict job (the required aggregate) is success exactly once;
  - no job of that attempt executed a declared void step, whatever its conclusion;
  - that attempt uploaded exactly one unexpired `ci-full-run-receipt-a<attempt>` artifact (written by
    actions/full-run-receipt inside the verdict job), and the receipt says schema 2, mode full, event merge_group,
    this repository, this workflow path, head SHA, this run id and this attempt.
Anything missing, ambiguous, paginated past what was read, malformed or unreadable yields no reuse, so the push runs
its full suite; an empty result is never green. A missing or malformed configuration fails the step instead. Errors
are reported by type only (an error body can carry a URL with a token).

Pull-request runs are NOT evidence: they tested the PR merged onto an older main.

Consumer obligation (#59 R4, L5): steps whose `if:` depends on the event run differently under merge_group and push. A
reusing workflow declares them in EVENT_CONDITIONAL_STEPS (a JSON list, `[]` for none). The declaration is reviewed
with the workflow and printed in the summary; this reader cannot verify it.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import zipfile

SHA = re.compile(r"[0-9a-f]{40}")
RECEIPT_SCHEMA = 2
PAGE = 100
POLL_SECONDS = 20
MAX_WAIT_MINUTES = 30
PASSING = ("success", "skipped", "neutral")
# Any of these from a malformed response or receipt is a refusal (FULL), never a crash.
UNREADABLE = (OSError, KeyError, TypeError, ValueError, AttributeError, IndexError, zipfile.BadZipFile)


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


def name_list(raw: str | None, what: str) -> list[str]:
    value = json.loads(raw or "[]")
    if not isinstance(value, list) or not all(isinstance(s, str) and s for s in value):
        raise ValueError(f"{what} must be a JSON list of non-empty names")
    return value


def required_checks(get, repo: str, branch: str) -> set[str]:
    """The default branch's required status-check contexts, from its effective rules."""
    rules = get(f"/repos/{repo}/rules/branches/{urllib.parse.quote(branch)}")
    if not isinstance(rules, list):
        raise ValueError("branch rules are not a list")
    required = set()
    for rule in rules:  # every rule: several rulesets, repository- and organization-sourced, may each require checks
        if rule.get("type") == "required_status_checks":
            for check in (rule.get("parameters") or {}).get("required_status_checks") or []:
                required.add(check["context"])
    return required


def all_jobs(get, repo: str, run_id: int, attempt: int) -> list[dict]:
    """Every job of the attempt, counted by unique job id against the API's total (a repeated page is refused)."""
    jobs, page = {}, 1
    while True:
        body = get(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page={PAGE}&page={page}")
        batch, total = body.get("jobs"), body.get("total_count")
        if not isinstance(batch, list) or not isinstance(total, int):
            raise ValueError("job listing is malformed")
        for job in batch:
            if not isinstance(job.get("id"), int) or job["id"] in jobs:
                raise ValueError("job listing repeats or lacks a job id")
            jobs[job["id"]] = job
        if len(jobs) >= total or not batch:
            break
        page += 1
    if len(jobs) != total:
        raise ValueError("job listing incomplete")
    return list(jobs.values())


def evaluate(get, run: dict, *, repo: str, sha: str, path: str, verdict_job: str, void_steps: list[str],
             ignore_jobs: list[str], required: set[str]) -> str | None:
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
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return f"run is {run.get('status')}/{run.get('conclusion')}, not completed/success"
    jobs = all_jobs(get, repo, run_id, attempt)
    verdicts = [job for job in jobs if job.get("name") == verdict_job]
    if len(verdicts) != 1:
        return f"verdict job {verdict_job!r} appears {len(verdicts)} times in attempt {attempt}"
    for job in jobs:
        name, status, conclusion = job.get("name"), job.get("status"), job.get("conclusion")
        if name in required and (status, conclusion) != ("completed", "success"):
            return f"required check {name!r} is {status}/{conclusion}"
        if name == verdict_job and (status, conclusion) != ("completed", "success"):
            return f"verdict job is {status}/{conclusion}"
        if name not in ignore_jobs and (status != "completed" or conclusion not in PASSING):
            return f"job {name!r} is {status}/{conclusion}"
        for step in job.get("steps") or []:
            if step.get("name") in void_steps and step.get("conclusion") != "skipped":
                return f"job {name!r} ran void step {step.get('name')!r}: nothing was verified"
    name = f"ci-full-run-receipt-a{attempt}"
    arts = get(f"/repos/{repo}/actions/runs/{run_id}/artifacts?name={urllib.parse.quote(name)}&per_page={PAGE}")
    live = [a for a in (arts.get("artifacts") or []) if a.get("name") == name and not a.get("expired")]
    if len(live) != 1:
        return f"{len(live)} unexpired {name} artifact(s)"
    with zipfile.ZipFile(io.BytesIO(get(live[0]["archive_download_url"], raw=True))) as z:
        receipt = json.loads(z.read("receipt.json"))
    if not isinstance(receipt, dict):
        return "receipt is not a JSON object"
    expected = {"schema": RECEIPT_SCHEMA, "mode": "full", "event": "merge_group", "repository": repo,
                "workflow_path": path, "head_sha": sha, "run_id": run_id, "run_attempt": attempt}
    for key, value in expected.items():
        if receipt.get(key) != value:
            return f"receipt {key} is {receipt.get(key)!r}, not {value!r}"
    return None


def configuration(env: dict) -> dict:
    """The consumer's declarations. Raises ValueError (the step fails red, never reuses) when one is missing or bad."""
    verdict_job = env.get("VERDICT_JOB", "")
    if not verdict_job:
        raise ValueError("verdict-job is required: the name of the required aggregate job")
    # GitHub does not enforce `required: true` on an action input (an omitted one arrives as ""), so the value is checked.
    if not (env.get("EVENT_CONDITIONAL_STEPS") or "").strip():
        raise ValueError("event-conditional-steps is required: a JSON list of event-conditional steps, [] for none")
    wait = env.get("WAIT_MINUTES") or "10"
    if not re.fullmatch(r"\d+", wait) or int(wait) > MAX_WAIT_MINUTES:
        raise ValueError(f"wait-minutes must be an integer from 0 to {MAX_WAIT_MINUTES}")
    return {"repo": env.get("REPO", ""), "sha": env.get("SHA", ""), "verdict_job": verdict_job,
            "path": workflow_path(env.get("WORKFLOW_REF", ""), env.get("REPO", "")),
            "void_steps": name_list(env.get("VOID_STEPS"), "void-steps"),
            "ignore_jobs": name_list(env.get("IGNORE_JOBS"), "ignore-jobs"),
            "event_conditional": name_list(env.get("EVENT_CONDITIONAL_STEPS"), "event-conditional-steps"),
            "wait_seconds": int(wait) * 60}


def lookup(env: dict, get, sleep=time.sleep, now=time.monotonic) -> tuple[str, list[str]]:
    """(run id or '', log lines). Raises ValueError on a configuration error."""
    cfg = configuration(env)
    repo, sha = cfg["repo"], cfg["sha"]
    if env.get("EVENT") != "push" or env.get("REF") != "refs/heads/" + env.get("DEFAULT_BRANCH", ""):
        return "", ["not a push to the default branch"]
    if not SHA.fullmatch(sha):
        return "", ["pushed sha is not 40 hex"]
    try:
        required = required_checks(get, repo, env["DEFAULT_BRANCH"])
    except UNREADABLE as error:
        return "", ["required checks unreadable: " + type(error).__name__]
    if not required:
        # Classic branch protection, or none: the required set cannot be read here, so nothing proves that a skipped
        # or failed job was not a required check (root's #59 delta R4). FULL, never "nothing is required".
        return "", ["no required status checks in the default branch's rules: the full suite runs"]
    clash = sorted(required & set(cfg["ignore_jobs"]))
    if clash:
        raise ValueError(f"ignore-jobs names required check(s) {clash}: a required check is never ignored")
    try:
        workflow_file = urllib.parse.quote(cfg["path"].rsplit("/", 1)[1])
        listing = get(f"/repos/{repo}/actions/workflows/{workflow_file}/runs?event=merge_group&head_sha={sha}&per_page=20")
        runs = listing.get("workflow_runs")
        if not isinstance(runs, list) or not all(isinstance(r, dict) and isinstance(r.get("id"), int) for r in runs):
            raise ValueError("run listing is malformed")
        if not runs:
            return "", ["no merge_group run of this commit"]
        newest = max(runs, key=lambda r: r["id"])
        newest_id = newest["id"]
        deadline = now() + cfg["wait_seconds"]
        while newest.get("status") != "completed" and now() < deadline:
            sleep(POLL_SECONDS)
            newest = get(f"/repos/{repo}/actions/runs/{newest_id}")
            if not isinstance(newest, dict) or newest.get("id") != newest_id:
                raise ValueError("poll returned a different or malformed run")
        reason = evaluate(get, newest, repo=repo, sha=sha, path=cfg["path"], verdict_job=cfg["verdict_job"],
                          void_steps=cfg["void_steps"], ignore_jobs=cfg["ignore_jobs"], required=required)
    except UNREADABLE as error:
        return "", ["lookup unresolvable: " + type(error).__name__]
    others = len(runs) - 1
    note = f" ({others} older run(s) of this commit are never considered)" if others else ""
    if reason is not None:
        return "", [f"newest run {newest_id}: {reason}{note}"]
    return str(newest_id), [f"newest run {newest_id}: ACCEPTED{note}",
                               f"declared event-conditional steps: {cfg['event_conditional'] or 'none'}"]


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
            summary.write(f"Reused merge_group run {run_id} (same commit, completed/success, every non-ignored job "
                          "passing, required checks success, FULL receipt).\n" if run_id
                          else "No merge-group evidence for this commit; the full suite runs.\n")
            summary.write("```\n" + "\n".join(log) + "\n```\n")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["lookup"]:
        raise SystemExit("usage: reuse.py lookup")
    sys.exit(main())
