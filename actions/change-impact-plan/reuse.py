#!/usr/bin/env python3
"""Find a full-run receipt for the tree a push tests, and refuse any receipt not bound to the merge.

  reuse.py lookup    (env: GH_TOKEN REPO SHA EVENT REUSE WORKFLOW_REF RUNNER_TEMP)
writes $RUNNER_TEMP/ci-plan-tree.txt always, and $RUNNER_TEMP/ci-plan-receipt.json when a usable receipt
exists. A receipt is usable only when the run that wrote it:
  - is a successful pull_request run of THIS workflow file in THIS repository, from a head branch in this
    repository (fork runs carry the base repo as `repository`, so head_repository is the binding field);
  - tested the head that was MERGED: run.head_sha == the pushed commit's second parent. A PR rewrites its
    own workflow, so without this a PR could mint a receipt for another PR's merge tree. A squash or rebase
    merge has no second parent and never reuses.
"""
from __future__ import annotations

import io
import json
import os
import sys
import urllib.request
import zipfile


def run_usable(run: dict, *, repo: str, workflow_path: str, parents: list[str]) -> str | None:
    """None when usable, else the reason it is not."""
    if (run.get("head_repository") or {}).get("full_name") != repo:
        return "head is not in this repository"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "another repository"
    if run.get("path") != workflow_path:
        return f"workflow {run.get('path')} is not {workflow_path}"
    if run.get("event") != "pull_request":
        return f"event {run.get('event')}"
    if run.get("conclusion") != "success":
        return f"run conclusion {run.get('conclusion')}"
    if len(parents) != 2:
        return f"pushed commit has {len(parents)} parent(s); only a merge commit can reuse"
    if run.get("head_sha") != parents[1]:
        return "the run tested a different head than the one merged"
    return None


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    # The artifact zip redirects to blob storage; the GitHub token must not follow it there.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


def lookup() -> int:
    opener = urllib.request.build_opener(_NoAuthOnRedirect)

    def get(url, raw=False):
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                                                   "Accept": "application/vnd.github+json"})
        with opener.open(req, timeout=30) as r:
            return r.read() if raw else json.load(r)

    repo = os.environ["REPO"]
    api = f"https://api.github.com/repos/{repo}"
    tmp = os.environ["RUNNER_TEMP"]
    commit = get(f"{api}/commits/{os.environ['SHA']}")
    tree = commit["commit"]["tree"]["sha"]
    open(os.path.join(tmp, "ci-plan-tree.txt"), "w").write(tree)
    print(f"tested tree: {tree}")
    if os.environ.get("EVENT") != "push" or os.environ.get("REUSE") != "true":
        return 0
    parents = [p["sha"] for p in commit.get("parents", [])]
    path = os.environ["WORKFLOW_REF"].split("/", 2)[2].split("@", 1)[0]
    arts = get(f"{api}/actions/artifacts?name=ci-full-run-{tree}&per_page=20").get("artifacts", [])
    for art in sorted(arts, key=lambda a: a["created_at"], reverse=True):
        if art.get("expired"):
            continue
        run = get(f"{api}/actions/runs/{art['workflow_run']['id']}")
        why = run_usable(run, repo=repo, workflow_path=path, parents=parents)
        if why:
            print(f"receipt {art['id']} (run {run.get('id')}) not usable: {why}")
            continue
        with zipfile.ZipFile(io.BytesIO(get(art["archive_download_url"], raw=True))) as z:
            receipt = json.loads(z.read("receipt.json"))
        receipt["run_id"] = run["id"]
        json.dump(receipt, open(os.path.join(tmp, "ci-plan-receipt.json"), "w"))
        print(f"receipt found: run {run['id']} (artifact {art['id']})")
        return 0
    print("no usable full-run receipt for this tree")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["lookup"]:
        raise SystemExit("usage: reuse.py lookup")
    sys.exit(lookup())
