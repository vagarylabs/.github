#!/usr/bin/env python3
"""Write the FULL-run receipt of a passed merge-group run (read by actions/full-run-reuse/reuse.py).

  receipt.py    env: FULL EVENT WORKFLOW_REF HEAD_SHA REPO JOB GITHUB_RUN_ID GITHUB_RUN_ATTEMPT RUNNER_TEMP GITHUB_OUTPUT

Writes $RUNNER_TEMP/ci-full-run/receipt.json and `written=a<attempt>` to GITHUB_OUTPUT only when the event is
merge_group and FULL is exactly "true"; otherwise `written=` and nothing else. A workflow_ref or sha that cannot be
bound to this repository is an error (the verdict job goes red), never a receipt.
"""
from __future__ import annotations

import json
import os
import re
import sys

SCHEMA = 2


def build_receipt(env: dict) -> dict | None:
    if env.get("EVENT") != "merge_group" or env.get("FULL") != "true":
        return None
    repo, ref, sha = env.get("REPO", ""), env.get("WORKFLOW_REF", ""), env.get("HEAD_SHA", "")
    if not repo or not ref.startswith(repo + "/") or "@" not in ref or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"cannot bind workflow_ref {ref!r} and sha {sha!r} to {repo!r}")
    path = ref[len(repo) + 1:].rsplit("@", 1)[0]
    if not path.startswith(".github/workflows/"):
        raise ValueError(f"workflow_ref {ref!r} does not name a workflow file")
    run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
    if run_id < 1 or attempt < 1:
        raise ValueError("run id and attempt must be positive")
    return {"schema": SCHEMA, "mode": "full", "event": "merge_group", "repository": repo, "workflow_path": path,
            "head_sha": sha, "run_id": run_id, "run_attempt": attempt, "job": env.get("JOB", "")}


def main() -> int:
    env = dict(os.environ)
    try:
        receipt = build_receipt(env)
    except (KeyError, ValueError) as error:
        print(f"full-run-receipt: {error}", file=sys.stderr)
        return 1
    with open(env["GITHUB_OUTPUT"], "a") as out:
        if receipt is None:
            print(f"no receipt: event {env.get('EVENT')}, full {env.get('FULL')!r}")
            out.write("written=\n")
            return 0
        directory = os.path.join(env["RUNNER_TEMP"], "ci-full-run")
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "receipt.json"), "w") as fh:
            json.dump(receipt, fh, sort_keys=True)
        out.write(f"written=a{receipt['run_attempt']}\n")
    print(f"receipt written for {receipt['head_sha']} (run {receipt['run_id']} attempt {receipt['run_attempt']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
