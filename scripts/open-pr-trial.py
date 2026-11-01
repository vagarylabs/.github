#!/usr/bin/env python3
"""open-pr-trial: before a gate rollout merges, run the new gate over a trial merge of EVERY open PR (root's K2 R3b).

A gate that lands on main is judged later on each open PR's next run, against the new main. A PR based before the
gate then goes red only when its checks run, often in the merge queue (execnode's #1140 case: two approved vps PRs
would have red on main's new hang-guard gate). This tool finds those PRs before the gate merges, with their owners.

For each open PR into --base-branch:
  1. a scratch clone that shares --clone's objects is reset to --candidate (the gate's own head);
  2. the PR head (refs/pull/N/head, fetched from --clone's origin) is merged WITHOUT a commit, so no commit, hook-less
     or otherwise, is ever made;
  3. --cmd runs in that working tree with TRIAL_BASE (the candidate sha), TRIAL_PR and TRIAL_HEAD (the PR head) set.
Result per PR:
  - GREEN: --cmd exited 0;
  - RED: it did not (the last lines are kept);
  - CONFLICT: the PR does not merge cleanly onto the candidate, so it must merge main first anyway (the files are
    listed);
  - ERROR: the PR head could not be fetched, or --cmd timed out.
Nothing is committed or pushed, and nothing is written to --clone. The scratch clone is this tool's own temporary
directory, removed at the end.

Example (K2's test-bounds adoption in vagaris):
  open-pr-trial.py --clone ~/vagaris --candidate cli/test-bounds-adoption --repo vagarylabs/vagaris \\
    --cmd 'python3 /path/to/.github/actions/test-bounds/check.py check --worktree --base "$TRIAL_BASE" --event pull_request'
Exit: 0 when every PR is GREEN or CONFLICT (a conflict is the PR's own, pre-existing work); 1 when any is RED or ERROR;
2 on a usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TAIL_LINES = 12


class Usage(Exception):
    pass


def git(cwd, *args, check=True, timeout=600):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"git {' '.join(args[:3])} exited {p.returncode}: {p.stderr.strip()[:300]}")
    return p


def open_prs(repo: str, base_branch: str, prs_json: str | None) -> list[dict]:
    """[{number, author, title, head}] of the open PRs into base_branch, oldest first."""
    if prs_json:
        raw = json.loads(Path(prs_json).read_text(encoding="utf-8"))
    else:
        if not repo:
            raise Usage("--repo OWNER/NAME is required to list the open PRs (or pass --prs-json)")
        # --jq prints one compact object per line, so a page boundary (or a "][" inside a PR body) never splits one.
        p = subprocess.run(["gh", "api", "--paginate", f"repos/{repo}/pulls?state=open&base={base_branch}&per_page=100",
                            "--jq", ".[] | {number, title, user: {login: .user.login}, head: {sha: .head.sha}}"],
                           capture_output=True, text=True, timeout=300)
        if p.returncode:
            raise RuntimeError(f"listing the open PRs failed (gh exited {p.returncode})")
        raw = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
        if not raw:
            raise RuntimeError("gh listed no open PRs; refusing to report an empty trial as clean")
    out = []
    for pr in raw:
        out.append({"number": int(pr["number"]), "author": (pr.get("user") or {}).get("login", pr.get("author", "?")),
                    "title": str(pr.get("title", ""))[:80], "head": (pr.get("head") or {}).get("sha", pr.get("head_sha", ""))})
    return sorted(out, key=lambda r: r["number"])


def trial(work: Path, candidate: str, pr: dict, cmd: str, timeout: int) -> dict:
    row = {**pr, "result": "", "detail": ""}
    git(work, "reset", "--quiet", "--hard", candidate)
    git(work, "clean", "-qfdx")
    ref = f"refs/trial/pr-{pr['number']}"
    f = git(work, "fetch", "--quiet", "--no-tags", "source", f"+refs/pull/{pr['number']}/head:{ref}", check=False)
    if f.returncode:
        row.update(result="ERROR", detail=f"the PR head could not be fetched: {f.stderr.strip()[:200]}")
        return row
    m = git(work, "-c", "user.name=open-pr-trial", "-c", "user.email=open-pr-trial@invalid", "merge", "--no-commit",
            "--no-ff", "--quiet", ref, check=False)
    if m.returncode:
        files = git(work, "diff", "--name-only", "--diff-filter=U", check=False).stdout.split()
        git(work, "merge", "--abort", check=False)
        row.update(result="CONFLICT", detail="conflicts with the candidate: " + (", ".join(files[:8]) or m.stdout.strip()[:200]))
        return row
    env = {**os.environ, "TRIAL_BASE": candidate, "TRIAL_PR": str(pr["number"]),
           "TRIAL_HEAD": git(work, "rev-parse", ref).stdout.strip()}
    try:
        r = subprocess.run(cmd, shell=True, cwd=work, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        row.update(result="ERROR", detail=f"--cmd timed out after {timeout} s")
    else:
        tail = (r.stdout + r.stderr).strip().splitlines()[-TAIL_LINES:]
        row.update(result="GREEN" if r.returncode == 0 else "RED",
                   detail="" if r.returncode == 0 else f"exit {r.returncode}: " + " | ".join(tail))
    git(work, "merge", "--abort", check=False)
    return row


def markdown(rows: list[dict], candidate: str) -> str:
    counts = {k: sum(1 for r in rows if r["result"] == k) for k in ("GREEN", "RED", "CONFLICT", "ERROR")}
    lines = [f"### open-PR trial onto {candidate[:12]}: " + ", ".join(f"{n} {k}" for k, n in counts.items()), "",
             "| PR | owner | result | detail |", "|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: ("RED", "ERROR", "CONFLICT", "GREEN").index(r["result"])):
        detail = r["detail"].replace("|", "/")[:400]
        lines.append(f"| #{r['number']} {r['title']} | {r['author']} | {r['result']} | {detail} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--clone", required=True, help="a local clone whose origin has the PR refs")
    ap.add_argument("--candidate", required=True, help="the rev the gate lands as (its PR head)")
    ap.add_argument("--cmd", required=True, help="the gate, run in each trial tree (shell)")
    ap.add_argument("--repo", default="", help="OWNER/NAME, to list the open PRs with gh")
    ap.add_argument("--base-branch", default="main")
    ap.add_argument("--prs-json", help="the open PRs as JSON instead of gh (tests)")
    ap.add_argument("--only", default="", help="comma-separated PR numbers")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per PR for --cmd")
    ap.add_argument("--json", dest="json_out", help="write the rows here")
    args = ap.parse_args(argv)
    try:
        clone = Path(args.clone).resolve()
        cand = git(clone, "rev-parse", "--verify", f"{args.candidate}^{{commit}}", check=False)
        if cand.returncode:
            raise Usage(f"--candidate {args.candidate} is not a commit in {clone}")
        candidate = cand.stdout.strip()
        source = git(clone, "remote", "get-url", "origin").stdout.strip()
        prs = open_prs(args.repo, args.base_branch, args.prs_json)
        if args.only:
            want = {int(x) for x in args.only.split(",") if x.strip()}
            prs = [p for p in prs if p["number"] in want]
    except Usage as e:
        print(f"open-pr-trial: {e}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="open-pr-trial-"))
    rows = []
    try:
        work = tmp / "w"
        git(tmp, "clone", "--quiet", "--shared", "--no-checkout", str(clone), str(work))
        git(work, "remote", "add", "source", source)
        git(work, "checkout", "--quiet", "--detach", candidate)
        for i, pr in enumerate(prs, 1):
            row = trial(work, candidate, pr, args.cmd, args.timeout)
            rows.append(row)
            print(f"[{i}/{len(prs)}] #{row['number']} {row['result']}", file=sys.stderr, flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report = markdown(rows, candidate)
    print(report)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"candidate": candidate, "rows": rows}, indent=1) + "\n",
                                       encoding="utf-8")
    return 1 if any(r["result"] in ("RED", "ERROR") for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
