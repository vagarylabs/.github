#!/usr/bin/env python3
"""The runs file for `trusted/pin_audit.py record`: each repository's newest pin-audit runs and their results.

cli runs this weekly for the U1 board line, with the operator's own gh login; it never runs inside a workflow, and
nothing is aggregated anywhere else (U1 ruling a). Stdlib and gh only:

  python3 scripts/pin_audit_runs.py --out runs.json vagarylabs/vagary-core vagarylabs/vagaris ...
  python3 trusted/pin_audit.py record --runs runs.json --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

Per repository: `gh run list --workflow pin-audit.yml` (the caller's file name, see pin-audit.yml's example), newest
LIMIT runs, and for each completed run `gh run download -n pin-audit`. A run whose artifact cannot be read back
(expired after the workflow's 35-day retention, never uploaded) carries result null and why; a repository whose runs
cannot be listed is under `errors`. `record` never counts either as complete.
"""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

WORKFLOW = "pin-audit.yml"
LIMIT = 6  # five weekly runs fit the 35-day artifact retention, plus a manual one


def gh(args):
    try:
        r = subprocess.run(["gh"] + args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)
    return r.returncode, r.stdout, r.stderr


def runs_for(repo, gh=gh):
    """([run rows], None) or ([], why) when the runs cannot be listed."""
    rc, out, err = gh(["run", "list", "-R", repo, "--workflow", WORKFLOW, "--limit", str(LIMIT),
                       "--json", "databaseId,createdAt,conclusion,status"])
    if rc != 0:
        return [], "gh run list failed: %s" % (err.strip()[:200] or "exit %d" % rc)
    try:
        listed = json.loads(out)
    except ValueError:
        return [], "gh run list printed no JSON"
    rows = []
    for run in listed:
        row = {"id": run["databaseId"], "created_at": run["createdAt"], "conclusion": run.get("conclusion") or "",
               "result": None, "error": None}
        if run.get("status") != "completed":
            row["error"] = "run %s" % run.get("status")
        else:
            with tempfile.TemporaryDirectory() as d:
                rc, _, err = gh(["run", "download", str(run["databaseId"]), "-R", repo, "-n", "pin-audit", "-D", d])
                result = pathlib.Path(d) / "pin-audit.json"
                if rc != 0 or not result.is_file():
                    row["error"] = "artifact unavailable: %s" % (err.strip()[:200] or "no pin-audit.json")
                else:
                    try:
                        row["result"] = json.loads(result.read_text(encoding="utf-8"))
                    except ValueError:
                        row["error"] = "pin-audit.json does not parse"
        rows.append(row)
    return rows, None


def collect(repos, gh=gh):
    doc = {"repos": {}, "errors": {}}
    for repo in repos:
        rows, why = runs_for(repo, gh)
        if why:
            doc["errors"][repo] = why
        else:
            doc["repos"][repo] = rows
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("repos", nargs="+", metavar="OWNER/NAME")
    args = ap.parse_args(argv)
    doc = collect(args.repos)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    print("%d repositories read, %d could not be listed" % (len(doc["repos"]), len(doc["errors"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
