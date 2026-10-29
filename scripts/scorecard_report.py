#!/usr/bin/env python3
"""scorecard helper: turn ONE repository's OpenSSF Scorecard JSON into a report-only summary.

Stdlib only. The reusable workflow .github/workflows/scorecard-weekly.yml carries a byte-identical copy of this file
inline (a reusable workflow cannot read a script from its own repository), and scripts/test_scorecard_report.py fails if
the copy drifts. Source of truth: this file.

  report --result FILE --repo OWNER/NAME [--rc FILE]   FILE is one `scorecard --format json` result, for exactly
                                                       github.com/OWNER/NAME; --rc holds that run's exit status.
                                                       Writes a Markdown summary. Exits 1 when there is no usable
                                                       result: report-only never means "pass on a void".

Root's U1 decisions (2026-10-29): each repository scores ITSELF, and its result stays in its own run (no cross-repository
report, no aggregation repository). The token is the caller's own contents:read GITHUB_TOKEN, so a check Scorecard cannot
evaluate with it (score -1) is UNMEASURED, never failing. Nothing is filed.
"""
import argparse
import json
import re
import sys

REPO_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")


def load_result(path, rc_path, repo):
    """(result dict or None, reason). A result must be Scorecard JSON for exactly github.com/<repo>, from a run that
    exited 0 when its exit status is known."""
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except FileNotFoundError:
        return None, "no result file"
    except (OSError, ValueError):
        return None, "result is not valid JSON"
    if not isinstance(d, dict) or not isinstance(d.get("checks"), list) or not isinstance(d.get("score"), (int, float)):
        return None, "result has no score or checks"
    if (d.get("repo") or {}).get("name") != f"github.com/{repo}":
        return None, "result names a different repository"
    rc = None
    if rc_path:
        try:
            with open(rc_path, encoding="utf-8") as fh:
                rc = fh.read().strip()
        except OSError:
            return None, "no exit status file"
    if rc not in (None, "0"):
        return None, f"scorecard exited {rc}"
    return d, ""


def classify(d, fail_below):
    """[(check, score, state, reason)] sorted by check: state is FAIL (0 <= score < fail_below), PASS, or UNMEASURED (a
    score Scorecard could not compute with this token, -1, or no score at all). UNMEASURED never counts as failing."""
    rows = []
    for c in d["checks"]:
        score = c.get("score")
        if not isinstance(score, (int, float)) or isinstance(score, bool) or score < 0:
            state = "UNMEASURED"
        else:
            state = "FAIL" if score < fail_below else "PASS"
        rows.append((str(c.get("name", "?")), score, state, " ".join(str(c.get("reason") or "").split())))
    return sorted(rows)


def cell(text, limit=160):
    text = text.replace("|", "\\|")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def render(repo, d, why, fail_below):
    out = ["## OpenSSF Scorecard (report-only)", ""]
    if d is None:
        out += [f"{repo}: no usable result ({why}). A void is not a pass.", ""]
        return "\n".join(out) + "\n"
    version = (d.get("scorecard") or {}).get("version") or "unknown"
    rows = classify(d, fail_below)
    n = {s: sum(1 for r in rows if r[2] == s) for s in ("FAIL", "UNMEASURED", "PASS")}
    score = f"{d['score']:.1f}/10" if d["score"] >= 0 else "none (no check could be scored)"
    out.append(f"{repo}, Scorecard {version}: score {score}. {n['FAIL']} failing (below {fail_below}/10), "
               f"{n['UNMEASURED']} UNMEASURED (not evaluable with this run's contents:read token; never failing), "
               f"{n['PASS']} passing.")
    out += ["", "| Check | Score | State | Reason |", "|---|---|---|---|"]
    for name, s, state, reason in sorted(rows, key=lambda r: ({"FAIL": 0, "UNMEASURED": 1, "PASS": 2}[r[2]], r[0])):
        out.append(f"| {cell(name)} | {'-' if state == 'UNMEASURED' else s} | {state} | {cell(reason)} |")
    out.append("")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("report")
    b.add_argument("--result", required=True)
    b.add_argument("--rc", help="the file holding scorecard's exit status")
    b.add_argument("--repo", required=True, help="OWNER/NAME: the repository that was scored")
    b.add_argument("--fail-below", type=int, default=5)
    b.add_argument("--summary", help="append the Markdown here (GITHUB_STEP_SUMMARY)")
    b.add_argument("--json-out", help="write the small machine summary here")
    args = ap.parse_args(argv)
    if not REPO_RE.match(args.repo) or not 0 <= args.fail_below <= 10:
        print("report: --repo must be OWNER/NAME and --fail-below 0-10", file=sys.stderr)
        return 2
    d, why = load_result(args.result, args.rc, args.repo)
    md = render(args.repo, d, why, args.fail_below)
    sys.stdout.write(md)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    if args.json_out:
        if d is None:
            small = {"repo": args.repo, "error": why}
        else:
            rows = classify(d, args.fail_below)
            small = {"repo": args.repo, "scorecard": (d.get("scorecard") or {}).get("version"), "score": d["score"],
                     "commit": (d.get("repo") or {}).get("commit"), "fail_below": args.fail_below,
                     "failing": [r[0] for r in rows if r[2] == "FAIL"],
                     "unmeasured": [r[0] for r in rows if r[2] == "UNMEASURED"],
                     "passing": [r[0] for r in rows if r[2] == "PASS"]}
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(small, fh, indent=1, sort_keys=True)
    return 1 if d is None else 0


if __name__ == "__main__":
    sys.exit(main())
