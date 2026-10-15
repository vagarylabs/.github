#!/usr/bin/env python3
"""Dogfood checks for .github/workflows/source-prep-stats.yml: a real actions/checkout, measured.

  dogfood_check.py record      LEG RECORD_JSON FIXTURE_PATH
  dogfood_check.py telemetry   LEG TELEMETRY_PATH
  dogfood_check.py artifact    NAME          (GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_API_URL)

Legs: depth0 (fetch-depth 0), blobless (filter blob:none), shallow-sparse (fetch-depth 1 + sparse-checkout).
Each check prints what it saw and exits non-zero on the first violated expectation.
"""
import json
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcstats  # noqa: E402


def expect(cond, what, got):
    print("%s %s: %r" % ("ok  " if cond else "FAIL", what, got))
    if not cond:
        raise SystemExit(1)


def check_record(leg, text, fixture):
    r = json.loads(text)
    expect(srcstats.validate(r, "source-prep.v1.json") == [], "schema source-prep.v1", srcstats.validate(r, "source-prep.v1.json"))
    expect(r["checkout"]["outcome"] == "success", "checkout outcome", r["checkout"]["outcome"])
    expect((r["checkout"]["seconds"] or 0) > 0, "checkout seconds", r["checkout"]["seconds"])
    # trace2 reached the wrapped `uses:` step through step-level env, or there would be no processes.
    trace = (r["measurement"] or {}).get("trace") or {}
    expect(trace.get("processes", 0) > 0, "trace2 processes from the wrapped checkout", trace)
    expect("transfer" not in r["unknown"], "transfer measured", r["unknown"].get("transfer"))
    expect((r["bytes"] or 0) > 0 and (r["objects"] or 0) > 0, "bytes and objects", (r["bytes"], r["objects"]))
    expect(r["transfer"]["fetch_attempts"] >= 1, "fetch attempts", r["transfer"]["fetch_attempts"])
    expect(r["warm"] is False, "cold start", r["warm"])
    if leg == "depth0":
        expect((r["depth"], r["shallow"], r["partial"], r["filter"], r["sparse"]) == ("full", False, False, None, False),
               "depth/shallow/partial/filter/sparse", (r["depth"], r["shallow"], r["partial"], r["filter"], r["sparse"]))
        expect(r["completeness"] == "complete", "completeness", r["completeness"])
        du = int(subprocess.run(["du", "-sb", os.path.join(fixture, ".git")], capture_output=True, text=True,
                                check=True).stdout.split()[0])
        got = r["bytes_detail"]["git_dir_bytes_after"]
        expect(abs(got - du) / du <= 0.01, "git_dir_bytes within 1% of du -sb .git (%d)" % du, got)
    elif leg == "blobless":
        expect((r["partial"], r["filter"], r["depth"]) == (True, "blob:none", "full"), "partial/filter/depth",
               (r["partial"], r["filter"], r["depth"]))
        expect(r["incomplete_reasons"] == ["partial"], "incomplete reasons", r["incomplete_reasons"])
        expect(r["transfer"]["lazy_fetches"] >= 1, "checkout fetched HEAD blobs lazily", r["transfer"]["lazy_fetches"])
    elif leg == "shallow-sparse":
        expect((r["shallow"], r["depth"], r["sparse"]) == (True, 1, True), "shallow/depth/sparse",
               (r["shallow"], r["depth"], r["sparse"]))
        expect(r["partial"] is True, "actions/checkout makes a sparse checkout blob:none", r["filter"])
        expect((r["files_skipped"] or 0) > 0, "files outside the cone are skipped", r["files_skipped"])
        expect(r["incomplete_reasons"] == ["shallow", "partial", "sparse"], "incomplete reasons",
               r["incomplete_reasons"])
    else:
        raise SystemExit("unknown leg %s" % leg)


def check_telemetry(leg, path):
    expect(bool(path) and os.path.isfile(path), "job-telemetry.json written", path)
    size = os.path.getsize(path)
    expect(0 < size < 8192, "small artifact (bytes)", size)
    with open(path) as fh:
        doc = json.load(fh)
    expect(srcstats.validate(doc, "job-telemetry.v1.json") == [], "schema job-telemetry.v1",
           srcstats.validate(doc, "job-telemetry.v1.json"))
    records = doc["source_prep"] or []
    expect(len(records) == 1 and (records[0]["bytes"] or 0) > 0, "one source-prep record with non-zero bytes",
           [r["bytes"] for r in records])
    fp = doc["footprint"]
    expect(fp["peak_mib"] is not None or "footprint.peak_mib" in doc["unknown"], "peak measured or explained",
           (fp["peak_mib"], doc["unknown"].get("footprint.peak_mib")))
    if leg == "blobless":
        git = doc["after_checkout_git"] or {}
        expect(git.get("lazy_fetches", 0) >= 1, "lazy fetches after the checkout (trace-job)", git)


def check_artifact(name):
    url = "%s/repos/%s/actions/runs/%s/artifacts?name=%s" % (
        os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_RUN_ID"], name)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        arts = json.load(resp).get("artifacts", [])
    expect(len(arts) == 1 and arts[0]["size_in_bytes"] > 0, "artifact uploaded with non-zero bytes",
           [(a["name"], a["size_in_bytes"]) for a in arts])


def main(argv):
    if argv[:1] == ["record"] and len(argv) == 4:
        check_record(argv[1], argv[2], argv[3])
    elif argv[:1] == ["telemetry"] and len(argv) == 3:
        check_telemetry(argv[1], argv[2])
    elif argv[:1] == ["artifact"] and len(argv) == 2:
        check_artifact(argv[1])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
