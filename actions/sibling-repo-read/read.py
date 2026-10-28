#!/usr/bin/env python3
"""Read sibling repositories with a freshly minted GitHub App installation token, safely.

A new installation token is not visible everywhere at once. A clone made within about a second of minting can be
answered "remote: Repository not found" (exit 128), with nothing wrong: vagaris #825's "Supply vagary-core objects"
(job 122068344051, 2026-10-27) and core #920's merge group both lost a full red cycle to it. So:

  ready   GET <api>/repos/<owner>/<repo> with the token until it answers 200, for every repository, within one
          wall-clock bound (default 60 s) with backoff. This is a readiness probe, not a blind retry: a real loss of
          access still fails, by name, inside the bound ("App token cannot see <owner>/<repo>: installation scope?").
  clone   only then: a bare clone of main (`--bare repo:path`) and/or a shallow checkout pinned to main's commit at
          job start (`--checkout repo:dir`), each written to the step summary.

The token is read from SIBLING_TOKEN and reaches git only through a credential helper that reads it from the
environment: never argv, never a URL, never a printed line. Git runs outside any checkout with the http extraheader
blanked, which actions/checkout persists with THIS repository's GITHUB_TOKEN and which would otherwise override it.
Stdlib only.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
SHA = re.compile(r"[0-9a-f]{40}")
HELPER = '!f(){ echo username=x-access-token; echo "password=$SIBLING_TOKEN"; }; f'


def fail(message: str) -> "None":
    print(f"sibling-repo-read: {message}", file=sys.stderr)
    sys.exit(1)


def token() -> str:
    value = os.environ.get("SIBLING_TOKEN", "")
    if not value:
        fail("SIBLING_TOKEN is empty: the App token was not minted")
    return value


def probe(api: str, owner: str, repo: str, secret: str, timeout: float) -> str:
    """One GET /repos/<owner>/<repo>: its HTTP status as text, or the network error's type."""
    request = urllib.request.Request(f"{api.rstrip('/')}/repos/{owner}/{repo}",
                                     headers={"Authorization": f"Bearer {secret}", "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sibling-repo-read"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return str(response.status)
    except urllib.error.HTTPError as error:
        return str(error.code)
    except (urllib.error.URLError, OSError) as error:
        return type(error).__name__


def ready(api: str, owner: str, repos: list[str], bound: float, sleep=time.sleep, clock=time.monotonic) -> list[dict]:
    """Wait until the token sees every repository (200), within one wall-clock bound shared by all of them."""
    secret = token()
    deadline = clock() + bound
    report = []
    for repo in repos:
        attempts, delay, status = 0, 1.0, ""
        while True:
            attempts += 1
            remaining = deadline - clock()
            status = probe(api, owner, repo, secret, timeout=max(1.0, min(10.0, remaining)))
            if status == "200":
                report.append({"repo": repo, "attempts": attempts})
                break
            remaining = deadline - clock()
            if remaining <= 0:
                fail(f"App token cannot see {owner}/{repo} after {bound:g} s (last answer {status}, {attempts} "
                     f"attempt(s)): installation scope?")
            sleep(min(delay, remaining))
            delay = min(delay * 2, 8.0)
    return report


def git(*args: str, cwd: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    out = subprocess.run(["git", "-c", "http.https://github.com/.extraheader=", "-c", f"credential.helper={HELPER}",
                          *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    if out.returncode != 0:
        # git's stderr can carry a URL; ours never holds the token, and the helper never echoes it.
        fail(f"git {args[0]} failed (exit {out.returncode}): {out.stderr.strip()[-400:]}")
    return out.stdout


def pairs(values: list[str], what: str) -> list[tuple[str, str]]:
    out = []
    for value in values:
        repo, sep, dest = value.partition(":")
        if not sep or not NAME.fullmatch(repo) or not dest:
            fail(f"--{what} wants repo:path, got {value!r}")
        out.append((repo, dest))
    return out


def clone(server: str, owner: str, bare: list[str], checkouts: list[str], allowed: list[str]) -> list[dict]:
    token()
    rows = []
    outside = tempfile.mkdtemp(prefix="sibling-read-")
    for kind, values in (("bare", bare), ("checkout", checkouts)):
        for repo, dest in pairs(values, kind):
            if repo not in allowed:
                fail(f"{repo} is not in the token's repositories ({', '.join(allowed)})")
            url = f"{server.rstrip('/')}/{owner}/{repo}.git"
            dest = os.path.abspath(dest)
            if kind == "bare":
                git("clone", "--quiet", "--bare", "--single-branch", "--branch", "main", url, dest, cwd=outside)
                sha = git("--git-dir", dest, "rev-parse", "refs/heads/main", cwd=outside).strip()
            else:
                line = git("ls-remote", url, "refs/heads/main", cwd=outside).split("\t", 1)[0].strip()
                if not SHA.fullmatch(line):
                    fail(f"{owner}/{repo} has no readable main")
                sha = line
                os.makedirs(dest, exist_ok=True)
                git("init", "--quiet", dest, cwd=outside)
                git("-C", dest, "fetch", "--quiet", "--depth", "1", url, sha, cwd=outside)
                git("-C", dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD", cwd=outside)
            rows.append({"repo": repo, "kind": kind, "path": dest, "commit": sha})
    return rows


def summarize(rows: list[dict]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not rows:
        return
    with open(path, "a") as summary:
        summary.write("### Sibling reads (main at job start)\n| repo | kind | path | commit |\n|---|---|---|---|\n")
        for row in rows:
            summary.write(f"| {row['repo']} | {row['kind']} | {row['path']} | {row['commit']} |\n")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("ready")
    r.add_argument("--api", required=True)
    r.add_argument("--owner", required=True)
    r.add_argument("--repos", required=True, help="comma-separated")
    r.add_argument("--bound", type=float, default=60.0)
    c = sub.add_parser("clone")
    c.add_argument("--server", required=True)
    c.add_argument("--owner", required=True)
    c.add_argument("--repos", required=True, help="comma-separated: the token's repositories")
    c.add_argument("--bare", action="append", default=[], help="repo:path, repeatable")
    c.add_argument("--checkout", action="append", default=[], help="repo:dir, repeatable")
    a = ap.parse_args(argv)
    if not NAME.fullmatch(a.owner):
        fail(f"bad owner {a.owner!r}")
    repos = [x.strip() for x in a.repos.split(",") if x.strip()]
    if not repos or not all(NAME.fullmatch(x) for x in repos):
        fail(f"bad repositories {a.repos!r}")
    if a.cmd == "ready":
        if not 0 < a.bound <= 600:
            fail("--bound must be in (0, 600] seconds")
        print(json.dumps({"ready": ready(a.api, a.owner, repos, a.bound)}))
    else:
        rows = clone(a.server, a.owner, a.bare, a.checkout, repos)
        summarize(rows)
        print(json.dumps({"read": rows}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
