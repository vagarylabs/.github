#!/usr/bin/env python3
"""Read sibling repositories with a freshly minted read-only installation token, safely.

A new installation token is not visible everywhere at once. A clone made within about a second of minting can be
answered "remote: Repository not found" (exit 128), with nothing wrong: vagaris #825's "Supply vagary-core objects"
(job 122068344051, 2026-10-27) and core #920's merge group both lost a full red cycle to it. So:

  ready   GET <api>/repos/<owner>/<repo> with the token until it answers 200, for every repository, within one
          wall-clock bound (default 60 s) with backoff. This is a readiness probe, not a blind retry: a real loss of
          access still fails, by name, inside the bound ("App token cannot see <owner>/<repo>: installation scope?").
  clone   only then: a bare clone of main (`--bare repo:path`) and/or a shallow checkout pinned to main's commit at
          job start (`--checkout repo:dir`), each written to the step summary. And a SPARSE checkout in two phases
          (root's ruling 2026-10-29, item (2); contract agreed with spine on the board), so this never runs the
          consumer's code (its derive step, on a PR, is PR code):
            --tree repo:dir      main's commit at job start, commits and trees only (a blobless, depth-1 partial
                                 clone, no checkout), and its NUL-separated path listing, recorded under
                                 $RUNNER_TEMP/sibling-repo-read/ (<repo>.tree.z, <repo>.sha, <repo>.dir);
            (the consumer derives its patterns from <repo>.tree.z, e.g. vagary-core's sibling_sparse.py derive)
            --sparse repo:dir:patterns-file
                                 in a later call: `sparse-checkout set --no-cone` with exactly those patterns, a
                                 checkout of EXACTLY the commit the tree phase recorded (main is never re-resolved
                                 between the phases), then the promisor remote removed, so a later read outside the
                                 set is a git error, never a lazy fetch. The step output `sparse-ok` names each repository
                                 whose sparse checkout completed; a repository that falls back (the consumer removes
                                 the directory and asks for --checkout) is not in it.

The token comes from one of two sources, exactly one per call:
  - SIBLING_TOKEN: the App token action.yml minted (one token for every listed repository); or
  - --token-dir: broker-source-read's mint output (root's ruling 2026-10-29, core sibling-read path (a)): its 0700
    directory strictly inside $RUNNER_TEMP, one 0600 file `<owner>__<name>` per repository, each holding that
    repository's token. That action is the only broker client: it masked each token when it arrived, waited for
    readiness, and its `mode: revoke` step is the only revoke. This reads the files and nothing else: it never prints,
    re-masks, moves or deletes a token, and a directory or file that is a symlink, not the runner user's, readable by
    others, outside $RUNNER_TEMP, missing for a listed repository, or not exactly one credential is refused unread.
Each git call gets only its own repository's token, through a credential helper that reads it from the
environment: never argv, never a URL, never a printed line. Git runs outside any checkout with the http extraheader
blanked, which actions/checkout persists with THIS repository's GITHUB_TOKEN and which would otherwise override it.
Stdlib only.
"""
import argparse
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
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


def _broker_client():
    """broker-source-read's client.py, from the same vagarylabs/.github commit as this file (a composite action's whole
    repository is fetched at the pinned SHA): its RUNNER_TEMP confinement rule and credential shape are the contract
    the token directory was written under, so they are reused, never restated. Compiled from its SOURCE, never through
    the import system: that would write a __pycache__ into the runner's shared action cache and read one back, and a
    bytecode file planted there by an earlier job would then run in place of the source. Nothing in it runs at import."""
    path = pathlib.Path(__file__).resolve().parent.parent / "broker-source-read" / "client.py"
    module = types.ModuleType("broker_source_read_client")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module  # its dataclasses and annotations resolve their module by name
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def _private(path: str, kind: str) -> os.stat_result:
    """lstat of a token path that must be the runner user's own `kind` (dir or file), not a symlink, and closed to
    group and others."""
    try:
        st = os.lstat(path)
    except OSError as error:
        fail(f"--token-dir: {path} cannot be read ({type(error).__name__}): did broker-source-read mint into it?")
    want = stat.S_ISDIR if kind == "dir" else stat.S_ISREG
    if stat.S_ISLNK(st.st_mode) or not want(st.st_mode):
        fail(f"--token-dir: {path} is not a plain {kind} (a symlink or another type)")
    if st.st_uid != os.getuid():
        fail(f"--token-dir: {path} is not owned by the runner user")
    if st.st_mode & 0o077:
        fail(f"--token-dir: {path} is open to group or others (mode {stat.S_IMODE(st.st_mode):o}); broker-source-read "
             "writes 0700 directories and 0600 files")
    return st


def dir_tokens(token_dir: str, owner: str, repos: list[str]) -> dict:
    """{repo: token} from broker-source-read's token directory, one file `<owner>__<name>` per listed repository."""
    if os.environ.get("SIBLING_TOKEN"):
        fail("exactly one token source: SIBLING_TOKEN is set and --token-dir is given")
    client = _broker_client()
    try:
        client.inside_runner_temp(token_dir, "token-dir", dict(os.environ))
    except client.OutsideRunnerTemp as error:
        fail(f"--token-dir: {error}")
    _private(token_dir, "dir")
    tokens = {}
    for repo in repos:
        name = f"{owner}__{repo}"
        if not client.TOKEN_FILE_RE.fullmatch(name):
            fail(f"--token-dir: {name!r} is not a token file name broker-source-read writes")
        path = os.path.join(token_dir, name)
        _private(path, "file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(16385)
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError:
            value = ""
        if not client.CREDENTIAL_RE.fullmatch(value):
            fail(f"--token-dir: {path} does not hold exactly one credential (printable ASCII, no space or line break)")
        tokens[repo] = value
    return tokens


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


# The environment git (and the credential helper's shell) gets: no inherited GIT_*, shell start-up file or loader
# variable, and a PATH that a job step's GITHUB_PATH entries cannot reach (root's class item on #37).
UNSAFE_ENV = ("BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH")
SAFE_PATH = "/usr/bin:/bin"


def git(*args: str, cwd: str, secret: str = "", stdin: "str | None" = None) -> str:
    """git with only `secret` (one repository's token) for the credential helper; none for a local command."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in UNSAFE_ENV and k != "SIBLING_TOKEN"}
    # Only https (and file, the tests' remotes) is a transport: never ext::, which runs a command (root's R4 of #52, B2).
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, PATH=SAFE_PATH,
               GIT_ALLOW_PROTOCOL="https:file")
    if secret:
        env["SIBLING_TOKEN"] = secret
    # The EMPTY credential.helper first resets any helper a repository config names, so only ours sees the token; no
    # fsmonitor (a command git would run with this environment), hooks off, ext:: refused.
    out = subprocess.run(["git", "-c", "http.https://github.com/.extraheader=", "-c", "credential.helper=",
                          "-c", f"credential.helper={HELPER}", "-c", f"core.hooksPath={os.devnull}",
                          "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never", *args],
                         cwd=cwd, env=env, capture_output=True, text=True, timeout=600, input=stdin)
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


STATE = "sibling-repo-read"  # under $RUNNER_TEMP: each tree phase's record, which its sparse phase reads


def state_dir() -> str:
    root = os.environ.get("RUNNER_TEMP", "")
    if not root or not os.path.isabs(root):
        fail("--tree and --sparse keep their record under RUNNER_TEMP, which is not set (or not absolute)")
    path = os.path.join(root, STATE)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def records(repo: str) -> dict:
    state = state_dir()
    return {key: os.path.join(state, f"{repo}.{key}") for key in ("tree.z", "sha", "dir", "git")}


# Phase B's .git/config, whole (root's R4 of #52, B2): between the phases the consumer's code (PR code, on a PR) can
# write the clone's config, and a planted core.fsmonitor, credential helper, url.insteadOf or ext:: remote would run
# with the token in phase B. So before any token-carrying call phase B rewrites the config from this template, and
# refuses a .git whose top-level entries changed since phase A (a planted commondir points git at another repository's
# config).
CONFIG_TEMPLATE = """[core]
\trepositoryformatversion = 1
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[extensions]
\tpartialClone = origin
[remote "origin"]
\turl = {url}
\tpromisor = true
\tpartialclonefilter = blob:none
"""


def git_entries(dest: str) -> str:
    return "".join(f"{name}\n" for name in sorted(os.listdir(os.path.join(dest, ".git"))))


def fresh(dest: str, what: str) -> None:
    if os.path.exists(dest) and (not os.path.isdir(dest) or os.listdir(dest)):
        fail(f"--{what} destination {dest} exists and is not empty: a checkout goes into a fresh directory")
    os.makedirs(dest, exist_ok=True)


def main_sha(url: str, owner: str, repo: str, secret: str, outside: str) -> str:
    line = git("ls-remote", url, "refs/heads/main", cwd=outside, secret=secret).split("\t", 1)[0].strip()
    if not SHA.fullmatch(line):
        fail(f"{owner}/{repo} has no readable main")
    return line


def tree_phase(url: str, owner: str, repo: str, dest: str, secret: str, outside: str) -> dict:
    """Phase 1 of a sparse read: main's commit with its trees and no blob, and the listing a consumer derives from."""
    rec = records(repo)
    if any(os.path.lexists(path) for path in rec.values()):
        fail(f"--tree {repo}: a tree phase already ran for it in this job")
    sha = main_sha(url, owner, repo, secret, outside)
    fresh(dest, "tree")
    git("init", "--quiet", dest, cwd=outside)
    for key, value in (("core.repositoryformatversion", "1"), ("extensions.partialClone", "origin"),
                       ("remote.origin.url", url), ("remote.origin.promisor", "true"),
                       ("remote.origin.partialclonefilter", "blob:none")):
        git("-C", dest, "config", key, value, cwd=outside)
    git("-C", dest, "fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", sha, cwd=outside, secret=secret)
    # A server that ignores the filter sends every blob (git only warns): refused, never a silent full fetch. Read from
    # the local object store only (--batch-all-objects never lazy-fetches).
    kinds = git("-C", dest, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype)", cwd=outside).split()
    if "blob" in kinds:
        fail(f"--tree {repo}: the server sent blobs despite --filter=blob:none ({kinds.count('blob')} of them)")
    names = git("-C", dest, "ls-tree", "-r", "-z", "--name-only", sha, cwd=outside)
    for key, body in (("tree.z", names), ("sha", sha + "\n"), ("dir", dest + "\n"), ("git", git_entries(dest))):
        fd = os.open(rec[key], os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
    return {"repo": repo, "kind": "tree", "path": dest, "commit": sha, "tree": rec["tree.z"], "paths": names.count("\0")}


def sparse_phase(url: str, owner: str, repo: str, dest: str, patterns_file: str, secret: str, outside: str) -> dict:
    """Phase 2: exactly `patterns_file`'s set of the commit phase 1 recorded, and no promisor left behind."""
    rec = records(repo)
    try:
        with open(rec["sha"]) as fh:
            sha = fh.read().strip()
        with open(rec["dir"]) as fh:
            prepared = fh.read().rstrip("\n")
        with open(rec["tree.z"]) as fh:
            total = fh.read().count("\0")
        with open(rec["git"]) as fh:
            entries = fh.read()
    except OSError:
        fail(f"--sparse {repo}: no tree phase ran for it in this job (ask for `trees: {repo}:<dir>` first)")
    if not SHA.fullmatch(sha):
        fail(f"--sparse {repo}: the tree phase's commit record is not a commit")
    if dest != prepared:
        fail(f"--sparse {repo}: {dest} is not the directory its tree phase prepared ({prepared})")
    if sorted(os.listdir(dest)) != [".git"]:
        fail(f"--sparse {repo}: {dest} is no longer the tree phase's bare partial clone (it has files, or no .git)")
    gitdir = os.path.join(dest, ".git")
    if not stat.S_ISDIR(os.lstat(gitdir).st_mode):
        fail(f"--sparse {repo}: {gitdir} is not a plain directory (a symlink or a gitdir file)")
    if git_entries(dest) != entries:
        fail(f"--sparse {repo}: {gitdir}'s entries changed since the tree phase (a planted commondir, worktree or module?)")
    config = os.path.join(gitdir, "config")
    if os.path.lexists(config):
        os.unlink(config)
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(CONFIG_TEMPLATE.format(url=url))
    try:
        with open(patterns_file, newline="") as fh:  # newline="": a carriage return stays visible to the check below
            patterns = fh.read()
    except OSError as error:
        fail(f"--sparse {repo}: the patterns file {patterns_file} cannot be read ({type(error).__name__})")
    if "\r" in patterns or "\0" in patterns:
        fail(f"--sparse {repo}: the patterns file holds a carriage return or a NUL")
    if not [line for line in patterns.splitlines() if line.strip() and not line.lstrip().startswith("#")]:
        fail(f"--sparse {repo}: the patterns file is empty: an empty set is refused, never a checkout of nothing")
    git("-C", dest, "sparse-checkout", "set", "--no-cone", "--stdin", cwd=outside, stdin=patterns)
    git("-C", dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", sha, cwd=outside, secret=secret)
    # No lazy fetch afterwards: a read of a blob outside the set is an ERROR, never one network round trip per object.
    git("-C", dest, "remote", "remove", "origin", cwd=outside)
    git("-C", dest, "config", "--unset", "extensions.partialClone", cwd=outside)
    head = git("-C", dest, "rev-parse", "HEAD", cwd=outside).strip()
    if head != sha:
        fail(f"{owner}/{repo} sparse checkout at {dest} is at {head}, not the tree phase's {sha}")
    listed = git("-C", dest, "ls-files", "-t", "-z", cwd=outside).split("\0")
    materialized = sum(1 for entry in listed if entry and not entry.startswith("S "))
    if materialized == 0:
        # root's R4 of #52, B1: a set that matches nothing (a stale derived path) is no checkout, never a success.
        fail(f"--sparse {repo}: the patterns matched nothing in {sha}: a stale derived set, refused")
    return {"repo": repo, "kind": "sparse", "path": dest, "commit": sha, "materialized": materialized, "paths": total}


def clone(server: str, owner: str, bare: list[str], checkouts: list[str], allowed: list[str],
          tokens: "dict | None" = None, trees: "list[str] | None" = None, sparse: "list[str] | None" = None) -> list[dict]:
    """`tokens` is {repo: token} from --token-dir; without it every repository uses SIBLING_TOKEN."""
    if tokens is None:
        shared = token()
        tokens = {repo: shared for repo in allowed}
    planned = []
    for value in sparse or []:
        repo, sep, rest = value.partition(":")
        dest, sep2, patterns_file = rest.rpartition(":")
        if not (sep and sep2) or not NAME.fullmatch(repo) or not dest or not patterns_file:
            fail(f"--sparse wants repo:dir:patterns-file, got {value!r}")
        planned.append((repo, os.path.abspath(dest), patterns_file))
    tree_repos = {repo for repo, _ in pairs(trees or [], "tree")}
    for repo, _, _ in planned:
        if repo in tree_repos:
            fail(f"--sparse {repo}: its tree phase is in this same call; the consumer derives the patterns in between")
    rows = []
    outside = tempfile.mkdtemp(prefix="sibling-read-")
    for kind, values in (("bare", bare), ("checkout", checkouts), ("tree", trees or [])):
        for repo, dest in pairs(values, kind):
            if repo not in allowed:
                fail(f"{repo} is not in the token's repositories ({', '.join(allowed)})")
            url = f"{server.rstrip('/')}/{owner}/{repo}.git"
            dest = os.path.abspath(dest)
            secret = tokens[repo]
            if kind == "tree":
                rows.append(tree_phase(url, owner, repo, dest, secret, outside))
                continue
            if kind == "bare":
                git("clone", "--quiet", "--bare", "--single-branch", "--branch", "main", url, dest, cwd=outside,
                    secret=secret)
                sha = git("--git-dir", dest, "rev-parse", "refs/heads/main", cwd=outside).strip()
            else:
                sha = main_sha(url, owner, repo, secret, outside)
                fresh(dest, "checkout")
                git("init", "--quiet", dest, cwd=outside)
                git("-C", dest, "fetch", "--quiet", "--depth", "1", url, sha, cwd=outside, secret=secret)
                git("-C", dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD", cwd=outside)
                head = git("-C", dest, "rev-parse", "HEAD", cwd=outside).strip()
                if head != sha:
                    fail(f"{owner}/{repo} checkout at {dest} is at {head}, not main's {sha}")
            rows.append({"repo": repo, "kind": kind, "path": dest, "commit": sha})
    for repo, dest, patterns_file in planned:
        if repo not in allowed:
            fail(f"{repo} is not in the token's repositories ({', '.join(allowed)})")
        rows.append(sparse_phase(f"{server.rstrip('/')}/{owner}/{repo}.git", owner, repo, dest, patterns_file,
                                 tokens[repo], outside))
    return rows


def outputs(rows: list[dict]) -> None:
    """Step outputs: `trees` (JSON {repo: {dir, tree, sha}}) and `sparse-ok` (the repositories whose sparse checkout
    completed, comma-separated)."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    trees = {r["repo"]: {"dir": r["path"], "tree": r["tree"], "sha": r["commit"]} for r in rows if r["kind"] == "tree"}
    done = [r["repo"] for r in rows if r["kind"] == "sparse"]
    with open(path, "a") as fh:
        fh.write(f"trees={json.dumps(trees, sort_keys=True)}\n")
        fh.write(f"sparse-ok={','.join(done)}\n")


def summarize(rows: list[dict]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not rows:
        return
    with open(path, "a") as summary:
        summary.write("### Sibling reads (main at job start)\n| repo | kind | path | commit | paths |\n|---|---|---|---|---|\n")
        for row in rows:
            paths = (f"{row['materialized']} of {row['paths']} materialized" if row["kind"] == "sparse"
                     else f"{row['paths']} listed, none materialized" if row["kind"] == "tree" else "all")
            summary.write(f"| {row['repo']} | {row['kind']} | {row['path']} | {row['commit']} | {paths} |\n")


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
    c.add_argument("--tree", action="append", default=[], help="repo:dir, repeatable: phase 1 of a sparse read")
    c.add_argument("--sparse", action="append", default=[], help="repo:dir:patterns-file, repeatable: phase 2")
    c.add_argument("--token-dir", help="broker-source-read's token directory (instead of SIBLING_TOKEN)")
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
        tokens = dir_tokens(a.token_dir, a.owner, repos) if a.token_dir else None
        rows = clone(a.server, a.owner, a.bare, a.checkout, repos, tokens, a.tree, a.sparse)
        summarize(rows)
        outputs(rows)
        print(json.dumps({"read": rows}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
