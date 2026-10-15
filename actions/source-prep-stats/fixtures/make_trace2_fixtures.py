#!/usr/bin/env python3
"""Regenerate fixtures/trace2/* from REAL git runs, sanitized (paths, host, port, git binary path).

  python3 actions/source-prep-stats/fixtures/make_trace2_fixtures.py

Cases:
  http-429-retry          fetch over smart HTTP; the first attempt is answered 429, the identical retry succeeds
  file-blobless-checkout  blob:none fetch over file:// (server-side upload-pack/pack-objects land in the client's
                          trace on a local transport) and a checkout that lazily fetches the HEAD blobs
test_trace2.py asserts the parser's reading of these files; a regenerated set must keep those expectations true.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from gitserver import GitHTTPServer  # noqa: E402
from test_hermetic import CLEAN, commit_files, git  # noqa: E402

OUT = os.path.join(HERE, "trace2")


def sanitize(case_dir, tmp, port):
    host = socket.gethostname()
    for name in sorted(os.listdir(case_dir)):
        path = os.path.join(case_dir, name)
        lines = []
        with open(path) as fh:
            for line in fh:
                text = line.replace(os.path.realpath(tmp), "/fixture").replace(tmp, "/fixture")
                text = text.replace("127.0.0.1:%d" % port, "127.0.0.1:0") if port else text
                text = text.replace(host, "runner")
                ev = json.loads(text)
                if ev.get("event") == "start" and ev.get("argv"):
                    ev["argv"][0] = re.sub(r".*/", "", ev["argv"][0])
                ev.pop("file", None)
                ev.pop("line", None)
                lines.append(json.dumps(ev, sort_keys=True))
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")


def main():
    tmp = tempfile.mkdtemp(prefix="trace2-fixtures-")
    try:
        work = os.path.join(tmp, "work")
        git("init", "-q", "-b", "main", work)
        commit_files(work, 0, 12)
        serve = os.path.join(tmp, "serve")
        os.makedirs(serve)
        bare = os.path.join(serve, "fixture.git")
        git("clone", "-q", "--bare", work, bare)
        git("-C", bare, "config", "uploadpack.allowFilter", "true")
        git("-C", bare, "repack", "-adq")

        case = os.path.join(OUT, "http-429-retry")
        shutil.rmtree(case, ignore_errors=True)
        os.makedirs(case)
        with GitHTTPServer(serve) as srv:
            dest = os.path.join(tmp, "http")
            git("init", "-q", dest)
            git("-C", dest, "remote", "add", "origin", srv.url("fixture.git"))
            git("-C", dest, "config", "--local", "gc.auto", "0")  # as actions/checkout does
            env = dict(CLEAN, GIT_TRACE2_EVENT=case, GIT_TRACE2_EVENT_NESTING="8", GIT_TERMINAL_PROMPT="0")
            srv.throttle(1)
            args = ["-C", dest, "-c", "protocol.version=2", "fetch", "--no-tags", "--prune",
                    "--no-recurse-submodules", "origin", "+refs/heads/main:refs/remotes/origin/main"]
            assert git(*args, env=env, check=False).returncode != 0
            git(*args, env=env)
            sanitize(case, tmp, srv.port)

        case = os.path.join(OUT, "file-blobless-checkout")
        shutil.rmtree(case, ignore_errors=True)
        os.makedirs(case)
        dest = os.path.join(tmp, "file")
        git("init", "-q", dest)
        git("-C", dest, "remote", "add", "origin", "file://" + bare)
        git("-C", dest, "config", "--local", "gc.auto", "0")
        env = dict(CLEAN, GIT_TRACE2_EVENT=case, GIT_TRACE2_EVENT_NESTING="8")
        git("-C", dest, "-c", "protocol.version=2", "fetch", "--no-tags", "--filter=blob:none", "origin",
            "+refs/heads/main:refs/remotes/origin/main", env=env)
        git("-C", dest, "checkout", "--force", "-B", "main", "refs/remotes/origin/main", env=env)
        sanitize(case, tmp, None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("fixtures written under", OUT)


if __name__ == "__main__":
    main()
