#!/usr/bin/env python3
"""Helpers for the secret scan, on what scope.sh selected (stdlib only; run in the scanned repository).

  diffscan.py tree DIR REVS             write the added lines of `git log -p -U0 REVS` to DIR/<label>/<path>, each at
                                        its line number in the new file (blank lines between); print the file count
  diffscan.py count REVS                the number of commits gitleaks 8.30.1 reports as scanned for --log-opts=REVS
  diffscan.py gitleaks REPORT LOG RC N  judge a gitleaks run (rc, error lines, scanned count == N); print findings
  diffscan.py trufflehog TREE           read `trufflehog --json` results on stdin; print findings
  diffscan.py trufflehog-log LOG MIN    judge trufflehog's stderr: no error line, "finished scanning", chunks >= MIN

Findings are printed as detector/rule, commit, path and line, NEVER the matched value (no Raw, RawV2, Redacted,
Secret, Match or Line field is ever read out). A finding on a local scan commit is named for what it stands for: a
merge's remerge delta names the MERGE, the net commit names "net change <merge-base>..<head>".

<label> in the tree is the commit's SHA; for a remerge delta it is the MERGE's SHA, for the net change the net commit's.
Exit codes: 0 clean, 1 findings or a failed check, 2 usage or a malformed input.
"""
import json
import os
import re
import subprocess
import sys

NS = "refs/secret-scan/leg/"
REV_TOKEN = re.compile(r"^(\^?[0-9a-f]{40}|--glob=refs/secret-scan/(leg|auto)/\*|--not)$")
HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TOKENISH = re.compile(r"[A-Za-z0-9+=_-]{16,}")


def die(msg, code=2):
    print(f"::error::diffscan: {msg}", file=sys.stderr)
    sys.exit(code)


def revs_of(text):
    revs = text.split()
    bad = [t for t in revs if not REV_TOKEN.match(t)]
    if not revs or bad:
        die(f"refusing revs with unexpected token(s): {bad[:3]}")
    return revs


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def legs():
    """{local scan commit: (tree label, description)} from refs/secret-scan/leg/*."""
    out = {}
    for line in git("for-each-ref", "--format=%(objectname) %(refname)", NS).decode().splitlines():
        sha, ref = line.split(" ", 1)
        name = ref[len(NS):]
        if name == "net":
            subject = git("log", "-1", "--format=%s", sha).decode().strip()
            m = re.search(r"net change ([0-9a-f]{40})\.\.([0-9a-f]{40})", subject)
            span = f"{m.group(1)[:12]}..{m.group(2)[:12]}" if m else "merge-base..head"
            out[sha] = (sha, f"net change {span} (local commit {sha[:12]})")
        else:
            out[sha] = (name, f"merge {name} (what it adds beyond the automatic merge)")
    return out


def describe(table, key):
    """A commit SHA or tree label -> what it stands for."""
    if key in table:
        return table[key][1]
    for label, desc in table.values():
        if label == key:
            return desc
    return f"commit {key}"


def unquote(raw):
    """A path as git prints it in a diff header: C-quoted when it has unusual bytes."""
    if not raw.startswith(b'"'):
        return raw
    body, out, i = raw[1:-1], bytearray(), 0
    esc = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10, ord("v"): 11, ord("f"): 12, ord("r"): 13,
           ord('"'): 34, ord("\\"): 92}
    while i < len(body):
        c = body[i]
        if c != 92:
            out.append(c)
            i += 1
        elif body[i + 1] in esc:
            out.append(esc[body[i + 1]])
            i += 2
        else:
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
    return bytes(out)


def log_p(revs, extra=()):
    cmd = ["git", "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", *extra, "--format=%x01%H", *revs]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE)


def tree(out_dir, revs):
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        die(f"{out_dir} exists and is not empty")
    os.makedirs(out_dir, exist_ok=True)
    root = os.path.realpath(out_dir)
    table = legs()
    files = 0
    label = path = None
    lines = {}
    in_hunk = False
    lineno = 0

    def flush():
        nonlocal files, lines
        if label and path and lines:
            parts = path.split(b"/")
            if path.startswith(b"/") or any(p in (b"", b".", b"..") for p in parts):
                die(f"refusing an unsafe path in {label}")
            dest = os.path.join(root, label, os.fsdecode(path))
            if not os.path.realpath(dest).startswith(root + os.sep):
                die(f"refusing a path outside the tree in {label}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                at = 1
                for n in sorted(lines):
                    f.write(b"\n" * (n - at) + lines[n] + b"\n")
                    at = n + 1
            files += 1
        lines = {}

    proc = log_p(revs, ["--diff-merges=off", "--src-prefix=a/", "--dst-prefix=b/"])
    for raw in proc.stdout:
        raw = raw.rstrip(b"\n")
        if raw.startswith(b"\x01"):
            flush()
            sha = raw[1:].decode()
            label, path, in_hunk = table.get(sha, (sha, None))[0], None, False
        elif raw.startswith(b"diff --git "):
            flush()
            path, in_hunk = None, False
        elif in_hunk and raw.startswith(b"+"):
            if path is not None:
                lines[lineno] = raw[1:]
            lineno += 1
        elif in_hunk and raw.startswith((b"-", b"\\")):
            pass
        elif raw.startswith(b"+++ "):
            name = raw[4:]
            name = unquote(name) if name.startswith(b'"') else name.split(b"\t")[0]
            path = name[2:] if name.startswith(b"b/") else None  # /dev/null: a deleted file adds nothing
        else:
            m = HUNK.match(raw)
            if m:
                in_hunk, lineno = True, int(m.group(1))
            else:
                in_hunk = False
    flush()
    if proc.wait() != 0:
        die(f"git log failed ({proc.returncode})", 1)
    print(files)


def count(revs):
    """Commits with at least one text hunk in a file that is not deleted: what gitleaks 8.30.1 counts as scanned
    (measured: 1069 of 1069 on 1500 vagary-core commits; empty, binary-only, mode-only, rename-only, deletion-only
    commits and merges count 0)."""
    n, cur, deleted = 0, False, False
    proc = log_p(revs)
    for raw in proc.stdout:
        if raw.startswith(b"\x01"):
            n += cur
            cur, deleted = False, False
        elif raw.startswith(b"diff --git "):
            deleted = False
        elif raw.startswith(b"deleted file mode"):
            deleted = True
        elif raw.startswith(b"@@") and not deleted:
            cur = True
    n += cur
    if proc.wait() != 0:
        die(f"git log failed ({proc.returncode})", 1)
    print(n)


def gitleaks(report, log, rc, expected):
    problems = []
    text = ANSI.sub("", open(log, encoding="utf-8", errors="replace").read())
    if rc not in (0, 1):
        problems.append(f"gitleaks exited {rc}")
    errors = [ln for ln in text.splitlines() if re.match(r"^\S+ (ERR|FTL) ", ln)]
    if errors:
        problems.append(f"gitleaks logged {len(errors)} error line(s) (a git failure makes gitleaks scan nothing and exit 0)")
    scanned = re.findall(r" (\d+) commits scanned\.", text)
    if not scanned:
        problems.append("gitleaks printed no 'commits scanned' line")
    elif int(scanned[-1]) != expected:
        problems.append(f"gitleaks scanned {scanned[-1]} commit(s) but the selected revisions hold {expected} with text changes")
    try:
        found = json.load(open(report, encoding="utf-8"))
    except (OSError, ValueError) as e:
        problems.append(f"no readable gitleaks report ({type(e).__name__})")
        found = []
    table = legs()
    for f in found:
        print(f"::error::gitleaks {f.get('RuleID')}: {describe(table, f.get('Commit', ''))}, "
              f"path {f.get('File')}, line {f.get('StartLine')}")
    if rc == 1 and not found:
        problems.append("gitleaks exited 1 with an empty report")
    if rc == 0 and found:
        problems.append("gitleaks exited 0 with findings in its report")
    for p in problems:
        print(f"::error::{p}")
    print(f"gitleaks: {len(found)} finding(s); scanned {scanned[-1] if scanned else '?'} of {expected} commit(s)")
    sys.exit(1 if problems or found else 0)


def trufflehog(tree_dir):
    root = os.path.realpath(tree_dir) + os.sep if tree_dir else None
    table = legs()
    found = bad = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            data = d["SourceMetadata"]["Data"]
            det = d["DetectorName"]
        except (ValueError, KeyError, TypeError):
            bad += 1  # never echoed: it could carry a value
            continue
        state = "verified" if d.get("Verified") else "unverified"
        if "Filesystem" in data and root:
            fs = data["Filesystem"]
            rel = os.path.realpath(fs.get("file", ""))
            if rel.startswith(root):
                label, _, path = rel[len(root):].partition(os.sep)
                where = f"{describe(table, label)}, path {path}, line {fs.get('line')}"
            else:
                where = f"a file outside the scan tree, line {fs.get('line')}"
        elif "Git" in data:
            g = data["Git"]
            where = f"{describe(table, g.get('commit', ''))}, path {g.get('file')}, line {g.get('line')}"
        else:
            where = f"source {sorted(data)}"
        found += 1
        print(f"::error::trufflehog {det} ({state}): {where}")
    if bad:
        print(f"::error::trufflehog printed {bad} output line(s) that are not results (not shown)")
    print(f"trufflehog: {found} finding(s)")
    sys.exit(1 if found or bad else 0)


def trufflehog_log(log, min_chunks):
    problems, finished = [], []
    for line in open(log, encoding="utf-8", errors="replace"):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except ValueError:
            problems.append("a stderr line that is not a JSON log record (not shown)")
            continue
        if d.get("level") == "error":
            msg = TOKENISH.sub("<masked>", f"{d.get('msg')}: {d.get('error', '')}")[:300]
            problems.append(f"trufflehog logged an error: {msg}")
        if d.get("msg") == "finished scanning":
            finished.append(d)
    if not finished:
        problems.append("trufflehog never logged 'finished scanning'")
    elif int(finished[-1].get("chunks", 0)) < min_chunks:
        problems.append(f"trufflehog scanned {finished[-1].get('chunks')} chunk(s), expected at least {min_chunks}")
    else:
        print(f"trufflehog: finished scanning, {finished[-1].get('chunks')} chunk(s), {finished[-1].get('bytes')} byte(s)")
    for p in problems:
        print(f"::error::{p}")
    sys.exit(1 if problems else 0)


def main(argv):
    cmd, args = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    if cmd == "tree" and len(args) == 2:
        tree(args[0], revs_of(args[1]))
    elif cmd == "count" and len(args) == 1:
        count(revs_of(args[0]))
    elif cmd == "gitleaks" and len(args) == 4:
        gitleaks(args[0], args[1], int(args[2]), int(args[3]))
    elif cmd == "trufflehog" and len(args) == 1:
        trufflehog(args[0])
    elif cmd == "trufflehog-log" and len(args) == 2:
        trufflehog_log(args[0], int(args[1]))
    else:
        die("usage: diffscan.py tree DIR REVS | count REVS | gitleaks REPORT LOG RC N | trufflehog TREE | trufflehog-log LOG MIN")


if __name__ == "__main__":
    main(sys.argv)
