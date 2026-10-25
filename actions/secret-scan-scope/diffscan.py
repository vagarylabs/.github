#!/usr/bin/env python3
"""Helpers for the secret scan, on what scope.sh selected (stdlib only; run in the scanned repository).

  diffscan.py tree DIR REVS             write the added lines of `git log -p -U0 REVS` to DIR/<label>/<path>, each at
                                        its line number in the new file (blank lines between); print the file count
  diffscan.py count REVS                the number of commits gitleaks 8.30.1 reports as scanned for --log-opts=REVS
  diffscan.py gitleaks REPORT LOG RC N [--registry FILE --policy sweep|gate]
                                        judge a gitleaks run (rc, error lines, scanned count == N); print findings;
                                        delete REPORT
  diffscan.py trufflehog TREE [--registry FILE --policy sweep|gate]
                                        read `trufflehog --json` results on stdin; print findings
  diffscan.py trufflehog-log LOG MIN    judge trufflehog's stderr: no error line, "finished scanning", chunks >= MIN
  diffscan.py registry FILE POLICY      judge the caller's accepted-live registry (POLICY: sweep | gate); list entries
  diffscan.py excludes FILE HIST TREE   validate the caller's trufflehog sweep excludes; write HIST (git source, repo
                                        paths) and TREE (filesystem source, the <label>/<path> tree) pattern files
  diffscan.py measure OUT -- CMD...     run CMD (stdout and stderr passed through), then write its peak RSS and wall
                                        time to OUT; exit with CMD's status

Findings are printed as detector/rule, commit, path and line, NEVER the matched value (no Raw, RawV2, Redacted,
Secret, Match or Line field is ever read out). A finding on a local scan commit is named for what it stands for: a
merge's remerge delta names the MERGE, the net commit names "net change <merge-base>..<head>".

THE ACCEPTED-LIVE REGISTRY. A caller may keep .github/secret-scan-registry.json: real, live credentials that history
cannot forget and whose rotation an operator ruling has deferred. Each entry names one value by sha256(value)[:20] (the
vagary-voice convention), so one entry covers both scanners: gitleaks' Secret and trufflehog's Raw (RawV2 when Raw is
empty) are hashed in-process and looked up. Rules and detector names are never matched (gitleaks says generic-api-key
where trufflehog says ElevenLabs). Only under --policy sweep (scope.sh's registry_policy for the scheduled or
dispatched full sweep) is a registered value reported as accepted and not failed; anything else fails as "NOT in
registry". Under --policy gate (every other scan) the registry is not consulted: every finding fails, registered or
not, and prints exactly as with no registry.
`registry FILE POLICY` runs in every scan whose caller has the file: a malformed registry fails it in both policies;
an entry whose review_by has passed fails the sweep and is a warning in the gate; every entry is listed (a warning in
the sweep). No digest is ever printed: an entry is named by its index, rule, status, review_by and ruling.

TRUFFLEHOG SWEEP EXCLUDES. A caller may keep .github/secret-scan-trufflehog-exclude.txt: anchored regexes (one per
line, # comments) naming history that the FULL sweep's trufflehog may skip, e.g. inventoried captures too large to
scan (vagary-platform's HAR quarantine). The workflow honours it ONLY under --policy sweep: PR, push and merge-group
scans (a full-mode fallback included) read every added line. `excludes` refuses an unanchored pattern, a construct
RE2 (trufflehog's engine) lacks, and any pattern that matches a generic path: excludes must name specific history.
trufflehog matches the git source's patterns against the repository path and the filesystem source's against the
file's absolute path, so the TREE file prefixes each pattern with the tree's <label>/ (measured on 3.97.0).

<label> in the tree is the commit's SHA; for a remerge delta it is the MERGE's SHA, for the net change the net commit's.
Exit codes: 0 clean, 1 findings or a failed check, 2 usage or a malformed input.
"""
import datetime
import hashlib
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

LIVE = "live-pending-rotation"
REGISTRY_FIELDS = {"version", "about", "entries"}
ENTRY_REQUIRED = ("sha256_20", "status", "reason", "ruling", "review_by")
ENTRY_OPTIONAL = ("rule", "renewal", "seen_in")
HEX20 = re.compile(r"[0-9a-f]{20}\Z")
YMD = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def die(msg, code=2):
    print(f"::error::diffscan: {msg}", file=sys.stderr)
    sys.exit(code)


def esc(text):
    """Workflow-command data: % CR LF would end an annotation early or forge another."""
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def digest(value):
    """sha256(value)[:20], the registry's key. Computed in-process; never printed."""
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:20]


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def load_registry(path):
    """-> (entries, problems). An entry is valid through its review_by date (UTC) and expired from the day after.
    Problems name an entry by its index, never by its hash."""
    if os.path.islink(path):
        return [], [f"{path} is a symbolic link; the registry must be a regular file"]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return [], [f"{path} is not readable JSON ({type(e).__name__})"]
    if not isinstance(data, dict):
        return [], ["the registry is not a JSON object"]
    problems = []
    unknown = sorted(set(data) - REGISTRY_FIELDS)
    if unknown:
        problems.append(f"unknown top-level field(s) {', '.join(TOKENISH.sub('<masked>', k) for k in unknown)}")
    if data.get("version") != 1:
        problems.append("version must be 1")
    raw = data.get("entries")
    if not isinstance(raw, list):
        problems.append("entries must be a list")
        raw = []
    entries, first, today = [], {}, utc_today()
    for i, e in enumerate(raw):
        at = f"entry #{i}"
        if not isinstance(e, dict):
            problems.append(f"{at} is not an object")
            continue
        unknown = sorted(set(e) - set(ENTRY_REQUIRED) - set(ENTRY_OPTIONAL))
        if unknown:
            problems.append(f"{at}: unknown field(s) {', '.join(TOKENISH.sub('<masked>', k) for k in unknown)} "
                            f"(known: {', '.join(ENTRY_REQUIRED + ENTRY_OPTIONAL)})")
        for k in ENTRY_REQUIRED:
            if not isinstance(e.get(k), str) or not e[k].strip():
                problems.append(f"{at}: {k} is missing or empty")
        for k in ("rule", "renewal"):
            if k in e and (not isinstance(e[k], str) or not e[k].strip()):
                problems.append(f"{at}: {k}, when present, must be a non-empty string")
        seen = e.get("seen_in", [])
        if not (isinstance(seen, list) and all(isinstance(x, str) and x for x in seen)):
            problems.append(f"{at}: seen_in, when present, must be a list of paths")
        h, status, review_by = e.get("sha256_20"), e.get("status"), e.get("review_by")
        if isinstance(h, str) and h:
            if not HEX20.match(h):
                problems.append(f"{at}: sha256_20 must be 20 lowercase hex characters (sha256 of the value, first 20)")
            elif h in first:
                problems.append(f"entries #{first[h]} and #{i} name the same value (a duplicate sha256_20)")
            else:
                first[h] = i
        if isinstance(status, str) and status and status != LIVE:
            problems.append(f"{at}: status must be {LIVE!r}; a value that is not a live credential belongs in a "
                            ".gitleaks.toml allowlist, not here")
        due = None
        if isinstance(review_by, str) and review_by:
            try:
                due = datetime.date.fromisoformat(review_by) if YMD.match(review_by) else None
            except ValueError:
                pass
            if due is None:
                problems.append(f"{at}: review_by must be a real date written YYYY-MM-DD")
        entries.append({
            "n": i, "digest": h, "due": due, "expired": due is not None and due < today,
            "days": (due - today).days if due else None,
            "label": f"registry entry #{i} (rule {esc(e.get('rule') or '?')}, {LIVE}, review_by {esc(review_by)})",
            "ruling": esc(e.get("ruling", "")), "renewal": esc(e.get("renewal", "")),
        })
    return entries, problems


class Matcher:
    """Looks a finding's value up in the registry (sweep only). Its notes never hold a value or a digest."""

    def __init__(self, path, policy):
        self.on = bool(path) and policy == "sweep"  # under the gate policy the registry accepts nothing
        self.entries, self.problems = load_registry(path) if self.on else ([], [])
        self.by = {} if self.problems else {e["digest"]: e for e in self.entries}
        self.accepted = {}

    def judge(self, value):
        """-> (fails, suffix for the finding's line)."""
        if not self.on:
            return True, ""
        if self.problems:
            return True, ": NOT accepted (the registry is unusable; the registry check lists why)"
        if not value:
            return True, ": NOT in registry (the scanner gave no value to match)"
        e = self.by.get(digest(value))
        if e is None:
            return True, ": NOT in registry"
        if e["expired"]:
            return True, f": NOT accepted, {e['label']} has EXPIRED (renew it with a fresh ruling, or remove it)"
        self.accepted[e["n"]] = self.accepted.get(e["n"], 0) + 1
        return False, f": accepted ({e['label']})"

    def summary(self, scanner):
        if not self.on:
            return
        if self.problems:
            print(f"::error::{scanner}: the registry is unusable ({len(self.problems)} problem(s)); "
                  "nothing is accepted")
            return
        for e in self.entries:
            print(f"{scanner}: {e['label']} accepted {self.accepted.get(e['n'], 0)} finding(s) in this scan")


def registry(path, policy):
    """The registry check, run once per scanner job when the caller has the file."""
    entries, problems = load_registry(path)
    sweep = policy == "sweep"
    for p in problems:
        print(f"::error title=secret-scan registry refused::{path}: {esc(p)}")
    expired = 0
    for e in [] if problems else entries:
        why = f"ruling: {e['ruling']}" + (f"; renewal: {e['renewal']}" if e["renewal"] else "")
        if e["expired"]:
            expired += 1
            kind = "error" if sweep else "warning"
            print(f"::{kind} title=secret-scan registry entry expired::{e['label']} expired {-e['days']} day(s) ago. "
                  f"Renew review_by with a fresh ruling, or remove the entry. {why}")
        elif sweep:
            print(f"::warning title=accepted live credential::{e['label']}, {e['days']} day(s) left: {why}")
        else:
            print(f"{e['label']}, {e['days']} day(s) left: accepts nothing in this scan (only the scheduled sweep "
                  f"may); {why}")
    print(f"registry: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, {expired} expired, "
          f"{len(problems)} problem(s); policy {policy}")
    sys.exit(1 if problems or (sweep and expired) else 0)


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


def gitleaks(report, log, rc, expected, registry_path=None, policy="gate"):
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
    # With a registry the report is unredacted: read it, then delete it whatever happens. Values live only in memory.
    try:
        with open(report, encoding="utf-8") as f:
            found = json.load(f)
        if not isinstance(found, list) or not all(isinstance(x, dict) for x in found):
            raise ValueError("not a list of findings")
    except (OSError, ValueError) as e:
        problems.append(f"no readable gitleaks report ({type(e).__name__})")
        found = []
    finally:
        try:
            os.unlink(report)
        except FileNotFoundError:
            pass
    table = legs()
    match = Matcher(registry_path, policy)
    failing = 0
    for f in found:
        secret = f.get("Secret")
        fails, note = match.judge(secret if isinstance(secret, str) else "")
        failing += fails
        line = (f"gitleaks {f.get('RuleID')}: {describe(table, f.get('Commit', ''))}, "
                f"path {f.get('File')}, line {f.get('StartLine')}{note}")
        print(f"::error::{line}" if fails else line)
    if rc == 1 and not found:
        problems.append("gitleaks exited 1 with an empty report")
    if rc == 0 and found:
        problems.append("gitleaks exited 0 with findings in its report")
    for p in problems:
        print(f"::error::{p}")
    match.summary("gitleaks")
    accepted = f", {len(found) - failing} accepted by the registry" if match.on else ""
    print(f"gitleaks: {len(found)} finding(s){accepted}; "
          f"scanned {scanned[-1] if scanned else '?'} of {expected} commit(s)")
    sys.exit(1 if problems or failing or match.problems else 0)


def trufflehog(tree_dir, registry_path=None, policy="gate"):
    root = os.path.realpath(tree_dir) + os.sep if tree_dir else None
    table = legs()
    match = Matcher(registry_path, policy)
    found = bad = failing = 0
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
        raw = d.get("Raw") or d.get("RawV2") or ""
        fails, note = match.judge(raw if isinstance(raw, str) else "")
        failing += fails
        line = f"trufflehog {det} ({state}): {where}{note}"
        print(f"::error::{line}" if fails else line)
    if bad:
        print(f"::error::trufflehog printed {bad} output line(s) that are not results (not shown)")
    match.summary("trufflehog")
    accepted = f", {found - failing} accepted by the registry" if match.on else ""
    print(f"trufflehog: {found} finding(s){accepted}")
    sys.exit(1 if failing or bad or match.problems else 0)


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


EXCLUDE_PROBES = ("a", "README.md", "src/main.py", ".github/workflows/ci.yml", ".env", "package.json", "docs/index.md",
                  "frontend/src/App.jsx", "backend/server.py")
NOT_RE2 = re.compile(r"\(\?[=!<]|\\[1-9]")


def excludes(path, hist_out, tree_out):
    if os.path.islink(path):
        die(f"{path} is a symlink")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f]
    except (OSError, UnicodeDecodeError) as exc:
        die(f"{path} is unreadable: {exc}")
    patterns = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not patterns:
        die(f"{path} holds no pattern")
    for n, pattern in enumerate(patterns, 1):
        if not pattern.startswith("^") or pattern != pattern.strip():
            die(f"{path}: pattern {n} is not anchored at the path start (^), or has surrounding space")
        if NOT_RE2.search(pattern):
            die(f"{path}: pattern {n} uses a lookaround or backreference, which RE2 does not support")
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            die(f"{path}: pattern {n} does not compile: {exc}")
        hit = next((probe for probe in EXCLUDE_PROBES if rx.search(probe)), None)
        if hit is not None:
            die(f"{path}: pattern {n} matches the generic path {hit!r}; excludes must name specific history")
    with open(hist_out, "w", encoding="utf-8") as f:
        f.write("\n".join(patterns) + "\n")
    with open(tree_out, "w", encoding="utf-8") as f:
        f.write("\n".join("(^|/)[0-9a-f]{40}/" + pattern[1:] for pattern in patterns) + "\n")
    print(f"::warning::trufflehog sweep excludes: {len(patterns)} pattern(s) from {esc(path)} skipped in this FULL "
          "sweep only; PR, push and merge-group scans read every added line")


def measure(out, cmd):
    import resource
    import time
    start = time.monotonic()
    try:
        rc = subprocess.run(cmd, check=False).returncode
    except OSError as exc:
        die(f"measure: cannot run {cmd[0]}: {exc}")
    wall = time.monotonic() - start
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak_mb = peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024  # bytes on macOS, KiB on Linux
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"peak RSS {peak_mb:.0f} MB, wall {wall:.0f} s\n")
    sys.exit(rc)


def registry_opt(args, n):
    """n positional arguments, then optionally `--registry FILE --policy sweep|gate` -> (positional, FILE, policy)."""
    if len(args) == n:
        return args, None, "gate"
    if (len(args) == n + 4 and args[n] == "--registry" and args[n + 1] and args[n + 2] == "--policy"
            and args[n + 3] in ("sweep", "gate")):
        return args[:n], args[n + 1], args[n + 3]
    die("usage: the only option is a trailing `--registry FILE --policy sweep|gate`")


def main(argv):
    cmd, args = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    if cmd == "tree" and len(args) == 2:
        tree(args[0], revs_of(args[1]))
    elif cmd == "count" and len(args) == 1:
        count(revs_of(args[0]))
    elif cmd == "gitleaks" and len(args) in (4, 8):
        args, reg, policy = registry_opt(args, 4)
        gitleaks(args[0], args[1], int(args[2]), int(args[3]), reg, policy)
    elif cmd == "trufflehog" and len(args) in (1, 5):
        args, reg, policy = registry_opt(args, 1)
        trufflehog(args[0], reg, policy)
    elif cmd == "trufflehog-log" and len(args) == 2:
        trufflehog_log(args[0], int(args[1]))
    elif cmd == "registry" and len(args) == 2 and args[1] in ("sweep", "gate"):
        registry(args[0], args[1])
    elif cmd == "excludes" and len(args) == 3:
        excludes(args[0], args[1], args[2])
    elif cmd == "measure" and len(args) >= 3 and args[1] == "--":
        measure(args[0], args[2:])
    else:
        die("usage: diffscan.py tree DIR REVS | count REVS | gitleaks REPORT LOG RC N [--registry FILE --policy P] | "
            "trufflehog TREE [--registry FILE --policy P] | trufflehog-log LOG MIN | registry FILE P (P: sweep|gate) | "
            "excludes FILE HIST TREE | measure OUT -- CMD...")


if __name__ == "__main__":
    main(sys.argv)
