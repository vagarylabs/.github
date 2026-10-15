#!/usr/bin/env python3
"""source-prep-stats: how a CI job prepared its source, as a versioned record.

Subcommands (each exits 0: measurement must never fail a job):
  before     snapshot the checkout path; make a private trace2 directory for the wrapped checkout
  after      parse that trace, snapshot again, write the source-prep.v1 record, step outputs and summary
  telemetry  job-footprint's half: job-telemetry.v1 = the job's source-prep records + cgroup footprint + runner

Rules the record keeps:
  - A value that was not measured is null, and "unknown" says why. 0 only ever means "measured zero".
  - A shallow, partial (filtered), sparse or submodule-less tree is "incomplete", never "complete".
  - Every read of one invocation shares one deadline and one byte/event budget (Budget). Running out is unknown,
    never a partial count, a crash or a hang.
  - Only allow-listed aggregates leave this module. Raw trace2 lines carry argv, remote URLs and error
    text; they stay in a 0700 directory under RUNNER_TEMP and are deleted once parsed. The two trace strings
    that are published (protocol version, effective filter) are mapped to a closed form first: anything
    outside it is "other", never the raw value.

Schemas: schema/source-prep.v1.json and schema/job-telemetry.v1.json (draft; the canonical home is
vagary-core contracts/delivery/v1, P7-01). Standard library only.
"""
import argparse
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

SOURCE_PREP_SCHEMA = "source-prep.v1"
TELEMETRY_SCHEMA = "job-telemetry.v1"
SCHEMA_STATUS = "draft"

FETCH_FAMILY = {"fetch", "clone", "fetch-pack", "pull"}
# Server-side processes show up in the client's trace when the transport is local (file://, ssh to localhost).
SERVER_SIDE = {"upload-pack", "http-backend", "receive-pack", "upload-archive"}
THROTTLE_RE = re.compile(r"\b429\b|too many requests|rate[ -]?limit", re.I)
PACK_HEADER_RE = re.compile(r"^--pack_header=\d+,(\d+)$")
HTTP_429_SINCE = (2, 54)  # git >= 2.54 traces every 429 response (http/429-retry-after), retried or not
LAZY_MARK = "fetch.negotiationAlgorithm=noop"  # promisor-remote.c runs lazy fetches as `git -c <this> fetch ... --stdin`
DEFAULT_WALK_BUDGET = 20.0
# One budget for every read of one invocation (trace2 files, git output, object listing, size walks). Running
# out is unknown, never a partial count, a crash or a hang. The size walks also stop at walk-budget-seconds.
DEADLINE_SECONDS = 120.0
MAX_READ_BYTES = 256 << 20  # trace2 lines + git stdout + the sparse-checkout file
MAX_EVENTS = 4000000  # trace2 events + directory entries
MAX_TRACE_FILES = 20000
MAX_LINE_BYTES = 1 << 20
MAX_SPARSE_BYTES = 16 << 20
PROTOCOL_VERSIONS = ("0", "1", "2")
# Every published filter is one of these (or "other"). sparse:oid=<rev> keeps only its kind: the rev is free text.
FILTER_PART_RE = re.compile(r"blob:none|blob:limit=[0-9]{1,20}[kmgKMG]?|tree:[0-9]{1,10}|"
                            r"object:type=(?:blob|tree|commit|tag)")
MAX_FILTER_LEN = 512
MAX_COMBINE_PARTS = 8
SID_RE = re.compile(r"[0-9]{1,20}-[0-9a-f]{8}")  # the before step's run id: "<epoch ms>-<8 hex>"
STRIP_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
             "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE")


# ---------------------------------------------------------------- trace2 ------------------------------------------

def _hierarchy_is_server(hierarchy):
    return any(part in SERVER_SIDE for part in (hierarchy or "").split("/"))


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def protocol_version(value):
    """A traced negotiated-version as "0", "1" or "2"; any other value is "other", never echoed."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return "other"
    return str(value) if str(value) in PROTOCOL_VERSIONS else "other"


def filter_spec(value, nested=False):
    """A partial-clone filter spec in its allow-listed form; any other value is "other", never echoed.

    blob:none, blob:limit=<n>[kmg], tree:<depth>, object:type=<type>, sparse:oid (its rev dropped) and
    combine:<a>+<b>... of those (git URL-encodes each part)."""
    if not isinstance(value, str) or len(value) > MAX_FILTER_LEN:
        return "other"
    if value.startswith("sparse:oid="):
        return "sparse:oid"
    if value.startswith("combine:") and not nested:
        parts = value[len("combine:"):].split("+")
        if not 2 <= len(parts) <= MAX_COMBINE_PARTS:
            return "other"
        normalized = [filter_spec(urllib.parse.unquote(part), nested=True) for part in parts]
        return "other" if "other" in normalized else "combine:" + "+".join(normalized)
    return value if FILTER_PART_RE.fullmatch(value) else "other"


# The fields read from each event kind and their JSON types. An event whose read field has another type (a
# number for a hierarchy, a list for a name, a string for an argv) is a bad line, never a crash.
_NUM = (int, float)
EVENT_FIELDS = {
    "version": {"exe": str},
    "start": {"argv": list, "time": str},
    "cmd_name": {"name": str, "hierarchy": str},
    "exit": {"code": int, "t_abs": _NUM},
    "signal": {"t_abs": _NUM},
    "error": {"msg": str, "fmt": str},
    "data": {"category": str, "key": str, "value": (str, int)},
}
MAX_SID_LEN = 1024


def _well_formed(ev):
    if not isinstance(ev, dict) or not isinstance(ev.get("sid"), str) or not 0 < len(ev["sid"]) <= MAX_SID_LEN:
        return False
    kind = ev.get("event")
    if not isinstance(kind, str):
        return False
    for field, types in EVENT_FIELDS.get(kind, {}).items():
        value = ev.get(field)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, types):
            return False
    return kind != "start" or all(isinstance(a, str) for a in ev.get("argv") or [])


def _open_regular(path):
    """A binary reader for path when it is a regular file (never a FIFO or device, never through a symlink)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    return os.fdopen(fd, "rb")


def read_trace(trace_dir, budget):
    """Read a GIT_TRACE2_EVENT directory (one file per process) into per-process summaries keyed by sid.

    Every file, line and byte is charged to the budget; raises BudgetExhausted when it runs out. A line longer
    than MAX_LINE_BYTES is a bad line, skipped without being held in memory."""
    names = []
    with os.scandir(trace_dir) as entries:
        for e in entries:
            budget.charge(events=1)
            if e.is_file(follow_symlinks=False):
                if len(names) >= MAX_TRACE_FILES:  # this trace only: later reads keep their budget
                    raise BudgetExhausted("more than %d trace2 files" % MAX_TRACE_FILES)
                names.append(e.name)
    procs, bad_lines = {}, 0
    for name in sorted(names):
        fh = _open_regular(os.path.join(trace_dir, name))
        if fh is None:
            continue
        with fh:
            overlong = False
            while True:
                raw = fh.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break
                budget.charge(nbytes=len(raw), events=1)
                if overlong or len(raw) > MAX_LINE_BYTES:
                    bad_lines += 0 if overlong else 1
                    overlong = not raw.endswith(b"\n")  # still inside the long line until its newline
                    continue
                try:
                    ev = json.loads(raw)
                except (ValueError, RecursionError):  # RecursionError: a line of deeply nested brackets
                    bad_lines += 1
                    continue
                if not _well_formed(ev):
                    bad_lines += 1
                    continue
                p = procs.setdefault(ev["sid"], {
                    "sid": ev["sid"], "argv": [], "name": None, "hierarchy": "", "started": False, "exited": False,
                    "code": None, "t_abs": None, "time": None, "throttled": False, "data": [], "exe": None})
                kind = ev["event"]
                if kind == "version":
                    p["exe"] = ev.get("exe")
                elif kind == "start":
                    p["started"], p["argv"], p["time"] = True, list(ev.get("argv") or []), ev.get("time")
                elif kind == "cmd_name":
                    p["name"], p["hierarchy"] = ev.get("name"), ev.get("hierarchy") or ""
                elif kind == "exit" and not p["exited"]:  # a detached child repeats exit under the same sid
                    p["exited"], p["code"], p["t_abs"] = True, ev.get("code"), ev.get("t_abs")
                elif kind == "signal" and not p["exited"]:
                    p["exited"], p["code"], p["t_abs"] = True, None, ev.get("t_abs")
                elif kind == "error":
                    if THROTTLE_RE.search("%s %s" % (ev.get("msg") or "", ev.get("fmt") or "")):
                        p["throttled"] = True
                elif kind == "data":
                    p["data"].append((ev.get("category"), ev.get("key"), ev.get("value")))
                    # git >= 2.54 reports each 429 as data, including ones it retried itself (http.maxRetries)
                    if ev.get("category") == "http" and (ev.get("key") or "").startswith("http/429"):
                        p["throttled"] = True
    return procs, bad_lines


def summarize_trace(trace_dir, budget=None):
    """Allow-listed transfer aggregates from a trace2 directory, or (None, reason) when nothing was traced.

    Never raises: a trace it cannot read, or one larger than the read budget, is an unknown transfer (never a
    partial count), and the caller still deletes the raw files."""
    if not trace_dir or not os.path.isdir(trace_dir):
        return None, "no trace2 directory (the before step did not run)"
    try:
        return _summarize(*read_trace(trace_dir, budget or Budget(DEFAULT_WALK_BUDGET)))
    except BudgetExhausted as exc:
        return None, "trace2 output not read in full: %s" % exc
    except Exception as exc:  # the reason names the failure, never its message (it can quote the trace)
        return None, "the trace2 output could not be read (%s)" % type(exc).__name__


def _summarize(procs, bad_lines):
    if not procs:
        return None, "no git process wrote trace2 output (git older than 2.22, or checkout fell back to the REST API)"
    client = {sid: p for sid, p in procs.items() if not _hierarchy_is_server(p["hierarchy"])}

    def is_fetch(p):
        return p["name"] in FETCH_FAMILY

    def is_lazy(p):
        return p["name"] == "fetch" and "--stdin" in p["argv"] and LAZY_MARK in p["argv"]

    def ancestors(sid):
        parts = sid.split("/")
        return ["/".join(parts[:i]) for i in range(len(parts) - 1, 0, -1)]  # nearest first

    def version(p):
        m = re.match(r"(\d+)\.(\d+)", str(p["exe"] or ""))
        return (int(m.group(1)), int(m.group(2))) if m else None

    versions = [version(p) for p in client.values()]
    responses_429 = None
    if versions and all(v is not None and v >= HTTP_429_SINCE for v in versions):
        responses_429 = sum(1 for p in client.values() for c, k, _ in p["data"]
                            if c == "http" and k == "http/429-retry-after")

    attempts, lazies = [], []
    for sid, p in client.items():
        if is_lazy(p):
            lazies.append(p)
        elif is_fetch(p) and not any(a in client and is_fetch(client[a]) for a in ancestors(sid)):
            attempts.append(p)
    attempts.sort(key=lambda p: (p["time"] or "", p["sid"]))

    def failed(p):
        return p["code"] != 0

    retries = 0
    for i, p in enumerate(attempts):
        if failed(p) and any(q["argv"][1:] == p["argv"][1:] for q in attempts[i + 1:]):
            retries += 1

    # One throttled attempt is one hit, however many of its processes (remote-curl, fetch) reported it.
    throttled = set()
    for sid, p in client.items():
        if p["throttled"]:
            owner = next((a for a in [sid] + ancestors(sid) if a in client and is_fetch(client[a])), sid)
            throttled.add(owner)

    objects_received = 0
    rounds = haves = lazy_objects = None
    protocol = filter_effective = None
    for p in client.values():
        if p["name"] in ("index-pack", "unpack-objects"):
            for arg in p["argv"]:
                m = PACK_HEADER_RE.match(arg)
                if m:
                    objects_received += int(m.group(1))
        for category, key, value in p["data"]:
            if key == "total_rounds" and _int(value) is not None:
                rounds = (rounds or 0) + _int(value)
            elif key == "haves_added" and _int(value) is not None:
                haves = (haves or 0) + _int(value)
            elif category == "promisor" and key == "fetch_count" and _int(value) is not None:
                lazy_objects = (lazy_objects or 0) + _int(value)
            elif category == "transfer" and key == "negotiated-version" and protocol is None:
                protocol = protocol_version(value)  # a closed form: the raw trace value is never published
            elif category == "fetch" and key == "filter/effective" and filter_effective is None:
                filter_effective = filter_spec(value)
    if lazy_objects is None and not lazies:
        lazy_objects = 0  # no lazy fetch ran, so none of its objects were fetched: a measured zero
    if not attempts and not lazies:
        rounds, haves = rounds or 0, haves or 0  # no fetch ran: zero rounds, measured
    seconds = [p["t_abs"] for p in attempts if isinstance(p["t_abs"], (int, float))]
    unterminated = sum(1 for p in client.values() if p["started"] and not p["exited"])
    return {
        "fetch_attempts": len(attempts),
        "failed_fetch_attempts": sum(1 for p in attempts if failed(p)),
        "retries": retries,
        "throttle_hits": len(throttled),
        "fetch_seconds": round(sum(seconds), 3) if len(seconds) == len(attempts) else None,
        "objects_received": objects_received,
        "lazy_fetches": len(lazies),
        "lazy_fetch_failures": sum(1 for p in lazies if failed(p)),
        "lazy_objects": lazy_objects,
        "protocol_version": protocol,
        "negotiation_rounds": rounds,
        "haves_sent": haves,
        "filter_effective": filter_effective,
        "http_429_responses": responses_429,
        "trace": {"processes": len(client), "excluded_server_processes": len(procs) - len(client),
                  "unterminated": unterminated, "bad_lines": bad_lines},
    }, None


# ---------------------------------------------------------------- filesystem --------------------------------------

class BudgetExhausted(Exception):
    """The invocation's read budget ran out: the value being read, and every read after it, is unknown."""


class WalkTimedOut(BudgetExhausted):
    """The size walks used up walk-budget-seconds; other reads may go on."""


def _finite_seconds(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


class Budget:
    """One deadline, byte allowance and event allowance shared by every read of one invocation: trace2 files,
    git output, the object listing and the size walks. The walks also stop at their own walk budget, which
    starts with the first walk. Exhaustion raises BudgetExhausted; callers turn it into unknown."""

    def __init__(self, walk_seconds):
        now = time.monotonic()
        self.walk_seconds = walk_seconds if _finite_seconds(walk_seconds) else DEFAULT_WALK_BUDGET
        self.deadline = now + DEADLINE_SECONDS
        self.walk_deadline = None
        self.bytes_left, self.events_left = MAX_READ_BYTES, MAX_EVENTS
        self.exhausted = None  # why the shared budget ran out
        self.hit = False  # a size walk was cut short, so its total is unknown

    def remaining(self):
        return self.deadline - time.monotonic()

    def exhaust(self, reason):
        if self.exhausted is None:
            self.exhausted = reason
        return BudgetExhausted(self.exhausted)

    def charge(self, nbytes=0, events=0):
        """Account for one read. Raises BudgetExhausted once the deadline, the bytes or the events are spent."""
        if self.exhausted is None:
            self.bytes_left -= nbytes
            self.events_left -= events
            if time.monotonic() >= self.deadline:
                self.exhaust("the step's %g s read deadline passed" % DEADLINE_SECONDS)
            elif self.bytes_left < 0:
                self.exhaust("the step read more than %d bytes" % MAX_READ_BYTES)
            elif self.events_left < 0:
                self.exhaust("the step read more than %d trace events and directory entries" % MAX_EVENTS)
        if self.exhausted is not None:
            raise BudgetExhausted(self.exhausted)

    def charge_walk(self):
        """One directory entry of a size walk: the shared budget, then the walk budget."""
        self.charge(events=1)
        now = time.monotonic()
        if self.walk_deadline is None:
            self.walk_deadline = now + self.walk_seconds
        if now >= self.walk_deadline:
            raise WalkTimedOut(WALK_TIMED_OUT)


WALK_TIMED_OUT = "walk exceeded the time budget"


def _unreadable(what, exc):
    return "%s could not be read (%s)" % (what, type(exc).__name__)


def walk_bytes(root, budget, seen=None):
    """(bytes, None) or (None, reason). Apparent bytes under root: regular files and symlinks, each inode once,
    directories 0. That is GNU `du -sb` from coreutils 9.2 on (du.c usable_st_size; 8.x also added directory
    sizes). A walk cut short or a directory it could not read is unknown, never a partial or zero total.
    An entry that vanished mid-walk is no longer there to count."""
    seen = set() if seen is None else seen
    total, stack = 0, [root]
    try:
        budget.charge_walk()  # a zero walk budget, or one already spent, sizes nothing
        while stack:
            top = stack.pop()
            try:
                with os.scandir(top) as entries:
                    for e in entries:
                        budget.charge_walk()
                        try:
                            if e.is_dir(follow_symlinks=False):
                                stack.append(e.path)
                            elif e.is_file(follow_symlinks=False) or e.is_symlink():
                                st = e.stat(follow_symlinks=False)
                                key = (st.st_dev, st.st_ino)
                                if key not in seen:
                                    seen.add(key)
                                    total += st.st_size
                        except FileNotFoundError:
                            continue
            except FileNotFoundError as exc:
                if top == root:
                    return None, _unreadable("the directory", exc)
            except OSError as exc:
                return None, _unreadable("a directory in the walk", exc)
    except BudgetExhausted as exc:
        budget.hit = True
        return None, str(exc)
    return total, None


def object_files(objects_dir, budget):
    """Pack files {name: bytes} and loose-object bytes under .git/objects, plus None; or (None, None, reason)
    when a directory there could not be read (unknown, never an empty or zero listing). Raises
    BudgetExhausted when the read budget runs out."""
    packs, loose = {}, 0
    pack_dir = os.path.join(objects_dir, "pack")
    try:
        if os.path.isdir(pack_dir):
            with os.scandir(pack_dir) as entries:
                for e in entries:
                    budget.charge(events=1)
                    if e.name.endswith(".pack") and e.is_file(follow_symlinks=False):
                        packs[e.name] = e.stat(follow_symlinks=False).st_size
        with os.scandir(objects_dir) as entries:
            for e in entries:
                budget.charge(events=1)
                if len(e.name) == 2 and all(c in "0123456789abcdef" for c in e.name) \
                        and e.is_dir(follow_symlinks=False):
                    with os.scandir(e.path) as files:
                        for f in files:
                            budget.charge(events=1)
                            if f.is_file(follow_symlinks=False):
                                loose += f.stat(follow_symlinks=False).st_size
    except OSError as exc:
        return None, None, _unreadable("a directory under .git/objects", exc)
    return packs, loose, None


# ---------------------------------------------------------------- git -------------------------------------------

def _git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_TRACE") and k not in STRIP_ENV}
    env["GIT_NO_LAZY_FETCH"] = "1"  # measuring must never fetch (git >= 2.45; older git ignores it)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _kill(proc):
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)  # its own session: git's children (pack-objects, hooks) too
        else:
            proc.kill()
    except OSError:
        pass


def run_bounded(argv, env, budget):
    """(exit code, stdout bytes) of argv, or (None, None) when it cannot start. It gets only what is left of the
    budget's deadline and bytes: past either, its process group is killed and BudgetExhausted raised. stderr
    is discarded (it can carry URLs, and a full pipe must not stall the child)."""
    budget.charge()  # raises when the budget is already spent: nothing more is started
    timeout = budget.remaining()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, start_new_session=(os.name == "posix"))
    except (OSError, ValueError):
        return None, None
    chunks, failed = [], []

    def pump():
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    return
                budget.charge(nbytes=len(chunk))
                chunks.append(chunk)
        except BudgetExhausted as exc:
            failed.append(exc)
            _kill(proc)
        except (OSError, ValueError):
            return

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    reader.join(timeout)
    try:
        if reader.is_alive():
            _kill(proc)
            reader.join(5)
            raise budget.exhaust("a git command outlasted the step's %g s read deadline" % DEADLINE_SECONDS)
        if failed:
            raise failed[0]
        try:
            code = proc.wait(timeout=max(0.0, budget.remaining()) + 1)
        except subprocess.TimeoutExpired:
            _kill(proc)
            raise budget.exhaust("a git command outlasted the step's %g s read deadline" % DEADLINE_SECONDS)
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if not reader.is_alive():  # a reader still blocked in read() holds the stream; never wait on it here
            proc.stdout.close()
    return code, b"".join(chunks)


def git(path, budget, *args):
    """stdout of `git -C path args` confined to path (no discovery into a parent repo), or None when it fails.
    Raises BudgetExhausted when the read budget runs out."""
    env = _git_env()
    env["GIT_CEILING_DIRECTORIES"] = os.path.dirname(os.path.abspath(path))
    code, out = run_bounded(["git", "-c", "safe.directory=" + os.path.abspath(path), "-C", path] + list(args), env,
                            budget)
    return out.decode("utf-8", "replace") if code == 0 else None


def git_version(budget):
    try:
        code, out = run_bounded(["git", "version"], _git_env(), budget)
    except BudgetExhausted:
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", (out or b"").decode("utf-8", "replace") if code == 0 else "")
    return m.group(1) if m else None


def count_objects(path, budget):
    out = git(path, budget, "count-objects", "-v")
    if out is None:
        return None
    vals = {}
    for line in out.splitlines():
        key, _, value = line.partition(":")
        if _int(value.strip()) is not None:
            vals[key.strip()] = int(value.strip())
    return vals if "count" in vals and "in-pack" in vals else None


def snapshot(path, budget, whole_git_dir=True, walk=True):
    """The repository at path, or {'repo': False} when there is none (a cold start: zero, measured).
    walk=False leaves the size walks to size_walks(), so they cannot starve the cheaper facts."""
    if not os.path.exists(os.path.join(path, ".git")):
        return {"repo": False}
    try:
        git_dir = (git(path, budget, "rev-parse", "--absolute-git-dir") or "").strip()
    except BudgetExhausted as exc:
        return {"repo": None, "unknown": {"repository": str(exc)}}
    if not git_dir or not os.path.isdir(os.path.join(git_dir, "objects")):
        return {"repo": None}
    unknown = {}  # field -> why it is null
    snap = {"repo": True, "git_dir": git_dir, "objects": None, "packs": None, "loose_bytes": None,
            "objects_bytes": None, "git_dir_bytes": None, "unknown": unknown}
    try:
        co = count_objects(path, budget)
        snap["objects"] = (co["count"] + co["in-pack"]) if co else None
        snap["packs"], snap["loose_bytes"], reason = object_files(os.path.join(git_dir, "objects"), budget)
        if reason:
            unknown["bytes"] = reason
    except BudgetExhausted as exc:
        unknown.setdefault("objects", str(exc))
        unknown.setdefault("bytes", str(exc))
    if walk:
        size_walks(snap, budget, whole_git_dir)
    return snap


def size_walks(snap, budget, whole_git_dir=True):
    """objects_bytes (and git_dir_bytes) of a snapshot, under the walk budget; None with the reason otherwise."""
    if snap.get("repo") is not True:
        return
    unknown = snap["unknown"]
    snap["objects_bytes"], reason = walk_bytes(os.path.join(snap["git_dir"], "objects"), budget)
    if reason:
        unknown["objects_bytes"] = reason
    if whole_git_dir:
        snap["git_dir_bytes"], reason = walk_bytes(snap["git_dir"], budget)
        if reason:
            unknown["git_dir_bytes"] = reason


SHAPE_FIELDS = ("shallow", "depth", "partial", "filter", "sparse", "files_materialised", "files_skipped", "commit")


def tree_shape(path, budget):
    """Observed history/partial/sparse/materialisation facts of the checked-out repository. All unknown when
    the read budget runs out: a fact never defaults to "not shallow" or "not partial" for want of a read."""
    try:
        return _tree_shape(path, budget)
    except BudgetExhausted as exc:
        return {}, {field: str(exc) for field in SHAPE_FIELDS}


def _tree_shape(path, budget):
    shape, unknown = {}, {}
    shallow = (git(path, budget, "rev-parse", "--is-shallow-repository") or "").strip()
    shape["shallow"] = {"true": True, "false": False}.get(shallow)
    if shape["shallow"] is None:
        unknown["shallow"] = "git rev-parse --is-shallow-repository failed"
    if shape["shallow"] is True:
        shape["depth"] = _int((git(path, budget, "rev-list", "--count", "HEAD") or "").strip())
        if shape["depth"] is None:
            unknown["depth"] = "git rev-list --count HEAD failed"
    else:
        shape["depth"] = "full" if shape["shallow"] is False else None
    remote = (git(path, budget, "config", "--get", "extensions.partialclone") or "").strip()
    if not remote:
        promisors = git(path, budget, "config", "--get-regexp", r"^remote\..*\.promisor$") or ""
        remote = next((l.split()[0][len("remote."):-len(".promisor")] for l in promisors.splitlines()
                       if l.split()[-1:] == ["true"]), "")
    shape["partial"] = bool(remote)
    raw_filter = ((git(path, budget, "config", "--get", "remote.%s.partialclonefilter" % remote) or "").strip()
                  if remote else "")
    shape["filter"] = filter_spec(raw_filter) if raw_filter else None
    sparse = (git(path, budget, "config", "--bool", "--get", "core.sparseCheckout") or "false").strip() == "true"
    shape["sparse"] = sparse
    shape["sparse_cone"] = None
    shape["sparse_patterns"] = shape["sparse_patterns_sha256"] = None
    if sparse:
        cone = git(path, budget, "config", "--bool", "--get", "core.sparseCheckoutCone")
        shape["sparse_cone"] = (cone or "").strip() == "true"
        rel = (git(path, budget, "rev-parse", "--git-path", "info/sparse-checkout") or "").strip()
        pfile = rel if os.path.isabs(rel) else os.path.join(path, rel)
        try:
            fh = _open_regular(pfile)
            if fh is None:
                raise OSError("not a regular file")
            with fh:
                data = fh.read(MAX_SPARSE_BYTES + 1)
            budget.charge(nbytes=len(data))
            if len(data) > MAX_SPARSE_BYTES:
                unknown["sparse_patterns"] = "sparse-checkout file larger than %d bytes" % MAX_SPARSE_BYTES
            else:
                shape["sparse_patterns_sha256"] = hashlib.sha256(data).hexdigest()
                shape["sparse_patterns"] = sum(1 for l in data.decode("utf-8", "replace").splitlines()
                                               if l.strip() and not l.lstrip().startswith("#"))
        except OSError:
            unknown["sparse_patterns"] = "sparse-checkout file unreadable"
    listing = git(path, budget, "ls-files", "-t", "-z")
    if listing is None:
        shape["files_materialised"] = shape["files_skipped"] = None
        unknown["files_materialised"] = "git ls-files failed"
    else:
        tags = [entry[:1] for entry in listing.split("\0") if entry]
        shape["files_skipped"] = tags.count("S")
        shape["files_materialised"] = len(tags) - shape["files_skipped"]
    shape["has_submodules"] = os.path.isfile(os.path.join(path, ".gitmodules"))
    head = (git(path, budget, "rev-parse", "--verify", "-q", "HEAD") or "").strip()
    shape["commit"] = head if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) else None
    return shape, unknown


def completeness(outcome, shape, requested):
    """complete | incomplete (with reasons) | unknown. A truncated tree is never complete."""
    if not shape:
        return "unknown", []
    reasons = []
    if outcome not in (None, "success"):
        reasons.append("checkout-" + str(outcome))
    if shape.get("shallow") is True:
        reasons.append("shallow")
    if shape.get("partial") is True:
        reasons.append("partial")
    if shape.get("sparse") is True or (shape.get("files_skipped") or 0) > 0:
        reasons.append("sparse")
    if shape.get("has_submodules") and str(requested.get("submodules") or "false").lower() == "false":
        reasons.append("submodules-not-fetched")
    if reasons:
        return "incomplete", reasons
    if None in (shape.get("shallow"), shape.get("partial"), shape.get("sparse"), shape.get("files_skipped")):
        return "unknown", []
    return "complete", []


# ---------------------------------------------------------------- context ----------------------------------------

def attribution():
    env = os.environ
    return {
        "repository": env.get("GITHUB_REPOSITORY") or None, "workflow": env.get("GITHUB_WORKFLOW") or None,
        "job": env.get("GITHUB_JOB") or None, "run_id": _int(env.get("GITHUB_RUN_ID")),
        "run_attempt": _int(env.get("GITHUB_RUN_ATTEMPT")), "event": env.get("GITHUB_EVENT_NAME") or None,
        "runner_name": env.get("RUNNER_NAME") or None, "runner_os": env.get("RUNNER_OS") or None,
        "runner_arch": env.get("RUNNER_ARCH") or None, "runner_environment": env.get("RUNNER_ENVIRONMENT") or None,
    }


def requested_from_env():
    env = os.environ

    def flag(name):
        v = (env.get(name) or "").strip().lower()
        return {"true": True, "false": False}.get(v)

    return {
        "fetch_depth": _int(env.get("SPS_REQ_FETCH_DEPTH")),
        "filter": (env.get("SPS_REQ_FILTER") or "").strip() or None,
        "sparse_checkout": bool((env.get("SPS_REQ_SPARSE") or "").strip()),
        "fetch_tags": flag("SPS_REQ_FETCH_TAGS"), "lfs": flag("SPS_REQ_LFS"),
        "submodules": (env.get("SPS_REQ_SUBMODULES") or "").strip() or None,
    }


def resolve_path(path):
    path = path or ""
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(os.environ.get("GITHUB_WORKSPACE") or os.getcwd(), path))


def rel_path(path):
    try:
        return os.path.relpath(path, os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    except ValueError:
        return path


def walk_budget_seconds(text):
    """(seconds, None), or (the default, why) when the input is not a finite number of seconds >= 0: inf, NaN or
    a negative value would leave the walks unbounded or meaningless. The input itself is never echoed."""
    text = (text or "").strip()
    if not text:
        return DEFAULT_WALK_BUDGET, None
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not _finite_seconds(value):
        return DEFAULT_WALK_BUDGET, ("walk-budget-seconds must be a finite number of seconds >= 0; "
                                     "using the default %g" % DEFAULT_WALK_BUDGET)
    return value, None


def default_state_dir():
    # Raw traces live here until parsed: under RUNNER_TEMP (emptied after every job), never the workspace.
    return os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "source-prep-stats")


def private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def set_outputs(**values):
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a") as fh:
        for key, value in values.items():
            fh.write("%s=%s\n" % (key, "" if value is None else value))


def summary(text):
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a") as fh:
            fh.write(text + "\n")


def export_env(**values):
    out = os.environ.get("GITHUB_ENV")
    if out:
        with open(out, "a") as fh:
            for key, value in values.items():
                fh.write("%s=%s\n" % (key, value))


def dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def store_snapshot(store, budget):
    store = os.path.abspath(os.path.expanduser(store))
    if not os.path.isdir(store):
        return {"path": store, "bytes": None, "reason": "store directory does not exist"}
    size, reason = walk_bytes(store, budget)
    return {"path": store, "bytes": size, "reason": reason}


# ---------------------------------------------------------------- schema -----------------------------------------

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema")
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _is_type(value, name):
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def validate(value, schema, where="$"):
    """Errors of value against the JSON Schema subset these schema files use (stdlib only, no jsonschema)."""
    if isinstance(schema, str):
        with open(os.path.join(SCHEMA_DIR, schema)) as fh:
            schema = json.load(fh)
    errors = []
    if "$ref" in schema:
        return validate(value, schema["$ref"], where)
    if "anyOf" in schema:
        if all(validate(value, sub, where) for sub in schema["anyOf"]):
            errors.append("%s: matches no anyOf branch" % where)
        return errors
    if "const" in schema and value != schema["const"]:
        errors.append("%s: expected %r" % (where, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r not in %r" % (where, value, schema["enum"]))
    types = schema.get("type")
    if types is not None:
        types = [types] if isinstance(types, str) else types
        if not any(_is_type(value, t) for t in types):
            return errors + ["%s: %r is not %s" % (where, value, "/".join(types))]
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema \
            and value < schema["minimum"]:
        errors.append("%s: %r < %r" % (where, value, schema["minimum"]))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append("%s: too short" % where)
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append("%s: %r does not match %s" % (where, value, schema["pattern"]))
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append("%s: missing %s" % (where, key))
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                errors += validate(item, props[key], "%s.%s" % (where, key))
            elif extra is False:
                errors.append("%s: unexpected %s" % (where, key))
            elif isinstance(extra, dict):
                errors += validate(item, extra, "%s.%s" % (where, key))
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += validate(item, schema["items"], "%s[%d]" % (where, i))
    return errors


# ---------------------------------------------------------------- subcommands ------------------------------------

def cmd_before(args):
    state = private_dir(args.state_dir)
    sid = "%d-%s" % (int(time.time() * 1000), secrets.token_hex(4))
    run_dir = private_dir(os.path.join(state, "runs", sid))
    trace_dir = private_dir(os.path.join(run_dir, "trace"))
    budget = Budget(args.walk_budget)
    path = resolve_path(args.path)
    snap = snapshot(path, budget, whole_git_dir=False)
    if args.pnpm_store and not os.path.exists(os.path.join(state, "pnpm-before.json")):
        with open(os.path.join(state, "pnpm-before.json"), "w") as fh:
            json.dump(store_snapshot(args.pnpm_store, budget), fh)
    # The checkout clock starts after this step's own walks: they are measurement, not checkout time.
    before = {"t0": time.time(), "path": path, "snapshot": snap}
    with open(os.path.join(run_dir, "before.json"), "w") as fh:
        json.dump(before, fh)
    set_outputs(id=sid, trace_dir=trace_dir)
    print("source-prep-stats: before snapshot %s (repository present: %s)" % (sid, before["snapshot"].get("repo")))


def build_record(sid, path, before, outcome, requested, transfer, transfer_reason, shape, shape_unknown, after,
                 seconds, budget_hit, producer_git_version):
    unknown = dict(shape_unknown)
    b = (before or {}).get("snapshot") or {}
    if before is None:
        unknown["before"] = "no before snapshot (the before step failed or did not run)"
    if transfer is None:
        unknown["transfer"] = transfer_reason
    if not after.get("repo"):
        unknown["repository"] = "no git repository at the checkout path after the checkout step"

    after_unknown = after.get("unknown") or {}
    before_unknown = {"before." + k: v for k, v in (b.get("unknown") or {}).items()}
    unknown.update(after_unknown)
    unknown.update(before_unknown)
    new_pack = loose_delta = objects = None
    if after.get("repo") and b.get("repo") is not None and before is not None:
        cold = b.get("repo") is False  # nothing existed before: the before side is a measured zero
        # A before value that was not read is unknown: never "no packs" or "0 loose bytes", which would count
        # every pack as new.
        if after.get("packs") is not None and (cold or b.get("packs") is not None):
            old_packs = b.get("packs") or {}
            new_pack = sum(size for name, size in after["packs"].items() if name not in old_packs)
        if after.get("loose_bytes") is not None and (cold or b.get("loose_bytes") is not None):
            loose_delta = after["loose_bytes"] - (b.get("loose_bytes") or 0)
        if after.get("objects") is not None and (cold or b.get("objects") is not None):
            objects = after["objects"] - (b.get("objects") or 0)
    bytes_ = new_pack + loose_delta if new_pack is not None and loose_delta is not None else None
    if bytes_ is None:
        unknown.setdefault("bytes", before_unknown.get("before.bytes") or "needs both snapshots of a repository")
    if objects is None:
        unknown.setdefault("objects", "needs git count-objects before and after")
    for key in ("objects_bytes", "git_dir_bytes"):
        if after.get("repo") and after.get(key) is None:
            unknown.setdefault(key, WALK_TIMED_OUT)

    warm = None
    if before is not None and b.get("repo") is False:
        warm = False
    elif before is not None and b.get("repo") is True and b.get("objects") is not None:
        warm = b["objects"] > 0
    state, reasons = completeness(outcome, shape if after.get("repo") else None, requested)
    t = transfer or {}
    trace = t.get("trace") or {}
    measured = (before is not None and transfer is not None and after.get("repo") is True and not budget_hit
                and not after_unknown and not before_unknown
                and trace.get("unterminated") == 0 and trace.get("bad_lines") == 0)
    shape = shape or {}
    return {
        "schema": SOURCE_PREP_SCHEMA, "schema_status": SCHEMA_STATUS, "id": sid,
        "producer": {"name": "vagarylabs/.github actions/source-prep-stats", "git_version": producer_git_version},
        "attribution": attribution(),
        "subject": {"repository": os.environ.get("SPS_REQ_REPOSITORY") or None,
                    "path": rel_path(path),
                    "commit": shape.get("commit")},
        "requested": requested,
        "checkout": {"outcome": outcome or None, "seconds": seconds},
        "warm": warm,
        "bytes": bytes_,
        "bytes_detail": {"new_pack_bytes": new_pack, "loose_bytes_delta": loose_delta,
                         "objects_bytes_before": b.get("objects_bytes", 0 if b.get("repo") is False else None),
                         "objects_bytes_after": after.get("objects_bytes"),
                         "git_dir_bytes_after": after.get("git_dir_bytes")},
        "objects": objects,
        "objects_detail": {"before": b.get("objects", 0 if b.get("repo") is False else None),
                           "after": after.get("objects"), "received": t.get("objects_received")},
        "depth": shape.get("depth"), "shallow": shape.get("shallow"),
        "partial": shape.get("partial"), "filter": shape.get("filter"),
        "sparse": shape.get("sparse"), "sparse_cone": shape.get("sparse_cone"),
        "sparse_patterns": shape.get("sparse_patterns"), "sparse_patterns_sha256": shape.get("sparse_patterns_sha256"),
        "files_materialised": shape.get("files_materialised"), "files_skipped": shape.get("files_skipped"),
        "retries": t.get("retries"), "throttle_hits": t.get("throttle_hits"),
        "transfer": None if transfer is None else {k: v for k, v in transfer.items()
                                                   if k not in ("trace", "retries", "throttle_hits")},
        "completeness": state, "incomplete_reasons": reasons,
        "measurement": {"complete": measured, "trace": trace or None},
        "unknown": unknown,
    }


def purge_trace(trace_dir, keep_dir=False):
    """Delete raw trace2 output (argv, URLs, error text). keep_dir empties it instead: GIT_TRACE2_EVENT may still
    point at it. Says so, without the content, when something could not be removed."""
    if not trace_dir or not os.path.isdir(trace_dir):
        return
    if keep_dir:
        for name in os.listdir(trace_dir):
            path = os.path.join(trace_dir, name)
            try:
                shutil.rmtree(path) if os.path.isdir(path) and not os.path.islink(path) else os.remove(path)
            except OSError:
                pass
        left = os.listdir(trace_dir)
    else:
        shutil.rmtree(trace_dir, ignore_errors=True)
        left = os.path.exists(trace_dir)
    if left:
        print("::warning::source-prep-stats: raw trace2 output could not be fully removed from RUNNER_TEMP")


def cmd_after(args):
    t_end = time.time()  # the checkout ended before this step began; the parse and walks below are not its time
    # Only an id the before step could have made names a run directory: the trace under it is deleted below.
    sid = args.id if SID_RE.fullmatch(args.id or "") else ""
    run_dir = os.path.join(args.state_dir, "runs", sid) if sid else None
    trace_dir = os.path.join(run_dir, "trace") if run_dir else None
    try:
        _after(args, t_end, sid, run_dir, trace_dir)
    finally:  # every path, a raise included: raw argv/URLs/error text never outlive this step
        purge_trace(trace_dir)


def _after(args, t_end, sid, run_dir, trace_dir):
    state = private_dir(args.state_dir)
    before = None
    if run_dir and os.path.isfile(os.path.join(run_dir, "before.json")):
        with open(os.path.join(run_dir, "before.json")) as fh:
            before = json.load(fh)
    if not sid:
        sid = "%d-%s" % (int(time.time() * 1000), secrets.token_hex(4))
    path = resolve_path(args.path)
    budget = Budget(args.walk_budget)  # one deadline and byte/event budget for every read below
    transfer, transfer_reason = summarize_trace(trace_dir, budget)
    purge_trace(trace_dir)  # parsed: gone now, not only when the step ends
    # The cheap facts first, the size walks last: a slow walk can then cost only the sizes.
    after = snapshot(path, budget, walk=False)
    shape, shape_unknown = tree_shape(path, budget) if after.get("repo") else ({}, {})
    producer_git = git_version(budget)
    size_walks(after, budget)
    seconds = round(t_end - before["t0"], 3) if before else None
    record = build_record(sid, path, before, args.outcome, requested_from_env(), transfer, transfer_reason,
                          shape, shape_unknown, after, seconds, budget.hit or budget.exhausted is not None,
                          producer_git)
    records = private_dir(os.path.join(state, "records"))
    record_path = os.path.join(records, sid + ".json")
    text = dumps(record)
    with open(record_path, "w") as fh:
        fh.write(text + "\n")
    if args.trace_job:
        job_trace = private_dir(os.path.join(state, "job-trace"))
        export_env(GIT_TRACE2_EVENT=job_trace, GIT_TRACE2_EVENT_NESTING="8")
    set_outputs(record=text, record_path=record_path, bytes=record["bytes"], objects=record["objects"],
                completeness=record["completeness"], checkout_seconds=seconds)
    line = ("source-prep-stats: %s %s bytes %s, objects %s, depth %s, filter %s, sparse %s, checkout %ss, "
            "fetch attempts %s, retries %s, throttle hits %s, lazy fetches %s" % (
                record["subject"]["path"], record["completeness"], record["bytes"], record["objects"], record["depth"],
                record["filter"], record["sparse"], seconds, (transfer or {}).get("fetch_attempts"),
                record["retries"], record["throttle_hits"], (transfer or {}).get("lazy_fetches")))
    print(line)
    summary(line + "\n\n```json\n" + text + "\n```\n")


def footprint_from_env():
    env, unknown = os.environ, {}
    peak, usec = _int(env.get("FP_PEAK_BYTES")), _int(env.get("FP_USAGE_USEC"))
    mem_max = (env.get("FP_MEM_MAX") or "").strip() or None
    cpu_max = (env.get("FP_CPU_MAX") or "").split()
    cpus = None
    if len(cpu_max) == 2 and cpu_max[0] == "max":
        cpus = "max"
    elif len(cpu_max) == 2 and _int(cpu_max[0]) and _int(cpu_max[1]):
        cpus = round(int(cpu_max[0]) / int(cpu_max[1]), 3)
    if peak is None:
        unknown["peak_mib"] = "no cgroup v2 memory.peak readable on this runner"
    if usec is None:
        unknown["cpu_s"] = "no cgroup v2 cpu.stat readable on this runner"
    scope = (env.get("FP_SCOPE") or "").strip() or None
    if scope not in (None, "job", "shared"):
        unknown["scope"] = "unrecognised scope %r (expected job or shared)" % scope[:40]
        scope = None
    elif scope is None:
        unknown["scope"] = ("not declared: the cgroup is the job's alone only on an ephemeral one-job container; "
                            "on a shared VM it is the runner service's and the numbers are an upper bound")
    return {
        "peak_mib": peak // 1048576 if peak is not None else None,
        "cpu_s": round(usec / 1e6, 3) if usec is not None else None,
        "mem_limit": (_int(mem_max) if _int(mem_max) is not None else mem_max),
        "cpus": cpus, "cgroup": (env.get("FP_CGROUP") or "").strip() or None, "scope": scope,
    }, unknown


def cmd_telemetry(args):
    job_trace = os.path.join(args.state_dir, "job-trace")
    try:
        _telemetry(args, job_trace)
    finally:  # every path, a raise included; the directory stays because GIT_TRACE2_EVENT still points at it
        purge_trace(job_trace, keep_dir=True)


def _telemetry(args, job_trace):
    state = private_dir(args.state_dir)
    unknown = {}
    records_dir = os.path.join(state, "records")
    records = []
    if os.path.isdir(records_dir):
        for name in sorted(os.listdir(records_dir)):
            if name.endswith(".json"):
                try:
                    with open(os.path.join(records_dir, name)) as fh:
                        records.append(json.load(fh))
                except (OSError, ValueError):
                    unknown["source_prep"] = "a source-prep record was unreadable"
    if not records:
        unknown["source_prep"] = "no source-prep-stats step ran in this job (a plain checkout is not measured)"
    footprint, fp_unknown = footprint_from_env()
    unknown.update({"footprint." + k: v for k, v in fp_unknown.items()})

    budget = Budget(args.walk_budget)  # one deadline and byte/event budget for every read below
    job_git = None
    if os.path.isdir(job_trace):
        summary_, reason = summarize_trace(job_trace, budget)
        if summary_ is None:
            unknown["after_checkout_git"] = reason
        else:
            job_git = {k: summary_[k] for k in ("fetch_attempts", "failed_fetch_attempts", "retries", "throttle_hits",
                                                 "lazy_fetches", "lazy_fetch_failures", "lazy_objects")}
            job_git["processes"] = summary_["trace"]["processes"]
        purge_trace(job_trace, keep_dir=True)  # parsed: drop the raw lines, keep the directory for later git calls
    else:
        unknown["after_checkout_git"] = "not traced (source-prep-stats trace-job was not enabled)"

    pnpm = None
    before_path = os.path.join(state, "pnpm-before.json")
    pnpm_before = None
    if os.path.isfile(before_path):
        with open(before_path) as fh:
            pnpm_before = json.load(fh)
    store = args.pnpm_store or (pnpm_before or {}).get("path")
    if store:
        now = store_snapshot(store, budget)
        bb = (pnpm_before or {}).get("bytes")
        same = pnpm_before is not None and pnpm_before.get("path") == now["path"]
        pnpm = {"bytes_before": bb if same else None, "bytes_after": now["bytes"],
                "delta": (now["bytes"] - bb) if same and bb is not None and now["bytes"] is not None else None}
        if now["bytes"] is None:
            unknown["pnpm_store.bytes_after"] = now["reason"]
        if pnpm["delta"] is None:
            unknown["pnpm_store.delta"] = (now["reason"] or (pnpm_before or {}).get("reason")
                                           or "no before snapshot of this store (set pnpm-store-dir on source-prep-stats)")
    else:
        unknown["pnpm_store"] = "no pnpm store directory given"

    doc = {
        "schema": TELEMETRY_SCHEMA, "schema_status": SCHEMA_STATUS,
        "attribution": attribution(), "footprint": footprint,
        "source_prep": records or None, "after_checkout_git": job_git, "pnpm_store": pnpm, "unknown": unknown,
    }
    att = doc["attribution"]
    suffix = secrets.token_hex(4)  # matrix legs share github.job; artifact names must not collide
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", "job-telemetry-%s-%s-%s-%s" % (
        att["run_id"] or "local", att["run_attempt"] or 0, att["job"] or "job", suffix))
    out_dir = private_dir(os.path.join(state, "telemetry", name))
    out = os.path.join(out_dir, "job-telemetry.json")
    with open(out, "w") as fh:
        fh.write(dumps(doc) + "\n")
    set_outputs(path=out, name=name)
    line = "job-telemetry: %s (%d source-prep record(s), %d bytes)" % (name, len(records), os.path.getsize(out))
    print(line)
    summary(line)


def main(argv=None):
    env = os.environ
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", default=env.get("SPS_STATE_DIR") or default_state_dir())
    common.add_argument("--walk-budget", default=env.get("SPS_WALK_BUDGET", ""))
    b = sub.add_parser("before", parents=[common])
    b.add_argument("--path", default=env.get("SPS_PATH", ""))
    b.add_argument("--pnpm-store", default=env.get("SPS_PNPM_STORE", ""))
    a = sub.add_parser("after", parents=[common])
    a.add_argument("--id", default=env.get("SPS_ID", ""))
    a.add_argument("--path", default=env.get("SPS_PATH", ""))
    a.add_argument("--outcome", default=env.get("SPS_OUTCOME", ""))
    a.add_argument("--trace-job", action="store_true",
                   default=(env.get("SPS_TRACE_JOB") or "").strip().lower() == "true")
    t = sub.add_parser("telemetry", parents=[common])
    t.add_argument("--pnpm-store", default=env.get("SPS_PNPM_STORE", ""))
    args = ap.parse_args(argv)
    args.walk_budget, refused = walk_budget_seconds(args.walk_budget)
    if refused:
        print("::warning::source-prep-stats %s: %s" % (args.cmd, refused))
    try:
        {"before": cmd_before, "after": cmd_after, "telemetry": cmd_telemetry}[args.cmd](args)
    except Exception as exc:  # measurement never fails the job
        # The job log is public on a public repository, and an exception's text can quote trace content (a URL,
        # an argv). Name the exception and where it was raised, never its message.
        where = traceback.extract_tb(exc.__traceback__)[-1:]
        print("::warning::source-prep-stats %s: %s%s (message withheld)" % (
            args.cmd, type(exc).__name__, " in %s line %d" % (where[0].name, where[0].lineno) if where else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
