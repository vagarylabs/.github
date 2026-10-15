"""Hermetic end-to-end tests: a local smart-HTTP git server, the git command sequence actions/checkout v4 runs,
and the action's subcommands driven exactly as action.yml drives them (env in; GITHUB_OUTPUT/ENV/STEP_SUMMARY out).

No network beyond 127.0.0.1. Needs git with http-backend (any git >= 2.30). Every produced document is checked
against the draft schemas in schema/.
"""
import contextlib
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import srcstats  # noqa: E402
from gitserver import GitHTTPServer  # noqa: E402

SCRIPT = os.path.join(HERE, "srcstats.py")
CLEAN = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITHUB_", "RUNNER_", "SPS_", "FP_"))}
# A fake credential-bearing remote, assembled at run time so no scanner mistakes the source for a real one.
PLANTED_TOKEN = "planted-" + "token"
PLANTED = "https://user:%s@example.invalid/org/repo.git" % PLANTED_TOKEN


def git(*args, cwd=None, env=None, check=True, stdin=None):
    r = subprocess.run(["git"] + list(args), cwd=cwd, env=env or CLEAN, capture_output=True, timeout=120,
                       input=stdin)
    if check and r.returncode != 0:
        raise AssertionError("git %s failed: %s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r


def commit_files(work, start, count):
    """`count` commits, each adding one file under a/, b/ or c/ (3 objects per commit: commit, tree path, blob)."""
    for i in range(start, start + count):
        d = os.path.join(work, "abc"[i % 3])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "f%03d.txt" % i), "w") as fh:
            fh.write("".join("file %d line %d %08x\n" % (i, j, (i * 2654435761 + j * 40503) & 0xFFFFFFFF)
                             for j in range(40)))
        git("add", "-A", cwd=work)
        git("-c", "user.email=fixture@example.invalid", "-c", "user.name=fixture", "commit", "-q", "-m", "c%d" % i,
            cwd=work)


def gnu_du():
    """A GNU du whose -b excludes directory sizes (coreutils >= 9.2): `du` on Linux, `gdu` from Homebrew."""
    for exe in ("du", "gdu"):
        try:
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.search(r"\(GNU coreutils\) (\d+)\.(\d+)", out)
        if m and (int(m.group(1)), int(m.group(2))) >= (9, 2):
            return exe
    return None


def read(path):
    with open(path) as fh:
        return fh.read()


def files_containing(root, needle):
    """Every file under root whose bytes contain needle (symlinks are not followed)."""
    found = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as fh:
                    if needle.encode() in fh.read():
                        found.append(path)
    return found


def planted_events(sid):
    """One client fetch whose every free-text trace field carries PLANTED: argv, error text, and the two data
    values the record publishes (negotiated-version, filter/effective)."""
    return [{"event": "version", "sid": sid, "evt": "4", "exe": "2.50.1"},
            {"event": "start", "sid": sid, "argv": ["git", "fetch", PLANTED], "time": "2026-10-15T00:00:00Z"},
            {"event": "cmd_name", "sid": sid, "name": "fetch", "hierarchy": "fetch"},
            {"event": "error", "sid": sid, "msg": "unable to access '%s'" % PLANTED, "fmt": "%s"},
            {"event": "data", "sid": sid, "category": "transfer", "key": "negotiated-version", "value": PLANTED},
            {"event": "data", "sid": sid, "category": "fetch", "key": "filter/effective", "value": PLANTED},
            {"event": "exit", "sid": sid, "code": 0, "t_abs": 0.1}]


def malformed_events(sid):
    """A process whose read fields have the wrong JSON types, each carrying PLANTED, and a line nested past the
    JSON parser's depth (appended by the caller). Each used to raise inside the parse, before the raw trace
    was deleted."""
    return [{"event": "version", "sid": sid, "evt": "4", "exe": [PLANTED]},
            {"event": "start", "sid": sid, "argv": "git fetch " + PLANTED, "time": {"t": PLANTED}},
            {"event": "cmd_name", "sid": sid, "name": ["fetch", PLANTED], "hierarchy": 7},
            {"event": "cmd_name", "sid": sid + "/x", "name": "fetch", "hierarchy": {"h": PLANTED}},
            {"event": "data", "sid": sid, "category": "fetch", "key": "filter/effective", "value": {"v": PLANTED}},
            {"event": "exit", "sid": sid, "code": PLANTED, "t_abs": PLANTED}]


DEEP = "[" * 100000 + "\n"


def unreadable(*paths):
    """os.scandir refuses these directories with EACCES, as for a mode-000 directory, for whoever runs the test
    (chmod does not stop root). In-process only; git subprocesses still read them."""
    real, refused = os.scandir, {os.path.realpath(p) for p in paths}

    def scandir(path="."):
        if isinstance(path, (str, bytes, os.PathLike)) and os.path.realpath(path) in refused:
            raise PermissionError(13, "Permission denied", path)
        return real(path)

    return mock.patch.object(srcstats.os, "scandir", scandir)


def stat_refused(*paths):
    """os.stat and os.scandir refuse these paths with EACCES, as when a parent directory is not searchable, for
    whoever runs the test. os.path.exists and os.path.isdir answer False for such a path rather than raise."""
    real_stat, real_scandir = os.stat, os.scandir
    refused = {os.path.normpath(p) for p in paths}

    def denied(path):
        return isinstance(path, str) and os.path.normpath(path) in refused

    def stat_(path, *args, **kwargs):
        if denied(path):
            raise PermissionError(13, "Permission denied", path)
        return real_stat(path, *args, **kwargs)

    def scandir(path="."):
        if denied(path):
            raise PermissionError(13, "Permission denied", path)
        return real_scandir(path)

    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch.object(srcstats.os, "stat", stat_))
    stack.enter_context(mock.patch.object(srcstats.os, "scandir", scandir))
    return stack


PROMISOR_RE = r"^remote\..*\.promisor$"
# A config read that failed, by how it failed: git exited with an error, was killed, or never started.
FAILED_READS = (128, -9, None)


def config_read_fails(key, code):
    """Every `git config` read naming key (an exact argv element: core.sparseCheckout is a prefix of
    core.sparseCheckoutCone) ends with code, or does not start when code is None; every other git call runs.
    Only exit 1 means "not set": a read that failed is a different answer."""
    real = srcstats.run_bounded

    def run_bounded(argv, env, budget):
        if "config" in argv and key in argv:
            return (None, None) if code is None else (code, b"")
        return real(argv, env, budget)

    return mock.patch.object(srcstats, "run_bounded", run_bounded)


def write_trace(trace_dir, name, events, tail=""):
    with open(os.path.join(trace_dir, name), "w") as fh:
        fh.write("".join(json.dumps(e) + "\n" for e in events) + tail)


class Env:
    """One simulated job: workspace, RUNNER_TEMP and the GitHub command files."""

    def __init__(self, root):
        self.root = root
        self.ws = os.path.join(root, "ws")
        self.temp = os.path.join(root, "runner-temp")
        os.makedirs(self.ws)
        os.makedirs(self.temp)
        self.files = {k: os.path.join(root, k.lower()) for k in ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY")}
        for f in self.files.values():
            open(f, "w").close()

    def env(self, **extra):
        env = dict(CLEAN, GITHUB_WORKSPACE=self.ws, RUNNER_TEMP=self.temp, GITHUB_RUN_ID="4242",
                   GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="fixture", GITHUB_REPOSITORY="vagarylabs/fixture",
                   GITHUB_EVENT_NAME="pull_request", RUNNER_NAME="hermetic", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                   **self.files)
        env.update({k: str(v) for k, v in extra.items()})
        return env

    def step(self, cmd, **extra):
        out, log = self.step_logged(cmd, **extra)
        assert "::warning::" not in log, log
        return out

    def step_logged(self, cmd, **extra):
        """One subcommand as a separate process: its GITHUB_OUTPUT values and its log (stdout + stderr)."""
        open(self.files["GITHUB_OUTPUT"], "w").close()
        r = subprocess.run([sys.executable, SCRIPT, cmd], env=self.env(**extra), capture_output=True, text=True,
                           timeout=120)
        assert r.returncode == 0, r.stderr
        out = {}
        with open(self.files["GITHUB_OUTPUT"]) as fh:
            for line in fh:
                key, _, value = line.rstrip("\n").partition("=")
                out[key] = value
        return out, r.stdout + r.stderr

    def published(self):
        """What the steps publish besides their log: outputs, env and step summary files."""
        return "".join(read(f) for f in self.files.values())

    def inproc(self, cmd, **extra):
        """One subcommand in this process (so a test can patch the module): its outputs and its printed log."""
        open(self.files["GITHUB_OUTPUT"], "w").close()
        printed = io.StringIO()
        with mock.patch.dict(os.environ, self.env(**extra), clear=True), contextlib.redirect_stdout(printed), \
                contextlib.redirect_stderr(printed):
            assert srcstats.main([cmd]) == 0
        with open(self.files["GITHUB_OUTPUT"]) as fh:
            return dict(line.rstrip("\n").partition("=")[::2] for line in fh), printed.getvalue()

    def checkout(self, url, path, depth=0, filt=None, sparse=None, trace=None, attempts=3):
        """actions/checkout v4's git sequence: init, remote, fetch (3 tries), sparse-checkout, checkout -B."""
        dest = os.path.join(self.ws, path)
        env = dict(CLEAN, GIT_TERMINAL_PROMPT="0")
        if trace:
            env.update(GIT_TRACE2_EVENT=trace, GIT_TRACE2_EVENT_NESTING="8")
        if not os.path.isdir(os.path.join(dest, ".git")):
            git("init", "-q", dest, env=env)
            git("-C", dest, "remote", "add", "origin", url, env=env)
        git("-C", dest, "config", "--local", "gc.auto", "0", env=env)
        args = ["-c", "protocol.version=2", "fetch", "--no-tags", "--prune", "--no-recurse-submodules"]
        if filt or sparse:
            args.append("--filter=" + (filt or "blob:none"))  # checkout v4: sparse-checkout implies blob:none
        if depth:
            args.append("--depth=%d" % depth)
        args += ["origin", "+refs/heads/main:refs/remotes/origin/main"]
        for _ in range(attempts):
            if git("-C", dest, *args, env=env, check=False).returncode == 0:
                break
        else:
            return "failure"
        if sparse:
            git("-C", dest, "sparse-checkout", "set", "--cone", *sparse, env=env)
        git("-C", dest, "checkout", "--progress", "--force", "-B", "main", "refs/remotes/origin/main", env=env)
        return "success"

    def prepare(self, url, path, depth=0, filt=None, sparse=None, trace_job=False, **extra):
        """The action: before -> traced checkout -> after. Returns the record."""
        b = self.step("before", SPS_PATH=path, **extra)
        outcome = self.checkout(url, path, depth=depth, filt=filt, sparse=sparse, trace=b["trace_dir"])
        a = self.step("after", SPS_ID=b["id"], SPS_PATH=path, SPS_OUTCOME=outcome, SPS_REQ_FETCH_DEPTH=depth,
                      SPS_REQ_FILTER=filt or "", SPS_REQ_SPARSE="\n".join(sparse or []), SPS_REQ_FETCH_TAGS="false",
                      SPS_REQ_LFS="false", SPS_REQ_SUBMODULES="false", SPS_REQ_REPOSITORY="vagarylabs/fixture",
                      SPS_TRACE_JOB="true" if trace_job else "false", **extra)
        record = json.loads(a["record"])
        assert not os.path.exists(b["trace_dir"]), "raw trace must be deleted once parsed"
        errors = srcstats.validate(record, "source-prep.v1.json")
        assert not errors, errors
        return record


class HermeticTest(unittest.TestCase):
    COMMITS = 45  # 135 objects: above fetch.unpackLimit (100), so a full fetch keeps one pack

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="srcstats-")
        work = os.path.join(cls.tmp, "work")
        git("init", "-q", "-b", "main", work)
        commit_files(work, 0, cls.COMMITS)
        cls.work = work
        cls.serve = os.path.join(cls.tmp, "serve")
        os.makedirs(cls.serve)
        cls.bare = os.path.join(cls.serve, "fixture.git")
        git("clone", "-q", "--bare", work, cls.bare)
        git("-C", cls.bare, "config", "uploadpack.allowFilter", "true")
        git("-C", cls.bare, "config", "uploadpack.allowAnySHA1InWant", "true")
        git("-C", cls.bare, "repack", "-adq")
        cls.server = GitHTTPServer(cls.serve).__enter__()
        cls.url = cls.server.url("fixture.git")

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.job = Env(tempfile.mkdtemp(dir=self.tmp))

    def server_pack_bytes(self):
        """What upload-pack sends for a full fetch of main, computed on the server (independent of the module)."""
        r = git("-C", self.bare, "pack-objects", "--revs", "--stdout", "--delta-base-offset", stdin=b"refs/heads/main\n")
        return len(r.stdout)

    def server_objects(self, *revs):
        """Objects reachable on the server (the warm test leaves unreachable ones behind)."""
        out = git("-C", self.bare, "rev-list", "--objects", *(revs or ("main",))).stdout.decode()
        return len(out.splitlines())

    def test_full_clone_bytes_match_server_pack_within_5_percent(self):
        r = self.job.prepare(self.url, "full")
        server = self.server_pack_bytes()
        self.assertGreater(r["bytes"], 0)
        self.assertLessEqual(abs(r["bytes"] - server) / server, 0.05, (r["bytes"], server))
        self.assertEqual(r["objects"], self.server_objects())
        self.assertEqual(r["objects_detail"]["received"], r["objects"])
        self.assertEqual((r["depth"], r["shallow"], r["partial"], r["filter"], r["sparse"]),
                         ("full", False, False, None, False))
        self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("complete", []))
        self.assertEqual((r["retries"], r["throttle_hits"], r["transfer"]["fetch_attempts"],
                          r["transfer"]["lazy_fetches"], r["transfer"]["lazy_objects"]), (0, 0, 1, 0, 0))
        self.assertEqual(r["transfer"]["protocol_version"], "2")
        self.assertGreaterEqual(r["transfer"]["negotiation_rounds"], 1)
        self.assertIs(r["warm"], False)
        self.assertTrue(r["measurement"]["complete"])
        self.assertEqual(r["files_materialised"], self.COMMITS)
        self.assertEqual(r["subject"]["commit"], git("-C", self.bare, "rev-parse", "main").stdout.decode().strip())
        self.assertEqual(r["unknown"], {})

    def test_git_dir_bytes_match_du_within_1_percent(self):
        du_exe = gnu_du()
        if du_exe is None:
            self.skipTest("needs GNU du >= 9.2 (du on Linux, gdu from Homebrew coreutils)")
        r = self.job.prepare(self.url, "du")
        git_dir = os.path.join(self.job.ws, "du", ".git")
        os.symlink("HEAD", os.path.join(git_dir, "link-for-du"))  # du counts a symlink's own size: so must we
        r = json.loads(self.job.step("after", SPS_ID="", SPS_PATH="du", SPS_OUTCOME="success")["record"])
        du = int(subprocess.run([du_exe, "-sb", git_dir], capture_output=True, text=True, check=True).stdout.split()[0])
        got = r["bytes_detail"]["git_dir_bytes_after"]
        self.assertLessEqual(abs(got - du) / du, 0.01, (got, du))  # the acceptance bound; in practice equal
        self.assertEqual(got, du)

    def test_dogfood_record_check_reports_the_du_comparison(self):
        """dogfood_check.py record depth0 on a real record, through its own main(), down to the du comparison.

        On a host without GNU du >= 9.2 (macOS) that branch is skipped, so du is stubbed as GNU 9.4: the line
        that compares git_dir_bytes with du must report ok or FAIL, never raise while building its message."""
        import dogfood_check
        r = self.job.prepare(self.url, "dogfood")
        fixture, text = os.path.join(self.job.ws, "dogfood"), json.dumps(r)
        got = r["bytes_detail"]["git_dir_bytes_after"]
        real_run = subprocess.run

        def du_reporting(size):
            def run(argv, *args, **kwargs):
                if list(argv[:1]) != ["du"]:
                    return real_run(argv, *args, **kwargs)
                if list(argv[1:]) == ["--version"]:
                    return subprocess.CompletedProcess(argv, 0, "du (GNU coreutils) 9.4\n", "")
                return subprocess.CompletedProcess(argv, 0, "%d\t%s\n" % (size, argv[-1]), "")
            return run

        printed = io.StringIO()
        with mock.patch.object(dogfood_check.subprocess, "run", du_reporting(got)), contextlib.redirect_stdout(printed):
            dogfood_check.main(["record", "depth0", text, fixture])
        self.assertRegex(printed.getvalue(), r"ok +git_dir_bytes within 1%% of du -sb \.git \(%d\)" % got)

        printed = io.StringIO()
        with mock.patch.object(dogfood_check.subprocess, "run", du_reporting(int(got * 1.05))), \
                contextlib.redirect_stdout(printed), self.assertRaises(SystemExit) as failed:
            dogfood_check.main(["record", "depth0", text, fixture])
        self.assertEqual(failed.exception.code, 1, "a 5% gap is reported as a failed expectation")
        self.assertRegex(printed.getvalue(), r"FAIL git_dir_bytes within 1% of du")

        if gnu_du() == "du":  # a Linux runner: the same path once more against the real du
            with contextlib.redirect_stdout(io.StringIO()):
                dogfood_check.main(["record", "depth0", text, fixture])

    def test_dogfood_record_check_reports_an_unmeasured_git_dir_size(self):
        """A record whose git_dir_bytes_after is null (a walk ran out of time) fails the du check with a message;
        the check used to raise TypeError on None - int before it could report."""
        import dogfood_check
        r = self.job.prepare(self.url, "dogfood-null")
        r["bytes_detail"]["git_dir_bytes_after"] = None
        r["unknown"]["git_dir_bytes"] = srcstats.WALK_TIMED_OUT
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [], "positive control: a valid record")
        real_run = subprocess.run

        def gnu_du_94(argv, *args, **kwargs):
            if list(argv[:1]) != ["du"]:
                return real_run(argv, *args, **kwargs)
            if list(argv[1:]) == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, "du (GNU coreutils) 9.4\n", "")
            return subprocess.CompletedProcess(argv, 0, "4096\t%s\n" % argv[-1], "")

        printed = io.StringIO()
        with mock.patch.object(dogfood_check.subprocess, "run", gnu_du_94), contextlib.redirect_stdout(printed), \
                self.assertRaises(SystemExit) as failed:
            dogfood_check.main(["record", "depth0", json.dumps(r), os.path.join(self.job.ws, "dogfood-null")])
        self.assertEqual(failed.exception.code, 1)
        self.assertRegex(printed.getvalue(), r"FAIL git_dir_bytes measured and du -sb \.git non-zero \(4096\)")

    def test_planted_trace_strings_reach_no_published_output(self):
        """A credential-bearing URL in every free-text trace field: the record carries "other" for the two
        published trace strings, and the URL is in no output, log, summary or file left under the job."""
        b = self.job.step("before", SPS_PATH="planted")
        outcome = self.job.checkout(self.url, "planted", trace=b["trace_dir"])
        write_trace(b["trace_dir"], "0000-planted", planted_events("planted-sid"))  # sorts first: its values win
        out, log = self.job.step_logged("after", SPS_ID=b["id"], SPS_PATH="planted", SPS_OUTCOME=outcome)
        record = json.loads(out["record"])
        self.assertEqual(srcstats.validate(record, "source-prep.v1.json"), [])
        self.assertEqual((record["transfer"]["protocol_version"], record["transfer"]["filter_effective"]),
                         ("other", "other"))
        self.assertNotIn(PLANTED_TOKEN, out["record"])
        self.assertNotIn(PLANTED_TOKEN, log)
        self.assertNotIn(PLANTED_TOKEN, self.job.published())
        self.assertEqual(files_containing(self.job.root, PLANTED_TOKEN), [])

    def test_a_pack_without_a_traced_header_is_unknown_objects_not_zero(self):
        """fetch.unpackLimit 0: git unpacks the pack without --pack_header, so the received count is not traced.
        It used to be published as a measured 0 while 135 objects arrived."""
        b = self.job.step("before", SPS_PATH="noheader")
        dest = os.path.join(self.job.ws, "noheader")
        git("init", "-q", dest)  # the checkout's own init, with one config value set before its fetch
        git("-C", dest, "remote", "add", "origin", self.url)
        git("-C", dest, "config", "fetch.unpackLimit", "0")
        outcome = self.job.checkout(self.url, "noheader", trace=b["trace_dir"])
        r = json.loads(self.job.step("after", SPS_ID=b["id"], SPS_PATH="noheader", SPS_OUTCOME=outcome)["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertEqual(r["objects"], self.server_objects(), "positive control: the objects did arrive")
        self.assertIsNone(r["objects_detail"]["received"])
        self.assertIsNone(r["transfer"]["objects_received"])
        self.assertIn("--pack_header", r["unknown"]["objects_received"])

    def test_non_finite_trace_numbers_never_reach_the_published_record(self):
        """A fetch whose exit time is NaN and whose counters are negative: the record output is strict JSON that
        validates, with those values null, and the trace marked damaged."""
        b = self.job.step("before", SPS_PATH="nonfinite")
        outcome = self.job.checkout(self.url, "nonfinite", trace=b["trace_dir"])
        with open(os.path.join(b["trace_dir"], "0000-nonfinite"), "w") as fh:
            sid = "nonfinite-sid"
            fh.write('{"event":"start","sid":"%s","argv":["git","fetch","origin"],"time":"2026-10-15T00:00:00Z"}\n'
                     '{"event":"cmd_name","sid":"%s","name":"fetch","hierarchy":"fetch"}\n'
                     '{"event":"data","sid":"%s","category":"negotiation_v2","key":"total_rounds","value":"-3"}\n'
                     '{"event":"exit","sid":"%s","code":0,"t_abs":NaN}\n' % (sid, sid, sid, sid))
        out, log = self.job.step_logged("after", SPS_ID=b["id"], SPS_PATH="nonfinite", SPS_OUTCOME=outcome)
        self.assertNotIn("::warning::", log)

        def no_constants(name):
            raise ValueError("non-standard JSON constant %s in the published record" % name)

        record = json.loads(out["record"], parse_constant=no_constants)
        self.assertEqual(srcstats.validate(record, "source-prep.v1.json"), [])
        self.assertIsNone(record["transfer"]["fetch_seconds"])
        self.assertGreaterEqual(record["transfer"]["negotiation_rounds"], 1, "the real fetch's rounds, not -3")
        self.assertEqual(record["measurement"]["trace"]["bad_lines"], 2)
        self.assertFalse(record["measurement"]["complete"])

    def test_an_exception_message_never_reaches_the_public_log(self):
        """The catch-all names the exception, never its text: a message can quote trace content (a URL)."""
        b = self.job.step("before", SPS_PATH="raises")

        def leaky(*args, **kwargs):
            raise RuntimeError("unable to access '%s'" % PLANTED)

        with mock.patch.object(srcstats, "summarize_trace", leaky):
            _, log = self.job.inproc("after", SPS_ID=b["id"], SPS_PATH="raises", SPS_OUTCOME="failure")
        self.assertIn("::warning::", log)
        self.assertIn("RuntimeError", log)
        self.assertNotIn(PLANTED_TOKEN, log)

    def test_malformed_trace_leaves_no_raw_trace_or_secret_on_disk(self):
        """The malformed-hierarchy path: the step still writes a record, marks the trace damaged, and leaves the
        planted URL nowhere (no output, log, summary or file under the job, the raw trace included)."""
        b = self.job.step("before", SPS_PATH="malformed")
        outcome = self.job.checkout(self.url, "malformed", trace=b["trace_dir"])
        write_trace(b["trace_dir"], "0000-planted", planted_events("planted-sid"))
        write_trace(b["trace_dir"], "0001-malformed", malformed_events("malformed-sid"), tail=DEEP)
        out, log = self.job.step_logged("after", SPS_ID=b["id"], SPS_PATH="malformed", SPS_OUTCOME=outcome)
        self.assertEqual(files_containing(self.job.root, PLANTED_TOKEN), [])
        self.assertFalse(os.path.exists(b["trace_dir"]), "raw trace deleted")
        self.assertNotIn("::warning::", log)
        record = json.loads(out["record"])
        self.assertEqual(srcstats.validate(record, "source-prep.v1.json"), [])
        self.assertGreaterEqual(record["measurement"]["trace"]["bad_lines"], 1)
        self.assertFalse(record["measurement"]["complete"], "a damaged trace is not a complete measurement")
        self.assertNotIn(PLANTED_TOKEN, log + self.job.published())

    def test_a_raising_parse_still_deletes_the_raw_trace(self):
        """Whatever raises inside the after step, the finally deletes the raw trace."""
        b = self.job.step("before", SPS_PATH="raising")
        outcome = self.job.checkout(self.url, "raising", trace=b["trace_dir"])
        write_trace(b["trace_dir"], "0000-planted", planted_events("planted-sid"))

        def leaky(*args, **kwargs):
            raise RuntimeError("unable to access '%s'" % PLANTED)

        with mock.patch.object(srcstats, "summarize_trace", leaky):
            _, log = self.job.inproc("after", SPS_ID=b["id"], SPS_PATH="raising", SPS_OUTCOME=outcome)
        self.assertIn("RuntimeError", log, "positive control: the step did raise")
        self.assertFalse(os.path.exists(b["trace_dir"]), "raw trace deleted on the raise path")
        self.assertEqual(files_containing(self.job.root, PLANTED_TOKEN), [])
        self.assertNotIn(PLANTED_TOKEN, log + self.job.published())

    def test_telemetry_with_a_malformed_job_trace_leaves_no_raw_trace(self):
        self.job.prepare(self.url, "jobtrace", trace_job=True)
        env_lines = read(self.job.files["GITHUB_ENV"]).splitlines()
        job_trace = [l.split("=", 1)[1] for l in env_lines if l.startswith("GIT_TRACE2_EVENT=")][0]
        write_trace(job_trace, "0000-planted", planted_events("planted-sid"))
        write_trace(job_trace, "0001-malformed", malformed_events("malformed-sid"), tail=DEEP)
        out, log = self.job.step_logged("telemetry")
        self.assertEqual(files_containing(self.job.root, PLANTED_TOKEN), [])
        self.assertEqual(os.listdir(job_trace), [], "raw lines dropped; the directory stays for later git calls")
        doc = json.loads(read(out["path"]))
        self.assertEqual(srcstats.validate(doc, "job-telemetry.v1.json"), [])
        self.assertNotIn(PLANTED_TOKEN, log + self.job.published())

    def test_partial_clone_filter_from_config_is_allow_listed(self):
        self.job.prepare(self.url, "cfgfilter", filt="blob:none")
        git("-C", os.path.join(self.job.ws, "cfgfilter"), "config", "remote.origin.partialclonefilter", PLANTED)
        out = self.job.step("after", SPS_ID="", SPS_PATH="cfgfilter", SPS_OUTCOME="success")
        record = json.loads(out["record"])
        self.assertEqual((record["partial"], record["filter"]), (True, "other"))
        self.assertNotIn(PLANTED_TOKEN, self.job.published())

    def test_429_injector_counts_one_throttle_hit_and_one_retry(self):
        before = self.server.throttled
        self.server.throttle(1)
        r = self.job.prepare(self.url, "throttled")
        self.assertEqual(self.server.throttled - before, 1, "positive control: the injector answered one 429")
        self.assertEqual(r["throttle_hits"], 1)
        self.assertEqual(r["retries"], 1)
        self.assertEqual((r["transfer"]["fetch_attempts"], r["transfer"]["failed_fetch_attempts"]), (2, 1))
        self.assertEqual(r["checkout"]["outcome"], "success")
        self.assertEqual(r["completeness"], "complete")

    def test_exhausted_retries_are_a_failed_checkout_not_a_complete_tree(self):
        self.server.throttle(3)
        r = self.job.prepare(self.url, "exhausted")
        self.assertEqual((r["throttle_hits"], r["retries"]), (3, 2))
        self.assertEqual(r["checkout"]["outcome"], "failure")
        self.assertEqual(r["completeness"], "incomplete")
        self.assertIn("checkout-failure", r["incomplete_reasons"])

    def test_depth0_and_blobless_report_different_filter_and_partial(self):
        full = self.job.prepare(self.url, "depth0", depth=0)
        blobless = self.job.prepare(self.url, "blobless", depth=0, filt="blob:none")
        self.assertEqual((full["filter"], full["partial"]), (None, False))
        self.assertEqual((blobless["filter"], blobless["partial"]), ("blob:none", True))
        self.assertEqual(blobless["transfer"]["filter_effective"], "blob:none")
        self.assertEqual(full["depth"], "full")
        self.assertEqual(blobless["depth"], "full")
        self.assertEqual(blobless["sparse"], False, "partial and sparse are recorded separately")
        self.assertEqual((blobless["completeness"], blobless["incomplete_reasons"]), ("incomplete", ["partial"]))
        self.assertGreaterEqual(blobless["transfer"]["lazy_fetches"], 1, "checkout fetched the HEAD blobs lazily")
        self.assertEqual(full["transfer"]["lazy_fetches"], 0)
        self.assertEqual(blobless["files_materialised"], self.COMMITS)

    def test_shallow_sparse_is_incomplete_with_every_reason(self):
        r = self.job.prepare(self.url, "shallow-sparse", depth=1, sparse=["a"])
        self.assertEqual((r["shallow"], r["depth"]), (True, 1))
        self.assertEqual((r["sparse"], r["sparse_cone"]), (True, True))
        self.assertGreaterEqual(r["sparse_patterns"], 1)
        self.assertRegex(r["sparse_patterns_sha256"], "^[0-9a-f]{64}$")
        self.assertEqual(r["files_materialised"], len([i for i in range(self.COMMITS) if i % 3 == 0]))
        self.assertEqual(r["files_skipped"], self.COMMITS - r["files_materialised"])
        # actions/checkout makes every sparse checkout a blob:none partial clone too
        self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("incomplete", ["shallow", "partial", "sparse"]))
        self.assertEqual(r["filter"], "blob:none")
        self.assertIsNone(r["requested"]["filter"], "requested and observed are recorded separately")
        self.assertEqual(r["requested"]["fetch_depth"], 1)
        self.assertTrue(r["requested"]["sparse_checkout"])

    def after_with_failed_read(self, path, key, code):
        with config_read_fails(key, code):
            out, _ = self.job.inproc("after", SPS_ID="", SPS_PATH=path, SPS_OUTCOME="success")
        record = json.loads(out["record"])
        self.assertEqual(srcstats.validate(record, "source-prep.v1.json"), [])
        return record

    def test_unset_partial_and_sparse_keys_are_a_measured_false(self):
        r = self.job.prepare(self.url, "unset-keys")
        dest = os.path.join(self.job.ws, "unset-keys")
        # positive control: on this checkout each key is really unset, which `git config` answers with exit 1
        for args in (["--get", "extensions.partialclone"], ["--get-regexp", PROMISOR_RE],
                     ["--bool", "--get", "core.sparseCheckout"]):
            self.assertEqual(git("-C", dest, "config", *args, check=False).returncode, 1, args)
        self.assertEqual((r["partial"], r["filter"], r["sparse"], r["sparse_cone"]), (False, None, False, None))
        for field in ("partial", "filter", "sparse", "sparse_cone", "sparse_patterns"):
            self.assertNotIn(field, r["unknown"])
        self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("complete", []))
        git("-C", dest, "config", "core.sparseCheckout", "false")  # set to false: the same answer
        out = self.job.step("after", SPS_ID="", SPS_PATH="unset-keys", SPS_OUTCOME="success")
        again = json.loads(out["record"])
        self.assertEqual((again["sparse"], again["completeness"]), (False, "complete"))
        self.assertNotIn("sparse", again["unknown"])

    def test_a_failed_partial_or_sparse_read_is_unknown_never_false(self):
        """A config read that failed (an error exit, a kill, git not starting) is unknown with its reason, and
        the tree is then never complete: only exit 1 says the key is unset."""
        r = self.job.prepare(self.url, "failed-read")
        self.assertEqual((r["partial"], r["sparse"], r["completeness"]), (False, False, "complete"),
                         "positive control: unmocked, the same checkout is measured complete")
        cases = (("extensions.partialclone", "partial", ("filter",)), (PROMISOR_RE, "partial", ("filter",)),
                 ("core.sparseCheckout", "sparse", ("sparse_cone", "sparse_patterns")))
        for key, field, dependent in cases:
            for code in FAILED_READS:
                with self.subTest(key=key, code=code):
                    record = self.after_with_failed_read("failed-read", key, code)
                    self.assertNotEqual(record["completeness"], "complete", "an unread fact rounded up")
                    self.assertEqual(record["completeness"], "unknown")
                    self.assertIsNone(record[field])
                    self.assertIn("failed", record["unknown"].get(field, ""))
                    for other in dependent:  # not applicable only when the parent is false, not unknown
                        self.assertIn(other, record["unknown"])

    def test_a_failed_filter_or_cone_read_is_unknown_never_a_default(self):
        self.job.prepare(self.url, "failed-filter", filt="blob:none")
        self.job.prepare(self.url, "failed-cone", depth=1, sparse=["a"])
        promisor = git("-C", os.path.join(self.job.ws, "failed-filter"), "config", "--get", "remote.origin.promisor")
        self.assertEqual(promisor.stdout.strip(), b"true", "positive control: the blobless checkout has a promisor")
        for code in FAILED_READS:
            with self.subTest(read="extensions.partialclone, promisor found", code=code):
                r = self.after_with_failed_read("failed-filter", "extensions.partialclone", code)
                self.assertEqual((r["partial"], r["filter"]), (True, "blob:none"), "a promisor found is partial")
                self.assertNotIn("partial", r["unknown"])
                self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("incomplete", ["partial"]))
            with self.subTest(read="filter", code=code):
                r = self.after_with_failed_read("failed-filter", "remote.origin.partialclonefilter", code)
                self.assertEqual((r["partial"], r["filter"]), (True, None))
                self.assertIn("failed", r["unknown"].get("filter", ""))
                self.assertNotIn("origin", r["unknown"]["filter"], "the remote name is never published")
                self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("incomplete", ["partial"]))
            with self.subTest(read="cone", code=code):
                r = self.after_with_failed_read("failed-cone", "core.sparseCheckoutCone", code)
                self.assertEqual((r["sparse"], r["sparse_cone"]), (True, None))
                self.assertIn("failed", r["unknown"].get("sparse_cone", ""))
                self.assertGreaterEqual(r["sparse_patterns"], 1, "the patterns are still read")
                self.assertEqual(r["completeness"], "incomplete")

    def test_a_gitmodules_that_cannot_be_statted_is_unknown_never_no_submodules(self):
        """os.path.isfile answers False for a .gitmodules it may not stat, so a tree whose submodules were not
        fetched was published complete."""
        self.job.prepare(self.url, "lockedmodules")
        dest = os.path.join(self.job.ws, "lockedmodules")
        with open(os.path.join(dest, ".gitmodules"), "w") as fh:
            fh.write('[submodule "sub"]\n\tpath = sub\n\turl = ../sub.git\n')
        out, _ = self.job.inproc("after", SPS_ID="", SPS_PATH="lockedmodules", SPS_OUTCOME="success")
        r = json.loads(out["record"])
        self.assertEqual((r["completeness"], r["incomplete_reasons"]), ("incomplete", ["submodules-not-fetched"]),
                         "positive control: readable, the same .gitmodules makes the tree incomplete")
        with stat_refused(os.path.join(dest, ".gitmodules")):
            out, _ = self.job.inproc("after", SPS_ID="", SPS_PATH="lockedmodules", SPS_OUTCOME="success")
        r = json.loads(out["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertNotEqual(r["completeness"], "complete", "an unread fact rounded up")
        self.assertEqual(r["completeness"], "unknown")
        self.assertIn("could not be read", r["unknown"].get("has_submodules", ""))

    def test_warm_refetch_counts_only_the_new_objects(self):
        first = self.job.prepare(self.url, "warm")
        extra = os.path.join(self.tmp, "warm-work")
        git("clone", "-q", self.bare, extra)
        commit_files(extra, 1000, 4)  # the object count is read from the server below, not assumed
        git("-C", extra, "push", "-q", self.bare, "HEAD:main")
        try:
            new = self.server_objects("main", "^" + first["subject"]["commit"])
            again = self.job.prepare(self.url, "warm")
        finally:
            git("-C", self.bare, "update-ref", "refs/heads/main", first["subject"]["commit"])
        self.assertIs(again["warm"], True)
        self.assertEqual(again["objects"], new)
        self.assertGreater(again["bytes"], 0)
        # Below fetch.unpackLimit the objects arrive loose: no new pack, the bytes are the loose delta.
        self.assertEqual(again["bytes_detail"]["new_pack_bytes"], 0)
        self.assertEqual(again["bytes"], again["bytes_detail"]["loose_bytes_delta"])
        self.assertLess(again["bytes"], first["bytes"])

    def test_without_a_before_step_unmeasured_values_are_null_not_zero(self):
        self.job.checkout(self.url, "nobefore")
        a = self.job.step("after", SPS_ID="", SPS_PATH="nobefore", SPS_OUTCOME="success")
        r = json.loads(a["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        for key in ("bytes", "objects", "retries", "throttle_hits", "transfer", "warm"):
            self.assertIsNone(r[key], key)
        self.assertIsNone(r["checkout"]["seconds"])
        self.assertIn("before", r["unknown"])
        self.assertIn("transfer", r["unknown"])
        self.assertFalse(r["measurement"]["complete"])
        self.assertEqual(r["depth"], "full", "facts read from the repository afterwards are still measured")

    def test_no_repository_after_checkout_is_unknown(self):
        b = self.job.step("before", SPS_PATH="never")
        a = self.job.step("after", SPS_ID=b["id"], SPS_PATH="never", SPS_OUTCOME="failure")
        r = json.loads(a["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertEqual(r["completeness"], "unknown")
        self.assertIsNone(r["bytes"])
        self.assertIsNone(r["depth"])
        self.assertIn("repository", r["unknown"])
        self.assertIn("transfer", r["unknown"], "no git process ran, so transfer is unknown, not zero")

    def test_checkout_seconds_exclude_the_measurement_walks(self):
        """checkout.seconds is the checkout, not the snapshots around it (seconds of walking on a large warm .git)."""
        real = srcstats.snapshot

        def slow(*args, **kwargs):
            time.sleep(1.0)
            return real(*args, **kwargs)

        def run(cmd, **extra):  # in process, so the slow snapshot is the one the action's code calls
            open(self.job.files["GITHUB_OUTPUT"], "w").close()
            printed = io.StringIO()
            with mock.patch.dict(os.environ, self.job.env(**extra), clear=True), \
                    mock.patch.object(srcstats, "snapshot", slow), contextlib.redirect_stdout(printed):
                self.assertEqual(srcstats.main([cmd]), 0)
            self.assertNotIn("::warning::", printed.getvalue())
            with open(self.job.files["GITHUB_OUTPUT"]) as fh:
                return dict(line.rstrip("\n").partition("=")[::2] for line in fh)

        b = run("before", SPS_PATH="timed")
        start = time.monotonic()
        outcome = self.job.checkout(self.url, "timed", trace=b["trace_dir"])
        took = time.monotonic() - start
        a = run("after", SPS_ID=b["id"], SPS_PATH="timed", SPS_OUTCOME=outcome)
        seconds = json.loads(a["record"])["checkout"]["seconds"]
        self.assertGreater(seconds, 0)
        self.assertLess(seconds, took + 0.5, "a 1 s snapshot walk was counted as checkout time")

    def test_exhausted_walk_budget_is_unknown_not_partial(self):
        r = self.job.prepare(self.url, "budget", SPS_WALK_BUDGET="0")
        self.assertIsNone(r["bytes_detail"]["git_dir_bytes_after"])
        self.assertIn("git_dir_bytes", r["unknown"])
        self.assertFalse(r["measurement"]["complete"])
        self.assertGreater(r["bytes"], 0, "pack bytes do not need the walk")

    def prepare_then_after_with(self, path, patch):
        """before and a traced checkout as subprocesses, then the after step in process under `patch`."""
        b = self.job.step("before", SPS_PATH=path)
        outcome = self.job.checkout(self.url, path, trace=b["trace_dir"])
        with patch(os.path.join(self.job.ws, path, ".git")):
            out, log = self.job.inproc("after", SPS_ID=b["id"], SPS_PATH=path, SPS_OUTCOME=outcome)
        self.assertNotIn("::warning::", log)
        record = json.loads(out["record"])
        self.assertEqual(srcstats.validate(record, "source-prep.v1.json"), [])
        return record

    def test_an_unreadable_directory_in_git_dir_is_unknown_not_measured(self):
        r = self.prepare_then_after_with("unreadable-logs", lambda git_dir: unreadable(os.path.join(git_dir, "logs")))
        self.assertTrue(os.path.isdir(os.path.join(self.job.ws, "unreadable-logs", ".git", "logs")),
                        "positive control: the refused directory exists")
        self.assertIsNone(r["bytes_detail"]["git_dir_bytes_after"], "a total that skipped .git/logs is not a size")
        self.assertIn("could not be read", r["unknown"]["git_dir_bytes"])
        self.assertFalse(r["measurement"]["complete"])
        self.assertGreater(r["bytes"], 0, "the pack listing did not need .git/logs")

    def test_an_unreadable_pack_directory_is_unknown_bytes_not_a_lost_record(self):
        r = self.prepare_then_after_with(
            "unreadable-pack", lambda git_dir: unreadable(os.path.join(git_dir, "objects", "pack")))
        self.assertIsNone(r["bytes"])
        self.assertIsNone(r["bytes_detail"]["new_pack_bytes"])
        self.assertIn("could not be read", r["unknown"]["bytes"])
        self.assertIsNone(r["bytes_detail"]["objects_bytes_after"])
        self.assertFalse(r["measurement"]["complete"])

    def test_an_unreadable_store_is_unknown_not_zero(self):
        store = os.path.join(self.job.root, "locked-store")
        os.makedirs(store)
        with open(os.path.join(store, "a"), "wb") as fh:
            fh.write(b"x" * 1000)
        with unreadable(store):
            out, log = self.job.inproc("telemetry", SPS_PNPM_STORE=store)
        doc = json.loads(read(out["path"]))
        self.assertEqual(srcstats.validate(doc, "job-telemetry.v1.json"), [])
        self.assertIsNone(doc["pnpm_store"]["bytes_after"], "an unreadable store is unknown, never 0 bytes")
        self.assertIn("could not be read", doc["unknown"]["pnpm_store.bytes_after"])

    def test_an_unreadable_checkout_path_is_unknown_not_a_cold_start(self):
        """A warm path the before step cannot stat: os.path.exists said "no .git", so the warm re-fetch was
        recorded as a cold start (warm false, objects before 0) and every pack already there as new bytes."""
        self.job.prepare(self.url, "locked")
        with stat_refused(os.path.join(self.job.ws, "locked", ".git")):
            b, log = self.job.inproc("before", SPS_PATH="locked")
        self.assertNotIn("::warning::", log)
        outcome = self.job.checkout(self.url, "locked", trace=b["trace_dir"])
        r = json.loads(self.job.step("after", SPS_ID=b["id"], SPS_PATH="locked", SPS_OUTCOME=outcome)["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertGreater(r["objects_detail"]["after"], 0, "positive control: the repository is there after")
        self.assertIsNone(r["warm"])
        self.assertEqual((r["bytes"], r["objects"], r["objects_detail"]["before"]), (None, None, None))
        self.assertIn("could not be read", r["unknown"]["before.repository"])
        self.assertFalse(r["measurement"]["complete"])

    def test_a_pack_directory_that_cannot_be_statted_is_unknown_not_empty(self):
        """os.path.isdir answered False for a pack directory it could not stat, which listed as "no packs"."""
        self.job.prepare(self.url, "lockedpack")
        objects = os.path.join(self.job.ws, "lockedpack", ".git", "objects")
        packs, loose, reason = srcstats.object_files(objects, srcstats.Budget(20))
        self.assertTrue(packs, "positive control: the pack is listed when readable")
        with stat_refused(os.path.join(objects, "pack")):
            packs, loose, reason = srcstats.object_files(objects, srcstats.Budget(20))
        self.assertEqual((packs, loose), (None, None))
        self.assertIn("could not be read", reason)

    def test_a_store_that_cannot_be_statted_says_so(self):
        store = os.path.join(self.job.root, "unstattable-store")
        os.makedirs(store)
        with stat_refused(store):
            snap = srcstats.store_snapshot(store, srcstats.Budget(20))
        self.assertIsNone(snap["bytes"])
        self.assertIn("could not be read", snap["reason"], "it exists: 'does not exist' is the wrong reason")

    def test_a_non_finite_walk_budget_is_refused_and_the_walk_still_stops(self):
        """walk-budget-seconds inf (or 1e400, NaN, negative) is refused with a warning and the default used. A
        clock that runs 50 s per reading stands in for a slow walk: with an infinite budget it never ended."""
        self.job.prepare(self.url, "budget-inf")
        for value in ("inf", "1e400", "nan", "-1"):
            with self.subTest(value=value):
                ticks = itertools.count(1000.0, 50.0)
                with mock.patch("time.monotonic", lambda: next(ticks)):
                    out, log = self.job.inproc("after", SPS_ID="", SPS_PATH="budget-inf", SPS_OUTCOME="success",
                                               SPS_WALK_BUDGET=value)
                r = json.loads(out["record"])
                self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
                self.assertIsNone(r["bytes_detail"]["git_dir_bytes_after"], "the walk was not allowed to run on")
                self.assertFalse(r["measurement"]["complete"])
                self.assertRegex(log, r"::warning::.*walk-budget-seconds must be a finite number")

    def test_a_hung_git_cannot_outlast_the_step_deadline(self):
        """A git that never answers is killed at the step's read deadline (patched to 2 s): every later read is
        unknown and the record is still written. It used to wait 60 s per git command."""
        fakebin = os.path.join(self.job.root, "fakebin")
        os.makedirs(fakebin)
        with open(os.path.join(fakebin, "git"), "w") as fh:
            fh.write("#!/bin/sh\nexec sleep 30\n")  # exec: no orphan keeps the pipe open
        os.chmod(os.path.join(fakebin, "git"), 0o755)
        os.makedirs(os.path.join(self.job.ws, "hung", ".git"))
        result = {}

        def run():
            with mock.patch.object(srcstats, "DEADLINE_SECONDS", 2.0, create=True):
                result["after"] = self.job.inproc("after", SPS_ID="", SPS_PATH="hung", SPS_OUTCOME="success",
                                                  PATH=fakebin + os.pathsep + os.environ.get("PATH", ""))

        start = time.monotonic()
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(20)
        self.assertFalse(worker.is_alive(), "the after step hung on a git that never answers")
        self.assertLess(time.monotonic() - start, 12)
        out, log = result["after"]
        self.assertNotIn("::warning::", log)
        r = json.loads(out["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertIn("deadline", r["unknown"]["repository"])
        self.assertIsNone(r["producer"]["git_version"])
        self.assertEqual(r["completeness"], "unknown")

    def run_driver(self, body, wait=None, **extra):
        """srcstats.main(["after"]) in a child Python after `body` (patches), as the composite step runs it.
        wait(proc) runs while it is alive. Returns its exit code."""
        driver = os.path.join(self.job.root, "driver.py")
        with open(driver, "w") as fh:
            fh.write("import os, signal, sys\nsys.path.insert(0, %r)\nimport srcstats\n%s\n"
                     "sys.exit(srcstats.main(['after']))\n" % (HERE, body))
        proc = subprocess.Popen([sys.executable, "-B", driver], env=self.job.env(**extra), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            if wait:
                wait(proc)
            return proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_a_terminated_after_step_still_deletes_the_raw_trace(self):
        """A cancelled or timed-out job sends the step SIGTERM. Python's default action exits without running
        finally blocks, which left the raw trace (and its planted URL) in RUNNER_TEMP."""
        b = self.job.step("before", SPS_PATH="sigterm")
        outcome = self.job.checkout(self.url, "sigterm", trace=b["trace_dir"])
        write_trace(b["trace_dir"], "0000-planted", planted_events("planted-sid"))
        code = self.run_driver(
            "def parse(*args, **kwargs):\n    os.kill(os.getpid(), signal.SIGTERM)\n    return None, 'unreached'\n"
            "srcstats.summarize_trace = parse",
            SPS_ID=b["id"], SPS_PATH="sigterm", SPS_OUTCOME=outcome)
        self.assertIn(code, (143, -15), "positive control: the step was terminated mid-parse")
        self.assertFalse(os.path.exists(b["trace_dir"]), "raw trace deleted on the SIGTERM path")
        self.assertEqual(files_containing(self.job.root, PLANTED_TOKEN), [])

    def test_a_terminated_step_leaves_no_git_running(self):
        """git runs in its own session, so killing the step's process group does not reach it. SIGTERM during
        a git read must kill it before the step exits."""
        fakebin = os.path.join(self.job.root, "fakebin")
        os.makedirs(fakebin)
        pidfile = os.path.join(self.job.root, "git.pid")
        with open(os.path.join(fakebin, "git"), "w") as fh:
            fh.write("#!/bin/sh\necho $$ > %s\nexec sleep 30\n" % pidfile)
        os.chmod(os.path.join(fakebin, "git"), 0o755)
        os.makedirs(os.path.join(self.job.ws, "orphan", ".git"))

        def alive(pid):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            return True

        def terminate_when_git_runs(proc):
            for _ in range(200):
                if os.path.exists(pidfile) and os.path.getsize(pidfile):
                    break
                time.sleep(0.05)
            self.assertTrue(os.path.exists(pidfile), "positive control: the step started git")
            proc.send_signal(15)

        pid = None
        try:
            code = self.run_driver("", wait=terminate_when_git_runs, SPS_ID="", SPS_PATH="orphan",
                                   SPS_OUTCOME="success", PATH=fakebin + os.pathsep + os.environ.get("PATH", ""))
            pid = int(read(pidfile))
            self.assertIn(code, (143, -15))
            for _ in range(40):  # reaped by init once the step is gone: allow a moment
                if not alive(pid):
                    break
                time.sleep(0.05)
            self.assertFalse(alive(pid), "git outlived the terminated step")
        finally:
            if pid and alive(pid):
                os.kill(pid, 9)

    def test_a_spent_byte_budget_leaves_every_later_read_unknown(self):
        """Past the shared byte budget (patched to 2000 bytes; the checkout's trace alone is larger), the trace
        and every git read after it are unknown, and the record is still written."""
        b = self.job.step("before", SPS_PATH="spent")
        outcome = self.job.checkout(self.url, "spent", trace=b["trace_dir"])
        traced = sum(os.path.getsize(os.path.join(b["trace_dir"], n)) for n in os.listdir(b["trace_dir"]))
        self.assertGreater(traced, 2000, "positive control: the trace is over the patched budget")
        with mock.patch.object(srcstats, "MAX_READ_BYTES", 2000, create=True):
            out, log = self.job.inproc("after", SPS_ID=b["id"], SPS_PATH="spent", SPS_OUTCOME=outcome)
        self.assertNotIn("::warning::", log)
        r = json.loads(out["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertIsNone(r["transfer"])
        self.assertIn("bytes", r["unknown"]["transfer"])
        self.assertEqual(r["completeness"], "unknown", "a fact never defaults to complete for want of a read")
        self.assertIsNone(r["shallow"])
        self.assertFalse(r["measurement"]["complete"])
        self.assertFalse(os.path.exists(b["trace_dir"]))

    def test_telemetry_merges_records_footprint_lazy_fetches_and_pnpm_delta(self):
        store = os.path.join(self.job.root, "pnpm-store")
        os.makedirs(store)
        with open(os.path.join(store, "a"), "wb") as fh:
            fh.write(b"x" * 1000)
        self.job.prepare(self.url, "one", SPS_PNPM_STORE=store)
        self.job.prepare(self.url, "two", filt="blob:none", sparse=["a"], trace_job=True)
        env_lines = read(self.job.files["GITHUB_ENV"]).splitlines()
        trace = [l.split("=", 1)[1] for l in env_lines if l.startswith("GIT_TRACE2_EVENT=")]
        self.assertEqual(len(trace), 1)
        # A later step reads a file outside the sparse cone of the blobless tree: it arrives by lazy fetch,
        # traced job-wide.
        git("-C", os.path.join(self.job.ws, "two"), "show", "HEAD:b/f001.txt",
            env=dict(CLEAN, GIT_TRACE2_EVENT=trace[0], GIT_TRACE2_EVENT_NESTING="8"))
        with open(os.path.join(store, "b"), "wb") as fh:
            fh.write(b"y" * 500)
        out = self.job.step("telemetry", FP_PEAK_BYTES=3 * 1048576 + 5, FP_USAGE_USEC=2500000, FP_MEM_MAX="max",
                            FP_CPU_MAX="300000 100000", FP_CGROUP="/sys/fs/cgroup/x", FP_SCOPE="job")
        doc = json.loads(read(out["path"]))
        self.assertEqual(srcstats.validate(doc, "job-telemetry.v1.json"), [])
        self.assertEqual(len(doc["source_prep"]), 2)
        self.assertEqual(doc["footprint"], {"peak_mib": 3, "cpu_s": 2.5, "mem_limit": "max", "cpus": 3.0,
                                            "cgroup": "/sys/fs/cgroup/x", "scope": "job"})
        self.assertGreaterEqual(doc["after_checkout_git"]["lazy_fetches"], 1)
        self.assertEqual(doc["pnpm_store"]["delta"], 500)
        self.assertTrue(out["name"].startswith("job-telemetry-4242-1-fixture-"))
        self.assertLess(os.path.getsize(out["path"]), 8192)
        again = self.job.step("telemetry")
        self.assertNotEqual(again["name"], out["name"], "matrix legs share github.job; names must still differ")

    def state(self, *parts):
        return os.path.join(self.job.temp, "source-prep-stats", *parts)

    def test_telemetry_publishes_only_records_that_validate(self):
        """A record in the state directory that does not validate (here one with a raw URL as its filter, as an
        older version of this action wrote) is left out of the artifact, with the reason; valid ones stay."""
        r = self.job.prepare(self.url, "validrecord")
        raw = dict(r, id="raw", filter=PLANTED)
        with open(self.state("records", "0000-raw.json"), "w") as fh:
            json.dump(raw, fh)
        out, log = self.job.step_logged("telemetry")
        text = read(out["path"])
        doc = json.loads(text)
        self.assertEqual(srcstats.validate(doc, "job-telemetry.v1.json"), [])
        self.assertEqual([x["id"] for x in doc["source_prep"]], [r["id"]], "the valid record is still published")
        self.assertIn("did not validate", doc["unknown"]["source_prep"])
        self.assertNotIn(PLANTED_TOKEN, text + log + self.job.published())

    def test_a_fifo_in_the_records_directory_never_stalls_telemetry(self):
        """open() on a FIFO with no writer blocks forever; the records are read as regular files only."""
        self.job.prepare(self.url, "fiforecord")
        os.mkfifo(self.state("records", "0000-fifo.json"))
        open(self.job.files["GITHUB_OUTPUT"], "w").close()
        try:
            subprocess.run([sys.executable, SCRIPT, "telemetry"], env=self.job.env(), capture_output=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("telemetry blocked on a FIFO in the records directory")
        out = dict(line.rstrip("\n").partition("=")[::2] for line in open(self.job.files["GITHUB_OUTPUT"]))
        doc = json.loads(read(out["path"]))
        self.assertEqual(len(doc["source_prep"]), 1)

    def test_an_oversized_before_snapshot_is_refused_not_read_whole(self):
        """before.json is read under the step's budget (at most 1 MiB): a larger one is not used."""
        b = self.job.step("before", SPS_PATH="bigbefore")
        outcome = self.job.checkout(self.url, "bigbefore", trace=b["trace_dir"])
        path = self.state("runs", b["id"], "before.json")
        before = json.loads(read(path))
        before["pad"] = "x" * (1 << 20)
        with open(path, "w") as fh:
            json.dump(before, fh)
        r = json.loads(self.job.step("after", SPS_ID=b["id"], SPS_PATH="bigbefore", SPS_OUTCOME=outcome)["record"])
        self.assertEqual(srcstats.validate(r, "source-prep.v1.json"), [])
        self.assertIn("before", r["unknown"])
        self.assertIsNone(r["checkout"]["seconds"])
        self.assertGreater(r["objects_detail"]["after"], 0, "positive control: the after side was measured")

    def test_telemetry_without_measurements_says_unknown(self):
        out = self.job.step("telemetry")
        doc = json.loads(read(out["path"]))
        self.assertEqual(srcstats.validate(doc, "job-telemetry.v1.json"), [])
        self.assertIsNone(doc["source_prep"])
        self.assertIsNone(doc["footprint"]["peak_mib"])
        self.assertIsNone(doc["footprint"]["cpu_s"])
        for key in ("source_prep", "footprint.peak_mib", "footprint.cpu_s", "footprint.scope", "pnpm_store",
                    "after_checkout_git"):
            self.assertIn(key, doc["unknown"])


if __name__ == "__main__":
    unittest.main()
