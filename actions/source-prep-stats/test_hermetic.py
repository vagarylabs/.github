"""Hermetic end-to-end tests: a local smart-HTTP git server, the git command sequence actions/checkout v4 runs,
and the action's subcommands driven exactly as action.yml drives them (env in; GITHUB_OUTPUT/ENV/STEP_SUMMARY out).

No network beyond 127.0.0.1. Needs git with http-backend (any git >= 2.30). Every produced document is checked
against the draft schemas in schema/.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import srcstats  # noqa: E402
from gitserver import GitHTTPServer  # noqa: E402

SCRIPT = os.path.join(HERE, "srcstats.py")
CLEAN = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITHUB_", "RUNNER_", "SPS_", "FP_"))}


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


def read(path):
    with open(path) as fh:
        return fh.read()


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
        open(self.files["GITHUB_OUTPUT"], "w").close()
        r = subprocess.run([sys.executable, SCRIPT, cmd], env=self.env(**extra), capture_output=True, text=True,
                           timeout=120)
        assert r.returncode == 0, r.stderr
        assert "::warning::" not in r.stdout, r.stdout
        out = {}
        with open(self.files["GITHUB_OUTPUT"]) as fh:
            for line in fh:
                key, _, value = line.rstrip("\n").partition("=")
                out[key] = value
        return out

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
        probe = subprocess.run(["du", "-sb", self.job.ws], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("needs GNU du -b (apparent bytes); runs on the Linux CI runner")
        r = self.job.prepare(self.url, "du")
        git_dir = os.path.join(self.job.ws, "du", ".git")
        du = int(subprocess.run(["du", "-sb", git_dir], capture_output=True, text=True, check=True).stdout.split()[0])
        # du -sb counts directory entries too; the record counts file bytes. 1% is the acceptance bound.
        self.assertLessEqual(abs(r["bytes_detail"]["git_dir_bytes_after"] - du) / du, 0.01,
                             (r["bytes_detail"]["git_dir_bytes_after"], du))

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

    def test_exhausted_walk_budget_is_unknown_not_partial(self):
        r = self.job.prepare(self.url, "budget", SPS_WALK_BUDGET="0")
        self.assertIsNone(r["bytes_detail"]["git_dir_bytes_after"])
        self.assertIn("git_dir_bytes", r["unknown"])
        self.assertFalse(r["measurement"]["complete"])
        self.assertGreater(r["bytes"], 0, "pack bytes do not need the walk")

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
