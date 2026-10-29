"""Tests for read.py. Stdlib only, light: a stub API on localhost, and local bare repositories as the clone remote.
Run: python3 -m unittest discover -s actions/sibling-repo-read -p 'test_*.py' -v
"""
import http.server
import importlib.util
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
READ = HERE / "read.py"
SECRET = "ghs_fixtureTOKENthatMustNeverPrint0001"


class Stub:
    """A GitHub API stub: answers each GET /repos/<owner>/<repo> from a per-repo list of statuses (the last repeats)."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.seen = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                repo = self.path.rsplit("/", 1)[-1]
                stub.seen.append((self.path, self.headers.get("Authorization")))
                queue = stub.answers.get(repo, [404])
                status = queue.pop(0) if len(queue) > 1 else queue[0]
                body = json.dumps({"name": repo}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def run(args, token=SECRET, env_extra=None):
    env = dict(os.environ, SIBLING_TOKEN=token)
    env.update(env_extra or {})
    start = time.monotonic()
    out = subprocess.run([sys.executable, "-I", str(READ), *args], capture_output=True, text=True, env=env, timeout=120)
    return out, time.monotonic() - start


class Readiness(unittest.TestCase):
    def ready(self, answers, repos, bound="3"):
        stub = Stub(answers)
        self.addCleanup(stub.close)
        out, elapsed = run(["ready", "--api", stub.url, "--owner", "vagarylabs", "--repos", repos, "--bound", bound])
        return stub, out, elapsed

    def test_200_first_time_costs_no_delay(self):
        stub, out, elapsed = self.ready({"vagary-core": [200]}, "vagary-core")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(len(stub.seen), 1)
        self.assertLess(elapsed, 1.5)
        self.assertEqual(json.loads(out.stdout)["ready"], [{"repo": "vagary-core", "attempts": 1}])

    def test_200_first_time_never_sleeps(self):
        # In-process, with a recording sleep: wall-clock alone cannot tell a short pause from process start.
        import importlib.util
        spec = importlib.util.spec_from_file_location("sibling_read", READ)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        stub = Stub({"vagary-core": [200], "vagary-voice": [200]})
        self.addCleanup(stub.close)
        slept = []
        previous = os.environ.get("SIBLING_TOKEN")
        os.environ["SIBLING_TOKEN"] = SECRET
        try:
            report = module.ready(stub.url, "vagarylabs", ["vagary-core", "vagary-voice"], 5, sleep=slept.append)
        finally:
            if previous is None:
                del os.environ["SIBLING_TOKEN"]
            else:
                os.environ["SIBLING_TOKEN"] = previous
        self.assertEqual(slept, [])
        self.assertEqual([r["attempts"] for r in report], [1, 1])

    def test_404_then_200_succeeds_after_backoff(self):
        stub, out, _ = self.ready({"vagary-core": [404, 404, 200]}, "vagary-core", bound="20")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["ready"][0]["attempts"], 3)

    def test_a_persistent_404_fails_by_name_within_the_bound(self):
        stub, out, elapsed = self.ready({"vagary-core": [404]}, "vagary-core", bound="2")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("App token cannot see vagarylabs/vagary-core after 2 s (last answer 404", out.stderr)
        self.assertIn("installation scope?", out.stderr)
        self.assertLess(elapsed, 2 + 3)  # the bound plus process start, never an unbounded wait
        self.assertGreater(len(stub.seen), 1)

    def test_a_server_error_is_retried_within_the_bound(self):
        _, out, _ = self.ready({"vagary-core": [502, 200]}, "vagary-core", bound="10")
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_every_repository_must_answer_and_one_bound_covers_them_all(self):
        stub, out, _ = self.ready({"vagary-core": [200], "vagary-voice": [404]}, "vagary-core,vagary-voice", bound="2")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("vagarylabs/vagary-voice", out.stderr)

    def test_the_token_goes_only_in_the_authorization_header_and_is_never_printed(self):
        stub, out, _ = self.ready({"vagary-core": [404, 200]}, "vagary-core", bound="10")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(all(auth == f"Bearer {SECRET}" for _, auth in stub.seen))
        self.assertTrue(all(SECRET not in path for path, _ in stub.seen))
        self.assertNotIn(SECRET, out.stdout + out.stderr)
        _, failed, _ = self.ready({"vagary-core": [404]}, "vagary-core", bound="1")
        self.assertNotIn(SECRET, failed.stdout + failed.stderr)

    def test_an_empty_token_or_a_bad_input_refuses(self):
        out, _ = run(["ready", "--api", "http://127.0.0.1:9", "--owner", "vagarylabs", "--repos", "vagary-core"], token="")
        self.assertIn("SIBLING_TOKEN is empty", out.stderr)
        for args in (["--repos", "../x"], ["--repos", ""], ["--owner", "a/b", "--repos", "x"], ["--repos", "x", "--bound", "0"]):
            with self.subTest(args=args):
                base = {"--api": "http://127.0.0.1:9", "--owner": "vagarylabs", "--repos": "x", "--bound": "1"}
                for i in range(0, len(args), 2):
                    base[args[i]] = args[i + 1]
                flat = [v for kv in base.items() for v in kv]
                out, _ = run(["ready", *flat])
                self.assertNotEqual(out.returncode, 0)


class CloneFixture(unittest.TestCase):
    """Two local bare remotes (vagary-core, vagary-voice) and an output directory."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        self.server = root / "remote"
        work = root / "work"
        env = dict(os.environ, GIT_AUTHOR_NAME="f", GIT_AUTHOR_EMAIL="f@example.invalid", GIT_COMMITTER_NAME="f",
                   GIT_COMMITTER_EMAIL="f@example.invalid")
        for repo in ("vagary-core", "vagary-voice"):
            subprocess.run(["git", "init", "-q", "-b", "main", str(work / repo)], check=True)
            (work / repo / "README").write_text(repo + "\n")
            subprocess.run(["git", "-C", str(work / repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(work / repo), "commit", "-qm", "seed"], check=True, env=env)
            (self.server / "vagarylabs").mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "-q", "--bare", str(work / repo), str(self.server / "vagarylabs" / f"{repo}.git")],
                           check=True)
        self.heads = {r: subprocess.run(["git", "-C", str(work / r), "rev-parse", "HEAD"], capture_output=True, text=True,
                                        check=True).stdout.strip() for r in ("vagary-core", "vagary-voice")}
        self.out = root / "out"

    def clone(self, *args, repos="vagary-core,vagary-voice"):
        summary = self.out / "summary.md"
        self.out.mkdir(exist_ok=True)
        out, _ = run(["clone", "--server", f"file://{self.server}", "--owner", "vagarylabs", "--repos", repos, *args],
                     env_extra={"GITHUB_STEP_SUMMARY": str(summary)})
        return out, summary


class Clone(CloneFixture):
    def test_a_bare_clone_and_a_pinned_checkout_record_mains_commit(self):
        out, summary = self.clone("--bare", f"vagary-core:{self.out / 'core.git'}", "--checkout",
                                  f"vagary-voice:{self.out / 'voice'}")
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = {r["repo"]: r for r in json.loads(out.stdout)["read"]}
        self.assertEqual(rows["vagary-core"]["commit"], self.heads["vagary-core"])
        self.assertEqual(rows["vagary-voice"]["commit"], self.heads["vagary-voice"])
        self.assertTrue((self.out / "voice" / "README").is_file())
        self.assertTrue((self.out / "core.git" / "HEAD").is_file())
        self.assertIn(self.heads["vagary-voice"], summary.read_text())

    def test_a_repository_outside_the_tokens_scope_or_a_malformed_pair_refuses(self):
        out, _ = self.clone("--bare", f"vagary-voice:{self.out / 'v.git'}", repos="vagary-core")
        self.assertIn("vagary-voice is not in the token's repositories", out.stderr)
        out, _ = self.clone("--checkout", "no-colon-here")
        self.assertIn("wants repo:path", out.stderr)

    def test_a_checkout_goes_into_a_fresh_directory(self):
        (self.out / "busy").mkdir(parents=True)
        (self.out / "busy" / "left-over").write_text("x\n")
        out, _ = self.clone("--checkout", f"vagary-core:{self.out / 'busy'}")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("exists and is not empty", out.stderr)

    def test_a_checkout_not_at_mains_commit_fails(self):
        # The old per-repo loop asserted `git rev-parse HEAD` == the sha it fetched (root's class item on #37, (b)).
        spec = importlib.util.spec_from_file_location("sibling_read", READ)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real = module.git
        def drifting(*args, cwd, secret=""):
            out = real(*args, cwd=cwd, secret=secret)
            return "0" * 40 + "\n" if args[-2:] == ("rev-parse", "HEAD") else out
        env = dict(os.environ, SIBLING_TOKEN=SECRET)
        with mock.patch.object(module, "git", drifting), mock.patch.dict(os.environ, env, clear=True), \
                self.assertRaises(SystemExit), mock.patch("sys.stderr") as err:
            module.clone(f"file://{self.server}", "vagarylabs", [], [f"vagary-core:{self.out / 'c'}"], ["vagary-core"])
        said = "".join(str(c.args[0]) for c in err.write.call_args_list if c.args)
        self.assertIn(f"is at {'0' * 40}, not main's {self.heads['vagary-core']}", said)

    def test_the_token_steps_run_in_a_reset_shell_that_a_hostile_job_environment_cannot_reach(self):
        # Steps before this action may run PR code that writes BASH_ENV, ENV or a python3/git earlier on PATH (via
        # GITHUB_ENV / GITHUB_PATH). The clone step, run through the shell action.yml declares for it, must neither
        # source the one nor execute the others, and must still clone. Control: GitHub's plain `shell: bash` is caught.
        text = (HERE / "action.yml").read_text()
        step = text.split("    - id: read\n", 1)[1]
        shell = next(line.split("shell: ", 1)[1] for line in step.splitlines() if line.strip().startswith("shell: "))
        body = step.split("      run: |\n", 1)[1]
        script = "\n".join(line[8:] for line in body.splitlines() if line.startswith("        ") or not line.strip())
        evil = pathlib.Path(self.temp.name) / "evil"
        (evil / "bin").mkdir(parents=True)
        caught = evil / "caught"
        (evil / "bash_env.sh").write_text(f'printf "%s\\n" "bash_env:$SIBLING_TOKEN" >> "{caught}"\n')
        for tool, real in (("python3", "/usr/bin/python3"), ("git", "/usr/bin/git")):
            (evil / "bin" / tool).write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool}:$SIBLING_TOKEN" >> "{caught}"\nexec {real} "$@"\n')
            (evil / "bin" / tool).chmod(0o755)
        (evil / "step.sh").write_text(script + "\n")
        def run_step(template, dest):
            env = dict(os.environ, SIBLING_TOKEN=SECRET, SIBLING_SERVER=f"file://{self.server}", SIBLING_OWNER="vagarylabs",
                       SIBLING_REPOS="vagary-core", SIBLING_BARE="", SIBLING_CHECKOUTS=f"vagary-core:{dest}\n",
                       SIBLING_TOKEN_DIR="", SIBLING_TREES="", SIBLING_SPARSE="",
                       GITHUB_ACTION_PATH=str(HERE), BASH_ENV=str(evil / "bash_env.sh"), ENV=str(evil / "bash_env.sh"),
                       PATH=f"{evil / 'bin'}:{os.environ['PATH']}")
            env.pop("GITHUB_STEP_SUMMARY", None)
            return subprocess.run(shlex.split(template.replace("{0}", str(evil / "step.sh"))), env=env,
                                  capture_output=True, text=True, timeout=120)
        out = run_step(shell, self.out / "reset")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.out / "reset" / "README").is_file())
        self.assertFalse(caught.exists(), caught.read_text() if caught.exists() else "")
        self.assertNotIn(SECRET, out.stdout + out.stderr)
        control = run_step("bash --noprofile --norc -eo pipefail {0}", self.out / "plain")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertTrue(caught.exists() and "bash_env:" in caught.read_text() and "python3:" in caught.read_text(),
                        "the control must catch the token, or this test proves nothing")

    def test_read_py_runs_git_from_a_path_a_job_step_cannot_prepend_to(self):
        evil = pathlib.Path(self.temp.name) / "evil-git"
        evil.mkdir()
        caught = evil / "caught"
        (evil / "git").write_text(f'#!/bin/sh\nprintf "%s\\n" "$SIBLING_TOKEN" >> "{caught}"\nexec /usr/bin/git "$@"\n')
        (evil / "git").chmod(0o755)
        self.out.mkdir(exist_ok=True)
        out, _ = run(["clone", "--server", f"file://{self.server}", "--owner", "vagarylabs", "--repos", "vagary-core",
                      "--checkout", f"vagary-core:{self.out / 'c'}"], env_extra={"PATH": f"{evil}:{os.environ['PATH']}"})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(caught.exists(), "git ran from a PATH entry a job step can prepend")

    def test_a_missing_repository_fails_loudly(self):
        out, _ = self.clone("--checkout", f"vagary-core:{self.out / 'c'}", "--bare", f"absent:{self.out / 'a.git'}",
                            repos="vagary-core,absent")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("git clone failed", out.stderr)


def load():
    spec = importlib.util.spec_from_file_location("sibling_read", READ)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOKENS = {"vagary-core": "fixture-core-token-must-never-print", "vagary-voice": "fixture-voice-token-must-never-print"}


class TokenDirFixture(CloneFixture):
    """broker-source-read's token directory as the token source (root's ruling 2026-10-29, core sibling-read path (a)):
    one 0600 file <owner>__<name> per repository in a 0700 directory strictly inside RUNNER_TEMP, as client.py writes
    it. Each repository's git calls get that repository's token and nothing else."""

    def setUp(self):
        super().setUp()
        self.runner_temp = pathlib.Path(self.temp.name) / "runner-temp"
        self.dir = self.runner_temp / "broker-tokens"
        self.dir.mkdir(parents=True)
        os.chmod(self.dir, 0o700)
        for repo, value in TOKENS.items():
            path = self.dir / f"vagarylabs__{repo}"
            path.write_text(value)
            os.chmod(path, 0o600)

    def dir_clone(self, *args, repos="vagary-core,vagary-voice", token="", runner_temp=None, token_dir=None):
        self.out.mkdir(exist_ok=True)
        env = {"GITHUB_STEP_SUMMARY": str(self.out / "summary.md"), "RUNNER_TEMP": str(runner_temp or self.runner_temp)}
        out, _ = run(["clone", "--server", f"file://{self.server}", "--owner", "vagarylabs", "--repos", repos,
                      "--token-dir", str(token_dir or self.dir), *args], token=token, env_extra=env)
        return out


class TokenDir(TokenDirFixture):
    def test_a_token_dir_clone_needs_no_app_token_and_records_mains_commit(self):
        out = self.dir_clone("--bare", f"vagary-core:{self.out / 'core.git'}", "--checkout", f"vagary-voice:{self.out / 'voice'}")
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = {r["repo"]: r for r in json.loads(out.stdout)["read"]}
        self.assertEqual(rows["vagary-voice"]["commit"], self.heads["vagary-voice"])
        self.assertTrue((self.out / "voice" / "README").is_file())
        for value in TOKENS.values():
            self.assertNotIn(value, out.stdout + out.stderr)
        # The files are the caller's: read, never moved or deleted (broker-source-read's revoke removes them).
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["vagarylabs__vagary-core", "vagarylabs__vagary-voice"])

    def test_each_repository_s_git_calls_get_only_its_own_token(self):
        module = load()
        real, seen = module.git, []

        def recording(*args, cwd, secret=""):
            seen.append((args[0] if args[0] != "-C" else args[2], secret))
            return real(*args, cwd=cwd, secret=secret)
        env = {k: v for k, v in os.environ.items() if k != "SIBLING_TOKEN"}
        env["RUNNER_TEMP"] = str(self.runner_temp)
        with mock.patch.object(module, "git", recording), mock.patch.dict(os.environ, env, clear=True):
            tokens = module.dir_tokens(str(self.dir), "vagarylabs", ["vagary-core", "vagary-voice"])
            module.clone(f"file://{self.server}", "vagarylabs", [f"vagary-core:{self.out / 'c.git'}"],
                         [f"vagary-voice:{self.out / 'v'}"], ["vagary-core", "vagary-voice"], tokens)
        remote = {cmd: secret for cmd, secret in seen if cmd in ("clone", "ls-remote", "fetch")}
        self.assertEqual(remote, {"clone": TOKENS["vagary-core"], "ls-remote": TOKENS["vagary-voice"],
                                  "fetch": TOKENS["vagary-voice"]})
        self.assertTrue(all(secret == "" for cmd, secret in seen if cmd not in ("clone", "ls-remote", "fetch")),
                        "a local git command got a token")

    def test_the_helper_sees_only_the_secret_it_is_given(self):
        # The credential helper reads SIBLING_TOKEN from git's environment: git() must not pass an inherited one on.
        module = load()
        with mock.patch.dict(os.environ, {"SIBLING_TOKEN": SECRET, "PATH": os.environ["PATH"]}, clear=True), \
                mock.patch.object(module.subprocess, "run") as sub:
            sub.return_value = subprocess.CompletedProcess([], 0, "", "")
            module.git("ls-remote", "x", cwd="/", secret=TOKENS["vagary-core"])
            module.git("rev-parse", "HEAD", cwd="/")
        first, second = (c.kwargs["env"] for c in sub.call_args_list)
        self.assertEqual(first["SIBLING_TOKEN"], TOKENS["vagary-core"])
        self.assertNotIn("SIBLING_TOKEN", second)

    def test_reading_the_broker_s_rules_leaves_no_bytecode_in_the_action_cache(self):
        # The action directory is the runner's shared cache: the client is compiled from source, never imported. A
        # private copy of both actions, so no other test's run can have written the cache this one looks at.
        actions = pathlib.Path(self.temp.name) / "actions-copy"
        for name, files in (("sibling-repo-read", ("read.py",)), ("broker-source-read", ("client.py",))):
            (actions / name).mkdir(parents=True)
            for f in files:
                shutil.copy(HERE.parent / name / f, actions / name / f)
        self.out.mkdir(exist_ok=True)
        env = dict(os.environ, SIBLING_TOKEN="", RUNNER_TEMP=str(self.runner_temp))
        out = subprocess.run([sys.executable, "-I", str(actions / "sibling-repo-read" / "read.py"), "clone", "--server",
                              f"file://{self.server}", "--owner", "vagarylabs", "--repos", "vagary-core", "--token-dir",
                              str(self.dir), "--checkout", f"vagary-core:{self.out / 'c'}"], env=env, capture_output=True,
                             text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual([p.name for p in actions.rglob("*") if p.is_dir() and p.name == "__pycache__"], [])

    def test_every_unsafe_token_dir_is_refused_unread(self):
        cases = []

        def case(name, setup, expect, **kw):
            cases.append((name, setup, expect, kw))
        case("missing file for a listed repository", lambda: (self.dir / "vagarylabs__vagary-voice").unlink(),
             "vagarylabs__vagary-voice cannot be read")
        case("group-readable file", lambda: os.chmod(self.dir / "vagarylabs__vagary-core", 0o640), "open to group or others")
        case("world-readable directory", lambda: os.chmod(self.dir, 0o755), "open to group or others")
        case("a token with a line break", lambda: (self.dir / "vagarylabs__vagary-core").write_text(TOKENS["vagary-core"] + "\n"),
             "does not hold exactly one credential")
        case("a token with a space", lambda: (self.dir / "vagarylabs__vagary-core").write_text("fixture core token"),
             "does not hold exactly one credential")
        case("an empty token", lambda: (self.dir / "vagarylabs__vagary-core").write_text(""), "does not hold exactly one credential")

        def file_link():
            target = pathlib.Path(self.temp.name) / "elsewhere"
            target.write_text(TOKENS["vagary-core"])
            os.chmod(target, 0o600)
            (self.dir / "vagarylabs__vagary-core").unlink()
            (self.dir / "vagarylabs__vagary-core").symlink_to(target)
        case("a symlinked token file", file_link, "is not a plain file")

        def dir_link():
            (self.runner_temp / "linked").symlink_to(self.dir)
        # Keyword values are callables, read after each case's fresh setUp.
        case("a symlinked directory", dir_link, "is not a plain dir", token_dir=lambda: self.runner_temp / "linked")
        case("a directory outside RUNNER_TEMP", lambda: None, "not inside RUNNER_TEMP",
             runner_temp=lambda: pathlib.Path(self.temp.name) / "other-temp")
        case("RUNNER_TEMP unset", lambda: None, "RUNNER_TEMP is not set", runner_temp=lambda: "")
        case("an App token as well", lambda: None, "exactly one token source", token=lambda: SECRET)
        for name, setup, expect, lazy in cases:
            with self.subTest(name):
                self.setUp()
                setup()
                kw = {k: v() for k, v in lazy.items()}
                if kw.get("runner_temp") == "":
                    out, _ = run(["clone", "--server", f"file://{self.server}", "--owner", "vagarylabs", "--repos",
                                  "vagary-core,vagary-voice", "--token-dir", str(self.dir), "--checkout",
                                  f"vagary-core:{self.out / 'x'}"], token="", env_extra={"RUNNER_TEMP": ""})
                else:
                    if kw.get("runner_temp"):
                        kw["runner_temp"].mkdir(exist_ok=True)
                    out = self.dir_clone("--checkout", f"vagary-core:{self.out / 'x'}", **kw)
                self.assertNotEqual(out.returncode, 0, name)
                self.assertIn(expect, out.stderr)
                self.assertFalse((self.out / "x").exists(), "nothing is cloned once a token source is refused")
                for value in list(TOKENS.values()) + [SECRET]:
                    self.assertNotIn(value, out.stdout + out.stderr)


PLATFORM = {"keep/a.txt": "needed a\n", "keep/b/c.txt": "needed c\n", "scripts/cite.py": "print('cited')\n",
            "docs/big.bin": "x" * 200000 + "\n", "docs/trace.har": "{}\n"}
PATTERNS = "/keep/a.txt\n/keep/b/\n/scripts/cite.py\n"


class Sparse(TokenDirFixture):
    """The two-phase sparse read (root's ruling 2026-10-29, item (2); spine's contract points (a)-(c)): the tree phase
    takes commits and trees only, the consumer derives its patterns from the listing, the sparse phase materializes
    exactly that set of exactly that commit, and nothing outside it is ever fetched, then or later."""

    def setUp(self):
        super().setUp()
        root = pathlib.Path(self.temp.name)
        work = root / "work" / "vagary-platform"
        self.git_env = dict(os.environ, GIT_AUTHOR_NAME="f", GIT_AUTHOR_EMAIL="f@example.invalid", GIT_COMMITTER_NAME="f",
                            GIT_COMMITTER_EMAIL="f@example.invalid")
        subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
        for name, body in PLATFORM.items():
            (work / name).parent.mkdir(parents=True, exist_ok=True)
            (work / name).write_text(body)
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-qm", "seed"], check=True, env=self.git_env)
        self.work = work
        self.remote = self.server / "vagarylabs" / "vagary-platform.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(self.remote)], check=True)
        subprocess.run(["git", "-C", str(self.remote), "config", "uploadpack.allowFilter", "true"], check=True)
        self.sha = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  check=True).stdout.strip()
        self.big = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD:docs/big.bin"], capture_output=True,
                                  text=True, check=True).stdout.strip()
        self.dest = self.runner_temp / "siblings" / "vagary-platform"
        self.patterns = pathlib.Path(self.temp.name) / "patterns.txt"
        self.patterns.write_text(PATTERNS)
        self.output = pathlib.Path(self.temp.name) / "github-output"
        (self.dir / "vagarylabs__vagary-platform").write_text("fixture-platform-token-must-never-print")
        os.chmod(self.dir / "vagarylabs__vagary-platform", 0o600)

    def call(self, *args, repos="vagary-platform", token_dir=False):
        self.out.mkdir(exist_ok=True)
        env = {"GITHUB_STEP_SUMMARY": str(self.out / "summary.md"), "RUNNER_TEMP": str(self.runner_temp),
               "GITHUB_OUTPUT": str(self.output)}
        argv = ["clone", "--server", f"file://{self.server}", "--owner", "vagarylabs", "--repos", repos, *args]
        if token_dir:
            argv += ["--token-dir", str(self.dir)]
        out, _ = run(argv, token="" if token_dir else SECRET, env_extra=env)
        return out

    def present(self, oid):
        # The local object store only: `cat-file -e` in a partial clone would lazy-fetch the object it is asked about.
        objects = subprocess.run(["git", "-C", str(self.dest), "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
                                 capture_output=True, text=True, check=True).stdout.split()
        return oid in objects

    def outputs(self):
        lines = self.output.read_text().splitlines() if self.output.exists() else []
        return {k: v for k, _, v in (line.partition("=") for line in lines)}

    def test_exactly_the_derived_set_is_materialized_and_nothing_outside_it_is_ever_fetched(self):
        out = self.call("--tree", f"vagary-platform:{self.dest}")
        self.assertEqual(out.returncode, 0, out.stderr)
        trees = json.loads(self.outputs()["trees"])
        self.assertEqual(trees["vagary-platform"]["sha"], self.sha)
        self.assertEqual(self.outputs()["sparse-ok"], "", "a tree phase alone is never sparse-ok")
        listing = pathlib.Path(trees["vagary-platform"]["tree"]).read_text().split("\0")
        self.assertEqual(sorted(x for x in listing if x), sorted(PLATFORM))  # the whole tree is listed
        self.assertEqual(sorted(os.listdir(self.dest)), [".git"])  # and nothing is checked out
        self.assertFalse(self.present(self.big), "the tree phase fetched a blob")
        self.output.unlink()
        out = self.call("--sparse", f"vagary-platform:{self.dest}:{self.patterns}")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.outputs()["sparse-ok"], "vagary-platform")
        for name in ("keep/a.txt", "keep/b/c.txt", "scripts/cite.py"):
            self.assertEqual((self.dest / name).read_text(), PLATFORM[name], name)
        self.assertFalse((self.dest / "docs").exists())
        self.assertFalse(self.present(self.big), "a blob outside the set was fetched")
        listed = subprocess.run(["git", "-C", str(self.dest), "sparse-checkout", "list"], capture_output=True, text=True,
                                check=True).stdout
        self.assertEqual(listed, PATTERNS)  # exactly the patterns given, as derived
        # No lazy fetch later: a read outside the set is an error, never a fetch (the remote and promisor are gone).
        later = subprocess.run(["git", "-C", str(self.dest), "show", "HEAD:docs/big.bin"], capture_output=True, text=True,
                               timeout=30)
        self.assertNotEqual(later.returncode, 0)
        self.assertFalse(self.present(self.big))
        self.assertEqual(subprocess.run(["git", "-C", str(self.dest), "remote"], capture_output=True, text=True).stdout, "")
        self.assertEqual(json.loads(out.stdout)["read"][0]["materialized"], 3)
        self.assertIn("| 3 of 5 materialized |", (self.out / "summary.md").read_text())

    def test_the_sparse_phase_checks_out_the_tree_phase_commit_never_a_newer_main(self):
        self.assertEqual(self.call("--tree", f"vagary-platform:{self.dest}").returncode, 0)
        (self.work / "keep" / "a.txt").write_text("moved on\n")
        subprocess.run(["git", "-C", str(self.work), "commit", "-qam", "newer"], check=True, env=self.git_env)
        subprocess.run(["git", "-C", str(self.work), "push", "-q", str(self.remote), "main"], check=True)
        out = self.call("--sparse", f"vagary-platform:{self.dest}:{self.patterns}")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["read"][0]["commit"], self.sha)
        self.assertEqual((self.dest / "keep" / "a.txt").read_text(), PLATFORM["keep/a.txt"])

    def test_the_action_s_read_step_passes_both_phases_and_writes_sparse_ok(self):
        # The arg loops in action.yml's read step, through the shell it declares: trees, then sparse, then the output.
        step, script = step_script("read")
        shell = next(line.split("shell: ", 1)[1] for line in step.splitlines() if line.strip().startswith("shell: "))
        path = pathlib.Path(self.temp.name) / "read-step.sh"
        path.write_text(script + "\n")

        def step(trees="", sparse=""):
            env = dict(os.environ, SIBLING_TOKEN=SECRET, SIBLING_SERVER=f"file://{self.server}", SIBLING_OWNER="vagarylabs",
                       SIBLING_REPOS="vagary-platform", SIBLING_BARE="", SIBLING_CHECKOUTS="", SIBLING_TREES=trees,
                       SIBLING_SPARSE=sparse, SIBLING_TOKEN_DIR="", RUNNER_TEMP=str(self.runner_temp),
                       GITHUB_ACTION_PATH=str(HERE), GITHUB_OUTPUT=str(self.output))
            env.pop("GITHUB_STEP_SUMMARY", None)
            return subprocess.run(shlex.split(shell.replace("{0}", str(path))), env=env, capture_output=True, text=True,
                                  timeout=120)
        out = step(trees=f"vagary-platform:{self.dest}\n")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("vagary-platform", json.loads(self.outputs()["trees"]))
        out = step(sparse=f"vagary-platform:{self.dest}:{self.patterns}\n")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.outputs()["sparse-ok"], "vagary-platform")
        self.assertTrue((self.dest / "keep" / "a.txt").is_file())
        self.assertFalse((self.dest / "docs").exists())

    def test_a_server_that_ignores_the_blob_filter_is_refused(self):
        subprocess.run(["git", "-C", str(self.remote), "config", "uploadpack.allowFilter", "false"], check=True)
        out = self.call("--tree", f"vagary-platform:{self.dest}")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("the server sent blobs despite --filter=blob:none", out.stderr)

    def test_the_two_phases_compose_with_a_broker_token_dir(self):
        self.assertEqual(self.call("--tree", f"vagary-platform:{self.dest}", token_dir=True).returncode, 0)
        out = self.call("--sparse", f"vagary-platform:{self.dest}:{self.patterns}", token_dir=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.dest / "keep" / "a.txt").is_file())
        self.assertNotIn("fixture-platform-token-must-never-print", out.stdout + out.stderr)

    def test_a_fallback_is_a_plain_checkout_and_is_never_sparse_ok(self):
        self.assertEqual(self.call("--tree", f"vagary-platform:{self.dest}").returncode, 0)
        shutil.rmtree(self.dest)
        self.output.unlink()
        out = self.call("--checkout", f"vagary-platform:{self.dest}")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.outputs()["sparse-ok"], "")
        self.assertTrue((self.dest / "docs" / "big.bin").is_file())

    def test_every_sparse_phase_without_its_own_tree_phase_or_with_an_unusable_set_is_refused(self):
        def tree():
            self.assertEqual(self.call("--tree", f"vagary-platform:{self.dest}").returncode, 0)
        # Triples are callables, built after each case's fresh setUp.
        mine = lambda: f"vagary-platform:{self.dest}:{self.patterns}"
        other = lambda: self.runner_temp / "siblings" / "elsewhere"
        cases = (("no tree phase in this job", lambda: None, mine, "no tree phase ran for it in this job"),
                 ("an empty patterns file", lambda: (tree(), self.patterns.write_text("# nothing\n\n")), mine,
                  "an empty set is refused"),
                 ("a carriage return", lambda: (tree(), self.patterns.write_text("/keep/a.txt\r\n")), mine,
                  "carriage return"),
                 ("another directory", tree, lambda: f"vagary-platform:{other()}:{self.patterns}",
                  "is not the directory its tree phase prepared"),
                 ("a directory with files in it", lambda: (tree(), (self.dest / "planted").write_text("x")), mine,
                  "no longer the tree phase's"),
                 ("a malformed triple", lambda: None, lambda: "vagary-platform:no-patterns", "wants repo:dir:patterns-file"))
        for name, setup, triple, expect in cases:
            with self.subTest(name):
                self.setUp()
                setup()
                out = self.call("--sparse", triple())
                self.assertNotEqual(out.returncode, 0)
                self.assertIn(expect, out.stderr)
        with self.subTest("tree and sparse in one call"):
            self.setUp()
            out = self.call("--tree", f"vagary-platform:{self.dest}", "--sparse", f"vagary-platform:{self.dest}:{self.patterns}")
            self.assertIn("its tree phase is in this same call", out.stderr)
            self.assertFalse(self.dest.exists(), "refused before any read")
        with self.subTest("a second tree phase for the same repository"):
            self.setUp()
            tree()
            out = self.call("--tree", f"vagary-platform:{other()}")
            self.assertIn("a tree phase already ran for it in this job", out.stderr)


def step_script(name):
    """The run body of action.yml's step `name`, as the runner would write it."""
    text = (HERE / "action.yml").read_text()
    step = text.split(f"    - id: {name}\n", 1)[1].split("\n    - id: ", 1)[0]
    body = step.split("      run: |\n", 1)[1]
    return step, "\n".join(line[8:] for line in body.splitlines() if line.startswith("        ") or not line.strip())


class AppKeyFree(TokenDirFixture):
    def test_the_action_reads_with_a_token_dir_and_no_app_key_at_all(self):
        # The source check, then the read step through the very shell action.yml declares for it, with no app-id, no
        # private-key and an empty SIBLING_TOKEN: the App-key-free path end to end, short of the runner itself (ci.yml
        # runs that against a public repository).
        _, scope = step_script("scope")
        ok = subprocess.run(["bash", "-c", scope], capture_output=True, text=True,
                            env=dict(os.environ, SIBLING_PACKAGES="", SIBLING_HAS_APP_ID="false", SIBLING_HAS_KEY="false",
                                     SIBLING_HAS_DIR="true"))
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        step, script = step_script("read")
        shell = next(line.split("shell: ", 1)[1] for line in step.splitlines() if line.strip().startswith("shell: "))
        path = pathlib.Path(self.temp.name) / "read-step.sh"
        path.write_text(script + "\n")
        env = dict(os.environ, SIBLING_TOKEN="", SIBLING_SERVER=f"file://{self.server}", SIBLING_OWNER="vagarylabs",
                   SIBLING_REPOS="vagary-voice", SIBLING_BARE="", SIBLING_CHECKOUTS=f"vagary-voice:{self.out / 'v'}\n",
                   SIBLING_TREES="", SIBLING_SPARSE="", SIBLING_TOKEN_DIR=str(self.dir), RUNNER_TEMP=str(self.runner_temp),
                   GITHUB_ACTION_PATH=str(HERE))
        env.pop("GITHUB_STEP_SUMMARY", None)
        out = subprocess.run(shlex.split(shell.replace("{0}", str(path))), env=env, capture_output=True, text=True,
                             timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.out / "v" / "README").is_file())
        self.assertNotIn(TOKENS["vagary-voice"], out.stdout + out.stderr)

    def test_exactly_one_token_source_is_decided_before_any_mint(self):
        _, scope = step_script("scope")
        for app, key, tdir, packages, ok in (("true", "true", "false", "", True), ("true", "true", "false", "read", True),
                                             ("false", "false", "true", "", True), ("false", "false", "true", "read", False),
                                             ("true", "true", "true", "", False), ("false", "true", "true", "", False),
                                             ("true", "false", "false", "", False), ("false", "false", "false", "", False)):
            with self.subTest(app=app, key=key, tdir=tdir, packages=packages):
                out = subprocess.run(["bash", "-c", scope], capture_output=True, text=True,
                                     env=dict(os.environ, SIBLING_PACKAGES=packages, SIBLING_HAS_APP_ID=app,
                                              SIBLING_HAS_KEY=key, SIBLING_HAS_DIR=tdir))
                self.assertEqual(out.returncode == 0, ok, out.stdout + out.stderr)

    def test_token_dir_mode_mints_nothing_and_does_not_wait_again(self):
        text = (HERE / "action.yml").read_text()
        steps = {s.split("\n", 1)[0]: s for s in text.split("    - id: ")[1:]}
        for name in ("mint", "mint_packages", "ready"):
            self.assertIn("inputs.token-dir == ''", steps[name].split("\n", 2)[1], name)
        self.assertIn('--token-dir "$SIBLING_TOKEN_DIR"', steps["read"])
        self.assertNotIn("if:", steps["scope"].split("run: |", 1)[0])  # the source check always runs


class ActionShape(unittest.TestCase):
    def test_the_action_mints_then_probes_then_clones(self):
        text = (HERE / "action.yml").read_text()
        mint, probe, read = (text.index(m) for m in ("actions/create-github-app-token@", "read.py\" ready", "read.py\" clone"))
        self.assertLess(mint, probe)
        self.assertLess(probe, read)
        self.assertRegex(text, r"actions/create-github-app-token@[0-9a-f]{40} ")
        self.assertEqual(text.count("SIBLING_TOKEN: ${{ steps.mint.outputs.token || steps.mint_packages.outputs.token }}"), 2)

    def test_every_step_that_holds_the_token_runs_the_reset_shell_and_an_isolated_python(self):
        text = (HERE / "action.yml").read_text()
        steps = text.split("    - id: ")
        holders = [step for step in steps if "SIBLING_TOKEN:" in step]
        self.assertEqual(sorted(step.split("\n", 1)[0] for step in holders), ["read", "ready"])
        for step in holders:
            shell = next(line.strip() for line in step.splitlines() if line.strip().startswith("shell: "))
            self.assertRegex(shell, r"^shell: /usr/bin/env (-u \w+ )*PATH=/usr/bin:/bin /bin/bash --noprofile --norc ")
            for name in ("BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"):
                self.assertIn(f"-u {name} ", shell)
            self.assertIn('python3 -I -S "$GITHUB_ACTION_PATH/read.py"', step)
            self.assertNotIn("python3 -I \"", step)

    def test_the_token_is_minted_read_only_and_packages_read_only_when_asked(self):
        # Root's R4 of #37: least privilege. Each mint carries exactly its permissions; nothing else is requested.
        text = (HERE / "action.yml").read_text()
        steps = text.split("    - id: ")
        mint = next(step for step in steps if step.startswith("mint\n"))
        packages = next(step for step in steps if step.startswith("mint_packages\n"))
        perms = lambda step: sorted(line.strip() for line in step.splitlines() if line.strip().startswith("permission-"))
        self.assertEqual(perms(mint), ["permission-contents: read"])
        self.assertEqual(perms(packages), ["permission-contents: read", "permission-packages: read"])
        self.assertIn("if: ${{ inputs.token-dir == '' && inputs.packages == '' }}", mint)
        self.assertIn("if: ${{ inputs.token-dir == '' && inputs.packages == 'read' }}", packages)
        self.assertEqual(sum(len(perms(step)) for step in steps), 3, "no other step requests a permission")
        scope = next(step for step in steps if step.startswith("scope\n")).split("run: |\n", 1)[1]
        script = "\n".join(line[8:] for line in scope.splitlines() if line.startswith("        "))
        for value, ok in (("", True), ("read", True), ("write", False), ("admin", False), ("read,write", False)):
            with self.subTest(value=value):
                out = subprocess.run(["bash", "-c", script], env=dict(os.environ, SIBLING_PACKAGES=value, SIBLING_HAS_APP_ID="true",
                                                                       SIBLING_HAS_KEY="true", SIBLING_HAS_DIR="false"),
                                     capture_output=True, text=True)
                self.assertEqual(out.returncode == 0, ok, out.stdout + out.stderr)


if __name__ == "__main__":
    unittest.main()
