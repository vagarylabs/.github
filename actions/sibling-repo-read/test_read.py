"""Tests for read.py. Stdlib only, light: a stub API on localhost, and local bare repositories as the clone remote.
Run: python3 -m unittest discover -s actions/sibling-repo-read -p 'test_*.py' -v
"""
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest

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


class Clone(unittest.TestCase):
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

    def test_a_missing_repository_fails_loudly(self):
        out, _ = self.clone("--checkout", f"vagary-core:{self.out / 'c'}", "--bare", f"absent:{self.out / 'a.git'}",
                            repos="vagary-core,absent")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("git clone failed", out.stderr)


class ActionShape(unittest.TestCase):
    def test_the_action_mints_then_probes_then_clones(self):
        text = (HERE / "action.yml").read_text()
        mint, probe, read = (text.index(m) for m in ("actions/create-github-app-token@", "read.py\" ready", "read.py\" clone"))
        self.assertLess(mint, probe)
        self.assertLess(probe, read)
        self.assertRegex(text, r"actions/create-github-app-token@[0-9a-f]{40} ")
        self.assertIn("SIBLING_TOKEN: ${{ steps.mint.outputs.token }}", text)
        self.assertNotIn("${{ steps.mint.outputs.token }}\"", text.split("run:", 1)[1].split("env:", 1)[0])


if __name__ == "__main__":
    unittest.main()
