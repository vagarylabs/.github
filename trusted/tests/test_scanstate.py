"""Tests for trusted/scanstate.py (ledger C9 scan states) and the workflows that inline it.

Plain unittest, stdlib only. Credential-shaped strings are BUILT AT RUNTIME, never committed, so this file
cannot trip a secret scan or push protection. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
The real-binary trufflehog outage test runs only when TRUFFLEHOG_BIN names a trufflehog executable
(ci.yml fetches the pinned one); without it the test is skipped, and says so.
"""
import contextlib
import datetime
import io
import json
import os
import pathlib
import random
import re
import string
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import scanstate as ss  # noqa: E402

WF = ROOT / ".github" / "workflows"
TODAY = datetime.date(2026, 10, 15)


def fake_aws_pair(seed):
    r = random.Random(seed)
    kid = "AK" + "IA" + "".join(r.choice(string.ascii_uppercase + "234567") for _ in range(16))
    sec = "".join(r.choice(string.ascii_letters + string.digits + "/+") for _ in range(40))
    return kid, sec


class MergeAndGateTests(unittest.TestCase):
    def test_no_record_is_unavailable(self):
        state, reason, _ = ss.merge([], [])
        self.assertEqual(state, "UNAVAILABLE")
        self.assertIn("never reported", reason)

    def test_missing_expected_check_is_unavailable(self):
        recs = [ss.make_check("markers", "PASSED", "ok"), ss.make_check("exceptions", "PASSED", "ok")]
        state, reason, checks = ss.merge(recs, ["markers", "exceptions", "scan"])
        self.assertEqual(state, "UNAVAILABLE")
        self.assertIn("'scan'", reason)
        self.assertEqual(len(checks), 3)

    def test_worst_state_wins(self):
        for states, want in ((["PASSED", "NOT_APPLICABLE"], "PASSED"),
                             (["PASSED", "UNAVAILABLE"], "UNAVAILABLE"),
                             (["UNAVAILABLE", "FINDINGS"], "FINDINGS"),
                             (["NOT_APPLICABLE"], "NOT_APPLICABLE"),
                             (["AUTHORIZED_EXCEPTION", "PASSED"], "AUTHORIZED_EXCEPTION")):
            with self.subTest(states=states):
                recs = [ss.make_check("c%d" % i, s, s) for i, s in enumerate(states)]
                self.assertEqual(ss.merge(recs, [])[0], want)

    def test_blocking_gate(self):
        for state in ss.STATES:
            with self.subTest(state=state):
                want = 0 if state in ("PASSED", "NOT_APPLICABLE", "AUTHORIZED_EXCEPTION") else 1
                self.assertEqual(ss.gate_exit("gitleaks", state), want)
                self.assertEqual(ss.gate_exit("trufflehog", state), want)

    def test_report_only_never_fails_but_flip_blocks(self):
        self.assertTrue(ss.REPORT_ONLY["semgrep"])
        self.assertTrue(ss.REPORT_ONLY["sca"])
        self.assertFalse(ss.REPORT_ONLY["gitleaks"])
        self.assertFalse(ss.REPORT_ONLY["trufflehog"])
        for state in ss.STATES:
            self.assertEqual(ss.gate_exit("semgrep", state), 0)
        self.assertEqual(ss.gate_exit("semgrep", "UNAVAILABLE", report_only=False), 1)
        self.assertEqual(ss.gate_exit("sca", "FINDINGS", report_only=False), 1)
        self.assertEqual(ss.gate_exit("sca", "PASSED", report_only=False), 0)

    def test_cli_gate_writes_result_and_exits(self):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GITHUB_STEP_SUMMARY=os.path.join(d, "summary.md"),
                       GITHUB_OUTPUT=os.path.join(d, "out"), SCAN_HEAD="h" * 40)
            run = lambda *a: subprocess.run([sys.executable, "-I", str(ROOT / "trusted" / "scanstate.py"),
                                             "--records", d] + list(a), env=env, capture_output=True, text=True)
            self.assertEqual(run("record", "--scanner", "gitleaks", "--check", "scan", "--state", "PASSED",
                                 "--reason", "ok").returncode, 0)
            g = run("gate", "--scanner", "gitleaks", "--expect", "markers,scan")
            self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
            doc = json.loads(pathlib.Path(d, "scan-result-gitleaks.json").read_text())
            self.assertEqual(doc["schema"], "vagarylabs.scan-result/v1")
            self.assertEqual(doc["state"], "UNAVAILABLE")
            self.assertEqual(doc["gate"], "fail")
            self.assertEqual(doc["head"], "h" * 40)
            self.assertIn("state=UNAVAILABLE", pathlib.Path(d, "out").read_text())
            self.assertIn("**UNAVAILABLE**", pathlib.Path(d, "summary.md").read_text())
            self.assertIn("::error title=gitleaks UNAVAILABLE", g.stdout)
            # report-only: same state, exit 0, notice not error
            self.assertEqual(run("gate", "--scanner", "semgrep", "--expect", "scan").returncode, 0)
            doc = json.loads(pathlib.Path(d, "scan-result-semgrep.json").read_text())
            self.assertEqual((doc["state"], doc["mode"], doc["gate"]), ("UNAVAILABLE", "report-only", "report-only"))


class GitleaksTests(unittest.TestCase):
    def test_states(self):
        f = [{"RuleID": "github-pat", "File": "a.txt", "StartLine": 3, "Commit": "c" * 40, "Secret": "REDACTED"}]
        self.assertEqual(ss.classify_gitleaks(0, "[]", 3, "a..b")["state"], "PASSED")
        r = ss.classify_gitleaks(42, json.dumps(f), 3, "a..b")
        self.assertEqual(r["state"], "FINDINGS")
        self.assertEqual(r["items"][0], {"rule": "github-pat", "path": "a.txt", "line": 3, "commit": "c" * 12})
        self.assertNotIn("Secret", json.dumps(r))
        for rc, text, commits, why in ((1, "[]", 3, "exited 1"), (0, None, 3, "missing"), (0, "{", 3, "missing"),
                                       (0, "[]", 0, "empty scan range"), (42, "[]", 3, "lists none"),
                                       (2, "[]", 3, "exited 2")):
            with self.subTest(rc=rc, text=text, commits=commits):
                r = ss.classify_gitleaks(rc, text, commits, "a..b")
                self.assertEqual(r["state"], "UNAVAILABLE")
                self.assertIn(why, r["reason"])


class TrufflehogTests(unittest.TestCase):
    def line(self, verified, err=None, det="AWS"):
        d = {"DetectorName": det, "Verified": verified, "Raw": "SHOULD-NOT-LEAK",
             "SourceMetadata": {"Data": {"Git": {"file": "creds.txt", "line": 1, "commit": "d" * 40}}}}
        if err is not None:
            d["VerificationError"] = err
        return json.dumps(d)

    def test_verifier_outage_is_unavailable_not_passed(self):
        out = self.line(False, "Post \"https://sts.amazonaws.com\": dial tcp 127.0.0.1:9: connect: connection refused")
        r = ss.classify_trufflehog(0, out + "\n", 2, "m..HEAD")
        self.assertEqual(r["state"], "UNAVAILABLE")
        self.assertIn("cause connection-refused", r["reason"])
        self.assertIn("not cleared", r["reason"])
        self.assertNotIn("SHOULD-NOT-LEAK", json.dumps(r))
        self.assertNotIn("sts.amazonaws.com", json.dumps(r))

    def test_timeout_and_dns_causes(self):
        for err, cause in (("context deadline exceeded", "timeout"), ("dial tcp: lookup x: no such host", "dns"),
                           ("x509: certificate signed by unknown authority", "tls"), ("weird", "other")):
            with self.subTest(err=err):
                self.assertIn(cause, ss.classify_trufflehog(0, self.line(False, err), 1, "s")["reason"])

    def test_verified_is_findings_even_with_outage(self):
        out = "\n".join([self.line(True), self.line(False, "connection refused")])
        r = ss.classify_trufflehog(0, out, 1, "s")
        self.assertEqual(r["state"], "FINDINGS")
        self.assertEqual(r["counts"], {"verified": 1, "verification_errors": 1})

    def test_clean_and_errors(self):
        self.assertEqual(ss.classify_trufflehog(0, "", 4, "s")["state"], "PASSED")
        self.assertEqual(ss.classify_trufflehog(0, self.line(False), 4, "s")["state"], "PASSED")  # unverified, no error
        for rc, out, commits in ((1, "", 4), (183, "", 4), (0, "not json", 4), (0, "", 0), (0, None, 4)):
            with self.subTest(rc=rc, out=out, commits=commits):
                self.assertEqual(ss.classify_trufflehog(rc, out, commits, "s")["state"], "UNAVAILABLE")

    @unittest.skipUnless(os.environ.get("TRUFFLEHOG_BIN"), "TRUFFLEHOG_BIN not set (ci.yml sets it to the pinned binary)")
    def test_real_binary_verifier_outage(self):
        """The pinned trufflehog, a detector-shaped AWS pair built at runtime, and a dead proxy: the old
        invocation (--only-verified --fail) exits 0, i.e. reads the outage as a pass; the new one yields an
        unknown result that scanstate classifies UNAVAILABLE."""
        th = os.environ["TRUFFLEHOG_BIN"]
        with tempfile.TemporaryDirectory() as d:
            g = lambda *a: subprocess.run(("git",) + a, cwd=d, check=True, capture_output=True, text=True).stdout.strip()
            g("init", "-q", "-b", "main")
            g("config", "user.email", "t@example.invalid")
            g("config", "user.name", "t")
            pathlib.Path(d, "README").write_text("base\n")
            g("add", "-A")
            g("commit", "-qm", "base")
            base = g("rev-parse", "HEAD")
            kid, sec = fake_aws_pair(7)
            pathlib.Path(d, "creds.txt").write_text("aws_access_key_id = %s\naws_secret_access_key = %s\n" % (kid, sec))
            g("add", "-A")
            g("commit", "-qm", "head")
            env = dict(os.environ, HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9",
                       https_proxy="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9", NO_PROXY="", no_proxy="")
            common = [th, "git", "file://" + d, "--branch", "HEAD", "--since-commit", base, "--no-update"]
            old = subprocess.run(common + ["--only-verified", "--fail"], env=env, capture_output=True, text=True)
            self.assertEqual(old.returncode, 0, "the old invocation must exhibit the silent pass this test guards")
            new = subprocess.run(common + ["--results=verified,unknown", "--json", "--fail-on-scan-errors"],
                                 env=env, capture_output=True, text=True)
            r = ss.classify_trufflehog(new.returncode, new.stdout, 1, base[:12] + "..HEAD")
            self.assertEqual(r["state"], "UNAVAILABLE", r)
            self.assertEqual(r["counts"]["verification_errors"], 1, r)
            self.assertNotIn(sec, json.dumps(r))


class SemgrepTests(unittest.TestCase):
    def doc(self, *results, errors=()):
        return json.dumps({"results": [{"check_id": c, "path": p, "start": {"line": l}, "end": {"line": l},
                                        "extra": {"severity": s, "lines": "requires login"}}
                                       for c, p, l, s in results], "errors": list(errors)})

    def test_new_finding_only(self):
        with tempfile.TemporaryDirectory() as h, tempfile.TemporaryDirectory() as b:
            pathlib.Path(h, "a.py").write_text("x = 1\neval(user)\nexec(user)\n")
            pathlib.Path(b, "a.py").write_text("eval(user)\n")
            head = self.doc(("r.eval", "a.py", 2, "ERROR"), ("r.exec", "a.py", 3, "WARNING"), ("r.info", "a.py", 1, "INFO"))
            base = self.doc(("r.eval", "a.py", 1, "ERROR"))
            r = ss.classify_semgrep(0, head, base, 10, h, b, "m..h")
            self.assertEqual(r["state"], "FINDINGS")
            self.assertEqual([i["rule"] for i in r["items"]], ["r.exec"])  # eval pre-exists (moved line), info below threshold
            self.assertEqual(r["counts"]["new_findings"], 1)
            r = ss.classify_semgrep(0, self.doc(("r.eval", "a.py", 2, "ERROR")), base, 10, h, b, "m..h")
            self.assertEqual(r["state"], "PASSED")

    def test_unavailable(self):
        ok = self.doc()
        for rc, head, rules, why in ((0, ok, 0, "no semgrep rules"), (2, ok, 5, "exited 2"), (0, "", 5, "unreadable"),
                                     (0, self.doc(errors=[{"type": "Syntax error", "level": "warn"}]), 5, "1 error")):
            with self.subTest(why=why):
                r = ss.classify_semgrep(rc, head, None, rules, ".", "", "s")
                self.assertEqual(r["state"], "UNAVAILABLE")
                self.assertIn(why, r["reason"])
        self.assertEqual(ss.classify_semgrep(0, ok, None, 5, ".", "", "s")["state"], "PASSED")


class ScaTests(unittest.TestCase):
    def doc(self, root, *vulns):
        res = {}
        for path, name, version, vid in vulns:
            res.setdefault(path, []).append({"package": {"name": name, "version": version, "ecosystem": "PyPI"},
                                             "vulnerabilities": [{"id": vid}],
                                             "groups": [{"ids": [vid], "max_severity": "7.5"}]})
        return json.dumps({"results": [{"source": {"path": root + "/" + p, "type": "lockfile"}, "packages": pk}
                                       for p, pk in res.items()]})

    def test_introduced_only(self):
        head = self.doc("/t/sca/head", ("requirements.txt", "requests", "2.19.0", "PYSEC-1"),
                        ("requirements.txt", "idna", "2.7", "PYSEC-2"))
        base = self.doc("/t/sca/base", ("requirements.txt", "requests", "2.18.0", "PYSEC-1"))
        r = ss.classify_sca(1, head, 1, base, "/t/sca/head", "/t/sca/base", "m..h")
        self.assertEqual(r["state"], "FINDINGS")
        self.assertEqual([(i["rule"], i["path"]) for i in r["items"]], [("PYSEC-2", "requirements.txt")])
        self.assertEqual(ss.classify_sca(1, base.replace("/t/sca/base", "/t/sca/head"), 1, base,
                                         "/t/sca/head", "/t/sca/base", "s")["state"], "PASSED")
        self.assertEqual(ss.classify_sca(None, None, 1, base, "", "/t/sca/base", "s")["state"], "PASSED")  # lockfile removed
        self.assertEqual(ss.classify_sca(128, "", None, None, "", "", "s")["state"], "PASSED")  # empty lockfile

    def test_unavailable(self):
        clean = json.dumps({"results": []})
        for rc, err, why in ((129, "", "advisory API unreachable"), (130, "", "invalid config"), (127, "", "scanner error"),
                             (124, "", "timed out"), (1, "Error during extraction: x", "partly covered")):
            with self.subTest(rc=rc):
                r = ss.classify_sca(rc, clean, None, None, "", "", "s", head_err=err)
                self.assertEqual(r["state"], "UNAVAILABLE")
                self.assertIn(why, r["reason"])
        self.assertEqual(ss.classify_sca(0, "", None, None, "", "", "s")["state"], "UNAVAILABLE")  # rc 0, no JSON

    def test_lockfile_predicate(self):
        for p in ("pnpm-lock.yaml", "server/package-lock.json", "requirements.txt", "py/requirements-dev.txt",
                  "go.mod", "x/Cargo.lock", "uv.lock"):
            self.assertTrue(ss.is_lockfile(p), p)
        for p in ("package.json", "README.md", "src/lock.ts", "requirements.md", "go.sum.bak"):
            self.assertFalse(ss.is_lockfile(p), p)


class TrivyTests(unittest.TestCase):
    def test_distinct_exit_code(self):
        self.assertEqual(ss.classify_trivy(0, "img")["state"], "PASSED")
        self.assertEqual(ss.classify_trivy(ss.TRIVY_FINDINGS_RC, "img")["state"], "FINDINGS")
        self.assertEqual(ss.classify_trivy(1, "img")["state"], "UNAVAILABLE")  # trivy's own error exit


class ExceptionTests(unittest.TestCase):
    MIG = 'approver = "cc:root (migration 2026-10-15)"\n'

    def test_valid_forms(self):
        toml = ("[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = \"x\"\n" + self.MIG +
                "expires = 2027-01-13\npaths = ['''a''']\n\n[[rules]]\nid = \"jwt\"\n  [[rules.allowlists]]\n  " +
                self.MIG + "  expires = \"2027-01-13\"\n  regexes = [\n    '''[a-z]''',\n  ]\n"
                "[[rules]]\nid = \"k\"\n  [rules.allowlist]\n  " + self.MIG + "  expires = 2027-01-13 # UTC\n")
        n, problems = ss.check_gitleaks_toml(toml, TODAY)
        self.assertEqual((n, problems), (3, []))
        ign = '# why\n# exception: approver="cc:root (migration 2026-10-15)" expires=2027-01-13\nabc:f:rule:1\n'
        self.assertEqual(ss.check_gitleaksignore(ign, TODAY), (1, []))
        r = ss.classify_exceptions(toml, ign, TODAY)
        self.assertEqual(r["state"], "PASSED")
        self.assertEqual(r["counts"], {"allowlist_tables": 3, "ignore_fingerprints": 1, "invalid": 0})

    def test_expired_missing_and_too_long_fail(self):
        cases = {
            "no approver": "[[allowlists]]\nexpires = 2027-01-13\n",
            "no expires": "[[allowlists]]\n" + self.MIG,
            "EXPIRED": "[[allowlists]]\n" + self.MIG + "expires = 2026-10-14\n",
            "more than 90 days": "[[allowlists]]\n" + self.MIG + "expires = 2027-01-14\n",
            "not a YYYY-MM-DD": "[[allowlists]]\n" + self.MIG + "expires = soon\n",
        }
        for why, toml in cases.items():
            with self.subTest(why=why):
                r = ss.classify_exceptions(toml, "", TODAY)
                self.assertEqual(r["state"], "FINDINGS")
                self.assertIn(why, r["reason"])
        # expiry is inclusive: valid ON the date, expired the day after
        self.assertEqual(ss.check_gitleaks_toml("[[allowlists]]\n" + self.MIG + "expires = 2026-10-15\n", TODAY)[1], [])
        # a key in the NEXT table does not cover this one
        _, p = ss.check_gitleaks_toml("[[allowlists]]\npaths=['x']\n[[rules]]\n" + self.MIG + "expires = 2027-01-13\n", TODAY)
        self.assertEqual(len(p), 2)

    def test_gitleaksignore_needs_metadata_in_paragraph(self):
        for text in ("abc:f:r:1\n", '# exception: approver="x" expires=2027-01-13\n\nabc:f:r:1\n',
                     '# exception: approver="x" expires=2026-01-01\nabc:f:r:1\n', "# exception: approver=x\nabc:f:r:1\n"):
            with self.subTest(text=text):
                self.assertEqual(ss.classify_exceptions("", text, TODAY)["state"], "FINDINGS")
        self.assertEqual(ss.classify_exceptions("", "", TODAY)["state"], "PASSED")


class ScannerCoverageTests(unittest.TestCase):
    """Positive control: on a non-empty range the scanner must REPORT that it read something."""

    GL = "\x1b[90m3:05AM\x1b[0m INF \x1b[1m%d commits scanned.\x1b[0m\n"
    TH = '{"level":"info-0","msg":"finished scanning","chunks":%d,"bytes":%d,"verified_secrets":0}\n'

    def test_gitleaks_count_parsed_through_ansi(self):
        self.assertEqual(ss.gitleaks_commits_scanned(self.GL % 2), 2)
        self.assertIsNone(ss.gitleaks_commits_scanned("no such line\n"))

    def test_gitleaks_zero_scanned_is_unavailable(self):
        r = ss.classify_gitleaks(0, "[]", 3, "a..b", log_text=self.GL % 0)
        self.assertEqual(r["state"], "UNAVAILABLE")
        self.assertIn("0 commits scanned", r["reason"])

    def test_gitleaks_missing_count_is_unavailable(self):
        self.assertEqual(ss.classify_gitleaks(0, "[]", 3, "a..b", log_text="")["state"], "UNAVAILABLE")

    def test_gitleaks_scanned_passes_and_without_log_unchanged(self):
        self.assertEqual(ss.classify_gitleaks(0, "[]", 3, "a..b", log_text=self.GL % 2)["state"], "PASSED")
        self.assertEqual(ss.classify_gitleaks(0, "[]", 3, "a..b")["state"], "PASSED")

    def test_trufflehog_must_finish(self):
        r = ss.classify_trufflehog(0, "", 3, "a..b", log_text='{"msg":"running source"}\n', added=5)
        self.assertEqual(r["state"], "UNAVAILABLE")
        self.assertIn("finished scanning", r["reason"])

    def test_trufflehog_zero_chunks_on_added_lines_is_unavailable(self):
        r = ss.classify_trufflehog(0, "", 3, "a..b", log_text=self.TH % (0, 0), added=5)
        self.assertEqual(r["state"], "UNAVAILABLE")

    def test_trufflehog_zero_chunks_on_deletion_only_range_passes(self):
        self.assertEqual(ss.classify_trufflehog(0, "", 1, "a..b", log_text=self.TH % (0, 0), added=0)["state"],
                         "PASSED")

    def test_trufflehog_chunks_pass(self):
        self.assertEqual(ss.classify_trufflehog(0, "", 3, "a..b", log_text=self.TH % (5, 184), added=3)["state"],
                         "PASSED")

    def test_cli_missing_log_file_is_unavailable(self):
        with tempfile.TemporaryDirectory() as t:
            env = dict(os.environ, RUNNER_TEMP=t)
            for scanner, extra in (("gitleaks", ["--report", os.path.join(t, "r.json")]),
                                   ("trufflehog", ["--results", os.path.join(t, "r.jsonl"), "--added", "3"])):
                pathlib.Path(extra[1]).write_text("[]" if scanner == "gitleaks" else "")
                subprocess.run([sys.executable, "-I", str(ROOT / "trusted" / "scanstate.py"), scanner, "--rc", "0",
                                "--commits", "3", "--scope", "a..b", "--log", os.path.join(t, "absent.log")] + extra,
                               env=env, check=True, capture_output=True, text=True)
                g = subprocess.run([sys.executable, "-I", str(ROOT / "trusted" / "scanstate.py"), "gate",
                                    "--scanner", scanner, "--expect", "scan", "--out", t],
                                   env=env, capture_output=True, text=True)
                self.assertNotEqual(g.returncode, 0, (scanner, g.stdout, g.stderr))


class FullHistoryReportOnlyTests(unittest.TestCase):
    """Decision A (2026-10-17): the full-history scan reports findings but does not block until switched."""

    def gate(self, t, *extra):
        env = dict(os.environ, RUNNER_TEMP=t, GITHUB_STEP_SUMMARY=os.path.join(t, "summary.md"))
        rec = ss.make_check("scan", "FINDINGS", "1 gitleaks finding(s) in HEAD", {"findings": 1},
                            [{"rule": "generic-api-key", "path": "a.py", "line": 3, "commit": "abc"}])
        ss.append(os.path.join(t, "scan-records"), "gitleaks", rec)
        r = subprocess.run([sys.executable, "-I", str(ROOT / "trusted" / "scanstate.py"), "gate", "--scanner",
                            "gitleaks", "--expect", "scan"] + list(extra), env=env, capture_output=True, text=True)
        doc = json.loads(pathlib.Path(t, "scan-records", "scan-result-gitleaks.json").read_text())
        return r, doc, pathlib.Path(t, "summary.md").read_text()

    def test_report_only_exits_zero_but_surfaces_findings(self):
        with tempfile.TemporaryDirectory() as t:
            os.makedirs(os.path.join(t, "scan-records"))
            r, doc, summary = self.gate(t, "--report-only")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((doc["state"], doc["mode"], doc["gate"]), ("FINDINGS", "report-only", "report-only"))
            self.assertIn("a.py", summary)
            self.assertIn("::notice", r.stdout)

    def test_without_switch_findings_block(self):
        with tempfile.TemporaryDirectory() as t:
            os.makedirs(os.path.join(t, "scan-records"))
            r, doc, _ = self.gate(t)
            self.assertEqual(r.returncode, 1)
            self.assertEqual((doc["mode"], doc["gate"]), ("blocking", "fail"))

    def test_reusable_report_only_is_bound_to_full_mode_and_the_switch(self):
        t = (WF / "secret-scan.yml").read_text()
        self.assertIn("full-history-blocking:", t)
        self.assertRegex(t, r"full-history-blocking:\n(?:.*\n)*?\s+default: false")
        for sc in ("gitleaks", "trufflehog"):
            body = step_block("secret-scan", "Scan state (%s)" % sc)
            self.assertIn('if [ "$MODE" = full ] && [ "$FULL_BLOCKING" != true ]; then', body)
            self.assertIn("name: scan-result-%s" % sc, t)
        # range scans never get the flag: the only --report-only is inside the full-mode branch
        self.assertEqual(t.count("ro=(--report-only)"), 2)


def run_block(fragment):
    """The `run: |` body of a template fragment, de-indented: the exact bash the workflow executes."""
    text = (ROOT / "trusted" / "templates" / fragment).read_text()
    m = re.search(r"\n( +)run: \|\n(.*)", text, re.S)
    indent = len(m.group(1)) + 2
    return "\n".join(l[indent:] for l in m.group(2).split("\n")) + "\n"


class EventRangeTests(unittest.TestCase):
    """G3: no bindable range (new branch, force-push, unreadable before, schedule) means a FULL-history scan."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        up, cls.d = os.path.join(cls.tmp.name, "up"), os.path.join(cls.tmp.name, "clone")
        g = lambda cwd, *a: subprocess.run(("git",) + a, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
        os.makedirs(up)
        g(up, "init", "-q", "-b", "main")
        g(up, "config", "user.email", "t@example.invalid")
        g(up, "config", "user.name", "t")
        for i in range(2):
            pathlib.Path(up, "m%d" % i).write_text("m\n")
            g(up, "add", "-A")
            g(up, "commit", "-qm", "main %d" % i)
        cls.main = g(up, "rev-parse", "HEAD")
        g(up, "checkout", "-qb", "feat")
        for i in range(3):
            pathlib.Path(up, "f%d" % i).write_text("f\n")
            g(up, "add", "-A")
            g(up, "commit", "-qm", "feat %d" % i)
        cls.old = g(up, "rev-parse", "HEAD")
        g(up, "reset", "-q", "--hard", "HEAD~2")
        pathlib.Path(up, "g").write_text("g\n")
        g(up, "add", "-A")
        g(up, "commit", "-qm", "rewritten")
        cls.after = g(up, "rev-parse", "HEAD")  # force-pushed head: 2 commits above main, old head unreachable
        g(up, "checkout", "-q", "main")
        subprocess.run(["git", "clone", "-q", "--no-local", up, cls.d], check=True, capture_output=True)
        cls.g = g

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def resolve(self, event, before="", after="", pr_base="", pr_head="", rc=0):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "out")
            pathlib.Path(out).write_text("")
            env = dict(os.environ, EVENT=event, PR_BASE=pr_base, PR_HEAD=pr_head, PUSH_BEFORE=before,
                       PUSH_AFTER=after, GITHUB_OUTPUT=out)
            r = subprocess.run(["bash", "-c", run_block("_event_range.yml.in")], cwd=self.d, env=env,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, rc, r.stderr)
            return dict(l.split("=", 1) for l in pathlib.Path(out).read_text().split("\n") if l), r.stdout

    def full_count(self, sha):
        return subprocess.run(["git", "rev-list", "--count", sha], cwd=self.d, check=True, capture_output=True,
                              text=True).stdout.strip()

    def test_new_branch_scans_full_history(self):
        o, log = self.resolve("push", before="0" * 40, after=self.after)
        self.assertEqual((o["mode"], o["lower"], o["head"]), ("full", "", self.after), log)
        self.assertEqual(o["commits"], self.full_count(self.after))
        self.assertEqual(o["commits"], "4")  # 2 on main + 2 on the rewritten branch: never the pushed commit alone

    def test_force_push_scans_full_history(self):
        o, log = self.resolve("push", before=self.old, after=self.after)
        self.assertEqual((o["mode"], o["lower"], o["commits"]), ("full", "", self.full_count(self.after)), log)

    def test_unreadable_before_scans_full_history(self):
        o, log = self.resolve("push", before="f" * 40, after=self.after)
        self.assertEqual((o["mode"], o["commits"]), ("full", self.full_count(self.after)), log)

    def test_fast_forward_push_scans_before_after(self):
        o, _ = self.resolve("push", before=self.main, after=self.after)
        self.assertEqual((o["mode"], o["lower"], o["commits"]), ("range", self.main, "2"))

    def test_pull_request(self):
        o, _ = self.resolve("pull_request", pr_base=self.main, pr_head=self.after)
        self.assertEqual((o["mode"], o["lower"], o["head"], o["commits"]), ("range", self.main, self.after, "2"))
        self.assertNotIn("since", o)  # both engines scan merge-base..head of the PR head itself

    def test_pull_request_without_merge_base_is_empty_and_unavailable(self):
        o, _ = self.resolve("pull_request", pr_base="f" * 40, pr_head=self.after)
        self.assertEqual((o["mode"], o["lower"], o["commits"]), ("range", "", "0"))
        self.assertEqual(ss.classify_gitleaks(0, "[]", int(o["commits"]), "unresolved")["state"], "UNAVAILABLE")
        self.assertEqual(ss.classify_trufflehog(0, "", int(o["commits"]), "unresolved")["state"], "UNAVAILABLE")

    def test_schedule_and_dispatch_scan_full_history(self):
        for ev in ("schedule", "workflow_dispatch"):
            with self.subTest(event=ev):
                o, _ = self.resolve(ev, after=self.main)
                self.assertEqual((o["mode"], o["lower"], o["commits"]), ("full", "", self.full_count(self.main)))
                self.assertGreater(int(o["commits"]), 0)

    def test_default_branch_without_usable_before_scans_full_history(self):
        o, _ = self.resolve("push", before="0" * 40, after=self.main)
        self.assertEqual((o["mode"], o["commits"]), ("full", "2"))

    def test_unsupported_event_fails(self):
        self.resolve("release", after=self.main, rc=1)


def step_block(workflow, name):
    """The run body of the step called `name` in a rendered workflow, de-indented."""
    t = (WF / (workflow + ".yml")).read_text()
    i = t.index("- name: " + name)
    m = re.compile(r"\n( +)run: \|\n").search(t, i)
    ind, out = len(m.group(1)) + 2, []
    for line in t[m.end():].split("\n"):
        if line.strip() and not line.startswith(" " * ind):
            break
        out.append(line[ind:])
    return "\n".join(out) + "\n"


class AllowlistSideTests(unittest.TestCase):
    """The register is judged at BASE unless the PR edits it: a stale PR follows main, a renewal passes."""

    OLD = "[[allowlists]]\npaths = ['x']\n"
    NEW = "[[allowlists]]\napprover = \"cc:root (migration 2026-10-15)\"\nexpires = %s\npaths = ['x']\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = os.path.join(self.tmp.name, "repo")
        self.rt = os.path.join(self.tmp.name, "rt")
        os.makedirs(os.path.join(self.rt, "trusted"))
        pathlib.Path(self.rt, "trusted", "scanstate.py").write_text((ROOT / "trusted" / "scanstate.py").read_text())
        os.makedirs(self.d)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.mb = self.commit(".gitleaks.toml", self.OLD)
        today = datetime.datetime.now(datetime.timezone.utc).date()
        self.expires = (today + datetime.timedelta(days=30)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *a):
        return subprocess.run(("git",) + a, cwd=self.d, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, path, text):
        pathlib.Path(self.d, path).write_text(text)
        self.git("add", "-A")
        self.git("commit", "-qm", path)
        return self.git("rev-parse", "HEAD")

    def judge(self, base, head):
        rec = os.path.join(self.rt, "rec-" + head[:8])
        env = dict(os.environ, RUNNER_TEMP=self.rt, BASE=base, MB=self.mb, HEAD_SHA=head, SCAN_RECORDS=rec)
        r = subprocess.run(["bash", "-c", step_block("trusted-secret-scan", "Allowlist entries")], cwd=self.d,
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return ss.load(rec, "gitleaks")[-1], r.stdout

    def test_stale_pr_follows_migrated_base(self):
        head = self.commit("feature.txt", "work\n")  # the PR branched before the migration
        self.git("checkout", "-q", "-b", "later-main", self.mb)
        base = self.commit(".gitleaks.toml", self.NEW % self.expires)  # main migrated afterwards
        rec, out = self.judge(base, head)
        self.assertEqual(rec["state"], "PASSED", out)
        self.assertIn("BASE (this PR does not edit them)", out)

    def test_unmigrated_base_fails_untouched_pr(self):
        head = self.commit("feature.txt", "work\n")
        self.assertEqual(self.judge(self.mb, head)[0]["state"], "FINDINGS")

    def test_pr_that_renews_passes_and_bad_edit_fails(self):
        renew = self.commit(".gitleaks.toml", self.NEW % self.expires)
        rec, out = self.judge(self.mb, renew)
        self.assertEqual(rec["state"], "PASSED", out)
        self.assertIn("HEAD (this PR edits them)", out)
        bad = self.commit(".gitleaks.toml", self.NEW % "2020-01-01")
        self.assertEqual(self.judge(self.mb, bad)[0]["state"], "FINDINGS")


class WorkflowInlineTests(unittest.TestCase):
    def test_scanstate_inlined_byte_identical(self):
        src = (ROOT / "trusted" / "scanstate.py").read_text()
        for name in ("trusted-secret-scan", "trusted-code-scan", "secret-scan"):
            text = (WF / (name + ".yml")).read_text()
            bodies = re.findall(r"\n( *)cat > \"\$d/scanstate.py\" <<'TRUSTED_SCANSTATE_PY'\n(.*?)\n\1TRUSTED_SCANSTATE_PY\n",
                                text, re.S)
            self.assertTrue(bodies, name)
            for indent, body in bodies:
                body = "\n".join(l[len(indent):] if l.startswith(indent) else l for l in body.split("\n"))
                self.assertEqual(body + "\n", src, name)

    def test_every_scanner_job_gates_and_never_swallows(self):
        for name, gates in (("trusted-secret-scan", {"gitleaks": "markers,exceptions,scan", "trufflehog": "scan"}),
                            ("trusted-code-scan", {"semgrep": "scan", "sca": "scan"}),
                            ("secret-scan", {"gitleaks": "scan", "trufflehog": "scan"})):
            text = (WF / (name + ".yml")).read_text()
            with self.subTest(workflow=name):
                code = "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))
                self.assertNotIn("continue-on-error", code)
                self.assertNotIn("--only-verified", code)
                self.assertNotIn('range="-1', code)
                for scanner, expect in gates.items():
                    self.assertIn("gate --scanner %s --expect %s" % (scanner, expect), text)
                # Each gate step runs even after a failed step (`!cancelled()`); it may carry an env block and a
                # multi-line run (the reusable's report-only switch), but nothing that leaves the step.
                gate_steps = re.findall(r"if: \$\{\{ !cancelled\(\) \}\}\n(?:        (?!- ).*\n|          .*\n)*?"
                                        r".*python3 -I \"\$RUNNER_TEMP/trusted/scanstate.py\" gate", text)
                self.assertEqual(len(gate_steps), len(gates))

    def test_shared_workflow_text_has_no_dead_runner_label(self):
        text = (WF / "secret-scan.yml").read_text()
        self.assertNotIn("vl-c1-capped", text)
        self.assertNotIn("budget-blocked", text)

    def test_code_scan_ignores_pr_suppressions(self):
        text = (WF / "trusted-code-scan.yml").read_text()
        self.assertIn("--disable-nosem", text)
        self.assertIn('git show "$BASE:.semgrepignore"', text)
        self.assertIn('--config "$T/empty.toml"', text)
        self.assertIn("--metrics=off", text)

    def test_code_scan_budget_fits_the_job(self):
        text = (WF / "trusted-code-scan.yml").read_text()
        self.assertIn("timeout-minutes: 20", text)
        self.assertNotIn("--retry 2", text)
        for needle in ("--max-time 30 --retry 1", "timeout 60 python3 -m venv", "timeout 150",
                       'run "$T/head" "$T/head.json" 240', 'run "$T/base" "$T/base.json" 120',
                       "--max-time 90 -o", "timeout 45"):
            self.assertIn(needle, text)
        self.assertLess(2 * 62 + 60 + 150 + 240 + 120 + 90 + 2 * 45, 15 * 60)

    def test_uploads_overwrite_on_rerun(self):
        for name in ("trusted-secret-scan", "trusted-code-scan"):
            text = (WF / (name + ".yml")).read_text()
            self.assertEqual(text.count("uses: actions/upload-artifact@"), text.count("overwrite: true"), name)


if __name__ == "__main__":
    unittest.main()
