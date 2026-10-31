"""Tests for trusted/pin_audit.py (U1 pin audit, root's GO 2026-10-29) and its reusable workflow.

Root's proof before R4: a tag moved off its pin and a node pin behind its major's newest (both reported), a fetch
failure (reported INCOMPLETE, a hang included, so the bound is shown to bound), and revert-red mutants. Every registry
and Node read goes through the real HTTP path, against a loopback stub that answers the way a registry does (a Bearer
challenge, an anonymous token, HEAD with Docker-Content-Digest). Stdlib only, no network. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import pin_audit  # noqa: E402
import render  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "pin-audit.yml"
TODAY = "2026-10-29"
INDEX = "application/vnd.oci.image.index.v1+json"


def digest(n):
    return "sha256:" + format(n, "x").rjust(64, "0")


OLD, CUR, N20, LTS, IRON, PLATFORM = digest(1), digest(2), digest(3), digest(4), digest(5), digest(99)
DIST = [{"version": "v26.13.0", "date": "2026-10-28"}, {"version": "v24.22.2", "date": "2026-10-27"},
        {"version": "v24.22.1", "date": "2026-10-10"}, {"version": "v22.23.4", "date": "2026-10-20"},
        {"version": "v20.20.3", "date": "2026-04-10"}, {"version": "v20.20.2", "date": "2026-03-01"},
        {"version": "junk"}]
SCHEDULE = {"v20": {"end": "2026-04-30", "lts": "2023-10-24", "codename": "Iron"},
            "v22": {"end": "2027-04-30", "lts": "2024-10-29", "codename": "Jod"},
            "v24": {"end": "2028-04-30", "lts": "2025-10-28", "codename": "Krypton"},
            "v26": {"end": "2029-04-30", "lts": "2026-10-28", "codename": ""},
            "v0.10": {"end": "2016-10-31"}}


class Registry:
    """A loopback registry + token service + Node documents. `tags` maps (name, tag) to the index digest the registry
    serves; a HEAD without both index types in Accept gets one platform's manifest digest instead, as a real one does."""

    def __init__(self, tags, hang=(), status=None, dist=DIST, schedule=SCHEDULE, hang_seconds=3.0, realm=None):
        self.tags, self.hang, self.status = dict(tags), set(hang), dict(status or {})
        self.dist, self.schedule, self.hang_seconds, self.realm = dist, schedule, hang_seconds, realm
        self.calls, self.auth = [], []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, headers=(), body=b""):
                try:
                    self.send_response(code)
                    for k, v in headers:
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                except OSError:
                    pass  # the client gave up (the hang case): nothing to answer

            def _route(self):
                stub.calls.append((self.command, self.path))
                stub.auth.append(self.headers.get("Authorization"))
                path = urllib.parse.urlsplit(self.path).path
                if path in stub.status:
                    return self._send(stub.status[path])
                if path in stub.hang:
                    time.sleep(stub.hang_seconds)
                    return self._send(200, (), b"[]")
                if path == "/token":
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    name = q["scope"][0].split(":")[1]
                    return self._send(200, (("Content-Type", "application/json"),),
                                      json.dumps({"token": "anon-" + name}).encode())
                if path == "/redirect":
                    return self._send(302, (("Location", "http://example.invalid/x"),))
                if path == "/dist.json":
                    return self._send(200, (), json.dumps(stub.dist).encode())
                if path == "/schedule.json":
                    return self._send(200, (), json.dumps(stub.schedule).encode())
                m = re.match(r"^/v2/(?P<name>.+)/manifests/(?P<tag>[^/]+)$", path)
                if not m:
                    return self._send(404)
                name, tag = m.group("name"), m.group("tag")
                if self.headers.get("Authorization") != "Bearer anon-" + name:
                    realm = stub.realm or "http://127.0.0.1:%d/token" % stub.port
                    return self._send(401, (("WWW-Authenticate", 'Bearer realm="%s",service="stub",scope="repository:%s:pull"'
                                             % (realm, name)),))
                if (name, tag) not in stub.tags:
                    return self._send(404)
                accept = self.headers.get("Accept", "")
                served = stub.tags[(name, tag)] if INDEX in accept and "manifest.list.v2" in accept else PLATFORM
                return self._send(200, (("Docker-Content-Digest", served),))

            do_HEAD = do_GET = _route

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def endpoints(self):
        return {"docker.io": self.base, "node-dist": self.base + "/dist.json", "node-schedule": self.base + "/schedule.json"}

    def heads(self, tag=None):
        return [p for c, p in self.calls if c == "HEAD" and (tag is None or p.endswith("/manifests/" + tag))]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


DOCKERFILE = """ARG BASE=node:22.23.4-alpine@{old}
ARG UNUSED
FROM ${{BASE}} AS build
FROM node:22.23.4-alpine@{cur} AS app
FROM build AS again
FROM scratch
FROM python:3.12-slim
FROM ghcr.io/vagarylabs/private@{cur}
FROM ${{MISSING}}
""".format(old=OLD, cur=CUR)
SERVICE = """FROM node:20-slim@{n20}
FROM node:lts-trixie-slim@{lts}
FROM --platform=linux/amd64 node:iron-alpine@{iron}
""".format(n20=N20, lts=LTS, iron=IRON)
CI = """name: ci
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@0000000000000000000000000000000000000000 # v4.1.0
        with:
          node-version: '24.22.1'
      - uses: actions/setup-node@0000000000000000000000000000000000000000 # v4.1.0
        with:
          node-version: ['20.20.2', '22.23.4']
      - uses: actions/setup-node@0000000000000000000000000000000000000000 # v4.1.0
        with:
          node-version: ${{ matrix.node }}
      - uses: actions/setup-node@0000000000000000000000000000000000000000 # v4.1.0
        with:
          node-version-file: .nvmrc
"""
TAGS = {("library/node", "22.23.4-alpine"): CUR, ("library/node", "20-slim"): N20,
        ("library/node", "lts-trixie-slim"): LTS, ("library/node", "iron-alpine"): IRON}


class Fixture(unittest.TestCase):
    """A throwaway repository holding the pins above, and the stub registry."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pin-audit-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = pathlib.Path(self.tmp) / "repo"
        files = {"Dockerfile": DOCKERFILE, "svc/Dockerfile.svc": SERVICE, ".github/workflows/ci.yml": CI,
                 ".nvmrc": "22.23.4\n", "README.md": "FROM node:1.2.3@" + OLD + "\n"}
        for name, text in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text)
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "fixture"], check=True)
        self.head = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        self.cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.cwd)

    def stub(self, **kw):
        reg = Registry(kw.pop("tags", TAGS), **kw)
        self.addCleanup(reg.close)
        return reg

    def run_audit(self, reg, exemptions=(), docker="renovate", node="none", **fetch):
        f = pin_audit.Fetcher(loopback=True, **fetch)
        return pin_audit.audit("vagarylabs/x", self.head, "cc:test", list(exemptions), docker, node, reg.endpoints(),
                               f, today=TODAY)

    @staticmethod
    def rows(doc, cls=None):
        return sorted((f["class"], f["file"], f["line"], f["pin"], f["current"], f["newest"])
                      for f in doc["findings"] if cls is None or f["class"] == cls)


class Findings(Fixture):
    def test_a_moved_tag_and_a_node_pin_behind_its_major_are_both_reported(self):
        doc = self.run_audit(self.stub())
        self.assertTrue(doc["complete"])
        self.assertEqual(self.rows(doc, "tag_moved"), [("tag_moved", "Dockerfile", 3, "node:22.23.4-alpine@" + OLD, OLD, CUR)])
        self.assertEqual(self.rows(doc, "node_behind"), [
            ("node_behind", ".github/workflows/ci.yml", 9, "24.22.1", "24.22.1", "24.22.2 (released 2026-10-27)"),
            ("node_behind", ".github/workflows/ci.yml", 12, "20.20.2", "20.20.2", "20.20.3 (released 2026-04-10)")])
        # Node 20's end of life: the exact pin, the major-only image tag and the codename tag.
        self.assertEqual([(f, l, p) for _, f, l, p, _, _ in self.rows(doc, "node_eol")],
                         [(".github/workflows/ci.yml", 12, "20.20.2"), ("svc/Dockerfile.svc", 1, "20"),
                          ("svc/Dockerfile.svc", 3, "iron")])
        self.assertEqual({f["newest"] for f in doc["findings"] if f["class"] == "node_eol"}, {"Node 26.13.0 (LTS)"})
        # Every finding carries its owner, file:line and current vs newest.
        for f in doc["findings"]:
            self.assertEqual(f["owner"], "cc:test")
            self.assertTrue(f["file"] and f["line"] > 0 and f["current"] and f["newest"])
        self.assertEqual(len(doc["findings"]), 6)

    def test_the_current_pins_are_clean(self):
        doc = self.run_audit(self.stub())
        judged = {(f["file"], f["line"]) for f in doc["findings"]}
        for clean in (("Dockerfile", 4), (".github/workflows/ci.yml", 18)):  # 22.23.4 by digest; .nvmrc's 22.23.4
            self.assertNotIn(clean, judged)
        self.assertEqual(doc["read"], {"dockerfiles": 2, "workflow_files": 1, "image_pins": 5, "distinct_tags": 4,
                                       "node_pins": 9})

    def test_what_is_not_audited_is_listed_with_why(self):
        doc = self.run_audit(self.stub())
        why = {(x["file"], x["line"]): x["why"] for x in doc["not_audited"]}
        self.assertIn("C1 image_tag", why[("Dockerfile", 7)])
        self.assertIn("digest alone", why[("Dockerfile", 8)])
        self.assertIn("C1 image_arg", why[("Dockerfile", 9)])
        self.assertIn("moving Node alias", why[("svc/Dockerfile.svc", 2)])
        self.assertIn("C1 node_version_expr", why[(".github/workflows/ci.yml", 15)])
        self.assertEqual(len(why), 5)
        self.assertNotIn("README.md", {x["file"] for x in doc["not_audited"]})  # only Dockerfiles are read for FROM

    def test_one_head_per_distinct_tag_across_files_and_both_pins_judged(self):
        reg = self.stub()
        doc = self.run_audit(reg)
        # Dockerfile:3 (through its ARG) and Dockerfile:4 share node:22.23.4-alpine: one judged HEAD, two verdicts.
        self.assertEqual(len([a for (c, p), a in zip(reg.calls, reg.auth) if c == "HEAD" and a]), 4)
        self.assertEqual(len(reg.heads("22.23.4-alpine")), 1)
        self.assertEqual(len(reg.heads()), 5)  # four tags, and the first HEAD of the name meets the 401 challenge
        self.assertEqual([c for c in reg.calls if c[1].startswith("/token")].__len__(), 1)  # one token per repository
        self.assertEqual(doc["requests"], len(reg.calls))
        self.assertIn(("Dockerfile", 3), {(f["file"], f["line"]) for f in doc["findings"] if f["class"] == "tag_moved"})

    def test_the_index_digest_is_asked_for(self):
        # Without both index media types in Accept, a multi-arch tag answers with a platform digest and every pin
        # would read as moved.
        reg = self.stub()
        with mock.patch.object(pin_audit, "ACCEPT", "application/vnd.docker.distribution.manifest.v2+json"):
            doc = self.run_audit(reg)
        self.assertEqual(len(self.rows(doc, "tag_moved")), 5)
        doc = self.run_audit(reg)
        self.assertEqual(len(self.rows(doc, "tag_moved")), 1)

    def test_a_tag_the_registry_no_longer_has_is_gone(self):
        tags = dict(TAGS)
        del tags[("library/node", "20-slim")]
        doc = self.run_audit(self.stub(tags=tags))
        self.assertEqual([(f["file"], f["line"]) for f in doc["findings"] if f["class"] == "tag_gone"],
                         [("svc/Dockerfile.svc", 1)])
        self.assertTrue(doc["complete"])

    def test_an_updater_s_lag_is_reported_as_its_miss(self):
        doc = self.run_audit(self.stub(), docker="renovate", node="dependabot")
        by = {(f["class"], f["file"], f["line"]): f for f in doc["findings"]}
        moved = by[("tag_moved", "Dockerfile", 3)]
        self.assertEqual(moved["updater"], "renovate")
        self.assertIn("renovate did not refresh it (the updater's miss)", moved["detail"])
        self.assertEqual(by[("node_eol", "svc/Dockerfile.svc", 1)]["updater"], "renovate")  # a FROM pin: docker's
        self.assertEqual(by[("node_behind", ".github/workflows/ci.yml", 9)]["updater"], "dependabot")
        doc = self.run_audit(self.stub(), docker="none", node="none")
        self.assertFalse(any("miss" in f["detail"] for f in doc["findings"]))

    def test_an_exemption_names_one_pin_exactly_and_an_unused_one_is_stale(self):
        ex = {"repo": "vagarylabs/x", "file": ".github/workflows/ci.yml", "uses": "24.22.1", "reason": "held for the SDK digest",
              "record": "root 2026-10-29"}
        stale = dict(ex, uses="1.2.3")
        doc = self.run_audit(self.stub(), exemptions=[ex, stale])
        self.assertNotIn(("node_behind", ".github/workflows/ci.yml", 9), {(f["class"], f["file"], f["line"]) for f in doc["findings"]})
        self.assertEqual([(e["file"], e["line"], e["record"]) for e in doc["exempt"]], [(".github/workflows/ci.yml", 9, "root 2026-10-29")])
        self.assertEqual(doc["stale_exemptions"], [stale])
        self.assertIn("STALE EXEMPTION", pin_audit.render(doc))

    def test_the_manifest_section_is_closed(self):
        good = {"repo": "*", "file": "*", "uses": "x", "reason": "why", "record": "rec"}
        self.assertEqual(pin_audit.validate_pin_audit({"pin_audit": {"exemptions": [good]}}), [good])
        for bad in (None, {}, {"exemptions": {}}, {"exemptions": [], "mode": "report"}, {"exemptions": [dict(good, reason=" ")]},
                    {"exemptions": [dict(good, extra="x")]}):
            with self.subTest(bad=bad), self.assertRaises(pin_audit.classify.IntegrityError):
                pin_audit.validate_pin_audit({} if bad is None else {"pin_audit": bad})
        committed = json.loads((ROOT / "trusted" / "manifest.json").read_text())
        pin_audit.validate_pin_audit(pin_audit.classify.validate_manifest(committed))


class Incomplete(Fixture):
    def test_failed_fetches_are_a_finding_and_a_hang_is_bounded(self):
        reg = self.stub(status={"/v2/library/node/manifests/20-slim": 500, "/dist.json": 503},
                        hang={"/v2/library/node/manifests/iron-alpine"}, hang_seconds=6.0)
        t0 = time.monotonic()
        doc = self.run_audit(reg, timeout=0.5)
        # Unbounded, the audit would wait out the stub's 6 s hang; bounded, it gives up after 0.5 s.
        self.assertLess(time.monotonic() - t0, 5.0, "the per-request timeout did not bound the hung HEAD")
        self.assertFalse(doc["complete"])
        failed = {x["fetch"]: x["why"] for x in doc["incomplete"]}
        self.assertEqual(set(failed), {"registry HEAD docker.io/library/node:20-slim",
                                       "registry HEAD docker.io/library/node:iron-alpine",
                                       "Node releases (dist index and schedule)"})
        self.assertEqual(failed["registry HEAD docker.io/library/node:20-slim"], "HTTP 500")
        self.assertIn("no answer", failed["registry HEAD docker.io/library/node:iron-alpine"])
        inc = [f for f in doc["findings"] if f["class"] == "audit_incomplete"]
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["current"], "3 fetches failed")
        for what in failed:
            self.assertIn(what, inc[0]["detail"])
        md = pin_audit.render(doc)
        self.assertTrue(md.startswith("## Pin audit: vagarylabs/x: INCOMPLETE (3 fetches failed)"))
        self.assertIn("Not a clean week", md.splitlines()[0])
        # What the failed fetches cover is not judged, and what they do not cover still is.
        self.assertEqual({f["class"] for f in doc["findings"]}, {"tag_moved", "audit_incomplete"})

    def test_a_bad_answer_is_incomplete_never_clean(self):
        for kw in ({"status": {"/token": 403}}, {"status": {"/v2/library/node/manifests/22.23.4-alpine": 429}},
                   {"dist": {"not": "a list"}}, {"schedule": ["not", "an", "object"]}, {"schedule": {"v20": {}}}):
            with self.subTest(kw=kw):
                doc = self.run_audit(self.stub(**kw))
                self.assertFalse(doc["complete"])
                self.assertIn("audit_incomplete", {f["class"] for f in doc["findings"]})

    def test_nothing_is_attempted_past_the_deadline(self):
        doc = self.run_audit(self.stub(), deadline=0)
        self.assertFalse(doc["complete"])
        self.assertEqual(len(doc["incomplete"]), 5)  # four tags, the Node documents
        self.assertTrue(all(x["why"].startswith("not attempted") for x in doc["incomplete"]))
        self.assertEqual(doc["requests"], 0)

    def test_over_the_tag_bound_is_not_attempted_and_incomplete(self):
        with mock.patch.object(pin_audit, "MAX_TAGS", 2):
            doc = self.run_audit(self.stub())
        self.assertEqual(len([x for x in doc["incomplete"] if "tag bound" in x["why"]]), 2)
        self.assertFalse(doc["complete"])

    def test_an_over_cap_body_is_incomplete(self):
        with mock.patch.object(pin_audit, "MAX_BODY_BYTES", 100):
            doc = self.run_audit(self.stub())
        self.assertIn("over its 100-byte cap", {x["fetch"]: x["why"] for x in doc["incomplete"]}["Node releases (dist index and schedule)"])


class Transport(Fixture):
    def test_only_https_or_the_tests_loopback_is_fetched(self):
        self.assertTrue(pin_audit.allowed("https://registry-1.docker.io/v2/"))
        self.assertFalse(pin_audit.allowed("http://registry-1.docker.io/v2/"))
        self.assertFalse(pin_audit.allowed("http://127.0.0.1:1/x"))  # loopback http only in the tests' mode
        self.assertTrue(pin_audit.allowed("http://127.0.0.1:1/x", loopback=True))
        self.assertFalse(pin_audit.allowed("http://example.invalid/x", loopback=True))
        with self.assertRaises(pin_audit.Failed):
            pin_audit.Fetcher().request("GET", "http://127.0.0.1:1/x")

    def test_a_challenge_realm_that_is_not_https_is_refused(self):
        doc = self.run_audit(self.stub(realm="http://example.invalid/token"))
        self.assertFalse(doc["complete"])
        self.assertTrue(all("refused token realm" in x["why"] for x in doc["incomplete"] if x["fetch"].startswith("registry")))

    def test_a_redirect_off_https_is_not_followed(self):
        reg = self.stub()
        status, _, _ = pin_audit.Fetcher(loopback=True).request("GET", reg.base + "/redirect")
        self.assertEqual(status, 302)
        self.assertEqual([p for _, p in reg.calls], ["/redirect"])

    def test_no_credential_is_ever_sent(self):
        reg = self.stub()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "ghs_should_never_leave", "GH_TOKEN": "ghs_should_never_leave"}):
            self.run_audit(reg)
        sent = {a for a in reg.auth if a}
        self.assertEqual(sent, {"Bearer anon-library/node"})
        tokens = [a for (c, p), a in zip(reg.calls, reg.auth) if p.startswith("/token")]
        self.assertEqual(tokens, [None])  # the token request itself is anonymous

    def test_the_real_cli_runs_under_isolated_mode_from_its_own_directory(self):
        # The workflow writes classify.py, pin_audit.py and manifest.json into one directory and runs python3 -I, which
        # leaves that directory off sys.path: the classifier must load by its path.
        reg = self.stub()
        bin_dir = pathlib.Path(self.tmp) / "trusted"
        bin_dir.mkdir()
        for name in ("classify.py", "pin_audit.py", "manifest.json"):
            shutil.copy(ROOT / "trusted" / name, bin_dir / name)
        out = pathlib.Path(self.tmp) / "pin-audit.json"
        summary = pathlib.Path(self.tmp) / "summary.md"
        argv = [sys.executable, "-I", str(bin_dir / "pin_audit.py"), "audit", "--manifest", str(bin_dir / "manifest.json"),
                "--repo", "vagarylabs/x", "--head", self.head, "--owner", "cc:test", "--docker-updater", "renovate",
                "--json-out", str(out), "--summary", str(summary)]
        for key, url in reg.endpoints().items():
            argv += ["--endpoint", "%s=%s" % (key, url)]
        r = subprocess.run(argv, cwd=self.repo, capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, GITHUB_TOKEN="ghs_should_never_leave"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = json.loads(out.read_text())
        self.assertTrue(doc["complete"])
        self.assertIn(("tag_moved", "Dockerfile", 3), {(f["class"], f["file"], f["line"]) for f in doc["findings"]})
        self.assertTrue(summary.read_text().startswith("## Pin audit: vagarylabs/x: COMPLETE"))
        self.assertFalse((bin_dir / "__pycache__").exists(), "the classifier was imported, not compiled from source")
        self.assertNotIn("ghs_should_never_leave", "".join(a or "" for a in reg.auth))
        # A non-loopback endpoint and a bad head are usage errors, never a silent pass.
        bad = argv[:]
        bad[bad.index("--endpoint") + 1] = "docker.io=https://evil.example"
        self.assertEqual(subprocess.run(bad, cwd=self.repo, capture_output=True, text=True, timeout=60).returncode, 2)
        bad = argv[:]
        bad[bad.index("--head") + 1] = "f" * 40
        self.assertEqual(subprocess.run(bad, cwd=self.repo, capture_output=True, text=True, timeout=60).returncode, 2)


class Readers(unittest.TestCase):
    def test_image_references(self):
        for image, want in (("node:22-alpine@" + CUR, ("docker.io", "library/node", "22-alpine", CUR)),
                            ("docker.io/cloudflare/sandbox:0.7.0", ("docker.io", "cloudflare/sandbox", "0.7.0", None)),
                            ("gcr.io/distroless/nodejs22-debian13:nonroot@" + CUR,
                             ("gcr.io", "distroless/nodejs22-debian13", "nonroot", CUR)),
                            ("localhost:5000/a/b:1@" + CUR, ("localhost:5000", "a/b", "1", CUR)),
                            ("ghcr.io/o/p@" + CUR, ("ghcr.io", "o/p", "", CUR)),
                            ("node@sha256:short", None), ("Node:1", None)):
            with self.subTest(image):
                self.assertEqual(pin_audit.parse_image(image), want)

    def test_global_args_resolve_and_a_missing_default_does_not(self):
        args = pin_audit.global_args("ARG A=x:1\nARG B\nARG C='y:2'\nFROM $A\nARG D=z\n")
        self.assertEqual(args, {"A": "x:1", "C": "y:2"})
        self.assertEqual(pin_audit.resolve_args("${A}", args), "x:1")
        self.assertEqual(pin_audit.resolve_args("$C", args), "y:2")
        self.assertIsNone(pin_audit.resolve_args("${B}", args))
        self.assertIsNone(pin_audit.resolve_args("${D}", args))  # declared after the first FROM: not usable there

    def test_c1_and_the_audit_share_one_reader(self):
        # The refactor kept C1's verdicts: image_findings and node_version_findings are built on the shared readers.
        text = "FROM a AS x\nFROM x\nFROM scratch\nFROM b@" + CUR + "\nFROM $C\n# FROM d\n"
        self.assertEqual(pin_audit.classify.from_images(text), [(1, "a"), (4, "b@" + CUR), (5, "$C")])
        self.assertEqual(pin_audit.classify.image_findings(text), [(1, "image_tag", "a", None), (5, "image_arg", "$C", None)])
        wf = "      node-version: 22\n      node-version: ['1.2.3', 4]\n      node-version: 1.2.3\n"
        self.assertEqual([k for _, k, _, _ in pin_audit.classify.node_versions(wf)], ["value"] * 3)
        self.assertEqual([c for _, c, _, _ in pin_audit.classify.node_version_findings(wf)], ["node_version_loose"] * 2)


def run(repo, created, complete=True, findings=(), incomplete=0, result=True, error=None, rid=1):
    doc = {"complete": complete, "owner": "cc:x", "incomplete": [{"fetch": "f", "why": "w"}] * incomplete,
           "findings": [{"class": c, "updater": u} for c, u in findings]}
    return {"id": rid, "created_at": created, "conclusion": "success", "result": doc if result else None, "error": error}


class Record(unittest.TestCase):
    NOW = "2026-10-29T06:00:00Z"

    def test_last_complete_survives_an_incomplete_week(self):
        runs = {"repos": {"vagarylabs/a": [run("a", "2026-10-21T04:23:00Z", rid=1),
                                           run("a", "2026-10-28T04:23:00Z", complete=False, incomplete=2,
                                               findings=[("tag_moved", "renovate"), ("audit_incomplete", "none")], rid=2)]}}
        text = pin_audit.record(runs, self.NOW)
        self.assertIn("vagarylabs/a run 2 2026-10-28: INCOMPLETE (2 fetches failed), 1 findings (1 an updater's miss)", text)
        self.assertIn("last COMPLETE 2026-10-21", text)
        self.assertTrue(text.startswith("pin-audit week of 2026-10-29: 1 repositories, 0 COMPLETE, 1 INCOMPLETE"))

    def test_a_repository_without_a_recent_run_is_missing(self):
        runs = {"repos": {"vagarylabs/b": [run("b", "2026-10-19T04:23:00Z")], "vagarylabs/c": []}}
        text = pin_audit.record(runs, self.NOW)
        self.assertIn("vagarylabs/b MISSING: no run in the last 8 days (newest run 2026-10-19); last COMPLETE 2026-10-19", text)
        self.assertIn("vagarylabs/c MISSING: no run in the last 8 days (no run read)", text)
        self.assertIn("2 MISSING", text.splitlines()[0])

    def test_a_result_that_cannot_be_read_back_is_never_complete(self):
        runs = {"repos": {"vagarylabs/d": [run("d", "2026-10-28T04:23:00Z", result=False, error="artifact unavailable: gone"),
                                           run("d", "2026-10-21T04:23:00Z", result=False, error="expired")]},
                "errors": {"vagarylabs/e": "gh run list failed: HTTP 404"}}
        text = pin_audit.record(runs, self.NOW)
        self.assertIn("vagarylabs/d run 1 2026-10-28: NO RESULT (artifact unavailable: gone); no COMPLETE run among the 2 read", text)
        self.assertIn("vagarylabs/e NO RESULT (gh run list failed: HTTP 404)", text)
        self.assertIn("0 COMPLETE, 0 INCOMPLETE, 2 NO RESULT", text.splitlines()[0])

    def test_the_runs_file_is_written_from_gh(self):
        spec = importlib.util.spec_from_file_location("pin_audit_runs", ROOT / "scripts" / "pin_audit_runs.py")
        runs_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runs_mod)
        listed = [{"databaseId": 7, "createdAt": "2026-10-28T04:23:00Z", "conclusion": "success", "status": "completed"},
                  {"databaseId": 6, "createdAt": "2026-10-21T04:23:00Z", "conclusion": "success", "status": "completed"},
                  {"databaseId": 8, "createdAt": "2026-10-29T04:23:00Z", "conclusion": "", "status": "in_progress"}]
        calls = []

        def fake(args):
            calls.append(args)
            if args[:2] == ["run", "list"]:
                return (1, "", "HTTP 404") if args[3] == "vagarylabs/gone" else (0, json.dumps(listed), "")
            if args[2] == "7":
                d = pathlib.Path(args[args.index("-D") + 1])
                (d / "pin-audit.json").write_text(json.dumps({"complete": True}))
                return 0, "", ""
            return 1, "", "no artifact matches any of the names or patterns provided"
        doc = runs_mod.collect(["vagarylabs/a", "vagarylabs/gone"], gh=fake)
        rows = {r["id"]: r for r in doc["repos"]["vagarylabs/a"]}
        self.assertEqual(rows[7]["result"], {"complete": True})
        self.assertIsNone(rows[6]["result"])
        self.assertIn("artifact unavailable", rows[6]["error"])
        self.assertEqual(rows[8]["error"], "run in_progress")
        self.assertEqual(doc["errors"], {"vagarylabs/gone": "gh run list failed: HTTP 404"})
        self.assertNotIn(["run", "download", "8"], [c[:3] for c in calls])
        self.assertIn(["--workflow", "pin-audit.yml"], [c[4:6] for c in calls if c[:2] == ["run", "list"]])


class Workflow(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_rendered_and_every_inline_copy_is_byte_identical(self):
        self.assertEqual(render.main(["--check"]), 0)
        for marker, source in (("TRUSTED_CLASSIFY_PY", "trusted/classify.py"), ("TRUSTED_PIN_AUDIT_PY", "trusted/pin_audit.py"),
                               ("TRUSTED_MANIFEST_JSON", "trusted/manifest.json")):
            found = list(re.finditer(r"\n( *)cat > \"\$d/[^\"]+\" <<'%s'\n(.*?)\n\1%s\n" % (marker, marker), self.text, re.S))
            self.assertEqual(len(found), 1, marker)
            indent = found[0].group(1)
            body = "\n".join(l[len(indent):] if l.startswith(indent) else l for l in found[0].group(2).split("\n"))
            self.assertEqual(body + "\n", (ROOT / source).read_text(), marker)

    def test_called_only_by_a_caller_with_contents_read_and_no_secret(self):
        self.assertIn("\non:\n  workflow_call:\n", self.text)
        self.assertNotRegex(self.text, r"\n  (schedule|pull_request|push|pull_request_target|workflow_dispatch):")
        self.assertIn("\npermissions:\n  contents: read\n\njobs:", self.text)
        self.assertEqual(re.findall(r"\n    permissions:\n((?:      .*\n)+)", self.text), ["      contents: read\n"])
        yaml = re.sub(r"<<'(\w+)'\n.*?\n *\1\n", "\n", self.text, flags=re.S)  # the inline copies are data
        code = "\n".join(l for l in yaml.splitlines() if not l.lstrip().startswith("#"))
        for forbidden in ("secrets.", "github.token", "GITHUB_TOKEN", "id-token", ": write"):
            self.assertNotIn(forbidden, code, forbidden)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("default: vl-light", self.text)

    def test_every_uses_is_pinned_with_an_exact_release_and_timeouts_meet_the_floor(self):
        yaml = re.sub(r"<<'(\w+)'\n.*?\n *\1\n", "\n", self.text, flags=re.S)
        self.assertEqual(len(re.findall(r"\n\s+uses: (.*)", yaml)), 2)
        for line, cls, value, label in pin_audit.classify.pin_findings(yaml):
            self.fail("C1 pin finding at %d: %s %s" % (line, cls, value))
        self.assertEqual(re.findall(r"\n    timeout-minutes: (\d+)", self.text), ["12"])
        self.assertTrue(all(int(m) >= 6 for m in re.findall(r"timeout-minutes: (\d+)", yaml)))

    def test_artifact_retention_covers_the_weekly_reader(self):
        self.assertIn("retention-days: %d" % pin_audit.RETENTION_DAYS, self.text)
        self.assertGreaterEqual(pin_audit.RETENTION_DAYS, 4 * 7 + pin_audit.MISSING_DAYS - 1)
        self.assertIn("name: pin-audit\n", self.text)

    def test_ci_keeps_it_off_actionlint_s_shellcheck_and_shellchecks_it_directly(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        inline = re.search(r"inline=\(([^)]*)\)", ci).group(1).split()
        self.assertIn(".github/workflows/pin-audit.yml", inline)
        shell = (ROOT / "trusted" / "tests" / "test_trusted.py").read_text()
        self.assertIn('("pin-audit", ROOT / ".github" / "workflows" / "pin-audit.yml", 2)', shell)


if __name__ == "__main__":
    unittest.main()
