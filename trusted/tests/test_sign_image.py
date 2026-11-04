"""Static and behavioural tests for .github/workflows/sign-image.yml, the ONE shared keyless image signer.

The workflow is the signing trust root of the fleet, so what must never drift is pinned here: the admission `if:` (the
owner id, exactly 5 repository ids, exactly 7 caller workflow refs, main only, 3 events), the runner, the contract
(one input, two outputs, no secrets, no checkout), the pins, and the namespace table, which must name the same 7 callers
as the `if:`. The three Python programs the workflow embeds (namespace binding, revision binding, run-binding check)
are cut out of the workflow text and run against fixtures, so the file a caller pins is the file that is tested.
Plain unittest, stdlib only, no network. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_sign_image.py' -v
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "sign-image.yml"
TEXT = WORKFLOW.read_text()
CODE = "\n".join(line for line in TEXT.splitlines() if not line.lstrip().startswith("#"))  # the file without comments

OWNER_ID = "328526494"
REPOSITORY_IDS = ["1034277250", "1089791523", "1280724433", "1290498250", "1215614271"]
CALLERS = [
    "vagarylabs/vagary-platform/.github/workflows/cosign-sign-image.yml@refs/heads/main",
    "vagarylabs/vagary-voice/.github/workflows/cosign-sign-image.yml@refs/heads/main",
    "vagarylabs/vagaris/.github/workflows/docs-image.yml@refs/heads/main",
    "vagarylabs/vagaris/.github/workflows/server-image.yml@refs/heads/main",
    "vagarylabs/vagaris/.github/workflows/cognitive-executor-image.yml@refs/heads/main",
    "vagarylabs/vagary-core/.github/workflows/publish-images.yml@refs/heads/main",
    "vagarylabs/vagary-earnings/.github/workflows/cosign-sign-image.yml@refs/heads/main",
]
SAN = "https://github.com/vagarylabs/.github/.github/workflows/sign-image.yml@refs/heads/main"
ATT_TYPE = "https://vagarylabs.github.io/attestations/signing-run/v1"


def job_if():
    """The folded `if: >-` scalar of jobs.sign, as GitHub evaluates it (lines joined by single spaces)."""
    m = re.search(r"^    if: >-\n((?:      .*\n)+)", TEXT, re.M)
    assert m, "jobs.sign.if is not a folded scalar"
    return " ".join(line.strip() for line in m.group(1).splitlines())


def step_python(step_name):
    """The embedded `python3 -I - <<'PY'` program of the step with this name, dedented, as a module namespace."""
    m = re.search(r"- (?:id: \w+\n        )?name: " + re.escape(step_name) + r"\n(?:.*\n)*?          python3 -I - <<'PY'\n((?:.*\n)*?)          PY\n",
                  TEXT)
    assert m, "no embedded program in step: " + step_name
    source = textwrap.dedent(m.group(1))
    ns = {"__name__": "sign_image_embedded"}  # not __main__: the module's main() must not run on import
    exec(compile(source, step_name, "exec"), ns)  # noqa: S102 (our own file, tested)
    return ns


class Admission(unittest.TestCase):
    def test_owner_id(self):
        self.assertIn("github.repository_owner_id == '%s'" % OWNER_ID, job_if())

    def test_exactly_the_five_repository_ids(self):
        m = re.search(r"contains\(fromJSON\('(\[[^']*\])'\), github\.repository_id\)", job_if())
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), REPOSITORY_IDS)

    def test_exactly_the_seven_caller_workflow_refs(self):
        m = re.search(r"contains\(fromJSON\('(\[[^']*\])'\), github\.workflow_ref\)", job_if())
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), CALLERS)
        self.assertEqual(len(set(CALLERS)), 7)

    def test_main_branch_only(self):
        cond = job_if()
        self.assertIn("github.ref == 'refs/heads/main'", cond)
        self.assertIn("github.ref_type == 'branch'", cond)

    def test_exactly_three_events(self):
        m = re.search(r"contains\(fromJSON\('(\[[^']*\])'\), github\.event_name\)", job_if())
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), ["push", "workflow_dispatch", "workflow_run"])

    def test_every_term_is_anded_and_nothing_else_is(self):
        cond = job_if()
        self.assertEqual(cond.count("&&"), 5)  # six terms
        self.assertNotIn("||", cond)
        self.assertNotIn("!", cond.replace("!=", ""))
        # only documented `github` fields: a job-level `if:` cannot see steps, env or secrets
        for ctx in re.findall(r"\b(github|inputs|vars|secrets|env|needs|steps|runner)\.", cond):
            self.assertEqual(ctx, "github")


class Contract(unittest.TestCase):
    def test_runner_and_timeout(self):
        self.assertIn("\n    runs-on: [self-hosted, vl-builder]\n", TEXT)
        self.assertEqual(re.findall(r"^    timeout-minutes: (\d+)$", TEXT, re.M), ["15"])
        self.assertEqual(len(re.findall(r"^\s+runs-on:", TEXT, re.M)), 1)

    def test_only_workflow_call(self):
        triggers = re.search(r"^on:\n((?:  .*\n|\n)+)", TEXT, re.M).group(1)
        self.assertEqual(re.findall(r"^  (\S+):", triggers, re.M), ["workflow_call"])

    def test_one_input_two_outputs_no_secrets(self):
        call = re.search(r"^  workflow_call:\n((?:    .*\n|\n)+)", TEXT, re.M).group(1)
        inputs = re.search(r"^    inputs:\n((?:      .*\n)+)", call, re.M).group(1)
        outputs = re.search(r"^    outputs:\n((?:      .*\n)+)", call, re.M).group(1)
        self.assertEqual(re.findall(r"^      (\w+):", inputs, re.M), ["artifacts"])
        self.assertEqual(re.findall(r"^      (\w+):", outputs, re.M), ["signed", "record"])
        self.assertNotRegex(call, r"^    secrets:", "the signer takes no secrets: input")
        self.assertIsNone(re.search(r"\$\{\{\s*secrets\.", CODE))
        self.assertNotIn("secrets: inherit", TEXT)

    def test_permissions(self):
        self.assertIn("\npermissions: {}\n", TEXT)
        m = re.search(r"^    permissions:\n((?:      .*\n)+)", TEXT, re.M)
        self.assertEqual(re.findall(r"^      (\S+): (\S+)$", m.group(1), re.M),
                         [("id-token", "write"), ("packages", "write")])

    def test_no_checkout_of_caller_source(self):
        self.assertNotIn("actions/checkout", TEXT)
        self.assertNotIn("persist-credentials", TEXT)

    def test_no_key_material(self):
        self.assertIsNone(re.search(r"--key\b|COSIGN_PRIVATE_KEY|COSIGN_PASSWORD|env://|\.key\b|--tlog-upload=false|--insecure", CODE))

    def test_every_uses_is_a_full_commit_sha(self):
        uses = re.findall(r"^\s+uses: (\S+)", TEXT, re.M)
        self.assertEqual(len(uses), 1)
        for u in uses:
            self.assertRegex(u, r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")

    def test_no_expression_inside_a_script(self):
        """Inputs and context values reach scripts through `env:` only, never as script text (template injection)."""
        lines, in_run, base = TEXT.splitlines(), False, 0
        for n, line in enumerate(lines, 1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if in_run and stripped and indent <= base:
                in_run = False
            if in_run:
                self.assertNotIn("${{", line, "line %d: an expression inside a run script" % n)
            m = re.match(r"( *)(?:- )?run: [|>]", line)
            if m:
                in_run, base = True, len(m.group(1)) + (2 if stripped.startswith("- ") else 0)


class Pins(unittest.TestCase):
    def test_cosign_matches_release_assets_lock(self):
        lock = [ln.split() for ln in (ROOT / "release-assets.lock").read_text().splitlines()
                if ln.startswith("cosign 3.0.6 ")]
        self.assertEqual(len(lock), 1)
        _, version, url, sha = lock[0]
        self.assertIn("          tool: cosign\n          version: %s\n          url: %s\n          sha256: %s\n" % (version, url, sha), TEXT)

    def test_fetch_release_asset_pin_is_the_scorecard_pin(self):
        shas = set(re.findall(r"fetch-release-asset@([0-9a-f]{40})", TEXT))
        self.assertEqual(shas, {"85ac97443b6e2fb23570ccda190934f150973aef"})

    def test_identity_literals(self):
        # the canary exists to prove @main normalises to refs/heads/main: neither literal may be derived
        self.assertEqual(CODE.count("--certificate-identity " + SAN), 1)
        self.assertIn("--certificate-oidc-issuer https://token.actions.githubusercontent.com", TEXT)
        self.assertIn("--certificate-github-workflow-repository \"$GH_REPOSITORY\"", TEXT)
        self.assertIn("--certificate-github-workflow-ref refs/heads/main", TEXT)
        self.assertIn("--certificate-github-workflow-sha \"$RELEASE_SHA\"", TEXT)
        self.assertEqual(CODE.count("--type " + ATT_TYPE), 2)  # attest and verify-attestation

    def test_actionlint_knows_the_runner_label(self):
        labels = (ROOT / ".github" / "actionlint.yaml").read_text()
        self.assertIn("    - vl-builder\n", labels)


class Namespace(unittest.TestCase):
    ns = step_python("Validate the artifacts and bind the namespace to the caller")
    D = "sha256:" + "a" * 64

    def ref(self, package):
        return "ghcr.io/vagarylabs/%s@%s" % (package, self.D)

    def bind(self, caller, *packages):
        return self.ns["bind"]("\n".join(self.ref(p) for p in packages), caller)

    def test_the_table_names_the_same_seven_callers_as_the_admission(self):
        self.assertEqual(sorted(self.ns["BINDING"]), sorted(CALLERS))

    def test_each_caller_signs_its_own_packages(self):
        c = dict(zip(["platform", "voice", "docs", "server", "cog", "core", "earn"], CALLERS))
        self.assertEqual(len(self.bind(c["platform"], "vagary-platform")), 1)
        self.assertEqual(len(self.bind(c["voice"], "vagary-voice/api-service", "vagary-voice/voice-gateway")), 2)
        self.assertEqual(len(self.bind(c["docs"], "vagaris-docs-site")), 1)
        self.assertEqual(len(self.bind(c["server"], "vagaris-server")), 1)
        self.assertEqual(len(self.bind(c["cog"], "vagaris-cognitive-executor")), 1)
        self.assertEqual(len(self.bind(c["core"], "vagary-core-api", "vagary-core-tts-service")), 2)
        self.assertEqual(len(self.bind(c["earn"], "vagary-earnings")), 1)

    def test_a_caller_cannot_sign_another_products_package(self):
        c = dict(zip(["platform", "voice", "docs", "server", "cog", "core", "earn"], CALLERS))
        for caller, package in [
            ("platform", "vagary-earnings"), ("earn", "vagary-platform"), ("docs", "vagaris-server"),
            ("server", "vagaris-docs-site"), ("cog", "vagaris-server"), ("voice", "vagary-platform"),
            ("core", "vagary-platform"), ("platform", "vagary-platform-evil"), ("platform", "vagary-platform/x"),
            ("voice", "vagary-voice"), ("voice", "vagary-voice/a/b"), ("core", "vagary-core"),
            ("core", "vagary-core-a/b"), ("platform", "vagary-core-api"),
        ]:
            with self.subTest(caller=caller, package=package), self.assertRaises(SystemExit):
                self.bind(c[caller], package)

    def test_mixed_list_is_refused_whole(self):
        with self.assertRaises(SystemExit):
            self.bind(CALLERS[0], "vagary-platform", "vagary-earnings")

    def test_malformed_references(self):
        for bad in ["ghcr.io/vagarylabs/vagary-platform:latest", "ghcr.io/vagarylabs/vagary-platform@sha256:abc",
                    "ghcr.io/vagarylabs/vagary-platform@sha256:" + "A" * 64, "ghcr.io/other/vagary-platform@" + self.D,
                    "docker.io/vagarylabs/vagary-platform@" + self.D, "ghcr.io/vagarylabs/Vagary-Platform@" + self.D,
                    "ghcr.io/vagarylabs/vagary-platform@" + self.D + " extra", "ghcr.io/vagarylabs/../vagary-platform@" + self.D,
                    "--key=x"]:
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                self.ns["bind"](bad, CALLERS[0])

    def test_counts_and_duplicates(self):
        with self.assertRaises(SystemExit):
            self.ns["bind"]("", CALLERS[0])
        with self.assertRaises(SystemExit):
            self.ns["bind"]("\n  \n", CALLERS[0])
        with self.assertRaises(SystemExit):
            self.bind(CALLERS[0], "vagary-platform", "vagary-platform")
        many = "\n".join("ghcr.io/vagarylabs/vagary-core-p%d@sha256:%064x" % (i, i) for i in range(64))
        self.assertEqual(len(self.ns["bind"](many, CALLERS[5])), 64)
        with self.assertRaises(SystemExit):
            self.ns["bind"](many + "\nghcr.io/vagarylabs/vagary-core-x@" + self.D, CALLERS[5])

    def test_unknown_caller_is_refused(self):
        with self.assertRaises(SystemExit):
            self.ns["bind"](self.ref("vagary-platform"), "vagarylabs/vagary-platform/.github/workflows/evil.yml@refs/heads/main")

    def test_blank_lines_and_crlf_are_tolerated(self):
        got = self.ns["bind"]("\r\n" + self.ref("vagary-platform") + "\r\n\n", CALLERS[0])
        self.assertEqual(got, [self.ref("vagary-platform")])

    def test_the_program_runs_as_a_process(self):
        m = re.search(r"python3 -I - <<'PY'\n((?:.*\n)*?)          PY\n", TEXT)
        program = textwrap.dedent(m.group(1))
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "work"))
            env = {"PATH": os.environ["PATH"], "SIGN_DIR": d, "ARTIFACTS": self.ref("vagary-platform"), "WORKFLOW_REF": CALLERS[0]}
            ok = subprocess.run([sys.executable, "-I", "-"], input=program, text=True, env=env, capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(pathlib.Path(d, "work", "artifacts.txt").read_text(), self.ref("vagary-platform") + "\n")
            env["WORKFLOW_REF"] = CALLERS[1]
            bad = subprocess.run([sys.executable, "-I", "-"], input=program, text=True, env=env, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Registry:
    """A fake registry: content-addressed blobs and manifests, as the `get(kind, digest)` the program expects."""

    def __init__(self):
        self.store = {}

    def put(self, obj):
        data = json.dumps(obj, sort_keys=True).encode()
        self.store[sha(data)] = data
        return sha(data)

    def image(self, revision="c" * 40, labels=True):
        cfg = {"config": {"Labels": {"org.opencontainers.image.revision": revision}} if labels else {"Labels": None}}
        cd = self.put(cfg)
        return self.put({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                         "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": 1},
                         "layers": []})

    def get(self, kind, digest):
        return self.store[digest]


def index(entries):
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries}


def image_entry(digest, arch="amd64", os_="linux"):
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": 1,
            "platform": {"architecture": arch, "os": os_}}


def attestation_entry(digest):
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": 1,
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
            "platform": {"architecture": "unknown", "os": "unknown"}}


class RevisionBinding(unittest.TestCase):
    ns = step_python("Bind each digest to the caller's commit")

    def test_single_image_manifest(self):
        r = Registry()
        self.assertEqual(self.ns["revision_of"](r.get, r.image("c" * 40)), "c" * 40)

    def test_buildx_index_with_provenance_is_read_through_its_one_image(self):
        r = Registry()
        img, att = r.image("d" * 40), r.image("e" * 40)  # the attestation manifest's own label must not be read
        idx = r.put(index([image_entry(img), attestation_entry(att)]))
        self.assertEqual(self.ns["revision_of"](r.get, idx), "d" * 40)

    def test_multi_arch_index_is_refused(self):
        r = Registry()
        idx = r.put(index([image_entry(r.image()), image_entry(r.image("f" * 40), arch="arm64")]))
        with self.assertRaises(SystemExit):
            self.ns["revision_of"](r.get, idx)

    def test_index_whose_only_image_is_not_linux_amd64_is_refused(self):
        r = Registry()
        for arch, os_ in [("arm64", "linux"), ("amd64", "windows")]:
            idx = r.put(index([image_entry(r.image(), arch=arch, os_=os_)]))
            with self.subTest(arch=arch, os=os_), self.assertRaises(SystemExit):
                self.ns["revision_of"](r.get, idx)

    def test_index_of_only_attestations_and_an_empty_index_are_refused(self):
        r = Registry()
        for entries in ([attestation_entry(r.image())], []):
            idx = r.put(index(entries))
            with self.subTest(n=len(entries)), self.assertRaises(SystemExit):
                self.ns["revision_of"](r.get, idx)

    def test_nested_index_is_refused(self):
        r = Registry()
        inner = r.put(index([image_entry(r.image())]))
        outer = r.put(index([image_entry(inner)]))
        with self.assertRaises(SystemExit):
            self.ns["revision_of"](r.get, outer)

    def test_missing_label_reads_as_none_and_never_matches(self):
        r = Registry()
        self.assertIsNone(self.ns["revision_of"](r.get, r.image(labels=False)))

    def test_not_a_manifest_is_refused(self):
        r = Registry()
        with self.assertRaises(SystemExit):
            self.ns["revision_of"](r.get, r.put({"hello": "world"}))

    def test_malformed_child_and_config_digests_are_refused(self):
        r = Registry()
        with self.assertRaises(SystemExit):
            self.ns["revision_of"](r.get, r.put(index([image_entry("sha256:zz")])))
        with self.assertRaises(SystemExit):
            self.ns["revision_of"](r.get, r.put({"config": {"digest": "../etc/passwd"}}))

    def test_main_refuses_a_mismatched_revision(self):
        """End to end with the HTTP layer faked: a label that is not github.sha stops the job."""
        r = Registry()
        digest = r.image("1" * 40)
        pkg = "vagarylabs/vagary-platform"

        def fake_http(url, headers):
            if url.startswith("https://ghcr.io/token"):
                return json.dumps({"token": "t"}).encode()
            return r.store[url.rsplit("/", 1)[1]]

        ns = dict(self.ns)
        ns["http_get"] = fake_http
        main = type(ns["main"])(ns["main"].__code__, ns)  # rebind main's globals to the faked namespace
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "work"))
            pathlib.Path(d, "work", "artifacts.txt").write_text("ghcr.io/%s@%s\n" % (pkg, digest))
            env = {"SIGN_DIR": d, "REGISTRY_USER": "u", "REGISTRY_TOKEN": "tok", "RELEASE_SHA": "1" * 40}
            old = {k: os.environ.get(k) for k in env}
            try:
                os.environ.update(env)
                main()  # label == github.sha: passes
                os.environ["RELEASE_SHA"] = "2" * 40
                with self.assertRaises(SystemExit):
                    main()
                os.environ["RELEASE_SHA"] = "not-a-sha"
                with self.assertRaises(SystemExit):
                    main()
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_the_token_never_reaches_a_command_line(self):
        self.assertIsNone(re.search(r"\b(curl|wget)\b", CODE))
        self.assertIsNone(re.search(r"--password(?!-stdin)|--registry-password|--registry-token|--identity-token", CODE))
        self.assertIn("--password-stdin", CODE)


class RunBinding(unittest.TestCase):
    ns = step_python("Confirm the run binding and publish the outputs")
    ENV = {"RUN_ID": "42", "RUN_ATTEMPT": "1", "GH_REPOSITORY": "vagarylabs/vagary-platform",
           "WORKFLOW_REF": CALLERS[0], "RELEASE_SHA": "c" * 40}
    REF = "ghcr.io/vagarylabs/vagary-platform@sha256:" + "a" * 64

    def statement(self, **over):
        pred = {"run_id": "42", "run_attempt": "1", "repository": "vagarylabs/vagary-platform",
                "workflow_ref": CALLERS[0], "sha": "c" * 40, "artifact": self.REF}
        pred.update(over)
        return {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": ATT_TYPE,
                "subject": [{"name": "ghcr.io/vagarylabs/vagary-platform", "digest": {"sha256": "a" * 64}}],
                "predicate": pred}

    def dsse(self, statement):
        return {"payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}

    def test_the_matching_statement_binds(self):
        self.assertTrue(self.ns["binds_run"](self.statement(), self.REF, self.ENV))

    def test_any_field_off_does_not_bind(self):
        for field, value in [("run_id", "43"), ("run_attempt", "2"), ("repository", "vagarylabs/vagary-voice"),
                             ("workflow_ref", CALLERS[1]), ("sha", "d" * 40), ("artifact", self.REF.replace("a", "b"))]:
            with self.subTest(field=field):
                self.assertFalse(self.ns["binds_run"](self.statement(**{field: value}), self.REF, self.ENV))

    def test_wrong_subject_or_type_does_not_bind(self):
        s = self.statement()
        s["subject"][0]["digest"]["sha256"] = "b" * 64
        self.assertFalse(self.ns["binds_run"](s, self.REF, self.ENV))
        s = self.statement()
        s["predicateType"] = "https://slsa.dev/provenance/v1"
        self.assertFalse(self.ns["binds_run"](s, self.REF, self.ENV))

    def test_statements_reads_a_stream_or_an_array(self):
        a, b = self.dsse(self.statement()), self.dsse(self.statement(run_id="7"))
        stream = json.dumps(a) + "\n" + json.dumps(b) + "\n"
        self.assertEqual(len(list(self.ns["statements"](stream))), 2)
        self.assertEqual(len(list(self.ns["statements"](json.dumps([a, b])))), 2)
        self.assertEqual(list(self.ns["statements"]("")), [])

    def test_log_index_reads_the_bundle_and_refuses_one_without_an_entry(self):
        with tempfile.TemporaryDirectory() as d:
            good, bad = pathlib.Path(d, "g.json"), pathlib.Path(d, "b.json")
            good.write_text(json.dumps({"verificationMaterial": {"tlogEntries": [{"logIndex": "3036041465"}]}}))
            bad.write_text(json.dumps({"verificationMaterial": {"tlogEntries": []}}))
            self.assertEqual(self.ns["log_index"](str(good)), 3036041465)
            with self.assertRaises(SystemExit):
                self.ns["log_index"](str(bad))

    def test_outputs_are_written_only_when_every_artifact_binds(self):
        with tempfile.TemporaryDirectory() as d:
            work = pathlib.Path(d, "work")
            work.mkdir()
            work.joinpath("artifacts.txt").write_text(self.REF + "\n")
            bundle = json.dumps({"verificationMaterial": {"tlogEntries": [{"logIndex": 11}]}})
            work.joinpath("1.sig.json").write_text(bundle)
            work.joinpath("1.att.json").write_text(json.dumps({"verificationMaterial": {"tlogEntries": [{"logIndex": "12"}]}}))
            out, summary = pathlib.Path(d, "out"), pathlib.Path(d, "summary")
            env = dict(self.ENV, SIGN_DIR=d, GITHUB_OUTPUT=str(out), GITHUB_STEP_SUMMARY=str(summary))
            old = {k: os.environ.get(k) for k in env}
            try:
                os.environ.update(env)
                work.joinpath("1.verify-att.json").write_text(json.dumps(self.dsse(self.statement(run_id="999"))))
                with self.assertRaises(SystemExit):
                    self.ns["main"]()
                self.assertFalse(out.exists(), "no output may be written for an unbound artifact")
                work.joinpath("1.verify-att.json").write_text(json.dumps(self.dsse(self.statement())))
                self.ns["main"]()
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            lines = out.read_text().splitlines()
            self.assertEqual(lines[0], "signed=true")
            self.assertEqual(json.loads(lines[1][len("record="):]),
                             [{"ref": self.REF, "sig_log_index": 11, "att_log_index": 12}])


if __name__ == "__main__":
    unittest.main()
