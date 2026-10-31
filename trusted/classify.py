#!/usr/bin/env python3
"""Trusted path classifier for the org ruleset required workflows.

This file is the single source of the classifier. trusted-workflow-integrity.yml and
trusted-protected-paths.yml carry a byte-identical copy inline (a heredoc), because a ruleset
workflow must not read anything from the repository it judges, and the pinned workflow bytes are
the trust root. trusted/tests/test_classify.py fails if an inline copy drifts from this file.

The PR is DATA. Every file is read with `git show <sha>:<path>`; nothing from the PR is executed or
imported. Ratchet constants are read with ast.parse, which parses and never runs the code.

Integrity mode also REPORTS the FL-4 test-weakening predicates: content predicates over the +/- lines of
the PR's diff (a test skip, a retry, continue-on-error, a swallowed test failure, a deleted test with no
successor, a loosened budget or timeout, a new `timeout under test:` exemption). The report never changes the exit
code; see weakening_report().

Timeout-floor mode checks every job's timeout-minutes in the head tree's workflows against the manifest's
completion floor (timeout_floor); see the timeout floor section and run_timeout_floor().

Exit codes: 0 pass, 1 policy refusal (protected-paths, once fail-closed; timeout-floor in enforce mode),
2 integrity error.
"""
import argparse
import ast
import bisect
import fnmatch
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# INTERIM EXCEPTION (the only one): while this is True, trusted-protected-paths REPORTS protected
# classes and does not block. One org account cannot approve its own PR, so a blocking gate would
# deadlock every protected IaC change. Set it to False in the same PR that makes
# verify_vagaris_approval() return "verified" for a real Vagaris signed approval (the G-23 seam);
# from then on "not-yet-available", "missing" and "denied" all fail the job.
INTERIM_REPORT_ONLY = True


class IntegrityError(Exception):
    pass


def verify_vagaris_approval(repo, head_sha, classes):
    """Return the Vagaris signed-approval verdict for (repo, head_sha, classes).

    Contract: one of "verified", "missing", "denied", "not-yet-available". Only "verified" passes
    once INTERIM_REPORT_ONLY is False. The verifier does not exist yet (G-23 seam), so this returns
    "not-yet-available" unconditionally.
    """
    del repo, head_sha, classes
    return "not-yet-available"


def protected_decision(classes, verdict, interim=None):
    """Map (protected classes touched, approval verdict) to (exit_code, message)."""
    interim = INTERIM_REPORT_ONLY if interim is None else interim
    if not classes:
        return 0, "no protected class touched"
    if verdict == "verified":
        return 0, "Vagaris signed approval verified"
    if interim:
        return 0, ("INTERIM report-only: protected classes %s need a Vagaris signed approval "
                   "(verdict: %s); not blocking" % (", ".join(sorted(classes)), verdict))
    return 1, "protected classes %s refused: Vagaris approval verdict %s" % (
        ", ".join(sorted(classes)), verdict)


# --- manifest --------------------------------------------------------------------------------

def validate_manifest(m):
    if not isinstance(m, dict) or m.get("version") != 1:
        raise IntegrityError("manifest: version must be 1")
    entries = [("default", m.get("default"))] + list((m.get("repos") or {}).items())
    for name, e in entries:
        if not isinstance(e, dict):
            raise IntegrityError("manifest: %s entry must be an object" % name)
        prot = e.get("protected")
        if not isinstance(prot, list) or not prot:
            raise IntegrityError("manifest: %s.protected must be a non-empty list" % name)
        for p in prot:
            if not isinstance(p, dict) or not isinstance(p.get("class"), str) or not p["class"]:
                raise IntegrityError("manifest: %s has a protected entry without a class" % name)
            pats = p.get("patterns")
            if not isinstance(pats, list) or not pats or not all(isinstance(x, str) and x for x in pats):
                raise IntegrityError("manifest: %s/%s needs non-empty string patterns" % (name, p["class"]))
        rf = e.get("ratchet_files")
        if not isinstance(rf, list) or not all(isinstance(x, str) and x for x in rf):
            raise IntegrityError("manifest: %s.ratchet_files must be a list of paths" % name)
    validate_timeout_floor(m.get("timeout_floor"))
    sr = m.get("sibling_read")
    if not isinstance(sr, dict) or sr.get("mode") not in ("report", "enforce"):
        raise IntegrityError("manifest: sibling_read.mode must be report or enforce")
    validate_pins(m.get("pins"))
    wl = m.get("workflow_lint")
    if not isinstance(wl, dict) or set(wl) != {"mode"} or wl["mode"] not in ("report", "enforce"):
        raise IntegrityError("manifest: workflow_lint must be {\"mode\": report or enforce}")
    return m


# An exemption names one `uses:` value exactly, plus why and the record that approved it. `repo` and `file` may be "*",
# because a first-party reusable workflow called @main (issue-triage, secret-scan) is called the same way org-wide.
PIN_EXEMPTION_FIELDS = ("repo", "file", "uses", "reason", "record")


def validate_pins(p):
    if not isinstance(p, dict) or p.get("mode") not in ("report", "enforce"):
        raise IntegrityError("manifest: pins.mode must be report or enforce")
    ex = p.get("exemptions")
    if not isinstance(ex, list):
        raise IntegrityError("manifest: pins.exemptions must be a list")
    for i, e in enumerate(ex):
        if not isinstance(e, dict) or set(e) != set(PIN_EXEMPTION_FIELDS) or not all(
                isinstance(e[f], str) and e[f].strip() for f in PIN_EXEMPTION_FIELDS):
            raise IntegrityError("manifest: pins exemption %d needs exactly the non-empty strings %s"
                                 % (i, ", ".join(PIN_EXEMPTION_FIELDS)))


# An exemption names one job exactly: repo, workflow path, job id and the timeout-minutes text it declares (a literal
# or an expression, as the TSV prints it), plus why and the record that approved it. An expression's `$` is written
# as \u0024 in manifest.json: the manifest is inlined into a workflow run block, where Actions would expand it, and
# trusted/render.py refuses to inline one.
FLOOR_EXEMPTION_FIELDS = ("repo", "workflow", "job", "minutes", "reason", "record")


def validate_timeout_floor(tf):
    if not isinstance(tf, dict):
        raise IntegrityError("manifest: timeout_floor must be an object")
    mins = tf.get("minutes")
    if isinstance(mins, bool) or not isinstance(mins, int) or mins < 1:
        raise IntegrityError("manifest: timeout_floor.minutes must be a positive integer")
    if tf.get("mode") not in ("report", "enforce"):
        raise IntegrityError("manifest: timeout_floor.mode must be report or enforce")
    ex = tf.get("exemptions")
    if not isinstance(ex, list):
        raise IntegrityError("manifest: timeout_floor.exemptions must be a list")
    for i, e in enumerate(ex):
        if not isinstance(e, dict) or not all(isinstance(e.get(f), str) and e[f].strip()
                                              for f in FLOOR_EXEMPTION_FIELDS):
            raise IntegrityError("manifest: timeout_floor exemption %d needs non-empty strings %s"
                                 % (i, ", ".join(FLOOR_EXEMPTION_FIELDS)))
        if not _FLOOR_FILE.match(e["workflow"]):
            raise IntegrityError("manifest: timeout_floor exemption %d: workflow must be a "
                                 ".github/workflows/<name>.yml or .yaml path" % i)


def repo_entry(m, repo):
    return (m.get("repos") or {}).get(repo) or m["default"]


def classes_for(entry, path):
    """Every class whose pattern matches path. fnmatch '*' crosses '/', which over-includes."""
    out = set()
    for p in entry["protected"]:
        if any(fnmatch.fnmatchcase(path, pat) for pat in p["patterns"]):
            out.add(p["class"])
    if path in entry["ratchet_files"]:
        out.add("ci-judge")
    return out


def classify(entry, changes):
    """changes: [(status, path)] -> [(status, path, sorted classes)] for protected paths only."""
    rows = []
    for status, path in changes:
        cls = classes_for(entry, path)
        if cls:
            rows.append((status, path, sorted(cls)))
    return rows


# --- ratchet constants -----------------------------------------------------------------------

def ratchet_constants(source, label):
    """Top-level NAME = value assignments, as {name: normalised source}. Parsed, never executed."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise IntegrityError("ratchet %s does not parse: %s" % (label, exc))
    out = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Name):
                out[t.id] = ast.dump(node.value)
    return out


def diff_constants(base, head):
    return {
        "added": sorted(set(head) - set(base)),
        "removed": sorted(set(base) - set(head)),
        "changed": sorted(k for k in set(base) & set(head) if base[k] != head[k]),
    }


# --- git (data only) -------------------------------------------------------------------------

def git(*args):
    r = subprocess.run(("git",) + args, capture_output=True, text=True)
    if r.returncode != 0:
        raise IntegrityError("git %s failed: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def blob(sha, path):
    """File text at sha, or None when the path is absent there."""
    r = subprocess.run(["git", "cat-file", "-e", "%s:%s" % (sha, path)], capture_output=True)
    if r.returncode != 0:
        return None
    return git("show", "%s:%s" % (sha, path))


def resolve_head(base, head):
    """The timeout-floor mode reads the head tree only: base, when given, must be an exact SHA, but it is never
    resolved and need not be in the object store (the job checks out the head alone, fetch-depth 1)."""
    for label, sha in (("base", base), ("head", head)):
        if (sha is not None or label == "head") and not SHA_RE.match(sha or ""):
            raise IntegrityError("%s is not an exact 40-hex SHA: %r" % (label, sha))
    git("cat-file", "-e", "%s^{commit}" % head)


def resolve(base, head):
    for label, sha in (("base", base), ("head", head)):
        if not SHA_RE.match(sha or ""):
            raise IntegrityError("%s is not an exact 40-hex SHA: %r" % (label, sha))
        git("cat-file", "-e", "%s^{commit}" % sha)
    return git("merge-base", base, head).strip()


def changed_paths(mb, head):
    out = []
    for line in git("diff", "--name-status", "--no-renames", "-z", mb, head).split("\0"):
        if line:
            out.append(line)
    # -z yields status and path as alternating fields.
    return [(out[i], out[i + 1]) for i in range(0, len(out) - 1, 2)]


# --- FL-4: test-weakening predicates (report-only) -------------------------------------------
#
# Effect predicates over the +/- lines of the PR's diff, read as data through `git diff` and `git cat-file`.
# Every rule is scoped by a positive file-type allow-list, so a doc that quotes a pattern is never
# scanned. Token rules count NET-NEW matches: an added line identical (whitespace aside) to a removed
# line in the same file is a move, and a rule's added matches are offset by its removed matches.
# Numeric rules pair a key's removed and added values in file order and report only the direction that
# accepts more (a higher timeout, retry or upper bound; a lower coverage floor, assertion count or lower
# bound). A job's own timeout-minutes raised no higher than the completion floor (manifest timeout_floor.minutes) is
# listed as a floor raise, not a weakening. A `vagaris-quarantine: <id>` or `vagaris-approval: <id>` marker on or
# just above the line, or the same as a commit trailer, is LISTED with the finding and never clears it: no
# quarantine or approval verifier exists yet. Whether a workflow job backs a required check is not readable
# with this job's token, so continue-on-error is reported on every job and step.
#
# The PR decides how much git prints (a huge file, thousands of paths, a long commit message), so every git read
# of the scan runs against ONE budget (ScanBudget): wall time to a single deadline and a total of bytes read
# from git. Bytes are counted before they are kept, a file whose blob is over WEAKENING_MAX_BLOB_BYTES is never
# diffed (git would load it whole), and git is killed at a limit. Running out is INCOMPLETE, never a clean pass.
# Work derived from what was read is bounded as well: only the LISTED findings are enriched from the head file
# (job/step level, inline references), each names at most WEAKENING_MAX_REFS references, and a head-side line over
# WEAKENING_MAX_LINE is not read.

WEAKENING_VERSION = "fl4-v1"
WEAKENING_EFFECT = "ci-policy:test-weakening"
WEAKENING_MAX_FILES = 3000
WEAKENING_MAX_PATCH_BYTES = 2000000     # one file's diff; a larger one is dropped as it streams: INCOMPLETE
WEAKENING_MAX_BLOB_BYTES = 8000000      # either side of a file larger than this is not diffed: INCOMPLETE
WEAKENING_MAX_TOTAL_BYTES = 32000000    # everything the scan reads from git, kept or skipped
WEAKENING_MAX_CENSUS_BYTES = 4000000    # the changed-file list (about 30k files)
WEAKENING_MAX_TRAILER_BYTES = 1000000   # commit messages read for trailer references
WEAKENING_MAX_LINE = 4000          # longer lines (minified or generated) are not regex-scanned: INCOMPLETE
WEAKENING_DEADLINE_SECONDS = 120   # the whole scan, every git call included; the job's own timeout is 10 minutes
WEAKENING_MAX_LISTED = 200        # findings listed; only these are enriched from the head file and given refs
WEAKENING_MAX_REFS = 5             # references named per finding; the rest are counted
WEAKENING_MAX_FINDINGS = 5000      # findings kept; reaching it stops the scan after that file: INCOMPLETE
WEAKENING_MAX_WALK = 10000         # lines coe_level walks up to a step or job (the fleet's longest workflow: 3234)
WEAKENING_MAX_ANNOTATIONS = 8      # GitHub keeps 10 warnings per step: 2 stay free for the pointers below

_JS_EXT = re.compile(r"\.(?:[cm]?[jt]sx?|vue|svelte)$")
_TEST_DIR = re.compile(r"(?:^|/)(?:tests?|__tests__|e2e|specs?)/")
_NOT_TEST = re.compile(r"(?:^|/)(?:fixtures?|__fixtures__|__snapshots__|snapshots|testdata|__mocks__)/")
# The runners' own default forms plus the fleet's conventions (git ls-files across the fleet, 2026-10-15).
_TEST_FILE = re.compile(
    # vitest, jest, playwright, mocha: a.test.ts, b.spec.jsx, c.e2e.ts; vps-ansible's x.test.sh and the
    # CI-run scripts/restic-restore-test-emit.selftest.sh
    r"\.(?:test|spec|e2e|selftest)\.(?:[cm]?[jt]sx?|py|sh|bash)$"
    # go test, pytest, ExUnit (vagary-voice voice-gateway/test/**/*_test.exs), node --test's *_test.js,
    # minitest (vagary-voice sdks/ruby, Rakefile test/**/*_test.rb)
    r"|_test\.(?:go|py|exs|rb|[cm]?[jt]sx?)$"
    # Pester's default *.Tests.ps1 (vagaris cell-broker, run by vagary-node-windows.yml); SwiftPM/XCTest
    # Tests/<Target>Tests/*Tests.swift (vagary-core services/client-sdks/ios)
    r"|\.Tests\.ps1$|(?:^|/)Tests/(?:[^/]+/)*[^/]+Tests?\.swift$"
    r"|(?:^|/)test_[^/]*\.py$|(?:^|/)test-[^/]*\.(?:py|sh|bash|[cm]?[jt]s)$"
    # Any code file under a test directory: node --test's default **/test/** (vagary-core runs
    # services/identity/test/*.mjs this way), jest's __tests__, e2e harnesses; python and shell suites.
    r"|(?:^|/)(?:tests?|__tests__|e2e)/(?:[^/]+/)*[^/]+\.(?:[cm]?[jt]sx?|py|sh|bash)$"
    # promtool rule tests (vps-ansible prometheus-rules/tests/*.test.yml)
    r"|(?:^|/)tests?/(?:[^/]+/)*[^/]+\.test\.ya?ml$"
    r"|\.bats$")
_JS_TEST_CONFIG = re.compile(r"(?:^|/)(?:vitest|vite|jest|playwright)[\w.-]*\.(?:config|workspace)[\w.-]*\.[cm]?[jt]s$")
_PLAYWRIGHT_CONFIG = re.compile(r"(?:^|/)playwright[\w.-]*\.config[\w.-]*\.[cm]?[jt]s$")
_COVERAGE_RC = re.compile(r"(?:^|/)(?:package\.json|\.nycrc(?:\.json|\.ya?ml)?|\.c8rc(?:\.json|\.ya?ml)?)$")
_PY_TEST_CONFIG = re.compile(r"(?:^|/)(?:pytest\.ini|pyproject\.toml|setup\.cfg|tox\.ini|\.coveragerc)$")
_PYTEST_INI = re.compile(r"(?:^|/)pytest\.ini$")
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$|(?:^|/)action\.ya?ml$")
_SHELL = re.compile(
    r"\.(?:sh|bash|zsh|mk)$"
    r"|(?:^|/)(?:Makefile|GNUmakefile|makefile|justfile|Justfile|package\.json|tox\.ini)$"
    r"|(?:^|/)(?:Taskfile|lefthook)[\w.-]*\.ya?ml$|(?:^|/)\.pre-commit-config\.ya?ml$"
    r"|^\.githooks/|^\.husky/")


def is_test_file(path):
    if _NOT_TEST.search(path) or path.rsplit("/", 1)[-1] == "__init__.py":
        return False
    return bool(_TEST_FILE.search(path))


def path_scopes(path):
    """The rule scopes a path belongs to. A path in no scope is never content-scanned."""
    s = set()
    test = is_test_file(path)
    js_test_config = bool(_JS_TEST_CONFIG.search(path))
    if _JS_EXT.search(path) and not _NOT_TEST.search(path) and (test or _TEST_DIR.search(path)):
        s.add("js-testlike")
    if js_test_config:
        s.add("js-test-config")
    if _PLAYWRIGHT_CONFIG.search(path):
        s.add("playwright-config")
    if js_test_config or _COVERAGE_RC.search(path):
        s.add("coverage-config")
    if path.endswith(".py"):
        s.add("py")
    if _PY_TEST_CONFIG.search(path):
        s.add("py-test-config")
    if _PYTEST_INI.search(path):
        s.add("pytest-ini")
    if path.endswith("_test.go"):
        s.add("go-test")
    if path.endswith(".bats"):
        s.add("bats")
    if _WORKFLOW.search(path):
        s.update(("workflow", "shell"))
    if _SHELL.search(path):
        s.add("shell")
    if test or js_test_config or "pytest-ini" in s:
        s.add("testlike-any")
    return s


# A leading `*/` and closed `/* ... */` blocks: code after them is not a comment (`/**/ it.skip(...)`).
_LEADING_BLOCK_COMMENTS = re.compile(r"(?:\*/)?\s*(?:/\*.*?\*/\s*)*")


def is_comment(text):
    s = text.strip()
    if not s:
        return False
    rest = s[_LEADING_BLOCK_COMMENTS.match(s).end():]
    if not rest or rest.startswith(("#", "//", "/*", "<!--")):
        return True
    # ` * text` inside a block comment; a shell case arm `*) npm test || true ;;` is code.
    return rest == "*" or rest.startswith(("* ", "*\t", "**"))


# Token rules -------------------------------------------------------------------------------

_SKIP_JS = re.compile(
    r"(?<![\w$.])(?P<tok>(?:it|test|describe|suite|context|bench)"
    r"(?:\.(?:concurrent|sequential|shuffle|each|for|describe|serial|parallel))*"
    r"\.(?:skip|todo|skipIf|runIf|fixme|only)"
    r"|xit|xtest|xdescribe|xcontext|xsuite|fit|fdescribe|ftest)\b(?=\s*[.(`])")
_SKIP_PY = re.compile(
    r"(?P<tok>\bpytest\.mark\.(?:skip|skipif|xfail)\b|\bpytest\.(?:skip|xfail)\s*\(|"
    r"@unittest\.(?:skip|skipIf|skipUnless|expectedFailure)\b|\bself\.skipTest\s*\(|"
    r"\braise\s+(?:unittest\.)?SkipTest\b)")
_SKIP_GO = re.compile(r"\bt\.(?P<tok>Skip|SkipNow|Skipf)\s*\(")
_SKIP_BATS = re.compile(r"^\s*(?P<tok>skip)\b")
_FLAKY_PY = re.compile(r"(?P<tok>@pytest\.mark\.flaky)\b")
_SLOW_JS = re.compile(r"(?<![\w$.])(?P<tok>test\.slow)\s*\(")
_HAS_ASSERTIONS = re.compile(r"\b(?P<tok>expect\.hasAssertions)\s*\(")
# The test-bounds (K2) exemption: a short wall-clock bound marked as the behaviour under test. A net-new mark clears
# a finding there, so it is listed here as a weakening too (root's K2 condition 3).
_BOUND_MARK = re.compile(r"(?P<tok>timeout under test:)")
_COE = re.compile(r"^\s*(?:-\s+)?continue-on-error\s*:\s*(?P<v>[^#]*?)\s*(?:#.*)?$")

_SWALLOW = re.compile(r"\|\|\s*(?P<s>true\b|:(?=\s|$|[;)\"'])|exit\s+0\b|echo\b|printf\b)")
_SEGMENT_SEP = re.compile(r"\|\||&&|;|\$\(|`|\(|\)")
_RUNNER = re.compile(
    r"(?P<r>vitest|jest|mocha|ava|playwright\s+test|pytest|py\.test|tox|nox|go\s+test|cargo\s+test|bats"
    r"|node\s+--test|deno\s+test|bun\s+test|unittest"
    r"|(?:npm|pnpm|yarn|bun)(?:\s+(?:-r|--recursive|-w|--workspace-root|--if-present|--silent|-s"
    r"|--filter(?:=|\s+)\S+|-F\s+\S+|-C\s+\S+|--dir(?:=|\s+)\S+))*\s+(?:run\s+)?(?:test|check)(?:[:\w.-]*)"
    r"|turbo\s+(?:run\s+)?(?:test|check)[\w:.-]*|make\s+(?:-\S+\s+)*(?:test|check)[\w.-]*"
    r"|ansible-lint|shellcheck|actionlint|yamllint|eslint|tsc|ruff|mypy|semgrep|gitleaks|trufflehog)\b")
_WRAPPERS = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+|(?:env|sudo|time|command|exec)\s+|nice(?:\s+-n\s*-?\d+)?\s+"
    r"|timeout\s+(?:-\S+\s+)*\S+\s+|xvfb-run\s+(?:-\S+\s+)*|npx\s+(?:--yes\s+|-y\s+)?|bunx\s+"
    r"|pnpm\s+(?:exec|dlx)\s+|(?:pnpm|yarn)\s+(?=(?:vitest|jest|mocha|playwright|eslint|tsc)\b)"
    r"|(?:uv|poetry|pipenv|hatch)\s+run\s+|python3?(?:\.\d+)?\s+-m\s+|(?:\./)?node_modules/\.bin/)+")


def safe_tok(text):
    """A matched token reduced to a fixed character set: PR text never reaches markdown or a command."""
    return re.sub(r"[^A-Za-z0-9_ .:@/|-]", "", " ".join(str(text).split()))[:80].strip()


def _tokens(rx):
    def match(line):
        return [safe_tok(m.group("tok").rstrip().rstrip("(")) for m in rx.finditer(line)]
    return match


def coe_tokens(line):
    m = _COE.match(line)
    if not m:
        return []
    v = m.group("v").strip().strip("\"'").lower()
    if v in ("false", ""):
        return []
    return ["continue-on-error: true" if v == "true" else "continue-on-error: <expression>"]


_INTERPRETER = re.compile(r"^(?:python(?:3(?:\.\d+)?)?|bash|sh|zsh|node|bats)$")
_SCRIPT_ROOT = re.compile(r"^(?:\$\{?GITHUB_WORKSPACE\}?/|\./)+")


def test_script(cand, command_pos):
    """The test file that cand runs as `<interpreter> [flags] <path>` or as a bare path, or None.

    The fleet mostly runs tests this way (python3 scripts/test-*.py, bash test/run-*.sh). A bare path counts
    in command position (segment start, after `run:`) or with a ./ or $GITHUB_WORKSPACE/ prefix; after a
    quote it is more likely an argument (git diff -- "tests/test_x.py"), so there it needs an interpreter.
    """
    words = cand.split(None, 6)
    if not words:
        return None
    i = 0
    if _INTERPRETER.match(words[0].strip("\"'").rsplit("/", 1)[-1]):
        i = 1
        while i < len(words) and words[i].startswith("-"):
            i += 1
        if i >= len(words):
            return None
    elif not command_pos and not _SCRIPT_ROOT.match(words[0].lstrip("\"'")):
        return None
    path = _SCRIPT_ROOT.sub("", words[i].strip("\"'"))
    return path if path and is_test_file(path) else None


def swallowed_runner(line):
    """The test or check command whose failure a `|| true`-style tail swallows, or None."""
    sep_ends = [s.end() for s in _SEGMENT_SEP.finditer(line)]  # one pass: segments stay linear in the line
    for m in _SWALLOW.finditer(line):
        i = bisect.bisect_right(sep_ends, m.start()) - 1
        segment = line[(sep_ends[i] if i >= 0 else 0): m.start()]
        for element in segment.split("|"):
            starts = [(0, True)] + [(x.end(), x.group().startswith("run"))
                                    for x in re.finditer(r"[\"']|\brun:\s*", element)]
            for st, command_pos in starts:
                cand = _WRAPPERS.sub("", element[st:].lstrip(" \t\"'"))
                r = _RUNNER.match(cand)
                if r:
                    return safe_tok("%s || %s" % (r.group("r"), m.group("s")))
                script = test_script(cand, command_pos)
                if script:
                    return safe_tok("%s || %s" % (script, m.group("s")))
    return None


def swallow_tokens(line):
    t = swallowed_runner(line)
    return [t] if t else []


# (rule, scope, matcher, direction): "add" flags net-new added matches, "remove" net removed ones.
TOKEN_RULES = [
    ("test-skip", "js-testlike", _tokens(_SKIP_JS), "add"),
    ("test-skip", "py", _tokens(_SKIP_PY), "add"),
    ("test-skip", "go-test", _tokens(_SKIP_GO), "add"),
    ("test-skip", "bats", _tokens(_SKIP_BATS), "add"),
    ("test-retry", "py", _tokens(_FLAKY_PY), "add"),
    ("budget-loosened", "js-testlike", _tokens(_SLOW_JS), "add"),
    ("budget-loosened", "js-testlike", _tokens(_HAS_ASSERTIONS), "remove"),
    ("bound-exempted", "testlike-any", _tokens(_BOUND_MARK), "add"),
    ("continue-on-error", "workflow", coe_tokens, "add"),
    ("swallowed-failure", "shell", swallow_tokens, "add"),
]

# Numeric rules -----------------------------------------------------------------------------
# (rule, family, scope, regex with groups k and v, direction, absent)
# direction "up": a higher value accepts more; "down": a lower value accepts more.
# absent: the baseline for an added key with no removed counterpart (0 for retries: none by default),
# "removal" when deleting the key loosens (a coverage floor, an assertion count), else None.
NUMERIC_RULES = [
    ("test-retry", "retry", "js-test-config", r"\b(?P<k>retry|retries)\s*:\s*(?P<v>[^,}\n]+)", "up", 0),
    ("test-retry", "retry", "js-testlike",
     r"\.configure\s*\(\s*\{[^{}\n]*?\b(?P<k>retries)\s*:\s*(?P<v>[^,}\n]+)", "up", 0),
    ("test-retry", "retry", "js-testlike",
     r"(?<![\w$.])(?:it|test|describe|suite|bench)(?:\.\w+)*\s*\(\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|\w+)"
     r"\s*,\s*\{[^{}\n]*?\b(?P<k>retry)\s*:\s*(?P<v>[^,}\n]+)", "up", 0),
    ("test-retry", "retry", "js-testlike",
     r"\b(?:this|jest)\.(?P<k>retries|retryTimes)\s*\(\s*(?P<v>[^,)\n]+)", "up", 0),
    ("test-retry", "retry", "shell",
     r"\b(?:vitest|playwright|jest)\b[^\n]*?(?P<k>--retry|--retries)(?:=|\s+)(?P<v>\d+)", "up", 0),
    ("test-retry", "retry", "shell", r"(?P<k>--reruns)(?:=|\s+)(?P<v>\d+)", "up", 0),
    ("test-retry", "retry", "py-test-config", r"(?P<k>--reruns)(?:=|\s+)(?P<v>\d+)", "up", 0),
    ("test-retry", "retry", "py-test-config", r"^\s*(?P<k>reruns)\s*=\s*(?P<v>\d+)", "up", 0),
    ("budget-loosened", "timeout", "js-test-config",
     r"\b(?P<k>testTimeout|hookTimeout|teardownTimeout)\s*:\s*(?P<v>[^,}\n]+)", "up", None),
    ("budget-loosened", "timeout", "js-testlike",
     r"\b(?P<k>testTimeout|hookTimeout|teardownTimeout)\s*:\s*(?P<v>[^,}\n]+)", "up", None),
    ("budget-loosened", "timeout", "js-testlike",
     r"\b(?P<k>jest\.setTimeout|this\.timeout|test\.setTimeout)\s*\(\s*(?P<v>[^,)\n]+)", "up", None),
    # The per-test options form, it('x', { timeout: 60_000 }, ...): the same shape as the retry option above.
    ("budget-loosened", "timeout", "js-testlike",
     r"(?<![\w$.])(?:it|test|describe|suite|bench)(?:\.\w+)*\s*\(\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|\w+)"
     r"\s*,\s*\{[^{}\n]*?\b(?P<k>timeout)\s*:\s*(?P<v>[^,}\n]+)", "up", None),
    ("budget-loosened", "timeout", "playwright-config", r"\b(?P<k>timeout)\s*:\s*(?P<v>[^,}\n]+)", "up", None),
    ("budget-loosened", "timeout", "py",
     r"@pytest\.mark\.(?P<k>timeout)\s*\(\s*(?:timeout\s*=\s*)?(?P<v>[^,)\n]+)", "up", None),
    ("budget-loosened", "timeout", "pytest-ini", r"^\s*(?P<k>timeout)\s*=\s*(?P<v>[^\s#;]+)", "up", None),
    # A workflow job's or step's timeout-minutes. A raise of a JOB's own timeout-minutes to at most the completion
    # floor (manifest timeout_floor.minutes) is a floor raise, not a weakening (floor_raises); a step's raise stays a
    # weakening: the floor is per job.
    ("budget-loosened", "timeout", "workflow", r"^\s*(?:-\s+)?(?P<k>timeout-minutes)\s*:\s*(?P<v>[^#\n]+)", "up", None),
    ("budget-loosened", "coverage", "coverage-config",
     r"[\"']?\b(?P<k>lines|branches|functions|statements)[\"']?\s*:\s*(?P<v>[^,}\n]+)", "down", "removal"),
    ("budget-loosened", "coverage", "py-test-config",
     r"\b(?P<k>fail_under|fail-under)\s*=\s*(?P<v>[^\s#;]+)", "down", "removal"),
    ("budget-loosened", "coverage", "shell", r"(?P<k>--cov-fail-under|--fail-under)(?:=|\s+)(?P<v>[\d.]+)",
     "down", "removal"),
    ("budget-loosened", "coverage", "py-test-config",
     r"(?P<k>--cov-fail-under|--fail-under)(?:=|\s+)(?P<v>[\d.]+)", "down", "removal"),
    ("budget-loosened", "assertions", "js-testlike", r"\bexpect\.(?P<k>assertions)\s*\(\s*(?P<v>[^,)\n]+)",
     "down", "removal"),
    ("budget-loosened", "bound", "js-testlike",
     r"\.(?P<k>toBeLessThan|toBeLessThanOrEqual)\s*\(\s*(?P<v>[^,)\n]+)", "up", None),
    ("budget-loosened", "bound", "js-testlike",
     r"\.(?P<k>toBeGreaterThan|toBeGreaterThanOrEqual)\s*\(\s*(?P<v>[^,)\n]+)", "down", None),
    # Any identifier, kept only when it names a budget (numeric_findings): one bounded identifier per word
    # start keeps the match linear, where a "...budget..." pattern backtracks quadratically inside a long word.
    ("budget-loosened", "budget", "testlike-any",
     r"(?<![A-Za-z0-9_])(?P<k>[A-Za-z0-9_]+)\s*[:=]\s*(?P<v>[^,;{}\n]+)", "up", None),
]
NUMERIC_RULES = [(r, f, s, re.compile(x), d, a) for r, f, s, x, d, a in NUMERIC_RULES]

_NUM = r"\d[\d_]*(?:\.\d+)?"
_PRODUCT = re.compile(r"^%s(?:\s*\*\s*%s)*$" % (_NUM, _NUM))


def parse_num(raw):
    """A literal number (products like 30 * 1000 allowed), 0 for false/null/undefined/None, else None."""
    v = re.split(r"//|/\*|#", raw, 1)[0].strip().rstrip(",;)}]").strip().strip("\"'").strip()
    if v.lower() in ("false", "null", "undefined", "none"):
        return 0.0
    if not _PRODUCT.match(v):
        return None
    out = 1.0
    for part in v.split("*"):
        out *= float(part.strip().replace("_", ""))
    return out


def _fmt(n):
    return "non-literal" if n is None else ("%d" % n if n == int(n) else "%g" % n)


def safe_key(k):
    return re.sub(r"[^A-Za-z0-9_.:-]", "", k)[:64]


# Bounded git reads -------------------------------------------------------------------------

class ScanBudget:
    """What the FL-4 scan may still spend: wall time to one deadline, and bytes read from git."""

    def __init__(self, seconds, max_bytes):
        self.deadline = time.monotonic() + seconds
        self.bytes_left = max_bytes

    def time_left(self):
        return self.deadline - time.monotonic()


class Exhausted(Exception):
    """A git read stopped at a limit: "time" or "bytes" (the scan's budget), or "cap" (that call's own limit).
    partial holds what was read before the stop."""

    def __init__(self, kind, partial=b""):
        Exception.__init__(self, kind)
        self.kind = kind
        self.partial = partial


_READ_CHUNK = 65536


def git_chunks(budget, args, cap=None, stdin=None):
    """Yield git's stdout in chunks; raise Exhausted at the deadline, the byte budget or cap, and kill git.

    One byte past a limit is the most ever read and it is never kept, so memory follows the limit, not the PR.
    A git that fails raises IntegrityError. stderr goes to a file, so an undrained pipe cannot stall git.
    """
    if budget.time_left() <= 0:
        raise Exhausted("time")
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(("git",) + tuple(args), stdout=subprocess.PIPE, stderr=err,
                                stdin=subprocess.DEVNULL if stdin is None else stdin)
        sel = selectors.DefaultSelector()
        try:
            sel.register(proc.stdout, selectors.EVENT_READ)
            taken = 0
            while True:
                left = budget.time_left()
                if left <= 0:
                    raise Exhausted("time")
                if not sel.select(left):
                    continue
                cap_left = None if cap is None else cap - taken
                room = budget.bytes_left if cap_left is None else min(budget.bytes_left, cap_left)
                data = os.read(proc.stdout.fileno(), max(1, min(_READ_CHUNK, room)))
                if not data:
                    break
                if len(data) > room:
                    raise Exhausted("cap" if cap_left is not None and cap_left <= budget.bytes_left else "bytes")
                taken += len(data)
                budget.bytes_left -= len(data)
                yield data
            try:
                code = proc.wait(timeout=max(budget.time_left(), 0.5))
            except subprocess.TimeoutExpired:
                raise Exhausted("time")
            if code != 0:
                err.seek(0)
                raise IntegrityError("git %s failed: %s" % (args[0], err.read(2000).decode("utf-8", "replace").strip()))
        finally:
            sel.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()


def git_read(budget, args, cap=None, stdin=None):
    """git's whole stdout as bytes under the same limits; an Exhausted carries what was read before the stop."""
    parts = []
    try:
        for chunk in git_chunks(budget, args, cap, stdin):
            parts.append(chunk)
    except Exhausted as exc:
        exc.partial = b"".join(parts)
        raise
    return b"".join(parts)


_NULL_SHA = "0" * 40


def census(budget, mb, head):
    """([(status, old path, new path, old blob, new blob)], stop kind or None): the changed files with rename
    detection, old == new except for R and C. On a stop the complete records read before it are returned."""
    stop = None
    try:
        raw = git_read(budget, ("diff", "--raw", "--no-abbrev", "-z", "-M", mb, head), WEAKENING_MAX_CENSUS_BYTES)
    except Exhausted as exc:
        raw, stop = exc.partial, exc.kind
    fields = raw.split(b"\0")
    if stop:
        fields = fields[:-1]  # the last field may be cut short
    rows, i = [], 0
    while i < len(fields) and fields[i].startswith(b":"):
        meta = fields[i].decode("ascii").split()  # :<old mode> <new mode> <old blob> <new blob> <status>
        st = meta[4][:1]
        n = 3 if st in ("R", "C") else 2
        if i + n > len(fields):
            break
        rows.append((st, fields[i + 1].decode("utf-8"), fields[i + n - 1].decode("utf-8"), meta[2], meta[3]))
        i += n
    return rows, stop


def blob_sizes(budget, shas):
    """{blob: size} for the blobs among shas (a submodule commit is absent), from one git cat-file process whose
    input is a file, so no pipe can deadlock."""
    want = sorted({s for s in shas if s != _NULL_SHA})
    if not want:
        return {}
    with tempfile.TemporaryFile() as fh:
        fh.write(("\n".join(want) + "\n").encode("ascii"))
        fh.flush()
        fh.seek(0)
        raw = git_read(budget, ("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
                       120 * len(want), fh)
    sizes = {}
    for line in raw.decode("ascii", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
            sizes[parts[0]] = int(parts[2])
    return sizes


_DIFF_ARGS = ("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--text", "-M", "--unified=1")
_SECTION = b"\ndiff --git "


def diff_args(mb, head, paths):
    return _DIFF_ARGS + (mb, head, "--") + tuple(":(literal)" + p for p in sorted(paths))


def _first_line(buf):
    j = buf.find(b"\n")
    return bytes(buf[: j if 0 <= j < 8192 else 8192]).decode("utf-8", "replace")


def _section(data, dropped, cap):
    if dropped is not None:
        return dropped, None
    if len(data) > cap:
        return _first_line(data), None
    return _first_line(data), bytes(data).decode("utf-8", "replace")


def patch_sections(chunks, cap):
    """Split a streamed `git diff` into (header line, patch text, or None for a section over cap bytes).

    Every diff body line starts with ' ', '+', '-', '@' or a backslash, so a line starting `diff --git ` is a
    header. An over-cap section is dropped as it streams: memory stays under cap plus one chunk.
    """
    keep = len(_SECTION) - 1
    buf, dropped, start = bytearray(), None, 0
    for chunk in chunks:
        buf += chunk
        while True:
            i = buf.find(_SECTION, start)
            if i < 0:
                break
            yield _section(buf[: i + 1], dropped, cap)
            del buf[: i + 1]
            dropped, start = None, 0
        if dropped is None and len(buf) > cap:
            dropped = _first_line(buf)
        if dropped is not None:
            del buf[: max(len(buf) - keep, 0)]
        start = max(len(buf) - keep, 0)
    if buf or dropped is not None:
        yield _section(buf, dropped, cap)


_PATHSPEC_BYTES = 65536  # one git call's pathspec, far under the OS argument limit


def pathspec_batches(items):
    """items [(key, paths)] grouped so one call's pathspec stays under _PATHSPEC_BYTES; an item is never split."""
    batch, size = [], 0
    for key, paths in items:
        n = sum(len(p.encode("utf-8")) + 11 for p in paths)
        if batch and size + n > _PATHSPEC_BYTES:
            yield batch
            batch, size = [], 0
        batch.append((key, paths))
        size += n
    if batch:
        yield batch


def parse_patch(patch):
    """(added [(new line no, text)], removed [(old line no, text)], first new-side hunk line)."""
    added, removed, first = [], [], None
    lines = patch.split("\n")
    i = 0
    hunk = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    while i < len(lines):
        m = hunk.match(lines[i])
        i += 1
        if not m:
            continue
        old_no, old_left = int(m.group(1)), int(m.group(2) or 1)
        new_no, new_left = int(m.group(3)), int(m.group(4) or 1)
        if first is None:
            first = max(new_no, 1)
        while (old_left > 0 or new_left > 0) and i < len(lines):
            ln = lines[i]
            i += 1
            if ln.startswith("\\"):
                continue
            tag, text = ln[:1], ln[1:]
            if tag == "+":
                added.append((new_no, text))
                new_no += 1
                new_left -= 1
            elif tag == "-":
                removed.append((old_no, text))
                old_no += 1
                old_left -= 1
            else:
                old_no += 1
                new_no += 1
                old_left -= 1
                new_left -= 1
    return added, removed, first


# Findings ----------------------------------------------------------------------------------

def _finding(rule, path, line, detail):
    return {"rule": rule, "effect": WEAKENING_EFFECT, "path": path, "line": line, "detail": detail, "refs": []}


def token_findings(path, scopes, added, removed):
    added = [(n, t) for n, t in added if not is_comment(t)]
    removed = [t for _, t in removed if not is_comment(t)]
    # An added line equal (whitespace aside) to a removed one is a move or re-indent: both drop out.
    unmatched = {}
    for t in removed:
        unmatched[t.strip()] = unmatched.get(t.strip(), 0) + 1
    fresh = []
    for n, t in added:
        if unmatched.get(t.strip()):
            unmatched[t.strip()] -= 1
        else:
            fresh.append((n, t))
    gone = []
    for t in removed:
        if unmatched.get(t.strip()):
            unmatched[t.strip()] -= 1
            gone.append(t)
    out = []
    for rule, scope, match, direction in TOKEN_RULES:
        if scope not in scopes:
            continue
        add_hits = [(n, tok) for n, t in fresh for tok in match(t)]
        rem_hits = [tok for t in gone for tok in match(t)]
        if direction == "add":
            for n, tok in add_hits[len(rem_hits):]:
                out.append(_finding(rule, path, n, "adds `%s`" % tok))
        else:
            for tok in rem_hits[len(add_hits):]:
                out.append(_finding(rule, path, None, "removes `%s`" % tok))
    return out


FLOOR_RAISE_RULE = "timeout-floor-raise"
FLOOR_RAISE_EFFECT = "ci-policy:completion-floor"


def numeric_findings(path, scopes, added, removed, first_line, floor=None):
    """floor: the completion floor in minutes, or None. A timeout-minutes raise to at most it is a floor-raise
    CANDIDATE (the finding carries "raise"): only floor_raises() can make it one, once the head file shows the line is
    a job's own timeout-minutes. Until then, and for a step's, it is an ordinary weakening."""
    out = []
    for rule, family, scope, rx, direction, absent in NUMERIC_RULES:
        if scope not in scopes:
            continue
        olds, news = {}, {}
        for _, t in removed:
            if not is_comment(t):
                for m in rx.finditer(t):
                    if family != "budget" or "budget" in m.group("k").lower():
                        olds.setdefault(m.group("k"), []).append(parse_num(m.group("v")))
        for n, t in added:
            if not is_comment(t):
                for m in rx.finditer(t):
                    if family != "budget" or "budget" in m.group("k").lower():
                        news.setdefault(m.group("k"), []).append((n, parse_num(m.group("v"))))
        for k in sorted(set(olds) | set(news)):
            ov, nv = olds.get(k, []), news.get(k, [])
            key = safe_key(k)
            # TODO(next PR): pairs by file order across jobs; a deleted job at 2 plus an added one at 6 reads as a raise.
            for i in range(max(len(ov), len(nv))):
                if i < len(ov) and i < len(nv):
                    o, (n, v) = ov[i], nv[i]
                    if v is None and o is not None and absent == 0:
                        out.append(_finding(rule, path, n, "changes %s `%s` from %s to a non-literal value"
                                            % (family, key, _fmt(o))))
                        continue
                    if o is None or v is None:
                        continue
                    if (direction == "up" and v > o) or (direction == "down" and v < o):
                        verb = "raises" if direction == "up" else "lowers"
                        f = _finding(rule, path, n, "%s %s `%s` %s -> %s" % (verb, family, key, _fmt(o), _fmt(v)))
                        if k == "timeout-minutes" and floor is not None and v <= floor:
                            f["raise"] = v
                        out.append(f)
                elif i < len(nv):
                    n, v = nv[i]
                    if absent == 0 and (v is None or v > 0):
                        out.append(_finding(rule, path, n, "sets %s `%s` to %s (default 0)" % (family, key, _fmt(v))))
                elif absent == "removal":
                    out.append(_finding(rule, path, first_line, "removes %s `%s` (was %s)" % (family, key, _fmt(ov[i]))))
    return out


def floor_raises(budget, findings, heads, floor, incomplete):
    """Turn each floor-raise candidate on a JOB's own timeout-minutes into a floor raise: "raised to the completion
    floor" at the floor, "raised toward" it while still under. The floor is per job (the completion call is), so the
    job-level lines come from the head file through parse_workflow (each job's timeout line); a step's timeout-minutes,
    a file the reader cannot judge cleanly, or one it could not read keeps the finding a weakening."""
    by_path = {}
    for f in findings:
        if "raise" in f:
            by_path.setdefault(f["path"], []).append(f)
    for done, (path, fs) in enumerate(by_path.items()):
        try:
            lines = head_lines(budget, heads[path]) if path in heads else None
        except Exhausted as exc:
            incomplete.append("%s before the head files of %d of %d workflows with a timeout-minutes raise were read; "
                              "those raises stay listed as weakenings" % (_stop_reason(exc.kind), len(by_path) - done,
                                                                         len(by_path)))
            break
        try:
            jobs, bad = parse_workflow("\n".join(lines)) if lines is not None else ([], ["unread"])
        except Exception:  # a reader bug keeps the weakening, never hides one
            jobs, bad = [], ["reader failed"]
        job_lines = set() if bad else {j["timeout"][3] for j in jobs if j["timeout"] and not j["reasons"]}
        for f in fs:
            if f["line"] in job_lines:
                v = f["raise"]
                f["rule"], f["effect"] = FLOOR_RAISE_RULE, FLOOR_RAISE_EFFECT
                f["detail"] += (", raised to the completion floor (%d minutes)" % floor if v >= floor else
                                ", raised toward the completion floor (%d minutes), still under it" % floor)
    for f in findings:
        f.pop("raise", None)


WEAKENING_MAX_CANDIDATES = 3


def _test_stem(p):
    b = p.rsplit("/", 1)[-1]
    b = re.sub(r"\.(?:test|spec|e2e|selftest|Tests)(?=\.)", "", b)
    b = re.sub(r"^test[_-]|_test(?=\.)", "", b)
    return b.rsplit(".", 1)[0]


def _candidate_listing(candidates, keys):
    """The first WEAKENING_MAX_CANDIDATES distinct paths filed under keys, then a count of the rest; "" for none.
    A set does the de-duplication, so the cost is the number of paths filed, never that number squared."""
    seen, names = set(), []
    for key in keys:
        for p in candidates.get(key, ()):
            if p not in seen:
                seen.add(p)
                if len(names) < WEAKENING_MAX_CANDIDATES:
                    names.append(p)
    listed = ", ".join(md_code(p) for p in names)
    if len(seen) > len(names):
        listed += " and %d more" % (len(seen) - len(names))
    return listed


def deleted_test_findings(status_rows):
    """A test file deleted, or renamed to a non-test path (b.test.ts.bak, tests/fixtures/), is reported.

    Only a rename git pairs by CONTENT to another test path is a move, and that never reaches this list as a
    deletion. A test added elsewhere under the same file name or stem proves nothing about the deleted cases
    (critical/a.test.ts is not replaced by an unrelated unrelated/a.test.ts), so it is listed with the finding as
    an unverified successor candidate and never clears it.
    """
    candidates = {}
    for st, old, new in status_rows:
        if st in ("A", "R", "C") and is_test_file(new):
            for key in {new.rsplit("/", 1)[-1], _test_stem(new)}:
                candidates.setdefault(key, []).append(new)
    deleted_sources = {_test_stem(o) for st, o, _ in status_rows if st == "D" and not is_test_file(o)}
    # The listing depends only on the deleted file's name, and a PR can delete thousands of tests of one name; their
    # identical details share one string (16k deletions naming three 4 KB candidate paths held 187 MB of copies).
    listing, shared = {}, {}
    out = []
    for st, old, new in status_rows:
        if not is_test_file(old):
            continue
        if st == "D":
            detail = "deletes a test file"
        elif st == "R" and not is_test_file(new):
            # git -M reports a test moved out of the runner's reach as a rename, not a deletion.
            detail = "renames a test file to the non-test path %s" % md_code(new)
        else:
            continue
        keys = (old.rsplit("/", 1)[-1], _test_stem(old))
        if keys not in listing:
            listing[keys] = _candidate_listing(candidates, keys)
        listed = listing[keys]
        if listed:
            detail += ("; unverified successor candidate by name only: %s (git does not pair it by content, so the "
                       "deleted cases may not run)" % listed)
        else:
            detail += " with no successor"
        if _test_stem(old) in deleted_sources:
            detail += " (a source file of the same stem is deleted too)"
        out.append(_finding("test-deleted", old, None, shared.setdefault(detail, detail)))
    return out


def coe_level(lines, idx):
    """'job <id>', 'step' or 'unknown' for the continue-on-error key on 0-based line idx."""
    def indent(t):
        return len(t) - len(t.lstrip(" "))
    line = lines[idx]
    if line.lstrip().startswith("- "):
        return "step"
    ind = indent(line)
    stop = max(idx - 1 - WEAKENING_MAX_WALK, -1)
    for j in range(idx - 1, stop, -1):
        if len(lines[j]) > WEAKENING_MAX_LINE:
            return "unknown"
        s = lines[j].strip()
        if not s or s.startswith("#") or indent(lines[j]) >= ind:
            continue
        if s.startswith("- "):
            return "step"
        m = re.match(r"^([A-Za-z0-9_.-]+|\"[^\"]+\"|'[^']+')\s*:\s*(?:#.*)?$", s)
        if not m:
            return "unknown"
        pi = indent(lines[j])
        for k in range(j - 1, stop, -1):
            if len(lines[k]) > WEAKENING_MAX_LINE:
                return "unknown"
            u = lines[k].strip()
            if not u or u.startswith("#") or indent(lines[k]) >= pi:
                continue
            return ("job `%s`" % safe_key(m.group(1).strip("\"'"))) if re.match(r"^jobs\s*:", u) else "unknown"
        return "unknown"
    return "unknown"


_MARKER = re.compile(r"\bvagaris-(?P<kind>quarantine|approval)\s*[:=]\s*(?P<id>[A-Za-z0-9][A-Za-z0-9._/#-]{1,63})", re.I)


def inline_refs(lines, line_no):
    """(distinct markers on the finding's line and the two above it, whether a line was skipped). A head-side line
    is not capped by the diff, so one over WEAKENING_MAX_LINE is not read, as on the diff side."""
    refs, skipped = {}, False
    for t in lines[max(line_no - 3, 0): line_no]:
        if len(t) > WEAKENING_MAX_LINE:
            skipped = True
            continue
        for m in _MARKER.finditer(t):
            refs.setdefault("%s `%s`" % (m.group("kind").lower(), m.group("id")), None)
    return list(refs), skipped


def named_refs(own, pr_refs, pr_set):
    """A finding's references, its own inline ones first: at most WEAKENING_MAX_REFS named and the rest counted, so a
    PR that floods its commit messages with references cannot grow every finding."""
    own_set = set(own)
    named = own[:WEAKENING_MAX_REFS]
    for r in pr_refs:
        if len(named) >= WEAKENING_MAX_REFS:
            break
        if r not in own_set:
            named.append(r)
    total = len(own_set) + len(pr_set) - len(own_set & pr_set)
    return named + (["and %d more" % (total - len(named))] if total > len(named) else [])


def _stop_reason(kind):
    if kind == "time":
        return "the %ds scan budget ran out" % WEAKENING_DEADLINE_SECONDS
    if kind == "findings":
        return "the %d-finding cap was reached" % WEAKENING_MAX_FINDINGS
    return "the %d-byte read budget ran out" % WEAKENING_MAX_TOTAL_BYTES


def trailer_refs(budget, mb, head, incomplete):
    """Quarantine and approval trailers of the PR's commits (the newest 500), read under WEAKENING_MAX_TRAILER_BYTES."""
    try:
        raw = git_read(budget, ("log", "--format=%B", "-n", "500", "%s..%s" % (mb, head)), WEAKENING_MAX_TRAILER_BYTES)
    except Exhausted as exc:
        # The last line may be cut short, and a cut-off id would still match as a shorter, wrong one.
        raw = exc.partial[: exc.partial.rfind(b"\n") + 1]
        incomplete.append("commit messages past %d bytes were not read for references" % WEAKENING_MAX_TRAILER_BYTES
                          if exc.kind == "cap" else
                          "%s while reading commit messages; later references are not listed" % _stop_reason(exc.kind))
    refs = {}  # insertion-ordered and de-duplicated in O(1): 1 MB of messages holds ~48k distinct references
    for line in raw.decode("utf-8", "replace").splitlines():
        m = re.match(r"^\s*vagaris-(quarantine|approval)\s*:\s*([A-Za-z0-9][A-Za-z0-9._/#-]{1,63})\s*$", line, re.I)
        if m:
            refs.setdefault("%s `%s`" % (m.group(1).lower(), m.group(2)), None)
    return list(refs)


def head_lines(budget, sha):
    """The head-side file's lines (for the job/step level and inline markers), or None when git cannot read it.
    A budget stop raises Exhausted."""
    try:
        return git_read(budget, ("cat-file", "blob", sha), WEAKENING_MAX_BLOB_BYTES).decode("utf-8", "replace").split("\n")
    except IntegrityError:
        return None


def enrich(budget, listed, heads, incomplete):
    """The job or step of a continue-on-error and the inline references, for the findings that will be LISTED only,
    from each one's head file read once. Work follows the listing cap, not the number of findings the PR produces."""
    by_path = {}
    for f in listed:
        if f["line"] and f["path"] in heads:
            by_path.setdefault(f["path"], []).append(f)
    for done, (path, fs) in enumerate(by_path.items()):
        try:
            lines = head_lines(budget, heads[path])
        except Exhausted as exc:
            incomplete.append("%s before the head files of %d of %d files with listed findings were read; their inline "
                              "references and the job or step of a continue-on-error are not listed"
                              % (_stop_reason(exc.kind), len(by_path) - done, len(by_path)))
            return
        if lines is None:
            incomplete.append("%s: the head file could not be read; inline references and the job or step of a "
                              "continue-on-error are not listed" % md_code(path))
            continue
        refs_at, skipped = {}, False
        for f in fs:
            if f["rule"] == "continue-on-error" and f["line"] <= len(lines):
                f["detail"] += " on %s; whether it backs a required check is not readable here" % coe_level(
                    lines, f["line"] - 1)
            if f["line"] not in refs_at:
                refs_at[f["line"]], skip = inline_refs(lines, f["line"])
                skipped = skipped or skip
            f["refs"] += refs_at[f["line"]]
        if skipped:
            incomplete.append("%s: a line over %d chars next to a finding was not read for references"
                              % (md_code(path), WEAKENING_MAX_LINE))


def scan_file(row, patch, incomplete, floor=None):
    """Findings for one in-scope file from its patch text (None: the diff was over WEAKENING_MAX_PATCH_BYTES)."""
    path, scopes = row[3], row[4]
    if patch is None:
        incomplete.append("%s: diff larger than %d bytes, not scanned" % (md_code(path), WEAKENING_MAX_PATCH_BYTES))
        return []
    added, removed, first = parse_patch(patch)
    # Regex cost grows with line length; a line past the cap is not matched, and the PR is told so.
    too_long = sum(1 for _, t in added + removed if len(t) > WEAKENING_MAX_LINE)
    if too_long:
        incomplete.append("%s: %d changed lines over %d chars not scanned" % (md_code(path), too_long, WEAKENING_MAX_LINE))
        added = [(n, t) for n, t in added if len(t) <= WEAKENING_MAX_LINE]
        removed = [(n, t) for n, t in removed if len(t) <= WEAKENING_MAX_LINE]
    return token_findings(path, scopes, added, removed) + numeric_findings(path, scopes, added, removed, first, floor)


def scan_patches(budget, mb, head, scoped, todo, results, incomplete, room, floor=None):
    """Fill results[i] for every i in todo; the stop kind, or None when every file was read. Once the files scanned hold
    room findings, the next file stops the scan ("findings"): a PR of `it.skip(` makes ~125k findings per MB of diff.

    The files are read from ONE streamed git diff (per pathspec batch), and a section is bound to its file only by
    its exact expected header. A path git quotes (control or non-ASCII bytes) or a rename paired differently in
    the narrower pathspec is not bound, and that file is diffed on its own afterwards.
    """
    want, kept = {}, [0]
    for i in todo:
        want.setdefault("diff --git a/%s b/%s" % (scoped[i][1], scoped[i][2]), i)

    def scan(i, patch):
        if kept[0] >= room:
            raise Exhausted("findings")
        results[i] = scan_file(scoped[i], patch, incomplete, floor)
        kept[0] += len(results[i])
    try:
        for batch in pathspec_batches([(i, {scoped[i][1], scoped[i][2]}) for i in todo]):
            chunks = git_chunks(budget, diff_args(mb, head, {p for _, ps in batch for p in ps}))
            try:
                for header, patch in patch_sections(chunks, WEAKENING_MAX_PATCH_BYTES):
                    i = want.get(header)
                    if i is not None and i not in results:
                        scan(i, patch)
            finally:
                chunks.close()  # kills git now, also on an early stop
        for i in todo:
            if i in results:
                continue
            try:
                patch = git_read(budget, diff_args(mb, head, {scoped[i][1], scoped[i][2]}),
                                 WEAKENING_MAX_PATCH_BYTES).decode("utf-8", "replace")
            except Exhausted as exc:
                if exc.kind != "cap":
                    raise
                patch = None
            scan(i, patch)
    except Exhausted as exc:
        return exc.kind
    return None


def weakening_scan(mb, head, floor=None):
    """(findings, incomplete reasons, files in scope). Every git read is bounded by one ScanBudget; a git failure or
    an undecodable path raises, and the caller reports that as INCOMPLETE. floor: see numeric_findings."""
    budget = ScanBudget(WEAKENING_DEADLINE_SECONDS, WEAKENING_MAX_TOTAL_BYTES)
    incomplete = []
    rows, listing_stop = census(budget, mb, head)
    if listing_stop == "cap":
        incomplete.append("the changed-file list is longer than %d bytes; only the first %d files were listed and "
                          "scanned" % (WEAKENING_MAX_CENSUS_BYTES, len(rows)))
    elif listing_stop:
        incomplete.append("%s while listing the changed files; only the %d listed were scanned"
                          % (_stop_reason(listing_stop), len(rows)))
    findings = deleted_test_findings([(st, old, new) for st, old, new, _, _ in rows])
    scoped = []
    for st, old, new, old_sha, new_sha in rows:
        if st == "D" and is_test_file(old):
            continue
        path = old if st == "D" else new
        scopes = path_scopes(path)
        if scopes:
            scoped.append((st, old, new, path, scopes, old_sha, new_sha))
    in_scope = len(scoped)
    if in_scope > WEAKENING_MAX_FILES:
        incomplete.append("%d files in scope; only the first %d were scanned" % (in_scope, WEAKENING_MAX_FILES))
        scoped = scoped[:WEAKENING_MAX_FILES]
    results = {}
    try:
        sizes = blob_sizes(budget, [sha for row in scoped for sha in row[5:7]])
    except Exhausted as exc:
        stop = exc.kind
    else:
        todo = []
        for i, row in enumerate(scoped):
            if max(sizes.get(row[5], 0), sizes.get(row[6], 0)) > WEAKENING_MAX_BLOB_BYTES:
                incomplete.append("%s: file larger than %d bytes, not diffed or scanned"
                                  % (md_code(row[3]), WEAKENING_MAX_BLOB_BYTES))
                results[i] = []
            else:
                todo.append(i)
        stop = scan_patches(budget, mb, head, scoped, todo, results, incomplete, WEAKENING_MAX_FINDINGS - len(findings),
                            floor)
    if stop:
        incomplete.append("%s after %d of %d files in scope; the rest were not scanned"
                          % (_stop_reason(stop), len(results), in_scope))
    for i in sorted(results):
        findings += results[i]
    heads = {row[3]: row[6] for row in scoped if row[0] != "D"}
    floor_raises(budget, findings, heads, floor, incomplete)
    listed = findings[:WEAKENING_MAX_LISTED]
    enrich(budget, listed, heads, incomplete)
    pr_refs = trailer_refs(budget, mb, head, incomplete) if listed else []
    pr_set = set(pr_refs)
    for f in listed:
        f["refs"] = named_refs(f["refs"], pr_refs, pr_set)
    return findings, incomplete, in_scope


def md_code(text):
    return "`%s`" % str(text).replace("`", "'").replace("\r", " ").replace("\n", " ")


def _cmd_data(text):
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _cmd_prop(text):
    return _cmd_data(text).replace(":", "%3A").replace(",", "%2C")


def weakening_report(mb, head, floor=None):
    """Summary lines for the FL-4 section, plus warning annotations. Never raises; never sets an exit code.
    A job's timeout-minutes raised to or toward the completion floor is listed on its own line: no annotation, not a
    weakening."""
    lines = ["", "### Test-weakening predicates (FL-4 `%s`, report-only)" % WEAKENING_VERSION]
    try:
        findings, incomplete, in_scope = weakening_scan(mb, head, floor)
    except Exception as exc:  # report-only: a scan failure is INCOMPLETE, never a pass and never a red job
        lines.append("- INCOMPLETE: the scan failed (%s); no weakening verdict for this PR" % type(exc).__name__)
        print("::warning title=test weakening (FL-4)::scan incomplete (%s)" % _cmd_data(type(exc).__name__))
        return lines
    raises = [f for f in findings if f["rule"] == FLOOR_RAISE_RULE]
    findings = [f for f in findings if f["rule"] != FLOOR_RAISE_RULE]
    for f in findings[:WEAKENING_MAX_LISTED]:
        where = f["path"] if not f["line"] else "%s:%d" % (f["path"], f["line"])
        ref = ("references %s (unverified)" % ", ".join(f["refs"])) if f["refs"] else "no quarantine or approval reference"
        lines.append("- WEAKENING %s %s %s; %s" % (f["rule"], md_code(where), f["detail"], ref))
    if len(findings) > WEAKENING_MAX_LISTED:
        lines.append("- ... and %d more findings" % (len(findings) - WEAKENING_MAX_LISTED))
    for f in raises[:WEAKENING_MAX_LISTED]:
        where = md_code("%s:%d" % (f["path"], f["line"]))
        lines.append("- FLOOR RAISE %s %s; not a test weakening" % (where, f["detail"]))
    if len(raises) > WEAKENING_MAX_LISTED:
        lines.append("- ... and %d more floor raises" % (len(raises) - WEAKENING_MAX_LISTED))
    for f in findings[:WEAKENING_MAX_ANNOTATIONS]:
        loc = "file=%s" % _cmd_prop(f["path"]) + (",line=%d" % f["line"] if f["line"] else "")
        print("::warning %s,title=test weakening (FL-4)::%s: %s" % (loc, f["rule"], _cmd_data(f["detail"])))
    if len(findings) > WEAKENING_MAX_ANNOTATIONS:
        print("::warning title=test weakening (FL-4)::%d more findings in the job summary"
              % (len(findings) - WEAKENING_MAX_ANNOTATIONS))
    if len(incomplete) > WEAKENING_MAX_LISTED:
        # Per-file reasons start with the file's path; the scan-wide ones (a stop, a cap) are always listed.
        scan_wide = [r for r in incomplete if not r.startswith("`")]
        per_file = [r for r in incomplete if r.startswith("`")]
        shown = per_file[: max(WEAKENING_MAX_LISTED - len(scan_wide), 0)]
        incomplete = scan_wide + shown + ["... and %d more per-file reasons" % (len(per_file) - len(shown))]
    for reason in incomplete:
        lines.append("- INCOMPLETE: %s" % reason)
    if incomplete:
        print("::warning title=test weakening (FL-4)::scan incomplete; see the job summary")
    if findings:
        lines.append("Reported, not enforced: a weakening is allowed only with a quarantine or approval record, "
                     "and no verifier for either exists yet, so a reference is listed, never honoured.")
    elif not incomplete:
        lines.append("No test-weakening pattern added (%d changed files in scope)." % in_scope)
    return lines


# --- timeout floor ---------------------------------------------------------------------------
#
# A runner reports a finished job to GitHub with one HTTP call, CompleteJob. actions/runner v2.338.0 sends it through
# RunnerService.RetryRequest (src/Runner.Common/RunnerService.cs: 5 attempts, a random 5-15 s backoff) with a 100 s
# timeout per attempt. When the job's timeout-minutes runs out while that call stalls, GitHub cancels a job that had
# already succeeded: on 2026-10-27 a platform test-gate (timeout-minutes: 2) finished green at 04:27:03Z, its
# CompleteJob attempt timed out after 100 s, and the job was cancelled at the 2-minute limit. So every job needs at
# least ceil((p95 + 30 s + 2 * 100 s + 15 s) / 60) minutes, one stalled attempt and a retry on top of its p95 run
# time, and never under 6. The p95 part needs run telemetry and lives in a separate census; this mode checks the
# static part, the absolute floor (manifest timeout_floor.minutes) for every job.
#
# The scan reads every .github/workflows/*.yml and *.yaml of the HEAD tree (the whole tree, not the diff: a job that
# was under the floor before the PR is still under it) as data, with one `git ls-tree` and a `git cat-file blob` per
# file under one ScanBudget, as FL-4 does. Nothing from the PR runs. Running out of budget is INCOMPLETE.
#
# No YAML library on this path. A stdlib reader built on indentation needs three levels only: the top-level `jobs:`
# key, the job ids under it, and each job's own keys. It still follows every construct whose content may sit at a
# shallow indentation (block scalars; quoted scalars and flow collections over several lines; plain scalars continued
# on the next line), so a line inside one is never read as a key. A step's timeout-minutes does not matter: the
# completion call is per job. What the reader cannot judge safely (a merge key; an anchor, alias or tag on a job or
# its timeout; a flow-style job or jobs block; a tab in the indentation; a second `jobs:` or YAML document) makes the
# job or the whole file INCOMPLETE rather than a guess. Keys compare case-insensitively, which can only add findings.
#
# Verdicts: no timeout-minutes passes (GitHub's default is 360); a literal number passes at or over the floor and is a
# violation under it; an expression is a violation (nothing static bounds it) unless an exemption names it exactly;
# a job-level `uses:` calls a reusable workflow, which cannot set timeout-minutes, and is skipped. Mode `report` exits
# 0 whatever it finds; mode `enforce` exits 1 on an unexempted violation or anything INCOMPLETE.

FLOOR_DEADLINE_SECONDS = 120       # the whole scan, every git call included; the job's own timeout is 10 minutes
FLOOR_MAX_TOTAL_BYTES = 16000000   # everything the scan reads from git
FLOOR_MAX_LISTING_BYTES = 1000000  # the .github/workflows listing
FLOOR_MAX_BLOB_BYTES = 2000000     # one workflow file; a larger one is not read: INCOMPLETE
FLOOR_MAX_FILES = 500              # workflow files judged; the rest: INCOMPLETE
FLOOR_MAX_JOBS = 2000              # rows; reaching it stops the scan: INCOMPLETE
FLOOR_MAX_VALUE = 200              # a longer timeout-minutes value is not judged: INCOMPLETE
FLOOR_MAX_REASONS = 3              # reasons named per INCOMPLETE row; the rest are counted
FLOOR_MAX_LISTED = 200             # summary lines; the TSV block carries every row
FLOOR_MAX_ANNOTATIONS = 8          # GitHub keeps 10 per level and step: room for the two pointers
FLOOR_TSV_HEADER = "repo\tworkflow_path\tjob_key\ttimeout_minutes_declared\tverdict"

# Built from two parts, never written as one literal: this file is inlined into a workflow run block.
_EXPR_OPEN = "$" + "{{"
_FLOOR_FILE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
_FLOOR_JOB_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,199}$")
_FLOOR_NUMBER = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_FLOOR_PROPS = re.compile(r"(?:[&!]\S*[ \t]*)+")
_FLOOR_QKEY = re.compile(r"\"((?:[^\"\\]|\\.)*)\"[ \t]*:(?=[ \t]|$)|'((?:[^']|'')*)'[ \t]*:(?=[ \t]|$)")
_FLOOR_DOC = re.compile(r"^(?:---|\.\.\.)(?=[ \t]|$)")
# YAML (and PyYAML) also breaks lines at a lone CR, NEL, LS and PS; this reader splits on LF only.
_FLOOR_ODD_BREAK = re.compile(r"\r(?!\n)|[\x85\u2028\u2029]")
_FLOOR_INDICATORS = frozenset("-?:,[]{}#&*!|>'\"%@`")
_FLOOR_KINDS = {"|": "block", ">": "block", '"': "quoted", "'": "quoted", "[": "flow", "{": "flow", "*": "alias"}


def _floor_plain_key(rest):
    """(key, end) for a plain `key:` at the start of rest, else None: a plain key starts with no indicator and ends at
    the first colon followed by a space or the line end; ` #` before that colon starts a comment."""
    if not rest or rest[0] in _FLOOR_INDICATORS:
        return None
    i = 0
    while True:
        j = rest.find(":", i)
        if j < 0:
            return None
        if j + 1 == len(rest) or rest[j + 1] in " \t":
            key = rest[:j]
            if " #" in key or "\t#" in key:
                return None
            return key.rstrip(" \t"), j + 1
        i = j + 1


def _floor_split(line, ind):
    """(dashes, key or None, node column, value) of a structural line indented ind spaces. dashes counts leading
    `- ` sequence entries; the node column is the key's, else the last dash's (a scalar's body is indented past it);
    value is the text after `key:`, or after the dashes. A double-quoted key keeps its escapes, so a key with a
    backslash is never mistaken for a plain one."""
    col, rest, dashes, node = ind, line[ind:], 0, ind - 1
    while rest[:1] == "-" and (len(rest) == 1 or rest[1] in " \t"):
        node = col
        nxt = rest[1:].lstrip(" \t")
        col += len(rest) - len(nxt)
        rest, dashes = nxt, dashes + 1
    m = _FLOOR_QKEY.match(rest)
    if m:
        key = m.group(1) if m.group(1) is not None else m.group(2).replace("''", "'")
        return dashes, key, col, rest[m.end():].lstrip(" \t")
    pk = _floor_plain_key(rest)
    if pk:
        return dashes, pk[0], col, rest[pk[1]:].lstrip(" \t")
    return dashes, None, node, rest


def _floor_node(value):
    """(kind, props, body) of the node value starts: kind is "empty", "block", "quoted", "flow", "alias" or "plain";
    props are the anchors (&a) and tags (!t) in front of it; body is the text from the node on."""
    m = _FLOOR_PROPS.match(value)
    props = m.group(0).split() if m else []
    body = value[m.end():] if m else value
    if not body or body.startswith("#"):
        return "empty", props, body
    return _FLOOR_KINDS.get(body[0], "plain"), props, body


def _flow_scan(text, state):
    """Advance a quoted scalar or flow collection over text: None once it closes, else the state for the next line.
    state is (open quote or None, bracket depth, whether a node may start here). Linear in the text."""
    q, depth, start = state
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if q == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                q, start = None, False
                if depth == 0:
                    return None
        elif q == "'":
            if c == "'":
                if text[i + 1:i + 2] == "'":
                    i += 2
                    continue
                q, start = None, False
                if depth == 0:
                    return None
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        elif c in "[{":
            depth, start = depth + 1, True
        elif c in "]}":
            depth, start = depth - 1, False
            if depth <= 0:
                return None
        elif c in ",?:":
            start = True
        elif c in "\"'" and start:
            q = c
        elif c not in " \t":
            start = False
        i += 1
    return (q, depth, start)


def parse_workflow(text):
    """([job], [file-level reason]) for one workflow's text. A job is a dict: id, line, timeout (None, or (kind, props,
    node text, line) of its job-level timeout-minutes), uses (a job-level `uses:`), reasons (why it cannot be judged).
    A file-level reason makes every job of the file INCOMPLETE."""
    if text.startswith("\ufeff"):
        text = text[1:]
    jobs, bad, ids = [], [], set()
    odd = _FLOOR_ODD_BREAK.search(text)
    if odd:
        # A key after such a break would sit inside the previous line here and read as absent: never judge the file.
        bad.append("line %d: a line break other than LF or CRLF (a lone CR, NEL, LS or PS)"
                   % (text.count("\n", 0, odd.start()) + 1))
    flow, flow_at = None, 0   # a quoted scalar or flow collection still open, and the line that opened it
    flow_ind = 0              # that line's indentation: a continuation left of it is not followed
    # (column, job or None) after a scalar value: lines indented past column belong to it (job: it is that job's
    # timeout). That covers block scalars (|, > and their indicators) too: YAML indents every body line of one past
    # its parent's column (the key's, or the `- `'s), so a body line is never read as a key, a tab or a quote.
    plain = None
    started = seen = False    # a `---` was read; a structural line was read
    top_seq = False           # the last top-level key has no value, so a `- ` at column 0 is its sequence
    last_top = None           # that key, lower-cased
    jobs_keys, in_jobs, id_ind, job = 0, False, None, None
    for no, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        if flow is not None:
            s = line.lstrip(" ")
            if s and not (flow[0] is None and s.startswith("#")) and len(line) - len(s) < flow_ind:
                bad.append("line %d: a quoted scalar or flow collection continues left of the line that opened it" % no)
            flow = _flow_scan(line, flow)
            continue
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip(" "))
        stripped = line.lstrip(" \t")
        if stripped.startswith("#"):
            continue
        if plain is not None:
            if ind > plain[0]:
                if plain[1] is not None:
                    plain[1]["reasons"].append("line %d: the timeout-minutes value continues on this line" % no)
                    plain = (plain[0], None)
                continue
            plain = None
        if "\t" in line[:len(line) - len(stripped)]:
            bad.append("line %d: a tab in the indentation" % no)
            continue
        if ind == 0 and (_FLOOR_DOC.match(line) or line.startswith("%")):
            tail = line[3:].strip(" \t")
            if line.startswith("---") and not (started or seen) and (not tail or tail.startswith("#")):
                started = True
            else:
                bad.append("line %d: a second YAML document, a document end or a directive" % no)
            continue
        seen = True
        dashes, key, node, value = _floor_split(line, ind)
        kind, props, body = _floor_node(value)
        opened = _flow_scan(body, (None, 0, True)) if kind in ("quoted", "flow") else None
        lkey = key.lower() if key is not None else None
        plain_job = None
        if ind == 0:
            if dashes:
                if last_top == "jobs":
                    bad.append("line %d: `jobs:` holds a sequence, not a mapping of job ids" % no)
                elif not top_seq:
                    bad.append("line %d: a top-level sequence entry; the workflow is not a block mapping" % no)
            else:
                in_jobs, job, top_seq, last_top = False, None, kind == "empty", lkey
                if key is None or "\\" in key:
                    bad.append("line %d: a top-level line that is not a plain `key:` entry" % no)
                elif lkey == "<<":
                    bad.append("line %d: a merge key (<<) at the top level" % no)
                elif lkey == "jobs":
                    top_seq = False
                    jobs_keys += 1
                    if jobs_keys > 1:
                        bad.append("line %d: a second `jobs:`" % no)
                    if kind != "empty" or props:
                        bad.append("line %d: `jobs:` is not a plain block mapping (flow style, an anchor, alias or "
                                   "tag, or a scalar)" % no)
                    else:
                        in_jobs, id_ind = True, None
        elif in_jobs:
            if id_ind is None:
                id_ind = ind
            if ind < id_ind:
                bad.append("line %d: a line inside `jobs:` left of the job ids" % no)
            elif ind == id_ind:
                if dashes:
                    bad.append("line %d: a sequence entry where `jobs:` needs job ids" % no)
                elif key is None or "\\" in key:
                    bad.append("line %d: a line at the job-id level that is not a plain `job-id:` entry" % no)
                elif lkey == "<<":
                    bad.append("line %d: a merge key (<<) in `jobs:`" % no)
                else:
                    job = {"id": key, "line": no, "timeout": None, "uses": False, "reasons": [], "ind": None,
                           "seq": False}
                    jobs.append(job)
                    why = []
                    if not _FLOOR_JOB_ID.match(key):
                        why.append("a job id GitHub does not accept")
                    if key.lower() in ids:
                        bad.append("line %d: a second job with the id %s" % (no, md_code(key)))
                    ids.add(key.lower())
                    if any(p.startswith("&") for p in props):
                        why.append("an anchor on the job")
                    if any(p.startswith("!") for p in props):
                        why.append("a tag on the job")
                    if kind == "alias":
                        why.append("the job is an alias")
                    elif kind == "flow":
                        why.append("the job is a flow-style mapping")
                    elif kind != "empty":
                        why.append("the job is a scalar, not a mapping")
                    job["reasons"] += ["line %d: %s" % (no, w) for w in why]
            elif job is not None:
                if job["ind"] is None:
                    job["ind"] = ind
                if ind < job["ind"]:
                    job["reasons"].append("line %d: a job line left of the job's keys" % no)
                elif ind == job["ind"]:
                    if dashes:
                        # `steps:` and its `- ` entries may share one indentation; any other entry here is not a key.
                        if not job["seq"]:
                            job["reasons"].append("line %d: a sequence entry where the job needs keys" % no)
                    elif key is None or "\\" in key:
                        job["reasons"].append("line %d: a job-level line that is not a plain `key:` entry (flow style, "
                                              "an explicit or escaped key, a tag)" % no)
                    else:
                        job["seq"] = kind == "empty"
                        if lkey == "<<":
                            job["reasons"].append("line %d: a merge key (<<) in the job" % no)
                        elif lkey == "timeout-minutes":
                            if job["timeout"] is not None:
                                job["reasons"].append("line %d: a second timeout-minutes" % no)
                            else:
                                job["timeout"] = (kind, props, body, no)
                                plain_job = job
                                if opened is not None:
                                    job["reasons"].append("line %d: the timeout-minutes value runs over several "
                                                          "lines" % no)
                        elif lkey == "uses":
                            job["uses"] = True
        if opened is not None:
            flow, flow_at, flow_ind = opened, no, ind
        elif kind != "empty":
            plain = (node, plain_job)
    if flow is not None:
        bad.append("line %d: a quoted scalar or flow collection that never closes" % flow_at)
    return jobs, bad


def _floor_declared(t):
    """(declared text, reason or None) of a job-level timeout-minutes: (kind, props, node text, line). The text is the
    value without quotes or a trailing comment, as the TSV prints it and an exemption names it."""
    kind, props, body, no = t
    if props:
        return body.strip(), "line %d: an anchor or tag on timeout-minutes" % no
    if kind == "alias":
        return body.strip(), "line %d: an alias as timeout-minutes" % no
    if kind == "empty":
        return "unknown", "line %d: no timeout-minutes value on its line" % no
    if kind in ("block", "flow"):
        return "unknown", "line %d: a block scalar or flow collection as timeout-minutes" % no
    why = None
    if kind == "quoted":
        q, i, escaped, end = body[0], 1, False, -1
        while i < len(body):
            if q == '"' and body[i] == "\\":
                escaped, i = True, i + 2
                continue
            if body[i] == q:
                if q == "'" and body[i + 1:i + 2] == "'":
                    i += 2
                    continue
                end = i
                break
            i += 1
        if end < 0:
            return "unknown", "line %d: the quoted timeout-minutes value does not close on its line" % no
        text = body[1:end].replace("''", "'") if q == "'" else body[1:end]
        tail = body[end + 1:].strip(" \t")
        if escaped:
            why = "line %d: an escape in the quoted timeout-minutes value" % no
        elif tail and not tail.startswith("#"):
            why = "line %d: text after the quoted timeout-minutes value" % no
    else:
        cut = min([i for i in (body.find(" #"), body.find("\t#")) if i >= 0] or [len(body)])
        text = body[:cut].rstrip(" \t")
    if len(text) > FLOOR_MAX_VALUE:
        return text[:FLOOR_MAX_VALUE] + "...", "line %d: a timeout-minutes value over %d chars" % (no, FLOOR_MAX_VALUE)
    return text, why


def _floor_verdict(job, floor):
    """(verdict, declared, detail) of a job no reason blocks, before exemptions."""
    if job["uses"]:
        return "skipped-reusable", "n/a", "calls a reusable workflow, which cannot set timeout-minutes"
    if job["timeout"] is None:
        return "pass", "default 360", "no timeout-minutes (GitHub's default is 360)"
    declared, why = _floor_declared(job["timeout"])
    if why:
        return "incomplete", declared, why
    if _EXPR_OPEN in declared:
        return "violation", declared, ("timeout-minutes is an expression, %s, which cannot be checked against the "
                                       "%d-minute floor" % (md_code(declared), floor))
    if _FLOOR_NUMBER.match(declared):
        if float(declared) >= floor:
            return "pass", declared, "timeout-minutes %s" % md_code(declared)
        return "violation", declared, "timeout-minutes %s is below the %d-minute floor" % (md_code(declared), floor)
    return "incomplete", declared, ("line %d: timeout-minutes %s is neither a number nor an expression"
                                    % (job["timeout"][3], md_code(declared)))


def _floor_row(path, job, line, declared, verdict, detail):
    return {"path": path, "job": job, "line": line, "declared": declared, "verdict": verdict, "detail": detail,
            "exemption": None}


def _floor_reasons(reasons):
    shown = reasons[:FLOOR_MAX_REASONS]
    more = len(reasons) - len(shown)
    return "; ".join(shown) + ("; and %d more" % more if more else "")


def _floor_rows(path, jobs, bad, floor):
    """One row per job of a parsed file; a file-level reason makes every row INCOMPLETE, or the file's one row."""
    if not jobs:
        return [_floor_row(path, "*", None, "unknown", "incomplete", _floor_reasons(bad))] if bad else []
    rows = []
    for j in jobs:
        line = j["timeout"][3] if j["timeout"] else j["line"]
        if bad or j["reasons"]:
            if j["timeout"]:
                declared = _floor_declared(j["timeout"])[0]
            else:
                declared = "n/a" if j["uses"] else "default 360"
            rows.append(_floor_row(path, j["id"], line, declared, "incomplete", _floor_reasons(j["reasons"] + bad)))
        else:
            verdict, declared, detail = _floor_verdict(j, floor)
            rows.append(_floor_row(path, j["id"], line, declared, verdict, detail))
    return rows


def _floor_stop(kind):
    if kind == "time":
        return "the %ds scan budget ran out" % FLOOR_DEADLINE_SECONDS
    return "the %d-byte read budget ran out" % FLOOR_MAX_TOTAL_BYTES


def timeout_floor_scan(head, floor):
    """(rows, scan-wide INCOMPLETE reasons, workflow files, files without jobs). A row is a dict: path, job, line,
    declared, verdict, detail, exemption; a file that cannot be read or parsed gives one row with job "*". A git that
    fails raises IntegrityError (the tree is unreadable); running out of budget is INCOMPLETE."""
    budget = ScanBudget(FLOOR_DEADLINE_SECONDS, FLOOR_MAX_TOTAL_BYTES)
    try:
        raw = git_read(budget, ("ls-tree", "-l", "-z", "--full-tree", head, "--", ".github/workflows/"),
                       FLOOR_MAX_LISTING_BYTES)
    except Exhausted as exc:
        why = ("the workflow listing is over %d bytes" % FLOOR_MAX_LISTING_BYTES if exc.kind == "cap"
               else _floor_stop(exc.kind))
        return [], ["%s; no workflow file was judged" % why], [], []
    files = []
    for rec in raw.split(b"\0"):
        meta, _, name = rec.partition(b"\t")
        path = name.decode("utf-8", "replace")
        if rec and _FLOOR_FILE.match(path):
            mode, otype, sha, size = meta.decode("ascii", "replace").split()
            files.append((mode, otype, sha, size, path))
    rows, reasons, nojobs = [], [], []
    if len(files) > FLOOR_MAX_FILES:
        reasons.append("%d workflow files; only the first %d were judged" % (len(files), FLOOR_MAX_FILES))
    for k, (mode, otype, sha, size, path) in enumerate(files[:FLOOR_MAX_FILES]):
        if len(rows) >= FLOOR_MAX_JOBS or budget.time_left() <= 0:
            reasons.append("%s after %d of %d workflow files; the rest were not judged" % (
                "the %d-job cap was reached" % FLOOR_MAX_JOBS if len(rows) >= FLOOR_MAX_JOBS
                else _floor_stop("time"), k, len(files)))
            break
        if mode == "120000":
            rows.append(_floor_row(path, "*", None, "unknown", "incomplete", "a symbolic link, which this reader "
                                   "does not follow"))
            continue
        if otype != "blob":
            continue
        if int(size) > FLOOR_MAX_BLOB_BYTES:
            rows.append(_floor_row(path, "*", None, "unknown", "incomplete", "larger than %d bytes, not read"
                                   % FLOOR_MAX_BLOB_BYTES))
            continue
        try:
            data = git_read(budget, ("cat-file", "blob", sha), FLOOR_MAX_BLOB_BYTES)
        except Exhausted as exc:
            reasons.append("%s after %d of %d workflow files; the rest were not judged" % (
                _floor_stop(exc.kind), k, len(files)))
            break
        try:
            jobs, bad = parse_workflow(data.decode("utf-8"))
        except UnicodeDecodeError:
            rows.append(_floor_row(path, "*", None, "unknown", "incomplete", "not valid UTF-8"))
            continue
        except Exception as exc:  # a reader bug is INCOMPLETE for that file, never a pass
            rows.append(_floor_row(path, "*", None, "unknown", "incomplete", "the reader failed (%s)"
                                   % type(exc).__name__))
            continue
        if not jobs and not bad:
            nojobs.append(path)
        rows += _floor_rows(path, jobs, bad, floor)
    return rows, reasons, [f[4] for f in files], nojobs


def apply_exemptions(rows, exemptions, repo):
    """Mark each violation an exemption names exactly (repo, workflow, job, declared text) exempt. Returns the
    exemptions for this repo that exempted nothing, as [(exemption, why)]: STALE, reported and never enforced."""
    index = {}
    for e in exemptions:
        if e["repo"] == repo:
            index.setdefault((e["workflow"], e["job"], e["minutes"]), []).append(e)
    used = set()
    for r in rows:
        hit = index.get((r["path"], r["job"], r["declared"])) if r["verdict"] == "violation" else None
        if hit:
            r["verdict"], r["exemption"] = "exempt", hit[0]
            used.update(id(e) for e in hit)
    by_job = {(r["path"], r["job"]): r for r in rows}
    stale = []
    for e in exemptions:
        if e["repo"] != repo or id(e) in used:
            continue
        r = by_job.get((e["workflow"], e["job"]))
        if r is None:
            why = ("the workflow was not judged" if (e["workflow"], "*") in by_job
                   else "no such job in the head tree's workflows")
        elif r["verdict"] == "incomplete":
            why = "the job could not be judged"
        elif r["declared"] != e["minutes"]:
            why = "the job now declares %s" % md_code(r["declared"])
        else:
            why = "the job passes without it"
        stale.append((e, why))
    return stale


def _tsv(text):
    return re.sub(r"[\t\r\n]", " ", str(text)).replace("`", "'")


# --- reporting -------------------------------------------------------------------------------

def summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write(text)


# ---------- sibling-read (root's class fix, 2026-10-27) ----------
# A freshly minted App installation token is not visible everywhere at once: a clone about a second later can be
# answered "Repository not found" with nothing wrong (vagaris #825, core #920). The ONE way to read a sibling repository
# with a fresh token is vagarylabs/.github/actions/sibling-repo-read, which waits for readiness. So a job that mints
# with actions/create-github-app-token itself and then reads a sibling (an actions/checkout of another repository, or a
# git clone/fetch/ls-remote while the job names a github.com URL) is refused. A mint alone (Renovate's) is not.
_SR_MINT = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?actions/create-github-app-token@")
_SR_CHECKOUT = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?actions/checkout@")
_SR_STEP = re.compile(r"^\s*-\s")
_SR_REPOSITORY = re.compile(r"^\s+repository\s*:\s*['\"]?(?P<v>[^'\"#\s][^'\"#]*?)['\"]?\s*(?:#.*)?$")
_SR_GIT_READ = re.compile(r"\bgit\b[^\n]*?\s(?:clone|fetch|ls-remote|pull)\b")
_SR_GITHUB_URL = re.compile(r"https://github\.com/")
# The checkout's own remote is no sibling: `git fetch origin main` reads the repository under test.
_SR_OWN_REMOTE = re.compile(r"\s(?:fetch|pull|ls-remote)\s+(?:-\S+\s+)*origin(?:\s|$)")
_SR_JOB = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?:#.*)?$")
_SR_FILE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$|(?:^|/)action\.ya?ml$")


def _sr_units(text):
    """(job id, first line number, lines) per job of a workflow, or one ("steps", 1, lines) unit for a composite action."""
    lines = text.split("\n")
    jobs_at = next((i for i, l in enumerate(lines) if re.match(r"^jobs\s*:\s*(?:#.*)?$", l)), None)
    if jobs_at is None:
        return [("steps", 1, lines)]
    units, current, start = [], None, 0
    for i in range(jobs_at + 1, len(lines)):
        line = lines[i]
        if line and not line.startswith((" ", "#")):
            break  # the next top-level key ends jobs:
        job = _SR_JOB.match(line)
        if job:
            if current is not None:
                units.append((current, start + 1, lines[start:i]))
            current, start = job.group(1), i
    if current is not None:
        end = next((i for i in range(start + 1, len(lines)) if lines[i] and not lines[i].startswith((" ", "#"))), len(lines))
        units.append((current, start + 1, lines[start:end]))
    return units


def sibling_read_findings(text):
    """[(job, line, what)] for one workflow or composite action text (see the sibling-read note above)."""
    findings = []
    for job, first, lines in _sr_units(text):
        mint = next((i for i, l in enumerate(lines) if _SR_MINT.match(l)), None)
        if mint is None:
            continue
        # Logical lines: a shell line continued with a trailing backslash is one command (`git -c ... \\` then
        # `clone ... https://github.com/...` on the next line is one clone).
        after, k = [], mint + 1
        while k < len(lines):
            start, text = k, lines[k]
            while text.endswith("\\") and k + 1 < len(lines):
                k += 1
                text = text[:-1] + " " + lines[k].strip()
            after.append((start, text))
            k += 1
        names_github = any(_SR_GITHUB_URL.search(l) for _, l in after)
        in_checkout = False
        for k, line in after:
            n = first + k
            if _SR_STEP.match(line):
                in_checkout = False  # a new step; `uses:` may be its first line or follow `- name:`
            if _SR_CHECKOUT.match(line):
                in_checkout = True
            repo = _SR_REPOSITORY.match(line) if in_checkout else None
            if repo and "github.repository" not in repo.group("v"):
                findings.append((job, n, "actions/checkout of %s after a raw create-github-app-token" % repo.group("v")))
            elif names_github and _SR_GIT_READ.search(line) and not _SR_OWN_REMOTE.search(line) \
                    and not line.lstrip().startswith("#"):
                findings.append((job, n, "a git read of a github.com repository after a raw create-github-app-token"))
    return findings


def run_sibling_read(m, repo, base, head):
    mode = m["sibling_read"]["mode"]
    resolve_head(base, head)
    files = workflow_files(head)
    rows = []
    for path in files:
        text = blob(head, path)
        for job, line, what in sibling_read_findings(text or ""):
            rows.append((path, job, line, what))
    level = "error" if mode == "enforce" else "warning"
    lines = ["## Sibling reads with a fresh App token: %s" % repo,
             "%d workflow/action files read at head `%s` (manifest `sibling_read`, mode `%s`)." % (len(files), head, mode)]
    for path, job, line, what in rows:
        lines.append("- `%s` job `%s` line %d: %s. Use vagarylabs/.github/actions/sibling-repo-read, which waits until "
                     "the token can see the repository." % (path, job, line, what))
        print("::%s file=%s,line=%d,title=sibling read without readiness::%s" % (level, path, line, what))
    if not rows:
        lines.append("No raw create-github-app-token is followed by a sibling read.")
    elif mode == "report":
        lines.append("Report-only (mode `report`): %d listed, not enforced." % len(rows))
    summary(lines)
    return 1 if mode == "enforce" and rows else 0


def run_integrity(m, repo, base, head):
    entry = repo_entry(m, repo)
    mb = resolve(base, head)
    rows = classify(entry, changed_paths(mb, head))
    lines = ["## Trusted workflow integrity: %s" % repo,
             "Compared against base-side commit `%s` (merge-base of base `%s` and head `%s`)." % (mb, base, head)]
    for status, path, cls in rows:
        lines.append("- PROTECTED-PATH CHANGE `%s` %s (%s)" % (path, status, ", ".join(cls)))
        print("::notice title=protected-path change::%s %s (%s)" % (status, path, ", ".join(cls)))
    for rf in entry["ratchet_files"]:
        b, h = blob(mb, rf), blob(head, rf)
        if b is None and h is None:
            continue
        if h is None:
            lines.append("- RATCHET REMOVED `%s`: the ratchet no longer exists at head" % rf)
            print("::notice title=ratchet removed::%s" % rf)
            continue
        hc = ratchet_constants(h, "%s@head" % rf)
        bc = ratchet_constants(b, "%s@base" % rf) if b is not None else {}
        d = diff_constants(bc, hc)
        for kind in ("added", "removed", "changed"):
            for name in d[kind]:
                lines.append("- RATCHET CONSTANT %s `%s` in `%s`" % (kind.upper(), name, rf))
                print("::notice title=ratchet constant %s::%s %s" % (kind, rf, name))
    if len(lines) == 2:
        lines.append("No protected workflow or ratchet change.")
    lines += weakening_report(mb, head, m["timeout_floor"]["minutes"])
    summary(lines)
    return 0


def run_protected(m, repo, base, head):
    entry = repo_entry(m, repo)
    mb = resolve(base, head)
    rows = classify(entry, changed_paths(mb, head))
    classes = sorted({c for _, _, cls in rows for c in cls})
    verdict = verify_vagaris_approval(repo, head, classes) if classes else "not-required"
    code, msg = protected_decision(classes, verdict)
    lines = ["## Protected paths: %s" % repo, msg]
    lines += ["- `%s` %s (%s)" % (p, s, ", ".join(c)) for s, p, c in rows]
    summary(lines)
    if classes:
        level = "error" if code else "notice"
        print("::%s title=protected paths::%s" % (level, msg))
    return code


def run_timeout_floor(m, repo, base, head):
    tf = m["timeout_floor"]
    floor, mode = tf["minutes"], tf["mode"]
    resolve_head(base, head)
    rows, scan_wide, files, nojobs = timeout_floor_scan(head, floor)
    stale = apply_exemptions(rows, tf["exemptions"], repo)
    count = {}
    for r in rows:
        count[r["verdict"]] = count.get(r["verdict"], 0) + 1
    violations, incomplete = count.get("violation", 0), count.get("incomplete", 0) + len(scan_wide)
    lines = ["## Timeout floor: %s" % repo,
             "Every job-level `timeout-minutes` in the %d workflow files of head `%s`, against the %d-minute "
             "completion floor (manifest `timeout_floor`, mode `%s`)." % (len(files), head, floor, mode)]
    level = "error" if mode == "enforce" else "warning"
    listed = annotated = 0
    for r in rows:
        if r["verdict"] not in ("violation", "exempt", "incomplete"):
            continue
        where = md_code(r["path"] if r["line"] is None else "%s:%d" % (r["path"], r["line"]))
        what = "the file" if r["job"] == "*" else "job %s" % md_code(r["job"])
        if r["verdict"] == "exempt":
            e = r["exemption"]
            text = "timeout-minutes %s, exempt by record %s: %s" % (md_code(r["declared"]), md_code(e["record"]),
                                                                    md_code(e["reason"]))
        else:
            text = r["detail"]
        if listed < FLOOR_MAX_LISTED:
            lines.append("- %s %s %s: %s" % (r["verdict"].upper(), where, what, text))
        listed += 1
        if r["verdict"] != "exempt" and annotated < FLOOR_MAX_ANNOTATIONS:
            loc = "file=%s" % _cmd_prop(r["path"]) + (",line=%d" % r["line"] if r["line"] else "")
            print("::%s %s,title=timeout floor::%s: %s" % (level, loc, _cmd_data(what), _cmd_data(text)))
            annotated += 1
    if listed > FLOOR_MAX_LISTED:
        lines.append("- ... and %d more; every row is in the TSV block below" % (listed - FLOOR_MAX_LISTED))
    for e, why in stale[:FLOOR_MAX_LISTED]:
        lines.append("- STALE EXEMPTION job %s in %s declaring %s (record %s): %s; reported, not enforced"
                     % (md_code(e["job"]), md_code(e["workflow"]), md_code(e["minutes"]), md_code(e["record"]), why))
        if annotated < FLOOR_MAX_ANNOTATIONS:
            print("::warning title=timeout floor stale exemption::%s"
                  % _cmd_data("job %s in %s (record %s): %s" % (e["job"], e["workflow"], e["record"], why)))
            annotated += 1
    if len(stale) > FLOOR_MAX_LISTED:
        lines.append("- ... and %d more stale exemptions" % (len(stale) - FLOOR_MAX_LISTED))
    unannotated = count.get("violation", 0) + count.get("incomplete", 0) + len(stale) - annotated
    if unannotated > 0:
        print("::%s title=timeout floor::%d more in the job summary" % (level, unannotated))
    for reason in scan_wide:
        lines.append("- INCOMPLETE: %s" % reason)
    if scan_wide:
        print("::%s title=timeout floor::scan incomplete; see the job summary" % level)
    if nojobs:
        more = " and %d more" % (len(nojobs) - 10) if len(nojobs) > 10 else ""
        lines.append("- No `jobs:` in %s%s: no job to judge" % (", ".join(md_code(p) for p in nojobs[:10]), more))
    if not violations and not incomplete:
        lines.append("All %d jobs meet the %d-minute floor, are exempt, or call a reusable workflow."
                     % (len(rows), floor))
    elif mode == "enforce":
        lines.append("Refused (mode `enforce`): %d violations, %d INCOMPLETE. Raise each listed timeout-minutes to at "
                     "least %d, or record an exemption in the trusted manifest." % (violations, incomplete, floor))
    else:
        lines.append("Report-only (mode `report`): %d violations and %d INCOMPLETE are listed, not enforced; "
                     "INCOMPLETE is never a pass." % (violations, incomplete))
    lines += ["", "One row per job, for diffing against the timeout census (same first four columns):", "", "```tsv",
              FLOOR_TSV_HEADER]
    # The census names a repo without its owner (.github, vagary-core): the TSV joins it on that name.
    short = repo.rsplit("/", 1)[-1]
    lines += ["\t".join(_tsv(x) for x in (short, r["path"], r["job"], r["declared"], r["verdict"])) for r in rows]
    lines.append("```")
    summary(lines)
    return 1 if mode == "enforce" and (violations or incomplete) else 0


# ---------- pins (C1 admission, root 2026-10-29) ----------
# Every `uses:` in a workflow or composite action names an immutable commit, labelled with what it is:
#   - third party: `owner/repo[/path]@<40-hex sha> # vX.Y.Z`, an exact release (a pre-release or build suffix allowed;
#     `# v4` or `# v4.1` is not exact, and no label is no label);
#   - first party: `vagarylabs/<repo>/...@<40-hex sha> # <repo> #<PR> merge` (`# .github #37 merge`), naming the PR
#     whose merge commit it is;
#   - a container: `docker://image@sha256:<64-hex>`; a local `./` action is the PR's own code.
# The merge path checks the FORM only: no network. Whether a label's tag still resolves to its sha upstream, and whether
# an internal sha is really that PR's merge commit, belong in a scheduled job (root, 2026-10-29).
_PIN_USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*(?P<v>.*?)\s*$")
_PIN_SHA = re.compile(r"^[0-9a-f]{40}$")
_PIN_HEXISH = re.compile(r"^[0-9a-f]{4,39}$")
_PIN_EXACT = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_PIN_INTERNAL = re.compile(r"^(?P<repo>[A-Za-z0-9_.-]+) #\d+ merge$")
_PIN_DOCKER = re.compile(r"^docker://\S+@sha256:[0-9a-f]{64}$")
PIN_CLASSES = ("tag_ref", "short_sha", "no_label", "major_only", "minor_only", "bad_label", "wrong_internal", "docker_tag",
               "image_tag", "image_arg", "node_version_loose", "node_version_expr", "pr_edited")


def pin_split(value):
    """(the `uses:` value, its trailing comment or None) from the raw text after `uses:`."""
    v = value.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        body, rest = (v[1:], "") if end == -1 else (v[1:end], v[end + 1:].strip())
    else:
        body, _, rest = v.partition(" ")
        rest = rest.strip()
    return body, (rest[1:].strip() if rest.startswith("#") else None)


def pin_verdict(value):
    """(class or None, uses, label) for one `uses:` value; None means it passes."""
    uses, label = pin_split(value)
    if uses.startswith("./") or uses == ".":
        return None, uses, label
    if uses.startswith("docker://"):
        return (None if _PIN_DOCKER.match(uses) else "docker_tag"), uses, label
    name, at, ref = uses.rpartition("@")
    if not at:
        return "tag_ref", uses, label
    if not _PIN_SHA.match(ref):
        return ("short_sha" if _PIN_HEXISH.match(ref) else "tag_ref"), uses, label
    parts = name.split("/")
    if parts[0].lower() == "vagarylabs":  # GitHub owners are case-insensitive: VagaryLabs/ is first party too
        m = _PIN_INTERNAL.match(label or "")
        return (None if m and len(parts) > 1 and m.group("repo") == parts[1] else "wrong_internal"), uses, label
    if not label:
        return "no_label", uses, label
    if _PIN_EXACT.match(label):
        return None, uses, label
    if re.match(r"^v\d+$", label):
        return "major_only", uses, label
    if re.match(r"^v\d+\.\d+$", label):
        return "minor_only", uses, label
    return "bad_label", uses, label


def pin_findings(text):
    """[(line, class, uses, label)] for every `uses:` line that does not pass (a commented line never matches)."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _PIN_USES.match(line)
        if m:
            cls, uses, label = pin_verdict(m.group("v"))
            if cls:
                out.append((i, cls, uses, label))
    return out


# ---------- the other pinned inputs, and F19 (root, 2026-10-29) ----------
# Pin enforcement lives ONLY here (root's ruling on the vagaris pin dedupe): beyond `uses:`, a Dockerfile `FROM` names
# its image by digest, and setup-node's `node-version` is an exact X.Y.Z. And F19: `edited` in a pull_request trigger
# restarts every job on a body or title edit (vagary-core #881 spawned four duplicate runs). Required checks attach to
# the head SHA, and a retarget needs no new run. A job-level `if:` guard is not enough: a skipped job reports success,
# and as the newest run on the SHA it can replace a red check (vagary-core #858). A workflow that must react to an edit
# and runs no required check is exempted by name. Each finding carries a `uses` key the exemptions match exactly.
_EXPR = "$" + "{{"  # an Actions expression opener, never written out (render.py refuses one inlined into a run block)
_DOCKERFILE = re.compile(r"(?:^|/)(?:Dockerfile(?:\.(?!(?:md|txt|rst|json|ya?ml)$)[^/]*)?|[^/]+\.[Dd]ockerfile)$")
_FROM = re.compile(r"^\s*FROM\s+(?P<rest>.+?)\s*$", re.I)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_NODE_VERSION = re.compile(r"^\s*(?:-\s+)?node-version(?P<file>-file)?\s*:\s*(?P<v>.*?)\s*$")
_NODE_EXACT = re.compile(r"^v?\d+\.\d+\.\d+$")


def image_findings(text):
    """[(line, class, image, None)] for every `FROM` whose image is not named by digest. `scratch` and an earlier
    stage's name pass; an image built from an ARG cannot be judged here (image_arg)."""
    out, stages = [], set()
    for i, line in enumerate(text.splitlines(), 1):
        m = _FROM.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        words = [w for w in m.group("rest").split() if not w.startswith("--")]
        if not words:
            continue
        image = words[0]
        if len(words) >= 3 and words[1].lower() == "as":
            stages.add(words[2].lower())
        if image.lower() == "scratch" or image.lower() in stages and not _DIGEST.search(image):
            continue
        if "$" in image:
            out.append((i, "image_arg", image, None))
        elif not _DIGEST.search(image):
            out.append((i, "image_tag", image, None))
    return out


def _node_items(lines, at, value):
    """The versions a `node-version` value names: one scalar, a flow list (`["20.20.2", "22.23.4"]`, a matrix), or for an
    empty value the block list of `- x` items indented under it. [] when it is none of those."""
    if value.startswith("[") and value.endswith("]"):
        return [x.strip().strip("'\"") for x in value[1:-1].split(",") if x.strip()]
    if value:
        return [value]
    indent, items = len(lines[at]) - len(lines[at].lstrip()), []
    for nxt in lines[at + 1:]:
        if not nxt.strip() or nxt.lstrip().startswith("#"):
            continue
        if len(nxt) - len(nxt.lstrip()) <= indent or not nxt.lstrip().startswith("- "):
            break
        items.append(nxt.lstrip()[2:].split(" #", 1)[0].strip().strip("'\""))
    return items


def node_version_findings(text, head=None, path=""):
    """[(line, class, value, None)] for every `node-version` that is not an exact X.Y.Z, and every `node-version-file`
    whose file (read at head) does not hold one. A list (a matrix, flow or block style) is exact only when every item
    is; an empty value with no list under it is loose."""
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        m = _NODE_VERSION.match(line)
        if not m:
            continue
        value = m.group("v").split(" #", 1)[0].strip().strip("'\"")
        if m.group("file"):
            body = (blob(head, value) or "") if head else ""
            first = body.strip().splitlines()[0].strip() if body.strip() else ""
            if not _NODE_EXACT.match(first):
                out.append((i, "node_version_loose", "node-version-file " + value, None))
        elif _EXPR in value:
            out.append((i, "node_version_expr", value, None))
        else:
            items = _node_items(lines, i - 1, value)
            if not items or not all(_NODE_EXACT.match(x) for x in items):
                out.append((i, "node_version_loose", value or ", ".join(items), None))
    return out


def pr_edited_findings(text):
    """[(line, "pr_edited", "<event>.types edited", None)] for each pull_request trigger (or its _target variant) whose
    types list `edited`. Read from the `on:` block by indentation (stdlib only); a form it cannot read never hides one:
    any `edited` token in an event's block counts."""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        if re.match(r"^(?:on|\"on\"|'on'|true)\s*:", lines[i]):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or lines[j][:1] in (" ", "\t", "#")):
                j += 1
            block = list(range(i, j))
            for k in block:
                m = re.match(r"^(?P<ind>\s*)(?P<ev>pull_request(?:_target)?)\s*:(?P<rest>.*)$", lines[k])
                if not m:
                    continue
                ind = len(m.group("ind"))
                region = [(k, m.group("rest"))]
                for n in block[block.index(k) + 1:]:
                    if lines[n].strip() and not lines[n].lstrip().startswith("#") and len(lines[n]) - len(lines[n].lstrip()) <= ind:
                        break
                    region.append((n, lines[n]))
                # Only the types list counts (a branch named `edited` is not a trigger type): an inline `types: [...]`
                # or `{types: [...]}`, or the `- item` lines under a `types:` key.
                tind = None
                for n, part in region:
                    code = part.split("#", 1)[0]
                    pind = len(part) - len(part.lstrip())
                    if tind is not None and code.strip() and pind <= tind and not code.lstrip().startswith("-"):
                        tind = None
                    t = re.search(r"(?<![A-Za-z0-9_-])types\s*:(?P<v>.*)$", code)
                    if t:
                        tind = pind if n != k else ind
                        code = t.group("v")
                    elif tind is None:
                        continue
                    if re.search(r"(?<![A-Za-z0-9_-])edited(?![A-Za-z0-9_-])", code):
                        out.append((n + 1, "pr_edited", "%s.types edited" % m.group("ev"), None))
                        break
            i = j
        else:
            i += 1
    return out


def dockerfiles(head):
    """The head tree's Dockerfiles (Dockerfile, Dockerfile.<x>, <x>.Dockerfile), NUL-separated."""
    return [p for p in git("ls-tree", "-r", "-z", "--name-only", head).split("\0") if p and _DOCKERFILE.search(p)]


def workflow_files(head):
    """The head tree's workflow and composite-action files, NUL-separated so no name is quoted or skipped."""
    return [p for p in git("ls-tree", "-r", "-z", "--name-only", head).split("\0") if p and _SR_FILE.search(p)]


def run_pins(m, repo, base, head):
    pins = m["pins"]
    mode = pins["mode"]
    resolve_head(base, head)
    files = workflow_files(head)
    images = dockerfiles(head)
    rows, used = [], set()
    found = []
    for path in files:
        text = blob(head, path) or ""
        found += [(path,) + f for f in pin_findings(text)]
        found += [(path,) + f for f in node_version_findings(text, head, path)]
        if path.startswith(".github/workflows/"):
            found += [(path,) + f for f in pr_edited_findings(text)]
    for path in images:
        found += [(path,) + f for f in image_findings(blob(head, path) or "")]
    for path, line, cls, uses, label in found:
        hit = next((e for e in pins["exemptions"] if e["uses"] == uses and e["repo"] in ("*", repo)
                    and e["file"] in ("*", path)), None)
        if hit:
            used.add(id(hit))
        rows.append((path, line, cls, uses, label, hit))
    level = "error" if mode == "enforce" else "warning"
    failing = [r for r in rows if r[5] is None]
    lines = ["## Pinned inputs and PR triggers: %s" % repo,
             "%d workflow/action files and %d Dockerfiles at head `%s` (manifest `pins`, mode `%s`): %d findings "
             "(`uses:` pins, image digests, exact node-version, F19 `edited` triggers), %d exempt."
             % (len(files), len(images), head, mode, len(failing), len(rows) - len(failing))]
    count = {}
    for path, line, cls, uses, label, hit in rows:
        if hit:
            lines.append("- EXEMPT %s: %s (record %s: %s)" % (md_code("%s:%d" % (path, line)), md_code(uses),
                                                               md_code(hit["record"]), md_code(hit["reason"])))
            continue
        count[cls] = count.get(cls, 0) + 1
        what = "%s: %s%s" % (cls, uses, " # " + label if label else "")
        if count[cls] <= FLOOR_MAX_LISTED:
            lines.append("- %s %s" % (cls.upper(), md_code("%s:%d %s" % (path, line, what))))
        print("::%s file=%s,line=%d,title=action pin::%s" % (level, _cmd_prop(path), line, _cmd_data(what)))
    for cls in PIN_CLASSES:
        if count.get(cls, 0) > FLOOR_MAX_LISTED:
            lines.append("- ... and %d more %s" % (count[cls] - FLOOR_MAX_LISTED, cls))
    for e in pins["exemptions"]:
        if e["repo"] == repo and id(e) not in used:
            lines.append("- STALE EXEMPTION %s in %s (record %s): nothing at head uses it; reported, not enforced"
                         % (md_code(e["uses"]), md_code(e["file"]), md_code(e["record"])))
    if not failing:
        lines.append("Every `uses:` is pinned to a commit with its exact release, every image by digest, every "
                     "node-version exact, and no pull_request trigger lists `edited`; or the finding is exempt.")
    elif mode == "report":
        lines.append("Report-only (mode `report`): %d listed, not enforced." % len(failing))
    else:
        lines.append("Refused (mode `enforce`): pin each listed ref to its commit with `# vX.Y.Z` (first party: "
                     "`# <repo> #<PR> merge`), each image to `@sha256:`, each node-version to an exact X.Y.Z, and drop "
                     "`edited` from pull_request types (F19), or record an exemption in the trusted manifest.")
    summary(lines)
    return 1 if mode == "enforce" and failing else 0


# ---------- workflow-lint (C1 admission, root 2026-10-29) ----------
# zizmor (MIT; offline audits only, so the verdict depends on the head tree alone) and actionlint (shellcheck off: it
# is slow and hung on large run blocks) read the head tree as data. This mode turns their JSON into the job summary and
# annotations. A tool that did not run, or whose output does not parse, is INCOMPLETE: never clean, never a pass.
WL_MAX_LISTED = 200


def _zizmor_shape(doc):
    """None when `doc` is zizmor's JSON finding list, else why it is not."""
    if not isinstance(doc, list):
        return "output is %s, not a finding list" % type(doc).__name__
    for i, f in enumerate(doc):
        if not (isinstance(f, dict) and isinstance(f.get("ident"), str) and isinstance(f.get("locations"), list)
                and isinstance(f.get("determinations"), dict) and isinstance(f["determinations"].get("severity"), str)):
            return "finding %d is not a finding (ident, determinations.severity, locations)" % i
    return None


def _actionlint_shape(doc, rc):
    """None when `doc` is actionlint's JSON error list and agrees with its exit code, else why it is not."""
    if not isinstance(doc, list):
        return "output is %s, not an error list" % type(doc).__name__
    for i, e in enumerate(doc):
        if not (isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("kind", "filepath", "message"))
                and isinstance(e.get("line"), int)):
            return "error %d is not an error (kind, filepath, line, message)" % i
    if (rc == 1) != bool(doc):
        return "exited %d with %d errors" % (rc, len(doc))
    return None


def _zizmor_rows(doc):
    rows = []
    for f in doc:
        sev = f["determinations"]["severity"]
        path, line = "?", 0
        for loc in f["locations"]:
            key = ((loc.get("symbolic") or {}).get("key") or {}) if isinstance(loc, dict) else {}
            local = key.get("Local") if isinstance(key, dict) else None
            if isinstance(local, dict) and (local.get("given_path") or local.get("verbatim_path")):
                path = str(local.get("given_path") or local["verbatim_path"])
                path = path[2:] if path.startswith("./") else path
            row = (((loc.get("concrete") or {}).get("location") or {}).get("start_point") or {}).get("row") \
                if isinstance(loc, dict) else None
            if isinstance(row, int):
                line = row + 1
            break
        rows.append((f["ident"], sev, path, line, str(f.get("desc") or "")))
    return rows


def _actionlint_rows(doc):
    return [(e["kind"], e["filepath"], e["line"], e["message"]) for e in doc]


def _load_tool(tool, path, rc, fetched, ok_codes, shape):
    """(the tool's JSON document, why the run is INCOMPLETE or None). The output must have the tool's own shape: an empty
    file, `{}`, `null` or `[1, 2]` is not a clean run (root's R4 of #41, B3)."""
    if fetched != "success":
        return None, "was not fetched (step outcome %s)" % fetched
    if rc == 124:
        return None, "timed out"
    if rc not in ok_codes:
        return None, "exited %d" % rc
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.loads(fh.read())
    except (OSError, ValueError) as exc:
        return None, "output did not parse (%s)" % type(exc).__name__
    why = shape(doc, rc) if tool == "actionlint" else shape(doc)
    return (None, why) if why else (doc, None)


def run_workflow_lint(m, repo, head, zizmor, zizmor_rc, actionlint, actionlint_rc, zizmor_fetch="success",
                      actionlint_fetch="success"):
    mode = m["workflow_lint"]["mode"]
    level = "error" if mode == "enforce" else "warning"
    lines = ["## Workflow lint: %s" % repo, "zizmor (offline, no PR-controlled config, ignores or .gitignore) and "
             "actionlint (the trusted config) over head `%s` (manifest `workflow_lint`, mode `%s`)." % (head, mode)]
    resolve_head(None, head)
    if not workflow_files(head):
        lines.append("Nothing to audit: the head tree has no workflow or composite-action file.")
        summary(lines)
        return 0
    zdoc, zwhy = _load_tool("zizmor", zizmor, zizmor_rc, zizmor_fetch, (0,), _zizmor_shape)
    adoc, awhy = _load_tool("actionlint", actionlint, actionlint_rc, actionlint_fetch, (0, 1), _actionlint_shape)
    findings = 0
    for tool, why in (("zizmor", zwhy), ("actionlint", awhy)):
        if why:
            lines.append("- INCOMPLETE: %s %s" % (tool, why))
            print("::%s title=workflow lint::%s %s; the scan is incomplete" % (level, tool, _cmd_data(why)))
    if zdoc is not None:
        rows = _zizmor_rows(zdoc)
        by = {}
        for ident, sev, path, line, desc in rows:
            by[(sev, ident)] = by.get((sev, ident), 0) + 1
        lines.append("zizmor: %d findings%s" % (len(rows), "".join(
            "; %s %s %d" % (sev, md_code(ident), n) for (sev, ident), n in sorted(by.items(), key=lambda kv: -kv[1]))))
        for ident, sev, path, line, desc in rows[:WL_MAX_LISTED]:
            print("::%s file=%s,line=%d,title=zizmor %s::%s" % (level, _cmd_prop(path), max(line, 1), _cmd_prop(ident),
                                                                _cmd_data("%s (%s)" % (desc, sev))))
        findings += len(rows)
    if adoc is not None:
        rows = _actionlint_rows(adoc)
        by = {}
        for kind, path, line, msg in rows:
            by[kind] = by.get(kind, 0) + 1
        lines.append("actionlint: %d findings%s" % (len(rows), "".join(
            "; %s %d" % (md_code(k), n) for k, n in sorted(by.items(), key=lambda kv: -kv[1]))))
        for kind, path, line, msg in rows[:WL_MAX_LISTED]:
            print("::%s file=%s,line=%d,title=actionlint %s::%s" % (level, _cmd_prop(path), max(line, 1), _cmd_prop(kind),
                                                                    _cmd_data(msg)))
        findings += len(rows)
    incomplete = bool(zwhy or awhy)
    if mode == "report":
        lines.append("Report-only (mode `report`): %d findings%s, not enforced."
                     % (findings, " and an INCOMPLETE scan" if incomplete else ""))
    elif findings or incomplete:
        lines.append("Refused (mode `enforce`): %d findings%s." % (findings, ", INCOMPLETE" if incomplete else ""))
    summary(lines)
    return 1 if mode == "enforce" and (findings or incomplete) else 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("integrity", "protected-paths", "timeout-floor", "sibling-read", "pins",
                                     "workflow-lint"))
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base", help="required, except in timeout-floor mode (which reads the head tree only)")
    ap.add_argument("--head", required=True)
    ap.add_argument("--zizmor", help="workflow-lint: zizmor's JSON output")
    ap.add_argument("--zizmor-rc", type=int, help="workflow-lint: zizmor's exit code")
    ap.add_argument("--actionlint", help="workflow-lint: actionlint's JSON output")
    ap.add_argument("--actionlint-rc", type=int, help="workflow-lint: actionlint's exit code")
    ap.add_argument("--zizmor-fetch", default="success", help="workflow-lint: the zizmor fetch step's outcome")
    ap.add_argument("--actionlint-fetch", default="success", help="workflow-lint: the actionlint fetch step's outcome")
    a = ap.parse_args(argv)
    try:
        if a.base is None and a.mode not in ("timeout-floor", "sibling-read", "pins", "workflow-lint"):
            raise IntegrityError("--base is required in %s mode" % a.mode)
        with open(a.manifest, encoding="utf-8") as fh:
            m = validate_manifest(json.load(fh))
        if a.mode == "workflow-lint":
            if None in (a.zizmor, a.zizmor_rc, a.actionlint, a.actionlint_rc):
                raise IntegrityError("workflow-lint needs --zizmor, --zizmor-rc, --actionlint and --actionlint-rc")
            return run_workflow_lint(m, a.repo, a.head, a.zizmor, a.zizmor_rc, a.actionlint, a.actionlint_rc,
                                     a.zizmor_fetch, a.actionlint_fetch)
        fn = {"integrity": run_integrity, "protected-paths": run_protected, "timeout-floor": run_timeout_floor,
              "sibling-read": run_sibling_read, "pins": run_pins}[a.mode]
        return fn(m, a.repo, a.base, a.head)
    except (IntegrityError, OSError, ValueError) as exc:
        print("::error title=trusted %s::%s" % (a.mode, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
