#!/usr/bin/env python3
"""Trusted path classifier for the org ruleset required workflows.

This file is the single source of the classifier. trusted-workflow-integrity.yml and
trusted-protected-paths.yml carry a byte-identical copy inline (a heredoc), because a ruleset
workflow must not read anything from the repository it judges, and the pinned workflow bytes are
the trust root. trusted/tests/test_classify.py fails if an inline copy drifts from this file.

The PR is DATA. Every file is read with `git show <sha>:<path>`; nothing from the PR is executed or
imported. Ratchet constants are read with ast.parse, which parses and never runs the code.

Exit codes: 0 pass, 1 policy refusal (protected-paths, once fail-closed), 2 integrity error.
"""
import argparse
import ast
import fnmatch
import json
import os
import re
import subprocess
import sys

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
    return m


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


# --- reporting -------------------------------------------------------------------------------

def summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write(text)


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


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("integrity", "protected-paths"))
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.manifest, encoding="utf-8") as fh:
            m = validate_manifest(json.load(fh))
        fn = run_integrity if a.mode == "integrity" else run_protected
        return fn(m, a.repo, a.base, a.head)
    except (IntegrityError, OSError, ValueError) as exc:
        print("::error title=trusted %s::%s" % (a.mode, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
