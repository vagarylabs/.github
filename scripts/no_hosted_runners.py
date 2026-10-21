#!/usr/bin/env python3
"""no-hosted-runners: refuse a GitHub-hosted runner in a PRIVATE repo's workflows, as it EFFECTIVELY resolves.

A hosted job in a private repo is refused in about 2 s with zero steps (no hosted budget), so it never runs. Reading
`runs-on:` text is not enough. Measured 2026-10-21:
  * `vars.RUNNER_TYPE || 'self-hosted'` (an expression) ran HOSTED wherever the repo var said ubuntu-latest;
  * jobs inside CALLED workflows (`uses: vagarylabs/.github/...`) carry their own runs-on.
So this script EVALUATES each runs-on expression with the caller's real `vars` (VARS_JSON, the job's
`toJSON(vars)`), and for every job that calls a reusable workflow, it evaluates the CALLED workflow's runs-on with the
caller's `with:` inputs and vars.
  * local calls (`./.github/workflows/x.yml`) are read from the checkout;
  * calls into public vagarylabs/.github are read at the pinned ref (raw.githubusercontent, no token);
  * a call into another PRIVATE repo cannot be read with this job's token. It is checked by that repo's own guard,
    and reported here as a note, not a pass.
A line may opt out with `# hosted-ok: <reason>`.
"""
import json
import os
import pathlib
import re
import sys
import urllib.request

HOSTED = re.compile(r"\b(?:ubuntu|windows|macos)-(?:latest|\d[\w.]*)\b")
ALLOW = re.compile(r"#\s*hosted-ok:\s*\S")
PUBLIC_REUSABLE_OWNER = "vagarylabs/.github"


# ── a small evaluator for the GitHub expression subset runs-on lines use ─────────────────────────────────────────
TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+)|(?P<op>&&|\|\||==|!=|!|\(|\)|,)|(?P<id>[A-Za-z_][\w.\-]*))")


def tokenize(src):
    out, i = [], 0
    while i < len(src):
        m = TOKEN.match(src, i)
        if not m or m.end() == i:
            if src[i:].strip() == "":
                break
            raise ValueError(f"unsupported expression near {src[i:i+20]!r}")
        i = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        out.append((kind, val[1:-1].replace("''", "'") if kind == "str" else val))
    return out


def falsy(v):
    return v in (None, False, 0, "") or v == []


def evaluate(expr, ctx):
    toks, pos = tokenize(expr), [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else (None, None)

    def take():
        t = peek(); pos[0] += 1; return t

    def primary():
        kind, val = take()
        if kind == "str":
            return val
        if kind == "num":
            return int(val)
        if kind == "op" and val == "(":
            v = disj(); take(); return v
        if kind == "op" and val == "!":
            return falsy(primary())
        if kind == "id":
            if peek() == ("op", "("):
                take(); args = []
                if peek() != ("op", ")"):
                    args.append(disj())
                    while peek() == ("op", ","):
                        take(); args.append(disj())
                take()
                if val == "fromJSON":
                    return json.loads(args[0]) if isinstance(args[0], str) else args[0]
                if val == "startsWith":
                    return str(args[0] or "").lower().startswith(str(args[1] or "").lower())
                if val == "contains":
                    hay = args[0]
                    return args[1] in hay if isinstance(hay, list) else str(args[1]).lower() in str(hay or "").lower()
                if val == "toJSON":
                    return json.dumps(args[0])
                raise ValueError(f"unsupported function {val}")
            if val in ("true", "false"):
                return val == "true"
            if val == "null":
                return None
            cur = ctx
            for part in val.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur
        raise ValueError(f"unexpected token {val!r}")

    def comparison():
        left = primary()
        while peek() in (("op", "=="), ("op", "!=")):
            op = take()[1]; right = primary()
            eq = str(left).lower() == str(right).lower() if not isinstance(left, bool) else left == right
            left = eq if op == "==" else not eq
        return left

    def conj():
        left = comparison()
        while peek() == ("op", "&&"):
            take(); right = comparison(); left = right if not falsy(left) else left
        return left

    def disj():
        left = conj()
        while peek() == ("op", "||"):
            take(); right = conj(); left = left if not falsy(left) else right
        return left

    return disj()


def resolve(runs_on, ctx):
    """The effective runs-on: the evaluated value for an expression, else the literal text."""
    text = runs_on.split("#", 1)[0].strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", text)
    if not m:
        return text
    v = evaluate(m.group(1), ctx)
    return json.dumps(v) if isinstance(v, list) else str(v if v is not None else "")


def is_hosted(effective):
    return bool(HOSTED.search(effective))


# ── workflow walking ────────────────────────────────────────────────────────────────────────────────────────────
def jobs(text):
    """[(job_id, block_text)] for a workflow's top-level jobs, by indentation."""
    body = ("\n" + text).split("\njobs:\n", 1)
    if len(body) < 2:
        return []
    out, cur, lines = [], None, []
    for line in body[1].split("\n"):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            if cur:
                out.append((cur, "\n".join(lines)))
            cur, lines = m.group(1), []
        elif cur:
            lines.append(line)
    if cur:
        out.append((cur, "\n".join(lines)))
    return out


def with_inputs(block):
    """The literal `with:` values of a job that calls a reusable workflow (expressions are kept as text)."""
    m = re.search(r"\n    with:\n((?:      .*\n?)+)", "\n" + block + "\n")
    out = {}
    for line in (m.group(1).split("\n") if m else []):
        kv = re.match(r"^      ([\w-]+):\s*(.*)$", line)
        if kv:
            v = kv.group(2).split(" #", 1)[0].strip()
            out[kv.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
    return out


def called_defaults(text):
    """inputs.<name>.default values declared by a reusable workflow's workflow_call."""
    out, name = {}, None
    for line in text.split("\n"):
        m = re.match(r"^      ([\w-]+):\s*$", line)
        if m:
            name = m.group(1)
        d = re.match(r"^        default:\s*(.*)$", line)
        if d and name:
            v = d.group(1).strip()
            out[name] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
    return out


def fetch_public(owner_repo, path, ref):
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"
    with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 - fixed host, public repo
        return r.read().decode("utf-8")


def check(root, vars_, repo_private, fetch=fetch_public):
    findings, notes = [], []
    base_ctx = {"vars": vars_, "github": {"event": {"repository": {"private": repo_private}}}}
    wf = pathlib.Path(root) / ".github" / "workflows"
    files = sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))) if wf.is_dir() else []
    for path in files:
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(root)
        for job, block in jobs(text):
            for line in block.split("\n"):
                m = re.match(r"^    runs-on:\s*(.*)$", line)
                if m and not ALLOW.search(line):
                    try:
                        eff = resolve(m.group(1), base_ctx)
                    except ValueError as e:
                        findings.append(f"{rel} [{job}]: runs-on could not be evaluated ({e}); write it so it can be, or add '# hosted-ok: <reason>'")
                        continue
                    if is_hosted(eff):
                        findings.append(f"{rel} [{job}]: runs-on resolves to {eff} with this repo's vars")
            u = re.search(r"^    uses:\s*(\S+)(.*)$", block, re.M)
            if not u or ALLOW.search(u.group(0)):
                continue
            target = u.group(1)
            try:
                if target.startswith("./"):
                    called = (pathlib.Path(root) / target[2:]).read_text(encoding="utf-8")
                elif target.startswith(PUBLIC_REUSABLE_OWNER + "/"):
                    path_ref = target[len(PUBLIC_REUSABLE_OWNER) + 1:]
                    cpath, _, ref = path_ref.partition("@")
                    called = fetch(PUBLIC_REUSABLE_OWNER, cpath, ref or "main")
                else:
                    notes.append(f"{rel} [{job}]: calls {target}, which is outside this repo and not public; that repo's own guard checks its runners")
                    continue
            except Exception as e:  # unreadable called workflow: refuse, never assume
                findings.append(f"{rel} [{job}]: could not read the called workflow {target} ({type(e).__name__})")
                continue
            inputs = {**called_defaults(called), **{k: v for k, v in with_inputs(block).items()}}
            for k, v in list(inputs.items()):
                if isinstance(v, str) and v.startswith("\x24{{"):
                    try:
                        inputs[k] = resolve(v, base_ctx)
                    except ValueError:
                        pass
            ctx = dict(base_ctx, inputs=inputs)
            for cjob, cblock in jobs(called):
                for line in cblock.split("\n"):
                    m = re.match(r"^    runs-on:\s*(.*)$", line)
                    if m and not ALLOW.search(line):
                        try:
                            eff = resolve(m.group(1), ctx)
                        except ValueError as e:
                            findings.append(f"{rel} [{job}] -> {target} [{cjob}]: runs-on could not be evaluated ({e})")
                            continue
                        if is_hosted(eff):
                            findings.append(f"{rel} [{job}] -> {target} [{cjob}]: called job resolves to {eff} with this repo's vars and inputs")
    return findings, notes, len(files)


def self_test():
    import tempfile
    vars_ = {"RUNNER_TYPE": "ubuntu-latest", "SECRET_SCAN_RUNNER": "vl-light"}
    called = ("on:\n  workflow_call:\n    inputs:\n      runner:\n        type: string\n        default: ubuntu-latest\njobs:\n"
              "  scan:\n    runs-on: \x24{{ inputs.runner != 'ubuntu-latest' && inputs.runner || vars.SECRET_SCAN_RUNNER || 'ubuntu-latest' }}\n"
              "  hard:\n    runs-on: ubuntu-latest\n")
    with tempfile.TemporaryDirectory() as d:
        w = pathlib.Path(d) / ".github" / "workflows"; w.mkdir(parents=True)
        (w / "local-called.yml").write_text(called.replace("  hard:\n    runs-on: ubuntu-latest\n", ""))
        (w / "ci.yml").write_text(
            "jobs:\n"
            "  literal:\n    runs-on: ubuntu-latest\n"
            "  via-var:\n    runs-on: \x24{{ vars.RUNNER_TYPE || 'self-hosted' }}\n"           # hosted only through the var
            "  fine:\n    runs-on: [self-hosted, vl-light]\n"
            "  allowed:\n    runs-on: windows-latest  # hosted-ok: MSI\n"
            "  local-call:\n    uses: ./.github/workflows/local-called.yml\n"                   # resolves vl-light: fine
            "  public-call:\n    uses: vagarylabs/.github/.github/workflows/scan.yml@abc\n"   # its `hard` job is hosted
            "  private-call:\n    uses: vagarylabs/vagary-core/.github/workflows/app-release.yml@main\n")
        got, notes, n = check(d, vars_, True, fetch=lambda o, p, r: called)
        joined = "\n".join(got)
        assert "[literal]" in joined and "[via-var]" in joined, got
        assert "[fine]" not in joined and "[allowed]" not in joined and "[local-call]" not in joined, got
        assert "[public-call] -> vagarylabs/.github/.github/workflows/scan.yml@abc [hard]" in joined, got
        assert "[public-call] -> vagarylabs/.github/.github/workflows/scan.yml@abc [scan]" not in joined, got
        assert len(notes) == 1 and "app-release.yml" in notes[0], notes
        assert len(got) == 3, got
        # The same tree with the var on the bridge: only the literal and the called hard-hosted job remain.
        got2, _, _ = check(d, {"RUNNER_TYPE": "vl-bridge", "SECRET_SCAN_RUNNER": "vl-light"}, True, fetch=lambda o, p, r: called)
        assert len(got2) == 2 and "[via-var]" not in "\n".join(got2), got2
    print("self-test OK: literal, var-resolved and called-workflow hosted runners are refused; self-hosted, allowlisted "
          "and bridge-resolving lines pass; a private cross-repo call is a note")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
        sys.exit(0)
    private = os.environ.get("REPO_PRIVATE") == "true"
    vars_ = json.loads(os.environ.get("VARS_JSON") or "{}")
    got, notes, n = check(".", vars_, private)
    for note in notes:
        print(f"::notice::{note}")
    if not private:
        print(f"PUBLIC repo: GitHub-hosted is correct here; {len(got)} hosted runner(s) noted, none refused")
        sys.exit(0)
    if n == 0:
        sys.exit("no workflow files found: refusing to report a pass for nothing")
    for f in got:
        print(f"::error::{f}. GitHub refuses a hosted job in a private repo (no hosted budget), so it never runs. Use the vl-bridge group, or '# hosted-ok: <reason>'")
    print(f"{n} workflow file(s), {len(got)} effective hosted runner(s), {len(notes)} note(s)")
    sys.exit(1 if got else 0)
