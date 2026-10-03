#!/usr/bin/env python3
"""Change-impact planner: decide which CI work a change can affect, deterministically.

This is a DETERMINISTIC cognitive operator (cognition-ladder ruling, 2026-10-01): the same inputs always
give the same plan, its confidence is 1.0, and the decision record carries a validity predicate. When the
predicate's inputs change, the record is stale and the plan must be recomputed. Anything it cannot decide
for certain becomes mode=full. It never skips silently: every skipped job carries a reason and the plan id.

Inputs
  --config        the repo's plan config (JSON), read from the BASE commit, so a change cannot weaken its own plan
  --root          a checkout of the BASE commit holding at least the manifests the config needs
  --paths-file    changed paths, one per line (a rename lists both names)
  --expected-count  the number of changed files the host reports; a different count means truncation -> full
  --event / --base / --head
Outputs
  --out-json      the decision record (also printed)
  --github-output appends plan, mode, plan_id, run (job -> bool) and matrices (name -> include list)

Method (version PLANNER_VERSION)
  1. Not a pull request, no config, no paths, or a truncated list => full.
  2. Any path matching a BUILTIN full trigger (workflows, CI config, lockfiles, manifests, workspace files,
     migrations) or a config `full_globs` => full. Config cannot remove a builtin trigger.
  3. Paths matching `inert_globs` affect no package. Each other path maps to the package whose directory
     is its longest prefix, or to the packages listed in `extra_edges` for a glob it matches. A path that
     maps to nothing => full (unknown impact).
  4. affected = changed packages + every package that depends on one, transitively (reverse closure of
     the workspace graph read from the manifests).
  5. Any `hub_packages` member affected => full.
  6. Otherwise each job and matrix entry runs iff its rule matches the affected set.
  Reuse (v1.1): a PUSH whose tree has a receipt from a successful FULL run (actions/full-run-receipt) of the
  identical tree, with equal lockfile and workflow hashes and the same planner version, plans `reused`:
  every planned job is skipped with the run id as the reason. No other event ever reuses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

PLANNER_VERSION = "1.1.0"
OPERATOR_ID = "ci.change-impact-plan"

# Paths that can change how CI itself, the dependency graph or the database behaves. Always full.
BUILTIN_FULL_GLOBS = [
    ".github/**",
    "**/package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package-lock.json",
    "yarn.lock",
    "npm-shrinkwrap.json",
    ".npmrc",
    ".nvmrc",
    ".node-version",
    ".tool-versions",
    "turbo.json",
    "nx.json",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "**/requirements*.txt",
    "**/migrations/**",
    "**/alembic/**",
    "**/prisma/**",
    "**/Dockerfile*",
]

RULE_KINDS = ("always", "full_only", "any_package", "{packages: [..]}", "{any_except: [..]}")


def glob_to_regex(pattern: str) -> re.Pattern:
    """`**` crosses directories, `*` and `?` do not. A pattern without a slash matches at any depth only
    when written as `**/name`; a bare name matches the root only."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def first_match(path: str, globs: list[str]) -> str | None:
    for g in globs:
        if glob_to_regex(g).match(path):
            return g
    return None


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def sha256_tree(root: Path, rel_dir: str) -> str | None:
    base = root / rel_dir
    if not base.is_dir():
        return None
    h = hashlib.sha256()
    for p in sorted(x for x in base.rglob("*") if x.is_file()):
        h.update(str(p.relative_to(root)).encode() + b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


# ---------- workspace graph ----------

def read_pnpm_workspace_patterns(root: Path) -> list[str]:
    """Reads the `packages:` list of pnpm-workspace.yaml without a YAML dependency (the runner has none)."""
    text = (root / "pnpm-workspace.yaml").read_text()
    patterns, in_packages = [], False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw.startswith((" ", "\t", "-")):
            in_packages = line.strip() == "packages:"
            continue
        if in_packages:
            m = re.match(r"^\s*-\s*(.+?)\s*$", line)
            if m:
                patterns.append(m.group(1).strip().strip("'\""))
    if not patterns:
        raise ValueError("pnpm-workspace.yaml has no packages list")
    return patterns


def discover_pnpm_packages(root: Path) -> dict[str, dict]:
    patterns = read_pnpm_workspace_patterns(root)
    include = [p for p in patterns if not p.startswith("!")]
    exclude = [p[1:] for p in patterns if p.startswith("!")]
    pkgs: dict[str, dict] = {}
    for manifest in sorted(root.rglob("package.json")):
        rel_dir = manifest.parent.relative_to(root).as_posix()
        if rel_dir == "." or "node_modules" in rel_dir.split("/"):
            continue
        if not any(glob_to_regex(p).match(rel_dir) for p in include):
            continue
        if any(glob_to_regex(p).match(rel_dir) or rel_dir.startswith(p.rstrip("/*") + "/") for p in exclude):
            continue
        data = json.loads(manifest.read_text())
        name = data.get("name")
        if not name:
            raise ValueError(f"{rel_dir}/package.json has no name")
        deps = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update((data.get(key) or {}).keys())
        pkgs[name] = {"dir": rel_dir, "deps": deps}
    for info in pkgs.values():
        info["deps"] = {d for d in info["deps"] if d in pkgs}
    return pkgs


def declared_packages(cfg: dict) -> dict[str, dict]:
    """For repos without a JS workspace: `workspace.packages = {name: {"dir": "x", "deps": [..]}}`."""
    pkgs = {}
    for name, spec in (cfg.get("packages") or {}).items():
        pkgs[name] = {"dir": spec["dir"].rstrip("/"), "deps": set(spec.get("deps") or [])}
    for name, info in pkgs.items():
        unknown = info["deps"] - set(pkgs)
        if unknown:
            raise ValueError(f"package {name} depends on undeclared {sorted(unknown)}")
    return pkgs


def reverse_closure(pkgs: dict[str, dict], seeds: set[str]) -> set[str]:
    dependents: dict[str, set[str]] = {n: set() for n in pkgs}
    for name, info in pkgs.items():
        for d in info["deps"]:
            dependents[d].add(name)
    seen, stack = set(seeds), list(seeds)
    while stack:
        for nxt in dependents.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def owner_package(path: str, pkgs: dict[str, dict]) -> str | None:
    best, best_len = None, -1
    for name, info in pkgs.items():
        d = info["dir"]
        if (path == d or path.startswith(d + "/")) and len(d) > best_len:
            best, best_len = name, len(d)
    return best


# ---------- planning ----------

def rule_matches(rule, affected: set[str]) -> tuple[bool, str]:
    if rule == "always":
        return True, "always runs"
    if rule == "full_only":
        return False, "runs only in a full plan"
    if rule == "any_package":
        return (bool(affected), "a package is affected" if affected else "no package is affected")
    if isinstance(rule, dict) and "packages" in rule:
        hit = sorted(affected & set(rule["packages"]))
        if hit:
            return True, "affected: " + ", ".join(hit)
        return False, "none of " + ", ".join(sorted(rule["packages"])) + " is affected"
    if isinstance(rule, dict) and "any_except" in rule:
        hit = sorted(affected - set(rule["any_except"]))
        if hit:
            return True, "affected: " + ", ".join(hit)
        return False, "no affected package outside " + ", ".join(sorted(rule["any_except"]))
    raise ValueError(f"unknown rule {rule!r}; expected one of {RULE_KINDS}")


def validity_predicate(root: Path, config_path: Path, cfg: dict, base: str, head: str) -> dict:
    lockfiles = {}
    for lf in ("pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"):
        h = sha256_file(root / lf)
        if h:
            lockfiles[lf] = h
    return {
        "planner_version": PLANNER_VERSION,
        "config_sha256": sha256_file(config_path),
        "lockfiles_sha256": lockfiles,
        "workflows_sha256": sha256_tree(root, ".github/workflows"),
        "base": base,
        "head": head,
        "holds_while": "planner_version, config, lockfiles and workflows at base are unchanged and head is the same commit",
    }


def tested_identity(tested_root: Path | None, tree: str) -> dict | None:
    """What a FULL run actually tested: the tree it checked out, plus the lockfile and workflow hashes of
    that same tree. Tree equality already implies the rest; the hashes are carried so a receipt names its
    own validity predicate explicitly."""
    if not tree or tested_root is None or not tested_root.is_dir():
        return None
    lockfiles = {}
    for lf in ("pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"):
        h = sha256_file(tested_root / lf)
        if h:
            lockfiles[lf] = h
    return {"tree": tree, "lockfiles_sha256": lockfiles,
            "workflows_sha256": sha256_tree(tested_root, ".github/workflows"), "planner_version": PLANNER_VERSION}


def reuse_verdict(receipt: dict | None, tested: dict | None, event: str) -> tuple[bool, str]:
    """A push may reuse a successful FULL run that tested the identical tree. Any other event never does
    (schedule, release, dispatch and merge_group always run in full)."""
    if event != "push":
        return False, f"event {event} never reuses a run"
    if not receipt:
        return False, "no full-run receipt for this tree"
    if not tested:
        return False, "the tested tree could not be identified"
    if receipt.get("mode") != "full":
        return False, "the receipt is not from a full plan"
    for key in ("tree", "lockfiles_sha256", "workflows_sha256", "planner_version"):
        if receipt.get("tested", {}).get(key) != tested.get(key):
            return False, f"receipt {key} differs from this tree's"
    return True, f"run {receipt.get('run_id')} passed the full suite on identical tree {tested['tree'][:12]}"


def plan(*, cfg: dict | None, root: Path, config_path: Path, paths: list[str] | None, event: str,
         base: str, head: str, expected_count: int | None, forced_full_reason: str | None = None,
         tested: dict | None = None, receipt: dict | None = None) -> dict:
    paths = sorted({p.strip() for p in (paths or []) if p.strip()})
    record = {
        "operator": OPERATOR_ID,
        "planner_version": PLANNER_VERSION,
        "method": "deterministic: glob rules + workspace reverse-dependency closure",
        "confidence": 1.0,
        "inputs": {
            "event": event,
            "base": base,
            "head": head,
            "changed_paths": len(paths),
            "paths_sha256": hashlib.sha256("\n".join(paths).encode()).hexdigest(),
        },
        "evidence": {"full_triggers": [], "unmapped": [], "inert": [], "changed_packages": []},
        "affected_packages": [],
        "tested": tested,
    }

    def finish(mode: str, reason: str, affected: set[str] | None = None) -> dict:
        record["mode"] = mode
        record["reason"] = reason
        record["affected_packages"] = sorted(affected or [])
        jobs, matrices = {}, {}
        cfg_jobs = (cfg or {}).get("jobs") or {}
        cfg_mats = (cfg or {}).get("matrices") or {}
        for job, rule in sorted(cfg_jobs.items()):
            if mode == "reused":
                jobs[job] = {"run": False, "reason": f"reused: {reason}"}
            elif mode == "full":
                jobs[job] = {"run": True, "reason": f"full plan: {reason}"}
            else:
                run, why = rule_matches(rule, affected or set())
                jobs[job] = {"run": run, "reason": why}
        for name, entries in sorted(cfg_mats.items()):
            inc, skipped = [], []
            for entry in entries:
                if mode == "reused":
                    skipped.append({"entry": entry["include"], "reason": f"reused: {reason}"})
                    continue
                if mode == "full":
                    inc.append(entry["include"])
                    continue
                run, why = rule_matches(entry.get("rule", "always"), affected or set())
                (inc if run else skipped).append(entry["include"] if run else {"entry": entry["include"], "reason": why})
            matrices[name] = {"include": inc, "skipped": skipped}
        record["jobs"] = jobs
        record["matrices"] = matrices
        record["validity"] = validity_predicate(root, config_path, cfg or {}, base, head)
        ident = json.dumps({"v": record["validity"], "p": record["inputs"]["paths_sha256"], "e": event},
                           sort_keys=True)
        record["plan_id"] = hashlib.sha256(ident.encode()).hexdigest()[:12]
        return record

    reuse, why = reuse_verdict(receipt, tested, event)
    record["reuse"] = {"reused": reuse, "reason": why}
    if reuse and cfg is not None and not forced_full_reason:
        return finish("reused", why)
    if forced_full_reason:
        return finish("full", forced_full_reason)
    if cfg is None:
        return finish("full", "no plan config on the base commit")
    if event not in ("pull_request", "pull_request_target"):
        return finish("full", f"event {event} always runs the full suite")
    if not paths:
        return finish("full", "no changed paths could be read")
    if expected_count is not None and expected_count > len(paths):
        return finish("full", f"changed-file list looks truncated ({len(paths)} read, {expected_count} reported)")

    full_globs = BUILTIN_FULL_GLOBS + list(cfg.get("full_globs") or [])
    triggers = [{"path": p, "rule": g} for p in paths if (g := first_match(p, full_globs))]
    record["evidence"]["full_triggers"] = triggers
    if triggers:
        return finish("full", f"{triggers[0]['path']} matches full trigger {triggers[0]['rule']}"
                      + (f" (+{len(triggers) - 1} more)" if len(triggers) > 1 else ""))

    ws = cfg.get("workspace") or {"type": "none"}
    try:
        if ws.get("type") == "pnpm":
            pkgs = discover_pnpm_packages(root)
        elif ws.get("type") == "declared":
            pkgs = declared_packages(ws)
        elif ws.get("type") == "none":
            pkgs = {}
        else:
            raise ValueError(f"unknown workspace type {ws.get('type')!r}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return finish("full", f"workspace graph unreadable: {exc}")

    inert_globs = list(cfg.get("inert_globs") or [])
    extra_edges = cfg.get("extra_edges") or {}
    changed: set[str] = set()
    for p in paths:
        if first_match(p, inert_globs):
            record["evidence"]["inert"].append(p)
            continue
        owners = set()
        for glob, targets in extra_edges.items():
            if glob_to_regex(glob).match(p):
                owners.update(targets)
        owner = owner_package(p, pkgs)
        if owner:
            owners.add(owner)
        unknown = owners - set(pkgs)
        if unknown:
            return finish("full", f"extra_edges for {p} name unknown package(s) {sorted(unknown)}")
        if not owners:
            record["evidence"]["unmapped"].append(p)
        changed |= owners
    record["evidence"]["changed_packages"] = sorted(changed)
    if record["evidence"]["unmapped"]:
        u = record["evidence"]["unmapped"]
        return finish("full", f"{u[0]} maps to no package (unknown impact)" + (f" (+{len(u) - 1} more)" if len(u) > 1 else ""))

    affected = reverse_closure(pkgs, changed)
    hubs = sorted(affected & set(cfg.get("hub_packages") or []))
    if hubs:
        return finish("full", "hub package affected: " + ", ".join(hubs), affected)
    if not affected:
        return finish("reduced", "only inert paths changed", affected)
    return finish("reduced", "affected: " + ", ".join(sorted(affected)), affected)


def summary_markdown(rec: dict) -> str:
    lines = [f"### change-impact plan `{rec['plan_id']}`: **{rec['mode']}**", "", f"{rec['reason']}", ""]
    lines.append(f"operator `{rec['operator']}` v{rec['planner_version']}, confidence {rec['confidence']}, "
                 f"{rec['inputs']['changed_paths']} path(s), base `{rec['inputs']['base'][:12]}` head `{rec['inputs']['head'][:12]}`")
    if rec["affected_packages"]:
        lines.append("")
        lines.append("affected: " + ", ".join(f"`{p}`" for p in rec["affected_packages"]))
    lines += ["", "| job | runs | reason |", "|---|---|---|"]
    for job, j in rec["jobs"].items():
        lines.append(f"| {job} | {'yes' if j['run'] else 'skipped by plan'} | {j['reason']} |")
    for name, m in rec["matrices"].items():
        for e in m["include"]:
            lines.append(f"| {name} {json.dumps(e)} | yes | |")
        for s in m["skipped"]:
            lines.append(f"| {name} {json.dumps(s['entry'])} | skipped by plan | {s['reason']} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--fallback-config", help="head-commit config, used only to enumerate a FULL plan")
    ap.add_argument("--paths-file")
    ap.add_argument("--expected-count", type=int)
    ap.add_argument("--event", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="")
    ap.add_argument("--tree", default="", help="tree SHA of the commit this run tests")
    ap.add_argument("--tested-root", help="checkout of the tested commit (lockfiles + workflows)")
    ap.add_argument("--receipt", help="a full-run receipt found for --tree (push events only)")
    ap.add_argument("--out-json")
    ap.add_argument("--github-output")
    ap.add_argument("--summary")
    a = ap.parse_args(argv)

    root = Path(a.root)
    config_path = root / a.config
    cfg, forced = None, None
    if config_path.is_file():
        cfg = json.loads(config_path.read_text())
        if cfg.get("schema") != 1:
            cfg, forced = None, f"plan config schema {cfg.get('schema')!r} is not 1"
    elif a.fallback_config and Path(a.fallback_config).is_file():
        # The base has no config (the adoption PR itself, or a base older than adoption). The head's config may
        # only ENUMERATE the full suite; it never reduces anything, because a change must not plan itself.
        cfg = json.loads(Path(a.fallback_config).read_text())
        forced = "no plan config on the base commit (head config used only to list the full suite)"
    paths = Path(a.paths_file).read_text().splitlines() if a.paths_file and os.path.exists(a.paths_file) else []
    rec = plan(cfg=cfg, root=root, config_path=config_path, paths=paths, event=a.event, base=a.base,
               head=a.head, expected_count=a.expected_count, forced_full_reason=forced,
               tested=tested_identity(Path(a.tested_root) if a.tested_root else None, a.tree),
               receipt=json.loads(Path(a.receipt).read_text()) if a.receipt and os.path.exists(a.receipt) else None)
    text = json.dumps(rec, indent=2, sort_keys=True)
    print(text)
    if a.out_json:
        Path(a.out_json).write_text(text + "\n")
    if a.github_output:
        run = {k: v["run"] for k, v in rec["jobs"].items()}
        mats = {k: v["include"] for k, v in rec["matrices"].items()}
        with open(a.github_output, "a") as fh:
            fh.write(f"plan={json.dumps(rec, sort_keys=True, separators=(',', ':'))}\n")
            fh.write(f"mode={rec['mode']}\nplan_id={rec['plan_id']}\n")
            fh.write(f"tested={json.dumps(rec.get('tested'), sort_keys=True, separators=(',', ':'))}\n")
            fh.write(f"run={json.dumps(run, separators=(',', ':'))}\n")
            fh.write(f"matrices={json.dumps(mats, separators=(',', ':'))}\n")
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(summary_markdown(rec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
