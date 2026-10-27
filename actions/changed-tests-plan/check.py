#!/usr/bin/env python3
"""changed-tests-plan check: the ONE validator for a pull request's `changed_tests` plan, version 1.

WHY. A pull request's fast tier defers the heavy suites to the merge queue, so a new or changed test used to run for
the first time there, and a defect in it evicted a whole group late. Each repository's fast tier now writes a plan of
the changed tests it must run first, and those lanes are REQUIRED. The mapping from a diff to a plan is repository
specific (vagaris: scripts/ci_change_class.py; vagary-core: scripts/ci-two-tier.py). The plan's SHAPE and the rules
below are shared, so land's admission check and every repository's aggregate read a plan the same way.

THE SHAPE is schema-v1.json, beside this file. It is read at run time, so the two cannot drift; this module implements
the JSON Schema subset that file uses (type, const, enum, required, additionalProperties, propertyNames, items,
uniqueItems, pattern, minLength, maxLength, local $ref) with the standard library only, because neither the runners
nor land have the jsonschema package.

CROSS-FIELD RULES (a JSON Schema cannot state these):
  - mode "none" lists no work: no whole group, no partition path, e2e false. A "none" that lists work is refused.
  - mode "selected" lists at least one unit of work.
  - every path is repository-relative POSIX: no leading "/", no backslash, no empty, "." or ".." segment, no
    trailing "/", no control character.
  - a deleted test is never also planned to run.

TIER RULE (`plan --tier`):
  - fast: the plan must exist and be valid. A fast tier without a valid v1 plan is refused.
  - full: no plan, or a plan of mode "none". A selected plan outside the fast tier is refused, because the full tier
    already runs everything and a plan there would only blur which tier produced the evidence.

GRADING (`grade`): the required lanes are every partition with at least one planned path, every whole group, and
"e2e" when e2e is true. Each must have concluded "success". Missing, skipped, cancelled, neutral or failed is red.
The caller builds the results map with exactly those lane names, because how a group maps to a job is the
repository's business. Lanes the plan does not require are ignored.

Usage:
  check.py plan --tier fast|full PLAN.json        exit 0 valid; 1 refused
  check.py grade --plan PLAN.json --results RESULTS.json   exit 0 every required lane succeeded; 1 refused
Exit 2 is a usage error. Refusals are printed one per line as "REFUSE: <reason>".
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("schema-v1.json")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool}


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve(node: dict, schema: dict) -> dict:
    ref = node.get("$ref")
    if ref is None:
        return node
    if not ref.startswith("#/definitions/"):
        raise ValueError(f"unsupported $ref {ref!r}")
    return schema["definitions"][ref[len("#/definitions/"):]]


def _validate(value: Any, node: dict, schema: dict, where: str, errors: list[str]) -> None:
    node = _resolve(node, schema)
    if "const" in node and (value != node["const"] or type(value) is not type(node["const"])):
        errors.append(f"{where}: must be {node['const']!r}")
        return
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{where}: must be one of {node['enum']}")
        return
    kind = node.get("type")
    if kind is not None:
        expected = TYPES[kind]
        # bool is an int subclass in Python, and an int is never a JSON boolean or string here.
        if type(value) is not expected:
            errors.append(f"{where}: must be a JSON {kind}")
            return
    if isinstance(value, str):
        if "minLength" in node and len(value) < node["minLength"]:
            errors.append(f"{where}: shorter than {node['minLength']}")
        if "maxLength" in node and len(value) > node["maxLength"]:
            errors.append(f"{where}: longer than {node['maxLength']}")
        if "pattern" in node and not re.search(node["pattern"], value):
            errors.append(f"{where}: does not match {node['pattern']}")
    if isinstance(value, list):
        if node.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{where}: items are not unique")
        if "items" in node:
            for i, item in enumerate(value):
                _validate(item, node["items"], schema, f"{where}[{i}]", errors)
    if isinstance(value, dict):
        for key in node.get("required", []):
            if key not in value:
                errors.append(f"{where}: missing required key {key!r}")
        props = node.get("properties", {})
        extra = node.get("additionalProperties", True)
        for key, item in value.items():
            if "propertyNames" in node:
                _validate(key, node["propertyNames"], schema, f"{where} key {key!r}", errors)
            if key in props:
                _validate(item, props[key], schema, f"{where}.{key}", errors)
            elif extra is False:
                errors.append(f"{where}: unknown key {key!r}")
            elif isinstance(extra, dict):
                _validate(item, extra, schema, f"{where}.{key}", errors)


def path_problem(path: str) -> str | None:
    if CONTROL.search(path):
        return "contains a control character"
    if path.startswith("/"):
        return "is absolute"
    if "\\" in path:
        return "contains a backslash"
    if path.endswith("/"):
        return "ends with /"
    if any(part in ("", ".", "..") for part in path.split("/")):
        return "has an empty, '.' or '..' segment"
    return None


def validate(plan: Any, schema: dict | None = None) -> list[str]:
    """Every reason `plan` is not a valid v1 plan; empty when it is."""
    schema = schema or load_schema()
    errors: list[str] = []
    _validate(plan, schema, schema, "plan", errors)
    if errors:
        return errors  # the cross-field rules assume the shape
    planned = [p for paths in plan["partitions"].values() for p in paths]
    for field, paths in (("partitions", planned), ("deleted_tests", plan["deleted_tests"]),
                         ("source_paths", plan["source_paths"])):
        for p in paths:
            problem = path_problem(p)
            if problem:
                errors.append(f"plan.{field}: {p!r} {problem}")
    work = bool(plan["whole_groups"]) or bool(planned) or plan["e2e"]
    if plan["mode"] == "none" and work:
        errors.append("plan: mode 'none' lists work")
    if plan["mode"] == "selected" and not work:
        errors.append("plan: mode 'selected' lists no work")
    for p in sorted(set(plan["deleted_tests"]) & set(planned)):
        errors.append(f"plan: deleted test {p!r} is also planned to run")
    return errors


def required_lanes(plan: dict) -> list[str]:
    lanes = [name for name, paths in plan["partitions"].items() if paths]
    lanes += plan["whole_groups"]
    if plan["e2e"]:
        lanes.append("e2e")
    return sorted(set(lanes))


def check_tier(plan: Any | None, tier: str) -> list[str]:
    if tier == "fast":
        if plan is None:
            return ["fast tier without a changed_tests plan"]
        return validate(plan)
    if plan is None:
        return []
    errors = validate(plan)
    if not errors and plan["mode"] != "none":
        errors.append("a selected changed_tests plan outside the fast tier")
    return errors


def grade(plan: Any, results: Any) -> list[str]:
    errors = validate(plan)
    if errors:
        return errors
    if not isinstance(results, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in results.items()):
        return ["results: must be a JSON object of lane name to conclusion string"]
    refused = []
    for lane in required_lanes(plan):
        conclusion = results.get(lane)
        if conclusion != "success":
            refused.append(f"required changed-tests lane {lane!r} concluded {conclusion or 'nothing (missing)'}")
    return refused


def _load(path: str, optional: bool = False) -> Any:
    p = Path(path)
    if optional and not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="validate and grade a changed_tests v1 plan")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--tier", choices=("fast", "full"), required=True)
    p_plan.add_argument("plan")
    p_grade = sub.add_parser("grade")
    p_grade.add_argument("--plan", required=True)
    p_grade.add_argument("--results", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "plan":
            errors = check_tier(_load(args.plan, optional=True), args.tier)
        else:
            errors = grade(_load(args.plan), _load(args.results))
    except (OSError, ValueError) as exc:  # unreadable or malformed JSON is a refusal, never a pass
        errors = [f"unreadable input: {exc}"]
    for e in errors:
        print(f"REFUSE: {e}")
    if not errors:
        print("OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
