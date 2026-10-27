# changed-tests-plan

A pull request's fast tier defers the heavy suites to the merge queue. Before this check, a new or changed test ran for the first time in the queue, and a defect in it evicted a whole group late.

Each repository's fast tier now writes a `changed_tests` plan listing the changed tests it must run first. The planned lanes are required. This directory holds the shared contract:

- `schema-v1.json` defines the shape.
- `check.py` validates a plan against its tier and grades the required lanes. It reads the schema at run time and adds the cross-field rules.

The mapping from a diff to a plan stays in each repository:

- vagaris: `scripts/ci_change_class.py`
- vagary-core: `scripts/ci-two-tier.py`

Land's admission check and each repository's aggregate read a plan the same way.

## The plan, v1

```json
{"version": 1, "mode": "none" | "selected", "whole_groups": [], "partitions": {"<lane>": ["repo/path"]},
 "e2e": false, "deleted_tests": [], "source_paths": [], "reasons": []}
```

## Rules

A plan is refused in any of these cases:

- `mode: "none"` lists work.
- `mode: "selected"` lists none.
- A path is not repository-relative POSIX.
- A deleted test is also planned to run.
- The shape is off: unknown keys, wrong types, or `version` other than the integer 1.

The tier rules:

- **Fast tier:** a valid plan is required.
- **Full tier:** no plan is allowed, or a plan with `mode: "none"`.

## Grading

The required lanes are:

- every partition with a planned path;
- every whole group;
- `e2e`, when it is true.

Each lane must conclude `success`. Missing, skipped, cancelled, neutral and failed all count as red.

## Usage

```
python3 -I check.py plan --tier fast plan.json
python3 -I check.py grade --plan plan.json --results results.json
```

Exit codes: 0 means OK, 1 means refused, 2 means a usage error. You can also call it as the composite action in `action.yml`.
