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
{"version": 1, "head_sha": "<40-hex>", "base_sha": "<40-hex>", "mode": "none" | "selected", "whole_groups": [], "partitions": {"<lane>": ["repo/path"]},
 "e2e": false, "deleted_tests": [], "source_paths": [], "reasons": []}
```

## Commit binding

A plan names the `head_sha` it was computed for and the `base_sha` its diff was taken against. Results take the shape `{"head_sha": "<40-hex>", "lanes": {"<lane>": "<conclusion>"}}`.

Land and audits read plans and results from outside the producing run, so this binding is what stops an older head's green results from grading a newer head's plan:

- `grade` refuses results whose `head_sha` differs from the plan's.
- `plan --head <sha>` refuses a plan computed for another head.

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
python3 -I check.py plan --tier fast --head "$HEAD_SHA" plan.json
python3 -I check.py grade --plan plan.json --results results.json
```

Exit codes: 0 means OK, 1 means refused, 2 means a usage error. You can also call it as the composite action in `action.yml`.
