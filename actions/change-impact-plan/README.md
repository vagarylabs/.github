# Change-impact planner

This deterministic action uses immutable candidate inputs and trusted base policy to describe affected work. Pin the action to a reviewed commit. The caller remains responsible for its complete validation obligations and final required verdict.

## Cumulative impact record

Planner 1.3 adds `plan.impact` (schema 1). It reuses the existing path ownership and reverse-dependency computation. It does not change merge-group jobs or matrices: those still select FULL validation, and this action does not authorize run-result reuse.

- `selection_authority` is always `false`.
- `status: known` means modeled impact under a matched supported-static-reader assessment, not complete reader qualification or approval to omit tests.
- `status: unknown` uses `null` for changed packages, affected packages and affected hubs. It must not be interpreted as an empty affected set.
- Global or unmapped inputs, absent or moved targets, missing policy and missing or malformed reader evidence remain unknown.
- An inert-only change may have known empty modeled impact; its merge-group execution still remains FULL.

The record includes the graph digest, reader assessment and coverage limits, changed/global/unmapped inputs, and immutable candidate, target, policy, source and producer-attempt identities. Its entire versioned content is bound into `plan_id`.

The reader assessment must cover the configured reader directories and bind the actual candidate, policy, graph and scanner. It covers only supported static expressions. Consumers need their own qualified complete obligation inventory, trustworthy execution receipts and enforced policy boundary before enabling any new selection.

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.
