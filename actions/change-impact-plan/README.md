# Change-impact planner

This deterministic action uses immutable candidate inputs and trusted base policy to describe affected work. Pin the action to a reviewed commit. The caller remains responsible for its complete validation obligations and final required verdict.

## Cumulative impact record

Planner 1.3 adds `plan.impact` (schema 1). It reuses the existing path ownership and reverse-dependency computation. It does not change merge-group jobs or matrices: those still select FULL validation, unless the caller opts in with `merge-group: reduce` (1.5.0, below), and this action does not authorize run-result reuse.

- `selection_authority` is always `false`.
- `status: known` means modeled impact under a matched supported-static-reader assessment, not complete reader qualification or approval to omit tests.
- `status: unknown` uses `null` for changed packages, affected packages and affected hubs. It must not be interpreted as an empty affected set.
- Global or unmapped inputs, absent or moved targets, missing policy and missing or malformed reader evidence remain unknown.
- An inert-only change may have known empty modeled impact; its merge-group execution still remains FULL.

The record includes the graph digest, reader assessment and coverage limits, changed/global/unmapped inputs, and immutable candidate, target, policy, source and producer-attempt identities. Its entire versioned content is bound into `plan_id`.

The reader assessment must cover the configured reader directories and bind the actual candidate, policy, graph and scanner. It covers only supported static expressions. Consumers need their own qualified complete obligation inventory, trustworthy execution receipts and enforced policy boundary before enabling any new selection.

## Source answer (1.4)

Planner 1.4 adds `source_answer` and `source_answer_meta` to every record; both are bound into `plan_id`.

- `source_answer` follows the SRC-01 source-context envelope (vagary-core `contracts/source/v1`, pinned in `plan.SOURCE_CONTRACT`). It covers repository identity (provider-stable `github.repository_id` and owner id), the pinned diff base and candidate SHAs, the analyzer (`ci.change-impact-plan` + version), how the candidate was materialized (history depth, clone filter and sparse patterns recorded independently, plus the policy files actually read), and completeness.
- `authorization` is deliberately absent. A CI job token is not a source-access grant. Consumers must obtain the canonical `authorize()` result themselves and must not treat this envelope as authorized.
- Completeness is derived, never asserted. Each of the following makes it partial or unknown, which makes the plan **FULL**:
  - unknown or moved scope;
  - a truncated path list;
  - an absent, unbound or unmatched reader assessment;
  - a base policy checkout that does not match the base tree byte for byte (for example, a sparse checkout missing a tracked manifest, lockfile, workflow or config);
  - an `analyzer` pin in the base policy that differs from this planner;
  - missing provider identity;
  - an unobservable checkout representation;
  - a provider witness that is capped, throttled, malformed or disagrees with Git.
- `source_answer_meta.decision` is `IMPACT_INPUT` only when every dimension is complete. It never grants selection, qualification or release authority.
- With no observed source facts, a library call to `plan()` also returns FULL.
- `source-query: witness` (default `off`) asks the provider's compare API at the pinned SHAs using this action's token.
  - It sends one request, refuses pagination and redirects, and caps the response at 8 MiB and 15 s.
  - A comparison with 300 or more files, or more than 100 commits, counts as incomplete. These caps mirror the existing Vagaris reader.
  - The witness can only widen a plan. Provider bodies and tokens are never recorded.

Callers that adopt 1.4 must update any recomputed `plan_id` identity: it now includes `impact`, `source` and `source_meta`.

## Merge-group reduction (1.5.0, opt-in)

By default a merge group plans FULL, as it always has. A caller that sets `merge-group: reduce` lets a merge group
narrow, and only over the canonical target's cumulative change: the diff from the target branch tip (read before the
policy checkout and re-read before output) to the group head, under the target's verified policy. It narrows only
when every leg holds:
- the opt-in;
- a `canonical-target-cumulative` scope;
- a matched reader assessment;
- provider identity;
- a verified policy checkout;
- an unmoved target;
- no full trigger, unmapped path or hub.

A missing leg keeps the group FULL. The callers that opt in own the matching obligation: under the vagary-core ruling
of 2026-10-22, the full suite runs on every target-branch commit after it merges.

## Reader scan (1.4.1)

`edges.py` reads a workspace-root literal (`"services"`, `"apps"`, ...) by where it stands.

- **Outside a path-construction call, after a `,`, it is metadata.** That covers a JSON field, an object key, an
  array of labels, SQL `VALUES` and keyword arguments. It is never a read and never a refusal. Before 1.4.1 such a
  line raised, and the check failed, so every plan for the repository was FULL.
  - One exception reads MORE: a list naming two or more roots (`("services", "apps")`) is a walker's root list. It
    reads every package under each root it names.
- **In a path,** meaning inside `os.path.join`, `path.join`/`path.resolve`, `joinpath` or `Path(...)`, or after a
  pathlib `/`, the literal components are joined.
  - A path whose literal prefix a package owns reads that package, even when a computed component follows.
  - A computed component under a prefix no package owns (`ROOT / "services" / cap`) reads EVERY package beneath that
    prefix. So does a literal directory above packages, such as a root itself.
  - A literal path with no package beneath it is unowned content. A change to it is unmapped and plans FULL, so it
    needs no edge.
  - A `..` component still refuses.

**The metadata rule narrows on purpose.** Such a line used to refuse, which made every plan FULL. Now it reads
nothing, because a listed value is not a path. The path and walker rules only widen: before 1.4.1 a computed join
refused, and now it reads every package under its literal prefix, which is a superset of anything a computed
component other than `..` can reach. A bare `join(...)`/`resolve(...)` imported from `node:path` counts as a path
call, so a computed walker in package code keeps its edge.

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.

On the approved POSIX/Linux runner path, the optional provider witness executes its single GET in an owned Python worker. Windows selectors do not support these process pipes; failure remains UNKNOWN/FULL. The parent enforces the existing whole-request deadline across process startup, DNS, connect, TLS, status/headers and body, and kills/reaps the worker on timeout, output overflow or catchable interruption (at most one additional second for reaping). Request credentials travel only through a private stdin pipe, not argv or inherited GH_TOKEN/GITHUB_TOKEN; worker stderr and exception details are not logged. Response metadata and body are capped separately. This changes transport containment, not source-access authority or plan-selection permissions. Malformed non-string provider file statuses remain UNKNOWN/FULL rather than raising an uncaught type error.

Abrupt parent termination (including default SIGTERM/SIGKILL) is outside Python exception cleanup; the runner must own and reap the complete job process group. This transport does not install a process-global signal handler or claim standalone orphan recovery after abrupt parent death.
