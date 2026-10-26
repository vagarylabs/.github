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

## Reader scan (1.4.1)

`edges.py` classifies each quoted workspace-root literal (`"services"`, `"apps"`, ...) by the source around it. A
construct opened on an earlier line is read as one logical line (up to 40 lines back), with brackets balanced.

1. **In a path, the literal is joined.** That means after a pathlib `/`, as an argument of a path call (`join`,
   `resolve`, `joinpath`, `Path(...)`, found by balanced brackets, so `join(get_root(), "services", x)` and black's
   one-argument-per-line output both count), or in a list spread into one, passed to `sep.join(`, or `.join(`-ed.
   - A literal prefix that a package owns reads that package. When a computed component follows, it also reads every
     package nested beneath that prefix.
   - A prefix that no package owns reads every package beneath it.
   - A `..`, `.parent` or `os.pardir` after a computed component REFUSES, and so does a literal `.` or `..` component.
   - An unowned path with nothing beneath it needs no edge, because a change to it is unmapped and plans FULL. When the
     caller's `inert_globs` or `extra_edges` cover it, that is no longer true, and the read REFUSES.
2. **A comma-listed literal outside a path call is metadata ONLY with positive evidence:** an object key or value, a
   subscript (`m["services"]`), SQL (`VALUES (`, or any `.sql` file).
   - Or when its list closes on the line and EVERY sibling is a string literal or a `name=` argument naming no package.
   - A sibling that names a package (`("services", "b")`) or a package-owning top-level directory
     (`("services", "packages")`) is a read.
   - A list or set holding only the root (`["services"]`, `("services",)`) is a walker over it.
   - An argv list passed to an exec call (`subprocess.run([...])`) refuses.
3. **Everything else REFUSES, as 1.4.0 did:** a computed or starred sibling, a bare tuple, an unrecognised call
   (`repo_path("services", name)`), or a list that runs past the line. A literal that is neither comma-listed nor in a
   path stays metadata, as before.

Before 1.4.1, ANY root literal followed by `,` or `/` that could not be resolved refused, so a JSON field or a UI
label made every plan FULL. 1.4.1 narrows only where the evidence is positive. An independent review ran 60
adversarial readers through it: every input either reads the truth or refuses. Two residuals were accepted by the
2026-10-26 ruling: a dict value later used as a path, and (closed here by the exec rule) an argv list. Template and
f-strings, `+` concatenation, `glob`/`listdir`, and lines that begin with `*` read nothing, here and in 1.4.0. They are
listed for a follow-up.

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.

On the approved POSIX/Linux runner path, the optional provider witness executes its single GET in an owned Python worker. Windows selectors do not support these process pipes; failure remains UNKNOWN/FULL. The parent enforces the existing whole-request deadline across process startup, DNS, connect, TLS, status/headers and body, and kills/reaps the worker on timeout, output overflow or catchable interruption (at most one additional second for reaping). Request credentials travel only through a private stdin pipe, not argv or inherited GH_TOKEN/GITHUB_TOKEN; worker stderr and exception details are not logged. Response metadata and body are capped separately. This changes transport containment, not source-access authority or plan-selection permissions. Malformed non-string provider file statuses remain UNKNOWN/FULL rather than raising an uncaught type error.

Abrupt parent termination (including default SIGTERM/SIGKILL) is outside Python exception cleanup; the runner must own and reap the complete job process group. This transport does not install a process-global signal handler or claim standalone orphan recovery after abrupt parent death.
