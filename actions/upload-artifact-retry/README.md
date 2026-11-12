# upload-artifact-retry

`actions/upload-artifact` for an artifact that **is a job's evidence** (a validation plan, a change manifest, a partition
receipt, observations a later job grades): attempt one is bounded by a budget that makes it **fail, never be cancelled**,
when it hangs, and a failed attempt one is retried **exactly once, with overwrite**, before the step fails.

```yaml
- id: plan_upload
  timeout-minutes: 6            # >= attempt-budget-ms + retry-budget-ms + 60 s, whole minutes
  uses: vagarylabs/.github/actions/upload-artifact-retry@<sha>
  with:
    name: ci-validation-plan
    path: ${{ runner.temp }}/plan.json
    if-no-files-found: error
    attempt-budget-ms: '150000'   # from the artifact's measured upload time, never from the job ceiling
    retry-budget-ms: '150000'
```

## Why a budget inside the process

A hung upload can run about 15 minutes inside `upload-artifact` before it fails on its own: 5 `CreateArtifact`
attempts at a 3-minute socket timeout, and a 5-minute stall timer per blob chunk (v4.6.2 `dist/upload/index.js`
`:2731`, `:12583`, `:2944`). A composite's inner steps cannot carry `timeout-minutes`, and the **calling** step's
`timeout-minutes` **cancels** the composite: `continue-on-error` converts a failure only (`actions/runner`
`ExecutionContext.cs`, `ApplyContinueOnError`), so the retry's `if: steps.first.outcome == 'failure'` reads a cancel,
is skipped, and the job is cancelled with it. That is no retry exactly when the fault is a stall (vagaris run
43094998692 attempt 1: a 309 s hang, then the 7-minute job limit).

`attempt-budget.cjs` is loaded into `upload-artifact`'s node process by `NODE_OPTIONS=--require` on both attempts
(the runner copies the step env into the process and sets no `NODE_OPTIONS` of its own,
`NodeScriptActionHandler.cs`; a job-level `NODE_OPTIONS` is kept). It arms one unref'd timer: at the budget it prints
an `::error::` line and exits 1, a plain step failure, which `continue-on-error` converts, so the retry runs inside a
budget the caller knows. Its contract (unset or mistyped budget: fail at load; `0`: no timer, control runs only) is
held by `attempt-budget.test.mjs`, which runs real node processes under `NODE_OPTIONS` the way the runner does.

## Why a composite, hosted here, pinned by sha

vagary-core's service-build roster binds one step id per rostered step and its partition receipt grades every rostered
outcome as `success` or `skipped`, so a second workflow step would need a roster entry and would read `skipped`
whenever attempt one succeeded. The receipt is trusted as graded by main's verifier, so the composite may not be read
from the candidate's own checkout: consumers pin `vagarylabs/.github/actions/upload-artifact-retry@<sha>`, one sha
across repositories.

## What the retry does not cover

- A job-level `timeout-minutes` or a workflow cancel: the job is cancelled, nothing retries.
- Runner loss.
- A deterministic fault (a missing path with `if-no-files-found: error`, a 4xx on the inputs): the retry repeats it
  and the job fails after both budgets.
- A budget below a healthy slow upload: one slow upload becomes two cut ones. Budgets come from measured durations.
- A name that existed **before** the step: the retry's `overwrite: true` replaces it, indistinguishable from attempt
  one's half-created artifact. Two steps writing one name is a static defect; the consumers' gates assert unique
  artifact names per workflow run.

## Proof runs

Recorded in the PR that introduced this action (vagarylabs/.github, 2026-11-12): on a self-hosted light runner, a
local proxy that holds the first `CONNECT` open and tunnels later ones, `https_proxy` on the calling step; attempt one
hung at `CreateArtifact`, the budget failed it, the retry succeeded through the proxy and the artifact exists. The
control run (budgets `0`, calling step `timeout-minutes: 2`) ran to the calling step's bound and the retry was skipped.
