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

## Two bounds the caller sets

**The step's `timeout-minutes`** covers both attempts: at least `attempt-budget-ms + retry-budget-ms + 60 s`, rounded up
to whole minutes. **The job's `timeout-minutes`** must cover every step before the upload **plus** that step bound: a job
limit fires on the job, not on the step, and nothing retries after it. In the incident the upload began with 308 s of
the 7-minute job left; with the default budgets (150 s + 150 s + 60 s = 360 s) that job would have had about 8 s to
spare, and a job whose tests run a little longer would be cancelled inside the retry. Set the job limit from the
measured job, not from the step bound alone. A budget is a decimal integer of milliseconds up to 2147483647 (node's
largest timer delay; a larger value is refused at load, since node would clamp it to 1 ms and cut a healthy upload).

## No outputs

The composite exposes none of `upload-artifact`'s outputs (`artifact-id`, `artifact-url`, `artifact-digest`): it is
not a drop-in for a step whose outputs are read, and no consumer reads them today. If outputs are added later they must
read the **retry's** values when the retry ran (attempt one's id names an artifact the retry replaced).

## Windows: unproven

Inside the double quotes of a `NODE_OPTIONS` value node reads a backslash as an escape, so a Windows action path
(`D:\a\_actions\...`) written straight into `--require "..."` loses its separators and node exits 1 with
`MODULE_NOT_FOUND` before the upload starts, on both attempts, healthy or not (root's R4 of #85, probe P1b; the test
holds the hazard with a backslash in the directory name). The composite's first step therefore writes the
slash-normalised path to `GITHUB_OUTPUT` under `bash` and both attempts read that output; the test runs the step's own
`run:` line on a Windows-shaped path. **No Windows run has exercised the composite.** Windows stays UNPROVEN here until
one does, and no Windows workflow (vagaris `vagary-node-windows.yml` uploads at `:64` and `:99`) adopts it before that.

## Why a budget inside the process

A hung upload can run about 15 minutes inside `upload-artifact` before it fails on its own: 5 `CreateArtifact`
attempts at a 3-minute socket timeout, and a 5-minute stall timer per blob chunk (v4.6.2 `dist/upload/index.js`
`:2731`, `:12583`, `:2944`). A composite's inner steps cannot carry `timeout-minutes`, and the **calling** step's
`timeout-minutes` fires on the whole composite: measured in the control run below, attempt one ends `outcome=failure`
("The action has timed out"), the retry step starts into the already-fired timeout and is timed out after 23 ms,
before it makes a request, and the calling step fails. That is no retry exactly when the fault is a stall (vagaris
run 43094998692 attempt 1: a 309 s hang, then the 7-minute job limit).

`attempt-budget.cjs` is loaded into `upload-artifact`'s node process by `NODE_OPTIONS=--require` on both attempts
(the runner copies the step env into the process and sets no `NODE_OPTIONS` of its own,
`NodeScriptActionHandler.cs`; a job-level `NODE_OPTIONS` is kept). It arms one unref'd timer: at the budget it prints
an `::error::` line and exits 1, a plain step failure, which `continue-on-error` converts, so the retry runs inside a
budget the caller knows. Its contract (unset, mistyped or over-large budget: fail at load; `0`: no timer, control runs
only; a budget exit that does not depend on the message write reaching a full pipe) is held by
`attempt-budget.test.mjs`, which runs real node processes under `NODE_OPTIONS` the way the runner does, on Node 20 and
24 in CI (the runner forced the node20 action onto Node 24 in the proof run).

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
- A child node process started by the upload would inherit `NODE_OPTIONS` and arm a timer of its own from the same
  budget; moot for v4.6.2, which starts no workers and no children.

## Proof runs

vagaris run 43132501977 (vagarylabs/.github #85; a self-hosted `vl-light` runner, a local proxy that holds the first
`CONNECT` open and tunnels later ones, `https_proxy` on the calling step). Job `hang-then-retry` (budgets 45 s / 90 s):
attempt one hung at the results service, the budget failed it at 45 s, the retry tunnelled through the proxy to the
results service and to the blob host (both clients take the proxy) and the artifact exists (id 13906101161, 168 bytes);
the calling step read `success` in 54 s. Job `control-no-budget` (budgets `0`, calling step `timeout-minutes: 2`):
attempt one hung to the calling step's bound, "The action has timed out" ended it as `failure`, the retry step started
and was timed out after 23 ms with no second `CONNECT`; the calling step read `failure`. The runner forced the node20
action onto Node.js 24; the preload ran there.
