# full-run-reuse (with full-run-receipt)

A merge queue merges by fast-forwarding the default branch to the exact commit its `merge_group` run tested. The push
to main that follows re-tests identical bytes. This pair lets that push reuse the merge group's run, and only when
the run is proven FULL and green for that exact commit.

- **`actions/full-run-receipt`** (writer) is a step of the REQUIRED verdict job. On a `merge_group` run whose
  selection the workflow declares FULL (`full: "true"`), it uploads `ci-full-run-receipt-a<attempt>`, holding schema
  2, mode full, the repository, workflow path, commit, run id and attempt.
- **`actions/full-run-reuse`** (reader) is a light job on `push`. It outputs `reused_run`, or empty.

## What is accepted

Everything below is read from the API at lookup time; `reuse.py`'s docstring is the contract.
- The NEWEST `merge_group` run of this workflow file in this repository whose `head_sha` is the pushed commit. If it
  is refused or unreadable, the full suite runs. An older run of the same commit is never considered.
- That run is `completed`/`success`. A run still in progress is polled for up to `wait-minutes` (default 10), then
  refused.
- In its latest attempt, every job is `completed` with `success`, `skipped` or `neutral`, except the reviewed
  advisory jobs named in `ignore-jobs`.
- Every job that reports a REQUIRED check of the default branch (read from its ruleset) is `success`. A required
  check can never be ignored: naming one in `ignore-jobs` fails the step.
- The verdict job is `success` exactly once.
- No job executed a declared void step, whatever that step's conclusion.
- Exactly one unexpired receipt for that attempt, with every field matching.

Pull-request runs are not evidence: they tested the PR merged onto an older main.

## Consumer obligations

- **Event-conditional steps** (`event-conditional-steps`, required). A step whose `if:` depends on the event runs
  differently under `merge_group` and `push`. Declare them, or `'[]'` for none. The declaration is reviewed with the
  workflow and printed in the summary; the reader cannot verify it.
- **Timeout.** The reuse job waits up to `wait-minutes`, so its `timeout-minutes` must be at least `wait-minutes` + 6
  (the org completion floor).
- **`workflow_call`.** `github.workflow_ref` names the CALLING workflow, so a reusable workflow binds to its caller's
  file and runs. The receipt must be written by the caller's verdict job.

## Fail-closed

- No evidence, an API error, a listing that pages past what was read, an expired or duplicate receipt, or any
  mismatch gives `reused_run=''`, and the full suite runs.
- A missing or malformed configuration fails the step.
- Errors are reported by type only.

## Consumer wiring

```yaml
merge-group-reuse:
  if: ${{ github.event_name == 'push' }}
  runs-on: <light class>
  timeout-minutes: 16              # >= wait-minutes (10) + the 6-minute completion floor
  permissions: { actions: read, contents: read }
  outputs:
    reused_run: ${{ steps.reuse.outputs.reused_run }}
  steps:
    - id: reuse
      uses: vagarylabs/.github/actions/full-run-reuse@<sha>
      with:
        verdict-job: build                          # the required aggregate's display name
        event-conditional-steps: '[]'               # required: list them, or [] for none
        ignore-jobs: '["slow-cases upload"]'        # reviewed advisory jobs only; never a required check
        void-steps: '["Obsolete merge-group candidate (nothing verified)"]'   # if the workflow has one
heavy-job:
  needs: [merge-group-reuse]
  if: ${{ !cancelled() && needs.merge-group-reuse.outputs.reused_run == '' }}
build:   # the verdict job, also on merge_group
  steps:
    # ...its checks; on a push with reused_run set it cites the run instead of re-judging skipped jobs...
    - if: ${{ success() }}
      uses: vagarylabs/.github/actions/full-run-receipt@<sha>
      with:
        full: ${{ <the run's own selection is FULL> }}   # a workflow with no selector passes 'true'
```

## Replaces

- `actions/change-impact-plan/reuse.py` (dormant since abf3bc7, 10-13: tree-keyed pull_request receipts).
- The pull_request-only `full-run-receipt` writer.
- The repo-local copies that become consumers:
  - vagaris `scripts/ci_push_reuse.py` (its merge-group path);
  - vagary-core `services.yml` `merge-group-proof` (which checked no FULL proof).
