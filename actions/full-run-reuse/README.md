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
- A `merge_group` run of this workflow file in this repository, whose `head_sha` is the pushed commit.
- In that run's latest attempt, the declared verdict job is `completed`/`success`, exactly once. The run itself may
  still be in progress, because non-required jobs can outlive the merge.
- No job of that attempt executed a declared void step.
- Exactly one unexpired receipt for that attempt, with every field matching.

Pull-request runs are not evidence: they tested the PR merged onto an older main.

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
  timeout-minutes: 6
  permissions: { actions: read, contents: read }
  outputs: { reused_run: ${{ steps.reuse.outputs.reused_run }} }
  steps:
    - id: reuse
      uses: vagarylabs/.github/actions/full-run-reuse@<sha>
      with:
        verdict-job: build                          # the required aggregate's display name
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
