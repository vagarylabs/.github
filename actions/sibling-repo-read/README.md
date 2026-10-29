# sibling-repo-read

The one way a vagarylabs workflow reads a sibling repository with a fresh read-only installation token: one it mints
from a GitHub App, or broker-source-read's (`token-dir`, no App key).

**Why.** A new installation token is not visible everywhere at once. A clone made about a second after minting can be
answered `remote: Repository not found` (exit 128) with nothing wrong. vagaris #825 ("Supply vagary-core objects",
job 122068344051) and core #920's merge group each lost a full red cycle to it on 2026-10-27.

**What it does.**
1. **Mints** the token: `actions/create-github-app-token`, pinned by SHA.
2. **Waits for readiness.** `GET <api>/repos/<owner>/<repo>` must answer 200 for every repository, within one
   wall-clock bound (`readiness-seconds`, default 60) with backoff of 1, 2, 4 and 8 s.
   - A first-time 200 costs no delay.
   - A 404, 401, 403, 5xx or network error is retried inside the bound.
   - At the bound the step fails by name: `App token cannot see <owner>/<repo> after 60 s (last answer 404, N
     attempt(s)): installation scope?`.
   - This is a readiness probe, not a blind retry: a real loss of access still fails, within 60 s.
3. **Reads** what the inputs name:
   - `bare`: one `repo:path` per line, a bare single-branch clone of `main`;
   - `checkouts`: one `repo:dir` per line, a depth-1 checkout of `main`'s commit at job start.

   Every read is written to the step summary with its commit.

**Scope: least privilege.** The token is minted READ-ONLY for the listed repositories: `contents: read` always, plus
`packages: read` only when `packages: read` is passed (a GHCR pull of those repositories' packages). Any other
`packages` value is refused before minting. It never carries the App's full installation permissions.

The token reaches git only through a credential helper that reads it from the environment: never argv, a URL or a
printed line. Git runs outside any checkout, with the http extraheader blanked: actions/checkout persists one holding
THIS repository's GITHUB_TOKEN, which would otherwise override the App token.

**The job around it.** Steps before this action may run PR-controlled code (a check script, a `pnpm install`
lifecycle, a PR-local setup action), which can write `GITHUB_PATH`, `GITHUB_ENV` or `BASH_ENV`. So the two steps that
hold the token run in a reset shell: `/usr/bin/env` unsets `BASH_ENV`, `ENV` and the dynamic-loader variables, sets
`PATH=/usr/bin:/bin`, and starts `/bin/bash --noprofile --norc`. read.py runs as `python3 -I -S` (no `PYTHON*`
variables, no user or site packages), and git runs with the same PATH, those variables removed and hooks off. A
python3 or git earlier on PATH, or a PR-built venv, never sees the token. A checkout goes into a fresh directory, and
`git rev-parse HEAD` must equal the main commit it fetched.

This narrows the channel; it does not close it. Code that already ran in the job can still reach the runner (on a
hosted runner it has sudo). The durable fix mints before any PR code runs, or in a separate job that hands off only the
objects: its own design.

The `token` output is for a later read the action does not cover. A later sibling clone or checkout should use the
action itself; `trusted-workflow-integrity` refuses a raw `create-github-app-token` followed by a sibling read.

**Broker tokens (`token-dir`).** Root's ruling of 2026-10-29 (core sibling-read path (a)): one shared action, broker
backed, by composition. broker-source-read is the only broker client: it mints into its `token-dir` (a 0700
directory strictly inside `$RUNNER_TEMP`, one 0600 file `<owner>__<name>` per repository), masks each token, waits for
readiness, and revokes in its `mode: revoke` step. This action reads those files and nothing else:
- exactly one token source per call: `token-dir`, or `app-id` with `private-key`, decided before anything is minted;
- no readiness wait of its own, no mint, and `packages` refused (the broker purpose fixes the permissions);
- each repository's git calls get that repository's token only;
- a directory or file that is a symlink, not the runner user's, open to group or others, outside `$RUNNER_TEMP`,
  missing for a listed repository, or not exactly one credential is refused, naming the file, before any clone;
- it never prints, re-masks, moves or deletes a token.

The App-key mode stays until C4 has landed on every consumer, then retires (check_no_source_read_app_key.py).

**Sparse reads (`trees`, then `sparse`).** Two calls with the consumer's derive between them, so this action never
runs repository code:
1. `trees: repo:dir`: main's commit at job start with its trees and no blob (a depth-1, `--filter=blob:none` partial
   clone, no checkout). A server that sends blobs anyway is refused. The NUL-separated path listing, the commit and
   the directory are recorded under `$RUNNER_TEMP/sibling-repo-read/`; output `trees` is `{repo: {dir, tree, sha}}`.
2. The consumer writes its patterns from the listing (vagary-core: `scripts/sibling_sparse.py derive --tree`).
3. `sparse: repo:dir:patterns-file`: `sparse-checkout set --no-cone` with exactly those patterns and a checkout of
   EXACTLY the recorded commit (main is never re-resolved between the phases). Then the promisor remote is removed, so
   a later read outside the set is a git error, never a lazy fetch. Output `sparse-ok` lists each repository that
   completed. An empty pattern set, a directory the tree phase did not prepare, and both phases in one call are refused.

To fall back (the consumer's derive refused), remove the directory and ask for `checkouts:`; it is never in
`sparse-ok`. Put `sparse:` in its own call when a fallback should also follow a failure.

## Use
```yaml
- uses: vagarylabs/.github/actions/sibling-repo-read@<commit sha>   # pin a SHA, never @main
  with:
    app-id: ${{ vars.SOURCE_READ_APP_ID }}
    private-key: ${{ secrets.SOURCE_READ_APP_PRIVATE_KEY }}
    repositories: vagary-core,vagary-voice
    bare: vagary-core:${{ runner.temp }}/core.git
    checkouts: |
      vagary-voice:${{ runner.temp }}/siblings/vagary-voice
    packages: read          # optional: only for a GHCR pull of the listed repositories' packages
```

Broker-backed and sparse (no App key; the job needs `id-token: write` for broker-source-read):
```yaml
- uses: vagarylabs/.github/actions/broker-source-read@<commit sha>
  with: {purpose: build_checkout, repository: vagarylabs/vagary-platform, provider: ..., service_account: ...,
         audience: ..., token-dir: "${{ runner.temp }}/broker-tokens"}
- id: tree
  uses: vagarylabs/.github/actions/sibling-repo-read@<commit sha>
  with:
    token-dir: ${{ runner.temp }}/broker-tokens
    repositories: vagary-platform
    trees: vagary-platform:${{ runner.temp }}/siblings/vagary-platform
- run: python3 scripts/sibling_sparse.py derive --tree "$TREE" > "$RUNNER_TEMP/platform-patterns.txt"
  env: {TREE: "${{ fromJSON(steps.tree.outputs.trees)['vagary-platform'].tree }}"}
- id: sparse
  uses: vagarylabs/.github/actions/sibling-repo-read@<commit sha>
  with:
    token-dir: ${{ runner.temp }}/broker-tokens
    repositories: vagary-platform
    sparse: vagary-platform:${{ runner.temp }}/siblings/vagary-platform:${{ runner.temp }}/platform-patterns.txt
- if: ${{ always() }}
  uses: vagarylabs/.github/actions/broker-source-read@<same sha>
  with: {mode: revoke, purpose: build_checkout, token-dir: "${{ runner.temp }}/broker-tokens"}
```

## Tests
`python3 -m unittest discover -s actions/sibling-repo-read -p 'test_*.py' -v`. Stdlib only. A localhost API stub
covers:
- 404 then 200 succeeds;
- a persistent 404 fails by name within the bound;
- a first-time 200 costs no delay;
- a 5xx is retried;
- one bound covers all repositories;
- the token goes only in the Authorization header and is never printed.

Local bare remotes cover the bare and pinned modes, the scope check, and a missing repository. Hardening:
- the clone step, run through its own declared shell with a hostile `BASH_ENV`, `ENV`, and a `python3` and `git`
  earlier on PATH, clones and leaks nothing, while plain `shell: bash` (the control) leaks;
- read.py's git ignores a PATH entry a step can prepend;
- a non-empty destination refuses;
- a checkout not at main's commit fails.

Token directory: a clone with no App token, each repository's git calls getting only its own token, the helper never
inheriting one, and each refusal (missing file, group-readable file, open directory, a line break or space, an empty
token, a symlinked file or directory, outside or without `$RUNNER_TEMP`, an App token as well) with nothing cloned and
no token printed; the source check for every combination; the read step through its own shell with no App key.
Sparse: exactly the patterns materialized, the outside blob never in the object store then or after (no promisor),
the tree phase's commit kept when main moves, both phases through the read step's shell, a filter-ignoring server
refused, the token-dir composition, the fallback, and each refusal. ci.yml also runs the token-dir and sparse paths on a
real runner against the public vagarylabs/bulk with a fake credential.
