# sibling-repo-read

The one way a vagarylabs workflow reads a sibling repository with a freshly minted GitHub App installation token.

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

The token reaches git only through a credential helper that reads it from the environment: never argv, a URL or a
printed line. Git runs outside any checkout, with the http extraheader blanked: actions/checkout persists one holding
THIS repository's GITHUB_TOKEN, which would otherwise override the App token.

The `token` output is for a later read the action does not cover. A later sibling clone or checkout should use the
action itself; `trusted-workflow-integrity` refuses a raw `create-github-app-token` followed by a sibling read.

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

Local bare remotes cover the bare and pinned modes, the scope check, and a missing repository.
