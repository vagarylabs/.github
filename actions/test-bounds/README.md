# test-bounds (K2)

One shared check for the F5 class: test code must not bound a wait with a short wall-clock value. A number below a
hang guard's size measures the runner's load, not the behaviour, so a loaded runner turns it into a red. This check
replaces three repository gates, each with its own engine:
- vagaris `check-test-bounds-are-hang-guards.mjs`;
- vagary-core `test_ci_test_pg.py`'s bound classes;
- vps-ansible `test_subprocess_hang_guards.py`.

Each adoption PR declares what it retires. The contract is in `check.py`'s docstring.

## Use

```yaml
test-bounds:
  timeout-minutes: 8
  steps:
    - uses: actions/checkout@<sha>
      # depth 1 is enough when the credentials persist (the default): the base commit is fetched alone
    - uses: vagarylabs/.github/actions/test-bounds@<sha>
      with:
        base: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}
```

In CI the base is the EVENT's, read from `GITHUB_EVENT_PATH`, so an edit to the workflow cannot switch off the
base-judged checks:
- every event that carries a pull request (`pull_request`, `pull_request_target`, `pull_request_review`,
  `pull_request_review_comment`) takes `pull_request.base.sha`, and `merge_group` takes `merge_group.base_sha`. An
  input naming another commit, or the head, is refused;
- `push` takes the payload's `before` and ignores the input. All zeros (a branch's first push) means no base: the run
  says so and judges the committed counts only;
- `workflow_dispatch` alone takes the input;
- every other event is refused.

The action fetches the base commit alone when a depth-1 checkout lacks it. That fetch needs the checkout's
credentials, so keep `persist-credentials` (the default) or use `fetch-depth: 0`; otherwise the run refuses.

The consumer's `.github/test-bounds.baseline.json` holds the configuration and the counts. Give it a CODEOWNERS entry.

```json
{"schema": 1, "check": "vagarylabs/.github/actions/test-bounds",
 "trees": [{"glob": "server/src/**/*.test.ts", "min_files": 300}, {"glob": "scripts/**/test_*.py", "min_files": 20}],
 "exclude": [],
 "launchers": [{"name": "startEmbeddedPostgresTestDatabase",
                "module": "server/src/__tests__/helpers/embedded-postgres.ts", "hook_floor_ms": 210000}],
 "counts": {"server/src/__tests__/a.test.ts": {"literal-bound": 3}}}
```

- `trees` is a list of globs, using the planner's glob semantics (`**/` crosses directories). Each tree has a
  `min_files` floor. A tree that scans fewer files than its floor is red, so a broken glob never reads clean.
- `exclude` lists globs that are not scanned.
- `launchers` is the startup-hook class (below).
- `counts` holds the shrink-only findings per file and rule. Write them with check.py, never by hand:
  - `check.py write-baseline --base "$(git merge-base origin/main HEAD)"` lowers them, or moves them with a rename or
    split;
  - `check.py write-baseline --seed` writes the first counts, once `trees` is filled in.

## What is a finding

ast-grep (0.42.1, pinned in `release-assets.lock` per runner arch) matches every bound position and captures its
value. The rules are in `rules/`.

| rule id | languages | position | floor |
|---|---|---|---|
| `literal-bound.option.{case,hook,subprocess,condition}` | ts tsx js | `{ timeout: V }` (or `{ timeout }`) in a call's arguments; the callee decides the kind (spawn/exec/execFile/fork and their Sync forms, and execa*, are subprocess) | 120 / 240 / 120 / 60 s |
| `literal-bound.registrar.case` | ts tsx js | the last argument of it/test/bench/describe* (with .each/.only/... modifiers). With 3+ arguments any value is captured; with 2, only a literal | 120 s |
| `literal-bound.registrar.hook` | ts tsx js | the last argument of beforeAll/beforeEach/afterAll/afterEach, including `beforeAll?.(fn, N)` | 240 s |
| `literal-bound.wait.condition` | ts tsx js | `vi.waitFor(fn, N)` / `vi.waitUntil(fn, N)` | 60 s |
| `literal-bound.default.condition` | ts tsx js | a parameter default named /timeout\|deadline\|budget/i | 60 s |
| `literal-bound.config.{case,hook}` | ts tsx js | testTimeout / hookTimeout, teardownTimeout | 120 / 240 s |
| `literal-bound.keyword.subprocess` | py | `timeout=` of run/check_output/check_call/call/Popen/communicate/wait (not asyncio's `wait`, read below) | 120 s |
| `literal-bound.positional.subprocess` | py | `wait(N)`, `communicate(input, N)` | 120 s |
| `literal-bound.default.subprocess` | py | a `timeout` parameter default | 120 s |
| `literal-bound.client.fixture` | ts tsx js py | a PostgreSQL client's timeout: node-postgres `connectionTimeoutMillis` / `statement_timeout` / `query_timeout`; asyncpg / psycopg / psycopg2 / psycopg_pool connect and pool `timeout` / `connect_timeout` / `command_timeout` (py: by binding, below; a literal 0 is "no limit") | 120 s (`fixture`) |
| `literal-bound.join.subprocess` | py | a thread or process `.join(N)` or `.join(timeout=N)`. A positional name or arithmetic is judged only when it resolves to a number, since `str.join` takes one | 120 s |
| `literal-bound.wait.condition` | py, by binding | `asyncio.wait_for(aw, N)` / `timeout=`, and `asyncio.wait(aws, timeout=N)` | 60 s |
| `literal-bound.timeout-ctx.condition` | py, by binding | `asyncio.timeout(N)`, `async_timeout.timeout(N)` | 60 s |
| `literal-bound.http.condition` | py, by binding | `timeout=` of `urllib.request.urlopen` (or its third positional argument), the requests and httpx functions, `requests.Session` / `httpx.Client` / `httpx.AsyncClient` methods, and the httpx client constructors | 60 s |
| `literal-bound.http-tuple.condition` | py, by binding | each element of an HTTP `timeout=(connect, read)` tuple (a `None` element is no bound) | 60 s |
| `literal-bound.mark.case` | py, by binding | `@pytest.mark.timeout(N)` (a literal 0 is "no limit") | 120 s |
| `literal-bound.ini.case` | pytest config | pytest-timeout's `timeout` and addopts `--timeout` in pytest.ini and .pytest.ini, tox.ini (`[pytest]`), setup.cfg (`[tool:pytest]`), pyproject.toml (`[tool.pytest.ini_options]` and pytest 9's native `[tool.pytest]`), pytest.toml and .pytest.toml (`[pytest]`), read in Python. A file that does not parse is unparsable; `timeout = 0` is "no limit" | 120 s |

**By binding** (root's #65 RC B3): the Python library calls are read over CPython's own parse of the file, not by
spelling (`check.py` PY_CALLS). A callee is resolved through `import x as y`, `from x import y` and a client
instance (`s = requests.Session()`, `with httpx.Client() as c`, `self.s = httpx.Client()`,
`requests.Session().get(...)`). The binding pass owns every direct argument of a call it resolves, so
`from asyncio import wait; wait(aws, timeout=5)` is a condition wait at 60 s, never a subprocess one. What it cannot
read is listed as NOT COVERED with every run (the summary, the log and the findings JSON), so its absence from the
findings is never a pass:
- a covered call whose bound may come through a `**` splat, with no explicit bound keyword;
- a call through a name two imports bind differently (`import requests as r` in one branch, `import httpx as r` in
  another).
A client reached any other way (a fixture parameter, a factory's return value) is not resolved, and a file CPython
cannot parse is unparsable (red).

Only these positions are read. Every run prints them (`covered (...)`), so absence elsewhere is never a pass. Not
yet covered, and due in K2 step 2: fixed flushes, sleep-as-wait, and elapsed-time asserts.

A captured value is cleared only on POSITIVE proof that it is at or above its floor (root's R1, value semantics).
Otherwise it is a finding. The proof can be:
- **an exact value**: numeric literals (with `_`), unary minus, and `+ - *` of those. Division, `**`, templates,
  calls, environment reads and legacy octal (`0210000`) are not evaluated.
- **a name, resolved in one hop with four guards** (root, 10-31). The name resolves to a same-file top-level
  `const NAME = <exact value>`, or to a direct named import from a relative path whose one target file holds
  `export const NAME = <exact value>` (Python: the one module-level assignment, `from .x import NAME`).
  1. No other site in the consuming file binds or might bind the name.
  2. The source binds it exactly once (Python: no augmented assignment).
  3. Its value is exact, as above.
  4. The relative path, with its extension, `index` and `.js -> .ts` forms, resolves to exactly one tracked file.

  Re-exports, namespace, default, type-only and package imports, a directory with a `package.json`, a Python star
  import in either file, and anything longer than one hop are not resolved. A `typeof NAME` in a type position is a
  read.
- **the launcher class**: a `beforeAll` whose first argument calls a declared launcher. The launcher must be bound
  by a plain named import from its declared module, under the same guards. Such a hook is judged against the
  launcher's own floor. Embedded Postgres owns a 180 s startup, so its hook floor is 210 000 ms.
- **a mark**: `timeout under test: <what it proves>`, with the mark's own text on the value's line (not merely a
  comment that ends there). A mark without a reason (a word of three letters) clears nothing. Every mark is listed,
  and a bound this change newly exempts is listed as NEW.

ast-grep runs isolated from the consumer's `sgconfig.yml` (a `languageGlobs` line would otherwise hide files). A
sentinel rule must parse every scanned file exactly once: a file it skips, such as one holding non-UTF-8 bytes, is
red.

## Parsing

tree-sitter recovers from what its grammar lacks. One such gap, tree-sitter-typescript #367 (open), hits
`f<typeof import("x")>()`.
- An ERROR node holding no identifier or digit character, or lying inside a string (but not in the code a
  template interpolates), cannot hide a bound. It is RECOVERED: listed, never red (root's R2).
- Any other ERROR node makes the file unparsable, which is red.

## Baseline and configuration

The semantics are the vagaris ratchet's, which root R4'd on #849. Given a base:
- A touched file is judged against the base's ACTUAL findings, read from its blobs, by rename/split group. A gain
  must be locked in on a pull_request, and is a notice on merge_group and push.
- An untouched file is judged against the committed counts, which may not rise against the base's.
- The configuration is also judged from the base. Each of these is red:
  - a file the base scans that the candidate does not;
  - a tree removed, or given a lower `min_files`;
  - a launcher added or lowered;
  - a scanned test file renamed out of the trees.
- A widened tree is seeded from what the base held.

## UNSCANNED

The summary and the findings JSON list two kinds of file:
- tree files in a language this check does not read;
- test-like files outside every tree.

## Self-test

Every run starts by checking `fixtures/<case>/` against its `expect.json`: exact counts per file and status, plus
the unparsable, recovered and NOT COVERED lists. Every rule of every language must be planted RED somewhere, so a
new rule without a fixture, or a gutted one, fails the check itself. For the binding pass the rule ids are declared
(PY_BOUND_RULES), and PY_CALLS must read exactly those, so emptying a position from PY_CALLS fails by name. Run it with `check.py self-test`; the tests are in
`test_check.py`.
