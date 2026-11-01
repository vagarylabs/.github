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
| `literal-bound.keyword.subprocess` | py | `timeout=` of run/check_output/check_call/call/Popen/communicate/wait | 120 s |
| `literal-bound.positional.subprocess` | py | `wait(N)`, `communicate(input, N)` | 120 s |
| `literal-bound.default.subprocess` | py | a `timeout` parameter default | 120 s |
| `literal-bound.client.fixture` | ts tsx js py | a PostgreSQL client's timeout: node-postgres `connectionTimeoutMillis` / `statement_timeout` / `query_timeout`; asyncpg / psycopg / psycopg_pool connect and pool `timeout` / `connect_timeout` / `command_timeout` | 120 s (`fixture`) |
| `literal-bound.wait.condition` | py | `asyncio.wait_for(aw, N)` / `wait_for(aw, timeout=N)` | 60 s |
| `literal-bound.timeout-ctx.condition` | py | `asyncio.timeout(N)`, `async_timeout.timeout(N)` | 60 s |
| `literal-bound.join.subprocess` | py | a thread or process `.join(N)` (a positional numeric literal; `str.join` takes names) or `.join(timeout=N)` | 120 s |
| `literal-bound.http.condition` | py | `timeout=` of urlopen, requests.*, httpx.* (and httpx clients) | 60 s |
| `literal-bound.mark.case` | py | `@pytest.mark.timeout(N)` | 120 s |
| `literal-bound.poll.condition` | ts tsx js py | a poll loop's BUDGET. A counted loop (`for (let i = 0; i < N; i++)`, py `for _ in range(N)`) whose body awaits one fixed sleep V (sleep/delay/wait, `new Promise(r => setTimeout(r, V))`; py time.sleep / asyncio.sleep) and can exit early (break or return, or an `&&` re-check in its test) has the budget N x V. A deadline loop (while, do-while, for) is bounded by D from `now - start < D`, or from `now < deadline` with `deadline = now + D` in a preceding statement (now: Date.now(), performance.now(); py time.monotonic, time.time, perf_counter, loop.time). A budget, or a count, that is a parameter of the enclosing function is not judged here; a `timeout`/`deadline`/`budget` parameter's default is `literal-bound.default.condition`. A poll's mark may sit on the loop's own line. A large budget exits early, so it costs nothing on a pass | 60 s |
| `literal-bound.ini.case` | pytest config | pytest-timeout's `timeout` and addopts `--timeout` in pytest.ini, tox.ini (`[pytest]`), setup.cfg (`[tool:pytest]`) and pyproject.toml (`[tool.pytest.ini_options]`), read in Python; a file that does not parse is unparsable | 120 s |

Elapsed-time asserts are the `elapsed-assert` rules, below. Only these positions are read. Every run prints them
(`covered (...)`), so absence elsewhere is never a pass. Not yet covered, and due in K2 step 2C: fixed flushes,
sleep-as-wait, poll budgets, and read and absence windows.

Not bounds, so not captured (the vagaris hardening branch, f2961a44f, 14 false findings on vagaris):
- an option whose value is a LITERAL zero (`timeout: 0`, `end({ timeout: 0 })`), which is a count
  or "none". A NAME resolving to 0 is still judged, because someone chose that bound;
- an object passed to an equality matcher (toEqual, toStrictEqual, toMatchObject, toContainEqual,
  toHaveBeenCalledWith and its Last/Nth forms, toHaveProperty, toBe), which is an expected VALUE. Playwright's
  web-first assertions (`toBeVisible({ timeout })`, toHaveURL, toPass) take a real bound and stay counted;
- a registrar-named call with no body beside its bound (`describeExit("wsl", 4)` registers nothing). The body is a
  function, or a name or member for one, so `it(name, handler, N)` still counts.

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

## Elapsed-time asserts

Root's R3a (10-31): an UPPER bound, in an assertion, on a real-clock ELAPSED difference (now minus an earlier
reading of the same clock) is a condition bound, judged against the 60 s floor in the clock's units. A
`timeout under test:` mark never exempts one: the remedy is a fake clock, or the code's own logged times. The family
is counted under its own rule (`counts: {file: {"elapsed-assert": n}}`); the rules are `rules/elapsed-assert*.yml`,
one per clock family (each `clock-<family>` util, with its unit in check.py's `ELAPSED_PER_S`).

| rule id | languages | clock | unit |
|---|---|---|---|
| `elapsed-assert.date.condition` | ts tsx js | `Date.now()`, `new Date()` (with `.getTime()`, `.valueOf()`, `+new Date()`) | ms |
| `elapsed-assert.perf.condition` | ts tsx js | `performance.now()` | ms |
| `elapsed-assert.hrtime.condition` | ts tsx js | `process.hrtime.bigint()` (a bigint bound is not exact, so a finding) | ns |
| `elapsed-assert.{time,monotonic,perf-counter}.condition` | py | `time.time()`, `time.monotonic()` / `monotonic()`, `time.perf_counter()` / `perf_counter()` | s |
| `elapsed-assert.{time-ns,monotonic-ns,perf-counter-ns}.condition` | py | the `_ns` forms | ns |
| `elapsed-assert.loop.condition` | py | `loop.time()`, `asyncio.get_running_loop().time()`, `get_event_loop().time()` | s |
| `elapsed-assert.datetime.condition` | py | `datetime.now()` / `utcnow()`: through `.total_seconds()`, or against an exact `timedelta(...)` | s |

- **The assertion.** ts/js: `expect(A).toBeLessThan(V)` and `toBeLessThanOrEqual` (also `expect.soft`, and with a
  message argument), `expect(A).not.toBeGreaterThan[OrEqual](V)`, chai `expect(A).to.be.below / lessThan / lt / lte
  / at.most(V)`, `assert.isBelow / isAtMost(A, V)`, and `A < V`, `A <= V`, `V > A` or `V >= A` as the first argument
  of `assert`, `assert.ok`, `assert.isTrue`, or of an `expect` that ends `.toBe(true)`, `.toEqual(true)`,
  `.toStrictEqual(true)` or `.toBeTruthy()`. py: `assertLess[Equal](A, V)`, `assertGreater[Equal](V, A)`, and those
  comparisons, or a chained `LO < A < V`, as an `assert`'s test or `assertTrue`'s first argument.
- **The measured side A.** (1) `clock - x`; (2) `name - x`, with `name` bound to the clock; (3) a name bound to a
  measured side; (4) `(d) / K`, `(d) * K` or `K * (d)`, which scales the unit by an exact K (an inexact K is a
  finding); (5) a name bound to a call of a same-file helper, one hop, whose return gives a measured side. The return
  can be the whole value or sit at the binding's tuple or array position (1-4, no holes). Examples: vps
  `test_uplink_probe.py:55` `return r, time.monotonic() - t0`, and vagary-core `security-events.mjs:318`. The call
  may be awaited, or run by `asyncio.run` or `run_until_complete`. The helper is resolved first in the nearest
  enclosing function, as a definition that is a direct statement of its body. Otherwise it is resolved in the file,
  which must hold exactly ONE definition of that name, or the read is not proven. A binding counts when it sits in a statement that precedes the assert's statement, in the same block or
  an enclosing one. The search goes down to, never into, another function. A preceding function or class
  declaration is not searched, so a sibling test's binding never counts. tree-sitter-typescript parses
  `a - b!.c()` as `(a - b)!.c()`, and the check reads it as the difference it is.
- **Not matched.** A lower bound. A remaining time (`deadline - now`), which a slow machine only shrinks. A value
  the test did not read from a clock, such as a logged duration or an injected clock. A clock call wrapped in another
  call (`Math.round(...)`, `round(...)`). A helper that returns another helper's call, which is two hops (vps
  `test_disk_floor_reclaim.py:472`, through `hook()` to `run()`). Object destructuring of a helper's return
  (`const { took } = await f()`).
- **Fake clocks clear only on positive proof, per family.**
  - ts/js: a statement that precedes the assert, in its block or an enclosing one, either makes the faking call
    itself or is a beforeEach/beforeAll hook that makes it. No `useRealTimers()`, `clock.uninstall()` or
    `clock.restore()` may precede the assert, either as a statement or inside a beforeEach/beforeAll hook. An
    afterEach, the usual cleanup, runs after the test and revokes nothing. A sibling test's body never counts.
    - The call is `vi/jest/sinon.useFakeTimers()`, with no argument or an object literal that does not advance with
      real time (`shouldAdvanceTime`, `advanceTimers`, `legacyFakeTimers`).
    - Date is faked unless `toFake` omits it or `toNotFake`/`doNotFake` names it. `performance` and `hrtime` are
      faked only when `toFake` names them, because vitest's default list changed across versions.
    - `vi/jest.setSystemTime(...)` fakes Date.
    - A config-level `fakeTimers` default is not read.
  - py:
    - freezegun's `freeze_time` without `tick=True` fakes every clock above (loop.time() reads time.monotonic). It
      counts as a decorator, as a `with`, as a preceding `freeze_time(...).start()`, through the `freezer`
      fixture, or as `@pytest.mark.freeze_time`.
    - `mock.patch("...time.<fn>")` or `patch.object(time, "<fn>")` fakes that one function's clock as a decorator, a
      `with`, or a preceding chained `.start()`. `monkeypatch.setattr(time, "<fn>", ...)` fakes it as a preceding
      statement.
    - A preceding statement must take effect when it runs. An unstarted `f = freeze_time(...)` or
      `p = mock.patch(...)` leaves the clock real, and a two-statement start (`f.start()`) is not read, so both are
      findings.
    - time_machine is not read: its `travel()` ticks by default, and it never fakes monotonic or perf_counter.

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
the unparsable and recovered lists. Every rule of every language must be planted RED somewhere, so a new rule
without a fixture, or a gutted one, fails the check itself. Run it with `check.py self-test`; the tests are in
`test_check.py`.
