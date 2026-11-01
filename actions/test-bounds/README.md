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
  says so and judges the committed counts only. A push outside the repository's default branch is refused (exit 2),
  because a feature branch's first push would pass unjudged; its pull request's run is what gates it;
  so a consumer runs this check on `push` only for its default branch (`on: push: branches: [<default>]`);
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
| `literal-bound.option.{case,hook,subprocess,condition}` | ts tsx js | `{ timeout: V }` (or `{ timeout }`) in a call's arguments; the callee decides the kind (spawn/exec/execFile/fork and their Sync forms, and execa*, are subprocess, also through an alias resolved by binding: a named or default+named import, a `const`/`let`/`var` destructured require, a member of a child_process module object (`const run = cp.spawnSync`), and `promisify()` of any of these. Not resolved, so read at 60 s: a destructure from a module object (`const { execFile } = cp`), `require("child_process").execFile` bound to a name, a dynamic `import()`, a re-export, `.bind()`, and a launcher passed as an argument) | 120 / 240 / 120 / 60 s |
| `literal-bound.registrar.case` | ts tsx js | the last argument of it/test/bench/describe* (with .each/.only/... modifiers). With 3+ arguments any value is captured; with 2, only a literal | 120 s |
| `literal-bound.registrar.hook` | ts tsx js | the last argument of beforeAll/beforeEach/afterAll/afterEach, including `beforeAll?.(fn, N)` | 240 s |
| `literal-bound.wait.condition` | ts tsx js | `vi.waitFor(fn, N)` / `vi.waitUntil(fn, N)` | 60 s |
| `literal-bound.default.condition` | ts tsx js | a parameter default named /timeout\|deadline\|budget/i | 60 s |
| `literal-bound.config.{case,hook}` | ts tsx js | testTimeout / hookTimeout, teardownTimeout | 120 / 240 s |
| `literal-bound.keyword.subprocess` | py | `timeout=` of run/check_output/check_call/call/Popen/communicate/wait (not asyncio's `wait`, read below) | 120 s |
| `literal-bound.positional.subprocess` | py | `wait(N)`, `communicate(input, N)` | 120 s |
| `literal-bound.default.subprocess` | py | a `timeout` parameter default | 120 s |
| `literal-bound.client.fixture` | ts tsx js py | a PostgreSQL client's timeout: node-postgres `connectionTimeoutMillis` / `statement_timeout` / `query_timeout`; asyncpg / psycopg / psycopg2 / psycopg_pool connect and pool `timeout` / `connect_timeout` / `command_timeout` (py: by binding, below). A literal 0 is "no limit" for the node-postgres keys and libpq's `connect_timeout` (psycopg, psycopg2); asyncpg's and psycopg_pool's `timeout=0` is an INSTANT timeout, so it stays a finding | 120 s (`fixture`) |
| `literal-bound.join.subprocess` | py | a thread or process `.join(N)` or `.join(timeout=N)`. A positional name or arithmetic is judged only when it resolves to a number, since `str.join` takes one | 120 s |
| `literal-bound.wait.condition` | py, by binding | `asyncio.wait_for(aw, N)` / `timeout=`, and `asyncio.wait(aws, timeout=N)` | 60 s |
| `literal-bound.timeout-ctx.condition` | py, by binding | `asyncio.timeout(N)`, `async_timeout.timeout(N)` | 60 s |
| `literal-bound.http.condition` | py, by binding | `timeout=` of `urllib.request.urlopen` (or its third positional argument), the requests and httpx functions, `requests.Session` / `httpx.Client` / `httpx.AsyncClient` methods, and the httpx client constructors | 60 s |
| `literal-bound.http-tuple.condition` | py, by binding | each element of an HTTP `timeout=(connect, read)` tuple (a `None` element is no bound) | 60 s |
| `literal-bound.mark.case` | py, by binding | `@pytest.mark.timeout(N)` (a literal 0 is "no limit"; a NAME resolving to 0 is still judged) | 120 s |
| `literal-bound.ini.case` | pytest config | pytest-timeout's `timeout` and addopts `--timeout` in pytest.ini and .pytest.ini, tox.ini (`[pytest]`), setup.cfg (`[tool:pytest]`), pyproject.toml (`[tool.pytest.ini_options]` and pytest 9's native `[tool.pytest]`), pytest.toml and .pytest.toml (`[pytest]`), read in Python. A file that does not parse is unparsable; `timeout = 0` is "no limit" | 120 s |

**By binding** (root's #65 RC B3 and delta B1-B3): the Python library calls are read over CPython's own parse of the
file, not by spelling (`check.py` PY_CALLS).
- **Scope** (delta B2). A name means what the nearest enclosing scope that binds it says, as in Python (a class body
  never encloses its methods). So `from asyncio import wait` inside one function makes that function's `wait(fs)`
  asyncio's, while `wait = proc.wait` or a `wait` parameter in another function is that function's own subprocess
  wait, judged at 120 s. A bare name no scope binds is not read.
- **Reached through:** `import x as y`; `from x import y` in any scope; a star import of a covered module, which binds
  each covered name it exports (delta B1); a re-export from a local module, followed one hop (`from .helpers import
  wait_for`, `from pkg.helpers import client`: the local module's one binding of the name must be a direct import
  from a covered library, or one client construction); a submodule or vendored spelling (`requests.api.get`,
  `asyncio.tasks.wait_for`, `from pip._vendor import requests`); a try/except fallback import whose bindings agree on
  position, kind and index (`asyncio.timeout` or `async_timeout.timeout`, delta L3).
- **Client instances:** an assignment, an annotated assignment, a walrus, `with ... as c`, a class body (read as
  `self.s` in its methods), `self.s = ...`, `requests.Session().get(...)`, `requests.session()`.
- **Ownership.** The binding pass owns every direct argument of a call it resolves, so `from asyncio import wait;
  wait(aws, timeout=5)` is a condition wait at 60 s, never a subprocess one.
- **NOT COVERED, listed per call** with every run (the summary, the log and the findings JSON), so its absence from
  the findings is never a pass:
  - a covered call whose bound may come through a `*` or `**` splat, with no explicit bound;
  - a call through a name its scope binds by an import AND another way (or declares global or nonlocal), or through
    a name imports bind to calls of different positions;
  - a call through a covered name imported from a local module one hop cannot read, or possibly bound by a star
    import of a module this check does not follow;
  - a call into a covered library this check does not read, or one that reaches it through getattr,
    importlib.import_module or functools.partial, when it passes a bound keyword;
  - any aiohttp call with a bound keyword: aiohttp is seen, not read yet (its bound is a ClientTimeout).
- **Not read, and not listed:** a client that is a fixture or a parameter, a factory's return value, or held in a
  container; a method alias (`g = s.get`); a module bound to a name by importlib or pytest.importorskip. A file
  CPython cannot parse is unparsable (red).

Elapsed-time asserts are the `elapsed-assert` rules, below. Only these positions are read. Every run prints them
(`covered (...)`), so absence elsewhere is never a pass. Not yet covered, and due in K2 step 2C: fixed flushes,
sleep-as-wait, poll budgets, and read and absence windows.

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
| `elapsed-assert.hrtime.condition` | ts tsx js | `process.hrtime.bigint()` (a BigInt bound such as `60_000_000_000n` is evaluated) | ns |
| `elapsed-assert.{time,monotonic,perf-counter}.condition` | py | `time.time()`, `time.monotonic()` / `monotonic()`, `time.perf_counter()` / `perf_counter()` | s |
| `elapsed-assert.{time-ns,monotonic-ns,perf-counter-ns}.condition` | py | the `_ns` forms | ns |
| `elapsed-assert.loop.condition` | py | `loop.time()`, `asyncio.get_running_loop().time()`, `get_event_loop().time()` | s |
| `elapsed-assert.datetime.condition` | py | `datetime.now()` / `utcnow()`: through `.total_seconds()`, or against an exact `timedelta(...)` | s |
| `elapsed-assert.<family>.remaining` | all | D5: a LOWER bound on a remaining time `D - now` of the family's clock | the family's |

- **The assertion.** ts/js: `expect(A).toBeLessThan(V)` and `toBeLessThanOrEqual` (also `expect.soft`, and with a
  message argument), `expect(A).not.toBeGreaterThan[OrEqual](V)`, chai `expect(A).to.be.below / lessThan / lt / lte
  / at.most(V)`, `assert.isBelow / isAtMost(A, V)`, and `A < V`, `A <= V`, `V > A` or `V >= A` as the first argument
  of `assert`, `assert.ok`, `assert.isTrue`, or of an `expect` that ends `.toBe(true)`, `.toEqual(true)`,
  `.toStrictEqual(true)` or `.toBeTruthy()`. py: `assertLess[Equal](A, V)`, `assertGreater[Equal](V, A)`, and those
  comparisons, or a chained `LO < A < V`, as an `assert`'s test or `assertTrue`'s first argument. A comparison that
  is an operand of `&&` / `and`, or sits in parentheses, inside such an assertion is read too (root's #66 RC B1:
  core `test_voice_paid_consumer.py:216`, `assert response.status_code >= 400 and time.monotonic() - started < 8`).
  An `||` / `or` operand and a `!` / `not` are not: neither is required true.
- **The measured side A.** (1) `clock - x`; (2) `name - x`, with `name` bound to the clock; (3) a name bound to a
  measured side; any of these in parentheses; (4) `(d) / K`, `(d) * K` or `K * (d)`, which scales the unit by an exact K (an inexact K is a
  finding); (5) a name bound to a call of a same-file helper, one hop, whose return gives a measured side. The return
  can be the whole value or sit at the binding's tuple or array position (1-4, no holes). Examples: vps
  `test_uplink_probe.py:55` `return r, time.monotonic() - t0`, and vagary-core `security-events.mjs:318`. The call
  may be awaited, or run by `asyncio.run` or `run_until_complete`. The helper is resolved first in the nearest
  enclosing function, as a definition that is a direct statement of its body. Otherwise it is resolved in the file,
  which must hold exactly ONE definition of that name, or the read is not proven. A binding counts when it sits in a statement that precedes the assert's statement, in the same block or
  an enclosing one. The search goes down to, never into, another function. A preceding function or class
  declaration is not searched, so a sibling test's binding never counts. tree-sitter-typescript parses
  `a - b!.c()` as `(a - b)!.c()`, and the check reads it as the difference it is.
- **One record per assert, every family proven** (root's #66 RC B2). When the measured side may read more than
  one clock family (a name rebound from `time.monotonic()` to `time.perf_counter()`), the assert clears only when
  EACH family clears it, by its own fake or its own floor. A fake of one clock never clears another's reading.
- **A lower bound on a remaining time** (root's D5, split by polarity). `D - now >= X` (and `X <= D - now`,
  `assertGreater[Equal](D - now, X)`, `assertLess[Equal](X, D - now)`, `expect(D - now).toBeGreaterThan[OrEqual](X)`,
  `.not.toBeLessThan[OrEqual](X)`, `assert.isAbove/isAtLeast(D - now, X)`) bounds the elapsed time by B - X when D
  was bound to `now + B` of the same clock in a preceding statement. B - X is judged against the floor. A deadline
  whose budget is not read is a finding (unproven). An UPPER bound on a remaining time bounds the elapsed time from
  below: compliant, never matched.
- **Not matched.** A lower bound on elapsed time. An upper bound on a remaining time, which a slow machine only
  shrinks. A value the test did not read from a clock, such as a logged duration or an injected clock. A clock call
  wrapped in another call (`Math.round(...)`, `Number(...)`, `round(...)`, `abs(...)`). An alias of time or datetime
  (`import time as t`). `//` scaling. `assert not (...)`, `assertAlmostEqual`, `.seconds`, `total_seconds() * k`,
  chai `.below()` without `to.be`, node:test `t.assert.ok`, `assert.strictEqual(A < V, true)`.
- **NOT COVERED, listed with every run** (root's D6: helper reads go one hop). These shapes are seen but not read,
  and each site is listed (the summary, the log, the findings JSON), never silently clean:
  - an upper bound on a duration-named value (`elapsed`, `took`, `*_ms`, `durationMs`, ...) that a call or a
    destructuring binds, when no elapsed rule read the assert: a helper two hops deep (vps
    `test_disk_floor_reclaim.py:472`, `rc, out, elapsed = b.hook(...)` through `hook()` to `run()`), or object
    destructuring of a helper's return (`const { took } = await f()`);
  - a helper read whose name the file defines more than once. A bare call reaches a function only, and a member call
    a function or a method (L4).
- **Fake clocks clear only on positive proof, per family.**
  - ts/js: a statement that precedes the assert, in its block or an enclosing one, either makes the faking call
    itself (as a statement, or as `const clock = sinon.useFakeTimers()`) or is a beforeEach/beforeAll hook that
    makes it. No revocation may precede the assert: `useRealTimers()`, `clock.uninstall()` or `clock.restore()`
    anywhere in a preceding statement's subtree (a try/finally included, a function body never), a call to a
    same-file function whose body makes one, or a beforeEach/beforeAll hook that makes one. An afterEach, the usual
    cleanup, runs after the test and revokes nothing. A sibling test's body never counts.
    - The call is `vi/jest/sinon.useFakeTimers()`, with no argument or an object literal that does not advance with
      real time (`shouldAdvanceTime`, `advanceTimers`, `legacyFakeTimers`). An object holding a spread is no proof
      (root's #66 RC B4).
    - Date is faked unless `toFake` omits it or `toNotFake`/`doNotFake` names it. `performance` and `hrtime` are
      faked only when `toFake` names them, because vitest's default list changed across versions.
    - `vi.setSystemTime(...)` fakes Date (vitest's mockDate works with real timers). `jest.setSystemTime` alone
      proves nothing: under real timers jest 30.2.0 warns and does nothing (root's #66 RC B3), and
      `jest.useFakeTimers()` proves Date itself.
    - A config-level `fakeTimers` default is not read.
  - py:
    - freezegun's `freeze_time` fakes every clock above (loop.time() reads time.monotonic), unless it has a `tick`
      whose value is not the literal `False`, or a `**` splat that may carry one (root's #66 RC B4). With
      `real_asyncio=True` (freezegun 1.3+) loop.time() stays real (L2). It counts as a decorator, as a `with`, as
      a preceding `freeze_time(...).start()`, through the `freezer` fixture, or as `@pytest.mark.freeze_time`.
    - `mock.patch("...time.<fn>")` or `patch.object(time, "<fn>")` fakes that one function's clock as a decorator, a
      `with`, or a preceding chained `.start()`. `monkeypatch.setattr(time, "<fn>", ...)` fakes it as a preceding
      statement.
    - A preceding statement must take effect when it runs. An unstarted `f = freeze_time(...)` or
      `p = mock.patch(...)` leaves the clock real, and a two-statement start (`f.start()`) is not read, so both are
      findings. A started fake is revoked by a preceding `patch.stopall()`, a patcher's `.stop()` or
      `monkeypatch.undo()` anywhere in a preceding statement's subtree (L1).
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
- An untouched file is judged against the committed counts, which may not rise against the base's, with ONE
  exception (K2 D8, root 11-01 and the #68 review): a pin bump may lock in debt that more detection found, when all
  of these hold:
  1. the change is a DETECTION change: BOTH
     - (a) the change moves the consumer's pin of this check. In Actions, the running job's one step `uses:` of
       `vagarylabs/.github/actions/test-bounds@<sha>` must be the running action's own ref (read from where the
       runner put it) and must differ from that job's pin at the base. Comments, `run:` bodies and other jobs or
       workflows are not read. The running workflow and job are the runner's `GITHUB_WORKFLOW_REF` and
       `GITHUB_JOB` (GitHub documents that a step cannot overwrite `GITHUB_*` through `$GITHUB_ENV`), and they must
       equal the `github` context the action passes in (`TB_CTX_*`, an expression no step can write). In Actions, a
       context that cannot be read locks nothing in. Outside Actions (`write-baseline`), every job's pins at the
       base and head are compared, and CI then judges the strict form;
     - (b) the base baseline's recorded `check_digest` is not the running check's. A pin move to a commit whose
       check detects identically locks nothing in. A base baseline with no digest was written by a check from
       before digests, so it differs;
  2. the file is byte-identical at the base (its base blob against the file the scan read), and the BASE TREE,
     scanned with the running check under the BASE's own configuration (its launchers and their floors), holds the
     same findings: the same count and the same identities (line, position, kind, value). So a change elsewhere
     cannot pass new findings off as old debt: a lowered constant an untouched test imports, a removed or raised
     launcher, or a swap of which bound is short;
  3. the raise goes to EXACTLY that count (committed = base tree = head);
  4. every raised (file, rule) is listed ("Debt locked in by a detection change" in the summary, `DEBT LOCKED IN` in
     the log, `locked_in` in the findings JSON).

  Fail-safe false reds, for adopters: a form guard 1 cannot prove locks nothing in, so the pin bump stays red until
  its findings are fixed (or fixed and then locked by a bump guard 1 can read). These are:
  - a tag pin (`@v1`): the runner's path names the tag, not a commit;
  - a pin bump inside a reusable workflow: `GITHUB_WORKFLOW_REF` names the caller, whose jobs do not hold the step;
  - the action run from a workspace checkout (`uses: ./...`);
  - renaming the running job in the same change.

  `write-baseline --base` writes such a raise. Any other raise is red.
- A baseline names the check that wrote it: `check_digest`, the digest of check.py, rules/, the scope globs and the
  ast-grep pin, written by `write-baseline`. A missing digest, or one that is not the running check's, is red, so a pin
  bump re-runs `write-baseline` (`[check_digest]` problems do not block it).
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
