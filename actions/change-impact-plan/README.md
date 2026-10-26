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

`edges.py` classifies every workspace-root literal: `"services"`, `"apps"`, ..., also `"./services"`, `"services/"` and a
backtick string with no substitution. It works from the WHOLE file's tokens: strings, comments, regex literals, and
brackets across lines. Lines are split on `\n` only, as `git grep` numbers them.

The rule is root's principle (2026-10-26): **metadata needs positive evidence; everything else refuses.** A refusal plans
FULL.

1. **A read, in a path.** The literal reads a path when it is:
   - after a pathlib `/`;
   - ALONE as an argument of `join`, `resolve`, `joinpath` or `Path(...)`;
   - in a list spread into one (`*[...]`, `...[...]`);
   - the sole argument of `sep.join(...)`;
   - or `[...].join(...)`-ed.

   Then:
   - The literal components that follow are joined, and the owning package is read.
   - A computed or glob component (`*`, `?`, `[`, `{`), or a walk of the result (`glob`, `rglob`, `iterdir`,
     `os.walk`, `readdir`, ...), also reads every package beneath the literal prefix.
   - A parent step after the root REFUSES: `..`, `.parent`, `os.pardir` or `dirname(...)`. It counts in the root's own
     argument, in a later argument of an enclosing path call, in a call around it, and later in its statement (nested
     blocks and objects excepted).
   - An unowned path normally needs no edge, because its change plans FULL. If the caller's `inert_globs` or
     `extra_edges` cover it, that no longer holds, so the read REFUSES.
2. **A read, as a walker.** These read every package beneath the root:
   - a collection holding only the root;
   - a loop over a collection holding it, or over pairs that hold it;
   - a method called on such a collection;
   - a list, tuple or set of literals in an assignment, an object value or a comparison (rule 8: there is no
     list-literal exemption, since `parts = ["services", "billing"]` can flow into `join(ROOT, *parts)`). Its siblings
     that name a package (`("services", "b")`) are read too;
   - a comparison (`==`, `===`, `in`, `not in`, `case`): `d == "services"` selects a value that may become a path.

   A root SEGMENT anywhere in a string reads every package beneath its literal prefix, whatever precedes it:
   `backend/services/`, `./services/`, `{}/services/`, `$ROOT/services`, a route, prose, a docstring, SQL text. That
   covers an f-string, a template and a glob too: `f"{ROOT}/services/{x}"`, `"services/*/migrations"`. A backslash
   always separates. A segment inside a pure-literal `../` run (`'../app/api/x/services/route.ts'`) is a path relative to
   the file, which the `rel` rule reads exactly. A string REFUSES when:
   - a `..` follows the segment in the same path run;
   - it is computed and holds a `..` step anywhere (`..`, `pardir`, `parent`, `dirname`; an ellipsis is not a step),
     or nests code naming a root: `f"{os.path.join(ROOT, 'services', x, '..')}"`. A substitution is opaque;
   - it is a doctest (`>>>`) naming a root, which is executed code;
   - the quoted root runs past the string the tokenizer saw (a desynchronised grammar: JSX text, a PEP 701 nested
     quote, a regex lexed as division).

   A file the tokenizer does not parse (shell, Dockerfile, YAML, TOML) reads the same way, line by line, after its
   trailing `#` comment is removed. A QUOTED root there (`"services"`) still REFUSES, and `.sql` files are metadata.
3. **Metadata, only with positive evidence:**
   - an object key or value, never a ternary branch (a JSON file is parsed, so its keys and values are these);
   - a subscript key (`m["services"]`);
   - any `.sql` file.
4. **Rule 7, parent steps on names (lexical taint).**
   - A name bound from a COMPUTED root read is tainted, and so is every name bound from a tainted one, transitively
     within the file. (A literal read such as `Path(ROOT, "services", "b")` does not start taint: residual below.)
   - A tainted statement holding a parent step REFUSES. The steps are:
     - `..` and a quoted `'..'`;
     - `.parent` and `.parents`;
     - `os.pardir` and `getattr(p, "parent")`;
     - a `dirname(` call, under any import or assigned alias;
     - a name bound only from parent material (`UP = os.pardir`, `"/".join([".."] * 2)`);
     - inside an f-string, t-string or JS `${}` substitution, any of these or dots repeated or concatenated
       (`'.' * 2`).
   - So does a tainted value passed to a same-file function whose body holds a parent step, whether it is called
     directly, as a method or by reference (`map(up2, [read])`).
   - In the read's own statement, a step BEFORE the read acts on its base (`Path(__file__).parents[2] / "services"`),
     so it does not count. A step inside a callback that the statement defines always counts. So does a step in the
     read token itself (a string that names a root and holds `..`).
   - A working directory set from a tainted value (`os.chdir(read)`, an exec call's `cwd=read`) with any `../` path in
     the file REFUSES.

   **What carries taint** (these constructs only):
   - every target before every top-level `=` (`a = b = v`, `a, (b, c) = ...`, `let q = 1, d = v`);
   - an augmented assignment (`p /= ".."`), which reads its own target;
   - an assignment expression (`(m := v)`);
   - `for` and `as` targets;
   - parameters (never a type or a default value), and a Python def parameter whose own default holds the read;
   - names read inside a substitution;
   - a container mutated with the value (`.append`, `.extend`, `.insert`, `.add`, `.update`, `.setdefault`, `.push`,
     `.unshift`, `.set`, `.splice`, and `setattr(obj, "name", value)`);
   - a function whose `return` or `yield` is tainted, and so its calls; a tainted `@property` is a tainted attribute;
   - a name bound in a class body, which is also an attribute (`self.BASE`, `this.base`, `Cls.BASE`).

   **Scope follows each language:**
   - a parameter is visible only inside its function;
   - JS `const`/`let` are block-scoped, `var` is function-scoped, and a bare assignment is file-wide;
   - a Python name is local to its `def` unless declared `global` or `nonlocal`;
   - an attribute matches by name across the file.

   **NOT covered** (named residuals below): flows through another file; a literal root read; a value carried through a
   container read back by a computed key or slice; `getattr` with a computed name; `eval`/`exec` and dynamic imports;
   a path head taken by string operations (`os.path.split(p)[0]`, `p.rsplit("/", 1)[0]`, tuple slicing
   `Path(*p.parts[:-2])`, a regex substitution).

   **In an unparsed file (shell, Makefile, Dockerfile, YAML, TOML), rule 7 is line-level,** after the trailing `#`
   comment:
   - a line holding a root segment, or a variable bound from one, together with a `..` step REFUSES. Variables are
     shell/Dockerfile `NAME=`, `ARG`/`ENV`, Make `NAME :=`/`?=`/`+=`/`=`, and a shell `for NAME in`, used as `$NAME`,
     `${NAME}` or `$(NAME)`;
   - so does any `..` step after a `cd`, `pushd`, `WORKDIR` or `working-directory:` into a root, or after a `cd` into
     one inside a command string.
   - A bare root WORD there (`pytest services -q`, `COPY services .`, `- services`, `cd services && make`) reads every
     package beneath it; a YAML/TOML key (`services:`) is metadata. So does a bare root word inside a command string
     handed to a process, never a database `execute()`. The process APIs recognised are exactly:
     - Python `subprocess.*`, `Popen`, `check_call`, `check_output`, `os.system` and `os.popen`;
     - `spawn*`, and child_process `exec`, `execSync`, `execFile`, `execFileSync`, `execl*`/`execv*`.

     A command string handed to any other API (a shell library such as `sh`, `plumbum` or `invoke`; `execa`; zx's
     `` $`...` ``) is a stated gap: its bare words read nothing.
5. **Everything else REFUSES**, including:
   - a root not alone in a path argument (`"services" + os.sep + x`, `"apps" if web else "services"`);
   - a subscripted list in a path call;
   - a direct argument of any other call (`make("services", v=1)`, `shutil.copytree("services", ...)`,
     `pytest.main(["services"])`). There is deliberately no allowlist of metadata calls; a caller rewrites such a line
     as a literal or a named constant;
   - a keyword argument or default parameter;
   - a bare assignment (`kind = "services"`);
   - an argv element of an exec call, or its options;
   - a root inside a regex literal;
   - any file whose brackets do not close.

The workspace manifest `pnpm-workspace.yaml` defines the graph, so it is not scanned. A change to it already plans FULL.

`test_edges_review_vectors.json` holds 424 adversarial readers:
- 245 from root's first three independent reviews;
- 12 of spine's own probes;
- 74 for round 4's rule 7 (R4T01-R4T63 must refuse; R4R01-R4R11 must keep reading);
- 89 from the fourth review (V01-V70, M1-M6, X1-X6, K05-K10);
- 4 for round 5's precision (R5R01-R5R04 must read; R5T01 must refuse).

Each one reads its truth or refuses, except the named residuals:
- A12, N08, N11: an object value or key later used as a path (root's metadata ruling).
- T19: a root built by deliberate string obfuscation (`"serv" + "ices"`).
- T36/T37: a root joined to a computed base that is a repo-internal directory other than the root (`join(WEB_SRC,
  "services", x)`) reads beneath the root segment, not beneath that directory. A rule refusing every base not provably
  the repo root would refuse 8 vagary-core files, 5 of them fixture trees under a temp directory.
- M5, M6, V48: a LITERAL root read does not start taint, so `P = Path(ROOT, "services", "b")` then `P.parent / "a"`
  reads b, not a. Measured: starting taint there refuses 11 more vagary-core files.
- V45, V46, V47: a path head taken by string operations (tuple slicing `Path(*p.parts[:-2])`, a regex substitution,
  `os.path.split(p)[0]`) is not a parent step.
- Rule 7 stays within a file and covers only the constructs listed under rule 7. A cross-file flow (a tainted path
  handed to a helper in another module), a computed container key, `getattr` with a computed name, and
  `eval`/`exec` are not followed.
- A computed path component whose runtime value holds `..` (an opaque substitution, such as a value read from config
  or the environment) reads beneath its literal prefix. Parent material the file itself builds (`os.pardir`, `'..'`,
  dots joined, repeated or concatenated) does count.

These are bounded by the 10-22 ruling: main runs FULL after every merge, and a red main blocks landings.

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.

On the approved POSIX/Linux runner path, the optional provider witness executes its single GET in an owned Python worker. Windows selectors do not support these process pipes; failure remains UNKNOWN/FULL. The parent enforces the existing whole-request deadline across process startup, DNS, connect, TLS, status/headers and body, and kills/reaps the worker on timeout, output overflow or catchable interruption (at most one additional second for reaping). Request credentials travel only through a private stdin pipe, not argv or inherited GH_TOKEN/GITHUB_TOKEN; worker stderr and exception details are not logged. Response metadata and body are capped separately. This changes transport containment, not source-access authority or plan-selection permissions. Malformed non-string provider file statuses remain UNKNOWN/FULL rather than raising an uncaught type error.

Abrupt parent termination (including default SIGTERM/SIGKILL) is outside Python exception cleanup; the runner must own and reap the complete job process group. This transport does not install a process-global signal handler or claim standalone orphan recovery after abrupt parent death.
