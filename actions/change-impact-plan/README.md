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
4. **Rule 7, parent steps on names (lexical taint). This is a CLOSED list of the forms implemented, exactly as coded.
   Any form not on this list is NOT covered.**
   - **Taint starts** at a COMPUTED root read. A literal read (`Path(ROOT, "services", "b")`) does not start taint.
   - **Taint passes** to a name, transitively within the file, through:
     - every target before every top-level `=` (`a = b = v`, `a, (b, c) = ...`, `let q = 1, d = v`);
     - an augmented assignment (`p /= ".."`), which reads its own target;
     - an assignment expression (`(m := v)`);
     - `for` and `as` targets;
     - parameters of a callback, a `function` or a `lambda` defined in the statement (never a type or a default
       value);
     - a Python def parameter whose own default holds the read;
     - a name read inside an f-string, t-string or JS `${}` substitution;
     - a call `RECEIVER.METHOD(...)`, where METHOD is one of `append`, `extend`, `insert`, `add`, `update`,
       `setdefault`, `push`, `unshift`, `set`, `splice` and RECEIVER is a plain name or `x.attr`;
     - `setattr(OBJ, "literal", value)`, which taints OBJ and the attribute `literal`;
     - a function whose `return` or `yield` statement is tainted, and so its calls;
     - a `@property` written as the exact line `@property` directly above `def NAME`, which taints the attribute NAME;
     - a name bound in a class body, which is also the attribute `self.NAME`, `this.NAME`, `Cls.NAME`.
   - **Scope follows each language:**
     - a parameter is visible only inside its function;
     - JS `const`/`let` are block-scoped, `var` is function-scoped, and a bare assignment is file-wide;
     - a Python name is local to its `def` unless declared `global` or `nonlocal`;
     - an attribute matches by name across the file.
   - **Parent steps:**
     - `..` as a path step, and a quoted `'..'`;
     - `.parent` and `.parents`;
     - the word `pardir`, and `getattr(x, "parent")`;
     - a call spelled `dirname(`, or one of three aliases:
       - `from ... import dirname as NAME`;
       - a destructured `{ dirname: NAME }`;
       - a line that is exactly `NAME = <dotted name ending in .dirname>` (an optional `const`/`let`/`var` and
         `;`, nothing after it);
     - a name bound by `NAME = <rhs>` when the RHS already holds one of these steps and consists only of `os`,
       `path`, `pardir`, `join`, `sep`, `posix`, digits, dots-only or separator-only string literals, `.`, `*`, `+`,
       `,` and brackets;
     - inside a substitution, also:
       - a dots-only string of two or more dots;
       - a dots-only string followed by `*` or `+`;
       - `*` or `+` followed by a dots-only string.
   - **A tainted statement refuses** when it holds a parent step. It also refuses when it passes a tainted value to
     a same-file function whose body holds a parent step, when that function is called directly, called as
     `x.NAME(...)`, or named (not called) in the statement.
   - **The anchor exception:** in the read's own statement, a step BEFORE the read acts on its base
     (`Path(__file__).parents[2] / "services"`), so it does not count. Two cases always count: a step inside a
     callback that the statement defines, and a step in the read token itself.
   - **A working directory set from a computed root read or a tainted name** refuses when the file holds any `../`,
     any `".."` string component, or `pardir`. The value is the argument of a call spelled `chdir(...)`, or a `cwd=` or
     `cwd:` argument of an exec call. It counts when it holds a computed root read, or a plain name that is tainted
     and visible at the call under the scoping above. An attribute is NOT followed, even a tainted one: `x.d` counts
     only when the plain name `x` is itself tainted, so `self.d` or `this.d` counts only when `self` or `this` is
     (`setattr(self, ...)` taints `self`). An exec call is one whose callee ends in `subprocess.<name>`,
     `run`, `call`, `check_call`, `check_output`, `Popen`, `spawn*`, `exec*` or `fork`.

   **In an unparsed file (shell, Makefile, Dockerfile, YAML, TOML), rule 7 is line-level,** after the trailing `#`
   comment:
   - **A line refuses** when it holds a root segment, or a variable bound from one, together with a `..` step. The
     variables are:
     - shell or Dockerfile `NAME=`, and `ARG` or `ENV`;
     - Make `NAME :=`, `?=`, `+=` or `=` at the start of a line;
     - a shell `for NAME in`;
     - each used as `$NAME`, `${NAME}` or `$(NAME)`.
   - **Any `..` step refuses** after `cd`, `pushd`, `WORKDIR`, `working-directory`, `working_dir`, `workdir` or `cwd`
     (followed by a space, `:` or `=`) into a root, on the same line or later.
   - **A bare root WORD reads** every package beneath it (`pytest services -q`, `COPY services .`, `- services`). In
     a `.yml` or `.yaml` file, a key (`services:`) is metadata instead. A TOML key is written `services =`, so in a
     `.toml` file it reads like any bare word.
   - **In code, a bare root word reads** only inside a string handed to a call whose callee ends in
     `subprocess.<name>`, `system`, `popen`, `Popen`, `check_call`, `check_output`, `spawn*`, `execSync`,
     `execFileSync`, `execFile`, `exec`, or `exec` + `l`/`v` (+ `p`)(+ `e`). Recognition is by spelling, so an
     aliased import (`import subprocess as sp`, `from subprocess import run`, `const { execSync: run }`) is not
     recognised.
   - **`package.json` `scripts` values are commands:** in a `package.json` the reader scan reaches (one of its lines
     matches the scan's `git grep` pattern; a binary file is never scanned), each STRING value of `scripts` is read
     like a line of a shell file, under the line-level rule 7 and the bare-word read. A value that is not a string
     is not a command and is skipped. One leading UTF-8 BOM is stripped first, as npm does. Such a file REFUSES when
     the rest is not strict JSON with an object at the top level, or when its `scripts` is present and is not an
     object (`null` included). Strict means `NaN`, `Infinity` and `-Infinity` refuse, as npm refuses them; nesting
     too deep, or an integer too long, for Python to decode also refuses, though npm would accept it.

   Any form not on this list is NOT covered.
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

`test_edges_review_vectors.json` holds 543 adversarial readers:
- 245 from root's first three independent reviews;
- 12 of spine's own probes;
- 74 for round 4's rule 7;
- 88 from the fourth review;
- 11 for round 5;
- 59 from the fifth review (the 52 inputs R5V01-R5V54, which skip R5V48 and R5V49, and Z1-Z7);
- 1 for round 6 (R6T01: `pardir` in a file whose working directory is set from a read);
- 33 from the sixth review (R6V01-R6V30 and the controls Q1-Q3);
- 20 for round 7:
  - R7T01-R7T07 and R7T13-R7T15 refuse the `package.json` forms (`NaN`, `-Infinity` and an integer too long to
    decode included);
  - R7T08-R7T11 are precision controls that read, and R7T12 pins that a TOML key reads;
  - R7T16, R7T19 and R7T20 refuse and pin the working-directory wording; R7T17 and R7T18 are named residuals.

Each one reads its truth or refuses, except the named residuals:
- **A12, N08, N11:** an object value or key later used as a path (root's metadata ruling).
- **T19:** a root built by deliberate string obfuscation (`"serv" + "ices"`).
- **T36/T37:** a root joined to a computed base that is a repo-internal directory other than the root
  (`join(WEB_SRC, "services", x)`) reads beneath the root segment, not beneath that directory. A rule refusing every
  base not provably the repo root would refuse 8 vagary-core files, 5 of them fixture trees under a temp directory.
- **M5, M6, V48:** a literal root read does not start taint. Starting taint there refuses 11 more vagary-core files.
- **V45, V46, V47:** a path head taken by string operations (tuple slicing, a regex, `os.path.split`) is not a parent
  step.
- **Forms outside rule 4's closed list,** each a named residual (the fifth review's inputs):
  - dirname under any other alias: a trailing comment, a tuple, or `require(...).dirname` (R5V24-R5V26);
  - parent material built any other way: `"." + "."`, `"".join([".", "."])`, `f"..{sep}.."`, a parent name inside a
    substitution, implicit string concatenation or joined dots in a substitution (R5V27, R5V28, R5V30-R5V33);
  - `@property` with anything on its line (R5V36);
  - an exec, `cwd=` or chdir reached through an aliased import or an unlisted API (R5V18, R5V19, R5V22, R5V01,
    R5V02, R5V08), including `asyncio.create_subprocess_shell` and `execa` (R5V04, R5V07);
  - a parent-step function bound to another name (R5V37).
- **Forms outside rule 4's closed list from the sixth review:**
  - a working directory set from an attribute of a receiver the file never binds: `os.chdir(self.d)`, `cwd=self.d`,
    JS `{ cwd: this.d }` (R6V21-R6V23);
  - a parent step taken from the working directory itself after a chdir, `Path.cwd().parent` (R6V24), and a `..`
    held only inside f-strings (R6V25);
  - task runners other than `package.json` `scripts`: husky `hooks` in a `package.json`, `deno.json` `tasks`
    (R6V18, R6V19);
  - a working directory set from a name that is not tainted where the call is, because another function binds
    it: a parameter of the calling function, or another function's local (R7T17, R7T18).
- **A YAML key used as a path** (R5V17, R6V02, R6V03): rule 4 makes a `.yml`/`.yaml` key metadata.
- **Shapes outside the list, each counted on vagary-core** (occurrences carrying a root path / all occurrences):
  - a command string in a variable passed to an exec call (R5V03): 0 / 11;
  - a Make target-specific variable (R5V13): 0 / 0;
  - a shell `while read` variable (R5V14): 0 / 0;
  - a Taskfile `dir:` (R5V15): 0 / 0;
  - `Path("..")` (R5V29): 0 / 0;
  - `@cached_property` (R5V35): 0 / 0;
  - a literal-name `getattr(...)(...)` call (R5V38): 0 / 0;
  - a factory closure (R5V39): 0 / 0;
  - a mutator outside the list, such as `appendleft` (R5V40): 0 / 3;
  - JS `Object.assign` (R5V41): 0 / 9.
- **Rule 7 stays within a file:** a cross-file flow, a container read back by a computed key, `getattr` with a
  computed name, and `eval`/`exec` are not followed.
- **An opaque `..`:** a computed component whose RUNTIME value holds `..` (read from config, the environment or a
  file) reads beneath its literal prefix.

These are bounded by the 10-22 ruling: main runs FULL after every merge, and a red main blocks landings.

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.

On the approved POSIX/Linux runner path, the optional provider witness executes its single GET in an owned Python worker. Windows selectors do not support these process pipes; failure remains UNKNOWN/FULL. The parent enforces the existing whole-request deadline across process startup, DNS, connect, TLS, status/headers and body, and kills/reaps the worker on timeout, output overflow or catchable interruption (at most one additional second for reaping). Request credentials travel only through a private stdin pipe, not argv or inherited GH_TOKEN/GITHUB_TOKEN; worker stderr and exception details are not logged. Response metadata and body are capped separately. This changes transport containment, not source-access authority or plan-selection permissions. Malformed non-string provider file statuses remain UNKNOWN/FULL rather than raising an uncaught type error.

Abrupt parent termination (including default SIGTERM/SIGKILL) is outside Python exception cleanup; the runner must own and reap the complete job process group. This transport does not install a process-global signal handler or claim standalone orphan recovery after abrupt parent death.
