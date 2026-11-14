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

Planner 1.7.7 makes the Python reader fail closed by token (R6-2 of #86, 2026-11-12). It implements cli's R6 design, which root accepted at 16:44 with decisions (i)-(iii), under the operator's ruling (d) of the same day: the measured R6-2 result goes to the operator on 11-14, and the reader stays fail closed. A Python file now reads only when every path-mutation capability in it is consumed by a read rule (rule 9). `python_file_facts` holds the one refuse point, so no caller decides read or refuse for Python, and the refusal names the first unconsumed occurrence by its source and line. The listing grep lists every Python file holding a capability word or `PYTHONPATH`, so more files are parsed, and a listed file that does not parse refuses. One new read rule consumes a `sys` binding whose every use is an attribute off the import path: `import sys; sys.exit(main())` reads (root's (i)). An alias, an argument, a subscript, a `del`, a rebinding, `from sys import path` or `from sys import *` refuses, and so does `globals()` in a file that imports sys. A dead import refuses (root's (ii)). An import of `site`, any use of a site-bound name and `addsitedir` by any name refuse: no rule reads them. `module_from_spec` is consumed by no rule, so a load through `spec_from_file_location` and `module_from_spec` refuses. The carve-out that read a file whose only `sys.path` sites recorded no entry (a reassignment, `site.addsitedir`, an alias of `sys.path`) is gone; a file whose entries are all residuals still reads. One named residual: a module re-exported under another name (`from helpers import s`, then `s.path.remove(x)`) reads. R6-1 added the no-regression gate, `test_r6_no_regression_against_main_reader`: main's reader runs beside this one on every review vector, root's 111 included (root's (iii) entered them verbatim). Root's ruling of 2026-11-12 21:32 added three narrowings, each a rule (rule 9, N1-N3): a `sys.path` membership test reads the list, a loader call with a literal module name reads through its chain, and `importlib.metadata` reads and literal `importlib.resources` anchors are not refusals. The review vectors number 1,060, the 51 R6-2 twins included: every accept twin reads a non-empty truth and its control, the same construct with one change, refuses. Measured tree cost of R6-2 (2026-11-12, after N1-N3, both readers on the same checkout): vagary-core head 9cea8193 (3,134 files), main's reader refuses 11 files, this one 154 (190 before N1-N3), so 143 more files plan FULL than on main (179 before); vagaris head 1ac91295 (49 files), 2 and 9, cost 7. The 11-14 result to the operator is this number re-measured on that day's heads.

Planner 1.7.6 closes two reader holes root found on main (2026-11-12, F1, F2 and F4 of the R-c review) and tightens the vector harness. F1/F4: rule 6 refused an unevaluable `sys.path` entry only when its literal named a scan root or a top-level directory outside every package, so `sys.path.insert(0, str(source / "packages/shared"))` (and the `os.path.join`, `+ "/packages/shared"` and f-string forms), `sys.path.insert(0, "packages/shared")`, `"./packages/shared"`, `str(Path.cwd() / "packages/shared")`, `os.path.abspath("packages/shared")` and `ROOT / "packages/shared"` with `ROOT` imported each read as a documented residual (nothing credited) while the module was imported from `packages/shared`. A PACKAGE top is a named top now, and a leading `./`, `/` or substitution (`{source}/`, `${x}/`) is stripped before the top-level name is read, so every one of those forms refuses. F2: the dot-route grep needed a word character after `../`, so `` `../${p}` `` in a file outside every package that nothing reached started no unit and its reader directory read nothing; `${` is accepted after the step, so the template starts its unit and, as a whole-checkout route, reads every package (or refuses on excluded code, rule 3). Harness: a review vector may carry `files` (a second tracked file, removed with the input after the case) and `unit` (the package or `readers:<dir>` judged); an accept vector with an empty truth is refused unless it is a declared precision control (`control: true`, the 26 existing ones, a closed list in the test, each with its reading pinned as `reads`); every write of a case sits inside its cleanup, and no case may write over a fixture path. Ten vectors pin the readings (RC1I x4, F4a-F4e, RC4G). Root's R4 of the first head (B1, B3, C1): the strip had hidden a tracked top-level directory literally named `{tpl}` or `${tpl}` (main refused, the first head read nothing), so each literal is compared as written and stripped; a declared computed load whose literal lands inside another package (`runpy.run_path(f"{source}/packages/shared/mod.py")`, rule 8) is honoured first instead of refusing before the declaration lookup; the strip covers `%s/`, `%(x)s/`, `$VAR/` and `{{x}}/`, a substitution holding quotes, and a name with one assignment, and the dot-route grep lists `../{p}` and `'../' + p` (both refuse or read the checkout, as `../${p}` does). Seventeen `R84_` vectors pin those readings (582 review vectors). Root's R4 of the second head (F1, K1-K3): the declaration-first route honoured a declared load without crediting the package its text lands in (`reach: "external"` read nothing, a reach list read only its own packages); the landing's owner is credited whatever the reach says. B3 does not only move readings toward refuse: `runpy.run_path(f"{source}/packages/shared/shared_mod.py".replace("packages/shared", "services/a"))`, declared, refused on main and reads `[a, shared]` now, every literal landing credited, which is sound by the literal-path rule (a literal naming a package is a load into it). Of eleven forms that read nothing on main and on both heads, ten are fixed: nested braces, `+=`, a two-level name chain, a name assigned in two branches, tuple unpacking, a `%-10s/` field, `{os.sep}`, and the dot-route grep's `` `../` + p ``, `'../'.concat(p)` (both refuse on the `.` route) and `"../%s" % p` (a template, read as `f"../{p}"` is); one is a dated residual, a bare parameter as the entry (`R84_S08`, review by 2026-12-10). Sixteen more `R84_` vectors pin those readings (598 review vectors). Root's R4 of the third head (B1, B2, C1-C3): the landing credit skipped a caller outside every package whose literals land one in a package and one on a package-free top (`scripts/x.py` loading `f"{source}/packages/shared/m.py" if k else f"{source}/tools/t.py"`, declared, read nothing: the credit was gated on every landing being in another package, a condition meant for the refusal of a PACKAGE caller), so the landing's owner is credited for every caller, and through a symlink; a name hid the landing at a loader site (`p = f"{source}/packages/shared/m.py"; runpy.run_path(p)`, declared as `p`, read nothing) since the loader read the argument's source alone, so it reads the text rule 6 reads, the name's assignments included; the JS twin (`` import(`${source}/packages/shared/m.mjs`) `` declared `"external"`) read nothing on main and every head, so rule 4 credits a template literal's landing package as rule 8 does; two forms that moved from `[shared]` to refuse (an augmentation that is not `+= "<literal>"` before a loader, a `sys.path` entry that is a parameter with a module-level default) are pinned; a name in an argument default or a decorator is the enclosing scope's, not the parameter's (no reading moves). Nine more `R84_` vectors pin those readings (607 review vectors). Root's R4 of the fourth head (K1-K3, N4): the symlink credit replaced the holder's owner with the target's (a package symlink `packages/a/m.py -> ../shared/m.py` loaded by name credited `shared` alone), so both are credited; the un-shadow of a parameter-named name in a default or decorator read the enclosing scope's name whatever its binding (`def f(p=p)` with a module `p` assigned in two branches read below truth), so it reads the enclosing name only when that name has one plain module literal binding, and refuses otherwise; a name a computed load reads that the scan cannot read (bound by a walrus, a `for`, a comprehension, `with ... as`, `except ... as`, a `match` pattern, a `def`, a `class`, a bare annotation, an unpacking the scan cannot pair, a starred or nested target, a parameter default that is not a plain module literal, or an attribute assignment) read `[]` under a declaration and refuses now, declared or not, naming the binding; an augmented computed loader that is declared (`p += f"/{x}"` before `runpy.run_path(p)`) refuses as the undeclared form does. A name alone as a `sys.path` entry inside a nested function (`R84_B11`) is a dated residual with `R84_S08`. Forty-two more `R84_` vectors pin those readings (649 review vectors). Root's R4 of that head (R1): a name the file also binds by something the scan does not read (`root = dirname(dirname(abspath(__file__)))` at module level and `for root, d, f in os.walk(t)` inside a function, or a method, a `with ... as`, an `except ... as`, a comprehension variable, a later module-level `for`) was unknown file-wide, so a `sys.path` entry reading it fell to the read-nothing residual and read `[]` where main read the package; such an entry refuses now, declared or not, naming the binding, as a loader site does; a name bound once by a plain assignment still evaluates. Eight more `R84_R6` vectors pin those readings, one of them the control (657 review vectors). Every other reading over the review vectors, the round-3/4 vectors and the R-c vectors is unchanged except where a reading moved toward refuse or toward a larger read by these rules (the both-readings table in the PR).

Planner 1.7.5 bounds a package.json's nesting before it is parsed at the two sites that were still unbounded: the planner's pnpm workspace graph (a manifest deeper than `PLAN_CONFIG_MAX_DEPTH` (64) levels is refused as unreadable, candidate and base alike) and edges.py's directory-runner read (deeper than `PACKAGE_JSON_MAX_DEPTH` (64) is read whole, like any unparsable manifest). CPython 3.14 parses depths 3.11-3.13 refuse with `RecursionError`, so the bound is the planner's own.

Planner 1.7.4 bounds a plan config's nesting before it is parsed: a config deeper than `PLAN_CONFIG_MAX_DEPTH` (64) levels is red with "the plan config nests too deeply to parse", as the candidate and as the base. Until 1.7.3 that refusal came only from `json.loads` raising `RecursionError`, which depends on the interpreter: CPython 3.13 raises at 100000 levels, 3.14 (the `ubuntu-26.04` runner image) parses them, and the 100000-level config then planned reduced. `RecursionError` stays a backstop.

Planner 1.7.3 makes a slow git call cost a retry, not the reduced plan (spine, from core #936: at Mac load 25-34 the reader scan's `git grep` ran past its 15 s ceiling on 2 of 4 runs). Every git subprocess gets ONE retry after a timeout, and every git ceiling scales by the new `git-timeout-scale` input (an integer 1-8, default 1). A call that times out on both attempts still plans full, under its own reason: `reader scan timed out; full validation required` (edges.py exits 3) or `canonical target lookup timed out` in the target observation. It is never folded into "unproven", and it never narrows a plan.

Planner 1.7.2 adds the `source_dir` output: `GITHUB_ACTION_PATH`, the directory this step ran `plan.py`, `edges.py` and `action.yml` from. It is written only after the plan is published, so a refused plan has none, and no existing output changes.
- It is a LOCATOR, never authority.
- A consumer that reads those files (core's orphan gate, for one) hashes them and must match BOTH `plan.validity.{planner,reader,action}_source_sha256` AND its own policy-pinned copies.
- Any other byte, or a missing file, is a refusal, never a fallback.

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

## Reader scan (1.4.1; 1.5.0 adds imported files; 1.5.2 Python sys.path)

`edges.py` classifies every workspace-root literal: `"services"`, `"apps"`, ..., also `"./services"`, `"services/"` and a
backtick string with no substitution. It works from the WHOLE file's tokens: strings, comments, regex literals, and
brackets across lines. Lines are split on `\n` only, as `git grep` numbers them. The scan's `git grep` runs with
`LC_ALL=C`: under a UTF-8 locale it stops matching a line at an invalid UTF-8 byte, which would hide a later mention.

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
     unquoted `cwd:` argument of an exec call; a quoted JS key (`{ "cwd": d }`) is not followed. It counts when it
     holds a computed root read, or a plain name written as a bare identifier that is tainted and visible at the call
     under the scoping above. A name inside a string or a substitution (`f"{d}"`, `` `${d}` ``) is NOT followed, and
     neither is an attribute, even a tainted one: `x.d` counts only when the bare `x` is itself tainted, so `self.d`
     or `this.d` counts only when `self` or `this` is (`setattr(self, ...)` taints `self`). An exec call is one whose
     callee ends in `subprocess.<name>`,
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
     object (`null` included). Strict means `NaN`, `Infinity` and `-Infinity` refuse, as npm refuses them. So does
     nesting deeper than 64 levels (counted before parsing, so the answer is the same on every Python) and an
     integer too long for Python to decode, though npm would accept either.

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

**Always-only reader directories (`edge_scan.always_reader_dirs`).** A top-level reader directory whose files run ONLY in
`always` jobs is left out of the scan. No plan can skip an `always` job, so what those files read cannot change a
selection, and a construct the scanner cannot read there no longer refuses (a refusal plans every change FULL). A change
to a file in the directory is still unmapped and still plans FULL: only its reads are out of scope.

The scanner REFUSES every declaration that could hide a read that selects:
- an entry that is not one plain top-level name (no `/`, no `.` or `..`, no glob);
- an entry that is not also in `edge_scan.reader_dirs`;
- a scan root, or a directory that holds a workspace package;
- an empty or repeated list;
- an `edge_scan.reader_job` whose rule in `jobs` is not exactly `"always"`.

The CONSUMER proves the premise this rests on: no selected job, and no matrix it builds, executes a file in the
directory. A file that a selected job runs (a test runner script, say) must not live in a declared directory. If one does,
the declaration is unsound, and nothing in this scanner can see it. One case it CAN see refuses since 1.5.0: a package
that imports a file in the directory runs it wherever the package runs, so the declaration refuses.

### Imported files outside every package (1.5.0)

Before 1.5.0 a relative path that resolved outside every package was dropped. So a test in package `a` that imported
`../../scripts/x.mjs`, where `x.mjs` reads `packages/b`, gave `deps(a) = []`. The read was credited only to the reader
job, and a change to `b` never selected `a`'s tests. A package now reads what the files it reaches read.

1. **The edge.** It comes from two places:
   - a relative path on a non-comment line of a package file (a `../` path, as before) that resolves to a tracked path
     outside every package;
   - every `./` or `../` string in a file outside every package that a package already reaches. That includes a shell
     `source`, a `. ` or a `$(dirname "$0")/` path, and a same-directory Python import. Such a file is read IN FULL,
     because a `./` import never matches the scan's grep.

   Resolution:
   - a `.js`, `.jsx`, `.mjs` or `.cjs` specifier names its TypeScript source as TypeScript resolves it (`.ts`, `.tsx`,
     `.d.ts`; `.tsx`; `.mts`, `.d.mts`; `.cts`, `.d.cts`), the house style for ESM imports of TypeScript. When both the
     `.js` file and its source are tracked, both are read;
   - an extensionless specifier resolves as Node and Python do (`x.js`, `x.ts`, ..., `x.py`);
   - a symlink resolves by its target;
   - a directory is every tracked file beneath it, and a package nested there is a dep, not a reached file.
   - **Nothing is dropped** (root's R4 of #33). An untracked path inside a package, such as its `dist/` output, stands
     for that package: a dep.
   - **Every route resolves, or the scan refuses** (root's delta R4 of #33, D5). A name that resolves to no tracked file
     or directory outside every package is an unresolved route, in ANY position. A scan that cannot run a line cannot
     tell a module position from data. `timeout 300 node ../dist/x.js`, `npx tsx`, `env -i node`,
     `node --import`, `pnpm exec`, `xargs`, `nohup`, a heredoc import, a `package.json` script, `fork`,
     `new Worker("...")` and `spawn(process.execPath, [...])` all read alike to it, and a test's `"../../etc/passwd"`
     looks no different. So it refuses unless an `edge_scan.unresolved_names` entry declares it: `{"file", "name",
     "reach"}`, where `name` is the repo path it resolves to. `reach` is `"none"` (it names nothing that runs: a test
     datum) or the tracked paths it stands for (a build output's sources), each then an edge. An entry that matches no
     route fails `check` as stale. `derive`'s report lists the declared names under `unresolved_data_names`. A path under
     `node_modules` stays external. Reach `"none"` refuses for a name with a code extension (F09): code something runs
     (`spawn(process.execPath, ["../../dist/x.js"])`) reaches its sources, so it must name them.
   - **A path at or above the repository root refuses** (N4): a `"../.."` alias, `baseUrl` or `root` reaches every
     file, so no mapping of it can be narrower than FULL. 1.5.2, root's rulings of 2026-10-29:
     - **(a) Above the checkout** (`../vagary-voice`, `../../etc/passwd` resolved from the root), a name joins the
       unresolved-name class. It is declared in `unresolved_names` by its exact path, or by a glob over such paths whose
       first segment below the `../` steps is literal (`../vagary-voice/**`; `../**` refuses). Its reach may be `"none"`
       even with a code extension, since nothing above the checkout is this repository's. It may also list the tracked
       paths it stands for. Two exceptions need a reach list (root's R4 of #49):
       - a name made only of `..` steps (`..`, `../..`, `x/../..`) is an ANCESTOR of the checkout, so it contains every
         file, as the root does (A7-A7c; `../sibling` with `"none"` still holds, A7d);
       - a name that re-enters the checkout by its own name (`../<repo>/...`, globs included) may be this repository's
         tree: CI checks out into `.../<repo>/<repo>`. The names are the checkout directory's and, in Actions,
         `GITHUB_REPOSITORY`'s;
       - 1.5.3 (root's delta R4 of #49): a name, or a glob's literal prefix, that resolves from the ACTUAL checkout path
         at scan time to the checkout, inside it or an ancestor of it, such as `../../../_work/**` on CI's
         `.../_work/<repo>/<repo>`. The resolution is lexical, so a path that does not exist on the scanning machine is
         still judged. **Residual:** a parent reached through a symlink is judged by its lexical path, not its target.
     - **(b) At the root** (`.`), a name refuses unless declared with a reach list. `"none"` refuses, because a name at
       the root reaches every file. A **root base** needs no declaration when every use joins string literals: it then
       stands for exactly those literals. A root base is a chain anchored at the file's directory that resolves to the
       root (vagaris's `realpathSync(path.resolve(__dirname, "../../.."))` and
       `path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..")`, core's
       `Path(__file__).resolve().parents[3]`). Its uses are:
       - the base, through `realpathSync`, `normalize`, `str` or `Path`, as the first argument of a `join` or `resolve`
         whose other arguments are all plain string literals;
       - a name bound to it once, whose every use is such a join, or a Python alias step with only literals
         (`REPO / "scripts" / "ci-test-pg.sh"`), or an expression the Python evaluator above judges itself (a
         `sys.path` entry or a loader path).

       Any other use refuses: a non-literal join, `cwd=REPO`, a template or f-string the tokens cannot see, an export
       to other files, or a literal that is itself the root or above.
   - **A lockfile is read only when it can select less than FULL** (1.5.2, root's ruling c). Every lockfile kind
     (`plan.LOCKFILE_NAMES`) is metadata: its `link:../x` entries run nothing. So the scan skips a lockfile when, and only
     when, `plan.classify_paths` plans a change to it FULL under the config in use. That check is per path and per
     consumer, and `derive`'s report lists the skipped ones under `lockfiles_not_read`. A skipped lockfile is not a
     backstop mentioner either. A root lockfile is a builtin full trigger. A nested one is its package's dependency input
     (root's ruling): `plan.classify_paths` maps it to exactly its owning package, so it selects that package and its
     reverse dependents. A nested lockfile that maps to no package, or to several, plans FULL. An `inert_globs` glob
     never hides one. A nested lockfile that selects its package is read like any other file.
   - **A `".."` segment is a parent step everywhere** (round 3, B2). A chain anchored at the file's own directory is
     read in ANY position, not only as an import argument, and resolves like the path written out:
     `path.join(__dirname, "..", "..", "lib", "x.mjs")` and `path.resolve(here, "..", "scripts", "x.mjs")` in JS,
     `os.path.join(os.path.dirname(__file__), "..", "x")` and `Path(__file__).resolve().parents[2] / "x"` in Python.
     So a vitest `dir: path.join(__dirname, "..", "..")` reaches the root and refuses (F15).
   - **A relative template is a glob** (round 3, F03). `` new URL(`./w-${n}.mjs`, import.meta.url) `` in a reached
     file stands for every tracked file it can spell (`w-*.mjs`). A parent step after a substitution, or a template
     that spells no tracked file, refuses.
2. **The credit.** Per importing package, the transitive closure credits the package with every read the scan finds in
   each reached file. Cycles end. A file two packages reach credits both. The reader job keeps its own credit, so crediting
   an importer never takes a read away from the reader job (the limits of "never narrower" are under rule 5).
   - **A caller outside every package** (root's R4 of #33, fix 2, in spine's binding shape). Its computed imports are
     checked whether or not a package reaches it. A target it loads is keyed by the caller's own path, so every package
     that reaches the caller is credited with it. The caller also maps to its own selection unit: its reader
     directory's job, or `<unmapped>` when no reader directory holds it, which fails `check` (FULL). The report lists
     each one under `unowned_callers`, with its unit and the packages it reaches.
   - A `.md` file is prose: its edge is recorded and nothing is credited.
   - **A reached non-code file is credited, and its recorded routes are followed** (round 3, B1): its `../` paths and
     each `./` word that names a tracked path. A compose volume `"../scripts/w.mjs:/app/w.mjs"`, a tsconfig `files`,
     `extends` or `references`, a Makefile recipe `node ./w.mjs` and an HTML `<script src="./w.mjs">` are routes. Code
     (JS/TS, Python, shell) is read in full. A reached `.mdx`, `.astro`, `.vue` or `.svelte` file can import modules,
     and the scan does not parse it, so reaching one refuses (D5, N5).
   - **A reacher outside every package** (D5, N3; round 3, B3). Every file outside every package that has a route,
     code or not, `./` routes included, starts a closure of its own unit: its reader directory, whose job runs it, or
     `<unmapped>`. What it reaches is that unit's import, listed under `unit_imports` in the report. So
     `test/compose.yml` mounting `../lib/entry.mjs` runs in the test job, as `test/run.mjs` importing it would (F13b),
     and a repository-root `run-all.mjs` is `<unmapped>` like `misc/run-all.mjs` (F12).
3. **Fail closed.** A reached path under `always_reader_dirs` refuses. So does a reached CODE file the scan excludes,
   since its reads cannot be credited, and a symlink loop.
4. **Computed imports: refuse unless declared** (spine's D2). A module-loading call whose argument is not one plain
   literal, in a package file or in a reached file, refuses. The calls are `import(`, `require(`, `require.resolve(`,
   `import.meta.resolve(`, `module.require(`, `createRequire(...)(`, and a name bound to `createRequire(...)`. The
   exception is an `edge_scan.computed_imports` entry that declares it: `{"file", "expr", "reach"}`, where `expr` is the
   exact argument text with whitespace collapsed. `reach` is one of:
   - `"package"`: inside the importing package. It refuses for a file outside every package, where it names and
     credits nothing; the same `owner()` result decides this and the credit above;
   - `"external"`: npm or the standard library, by name;
   - `"fixture"`: a test temp directory;
   - a list of repo paths, each of which then becomes an edge.

   Whatever the reach says, the package a literal of the expression lands in is credited (`` import(`${source}/packages/shared/m.mjs`) ``
   declared `"external"` credits `shared`, the leading `./`, `/` and substitutions stripped as the floor strips them):
   the reach adds to the landing, never replaces it, as rule 8 reads the Python loaders (root's C1 of #84's second
   delta R4, 2026-11-12). A plain literal under a TypeScript cast (`import("redis" as string)`) is a literal.

   **Both declaration lists are a registry** (root's ruling on #33 round 3). Each `computed_imports` and
   `unresolved_names` entry also carries `reason`, non-empty text (for reach `"none"`: why the name never runs), and
   `review_by`, an ISO date at most 30 days after today (UTC). A reasonless, expired or more-distant entry refuses, so
   it fails toward FULL. A change to either list needs root's R4 record first, as the secret-scan registry does. A PR
   cannot use its own new entries anyway: the action runs `check` with the BASE copy of the config and manifests
   (`--config "$STATE/base/$CONFIG"`), which a test pins. **The floor**, refined in spine's pre-review, decides parent steps:
   - **An anchored, all-literal path is a literal import.** It is anchored when it starts at the file's own directory:
     `__dirname`, `import.meta.dirname`, or a name bound to `dirname(fileURLToPath(import.meta.url))`.
     `pathToFileURL(...).href` is unwrapped. Every component is literal, as in
     `require(path.resolve(__dirname, '..', 'dist', 'ssrf.js'))`. Such a path is resolved and mapped, with no
     declaration.
   - **A parent step inside the package is allowed, if declared.** Every parent step must sit in the LEADING literal
     prefix, before the first substitution or non-literal argument, and that prefix must resolve inside the importing
     package's own directory, as in `` import(`../dist/${m}`) ``. The declaration must say `reach: "package"`, and the
     reviewer owns the claim that the substituted part cannot step out.
   - **Any other parent step refuses**, even when declared. So does a literal naming a top-level directory outside every
     package where nothing anchors it. An escape has to be written as a literal path, which the scan maps. A parent step
     is a `..` anywhere in the argument, including after a chain's closing bracket
     (`path.join(__dirname, "lib") + "/../../x"`), or a word: `pardir`, `.parent`, `.parents`, or any `dirname(...)`
     except the file's own directory (`dirname(fileURLToPath(import.meta.url))`, `dirname(__filename)`), which is the
     anchor. So `dirname(dirname(__dirname))` steps up.
5. **Declared, then verified** (spine's D5). `check` fails:
   - on an imported path that no `extra_edges` glob maps to at least its importers;
   - on an imported path an `inert_globs` glob matches ("inert import"). `plan.classify_paths` applies `inert_globs`
     before `extra_edges`, so such a path would select nothing when it changes;
   - on a `computed_imports` or `unresolved_names` entry that matches no site;
   - **on a narrowed import** (D5, N3): a path a reader unit imports, where the REAL `plan.classify_paths` under its
     mapping does not run that unit's reader job. A path left unmapped plans FULL, which runs every job, so it never
     fails here. A path reached by an `<unmapped>` file (in no reader directory, so no declared job runs it) may not be
     mapped at all;
   - **NOT on an unattributed mention: that is the backstop, and its consequence is per path** (1.5.1; root's ruling
     on #33 round 3, and on the consequence, 2026-10-29). It is attack-independent and fails toward FULL. For every mapped
     path P outside every package, every OTHER tracked text file that names P's basename as a token, in any syntax and
     excluded directories included, must be either in a package P's mapping selects, or a file outside every package
     whose route to P the scan recorded. Being in a reader unit whose job runs is not enough, since a package may run
     that file (F10). The planner's own config is not a mention.

     A hit fails nothing. P joins `backstop_full` in the bound assessment, so `assessment_sha256` and the plan id bind
     it, and `plan.py` plans FULL for a change that touches P (an inert P included), exactly as for a full trigger.
     Every other path keeps its mapping. `check` prints each reason as `BACKSTOP <P> plans FULL: <why>`. One
     declaration still narrows P back out: map P to the mentioning package too. The mentions are counted over BASE and
     HEAD, so a reader the PR deletes still flags P. The planner config stays the BASE copy (the action's rule), and
     the base tree is data like the head: it can only add FULL paths, never remove one.
     - **The BASE pass is bounded.** A file the PR left alone reads the same at both ends, so only its deleted and
       modified files (`git diff --no-renames --diff-filter=DMT`, a rename being D+A) are read at the base.
       `edges.py base-paths` lists them as escaped sparse patterns. The action adds those to its sparse base checkout,
       and `check --base-revision <base> --base-repo <that checkout>` reads them there. A blobless candidate (vagaris
       checks out `filter: blob:none`) holds no base blobs.
     - **The subjects are the union of both trees**, which need no blobs. So a P the PR deletes or moves, named by a
       file the PR did not touch, is still a subject (root's condition).
     - **Nothing unread passes as unmentioned.** On git 2.50 `git grep` exits 1, its "no match" status, when it cannot
       read a blob, and prints `unable to read`; git 2.56 exits 128. Every grep of the scan refuses, typed, on either
       signal (any exit but 0 or 1), and so does a pass whose git call times out on both attempts ("reader scan timed out", 1.7.3). Each one
       plans FULL.

     The backstop catches a runner by any spelling that still names the file (`fork(join(__dirname, "w.mjs"))`,
     `node "${0%/*}/w.mjs"`, `Path(__file__).parent / "w.py"`, core's `parents[3] / "scripts" / "ci-test-pg.sh"`, a
     workflow step), and a basename collision goes FULL, the safe direction. One extended-regex `git grep` for the
     mapped extensions, then a token lookup, keeps it to a few seconds on vagary-core.

     Round 4 (root's R4 of round 3) widens what it checks, each fail-toward-FULL:
     - **B1, transitively.** P's subjects are P plus every file outside every package that reaches P by a recorded
       route, to a fixpoint (cycle-safe). Every subject's mentions are held to P's rule. So `tools/run.mjs`, which
       imports `./worker.mjs`, cannot hide package c's `execFileSync(..., ["tools/run.mjs"])`. A mention by another
       subject is attributed, since whatever runs that subject is checked in turn;
     - **B2, gitlinks.** A submodule path under a mapped glob is a subject, as `plan.classify_paths` maps it;
     - **B3, symlinks.** `git grep` reads regular files only. So each symlink's target text is read as a mention (a
       symlink inside package c that points at P names P), and a symlink outside every package is a route to its
       target (it starts its unit, and an alias of P becomes P's subject);
     - **B4, inert globs.** A path an `inert_globs` glob maps to nothing is backstopped too ("inert mention"). Its
       remedy is to narrow the glob or add the path to `full_globs`, which `plan.classify_paths` applies first;
     - **directories (T10b).** A runner that names only a directory runs what is beneath it, as in
       `node --test "$REPO_ROOT/tools/"`, a workflow's `pytest scripts/`, or a config's `tools/**`. So every directory
       that holds a subject is a subject too, written `tools/`. A token that ENDS at it, with a slash beside it, is a
       mention when it is one of:
       - resolved from the mentioning file's directory;
       - resolved from the root, for a file at the root or under `.github/`, whose steps run there;
       - named after a prefix the scan cannot resolve (`$X/`, `${X}/`, `$(...)/`, a leading `/`).

       A package's own `test/` resolves inside the package, so it is not a mention of a top-level `test/`. Neither is
       a bare word (`"scripts": {"test": ...}`, a workflow's `test:` job, "the tools" in prose).

       Three more things are not runners, so they make no directory mention (root's R4 of round 4, P2-P4, no regression
       from 60e9f78). Each is skipped only on positive evidence:
       - prose (`.md`, `.markdown`, `.rst`, `.adoc`), as in a README's "lives in src/". An `.mdx` is still read: it
         compiles to JS, and Storybook or Docusaurus collect it by glob (P4b). So is a `.txt`: a CMakeLists.txt builds,
         pytest's default `--doctest-glob` is `test*.txt`, and a list file can feed a runner (P6);
       - an ignore list (`.gitignore`, `.dockerignore`, `.gitleaksignore`), except a `!lib/` line, which re-includes
         (P7, P7b);
       - a `package.json`'s metadata fields (`files`, `directories`, `repository` and the other descriptive ones), so
         `"files": ["lib/"]` publishes and runs nothing. Every other field is read, since runner configs live there too
         (`"mocha": {"spec": "lib/"}`, `"jest": {"roots": [...]}`; P5, P5b). A manifest that does not parse, or is not
         an object, is read whole (P5c).

       A glob argument (`shellcheck scripts/*.sh`) does not end at the directory, so it is not a mention either.

   **The invariant: a path is mappable only when every route to it resolved** (root's delta R4 of #33). Any route the
   scan cannot resolve refuses or keeps the path FULL. That covers a name that resolves to nothing, an importing file it
   does not parse, a reacher outside every package (unless the mapping still runs its job), and a path at or above the
   root. So `check`'s mapping can only narrow FULL to a plan that still runs every importer the scan found.

   **What this does not claim.** "Never narrower" holds for the routes this scan reads, plus, through the backstop,
   for every runner that names the basename of the mapped file or of any of its subjects (a file, gitlink or symlink
   outside every package that reaches it by a recorded route). It does not hold for a runner that does neither: the
   residuals below. A path whose own `check` fails plans FULL. The census (`lanes/cli/scratch/import-attribution`)
   compares the real `plan.classify_paths` with an independent oracle for every imported path in vagary-core and
   vagaris; the oracle finds importers through quoted `./`/`../` strings, data-position names included, and through
   reacher units.

   A declared edge then selects the importers through `plan.classify_paths`, as any `extra_edges` glob does. An
   undeclared one leaves the changed path unmapped, so the plan is FULL. `derive`, `check --out-json` and the bound
   assessment carry `imports`: each imported path with its importers.

### Python `sys.path` entries (1.5.2)

Package Python code that puts a directory on `sys.path` imports from it by NAME, so no relative path names those
modules. vagary-core does this in 482 files: `os.path.join(os.path.dirname(__file__), "..", "app")`,
`str(Path(__file__).resolve().parents[1] / "app")`, a name bound to either, or `REPO / "scripts"`.

6. **Each entry is evaluated from the file's AST.** The evaluator understands:
   - `__file__`;
   - `dirname`, `abspath`, `realpath`, `normpath`, `str`, `Path`, `.resolve()` and `.absolute()`;
   - `.parent` and `.parents[N]`;
   - `os.path.join` and `/` with string constants;
   - names assigned exactly once.

   It reads `sys.path.insert(i, x)` with exactly two arguments, `.append(x)` and `.extend(xs)` with exactly one, `+=`,
   and an assignment to a slice or an index of `sys.path` (`sys.path[0:0] = [...]`). Each of these consumes the
   statement it read (rule 9). Any other use of `sys.path` is consumed by no rule and refuses: `p = sys.path`,
   `sys.path.remove(x)`, `sys.path = [...]`, `sys.path.insert(*args)`, `list.insert(sys.path, 0, x)` and
   `sys.path.__iadd__([x])`. Where the entry lands decides the effect:
   - **inside the package's own directory:** nothing;
   - **inside another package:** a dep, since the package imports by name from that package's directory;
   - **outside every package:** each module that any of the package's Python files imports by name, and that exists
     there, is an edge (rule 1), so its reads are credited (rule 2). An entry in a `conftest.py` serves every test, so
     the names come from the whole package.

   **Fail closed:**
   - an entry that cannot be evaluated refuses when its text holds a parent step, or names a scan root, a PACKAGE top
     (`packages` of `packages/shared`) or a top-level directory outside every package. A cwd-relative string literal
     like `"../../shared-sdks/py"` is one. Each quoted literal is read as written AND stripped of what may stand before
     its top-level name (`./`, `/`, a `{...}`, `{{...}}` or `${...}` substitution, a `%s` or `%(x)s` field, a bare
     `$VAR`, in any number), and the literals of the text with every `{...}` collapsed to `{}` are read too (a
     substitution holding quotes, `f"{d['root']}/packages/shared"`), so `"${X}/packages/shared"`, `"/packages/shared"`,
     `".//packages/shared"`, `"%s/packages/shared" % x`, `os.path.expandvars("$ROOT/packages/shared")` and a tracked
     top-level directory literally named `{tpl}` or `${tpl}` all refuse. Braces nest (`f"{d[f'{k}']}/packages/shared"`),
     a `%` field may carry flags, a width and a precision (`"%-10s/packages/shared" % x`), and `{os.sep}` reads as `/`.
     A name stands for the text of EVERY assignment and augmented assignment of it, recursively through the names
     those read: `p = f"{source}/packages/shared"; sys.path.insert(0, p)`, `base = f"{source}/packages"; p = base +
     "/shared"`, `p = source; p += "/packages/shared"`, a name assigned in two branches (both texts), and `p, q =
     f"{source}/packages/shared", 1` (each name its own element; unpacked from anything else, the whole right side).
     A name that a parameter of the enclosing function binds is not evaluated from a module-level assignment (its own
     name stays beside that assignment's text), so a bare parameter as the entry is the residual named below; a name in
     an argument default or a decorator (`def setup(LIB=LIB)`) is the enclosing scope's, not the parameter's, but it
     is read as the module's ONLY when its single binding in the whole file is one plain, unmutated module-level
     assignment (root's K2 of #84's third delta R4: the scan looks a name up in the file's assignments whatever their
     scope, so beside a module `(LIB := ...)`, a `for LIB in ...`, an import of `LIB` or a second assignment in a
     helper the default stays the parameter's, and the entry is its text, which refuses when that text names a parent
     step or a top);
   - a file reads only when every `sys.path` entry in it resolves by a read rule. A residual entry (named below) beside
     an entry that resolves refuses the whole file. A file whose entries are ALL residuals reads, and reads nothing for
     them. R6-2 removed the carve-out that also read a file whose only sites recorded no entry (a reassignment,
     `site.addsitedir`, an alias of `sys.path`): those forms refuse under rule 9;
   - a Python file the scan reads (rule 9 says which) that does not parse refuses: `unresolved (a Python file the scan
     must read does not parse: <path>: <error>)`.
7. **pytest's `pythonpath` is a `sys.path` entry**, added in spine's pre-review of 1.5.2.
   - It is read from the config pytest would read: the nearest directory walking up from the package that holds one of
     `pytest.ini` (it wins in its directory, even with no `[pytest]` section), `pyproject.toml`
     (`[tool.pytest.ini_options]`), `tox.ini` (`[pytest]`) or `setup.cfg` (`[tool:pytest]`).
   - Each entry is relative to that config's directory and is applied, as in rule 6, to every package that holds
     Python files.
   - A config that does not parse refuses. So does `pyproject.toml` pytest options on a Python without `tomllib`.
8. **Python's loaders.** These are the `require.resolve` analog, under rule 4.
   - **By name:** `importlib.import_module(x)`, `__import__(x)` and `runpy.run_module(x)`. A literal name is an import
     by name, resolved through the package's entries. A non-literal name needs a `computed_imports` declaration.
     Each such call is consumed (rule 9). A literal naming `sys`, `site`, `importlib`, `runpy` or `builtins`
     (`__import__("sys").path`, `import_module("sys")`) is not an import by name. It is that module, judged by rule 9,
     and it refuses in every form, `__import__("sys").argv` included.
   - **By path:** `importlib.util.spec_from_file_location(name, p)` (or `location=p`), `runpy.run_path(p)` and
     `exec(open(p).read())`. Each such call is consumed (rule 9). `importlib.util.module_from_spec(spec)` is consumed
     only over a spec whose path evaluated (rule 9, fix F1); any other call of it refuses. A
     loader call with no path argument (`run_path()`) refuses too. The path `p` is evaluated as in rule 6:
     - evaluated, it is a literal load, an edge with no declaration;
     - not evaluated, the floor judges its longest EVALUATED prefix:
       - a prefix inside the importing package (no parent step after it) is declarable, as `reach: "package"`;
       - a prefix inside ANOTHER package is declarable, and that package becomes a dep;
       - a prefix outside every package refuses even when declared;
       - with no evaluated prefix, text holding a parent step or naming a scan root or an outside top-level
         directory refuses even when declared; text whose literals (read as rule 6 reads them) land only INSIDE
         another package (`runpy.run_path(f"{source}/packages/shared/mod.py")`) is a load into that package, declared
         with the paths it loads, and refuses undeclared. The package each literal lands in is credited WHATEVER the
         declaration's reach says (`"external"`, `"fixture"`, `"package"` or a list: the reach adds to the landing,
         never replaces it, as an evaluated prefix inside another package credits that package), so a reach of
         `"external"` on such a site is not a way to read nothing. A literal into the caller's own package, or onto a
         package-free top, refuses even when declared. A caller OUTSIDE every package has no package to leave: its
         literals onto a package-free top (`tools/t.py`, its own `scripts/`) are the paths its reach declares, and a
         literal into a package is credited to the caller's unit all the same (`scripts/x.py` loading
         `f"{source}/packages/shared/m.py" if k else f"{source}/tools/t.py"` credits `shared`, root's B1 of #84's second
         delta R4). The literals are read THROUGH names, as rule 6 reads them: `p = f"{source}/packages/shared/m.py";
         runpy.run_path(p)`, declared as `p`, lands in `shared` (root's B2). A symlinked landing credits BOTH the
         package holding the link and the package its target is in (`packages/pk/link/m.py`, link -> `../shared`:
         `pk` and `shared`); a link into the caller's own package, onto a package-free top or out of the repository
         credits the holder alone (root's K1 of the third delta R4: the target's owner once replaced the holder's, so
         a link back into the caller's package read nothing).
       - **A name the argument reads that the scan cannot read refuses the site, declared or not** (root's K3 of the
         third delta R4). The scan reads a name through a plain assignment, an annotated one, a pairwise tuple
         (`p, q = f"...", 1`) and `+=`; a name bound by anything else has no text, so a declaration of the site would
         stand for a path nobody read. Those bindings: a walrus (`(p := f"{source}/packages/shared/m.py");
         run_path(p)`), a `for` or comprehension variable, a `with ... as`, an `except ... as`, a `match` capture, a
         parameter that carries a default (`def f(p=f"{S}/packages/shared/m.py"): run_path(p)`), a starred or nested
         unpacking (`*ps, = [...]`, `(p, q), r = ...`), a `def` or `class` name (`run_path(where(source))`: a call's
         return is not a path the scan reads), and an attribute assigned anywhere on the same base
         (`self.p = ...; run_path(self.p)`), read directly or through the assignments of the names it reads. An
         imported name has no binding here and no text, so it is not one of these (the declaration stands for it, as
         before); a bare parameter is the S08 residual. The same unreadable names are never evaluated for a `sys.path`
         entry either (a module `(LIB := ...)` beside a helper's local `LIB = ...` once evaluated the helper's).
       A `scripts` segment under an in-package prefix is that package's own subdirectory. pathlib's `with_name`,
       `with_suffix` and `joinpath` with literals evaluate, like `/` (vagary-core's evidence app vendors
       `Path(__file__).with_name("_qualification_contract")`).
   - The same holds in a reached Python file.
   - **A loop over a literal is literal names.** `for m[, x] in (<constants or tuples of constants>): import_module(m)`
     loads exactly those constants, and so does a comprehension over the same. The conditions:
     - the iterable is a literal, or a module-level name bound exactly once to one and never mutated;
     - the loop variable is not rebound in the body;
     - the argument is that variable itself (no f-string or concatenation).

     The names then resolve by name like any import, so they are not assumed external. An iterable from a call
     (`sorted(x)`, `.split()`) stays computed.
9. **A Python file reads only when every path-mutation capability in it is consumed** (R6-2 of #86, root's ruling of
   2026-11-12, fail closed by token; cli's R6 design, accepted by root at 16:44).
   - **Which files.** The scan parses every Python file holding one of these words: `sys`, `site`, `importlib`, `runpy`,
     `builtins`, `__builtins__`, `exec`, `eval`, `compile`, `__import__`, `import_module`, `run_module`, `run_path`,
     `spec_from_file_location`, `module_from_spec`, `SourceFileLoader`, `addsitedir`. It also parses every file holding
     `PYTHONPATH` anywhere. A word in a comment or a string is read and found clean, except `PYTHONPATH` in a string.
   - **Consumed.** Each branch of rules 6 and 8 that records an entry, a name or a site consumes the statement or call
     it read, with every node inside it. Nothing else consumes a node. The binding rules below judge each import.
   - **The kinds.** Each of these, outside a consumed node, is an occurrence:
     - **sys binding:** `import sys` under any alias, `from sys import ...` (any name, any alias, `*`),
       `__import__("sys")` and `import_module("sys")`. A name literally called `sys`, `site`, `importlib`, `runpy` or
       `builtins` imported from ANY module binds that module, as the imported name or as the alias (`from helpers
       import sys`, `from os import sys as s`). A `del` or a rebinding of a bound name is an occurrence too.
     - **sys path reach:** `.path`, `.modules`, `.meta_path`, `.path_hooks`, `.path_importer_cache` or any dunder on a
       sys expression (a sys-bound name, `__import__("sys")`, `os.sys`): `p = sys.path`, `sys.path.remove(x)`,
       `sys.modules["sys"].path`, `sys.__dict__`. The one exception is N1's membership test below.
     - **site:** `import site` under any alias, `from site import ...`, any use of a site-bound name, and `addsitedir`
       by any name or attribute. No rule reads them, so each one refuses.
     - **loader:** an import of `importlib`, `runpy` or `builtins` under any alias, or of any submodule of them; a use
       of a loader-bound name outside a consumed call (`importlib.util.find_spec("m")`, `importlib.reload(m)`); a
       loader call by attribute on anything (`x.module_from_spec(spec)`). Submodules count: `from importlib.metadata
       import version` binds a loader name, consumed only when every use is an N3 read below; bound and unused, it
       refuses.
     - **exec:** `exec`, `eval` or `compile` as a bare name (`exec("import x")`, `eval("1")`, `exec(__doc__)`), or as an
       attribute of a loader-bound name (`builtins.exec(s)`). `exec(open(p).read())` is consumed by rule 8.
       `re.compile(...)` is not an occurrence.
     - **environment:** a string constant holding `PYTHONPATH`: an environ key, a shell string, an `env=` mapping, a
       docstring.
     - **scope:** `globals()`, `locals()` or `vars()` with no argument, in a file that binds sys by an import.
   - **The sys binding rule** (root's decision (i); R6 design line 5). A sys binding is consumed when the name is used
     at least once and EVERY use is an attribute other than the five above and the dunders, or sits inside a consumed
     node. `import sys; sys.exit(main())` reads, and so do `sys.argv`, `sys.stderr` and `import sys as s; s.exit(0)`.
     A name that is aliased (`s = sys`), passed (`getattr(sys, "path")`, `vars(sys)`, `dir(sys)`, `setattr(sys, ...)`),
     subscripted, deleted or rebound refuses. `from sys import argv` is the attribute read itself: consumed when `argv`
     is used. `from sys import path` (any of the five, any alias) and `from sys import *` always refuse. Only a bound
     name has the rule: `__import__("sys").argv` refuses.
   - **A loader binding** is consumed when it is used at least once and every use sits inside a consumed call:
     `import importlib; importlib.import_module("json")` reads.
   - **The narrowings N1-N3** (root's ruling of 2026-11-12 21:32, on cli's measured census of core main 9cea8193:
     R6-2 refused 190 of 3,134 files). Each is a rule, none a hand exemption, and each has a twin that keeps refusing:
     - **N1:** `x in sys.path` and `x not in sys.path` read the list: the attribute is a comparator of an `in` /
       `not in` compare. A guarded insert, append or remove in the same file is judged on its own, so
       `if p not in sys.path: sys.path.insert(0, p)` reads by rule 6 and the twin with `sys.path.remove(x)` in the
       guarded block refuses. These stay refusals: `sys.path in y` in every file; `'m' in sys.modules` in every file
       except as the last operand in a test file where F3 applies; and the `__import__("sys")` binding form. Twins: `R6_N1_guard_not_in_insert_reads`; `R6_N1_guard_in_remove_refuses`,
       `R6_N1_left_operand_refuses`, `R6_N1_modules_membership_refuses`.
     - **N2:** a loader call with a LITERAL module name that the recording branch consumed (`__import__("json")`,
       `import_module("server")`, `run_module("m")`) is read through the chain that follows it (`.loads(x)`,
       `.app`): the literal is already this file's dependency edge. A non-literal first argument refuses as before.
       Twins: `R6_N2_dunder_import_literal_chain_reads`, `R6_N2_import_module_literal_attr_reads`;
       `R6_N2_dunder_import_nonliteral_chain_refuses`, `R6_N2_import_module_nonliteral_attr_refuses`.
     - **N3:** `importlib.metadata.version(...)` and `.files(...)` read installed metadata and are not loads.
       `importlib.resources.files(anchor)` and `read_text(anchor, ...)` import the anchor package: a literal anchor
       is recorded as a dependency edge (receiver-checked, so `Path("x").read_text("utf-8")` is never one) and read
       through its chain; a non-literal anchor refuses. `entry_points(...).load()` stays a loader and refuses.
       Twins: `R6_N3_resources_files_literal_reads`, `R6_N3_resources_read_text_literal_reads`,
       `R6_N3_metadata_version_reads`; `R6_N3_resources_files_nonliteral_refuses`,
       `R6_N3_resources_read_text_nonliteral_refuses`, `R6_N3_metadata_entry_points_load_refuses`.
   - **The fixes F1-F3** (root's S2 of 2026-11-14: the census of core main 9cea8193 refused 154 files, and its top
     three causes held 114 of them: `module_from_spec` 48, SCOPE 41, SYS-PATH-REACH 25). Each is a recording branch
     in `python_file_facts`, and each read has a twin in `test_edges_r6_2_fix_vectors.json` that keeps refusing:
     - **F1:** `module_from_spec(spec)` reads when `spec` is the `spec_from_file_location` call itself, or a name
       resolved outward from the scope the call evaluates in (a default, an annotation, a decorator or a base
       evaluates in the scope enclosing its def, lambda or class; a class scope is skipped from a function nested in
       it), to the first scope that binds the name. A call whose own scope is a class body, or a comprehension or
       generator directly in one, refuses: Python reads a name the class has not yet assigned from the module, and
       such a comprehension cannot see the class's names, which the reader does not model. It reads only when that
       scope is the call's own or the module's, every binding there is a plain assignment of a `spec_from_file_location` call, and every one
       of those calls has a path the reader evaluated inside the repository and no keyword but `location=`. That load
       is already the file's edge by rule 8. These refuse: a computed path or a path above the root; a closure, a
       lambda or a default over an enclosing function's `spec` (a parameter or any assignment there), even beside a
       good module-level `spec`; any other binding of the name in the resolved scope (a parameter, a second
       assignment of another value, a loop, an import, a `def`); `global` or `nonlocal` on it; a spec call with
       `loader=` (an inline `SourceFileLoader` the consumed call would hide), `submodule_search_locations=` or
       `**kwargs`; a `module_from_spec` call with keywords or a second argument. A named spec also refuses in a file
       that may rebind it behind the reader: one with a star import, or with any `globals()` / `vars()` / `locals()`
       call that is not a read (a load subscript, `.get` / `.keys` / `.items` / `.values`, a loop, an `in`, `sorted` /
       `list` / `len`). Every use of the name bound where the call's is must be the call's argument, an `is` /
       `is not` comparison or a truth test, `spec.loader.exec_module(...)`, `spec.loader` tested, or a read of
       `name`, `origin`, `parent`, `cached` or `has_location`; any other use refuses, among them an attribute
       store, `setattr` / `delattr`, an alias (`s = spec`), a call argument, `del`, `loader = spec.loader` and
       `cast(..., spec.loader)`. A file naming `__spec__`, `__loader__` or `__dict__` (an attribute, a name or a
       string) refuses F1 in both forms, since the module's `__spec__` is the same object. Twins `M1`-`M13`
       (closure `M4`, lambda `M5`, `loader=` `M6`, default `M7`, attribute store `M8`, class body `M9`, `globals()`
       write `M10`, star import `M11`, alias `M12`, `mod.__spec__` `M13`). Open limit: another module that imports
       this one may assign its `spec` (`tool.spec = ...`) before a function here runs; the reader judges one file
       and does not see that write.
     - **F2:** `globals()["n"]` (load) and `globals().get("n"[, d])` read a module-level name the file binds by `def`,
       `class` or a plain assignment, not a capability-bound name or a dunder. The test-runner loop over `globals()`
       (`for k in globals()`, `.keys()`, `for k, v in globals().items()`, under `sorted` / `list`) reads when every
       call of a looked-up value is a no-argument call under `if k.startswith("<prefix>")`, the prefix is a literal
       with no leading underscore that no capability-bound name starts with, and `v` is otherwise used only as
       `callable(v)`, `v.__name__` or `getattr(v, "__name__"[, d])`. These refuse: a computed key; a write or a `del`
       at any key (`globals()["n"] = v`, `del globals()["n"]`, `monkeypatch.setitem(globals(), ...)`); a
       comprehension over `.items()`; `.values()` gated on a runtime `__name__`; `globals()` passed out; either loop
       form in a file with any star import (it may bring in any name the prefix admits); a gated call inside a
       lambda, a nested def or class, or a generator expression in the loop (it runs later, with the loop's last
       value); `globals`, `sorted`, `list`, `callable` or `getattr` bound by the file (a `def`, an assignment, a
       parameter), which is then not the builtin. Twins `G1`-`G6` (write and `del` `G1`, star import `G5`, lambda
       `G6`). The census held no literal-key site; 38 of its 41 SCOPE sites are the loop.
     - **F3:** in a test file only. A test file is one `plan.is_test_file(path, [])` accepts (`test_*.py`, `*_test.py`,
       anything under `test/`, `tests/` or `__tests__/`; no config `test_globs`) AND that no non-test Python file may
       import (root's ruling (b) of 2026-11-14: a name alone is not enough). `code_imported_test_files` decides the
       second from the AST of every tracked non-test Python file: every identifier and every string or bytes literal
       word in it (an import's names on any line of a multi-line import, an attribute, a loop literal fed to
       `importlib.import_module`, a path). A test file's module word is its stem, or its directory's name for an
       `__init__.py`. A non-test file holding the word marks the file, and a marked file's own words mark further
       test files, to a fixed point. A file that does not parse counts every word of its text, and a test file whose
       name is no identifier is always marked. The check matches a word, not a resolved import, so it marks more
       files than Python would import. It misses only a name the source computes (`"test_" + "utils"`, which the
       loader rules refuse at the import) and an importer outside Python (a workflow's `python -m`, a packaging
       entry point). On core main 9cea8193, 754 Python files are test files by name and 193 of them are marked. In such a
       file these forms bind or name a module for the test's own process: `sys.modules[k] = v`, `del sys.modules[k]`,
       a discarded `sys.modules.pop(k[, d])`, `monkeypatch.setitem(sys.modules, "m", v)`,
       `monkeypatch.delitem(sys.modules, "m"[, ...])`, `"m" in sys.modules` (the last operand only) and
       `for m in sys.modules`. None is an import edge into the repository, and a later `import m` is judged as an
       import. `sys.modules["m"]` and `sys.modules.get("m"[, d])` record `m` as the file's dependency edge. `sys.path`
       on the right of `in`, `not in`, `==` or `!=`, on the left of `==` or `!=`, indexed (load) or under `len` /
       `list` / `tuple` is a read of the list. Insert and append are rule 6 as before. These refuse:
       - a bind (`sys.modules[k] = v`, `setitem`) in a file that names `__path__`, `__spec__`,
         `submodule_search_locations` or `__dict__` anywhere (an attribute, a name, a keyword, or a string such as
         `"pkg.__path__"`), or calls `setattr` with a computed name or `vars` with an argument, because a stub with a
         `__path__` sends `import m.sub` to a directory no edge names;
       - a bound value that is not a constant, `types.ModuleType(<literal>)`, a `Mock()` / `MagicMock()` with no
         `spec`, `spec_set`, `wraps`, positional or `**` argument, or a name every binding of which in this file is a
         plain assignment of one of those (another file may hand back a stub with a `__path__`);
       - `setitem` / `delitem` on any receiver but `monkeypatch`;
       - `sys.path in y`, and `sys.modules` as a left operand;
       - a key naming `sys`, `site`, `importlib`, `runpy` or `builtins`, and a computed key on a read;
       - a use chained past the access (`sys.path[0].endswith(x)`, `sys.modules["m"].x`), `sys.modules.items()`,
         `.update(...)` and `p = sys.path`;
       - `len`, `list` or `tuple` bound by the file;
       - every one of these forms in a non-test file, a test file a non-test file may import, or a file the caller
         passes no `test_only` for.
       Twins `S1`-`S10` (`__path__` stub `S5`, `sys.path in y` `S6`, another receiver `S7`, `S8`:
       `services/b/test_utils.py` imported by `services/b/app.py`, `S9`: the same file named on a continuation line,
       in a parenthesised from-import and by a loop literal, `S10`: a stub another file builds).
   - **A dead import refuses** (root's decision (ii)). `import sys`, `import site`, `import importlib` or
     `from sys import argv`, bound and never used, is consumed by no rule.
   - **A local is not the module.** A bare `sys`, `site`, `importlib`, `runpy` or `builtins` the file never imports is
     the module all the same (a star import, an injection): `p = sys.path` with no import refuses. A file that binds
     the name itself (an assignment, a parameter, a `def`) holds a local, and its uses are not occurrences. An import of
     the name wins over a local binding, and the binding is then a rebinding, which refuses.
   - **One refuse point.** The last step of `python_file_facts` sorts the occurrences by line and column and refuses the
     file on the first: ``unresolved (the path-mutation capability `<segment>` on line <n> of <path> is consumed by no
     read rule; a file reads only when every one is) in <path>``. The segment is the occurrence's source, whitespace
     collapsed. A sys binding that fails its rule is an occurrence on its own import line, so a file that imports sys at
     the top and later reaches the path is named by its `import sys`, not by the reach.
   - **Every Python file the scan reads.** The refuse point holds for a package file, a file outside every package and a
     reached file: each is read through `python_file_facts`. A file with no occurrence has nothing to consume and reads
     as before.

Not closed (documented residuals). Each one names no basename the backstop matches, or names it only somewhere the
scan does not read. `test_edges_round4_vectors.json` pins root's round-4 instances (T5-T8b), T10g and T10h as the
drops they are:
- a mention that differs only in case (`tools/Worker.mjs` for `tools/worker.mjs`): the token match is exact;
- a Python module path (`from tools.worker import f`, `python -m tools.worker`): a dotted name is not a basename;
- a text file `.gitattributes` marks binary, and a basename inside a real binary file: `git grep -I` skips both;
- a file in an encoding other than ASCII-compatible (UTF-16 with or without a BOM): its bytes never spell the token;
- a directory or glob resolved against a root set elsewhere at runtime: vitest `dir: process.env.REPO_ROOT` with
  `include: ["tools/**/*.test.mjs"]` (T10g) reads `tools/` relative to its own package. A bare relative directory in a
  file below the root whose steps run from the root (`node --test tools/` in `scripts/run.sh`) has the same gap;
- a directory named as a bare word (`cd tools && node --test`, T10h): a mention needs a slash beside the name, so a
  bare `test` in a manifest or a workflow is not one;
- a mention by STEM only: an import by module NAME into a directory outside every package (Python `sys.path` plus
  `import x`, a tsconfig `paths` alias, a bundler alias), or an extensionless specifier in a position no rule reads.
  Python `sys.path` escapes are closed by rules 6-9 above, except the residuals below;
- a name built at runtime that never spells the basename: concatenated pieces, or a manifest's computed entries (a
  manifest that lists the file by name is a mention, so the backstop catches it);
- a glob in a non-code file (`include: ["**/*.mjs"]` in a config the scan does not parse), and a basename inside a
  binary file;
- a `./` word in a non-code file that names nothing tracked (a container path such as `./app`): it starts no route;
- an unanchored `".."` chain (`join(base, "..", "x")` with a computed base): not resolved, and the backstop still
  needs the basename;
- an unresolved `sys.path` entry that names no parent step and no top-level directory (`os.getcwd()`, an environment
  variable, or a bare parameter of the enclosing function, `def prepare(p): sys.path.insert(0, p)`: `R84_S08`, a dated
  residual, review by 2026-12-10);
- a module re-exported under another name (root's decision (i) of R6, a named residual): `from helpers import s`,
  where `helpers` binds `s` to `sys`, then `s.path.remove(x)`. The scan reads one file, and `s` is not literally `sys`,
  so the file reads and the removal is unseen. `from helpers import sys` and `from helpers import s as sys` are sys
  bindings (rule 9);
- the N1-N3 boundaries (root's ruling of 2026-11-12 21:32, rule 9): `importlib.metadata.version(...)` and
  `.files(...)` read installed metadata the scan does not see, so they add no edge (N3); a literal N2 / N3 name is an
  edge only where the scan resolves the name, like any import by name; an N1 membership test is a read of the list,
  and what the file does with the answer is judged only through the statements it guards;
- a `sys.path` entry or pytest config inside a reached file outside every package: its loaders and its capabilities
  (rule 9) are checked there, but a recorded entry is not applied;
- `PYTHONPATH` set in a workflow step's `env:` or inline on a `run:` line: workflows are not scanned (`.github` is a
  default exclude). In a Python file the scan reads, a `PYTHONPATH` string refuses (rule 9);
- a data-driven read (code that reads a manifest, then the paths in it);
- Python dotted and relative imports in a reached file (`from .x import y`, `import a.b`): only a same-directory
  `import x` / `from x import` is followed;
- a shell `source "$VAR/x"`: a substituted prefix is not resolved;
- a chain across reader directories (`tools/a.mjs` loads `scripts/b.mjs`, which reads a package): each file's reads
  are credited to its own reader directory, not to the directory of the file that reaches it.

`test_edges_round3_vectors.json` holds root's round-3 vectors of #33: 25 that dropped a true runner (B1-B4, L1 from
vagary-core's exact lines, F08, F09) and 7 correct-plan controls. Each is run end to end by root's method:
- commit, then run the real `check --revision`;
- apply check's own remedies until rc 0;
- judge the change with the real `plan.classify_paths` and `rule_matches`.

Each is pinned exact: it refuses, plans FULL, or selects its runner, and each control selects exactly its jobs.

`test_edges_152_rulings_vectors.json` holds 27 vectors for 1.5.2's root-climb rulings, run by the same method:
- A1-A7d: names above the checkout, an ancestor of it among them;
- B1-B11: root bases and root declarations;
- C1-C6: lockfiles and the nested-lockfile ruling.

`test_edges_review_vectors.json` holds 555 adversarial readers:
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
  - R7T16, R7T19 and R7T20 refuse and pin the working-directory wording; R7T17 and R7T18 are named residuals;
- 9 for round 8: the seventh review's R7B1a-R7B1d and R7V14, and R8T01-R8T04 (the working-directory wording's
  edges: R7B1b, R7B1d, R8T01 and R8T04 refuse; R7B1a, R7B1c, R8T02 and R8T03 are named residuals; R7V14 reads);
- 2 for the 64-level nesting bound: R8T05 (100 deep) refuses on every Python, R8T06 (exactly 64) reads.
- 1 for 1.5.2: R6V29b keeps R6V29's rule-7 precision (a `..` with no working-directory change reads) outside a
  `sys.path` entry, because R6V29 itself now refuses under rule 6 (its entry `os.path.join(HERE, "..")` cannot be
  evaluated and holds a parent step).

Each one reads its truth or refuses, except the named residuals. Each residual records `reads`, its reading when
pinned, and the suite asserts it exactly, so a residual that reads less (or more) fails until the pin is re-derived:
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
    it: a parameter of the calling function, or another function's local (R7T17, R7T18);
  - a working directory set through a string or substitution of a tainted name (`os.chdir(f"{d}")`), or through a
    quoted JS `"cwd"` or `'cwd'` key (R7B1a, R7B1c, R8T02, R8T03).
- **A YAML key used as a path** (R5V17, R6V02, R6V03): rule 4 makes a `.yml`/`.yaml` key metadata.
- **R84_S08, review by 2026-12-10** (root's K1 of #84's R4, 2026-11-12): a `sys.path` entry that is a bare parameter
  of the enclosing function (`p = "harmless"` at module level, `def prepare(p): sys.path.insert(0, p)`) names no
  parent step and no top-level directory, so it reads nothing against a truth of `[shared]`; the module-level
  assignment no longer stands for it (rule 6), the bare name is the documented residual above. **R84_B11** (root's K3
  of the third delta R4) is the loader-site twin: `def g(p): runpy.run_path(p)` called as
  `g(f"{source}/packages/shared/m.py")` reads nothing, the call-site argument is not read; same review date.
- **Dated residuals of #84's third delta R4, review by 2026-11-14** (root's N2 and N3; their vectors ride the r5
  reader PR, not this one, and each reads `[]` on main and on every head of #84; none is a regression):
  - N2, JS: a template whose literal lands in a package through a name (`const p = \`${source}/packages/shared/m.mjs\`;
    import(p)`), two leading substitutions (`` `${a}${b}/packages/shared/m.mjs` ``), a substitution under the
    package-holding top (`` `${source}/packages/${name}/m.mjs` ``) and a partial package name
    (`` `${source}/packages/shar${rest}` ``) read `[]` where the Python twins refuse or credit the landing;
  - N3: a caller outside every package whose literal lands on a package-free top (`tools/t.py`) that itself loads a
    package reads `[]` unless its reach names that path (`A6`/`A6b`); the reached file's own loads are not followed.
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

## Test inventory (1.7.0, S6)

A narrowed plan skips the jobs a change does not select. Before 1.7.0 nothing checked that every test file still ran
in SOME job a change to its owner selects, so a test missing from the configuration could silently disappear from
every narrowed plan. 1.7.0 makes the config declare which packages' test files each unit (a job or a matrix entry)
executes, and checks that declaration against the candidate's own test files.

```json
{
  "jobs": {"policy": "always", "e2e": {"packages": ["@v/ui"]}},
  "test_jobs": {"e2e": ["@v/ui"], "policy": ["path:scripts/**"]},
  "matrices": {"general_tests": [
    {"include": {"group": "server"}, "rule": "full_only", "tests": "*"},
    {"include": {"group": "workspaces"}, "rule": {"packages": ["@v/ui", "@v/cli"]}, "tests": ["@v/ui", "@v/cli"]}
  ]},
  "test_globs": ["**/*.check.ts"]
}
```

- **Declaration.**
  - `test_jobs` maps a job to `"*"` or to a list; a matrix entry carries the same value as `tests`.
  - A list holds package names and `path:<glob>` entries. A path entry covers test files outside every package.
  - A path entry is allowed only on a unit whose rule is `always`, because such a file cannot be tied to an affected
    package, so its unit must run on every narrowed plan.
- **Inventory.**
  - The candidate commit's tracked test files, read from its tree: `git ls-tree` in the scope root at the candidate,
    never the trusted-base checkout.
  - A test file is `*.test.*`, `*.spec.*`, `test_*.py`, `*_test.py`, `*_test.go`, or code (js/ts family, Python, Go) under
    `__tests__/`, `test/` or `tests/`, outside any `node_modules/` path segment. This is the union of the consumers'
    runner gates (vagaris check-test-collection-parity, core check_orphan_test_files.py). `test_globs` may add to these
    conventions, never remove from them.
- **Coverage.**
  - A test-owning package is covered when some unit declares it (or `"*"`) and the unit's rule selects the package's
    reverse closure. `full_only` never counts.
  - Selection rules are monotone in the affected set, so such a unit runs on every plan that affects the package.
  - A package whose change reaches a hub is covered by the full plan it always gets.
  - A test file outside every package is covered by an `always` unit whose `"*"` or `path:` entry matches it.
- **Verdicts.**
  - With a declaration, any uncovered package or file is an error (the step fails) on EVERY event, so a gap is never a
    silently smaller suite. So is:
    - a declaration naming an unknown job or package;
    - a path entry on a unit a narrowed plan can skip;
    - a test file inside a package that matches `inert_globs`, because a change to it would be classified inert and
      select nothing.
  - With no declaration, the plan is FULL with the reason `no test_jobs declaration`.
  - An unreadable inventory, or an empty one while a declaration exists, is FULL (refused as unproven). These guards
    read the candidate's tree with the BASE's `test_globs` only (1.7.1), so a glob a change adds cannot fill them.
- **Record.** `plan.test_inventory = {schema, files, digest, packages: {P: {files, covered_by}}, unowned: {files,
  uncovered}, gaps}` is bound into `plan_id`.
- **Not claimed.** The planner cannot see which files a unit really executes. That binding is the consumer's runner
  gate: vagaris `check-test-collection-parity`, core `check_orphan_test_files.py`. A unit declared `"*"` or a `path:`
  entry that its job does not collect must be refused there. This check closes the config hole; those gates close the
  runner hole.
- **Adoption.**
  - A consumer moving its pin to 1.7.0 gets FULL plans until it declares. A declaration must be complete from its first
    commit.
  - **Matrix gating precondition.** A matrix entry's `tests` count as coverage whenever the entry's rule selects it. The
    planner cannot see whether the consumer's workflow actually runs the matrix's PARENT job. So the consumer must run
    the parent job whenever any of its entries is included (vagaris builds its matrix from the plan, so it qualifies). A
    parent job gated by something else makes the entry's coverage claim untrue.
  - **Declaring in the same change (1.7.1).** Whether a change is red is decided by its OWN declaration (see Liveness
    below), so a change can add a package, its tests and its declaration together, or fix its own gap. The BASE still
    decides narrowing (a change cannot widen its own coverage), so such a change plans FULL rather than narrowed:
    - first tests for a package the base does not cover are covered by the change's own declaration, and the base's
      inventory has a gap, so the plan is FULL;
    - a test file in a package directory the base's graph does not know is outside every package there, so the base
      cannot narrow either.
    - The change after it narrows as usual, because its base now holds the declaration.
  - **Liveness: who decides RED (1.7.1, F29).** A gate that read its rules only from the base could wedge itself. A
    change that removed a declaration entry, or broke a selection rule, passed against the old base and landed, and
    then every change was red, including the fix (reproduced through `main()`, 2026-10-30; root's failure registry F29).
    Since 1.7.1:
    - the BASE config and graph still decide whether a plan may NARROW (F14: a change cannot widen its own selection);
    - the CANDIDATE's own config and workspace graph, read from its commit's git objects (the checkout can be sparse),
      decide whether the change is RED. Errors are:
      - a config that does not parse (a JSON typo, nesting too deep) or is not a JSON object;
      - a value of the wrong JSON type anywhere (a list where an object belongs, a string workspace), or an unknown
        workspace type. Each is a message, never a traceback. This includes the fields only selection reads
        (`full_globs`, `inert_globs`, `hub_packages`, `extra_edges`): a list `extra_edges` used to crash the next
        plan, and a string `hub_packages` was read as its characters, so the hub never matched;
      - invalid selection rules, an invalid declaration, or an inventory gap.
    - One rule reads both configs, so a malformed BASE config is the base's error with the same message, not a crash.
    - So a change that breaks the config is red BEFORE it lands, a syntax error included. A change that repairs a
      broken base plans FULL (its `config_check` names the base's errors) and can land. When the base config cannot be
      read at all, the FULL plan carries no job list, so the caller runs its complete roster. An unrelated change on a
      broken base stays red: only a repair lands. A change that adds a package, its tests and its declaration together
      is not red (the base cannot narrow it, so it plans FULL).
    - The candidate's config can only move a plan between RED and FULL, never narrower. A narrower candidate config
      (a dropped hub, a dropped rule) or graph (a dropped dependency edge) changes nothing about selection, at any
      config path, including one no full trigger matches.
    - A config at a schema other than 1 is refused the same way: RED as the candidate. As the base, a schema-1 repair
      plans FULL ("plan config schema N is not 1") and an unrelated change still at that schema stays red. Where the
      planner a change runs is the one its own workflow pins, a migration moves the pin and the schema in one change.
      Where the pin is held outside the change (core's ruleset-pinned services lane, NATIVE_WORKFLOW_PIN), the planner
      pin that reads the new schema lands first, and the schema follows.
    - The candidate's tree is listed name by name: a name that is not UTF-8 (`docs/caf\xe9.txt`) is kept as bytes, so it
      never makes the candidate unreadable, and a test file behind one is still inventoried (root's #57 RC2: one such
      name made the base decide, and an invalid rule landed and wedged main).
    - The candidate's config is read even when the SCOPE is unknown (a non-UTF-8 path in the diff, for one): it needs
      only the candidate commit, never the diff, and it moves the plan between RED and FULL only. So a typo landing
      beside such a path is red, and its repair lands with or without deleting the path.
    - The base decides both only when git cannot produce the candidate's config, or when the candidate's
      pnpm-workspace.yaml or a workspace manifest cannot be produced or does not parse. That is the tree's defect, not
      the config's: pnpm install refuses it in the change's own CI, so the planner does not judge it (a manifest edit is
      a builtin full trigger, so that change is FULL). Once it lands, the base's graph is unreadable and every plan is
      FULL until it is fixed.
    - Nothing of the candidate's own is validated when it has no config at that path (it removes it): a removal on a
      broken base plans FULL and can land.
    - The candidate's tree is read twice. With the BASE's `test_globs` for the base inventory and the narrowing guards;
      with both configs' `test_globs` for the candidate's RED check only (an extra glob only adds obligations). So a
      change that drops a glob is still bound by it: the files it matched need coverage in that change.
    - In the action, a reader check that fails on a broken base config forces FULL. It never stops the plan, so the
      candidate still decides RED.
    - `plan.config_check = {red_decided_by, base_errors, candidate_errors}` is bound into `plan_id`.
    - Each consumer's runner gate still validates the candidate's declaration in its own CI (root's prevention layer).

## Compatibility and validation

Legacy `mode`, `run` and `matrices` behavior is preserved. Disabling reader checks does not authorize narrower validation. Existing callers must explicitly adopt the new immutable version; changing this repository does not migrate their pins.

The existing public CI workflow runs planner regressions, asset-fetch controls and workflow lint. Existing GitHub-managed CodeQL remains separate. These results qualify the tested shared component; they do not prove a private consumer's coverage, merge safety or release readiness.

On the approved POSIX/Linux runner path, the optional provider witness executes its single GET in an owned Python worker. Windows selectors do not support these process pipes; failure remains UNKNOWN/FULL. The parent enforces the existing whole-request deadline across process startup, DNS, connect, TLS, status/headers and body, and kills/reaps the worker on timeout, output overflow or catchable interruption (at most one additional second for reaping). Request credentials travel only through a private stdin pipe, not argv or inherited GH_TOKEN/GITHUB_TOKEN; worker stderr and exception details are not logged. Response metadata and body are capped separately. This changes transport containment, not source-access authority or plan-selection permissions. Malformed non-string provider file statuses remain UNKNOWN/FULL rather than raising an uncaught type error.

Abrupt parent termination (including default SIGTERM/SIGKILL) is outside Python exception cleanup; the runner must own and reap the complete job process group. This transport does not install a process-global signal handler or claim standalone orphan recovery after abrupt parent death.
