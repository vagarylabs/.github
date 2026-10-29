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

## Reader scan (1.4.1; 1.5.0 adds imported files)

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
     file, so no mapping of it can be narrower than FULL.
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

   A plain literal under a TypeScript cast (`import("redis" as string)`) is a literal.

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
   - **on an unattributed mention: the backstop** (root's ruling on #33 round 3). It is attack-independent and fails
     toward FULL. For every mapped path P outside every package, every OTHER tracked text file that names P's basename
     as a token, in any syntax and excluded directories included, must be either in a package P's mapping selects, or
     a file outside every package whose route to P the scan recorded. Being in a reader unit whose job runs is not
     enough, since a package may run that file (F10). The planner's own config is not a mention. A failure names its
     remedy: map P to the mentioning package too, or add P to `full_globs` so a change to it plans FULL. It catches a
     runner by any spelling that still names the file (`fork(join(__dirname, "w.mjs"))`, `node "${0%/*}/w.mjs"`,
     `Path(__file__).parent / "w.py"`, core's `parents[3] / "scripts" / "ci-test-pg.sh"`, a workflow step), and a
     basename collision goes FULL, the safe direction. One extended-regex `git grep` for the mapped extensions, then a
     token lookup, keeps it to a few seconds on vagary-core.

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
  Python `sys.path` escapes are the next change;
- a name built at runtime that never spells the basename: concatenated pieces, or a manifest's computed entries (a
  manifest that lists the file by name is a mention, so the backstop catches it);
- a glob in a non-code file (`include: ["**/*.mjs"]` in a config the scan does not parse), and a basename inside a
  binary file;
- a `./` word in a non-code file that names nothing tracked (a container path such as `./app`): it starts no route;
- an unanchored `".."` chain (`join(base, "..", "x")` with a computed base): not resolved, and the backstop still
  needs the basename;
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

`test_edges_review_vectors.json` holds 554 adversarial readers:
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
