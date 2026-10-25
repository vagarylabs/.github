# secret-scan-scope

Fetches exactly the history a secret scan needs, after a blobless, depth-1, sparse checkout. It then says what to
scan: a proven **range** of the event's commits, or **full** history. Used by
[`secret-scan.yml`](../../.github/workflows/secret-scan.yml) for both gitleaks and trufflehog.

Why it exists: the scanners were already scoped to an event's commits, but the checkout in front of them fetched every
branch, tag and blob (`fetch-depth: 0`). On vagary-platform that was a 182 s p50 checkout for a 1 s gitleaks run.
Secret-scan was 31% of the light runners' minutes (execnode, 2026-10-25).

## Usage

Pin the action by **commit SHA**, never `@main`.

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  with:
    fetch-depth: 1
    filter: blob:none
    sparse-checkout: |
      /.gitleaks.toml
      /.gitleaksignore
    sparse-checkout-cone-mode: false
- id: scope
  uses: vagarylabs/.github/actions/secret-scan-scope@<40-char commit sha>
  with:
    tree: ${{ runner.temp }}/secret-scan-tree # optional: added lines as files, for a file scanner
- env:
    REVS: ${{ steps.scope.outputs.revs }}
  run: gitleaks git --log-opts="$REVS" .
```

The action reads the event itself (`github.event_name`, the pull_request and merge_group base/head SHAs,
`github.event.before`, `github.sha`). The checkout must keep its credentials (`persist-credentials` left at its
default), because the action and the scan fetch more objects from `origin`.

| Output | Meaning |
|---|---|
| `mode` | `range` or `full` |
| `head` | The commit whose history is scanned |
| `base`, `merge-base`, `net` | Range mode only: the event's base, `merge-base(base, head)`, and the local commit holding the net change |
| `revs` | What to scan, as `git log` revisions: `^<base> <head> <legs>` in range mode, `<head> <legs>` in full mode. `<legs>` is the fixed string `--glob=refs/secret-scan/leg/* --not --glob=refs/secret-scan/auto/*`. Space-separated; split it without shell globbing |
| `reason` | Why this mode, in words |
| `tree`, `tree-files` | The `tree` input directory and how many files it holds (when the input is set) |
| `dir` | This action's directory, for `diffscan.py` |

## What is scanned

**Range** applies to `pull_request`, `pull_request_target`, `merge_group`, and a fast-forward `push`. A range is used
only when it is **proven** complete: `merge-base(base, head)` resolves, and no shallow-boundary commit lies inside
`base..head`. The action fetches `base` and `head` blobless at depth 50, deepens up to 4 × 200 commits, then tries a
narrow `--unshallow` of just those two. A range that is still not proven becomes full. The scan then reads:

1. the added lines of each **non-merge commit** in `base..head`;
2. each two-parent **merge's remerge delta**, as a local commit. Its parent is the automatic merge of the merge's
   parents (`git merge-tree --write-tree`, conflict markers included), and its tree is the merge as committed. Its
   added lines are what the merge brought that neither parent did: a conflict resolution, or an "evil merge". Plain
   `git log -p` shows a merge with no diff at all;
3. the **net change** `merge-base..head`, as a local commit: head's tree on top of the merge-base, with real paths. It
   covers whatever reaches head, whatever the history's shape.

The local commits are never pushed. Their identity is fixed and their date is the source commit's, so both scanner
jobs build the same SHAs. They are reached through `refs/secret-scan/leg/*`. Their automatic-merge parents (root
commits) are excluded through `refs/secret-scan/auto/*`. One `git fetch` by object id then fetches every blob the
event's commits and the net change read. It uses no "have" negotiation, as git's own lazy fetch does; with
negotiation the server omits any blob reachable from a commit the client holds.

**Full** applies to `schedule` and `workflow_dispatch` (the daily sweep), a push of a new branch (`before` all
zeros), a force-push (`before` not an ancestor of `after`), a base that cannot be fetched, an unprovable range, and
any other event. It fetches head's whole history (head only, not every branch or tag), then every blob still missing,
by id, in one request. It then **verifies** that no object reachable from head is missing and that no shallow
boundary is in its history. It also builds a remerge delta for every two-parent merge in that history: measured at
about 38 ms a merge on vagary-core, whose 819 merges take about 30 s. A single `fetch --refetch --unshallow` was
measured to leave blobs missing in a sparse checkout, so the fetch is done in two steps.

## Blind spots

These are stated plainly, so nobody reads more coverage into a green check than there is:

- **Range mode does not scan binary files.** `git log -p` prints "Binary files differ" and no lines. The daily full
  sweep's trufflehog git source does read them: in the simulation it found a key inside a binary file. gitleaks never
  reads them, in either mode.
- **Removed lines are not scanned.** By design, a PR that deletes a secret does not fail.
- **History before the range is not scanned** in range mode. That is the daily full sweep's job.
- **An octopus merge (3+ parents) has no remerge delta**, because `git merge-tree` takes two parents. It is logged.
  In range mode the net change still covers what it left in head. In full mode, what such a merge introduced and a
  later commit removed is not read (vagary-core has one octopus merge; vagary-platform has none).
- **Detectors that need two values** (an AWS key id plus its secret) see only the added lines. If only one of the two
  was added, the pair is not in the scanned text.

## Fail closed

- Any git failure stops the step.
- A merge that `git merge-tree --write-tree` cannot remerge stops the step: either git is older than 2.38, or the
  merge failed. There is no fallback both scanners can read. gitleaks 8.30.1 reported nothing for an evil merge
  scanned with `--cc`. With `--remerge-diff` it found the key but reported the path as `b/conf.txt`, so path
  allowlists in `.gitleaks.toml` would no longer match.
- Full mode refuses to emit unless head's history is complete.

## diffscan.py

`diffscan.py` holds the helpers the scan steps run in the scanned repository. It is stdlib-only Python.

- `tree DIR REVS`: writes the added lines of `git log -p -U0 REVS` to `DIR/<label>/<path>`. Each line sits at its line
  number in the new file, with blank lines between, so a scanner's line number is the file's real line. `<label>` is
  the commit SHA. For a remerge delta it is the **merge's** SHA, and for the net change it is the net commit's SHA.
  It skips binary diffs, deletions and merges, and refuses unsafe paths.
- `count REVS`: how many commits gitleaks 8.30.1 reports as scanned for `--log-opts=REVS`. gitleaks counts a commit
  that has at least one text hunk in a file that is not deleted. On 1500 vagary-core commits this was measured at
  1069 against 1069. Empty, binary-only, mode-only, rename-only and deletion-only commits count 0, and so do merges.
- `gitleaks REPORT LOG RC N`: fails on any of these:
  - an exit code other than 0 or 1;
  - an `ERR` or `FTL` log line;
  - a "commits scanned" count other than `N`.

  This matters because gitleaks 8.30.1 exits **0** when its own `git log` fails, logging "0 commits scanned". The
  helper prints each finding as rule, commit, path and line.
- `trufflehog TREE`: reads `trufflehog --json` results and prints detector, commit, path and line. It fails on any
  finding and on any line it cannot parse, and never echoes that line.
- `trufflehog-log LOG MIN`: fails on any of these:
  - an `error` record;
  - a stderr line that is not JSON;
  - no `finished scanning` record;
  - fewer than `MIN` chunks.

  This matters because trufflehog 3.97.0 exits **0** on a directory that does not exist.

No finding is ever printed with its value: the `Raw`, `RawV2`, `Redacted`, `Secret`, `Match` and `Line` fields are
never read out. A finding on a remerge delta names the **merge**. A finding on the net commit reads "net change
`<merge-base>..<head>`".

`.gitleaksignore` entries are `commit:file:rule:line` fingerprints, which a local commit's SHA cannot match. To ignore
a finding the net change repeats, use the commit-less form `file:rule:line`. gitleaks 8.30.1 honours it (verified).

## Tests

`test_scope.sh` is hermetic and needs only git ≥ 2.38 and python3; it runs in CI as `secret-scan-scope-tests`. It
builds a local bare origin with merge-heavy history: an evil merge, an octopus, a binary, a dotfile, a path with a
space, and deletions. It simulates the checkout above: blobless, depth 1, non-cone sparse, detached at the PR's merge
ref. It then runs `scope.sh` per event and asserts:

- the mode;
- that the local `base..head` is **exactly** the origin's commit set;
- that no shallow boundary lies inside the range;
- the remerge legs, which must equal git's own `--remerge-diff`, also from depth 1;
- the net leg;
- the tree's paths and line numbers;
- in full mode, a complete history.

It also checks that the findings helpers never print a value. Set `SCOPE_SH=<path>` to run another `scope.sh`; this
is how negative controls run. Set `KEEP_SUITE=1` to keep the temporary tree.
