#!/usr/bin/env bash
# Fetch exactly the history a secret scan needs, and say what to scan. Called by action.yml; README.md has the contract.
#
# WHY. The scanners were already scoped to the commits an event introduces, but the checkout before them fetched EVERY
# branch, tag and blob (fetch-depth: 0). On vagary-platform that was a 182 s p50 checkout for a 1 s scan, and
# secret-scan was 31% of the light runners' minutes (execnode, 2026-10-25). This fetches only the event's commits,
# blobless, then the blobs the scanned diffs read, in one round trip.
#
# RANGE mode. A range is used only when it is PROVEN complete: the merge-base of base and head resolves, and no shallow
# boundary commit lies inside base..head. A boundary inside the range would make a scanner read that commit's whole
# tree as added, and an unresolved merge-base would let commits slip past unscanned. The range is scanned as:
#   - each non-merge commit in base..head (its added lines);
#   - each two-parent MERGE in base..head, as a local "remerge delta" commit: the automatic merge of its parents
#     (git merge-tree --write-tree, conflict markers included) -> the merge as committed. Its added lines are what the
#     merge brought that neither parent did (a conflict resolution, an "evil merge"). Plain `git log -p` shows merges
#     with no diff at all, so without this a key typed into a conflict resolution is never read;
#   - the NET change merge-base(base, head)..head, as a local commit (head's tree on top of the merge-base), so anything
#     that reaches head is read whatever the history's shape.
# These local commits are never pushed. They are reached through refs/secret-scan/leg/* (and their automatic-merge
# parents are excluded through refs/secret-scan/auto/*), so `revs` stays a short, fixed-size string.
#
# FULL mode re-fetches head's complete history WITH blobs (head only, not every branch and tag) and adds a remerge
# delta for every two-parent merge in it. It is used for anything not provable as a range:
#   - a push with no usable `before` (a new branch, all zeros) or a `before` that is not an ancestor of `after`;
#   - a base that cannot be fetched, or a merge-base that does not resolve after deepening;
#   - schedule / workflow_dispatch (the daily full sweep), and any event this script does not know.
#
# FAIL CLOSED. Every git failure stops the step. A merge that git merge-tree cannot remerge (git older than 2.38, or an
# error) stops it too: no fallback both scanners can read exists (gitleaks 8.30.1 reads nothing from `--cc` output and
# mis-reads `--remerge-diff` paths as "b/<path>"). An octopus merge (3+ parents) has no remerge; it is logged, and in
# range mode the net change still covers it.
#
# Env: EVENT, PR_BASE, PR_HEAD, MG_BASE, MG_HEAD, PUSH_BEFORE, PUSH_AFTER (action.yml maps them from the event).
# Knobs: SCOPE_INITIAL_DEPTH (50), SCOPE_DEEPEN (200), SCOPE_DEEPEN_ROUNDS (4), SCOPE_REMOTE (origin).
# Writes to $GITHUB_OUTPUT (else stdout): mode, head, base, merge_base, net, revs, tree_revs, reason.
set -euo pipefail

ZERO=0000000000000000000000000000000000000000
DEPTH=${SCOPE_INITIAL_DEPTH:-50}
DEEPEN=${SCOPE_DEEPEN:-200}
ROUNDS=${SCOPE_DEEPEN_ROUNDS:-4}
REMOTE=${SCOPE_REMOTE:-origin}
NS=refs/secret-scan
LEGS="--glob=$NS/leg/* --not --glob=$NS/auto/*"
out=${GITHUB_OUTPUT:-/dev/stdout}

say() { echo "secret-scan scope: $*" >&2; }
die() { echo "::error::secret-scan scope: $*" >&2; exit 1; }
emit() { printf '%s\n' "$@" >> "$out"; }
is_sha() { [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]; }
shallow_file() { echo "$(git rev-parse --git-dir)/shallow"; }

fetch() { git fetch --quiet --no-tags --filter=blob:none "$@" "$REMOTE" "${want[@]}"; }

# A commit built locally for the scan, never pushed: a fixed identity and the source commit's date, so the same inputs
# give the same SHA in both scanner jobs. Usage: synth <tree> <unix-seconds> <subject> [-p <parent>]...
synth() {
  local tree=$1 ct=$2 msg=$3
  shift 3
  printf 'secret-scan: %s (local only, never pushed)\n' "$msg" |
    GIT_AUTHOR_NAME=secret-scan GIT_AUTHOR_EMAIL=secret-scan@localhost GIT_AUTHOR_DATE="@$ct +0000" \
      GIT_COMMITTER_NAME=secret-scan GIT_COMMITTER_EMAIL=secret-scan@localhost GIT_COMMITTER_DATE="@$ct +0000" \
      git commit-tree --no-gpg-sign "$tree" "$@"
}

# A remerge-delta commit for every two-parent merge that `git rev-list <args>` selects.
merge_legs() {
  local list m p1 p2 extra res rc tree ct auto delta updates="" n=0 oct=0
  list=$(git rev-list --min-parents=2 --parents "$@")
  while read -r m p1 p2 extra; do
    [ -n "$m" ] || continue
    if [ -n "$extra" ]; then
      oct=$((oct + 1))
      say "octopus merge $m has no remerge leg (git merge-tree takes two parents)"
      continue
    fi
    rc=0
    res=$(git merge-tree --write-tree --no-messages --allow-unrelated-histories "$p1" "$p2") || rc=$?
    tree=${res%%$'\n'*}
    { [ "$rc" -le 1 ] && is_sha "$tree"; } ||
      die "git merge-tree --write-tree failed (rc=$rc) for merge $m: remerging needs git >= 2.38 ($(git version)) and both parents' history"
    ct=$(git show -s --format=%ct "$m")
    auto=$(synth "$tree" "$ct" "automatic remerge of $m")
    delta=$(synth "$(git rev-parse "$m^{tree}")" "$ct" "remerge delta of merge $m" -p "$auto")
    updates+="update $NS/auto/$m $auto"$'\n'"update $NS/leg/$m $delta"$'\n'
    n=$((n + 1))
  done <<< "$list"
  [ -z "$updates" ] || printf '%s' "$updates" | git update-ref --stdin
  say "remerged $n merge(s)$([ "$oct" -eq 0 ] || echo "; $oct octopus merge(s) without a leg")"
  legs_note="$n merge(s) remerged$([ "$oct" -eq 0 ] || echo ", $oct octopus without a leg")"
}

# Fetch, in one round trip, every blob the scanned diffs read; else git fetches them commit by commit during the scan.
prefetch() {
  local oids
  oids=$(git log --raw --no-renames --no-abbrev --format= "$@" |
    awk '/^:/ { if ($1 != ":160000" && $3 !~ /^0+$/) print $3; if ($2 != "160000" && $4 !~ /^0+$/) print $4 }' | sort -u)
  [ -z "$oids" ] || printf '%s\n' "$oids" | fetch_ids
}

# Fetch objects by id (stdin), as git's own lazy fetch does: with no "have" negotiation, else the remote omits any
# object reachable from a commit we hold, wanted or not.
fetch_ids() { git -c fetch.negotiationAlgorithm=noop fetch --quiet --no-tags --no-write-fetch-head --stdin "$REMOTE"; }

full() {
  say "FULL history: $1"
  is_sha "${head:-}" || die "no head commit to scan"
  # Head's complete history (not every branch and tag) WITH blobs: a full sweep reads every commit's patch, and
  # trufflehog's git source clones the history, which a partial clone cannot serve. Unshallow (if shallow; the remote
  # still applies the checkout's blob filter), then fetch by id every blob still missing, in one request, and VERIFY.
  # A single `fetch --refetch --unshallow` was measured to leave blobs missing in a sparse checkout.
  if [ -f "$(shallow_file)" ]; then
    git fetch --quiet --no-tags --unshallow "$REMOTE" "$head"
  else
    git fetch --quiet --no-tags "$REMOTE" "$head"
  fi
  local missing
  missing=$(git rev-list --objects --missing=print "$head" | sed -n 's/^?//p')
  [ -z "$missing" ] || printf '%s\n' "$missing" | fetch_ids
  missing=$(git rev-list --objects --missing=print "$head" | grep -c '^?' || true)
  [ "$missing" = 0 ] || die "$missing object(s) reachable from $head are still missing after the full fetch"
  if [ -f "$(shallow_file)" ] && [ "$(git rev-list "$head" | grep -cxFf "$(shallow_file)" || true)" != 0 ]; then
    die "head $head still has a shallow boundary in its history after the full fetch"
  fi
  merge_legs "$head"
  emit "mode=full" "head=$head" "revs=$head $LEGS" "tree_revs=$LEGS" "reason=$1; $legs_note"
  exit 0
}

# Is base..head complete? The merge-base must resolve, and no shallow boundary commit may be in base..head.
# (grep -c reads all its input: `rev-list | grep -q` under pipefail can report SIGPIPE as "no match".)
proven() {
  git merge-base "$base" "$head" > /dev/null 2>&1 || return 1
  local sf list
  sf=$(shallow_file)
  [ -f "$sf" ] || return 0
  list=$(git rev-list "$base..$head") || return 1
  [ "$(printf '%s\n' "$list" | grep -cxFf "$sf" || true)" = 0 ]
}

# A workspace a self-hosted runner reuses may hold an earlier job's local commits; start from none.
git for-each-ref --format='delete %(refname)' "$NS/" | git update-ref --stdin

event=${EVENT:-}
base=""
head=""
case "$event" in
  pull_request | pull_request_target) base=${PR_BASE:-} head=${PR_HEAD:-} ;;
  merge_group) base=${MG_BASE:-} head=${MG_HEAD:-} ;;
  push) base=${PUSH_BEFORE:-} head=${PUSH_AFTER:-} ;;
  schedule | workflow_dispatch) head=${PUSH_AFTER:-$(git rev-parse HEAD)} && full "scheduled/dispatched full sweep ($event)" ;;
  *) head=${PUSH_AFTER:-$(git rev-parse HEAD)} && full "unknown event '${event}'" ;;
esac

is_sha "$head" || { head=$(git rev-parse HEAD) && full "no head commit in the event payload"; }
if [ "$event" = push ] && { [ -z "$base" ] || [ "$base" = "$ZERO" ]; }; then full "push with no 'before' (new branch)"; fi
is_sha "$base" || full "no base commit in the event payload"

want=("$head" "$base")
fetch --depth="$DEPTH" || full "the narrow fetch of $base and $head failed"
for _ in $(seq 1 "$ROUNDS"); do
  proven && break
  fetch --deepen="$DEEPEN" || break
done
if ! proven; then
  # One last, still-narrow attempt: full history of just these two commits.
  fetch --unshallow 2> /dev/null || true
  proven || full "range $base..$head not provable (merge-base unresolved)"
fi
if [ "$event" = push ] && ! git merge-base --is-ancestor "$base" "$head"; then
  full "push 'before' is not an ancestor of 'after' (force-push)"
fi

n=$(git rev-list --count "$base..$head")
mb=$(git merge-base "$base" "$head")
net=$(synth "$(git rev-parse "$head^{tree}")" "$(git show -s --format=%ct "$head")" "net change $mb..$head" -p "$mb")
git update-ref "$NS/leg/net" "$net"
# The event's commits and the net change read only objects the remote has. A merge leg's automatic-merge side holds
# blobs git merge-tree wrote locally (conflict markers), which no remote has, so the legs are left to lazy fetching.
prefetch "^$base" "$head" "$net"
merge_legs "^$base" "$head"
revs="^$base $head $LEGS"
say "RANGE ${base:0:12}..${head:0:12}: $n commit(s), proven (merge-base resolved, no shallow boundary inside); $legs_note; net change ${mb:0:12}..${head:0:12} as ${net:0:12}"
emit "mode=range" "base=$base" "head=$head" "merge_base=$mb" "net=$net" "revs=$revs" "tree_revs=$revs" \
  "reason=proven range of $n commit(s); $legs_note; net change $mb..$head"
