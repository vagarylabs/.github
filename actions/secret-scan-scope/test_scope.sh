#!/usr/bin/env bash
# Tests for scope.sh and diffscan.py. Hermetic and scanner-free: git (>= 2.38) and python3 only, no network.
# Builds a local bare origin with merge-heavy history (an evil merge, an octopus, a binary, a dotfile, a path with a
# space, deletions), simulates the workflow's checkout (blobless, depth 1, non-cone sparse, detached at the event's
# ref), runs scope.sh per event and asserts: the mode; that the local base..head is EXACTLY the origin's commit set;
# no shallow boundary inside the range; the remerge and net legs; the added-lines tree (paths, line numbers, what is
# absent); in full mode that head's history is complete (no missing object, no shallow boundary). Then the findings
# filters: they name commit, path and line, and never print a value. Then the accepted-live registry: its validation,
# review_by expiry, and the sweep and gate policies for both scanners, on fake values generated at run time; no value
# or digest may appear in any output.
# Run: bash actions/secret-scan-scope/test_scope.sh   (SCOPE_SH=<path> runs another scope.sh, DIFFSCAN=<path> another
# diffscan.py: how negative controls run)
# shellcheck disable=SC2016,SC2059 # checks pass code for deferred expansion; put() takes a printf format
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scope=${SCOPE_SH:-$here/scope.sh}
diffscan=${DIFFSCAN:-$here/diffscan.py}

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
check() { # check <description> <command...>
  local d=$1
  shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}

suite=$(mktemp -d "${TMPDIR:-/tmp}/secret-scan-scope-test.XXXXXX")
trap 'if [ -n "${KEEP_SUITE:-}" ]; then echo "kept $suite"; else rm -rf "$suite"; fi' EXIT # KEEP_SUITE=1 to debug
# No user or system git config (signing, hooks, aliases) may reach the test.
export HOME="$suite/home" XDG_CONFIG_HOME="$suite/home/.config" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git config --global init.defaultBranch main
git config --global advice.detachedHead false

# ── the origin ────────────────────────────────────────────────────────────────────────────────────────────────────
w="$suite/work"
git init -q "$w"
g() { git -C "$w" "$@"; }
commit() { g add -A && g commit -q -m "$1" && g rev-parse HEAD; }
put() { printf "$2" > "$w/$1"; } # put <path> <printf format>
mainline() { # mainline <from> <to>: one commit per number, appending to main.txt
  local i
  for i in $(seq "$1" "$2"); do echo "$i" >> "$w/main.txt" && g add main.txt && g commit -q -m "main $i"; done
}

put conf.txt 'line1\nline2\nline3\nline4\nline5\n'
put old.txt 'keep\nMARKER-OLD\n'
put .gitleaks.toml '# test config\n'
mkdir -p "$w/.github"
put .github/secret-scan-registry.json '{"version": 1, "entries": []}\n' # the caller's registry, on disk via sparse checkout
put main.txt '0\n'
commit "main 0" > /dev/null
g checkout -q -b old
put conf.txt 'line1\nline2-old\nline3\nline4\nline5\n'
o1=$(commit "old: line2") # a linear history: no merge at all
g checkout -q main
put conf.txt 'line1\nline2-main\nline3\nline4\nline5\n'
commit "main: line2" > /dev/null
g merge -q old > /dev/null 2>&1 || true
put conf.txt 'line1\nline2-resolved\nMARKER-EVIL-OLD\nline3\nline4\nline5\n'
e0=$(commit "Merge old (evil resolution)")
for x in x1 x2; do g checkout -q -b "$x" "$e0" && put "$x.txt" "$x\n" && commit "$x" > /dev/null; done
g checkout -q main
mainline 1 1 # main moves on, so the octopus keeps all three parents
g merge -q --no-edit x1 x2 > /dev/null
oct=$(g rev-parse HEAD)
mainline 2 20
g checkout -q -b abandoned HEAD~10
put z.txt 'z\n'
z1=$(commit "abandoned") # a 'before' that is not an ancestor of the PR head: the force-push case
g checkout -q -b feat main
put a.cfg '# header\n\nMARKER-A\n'
f1=$(commit "feat 1: a.cfg")
put .env 'MARKER-DOTENV\n'
printf 'MARKER-BINARY\000\001\002' > "$w/bin.dat"
f2=$(commit "feat 2: .env + binary")
put conf.txt 'line1\nline2-resolved\nMARKER-EVIL-OLD\nline3-feat\nline4\nline5\n'
f3=$(commit "feat 3: conf")
put 'path with space.txt' 'MARKER-SPACE\n'
put 'café.txt' 'MARKER-QUOTED\n' # git C-quotes this path in diff headers
f4=$(commit "feat 4: a path with a space, a quoted path")
put transient.txt 'MARKER-TRANSIENT\n'
f5=$(commit "feat 5: transient")
g rm -q transient.txt
commit "feat 6: drop transient" > /dev/null
g rm -q old.txt
commit "feat 7: drop old.txt" > /dev/null
g checkout -q main
mainline 21 29
put conf.txt 'line1\nline2-resolved\nMARKER-EVIL-OLD\nline3-main\nline4\nline5\n'
commit "main 30: conf" > /dev/null
mainline 31 40
g checkout -q feat
g merge -q main > /dev/null 2>&1 || true
put conf.txt 'line1\nline2-resolved\nMARKER-EVIL-OLD\nline3-resolved\nMARKER-EVIL\nline4\nline5\n'
m1=$(commit "Merge main into feat (evil resolution)")
printf 'f8\n' >> "$w/a.cfg"
f8=$(commit "feat 8")
g checkout -q main
mainline 41 45
m43=$(g rev-parse HEAD~2)
g checkout -q -b side "$(g rev-parse HEAD~4)"
put s.txt 's\n'
commit "side" > /dev/null
g checkout -q main
g merge -q --no-ff --no-edit side > /dev/null
mp=$(g rev-parse HEAD)
g checkout -q --detach "$mp"
g merge -q --no-ff --no-edit "$f8" > /dev/null
mq=$(g rev-parse HEAD) # the PR merge ref and the merge-queue commit: f8 merged onto main's tip
u=$(g commit-tree -m unrelated "$(printf '100644 blob %s\tu.txt\n' "$(printf 'u\n' | g hash-object -w --stdin)" | g mktree)")
o="$suite/origin.git"
git clone -q --bare "$w" "$o"
git -C "$o" config uploadpack.allowFilter true
git -C "$o" config uploadpack.allowAnySHA1InWant true
git -C "$o" update-ref refs/heads/feat "$f8"
git -C "$o" update-ref refs/pull/1/merge "$mq"
git -C "$o" update-ref "refs/heads/gh-readonly-queue/main/pr-1-$mp" "$mq"
git -C "$o" update-ref refs/heads/unrelated "$u"
git -C "$o" update-ref refs/heads/abandoned "$z1"

# ── a runner: the workflow's checkout, then scope.sh ────────────────────────────────────────────────────────────────
# runner <name> <ref to check out> <event> <base> <head> [VAR=value ...]
runner() {
  local name=$1 ref=$2 event=$3 base=$4 head=$5 r
  shift 5
  r="$suite/$name"
  git init -q "$r"
  git -C "$r" remote add origin "file://$o"
  git -C "$r" fetch -q --no-tags --depth=1 --filter=blob:none origin "+$ref:refs/remotes/checkout"
  git -C "$r" sparse-checkout set --no-cone '/.gitleaks.toml' '/.gitleaksignore' '/.github/secret-scan-registry.json'
  git -C "$r" checkout -q --detach refs/remotes/checkout
  : > "$r.out"
  if (cd "$r" && env "$@" EVENT="$event" PR_BASE="$base" PR_HEAD="$head" MG_BASE="$base" MG_HEAD="$head" \
    PUSH_BEFORE="$base" PUSH_AFTER="$head" GITHUB_OUTPUT="$r.out" bash "$scope") 2> "$r.err"; then
    echo 0 > "$r.rc"
  else
    echo $? > "$r.rc"
  fi
}
out() { sed -n "s/^$2=//p" "$suite/$1.out" | head -n 1; } # out <runner> <key>
rg() { git -C "$suite/$1" "${@:2}"; }                      # rg <runner> <git args...>
same_set() { # same_set <runner> <base> <head>: local base..head == the origin's
  [ "$(rg "$1" rev-list "$2..$3" | sort)" = "$(git -C "$o" rev-list "$2..$3" | sort)" ]
}
no_boundary_in() { # no_boundary_in <runner> <base> <head>
  local sf="$suite/$1/.git/shallow"
  [ ! -f "$sf" ] || [ "$(rg "$1" rev-list "$2..$3" | grep -cxFf "$sf" || true)" = 0 ]
}
complete() { # complete <runner> <head>: no missing object and no shallow boundary in head's history
  local sf="$suite/$1/.git/shallow"
  [ "$(rg "$1" rev-list --objects --missing=print "$2" | grep -c '^?' || true)" = 0 ] &&
    { [ ! -f "$sf" ] || [ "$(rg "$1" rev-list "$2" | grep -cxFf "$sf" || true)" = 0 ]; }
}
leg() { rg "$1" rev-parse -q --verify "refs/secret-scan/leg/$2" > /dev/null; }
tree() { (cd "$suite/$1" && python3 "$diffscan" tree "$suite/$1.tree" "$(out "$1" tree_revs)") > "$suite/$1.files"; }
at_line() { [ "$(sed -n "${3}p" "$suite/$1.tree/$2")" = "$4" ]; } # at_line <runner> <label/path> <n> <text>
nowhere() { ! grep -rqF -- "$2" "$suite/$1.tree"; }                 # nowhere <runner> <text>
count() { (cd "$suite/$1" && python3 "$diffscan" count "$(out "$1" revs)"); }
remerge_plus() { # the added lines git's own --remerge-diff shows for a merge, as "<path>\t<text>"
  git -C "$o" show --remerge-diff --format= -U0 --no-color "$1" | awk '
    /^\+\+\+ / { p = substr($0, 7); next } /^diff / { p = "" } /^\+./ && p != "" { print p "\t" substr($0, 2) }' | sort
}
tree_plus() { # the same, from the tree's <label>/ files
  (cd "$suite/$1.tree/$2" && find . -type f | sed 's|^\./||' | sort | while read -r f; do
    awk -v f="$f" '$0 != "" { print f "\t" $0 }' "$f"
  done) | sort
}

# ── RANGE: pull_request (base = main's tip, head = the PR head; checkout = the merge ref) ─────────────────────────
runner pr refs/pull/1/merge pull_request "$mp" "$f8"
check "pr: scope succeeds" [ "$(cat "$suite/pr.rc")" = 0 ]
check "pr: mode=range" [ "$(out pr mode)" = range ]
check "pr: base..head is exactly the origin's commit set" same_set pr "$mp" "$f8"
check "pr: no shallow boundary inside the range" no_boundary_in pr "$mp" "$f8"
check "pr: merge_base output = git merge-base" [ "$(out pr merge_base)" = "$(git -C "$o" merge-base "$mp" "$f8")" ]
check "pr: the evil merge has a remerge leg" leg pr "$m1"
check "pr: the leg's parent is a root commit holding the automatic merge" \
  [ "$(rg pr rev-list --count "refs/secret-scan/auto/$m1")" = 1 ]
check "pr: the leg's tree is the merge's tree" [ "$(rg pr rev-parse "refs/secret-scan/leg/$m1^{tree}")" = "$(rg pr rev-parse "$m1^{tree}")" ]
net=$(out pr net)
check "pr: net = head's tree on top of the merge-base" \
  eval '[ "$(rg pr rev-parse "$net^{tree}")" = "$(rg pr rev-parse "$f8^{tree}")" ] && [ "$(rg pr rev-parse "$net^")" = "$(out pr merge_base)" ]'
check "pr: net is a leg" [ "$(rg pr rev-parse refs/secret-scan/leg/net)" = "$net" ]
check "pr: revs is the fixed-size form" \
  [ "$(out pr revs)" = "^$mp $f8 --glob=refs/secret-scan/leg/* --not --glob=refs/secret-scan/auto/*" ]
check "pr: gitleaks-equivalent count = 6 commits + the merge's delta + net" [ "$(count pr)" = 8 ]
tree pr
check "pr: added lines at their line numbers (new file)" at_line pr "$f1/a.cfg" 3 MARKER-A
check "pr: a dotfile is materialised" at_line pr "$f2/.env" 1 MARKER-DOTENV
check "pr: a binary diff is skipped" nowhere pr MARKER-BINARY
check "pr: a modified line keeps its line number" at_line pr "$f3/conf.txt" 4 line3-feat
check "pr: a path with a space" at_line pr "$f4/path with space.txt" 1 MARKER-SPACE
check "pr: a C-quoted (non-ASCII) path" at_line pr "$f4/café.txt" 1 MARKER-QUOTED
check "pr: an added-then-removed line is in its own commit" at_line pr "$f5/transient.txt" 1 MARKER-TRANSIENT
check "pr: ... and not in the net change" test ! -e "$suite/pr.tree/$net/transient.txt"
check "pr: the evil merge's key is under the MERGE's SHA at its line" at_line pr "$m1/conf.txt" 5 MARKER-EVIL
check "pr: the merge leg = git's own --remerge-diff added lines" [ "$(tree_plus pr "$m1")" = "$(remerge_plus "$m1")" ]
check "pr: the net change carries the evil merge's key" at_line pr "$net/conf.txt" 5 MARKER-EVIL
check "pr: the net change carries every surviving added line" at_line pr "$net/a.cfg" 3 MARKER-A
check "pr: removed and pre-range lines are not scanned" nowhere pr MARKER-OLD
check "pr: an evil merge before the range is not in a range scan" nowhere pr MARKER-EVIL-OLD
check "pr: the tree counts its files" [ "$(cat "$suite/pr.files")" = "$(find "$suite/pr.tree" -type f | wc -l | tr -d ' ')" ]
check "pr: the checkout was sparse (config only)" eval '[ -f "$suite/pr/.gitleaks.toml" ] && [ ! -e "$suite/pr/conf.txt" ]'
check "pr: the caller's registry is in the sparse checkout" test -f "$suite/pr/.github/secret-scan-registry.json"
check "pr: registry_policy=gate (a range never lets the registry accept)" [ "$(out pr registry_policy)" = gate ]

# ── RANGE: merge_group, push (fast-forward, with a merge) ─────────────────────────────────────────────────────────
runner mg "refs/heads/gh-readonly-queue/main/pr-1-$mp" merge_group "$mp" "$mq"
check "merge_group: mode=range" [ "$(out mg mode)" = range ]
check "merge_group: exact commit set" same_set mg "$mp" "$mq"
check "merge_group: legs for the queue merge and the evil merge" eval 'leg mg "$mq" && leg mg "$m1"'
check "merge_group: count (the clean queue merge adds no text)" [ "$(count mg)" = 8 ]
tree mg
check "merge_group: a clean merge's delta is empty" test ! -e "$suite/mg.tree/$mq"
check "merge_group: the evil merge is still named" at_line mg "$m1/conf.txt" 5 MARKER-EVIL
check "merge_group: registry_policy=gate" [ "$(out mg registry_policy)" = gate ]

runner push "$mp" push "$m43" "$mp"
check "push: mode=range" [ "$(out push mode)" = range ]
check "push: exact commit set" same_set push "$m43" "$mp"
check "push: the pushed merge has a leg" leg push "$mp"
check "push: count" [ "$(count push)" = 4 ]
check "push: registry_policy=gate" [ "$(out push registry_policy)" = gate ]

# ── RANGE from depth 1: the boundary check must refuse ranges until history proves them ─────────────────────────────
runner pr-d1 refs/pull/1/merge pull_request "$mp" "$f8" SCOPE_INITIAL_DEPTH=1 SCOPE_DEEPEN=1
check "depth 1 (deepen 1, then unshallow): mode=range" [ "$(out pr-d1 mode)" = range ]
check "depth 1 (deepen 1, then unshallow): exact commit set" same_set pr-d1 "$mp" "$f8"
check "depth 1 (deepen 1, then unshallow): no boundary inside" no_boundary_in pr-d1 "$mp" "$f8"
runner pr-d1b refs/pull/1/merge pull_request "$mp" "$f8" SCOPE_INITIAL_DEPTH=1 SCOPE_DEEPEN=2 SCOPE_DEEPEN_ROUNDS=40
check "depth 1 (deepen 2 until proven): mode=range" [ "$(out pr-d1b mode)" = range ]
check "depth 1 (deepen 2 until proven): exact commit set" same_set pr-d1b "$mp" "$f8"
check "depth 1 (deepen 2 until proven): still shallow (deepening, not unshallow)" test -f "$suite/pr-d1b/.git/shallow"
tree pr-d1b
check "depth 1: the remerge leg is right with shallow history" [ "$(tree_plus pr-d1b "$m1")" = "$(remerge_plus "$m1")" ]

# ── FULL ────────────────────────────────────────────────────────────────────────────────────────────────────────
full_case() { # full_case <runner> <description> <head> [registry policy: gate unless given]
  check "$2: mode=full" [ "$(out "$1" mode)" = full ]
  check "$2: head output" [ "$(out "$1" head)" = "$3" ]
  check "$2: head's history is complete (no missing object, no shallow boundary)" complete "$1" "$3"
  check "$2: registry_policy=${4:-gate}" [ "$(out "$1" registry_policy)" = "${4:-gate}" ]
}
runner sched "$mp" schedule "" "$mp"
full_case sched "schedule" "$mp" sweep
check "schedule: the old evil merge has a leg" leg sched "$e0"
check "schedule: the fixture's octopus has three parents" [ "$(git -C "$o" rev-list --no-walk --parents "$oct" | wc -w | tr -d ' ')" = 4 ]
check "schedule: the octopus merge has none, and says so" \
  sh -c '! git -C "$1" rev-parse -q --verify "refs/secret-scan/leg/$2" >/dev/null && grep -q octopus "$3"' _ "$suite/sched" "$oct" "$suite/sched.out"
check "schedule: revs = head plus the legs" [ "$(out sched revs)" = "$mp --glob=refs/secret-scan/leg/* --not --glob=refs/secret-scan/auto/*" ]
tree sched
check "schedule: the tree holds only the merge legs; the old evil merge is named" at_line sched "$e0/conf.txt" 3 MARKER-EVIL-OLD
check "schedule: no ordinary commit in the full tree" test ! -e "$suite/sched.tree/$f1"
runner linear "$o1" schedule "" "$o1"
full_case linear "schedule on a linear history (no merge, so no leg)" "$o1" sweep
check "linear history: no leg refs" [ -z "$(rg linear for-each-ref refs/secret-scan/)" ]
tree linear
check "linear history: the legs-only tree is empty, not a fallback to HEAD" [ "$(cat "$suite/linear.files")" = 0 ]
check "linear history: gitleaks count covers both commits" [ "$(count linear)" = 2 ]
runner disp "$mp" workflow_dispatch "" "$mp"
full_case disp "workflow_dispatch" "$mp" sweep
runner unknown "$mp" release "" "$mp"
full_case unknown "unknown event" "$mp"
runner newbr "$f8" push 0000000000000000000000000000000000000000 "$f8"
full_case newbr "push of a new branch" "$f8"
runner force "$f8" push "$z1" "$f8"
full_case force "force-push" "$f8"
check "force-push: the reason says so" grep -q 'force-push' "$suite/force.out"
runner unrel refs/pull/1/merge pull_request "$u" "$f8"
full_case unrel "unrelated base (a PR falling back to full mode stays gate)" "$f8"
check "unrelated base: legs for both evil merges in head's history" eval 'leg unrel "$m1" && leg unrel "$e0"'
runner nobase refs/pull/1/merge pull_request 1111111111111111111111111111111111111111 "$f8"
full_case nobase "a base the origin does not have" "$f8"
check "every case exits 0" sh -c 'for f in "$1"/*.rc; do [ "$(cat "$f")" = 0 ] || exit 1; done' _ "$suite"

# ── diffscan.py: refusals ──────────────────────────────────────────────────────────────────────────────────────
rc_of() { set +e; "$@" > "$suite/last.out" 2>&1; echo $?; set -e; }
check "revs with a foreign token are refused (exit 2)" [ "$(cd "$suite/pr" && rc_of python3 "$diffscan" count "$f8 --all")" = 2 ]
check "a non-empty tree directory is refused" [ "$(cd "$suite/pr" && rc_of python3 "$diffscan" tree "$suite/pr.tree" "$f8")" = 2 ]

# ── diffscan.py: findings never print a value ──────────────────────────────────────────────────────────────────
S=SENTINEL-VALUE-must-not-print
th() { (cd "$suite/pr" && rc_of python3 "$diffscan" trufflehog "$suite/pr.tree" < "$1"); }
python3 - "$suite/pr.tree" "$f1" "$m1" "$S" > "$suite/th.json" <<'PY'
import json, os, sys
tree, f1, m1, s = sys.argv[1:]
for label, path, line in ((f1, "a.cfg", 3), (m1, "conf.txt", 5)):
    print(json.dumps({"DetectorName": "AWS", "Verified": True, "Raw": s, "RawV2": s, "Redacted": s,
                      "SourceMetadata": {"Data": {"Filesystem": {"file": os.path.join(tree, label, path), "line": line}}}}))
print(json.dumps({"DetectorName": "Github", "Verified": True, "Raw": s,
                  "SourceMetadata": {"Data": {"Git": {"commit": f1, "file": "a.cfg", "line": 3}}}}))
PY
check "trufflehog findings fail the step" [ "$(th "$suite/th.json")" = 1 ]
check "trufflehog: a tree finding names commit, path and line" grep -qF "commit $f1, path a.cfg, line 3" "$suite/last.out"
check "trufflehog: a merge-leg finding names the merge" grep -qF "merge $m1 (what it adds beyond the automatic merge), path conf.txt, line 5" "$suite/last.out"
check "trufflehog: a git-source finding names commit, path and line" grep -qF "trufflehog Github (verified): commit $f1, path a.cfg, line 3" "$suite/last.out"
check "trufflehog: no value printed" sh -c '! grep -qF "$1" "$2"' _ "$S" "$suite/last.out"
printf '%s\n' "not json $S" > "$suite/th-bad.json"
check "trufflehog: an unparseable line fails closed" [ "$(th "$suite/th-bad.json")" = 1 ]
check "trufflehog: ... and is not echoed" sh -c '! grep -qF "$1" "$2"' _ "$S" "$suite/last.out"
: > "$suite/th-empty.json"
check "trufflehog: no results passes" [ "$(th "$suite/th-empty.json")" = 0 ]
fin() { printf '{"level":"info-0","msg":"finished scanning","chunks":%s,"bytes":10}\n' "$1"; }
thlog() { printf '%s\n' "$1" > "$suite/th.log"; (cd "$suite/pr" && rc_of python3 "$diffscan" trufflehog-log "$suite/th.log" "$2"); }
check "trufflehog log: finished with chunks passes" [ "$(thlog "$(fin 3)" 1)" = 0 ]
check "trufflehog log: zero chunks when some were expected fails" [ "$(thlog "$(fin 0)" 1)" = 1 ]
check "trufflehog log: zero chunks on an empty tree passes" [ "$(thlog "$(fin 0)" 0)" = 0 ]
check "trufflehog log: no 'finished scanning' fails" [ "$(thlog '{"level":"info-0","msg":"running source"}' 0)" = 1 ]
check "trufflehog log: an error line fails" \
  [ "$(thlog "{\"level\":\"error\",\"msg\":\"error running scan\",\"error\":\"x $S\"}
$(fin 3)" 1)" = 1 ]
check "trufflehog log: ... and long tokens in it are masked" sh -c '! grep -qF "$1" "$2"' _ "$S" "$suite/last.out"
check "trufflehog log: a non-JSON stderr line fails" [ "$(thlog "panic: $S
$(fin 3)" 1)" = 1 ]

gl() { # gl <report json> <log text> <rc> <expected>
  printf '%s\n' "$1" > "$suite/gl.json"
  printf '%s\n' "$2" > "$suite/gl.log"
  (cd "$suite/pr" && rc_of python3 "$diffscan" gitleaks "$suite/gl.json" "$suite/gl.log" "$3" "$4")
}
leg_m1=$(rg pr rev-parse "refs/secret-scan/leg/$m1")
rep="[{\"RuleID\":\"aws-access-token\",\"Commit\":\"$leg_m1\",\"File\":\"conf.txt\",\"StartLine\":5,\"Secret\":\"$S\",\"Match\":\"$S\",\"Line\":\"$S\"},
{\"RuleID\":\"generic-api-key\",\"Commit\":\"$net\",\"File\":\"a.cfg\",\"StartLine\":3,\"Secret\":\"$S\"}]"
check "gitleaks: findings fail the step" [ "$(gl "$rep" '1:00PM INF 8 commits scanned.' 1 8)" = 1 ]
check "gitleaks: a finding on a remerge delta names the merge" grep -qF "merge $m1 (what it adds beyond the automatic merge), path conf.txt, line 5" "$suite/last.out"
check "gitleaks: a finding on the net commit names the net change" grep -qF "net change $(out pr merge_base | cut -c1-12)..$(echo "$f8" | cut -c1-12)" "$suite/last.out"
check "gitleaks: no value printed" sh -c '! grep -qF "$1" "$2"' _ "$S" "$suite/last.out"
check "gitleaks: clean and complete passes" [ "$(gl '[]' '1:00PM INF 8 commits scanned.' 0 8)" = 0 ]
check "gitleaks: a git failure (exit 0, error line, 0 scanned) fails" \
  [ "$(gl '[]' '1:00PM ERR [git] fatal: Invalid revision range
1:00PM INF 0 commits scanned.' 0 8)" = 1 ]
check "gitleaks: fewer commits scanned than selected fails" [ "$(gl '[]' '1:00PM INF 7 commits scanned.' 0 8)" = 1 ]
check "gitleaks: no summary line fails" [ "$(gl '[]' '1:00PM INF no leaks found' 0 8)" = 1 ]
check "gitleaks: an unexpected exit code fails" [ "$(gl '[]' '1:00PM INF 8 commits scanned.' 2 8)" = 1 ]

# ── the accepted-live registry ─────────────────────────────────────────────────────────────────────────────────
# Fake values, generated at run time (no credential-shaped literal lives in this file). forbidden.txt holds every value
# and its digest: none may appear in any output below.
R="$suite/reg"
mkdir -p "$R"
python3 - "$R" "$f1" <<'PY'
import datetime, hashlib, json, os, secrets, sys
R, f1 = sys.argv[1:]
V = {k: f"fixture-{k}-{secrets.token_hex(12)}" for k in ("accepted", "today", "v2only", "unregistered", "expired")}
d = lambda v: hashlib.sha256(v.encode()).hexdigest()[:20]
today = datetime.datetime.now(datetime.timezone.utc).date()
day = lambda n: (today + datetime.timedelta(days=n)).isoformat()
def entry(k, n, drop=(), **extra):
    e = {"rule": "generic-api-key", "sha256_20": d(V[k]), "status": "live-pending-rotation",
         "reason": f"fixture {k}", "ruling": f"test ruling for {k}", "review_by": day(n), **extra}
    return {f: x for f, x in e.items() if f not in drop}
def write(name, obj):
    with open(os.path.join(R, name), "w") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj, indent=1))
reg = lambda *entries: {"version": 1, "entries": list(entries)}
write("ok.json", {"version": 1, "about": "fixture", "entries": [
    entry("accepted", 30, renewal="re-reviewed monthly", seen_in=["a.cfg"]), entry("today", 0), entry("v2only", 30)]})
write("expired.json", reg(entry("accepted", 30), entry("expired", -1)))
write("empty.json", reg())
bad = {
    "not-json": "{not json", "top-list": [], "top-unknown": {"version": 1, "entries": [], "extra": 1},
    "version": {"version": 2, "entries": []}, "no-version": {"entries": []},
    "entries-not-list": {"version": 1, "entries": {}}, "entry-not-object": reg("x"),
    "entry-unknown-field": reg(entry("accepted", 30, comment="x")),
    "status-accepted": reg(entry("accepted", 30, status="accepted")),
    "no-status": reg(entry("accepted", 30, drop=("status",))),
    "no-reason": reg(entry("accepted", 30, drop=("reason",))), "blank-ruling": reg(entry("accepted", 30, ruling="  ")),
    "no-ruling": reg(entry("accepted", 30, drop=("ruling",))),
    "no-review-by": reg(entry("accepted", 30, drop=("review_by",))),
    "compact-date": reg(entry("accepted", 30, review_by=day(30).replace("-", ""))),
    "impossible-date": reg(entry("accepted", 30, review_by="2026-02-30")),
    "hash-upper": reg(entry("accepted", 30, sha256_20=d(V["accepted"]).upper())),
    "hash-short": reg(entry("accepted", 30, sha256_20=d(V["accepted"])[:19])),
    "no-hash": reg(entry("accepted", 30, drop=("sha256_20",))),
    "duplicate": reg(entry("accepted", 30), entry("accepted", 60, reason="again")),
    "seen-in-string": reg(entry("accepted", 30, seen_in="a.cfg")), "rule-empty": reg(entry("accepted", 30, rule="")),
}
for k, v in bad.items():
    write(f"bad-{k}.json", v)
with open(os.path.join(R, "bad.list"), "w") as f:
    f.write("\n".join(bad) + "\n")
with open(os.path.join(R, "forbidden.txt"), "w") as f:
    f.write("".join(f"{v}\n{d(v)}\n{d(v).upper()}\n" for v in V.values()))
for k, n in (("today", 0), ("yesterday", -1), ("plus30", 30)):
    write(k, day(n))
def gl(*finds):
    return [{"RuleID": "generic-api-key", "Commit": f1, "File": "a.cfg", "StartLine": n, "Secret": V.get(k, ""),
             "Match": f"key = {V.get(k, '')}", "Line": f"key = {V.get(k, '')}"} for k, n in finds]
write("gl-mixed.json", gl(("accepted", 3), ("unregistered", 4)))
write("gl-all-accepted.json", gl(("accepted", 3), ("today", 5)))
write("gl-accepted.json", gl(("accepted", 3)))
write("gl-expired.json", gl(("expired", 6)))
write("gl-no-value.json", gl(("none", 7)))
write("gl-empty.json", [])
write("gl-broken.json", "{broken")
def th(*finds):
    return "".join(json.dumps({"DetectorName": "AWS", "Verified": True, "Raw": raw, "RawV2": raw2,
                               "Redacted": raw or raw2, "SourceMetadata": {"Data": {"Git": {
                                   "commit": f1, "file": "a.cfg", "line": n}}}}) + "\n" for raw, raw2, n in finds)
write("th-accepted.json", th((V["accepted"], "", 3), ("", V["v2only"], 9)))
write("th-unregistered.json", th((V["unregistered"], "", 3)))
write("th-mixed.json", th((V["accepted"], "", 3), (V["unregistered"], "", 4)))
write("th-expired.json", th((V["expired"], "", 6)))
write("th-no-value.json", th(("", "", 7)))
PY
today=$(cat "$R/today") yesterday=$(cat "$R/yesterday") plus30=$(cat "$R/plus30")
: > "$suite/reg-all.out"
rec() { cat "$suite/last.out" >> "$suite/reg-all.out"; }
in_last() { grep -qxF -- "$1" "$suite/last.out"; } # in_last <exact line>
has() { grep -qF -- "$1" "$suite/last.out"; }      # has <text>
regc() { (cd "$suite/pr" && rc_of python3 "$diffscan" registry "$@"); rec; } # regc <file> <policy>
glr() { # glr <report fixture> <gitleaks rc> [--registry FILE --policy P]: the judge deletes the report
  local rep=$1 grc=$2
  shift 2
  cp "$R/$rep" "$R/report.json"
  printf '%s\n' '1:00PM INF 8 commits scanned.' > "$R/gl.log"
  (cd "$suite/pr" && rc_of python3 "$diffscan" gitleaks "$R/report.json" "$R/gl.log" "$grc" 8 "$@")
  rec
}
thr() { # thr <results fixture> [--registry FILE --policy P]
  local res=$1
  shift
  (cd "$suite/pr" && rc_of python3 "$diffscan" trufflehog "$suite/pr.tree" "$@" < "$R/$res")
  rec
}
gone() { [ ! -e "$R/report.json" ]; }
e0="registry entry #0 (rule generic-api-key, live-pending-rotation, review_by $plus30)"
at3="commit $f1, path a.cfg, line 3"

# The registry check (diffscan.py registry FILE sweep|gate), run once per scanner job when the caller has the file.
check "registry: a valid registry passes the sweep" [ "$(regc "$R/ok.json" sweep)" = 0 ]
check "registry: ... and the sweep lists EVERY entry as a warning" \
  [ "$(grep -c '^::warning title=accepted live credential::registry entry #' "$suite/last.out")" = 3 ]
check "registry: ... with its ruling and renewal note" \
  has "$e0, 30 day(s) left: ruling: test ruling for accepted; renewal: re-reviewed monthly"
check "registry: review_by is inclusive (due today = valid, 0 days left)" has "review_by $today), 0 day(s) left"
check "registry: the gate passes a valid registry" [ "$(regc "$R/ok.json" gate)" = 0 ]
check "registry: ... lists its entries as accepting nothing, with no warning" \
  eval 'has "accepts nothing in this scan" && ! grep -q "^::warning" "$suite/last.out"'
check "registry: an EXPIRED entry FAILS the sweep" [ "$(regc "$R/expired.json" sweep)" = 1 ]
check "registry: ... loudly: an error naming the entry, its review_by and the remedy" in_last \
  "::error title=secret-scan registry entry expired::registry entry #1 (rule generic-api-key, live-pending-rotation, review_by $yesterday) expired 1 day(s) ago. Renew review_by with a fresh ruling, or remove the entry. ruling: test ruling for expired"
check "registry: ... the live entry is still listed" has "::warning title=accepted live credential::$e0"
check "registry: an expired entry is a warning in the gate (the gate accepts nothing anyway)" \
  eval '[ "$(regc "$R/expired.json" gate)" = 0 ] && has "::warning title=secret-scan registry entry expired::registry entry #1"'
check "registry: an empty entries list is valid" [ "$(regc "$R/empty.json" sweep)" = 0 ]
while read -r b; do
  check "registry refused, sweep and gate: $b" eval '[ "$(regc "$R/bad-$b.json" sweep)" = 1 ] &&
    has "::error title=secret-scan registry refused::" && [ "$(regc "$R/bad-$b.json" gate)" = 1 ]'
done < "$R/bad.list"
check "registry refused: a duplicate names both entries" \
  eval 'regc "$R/bad-duplicate.json" sweep > /dev/null; has "entries #0 and #1 name the same value"'
check "registry refused: status accepted says where false positives go" \
  eval 'regc "$R/bad-status-accepted.json" sweep > /dev/null; has ".gitleaks.toml allowlist"'
ln -s ok.json "$R/link.json"
check "registry refused: a symbolic link" [ "$(regc "$R/link.json" sweep)" = 1 ]
check "registry refused: a file named but absent" [ "$(regc "$R/absent.json" sweep)" = 1 ]
check "registry: an unknown policy is a usage error" [ "$(regc "$R/ok.json" lenient)" = 2 ]

# gitleaks: values are hashed in-process from the (unredacted, sweep-only) report, which is then deleted.
check "gitleaks sweep: an accepted value and an unregistered one -> fail" \
  [ "$(glr gl-mixed.json 1 --registry "$R/ok.json" --policy sweep)" = 1 ]
check "gitleaks sweep: ... the accepted finding names its entry and is not an error" \
  in_last "gitleaks generic-api-key: $at3: accepted ($e0)"
check "gitleaks sweep: ... the unregistered one is an error: NOT in registry" \
  in_last "::error::gitleaks generic-api-key: commit $f1, path a.cfg, line 4: NOT in registry"
check "gitleaks sweep: ... the report is deleted" gone
check "gitleaks sweep: only accepted values (one due today) -> pass" \
  [ "$(glr gl-all-accepted.json 1 --registry "$R/ok.json" --policy sweep)" = 0 ]
check "gitleaks sweep: ... counted" in_last "gitleaks: 2 finding(s), 2 accepted by the registry; scanned 8 of 8 commit(s)"
check "gitleaks sweep: ... per entry" in_last "gitleaks: $e0 accepted 1 finding(s) in this scan"
check "gitleaks sweep: ... the report is deleted on a pass too" gone
check "gitleaks sweep: an EXPIRED entry's value fails, reported as expired" \
  eval '[ "$(glr gl-expired.json 1 --registry "$R/expired.json" --policy sweep)" = 1 ] && has "has EXPIRED"'
check "gitleaks sweep: a malformed registry accepts nothing" \
  eval '[ "$(glr gl-accepted.json 1 --registry "$R/bad-status-accepted.json" --policy sweep)" = 1 ] &&
    has "NOT accepted (the registry is unusable"'
check "gitleaks sweep: a finding with no value fails" \
  eval '[ "$(glr gl-no-value.json 1 --registry "$R/ok.json" --policy sweep)" = 1 ] && has "the scanner gave no value to match"'
check "gitleaks sweep: exit 0 with findings still fails (fail closed)" \
  [ "$(glr gl-all-accepted.json 0 --registry "$R/ok.json" --policy sweep)" = 1 ]
check "gitleaks sweep: an unreadable report fails" [ "$(glr gl-broken.json 1 --registry "$R/ok.json" --policy sweep)" = 1 ]
check "gitleaks sweep: ... and is deleted" gone
check "gitleaks sweep: a clean report passes" [ "$(glr gl-empty.json 0 --registry "$R/ok.json" --policy sweep)" = 0 ]
check "gitleaks GATE (range): a registered value FAILS" \
  [ "$(glr gl-accepted.json 1 --registry "$R/ok.json" --policy gate)" = 1 ]
check "gitleaks gate: ... printed exactly as with no registry" in_last "::error::gitleaks generic-api-key: $at3"
check "gitleaks: no registry is today's behaviour (fails, same line, same summary)" \
  eval '[ "$(glr gl-accepted.json 1)" = 1 ] && in_last "::error::gitleaks generic-api-key: $at3" &&
    in_last "gitleaks: 1 finding(s); scanned 8 of 8 commit(s)"'
check "gitleaks: --registry without --policy is a usage error" [ "$(glr gl-accepted.json 1 --registry "$R/ok.json")" = 2 ]

# trufflehog: Raw (else RawV2) hashed in-process.
check "trufflehog sweep: accepted values (Raw; RawV2 when Raw is empty) -> pass" \
  [ "$(thr th-accepted.json --registry "$R/ok.json" --policy sweep)" = 0 ]
check "trufflehog sweep: ... named as accepted" in_last "trufflehog AWS (verified): $at3: accepted ($e0)"
check "trufflehog sweep: ... the RawV2-only one too" has "line 9: accepted (registry entry #2"
check "trufflehog sweep: an UNREGISTERED verified finding goes RED" \
  [ "$(thr th-unregistered.json --registry "$R/ok.json" --policy sweep)" = 1 ]
check "trufflehog sweep: ... as an error: NOT in registry" in_last "::error::trufflehog AWS (verified): $at3: NOT in registry"
check "trufflehog sweep: accepted + unregistered -> red" [ "$(thr th-mixed.json --registry "$R/ok.json" --policy sweep)" = 1 ]
check "trufflehog sweep: an EXPIRED entry's value goes red, reported as expired" \
  eval '[ "$(thr th-expired.json --registry "$R/expired.json" --policy sweep)" = 1 ] && has "has EXPIRED"'
check "trufflehog sweep: no raw value -> red" [ "$(thr th-no-value.json --registry "$R/ok.json" --policy sweep)" = 1 ]
check "trufflehog sweep: a malformed registry -> red" \
  [ "$(thr th-accepted.json --registry "$R/bad-no-reason.json" --policy sweep)" = 1 ]
check "trufflehog GATE (range): a registered value FAILS (strict)" \
  [ "$(thr th-accepted.json --registry "$R/ok.json" --policy gate)" = 1 ]
check "trufflehog gate: ... printed exactly as with no registry" in_last "::error::trufflehog AWS (verified): $at3"
check "trufflehog: no registry is today's behaviour" eval '[ "$(thr th-accepted.json)" = 1 ] && in_last "trufflehog: 2 finding(s)"'

# No value and no digest anywhere; the grep's own positive control first.
cp "$suite/reg-all.out" "$suite/reg-planted.out"
sed -n 1p "$R/forbidden.txt" >> "$suite/reg-planted.out"
check "control: the forbidden-output grep catches a planted value" grep -qFf "$R/forbidden.txt" "$suite/reg-planted.out"
check "registry: the outputs were captured" [ "$(grep -c . "$suite/reg-all.out")" -gt 50 ]
check "registry: no fake value or digest in any output" sh -c '! grep -qFf "$1" "$2"' _ "$R/forbidden.txt" "$suite/reg-all.out"

# ── trufflehog sweep excludes + measure ───────────────────────────────────────────────────────────────────────────
X="$suite/excludes"
mkdir -p "$X"
xrun() { # xrun <name> <file contents (printf format)>: run `excludes` on that file; rc in $X/<name>.rc
  printf "$2" > "$X/$1.txt"
  set +e
  python3 "$diffscan" excludes "$X/$1.txt" "$X/$1.hist" "$X/$1.tree" > "$X/$1.out" 2>&1
  echo $? > "$X/$1.rc"
  set -e
}
xrun good '# inventoried captures\n^docs/news/F001/trace\\.har$\n^graphify-out/\n'
check "excludes: a valid file passes" [ "$(cat "$X/good.rc")" = 0 ]
check "excludes: the history file holds the patterns as written" \
  [ "$(cat "$X/good.hist")" = "$(printf '^docs/news/F001/trace\\.har$\n^graphify-out/')" ]
check "excludes: the tree file prefixes each pattern with the tree's <label>/" \
  [ "$(cat "$X/good.tree")" = "$(printf '(^|/)[0-9a-f]{40}/docs/news/F001/trace\\.har$\n(^|/)[0-9a-f]{40}/graphify-out/')" ]
check "excludes: it says the excludes apply to the sweep only" grep -q 'FULL sweep only' "$X/good.out"
xrun unanchored 'docs/news/F001/trace.har\n'
check "excludes: an unanchored pattern is refused" [ "$(cat "$X/unanchored.rc")" = 2 ]
xrun catchall '^.*\n'
check "excludes: a catch-all pattern is refused (it matches a generic path)" [ "$(cat "$X/catchall.rc")" = 2 ]
xrun generic '^src/\n'
check "excludes: a pattern matching a generic source path is refused" [ "$(cat "$X/generic.rc")" = 2 ]
xrun lookaround '^(?!src)docs/x$\n'
check "excludes: a lookaround (not RE2) is refused" [ "$(cat "$X/lookaround.rc")" = 2 ]
xrun empty '# only a comment\n\n'
check "excludes: a file with no pattern is refused" [ "$(cat "$X/empty.rc")" = 2 ]
ln -s "$X/good.txt" "$X/link.txt"
set +e
python3 "$diffscan" excludes "$X/link.txt" "$X/link.hist" "$X/link.tree" > /dev/null 2>&1
link_rc=$?
set -e
check "excludes: a symlinked file is refused" [ "$link_rc" = 2 ]
wf="$here/../../.github/workflows/secret-scan.yml"
check "workflow: excludes are applied only under the sweep policy" \
  grep -qF '[ "${POLICY:-gate}" = sweep ] && { [ -e "$excludes" ] || [ -L "$excludes" ]; }' "$wf"
check "workflow: the trufflehog job's sparse checkout carries the excludes file" \
  grep -qF '/.github/secret-scan-trufflehog-exclude.txt' "$wf"
set +e
python3 "$diffscan" measure "$X/usage" -- sh -c 'echo through; exit 3' > "$X/measure.out" 2>&1
measure_rc=$?
set -e
check "measure: exits with the command's status" [ "$measure_rc" = 3 ]
check "measure: passes the command's output through" grep -qx through "$X/measure.out"
check "measure: records peak RSS and wall time" grep -qE '^peak RSS [0-9]+ MB, wall [0-9]+ s$' "$X/usage"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
