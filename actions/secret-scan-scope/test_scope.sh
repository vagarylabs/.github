#!/usr/bin/env bash
# Tests for scope.sh and diffscan.py. Hermetic and scanner-free: git (>= 2.38) and python3 only, no network.
# Builds a local bare origin with merge-heavy history (an evil merge, an octopus, a binary, a dotfile, a path with a
# space, deletions), simulates the workflow's checkout (blobless, depth 1, non-cone sparse, detached at the event's
# ref), runs scope.sh per event and asserts: the mode; that the local base..head is EXACTLY the origin's commit set;
# no shallow boundary inside the range; the remerge and net legs; the added-lines tree (paths, line numbers, what is
# absent); in full mode that head's history is complete (no missing object, no shallow boundary). Then the findings
# filters: they name commit, path and line, and never print a value.
# Run: bash actions/secret-scan-scope/test_scope.sh   (SCOPE_SH=<path> runs another scope.sh, for negative controls)
# shellcheck disable=SC2016,SC2059 # checks pass code for deferred expansion; put() takes a printf format
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scope=${SCOPE_SH:-$here/scope.sh}
diffscan="$here/diffscan.py"

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
  git -C "$r" sparse-checkout set --no-cone '/.gitleaks.toml' '/.gitleaksignore'
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

# ── RANGE: merge_group, push (fast-forward, with a merge) ─────────────────────────────────────────────────────────
runner mg "refs/heads/gh-readonly-queue/main/pr-1-$mp" merge_group "$mp" "$mq"
check "merge_group: mode=range" [ "$(out mg mode)" = range ]
check "merge_group: exact commit set" same_set mg "$mp" "$mq"
check "merge_group: legs for the queue merge and the evil merge" eval 'leg mg "$mq" && leg mg "$m1"'
check "merge_group: count (the clean queue merge adds no text)" [ "$(count mg)" = 8 ]
tree mg
check "merge_group: a clean merge's delta is empty" test ! -e "$suite/mg.tree/$mq"
check "merge_group: the evil merge is still named" at_line mg "$m1/conf.txt" 5 MARKER-EVIL

runner push "$mp" push "$m43" "$mp"
check "push: mode=range" [ "$(out push mode)" = range ]
check "push: exact commit set" same_set push "$m43" "$mp"
check "push: the pushed merge has a leg" leg push "$mp"
check "push: count" [ "$(count push)" = 4 ]

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
full_case() { # full_case <runner> <description> <head>
  check "$2: mode=full" [ "$(out "$1" mode)" = full ]
  check "$2: head output" [ "$(out "$1" head)" = "$3" ]
  check "$2: head's history is complete (no missing object, no shallow boundary)" complete "$1" "$3"
}
runner sched "$mp" schedule "" "$mp"
full_case sched "schedule" "$mp"
check "schedule: the old evil merge has a leg" leg sched "$e0"
check "schedule: the fixture's octopus has three parents" [ "$(git -C "$o" rev-list --no-walk --parents "$oct" | wc -w | tr -d ' ')" = 4 ]
check "schedule: the octopus merge has none, and says so" \
  sh -c '! git -C "$1" rev-parse -q --verify "refs/secret-scan/leg/$2" >/dev/null && grep -q octopus "$3"' _ "$suite/sched" "$oct" "$suite/sched.out"
check "schedule: revs = head plus the legs" [ "$(out sched revs)" = "$mp --glob=refs/secret-scan/leg/* --not --glob=refs/secret-scan/auto/*" ]
tree sched
check "schedule: the tree holds only the merge legs; the old evil merge is named" at_line sched "$e0/conf.txt" 3 MARKER-EVIL-OLD
check "schedule: no ordinary commit in the full tree" test ! -e "$suite/sched.tree/$f1"
runner linear "$o1" schedule "" "$o1"
full_case linear "schedule on a linear history (no merge, so no leg)" "$o1"
check "linear history: no leg refs" [ -z "$(rg linear for-each-ref refs/secret-scan/)" ]
tree linear
check "linear history: the legs-only tree is empty, not a fallback to HEAD" [ "$(cat "$suite/linear.files")" = 0 ]
check "linear history: gitleaks count covers both commits" [ "$(count linear)" = 2 ]
runner disp "$mp" workflow_dispatch "" "$mp"
full_case disp "workflow_dispatch" "$mp"
runner unknown "$mp" release "" "$mp"
full_case unknown "unknown event" "$mp"
runner newbr "$f8" push 0000000000000000000000000000000000000000 "$f8"
full_case newbr "push of a new branch" "$f8"
runner force "$f8" push "$z1" "$f8"
full_case force "force-push" "$f8"
check "force-push: the reason says so" grep -q 'force-push' "$suite/force.out"
runner unrel refs/pull/1/merge pull_request "$u" "$f8"
full_case unrel "unrelated base" "$f8"
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

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
