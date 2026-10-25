#!/usr/bin/env bash
# Local simulation of the accepted-live registry with the REAL pinned scanners (gitleaks 8.30.1, trufflehog 3.97.0)
# and the workflow's OWN step scripts, read out of .github/workflows/secret-scan.yml (needs python3 with PyYAML).
# Not run in CI: CI runs the hermetic test_scope.sh, which needs no scanner. This checks what those tests cannot: that
# the real binaries' output carries what diffscan.py hashes (gitleaks' unredacted Secret, trufflehog's Raw), that
# gitleaks run without --redact prints no value to its log, and that the steps wire it all up as intended.
#
# It builds local origins (with a live registry, an expired one, and none) holding a registered fake key in history,
# a branch adding an unregistered fake key, and a PR repeating the registered one; simulates the workflow's checkout
# (blobless, depth 1, sparse) and scope step per event; then runs the gitleaks and trufflehog step scripts with
# $RUNNER_TEMP/bin holding wrappers around the real binaries. trufflehog verifies only real providers, so its wrapper
# adds --config with a custom detector for the fake keys that "verifies" against a localhost endpoint answering 200:
# the results are Verified=true, as a live key's would be. Keys are generated at run time, prefixed "vlsim" (gitleaks
# ignores a generic-api-key value that contains a stopword such as "fake").
# Run: GITLEAKS=<gitleaks 8.30.1> TRUFFLEHOG=<trufflehog 3.97.0> bash actions/secret-scan-scope/simulate_registry.sh
# shellcheck disable=SC2016 # checks pass code for deferred expansion
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
workflow="$here/../../.github/workflows/secret-scan.yml"
GITLEAKS=$(command -v "${GITLEAKS:-gitleaks}") || { echo "set GITLEAKS to a gitleaks 8.30.1 binary" >&2; exit 2; }
TRUFFLEHOG=$(command -v "${TRUFFLEHOG:-trufflehog}") || { echo "set TRUFFLEHOG to a trufflehog 3.97.0 binary" >&2; exit 2; }
"$GITLEAKS" version | grep -qx 8.30.1 || { echo "needs gitleaks 8.30.1" >&2; exit 2; }
"$TRUFFLEHOG" --version 2>&1 | grep -q '3\.97\.0' || { echo "needs trufflehog 3.97.0" >&2; exit 2; }

pass=0
fail=0
check() { # check <description> <command...>
  local d=$1
  shift
  if "$@"; then pass=$((pass + 1)) && printf 'ok   %s\n' "$d"; else fail=$((fail + 1)) && printf 'FAIL %s\n' "$d"; fi
}

suite=$(mktemp -d "${TMPDIR:-/tmp}/secret-scan-sim.XXXXXX")
srv_pid=""
trap 'kill "$srv_pid" 2> /dev/null || true; if [ -n "${KEEP_SUITE:-}" ]; then echo "kept $suite"; else rm -rf "$suite"; fi' EXIT
export HOME="$suite/home" XDG_CONFIG_HOME="$suite/home/.config" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git config --global init.defaultBranch main
git config --global advice.detachedHead false

# ── the workflow's own step scripts ──────────────────────────────────────────────────────────────────────────────
python3 - "$workflow" "$suite" <<'PY'
import sys, yaml
wf, S = sys.argv[1:]
jobs = yaml.safe_load(open(wf))["jobs"]
for job in ("gitleaks", "trufflehog"):
    [step] = [s for s in jobs[job]["steps"] if s.get("id") == job]
    open(f"{S}/step-{job}.sh", "w").write(step["run"])
PY

# ── fake keys, registries, the trufflehog verifier ──────────────────────────────────────────────────────────────
python3 - "$suite" "$GITLEAKS" <<'PY'
import datetime, hashlib, json, os, secrets, string, subprocess, sys
S, gitleaks = sys.argv[1:]
a = string.ascii_letters + string.digits
def key():
    # gitleaks drops a generic-api-key value containing any of its stopwords; keep a candidate it actually flags.
    os.makedirs(f"{S}/keygen", exist_ok=True)
    for _ in range(50):
        k = "vlsim" + "".join(secrets.choice(a) for _ in range(30))
        open(f"{S}/keygen/c.cfg", "w").write(f'api_key = "{k}"\n')
        subprocess.run([gitleaks, "dir", f"{S}/keygen", "--no-banner", "--redact", "--report-format", "json",
                        "--report-path", f"{S}/keygen.json"], capture_output=True)
        if len(json.load(open(f"{S}/keygen.json"))) == 1:
            return k
    sys.exit("no candidate key that gitleaks flags")
keys = {"accepted": key(), "unregistered": key()}
d = lambda v: hashlib.sha256(v.encode()).hexdigest()[:20]
today = datetime.datetime.now(datetime.timezone.utc).date()
for name, v in keys.items():
    open(f"{S}/key-{name}", "w").write(v)
open(f"{S}/forbidden.txt", "w").write("".join(f"{v}\n{d(v)}\n" for v in keys.values()))
def registry(days):
    return json.dumps({"version": 1, "entries": [{
        "rule": "generic-api-key", "sha256_20": d(keys["accepted"]), "status": "live-pending-rotation",
        "reason": "simulation", "ruling": "simulation ruling",
        "review_by": (today + datetime.timedelta(days=days)).isoformat()}]}, indent=1) + "\n"
open(f"{S}/registry-live.json", "w").write(registry(30))
open(f"{S}/registry-expired.json", "w").write(registry(-1))
PY
acc=$(cat "$suite/key-accepted") new=$(cat "$suite/key-unregistered")

cat > "$suite/verifier.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
PY
python3 "$suite/verifier.py" "$suite/port" &
srv_pid=$!
for _ in $(seq 1 100); do [ -s "$suite/port" ] && break; sleep 0.1; done
cat > "$suite/th.yaml" << EOF
detectors:
  - name: SimLiveKey
    keywords: [vlsim]
    regex:
      key: 'vlsim[A-Za-z0-9]{30}'
    verify:
      - endpoint: http://127.0.0.1:$(cat "$suite/port")/verify
        unsafe: true
EOF

# ── origins: main holds the registered key in history; `more` adds an unregistered key; `pr` repeats the registered ──
mk_origin() { # mk_origin <name> <registry file or ''>
  local w="$suite/$1.work" o="$suite/$1.git"
  git init -q "$w"
  mkdir -p "$w/.github" "$w/svc"
  [ -z "$2" ] || cp "$2" "$w/.github/secret-scan-registry.json"
  printf 'host = "db"\napi_key = "%s"\n' "$acc" > "$w/svc/old.cfg"
  git -C "$w" add -A && git -C "$w" commit -q -m "history: the accepted key"
  echo x > "$w/readme.txt" && git -C "$w" add -A && git -C "$w" commit -q -m "main 1"
  git -C "$w" checkout -q -b more
  printf 'api_key = "%s"\n' "$new" > "$w/svc/new.cfg"
  git -C "$w" add -A && git -C "$w" commit -q -m "an unregistered key"
  git -C "$w" checkout -q -b pr main
  printf 'api_key = "%s"\n' "$acc" > "$w/svc/again.cfg"
  git -C "$w" add -A && git -C "$w" commit -q -m "PR: repeats the accepted key"
  git clone -q --bare "$w" "$o"
  git -C "$o" config uploadpack.allowFilter true
  git -C "$o" config uploadpack.allowAnySHA1InWant true
}
mk_origin live "$suite/registry-live.json"
mk_origin expired "$suite/registry-expired.json"
mk_origin none ""

# ── one scan: checkout, scope, then both jobs' step scripts ─────────────────────────────────────────────────────
# scan <name> <origin> <ref> <event> <base> <head>: writes <name>.{gitleaks,trufflehog}.rc and .out
scan() {
  local name=$1 o="$suite/$2.git" ref=$3 event=$4 base=$5 head=$6
  local r="$suite/$name" tmp="$suite/$name.tmp"
  git init -q "$r"
  git -C "$r" remote add origin "file://$o"
  git -C "$r" fetch -q --no-tags --depth=1 --filter=blob:none origin "+$ref:refs/remotes/checkout"
  git -C "$r" sparse-checkout set --no-cone '/.gitleaks.toml' '/.gitleaksignore' '/.github/secret-scan-registry.json'
  git -C "$r" checkout -q --detach refs/remotes/checkout
  (cd "$r" && EVENT=$event PR_BASE=$base PR_HEAD=$head PUSH_AFTER=$head GITHUB_OUTPUT="$r.scope" \
    bash "$here/scope.sh") 2> "$r.scope.err"
  get() { sed -n "s/^$1=//p" "$r.scope" | head -n 1; }
  mkdir -p "$tmp/bin"
  # Wrappers: record gitleaks' flags and umask (never its output), add the simulated live detector to trufflehog.
  printf '#!/bin/sh\necho "$*" > "%s/gitleaks.args"\numask > "%s/gitleaks.umask"\nexec "%s" "$@"\n' \
    "$suite/$name" "$suite/$name" "$GITLEAKS" > "$tmp/bin/gitleaks"
  printf '#!/bin/sh\nexec "%s" "$@" --config "%s"\n' "$TRUFFLEHOG" "$suite/th.yaml" > "$tmp/bin/trufflehog"
  chmod +x "$tmp/bin/gitleaks" "$tmp/bin/trufflehog"
  # The scope action's tree step (action.yml), for the trufflehog job.
  local files
  files=$(cd "$r" && python3 "$here/diffscan.py" tree "$tmp/secret-scan-tree" "$(get tree_revs)")
  local rc
  rc=0
  (cd "$r" && env RUNNER_TEMP="$tmp" GITHUB_OUTPUT="$r.gitleaks.gh" REVS="$(get revs)" SCOPE_DIR="$here" \
    POLICY="$(get registry_policy)" bash --noprofile --norc -eo pipefail "$suite/step-gitleaks.sh") \
    > "$r.gitleaks.out" 2>&1 || rc=$?
  echo "$rc" > "$r.gitleaks.rc"
  rc=0
  (cd "$r" && env RUNNER_TEMP="$tmp" GITHUB_OUTPUT="$r.trufflehog.gh" MODE="$(get mode)" HEAD_SHA="$(get head)" \
    TREE="$tmp/secret-scan-tree" TREE_FILES="$files" SCOPE_DIR="$here" POLICY="$(get registry_policy)" \
    bash --noprofile --norc -eo pipefail "$suite/step-trufflehog.sh") > "$r.trufflehog.out" 2>&1 || rc=$?
  echo "$rc" > "$r.trufflehog.rc"
  echo "mode=$(get mode) policy=$(get registry_policy)" > "$r.mode"
}
sha() { git -C "$suite/$1.git" rev-parse "$2"; }
rc() { cat "$suite/$1.$2.rc"; }
said() { grep -qF -- "$3" "$suite/$1.$2.out"; }   # said <scan> <gitleaks|trufflehog> <text>
line() { grep -qxF -- "$3" "$suite/$1.$2.out"; }   # line <scan> <gitleaks|trufflehog> <exact line>
args() { cat "$suite/$1/gitleaks.args"; }

scan sweep-ok live main schedule "" "$(sha live main)"
check "sweep, registered key only: full mode, policy sweep" grep -qx "mode=full policy=sweep" "$suite/sweep-ok.mode"
check "sweep, registered key only: the gitleaks step passes" [ "$(rc sweep-ok gitleaks)" = 0 ]
check "sweep, registered key only: the trufflehog step passes" [ "$(rc sweep-ok trufflehog)" = 0 ]
check "sweep: gitleaks ran WITHOUT --redact, under umask 077" \
  eval '! args sweep-ok | grep -q -- --redact && grep -qx 0077 "$suite/sweep-ok/gitleaks.umask"'
check "sweep: gitleaks names the finding as accepted" \
  said sweep-ok gitleaks "gitleaks generic-api-key: commit $(sha live main~1), path svc/old.cfg, line 2: accepted (registry entry #0"
check "sweep: trufflehog verified it and accepted it" \
  said sweep-ok trufflehog "trufflehog CustomRegex (verified): commit $(sha live main~1), path svc/old.cfg, line 2: accepted (registry entry #0"
check "sweep: each job lists the entry as a warning" eval 'said sweep-ok gitleaks "::warning title=accepted live credential::registry entry #0" &&
  said sweep-ok trufflehog "::warning title=accepted live credential::registry entry #0"'
check "sweep: no gitleaks report or private directory is left behind" \
  eval '[ -z "$(find "$suite/sweep-ok.tmp" -name "gitleaks.*" -type d)" ] && [ -z "$(find "$suite/sweep-ok.tmp" -name report.json)" ]'
check "sweep: the step wrote passed=true" eval 'grep -qx passed=true "$suite/sweep-ok.gitleaks.gh" && grep -qx passed=true "$suite/sweep-ok.trufflehog.gh"'

scan sweep-new live more schedule "" "$(sha live more)"
check "sweep + an unregistered key: the gitleaks step FAILS" [ "$(rc sweep-new gitleaks)" != 0 ]
check "sweep + an unregistered key: ... and wrote no passed=true" eval '! grep -qs passed=true "$suite/sweep-new.gitleaks.gh"'
check "sweep + an unregistered key: the trufflehog step FAILS" [ "$(rc sweep-new trufflehog)" != 0 ]
check "sweep: gitleaks says NOT in registry" \
  said sweep-new gitleaks "::error::gitleaks generic-api-key: commit $(sha live more), path svc/new.cfg, line 1: NOT in registry"
check "sweep: trufflehog says NOT in registry" \
  said sweep-new trufflehog "::error::trufflehog CustomRegex (verified): commit $(sha live more), path svc/new.cfg, line 1: NOT in registry"
check "sweep: the registered key is still accepted beside it" said sweep-new trufflehog "path svc/old.cfg, line 2: accepted"
check "sweep (failed): no gitleaks report left behind" eval '[ -z "$(find "$suite/sweep-new.tmp" -name report.json)" ]'

scan sweep-exp expired main schedule "" "$(sha expired main)"
check "sweep, review_by passed: the gitleaks step FAILS" [ "$(rc sweep-exp gitleaks)" != 0 ]
check "sweep, review_by passed: the trufflehog step FAILS" [ "$(rc sweep-exp trufflehog)" != 0 ]
check "sweep, review_by passed: the registry check errors in each job" \
  eval 'said sweep-exp gitleaks "::error title=secret-scan registry entry expired::registry entry #0" &&
    said sweep-exp trufflehog "::error title=secret-scan registry entry expired::registry entry #0"'
check "sweep, review_by passed: the finding is not accepted" said sweep-exp gitleaks "has EXPIRED"

scan pr-gate live refs/heads/pr pull_request "$(sha live main)" "$(sha live pr)"
check "PR repeating the registered key: range mode, policy gate" grep -qx "mode=range policy=gate" "$suite/pr-gate.mode"
check "PR (gate): the gitleaks step FAILS" [ "$(rc pr-gate gitleaks)" != 0 ]
check "PR (gate): ... on the repeated key, printed exactly as with no registry" \
  line pr-gate gitleaks "::error::gitleaks generic-api-key: commit $(sha live pr), path svc/again.cfg, line 1"
check "PR (gate): the trufflehog step FAILS" [ "$(rc pr-gate trufflehog)" != 0 ]
check "PR (gate): ... on the repeated key, verified, printed exactly as with no registry" \
  line pr-gate trufflehog "::error::trufflehog CustomRegex (verified): commit $(sha live pr), path svc/again.cfg, line 1"
check "PR (gate): gitleaks kept --redact" eval 'args pr-gate | grep -q -- --redact'
check "PR (gate): nothing is printed as accepted" eval '! grep -qF ": accepted (" "$suite/pr-gate.gitleaks.out" "$suite/pr-gate.trufflehog.out"'
check "PR (gate): the finding is the new file" said pr-gate trufflehog "path svc/again.cfg, line 1"

scan sweep-none none main schedule "" "$(sha none main)"
check "no registry file: the gitleaks step FAILS, as before" [ "$(rc sweep-none gitleaks)" != 0 ]
check "no registry file: ... on the history key, the line as before" \
  line sweep-none gitleaks "::error::gitleaks generic-api-key: commit $(sha none main~1), path svc/old.cfg, line 2"
check "no registry file: the trufflehog step FAILS, as before" [ "$(rc sweep-none trufflehog)" != 0 ]
check "no registry file: ... on the history key, the line as before" \
  line sweep-none trufflehog "::error::trufflehog CustomRegex (verified): commit $(sha none main~1), path svc/old.cfg, line 2"
check "no registry file: gitleaks kept --redact" eval 'args sweep-none | grep -q -- --redact'
check "no registry file: nothing mentions a registry" eval '! grep -qi registry "$suite/sweep-none.gitleaks.out" "$suite/sweep-none.trufflehog.out"'

cat "$suite"/*.gitleaks.out "$suite"/*.trufflehog.out "$suite"/*.scope.err "$suite"/*.tmp/*.log > "$suite/everything.out"
cp "$suite/everything.out" "$suite/planted.out" && sed -n 1p "$suite/forbidden.txt" >> "$suite/planted.out"
check "control: the grep catches a planted key" grep -qFf "$suite/forbidden.txt" "$suite/planted.out"
check "outputs captured (step logs, scanner logs)" [ "$(grep -c . "$suite/everything.out")" -gt 40 ]
check "no key and no digest in any step output or scanner log" \
  sh -c '! grep -qFf "$1" "$2"' _ "$suite/forbidden.txt" "$suite/everything.out"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
