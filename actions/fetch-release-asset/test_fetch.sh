#!/usr/bin/env bash
# Tests for fetch.sh. curl and mv are stubbed on PATH; every case runs in its own temp root with its own
# RUNNER_TOOL_CACHE, RUNNER_TEMP and GITHUB_OUTPUT, so the suite never touches a real runner's shared cache.
# Also lints the repository's release-assets.lock. Run: bash actions/fetch-release-asset/test_fetch.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/fetch.sh"
lock="$here/../../release-assets.lock"
real_mv=$(command -v mv)

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
check() { # check <description> <command...>
  local d=$1
  shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}
contains() { grep -qF -- "$2" "$1"; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

suite=$(mktemp -d "${TMPDIR:-/tmp}/fetch-release-asset-test.XXXXXX")
trap 'rm -rf "$suite"' EXIT

stubs="$suite/stubs"
mkdir -p "$stubs"
cat >"$stubs/curl" <<'EOF'
#!/usr/bin/env bash
# Stub curl: log the argv (one arg per line, then a separator) and write $STUB_CURL_BODY to the -o path.
set -euo pipefail
{ printf '%s\n' "$@"; echo '--end--'; } >>"$STUB_CURL_LOG"
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out=$2; shift; fi
  shift
done
[ -n "$out" ] || exit 2
cat "$STUB_CURL_BODY" >>"$out"
EOF
cat >"$stubs/mv" <<EOF
#!/usr/bin/env bash
# Stub mv: log the argv, then run the real mv.
printf '%s\n' "\$*" >>"\$STUB_MV_LOG"
exec "$real_mv" "\$@"
EOF
chmod +x "$stubs/curl" "$stubs/mv"

good="$suite/good.bin"
evil="$suite/evil.bin"
printf 'release asset payload\n' >"$good"
printf 'tampered payload\n' >"$evil"
want=$(sha_of "$good")
tool=restic
version=0.18.1
asset=restic_0.18.1_linux_amd64.bz2
url="https://github.com/restic/restic/releases/download/v0.18.1/$asset?x=1#frag"

# new_case <name>: fresh root; sets T, CACHE, ENTRY, DEST, OUT, CURL_LOG, MV_LOG.
new_case() {
  T="$suite/$1"
  mkdir -p "$T/temp"
  CACHE="$T/toolcache"
  ENTRY="$CACHE/$tool/$version/$asset"
  DEST="$T/out/sub/restic.bz2"
  OUT="$T/github_output"
  CURL_LOG="$T/curl.log"
  MV_LOG="$T/mv.log"
  : >"$OUT"
}
# run_fetch <body> [VAR=value ...]: runs fetch.sh with the case's environment; sets RC and LOG.
run_fetch() {
  local body=$1
  shift
  LOG="$T/run.log"
  set +e
  env PATH="$stubs:$PATH" RUNNER_TOOL_CACHE="$CACHE" RUNNER_TEMP="$T/temp" GITHUB_OUTPUT="$OUT" \
    STUB_CURL_LOG="$CURL_LOG" STUB_CURL_BODY="$body" STUB_MV_LOG="$MV_LOG" \
    ASSET_TOOL="$tool" ASSET_VERSION="$version" ASSET_URL="$url" ASSET_SHA256="$want" ASSET_DEST="$DEST" \
    "$@" bash "$script" >"$LOG" 2>&1
  RC=$?
  set -e
}
curl_calls() { if [ -f "$CURL_LOG" ]; then grep -c -- '--end--' "$CURL_LOG"; else echo 0; fi; }
same_as() { cmp -s "$1" "$2"; }
no_tmp_left() { [ -z "$(find "$1" -name '.*.tmp.*' 2>/dev/null)" ]; }
# shellcheck disable=SC2012 # the permission string, portably (stat flags differ on macOS and Linux)
mode_of() { ls -ld "$1" | cut -c1-10; }

echo "# cache hit"
new_case hit
mkdir -p "$(dirname "$ENTRY")"
cp "$good" "$ENTRY"
run_fetch "$good"
check "hit: exit 0" [ "$RC" = 0 ]
check "hit: logs cache hit with the entry path" contains "$LOG" "release-asset: cache hit $ENTRY"
check "hit: curl not called" [ "$(curl_calls)" = 0 ]
check "hit: dest has the verified bytes" same_as "$DEST" "$good"
check "hit: output path=dest" contains "$OUT" "path=$DEST"
check "hit: output source=cache-hit" contains "$OUT" "source=cache-hit"

echo "# cache entry with the wrong sha: miss, refetch, overwrite"
new_case mismatch
mkdir -p "$(dirname "$ENTRY")"
cp "$evil" "$ENTRY"
run_fetch "$good"
check "mismatch: exit 0" [ "$RC" = 0 ]
check "mismatch: logs have/want and refetching" \
  contains "$LOG" "release-asset: cache entry sha mismatch (have $(sha_of "$evil"), want $want), refetching"
check "mismatch: curl called exactly once" [ "$(curl_calls)" = 1 ]
check "mismatch: logs cache overwritten" contains "$LOG" "release-asset: cache overwritten $ENTRY"
check "mismatch: entry now has the pinned sha" [ "$(sha_of "$ENTRY")" = "$want" ]
check "mismatch: dest has the verified bytes" same_as "$DEST" "$good"
check "mismatch: output source=downloaded" contains "$OUT" "source=downloaded"
check "mismatch: no temp file left in the cache dir" no_tmp_left "$CACHE"

echo "# downloaded file with the wrong sha: fatal, nothing written"
new_case dlbad
mkdir -p "$(dirname "$ENTRY")"
cp "$evil" "$ENTRY"
run_fetch "$evil"
check "dl-mismatch: exit 1" [ "$RC" = 1 ]
check "dl-mismatch: ::error:: annotation" contains "$LOG" "::error::release-asset: downloaded file sha256 mismatch"
check "dl-mismatch: dest not written" [ ! -e "$DEST" ]
check "dl-mismatch: existing cache entry unchanged" same_as "$ENTRY" "$evil"
check "dl-mismatch: no temp file left in the cache dir" no_tmp_left "$CACHE"
check "dl-mismatch: no mv into the cache" [ ! -s "$MV_LOG" ]
check "dl-mismatch: no outputs" [ ! -s "$OUT" ]
new_case dlbad-fresh
run_fetch "$evil"
check "dl-mismatch (no entry): exit 1" [ "$RC" = 1 ]
check "dl-mismatch (no entry): cache dir never created" [ ! -e "$CACHE" ]
check "dl-mismatch (no entry): dest not written" [ ! -e "$DEST" ]
check "dl-mismatch (no entry): private temp dir removed" [ -z "$(ls -A "$T/temp")" ]

echo "# cache not writable (hosted runner): still succeeds"
new_case readonly
: >"$T/not-a-dir"
CACHE="$T/not-a-dir/toolcache" # mkdir fails even for root
run_fetch "$good"
check "readonly: exit 0" [ "$RC" = 0 ]
check "readonly: logs the skipped cache write" contains "$LOG" "release-asset: cache not writable ($CACHE/$tool/$version), skipping cache write"
check "readonly: dest has the verified bytes" same_as "$DEST" "$good"
check "readonly: output source=downloaded" contains "$OUT" "source=downloaded"

if [ "$(id -u)" != 0 ]; then
  echo "# unreadable cache entry: a miss, not an error"
  new_case unreadable
  mkdir -p "$(dirname "$ENTRY")"
  cp "$good" "$ENTRY"
  chmod 000 "$ENTRY"
  chmod 0555 "$(dirname "$ENTRY")" # the entry cannot be replaced either
  run_fetch "$good"
  chmod 0755 "$(dirname "$ENTRY")"
  chmod 0644 "$ENTRY"
  check "unreadable: exit 0" [ "$RC" = 0 ]
  check "unreadable: logged as a mismatch" contains "$LOG" "cache entry sha mismatch (have unreadable, want $want)"
  check "unreadable: cache write skipped" contains "$LOG" "skipping cache write"
  check "unreadable: dest has the verified bytes" same_as "$DEST" "$good"
fi

echo "# bad inputs: refused before any curl call or filesystem write"
refuse() { # refuse <description> VAR=value ...
  local d=$1
  shift
  new_case "refuse-$pass-$fail"
  run_fetch "$good" "$@"
  if [ "$RC" = 1 ] && grep -q '^::error::release-asset:' "$LOG" && [ "$(curl_calls)" = 0 ] \
    && [ ! -e "$CACHE" ] && [ ! -e "$DEST" ] && [ -z "$(ls -A "$T/temp")" ]; then
    ok "refused: $d"
  else
    bad "refused: $d (rc=$RC: $(tr '\n' ' ' <"$LOG"))"
  fi
}
refuse "tool with path traversal" ASSET_TOOL=../../etc
refuse "tool with a slash" ASSET_TOOL=a/b
refuse "tool '..'" ASSET_TOOL=..
refuse "tool '.'" ASSET_TOOL=.
refuse "empty tool" ASSET_TOOL=
refuse "version containing '..'" ASSET_VERSION=1..2
refuse "version with a newline then traversal" ASSET_VERSION=$'1.0\n../../x'
refuse "sha256 non-hex" ASSET_SHA256="$(printf 'z%.0s' $(seq 64))"
refuse "sha256 uppercase" ASSET_SHA256="$(printf '%s' "$want" | tr 'a-f' 'A-F')"
refuse "sha256 too short" ASSET_SHA256="${want:0:63}"
refuse "sha256 empty" ASSET_SHA256=
refuse "http url" ASSET_URL="http://github.com/restic/restic/releases/download/v0.18.1/$asset"
refuse "file url" ASSET_URL=file:///etc/passwd
refuse "url basename '..'" ASSET_URL=https://example.com/a/..
refuse "url with no basename" ASSET_URL=https://example.com/a/
refuse "max-time not a number" ASSET_MAX_TIME=abc
refuse "max-time zero" ASSET_MAX_TIME=0
refuse "empty dest" ASSET_DEST=
refuse "dest with a newline" ASSET_DEST=$'x\npath=/etc/passwd'

echo "# curl invocation and the concurrent-safe cache write (temp file in the entry's directory + mv)"
new_case write
run_fetch "$good"
check "write: exit 0" [ "$RC" = 0 ]
check "write: logs cache written" contains "$LOG" "release-asset: cache written $ENTRY"
args=$(tr '\n' ' ' <"$CURL_LOG")
case " $args" in *" -fsSL --retry 5 --retry-all-errors -C - --max-time 300 -o "*) ok "curl: flags in order" ;; *) bad "curl: flags in order ($args)" ;; esac
case " $args" in *" -o $T/temp/release-asset."*"/download "*) ok "curl: -o is a private temp file under RUNNER_TEMP" ;; *) bad "curl: -o path ($args)" ;; esac
case "$args" in *" $url --end--"*) ok "curl: fetches the url as given" ;; *) bad "curl: url ($args)" ;; esac
mv_line=$(head -n1 "$MV_LOG" 2>/dev/null || true)
case "$mv_line" in
  "-f $(dirname "$ENTRY")/.$asset.tmp."*" $ENTRY") ok "write: entry published by mv from a temp file in the same directory" ;;
  *) bad "write: mv from a same-directory temp file (got '$mv_line')" ;;
esac
check "write: exactly one mv" [ "$(cat "$MV_LOG" 2>/dev/null | wc -l | tr -d ' ')" = 1 ]
check "write: entry has the pinned sha" [ "$(sha_of "$ENTRY")" = "$want" ]
check "write: entry is group- and world-readable (rw-rw-r--)" [ "$(mode_of "$ENTRY" | cut -c2-10)" = "rw-rw-r--" ]
check "write: no temp file left in the cache dir" no_tmp_left "$CACHE"
check "write: private temp dir removed" [ -z "$(ls -A "$T/temp")" ]
new_case maxtime
run_fetch "$good" ASSET_MAX_TIME=42
check "curl: max-time input is passed through" contains "$CURL_LOG" $'--max-time\n42'
echo "# a second job after the write is a cache hit"
cp -R "$suite/write/toolcache" "$CACHE"
run_fetch "$good"
check "second job: cache hit" contains "$LOG" "release-asset: cache hit $ENTRY"
check "second job: curl not called again" [ "$(curl_calls)" = 1 ]

echo "# release-assets.lock"
lock_ok=1
lineno=0
entries=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  case "$line" in '' | '#'*) continue ;; esac
  # shellcheck disable=SC2086 # split the line into its fields
  set -- $line
  entries=$((entries + 1))
  if [ $# -ne 4 ] || ! [[ $1 =~ ^[A-Za-z0-9._+-]+$ ]] || [[ $1 == *..* ]] \
    || ! [[ $2 =~ ^[A-Za-z0-9._+-]+$ ]] || [[ $2 == *..* ]] \
    || ! [[ $3 =~ ^https://[^[:space:]]+$ ]] || ! [[ $4 =~ ^[0-9a-f]{64}$ ]]; then
    lock_ok=0
    printf '  bad lock line %d: %s\n' "$lineno" "$line"
  fi
done <"$lock"
check "lock: every entry is '<tool> <version> <https url> <sha256>'" [ "$lock_ok" = 1 ]
check "lock: has entries" [ "$entries" -gt 0 ]

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
