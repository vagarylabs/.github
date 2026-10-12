#!/usr/bin/env bash
# fetch-release-asset: deliver one pinned release asset to DEST, from the runner's shared tool cache when it
# holds a verified copy, else by a resumable download. Called by action.yml; runnable on its own for tests.
#
# Environment (all required except ASSET_MAX_TIME):
#   ASSET_TOOL, ASSET_VERSION  cache path components, [A-Za-z0-9._+-]+ and no '..'
#   ASSET_URL                  https URL of the release asset
#   ASSET_SHA256               64 lowercase hex: the sha256 of the downloaded FILE, pinned by the caller
#   ASSET_DEST                 path to write the verified file to
#   ASSET_MAX_TIME             curl --max-time in seconds (default 300)
# Optional: RUNNER_TOOL_CACHE (default /opt/hostedtoolcache), RUNNER_TEMP, GITHUB_OUTPUT.
#
# Order: cache hit -> copy. Cache entry with the wrong sha -> a miss, refetch and overwrite it. Download with
# the wrong sha -> fatal, nothing written. Cache write failure (e.g. hosted runner) -> skipped, never fatal.
set -euo pipefail

say() { printf 'release-asset: %s\n' "$*"; }
die() { printf '::error::release-asset: %s\n' "$*"; exit 1; }

tool="${ASSET_TOOL-}"
version="${ASSET_VERSION-}"
url="${ASSET_URL-}"
want="${ASSET_SHA256-}"
dest="${ASSET_DEST-}"
max_time="${ASSET_MAX_TIME:-300}"

# --- Validate every input before touching the filesystem or the network. -----------------------------------
component_re='^[A-Za-z0-9._+-]+$'
safe_component() {
  # [[ =~ ]] tests the whole string; grep would test line by line and pass "ok<newline>../x".
  [[ $1 =~ $component_re ]] && [[ $1 != *..* ]] && [ "$1" != "." ]
}
safe_component "$tool" || die "tool must match [A-Za-z0-9._+-]+ without '..' (got '$tool')"
safe_component "$version" || die "version must match [A-Za-z0-9._+-]+ without '..' (got '$version')"
sha_re='^[0-9a-f]{64}$'
[[ $want =~ $sha_re ]] || die "sha256 must be 64 lowercase hex characters (got '$want')"
url_re='^https://[^[:space:]]+$'
[[ $url =~ $url_re ]] || die "url must be https:// with no whitespace (got '$url')"
base="${url%%[?#]*}"
base="${base##*/}"
safe_component "$base" || die "url basename (query stripped) must be a safe file name (got '$base')"
time_re='^[1-9][0-9]*$'
[[ $max_time =~ $time_re ]] || die "max-time must be a positive integer of seconds (got '$max_time')"
[ -n "$dest" ] || die "dest is required"
case "$dest" in *$'\n'* | *$'\r'*) die "dest must not contain a newline" ;; esac

# --- Helpers. ----------------------------------------------------------------------------------------------
sha_of() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out=$(sha256sum "$1") || return 1
  else
    out=$(shasum -a 256 "$1") || return 1
  fi
  printf '%s\n' "${out%% *}"
}

cache_dir="${RUNNER_TOOL_CACHE:-/opt/hostedtoolcache}/$tool/$version"
entry="$cache_dir/$base"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/release-asset.XXXXXX")
cache_tmp=""
cleanup() {
  rm -rf "$work"
  if [ -n "$cache_tmp" ]; then rm -f "$cache_tmp"; fi
}
trap cleanup EXIT

deliver() { # $1 = verified file in $work, $2 = source
  mkdir -p "$(dirname "$dest")"
  cp "$1" "$dest"
  if [ -n "${GITHUB_OUTPUT-}" ]; then
    printf 'path=%s\nsource=%s\n' "$dest" "$2" >>"$GITHUB_OUTPUT"
  fi
}

# --- (a)/(b) Cache lookup. The entry is copied to a private file and THAT copy is hashed, so a concurrent
# overwrite between check and copy cannot deliver unverified bytes. ------------------------------------------
had_entry=0
if [ -e "$entry" ]; then
  had_entry=1
  have=""
  if cp "$entry" "$work/cached" 2>/dev/null; then
    have=$(sha_of "$work/cached" 2>/dev/null) || have=""
  fi
  if [ "$have" = "$want" ]; then
    deliver "$work/cached" cache-hit
    say "cache hit $entry"
    exit 0
  fi
  say "cache entry sha mismatch (have ${have:-unreadable}, want $want), refetching"
fi

# --- (c) Download into a private temp file; -C - resumes into the same file across curl's retries. --------
dl="$work/download"
say "downloading $url (max-time ${max_time}s)"
curl -fsSL --retry 5 --retry-all-errors -C - --max-time "$max_time" -o "$dl" "$url" \
  || die "download failed: $url"
got=$(sha_of "$dl") || die "could not hash the download"
if [ "$got" != "$want" ]; then
  die "downloaded file sha256 mismatch for $tool $version (have $got, want $want); nothing written"
fi

# --- (d) Publish to the shared cache: temp file in the same directory + atomic mv, so a concurrent reader
# sees the old entry or the complete new one, never a partial file. Any failure here only skips the cache. ---
cache_write() {
  mkdir -p "$cache_dir" 2>/dev/null || return 1
  cache_tmp=$(mktemp "$cache_dir/.$base.tmp.XXXXXX" 2>/dev/null) || return 1
  cp "$dl" "$cache_tmp" 2>/dev/null || return 1
  # mktemp creates 0600; under a default ACL that mode becomes the mask and the group would lose read.
  chmod 0664 "$cache_tmp" 2>/dev/null || return 1
  mv -f "$cache_tmp" "$entry" 2>/dev/null || return 1
  cache_tmp=""
}
if cache_write; then
  if [ "$had_entry" = 1 ]; then
    say "cache overwritten $entry"
  else
    say "cache written $entry"
  fi
else
  say "cache not writable ($cache_dir), skipping cache write"
fi

# --- (e) Deliver. -------------------------------------------------------------------------------------------
deliver "$dl" downloaded
say "downloaded $dest"
