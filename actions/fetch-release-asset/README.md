# fetch-release-asset

Fetches one GitHub release asset, verified against a sha256 pinned in the caller's repository. It serves
the file from the runner's shared tool cache when the cache holds a verified copy. Otherwise it downloads
the file with resumable retries and caches it for the next job.

Why it exists: on 2026-10-12, `release-assets.githubusercontent.com` served 10-90 KB/s from every vantage
point while other hosts were fast. Downloading per job then outran the job: promtool (150 MB) needed 30-80
min, and restic (10 MB) timed out at `--max-time 90`.

## Usage

Pin the action by **commit SHA**. Never use `@main` or a branch: the action decides which bytes your job
runs, so its own code must be pinned the same way the asset is.

```yaml
- id: restic
  uses: vagarylabs/.github/actions/fetch-release-asset@<40-char commit sha>
  with:
    tool: restic
    version: 0.18.1
    url: https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_linux_amd64.bz2
    sha256: 680838f19d67151adba227e1570cdd8af12c19cf1735783ed1ba928bc41f363d
    dest: ${{ runner.temp }}/restic.bz2
    max-time: "300" # optional, seconds for the download (default 300)
- run: bunzip2 -c "$RUNNER_TEMP/restic.bz2" > "$RUNNER_TEMP/restic" && chmod +x "$RUNNER_TEMP/restic"
```

| Input | Required | Meaning |
|---|---|---|
| `tool`, `version` | yes | Cache path components; must match `[A-Za-z0-9._+-]+` and must not contain `..` |
| `url` | yes | Full `https://` URL of the asset |
| `sha256` | yes | sha256 of the downloaded **file** (64 lowercase hex), taken from the project's checksum file |
| `dest` | yes | Where to write the verified file; parent directories are created |
| `max-time` | no | `curl --max-time` for the download, in seconds (default `300`) |

| Output | Meaning |
|---|---|
| `path` | The verified file (equal to `dest`) |
| `source` | `cache-hit` or `downloaded` |

Invalid inputs are refused before anything touches the filesystem or the network. That covers a path
traversal in `tool`/`version`, a sha256 that is not 64 lowercase hex, and a URL that is not https.

## Cache semantics

The cache entry is `${RUNNER_TOOL_CACHE:-/opt/hostedtoolcache}/<tool>/<version>/<url basename, query stripped>`.
On the CI bridge runners that directory is shared by every runner user (docker group, default ACL
`g:docker:rwX`). Hosted runners start with no cache, so every job there downloads.

1. **Cache hit.** If the entry exists and its sha256 equals the pin, it is copied to `dest`. The copy is
   made to a private file and that copy is hashed, so a concurrent overwrite cannot deliver unverified
   bytes. Log: `release-asset: cache hit <path>`.
2. **Cache entry with the wrong sha256 = a miss, not an error.** Log:
   `release-asset: cache entry sha mismatch (have X, want Y), refetching`. The entry is refetched and then
   overwritten (`release-asset: cache overwritten <path>`). One bad job writing a wrong entry under a pinned
   name must not fail every trusted job after it. An unreadable entry is treated the same way.
3. **Download.** `curl -fsSL --retry 5 --retry-all-errors -C - --max-time <max-time>` writes into a private
   temp file; `-C -` resumes into that same file across curl's retries.
4. **Downloaded file with the wrong sha256 = fatal.** The step fails with `::error::` and nothing is written
   to `dest` or to the cache.
5. **Cache write.** The verified file is written to a temp file in the entry's own directory, made
   group- and world-readable (`0664`), and moved into place with `mv`. Because the rename is atomic, a
   concurrent job sees either the old entry or the complete new one, never a partial file. If the cache
   directory cannot be created or written, the write is skipped and logged. A failed cache write never
   fails the job.
6. The verified file is copied to `dest`.

The cache is an accelerator, not a trust root: every delivery is checked against the caller's pin.

## The lock file

[`release-assets.lock`](../../release-assets.lock) at the repository root lists pinned assets, one per
line: `<tool> <version> <url> <sha256>`. Lines starting with `#` are comments. Each sha256 is that of
the downloaded file, copied from the project's own checksum file for that release (for example
`SHA256SUMS` or `sha256sums.txt`). It is never computed from a download you just made.
`test_fetch.sh` checks every line's shape.

A caller can keep its own lock file in the same format and read a line into the inputs:

```yaml
- id: pin
  run: |
    set -euo pipefail
    read -r tool version url sha < <(awk '$1 == "restic" && $2 == "0.18.1"' release-assets.lock)
    { echo "tool=$tool"; echo "version=$version"; echo "url=$url"; echo "sha256=$sha"; } >> "$GITHUB_OUTPUT"
- uses: vagarylabs/.github/actions/fetch-release-asset@<40-char commit sha>
  with:
    tool: ${{ steps.pin.outputs.tool }}
    version: ${{ steps.pin.outputs.version }}
    url: ${{ steps.pin.outputs.url }}
    sha256: ${{ steps.pin.outputs.sha256 }}
    dest: ${{ runner.temp }}/restic.bz2
```

## Tests

`bash actions/fetch-release-asset/test_fetch.sh` runs `fetch.sh` with `curl` and `mv` stubbed on `PATH`.
Each case uses its own private tool cache. The tests cover:

- a cache hit;
- a cache sha mismatch, which refetches and overwrites the entry;
- a download sha mismatch, which is fatal and writes nothing;
- a cache that cannot be written;
- inputs that are refused before any curl call;
- a cache write that goes through a temp file and `mv`;
- the shape of every line in the lock file.

CI runs the same command (`.github/workflows/ci.yml`, job `fetch-release-asset-tests`).
