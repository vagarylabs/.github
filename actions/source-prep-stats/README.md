# source-prep-stats

`actions/checkout`, measured. This action wraps the pinned `actions/checkout` (same inputs, same `ref` and `commit` outputs) and records how the job prepared its source as a versioned **`source-prep.v1`** record. `job-footprint` collects every record of the job into one small **`job-telemetry.v1`** artifact.

It measures. It does not change how anything is fetched, and it adds no cache.

```yaml
steps:
  - uses: vagarylabs/.github/actions/source-prep-stats@<sha>
    with:
      fetch-depth: 0              # any actions/checkout input, unchanged
  # ... the job ...
  - if: ${{ always() }}
    uses: vagarylabs/.github/actions/job-footprint@<sha>
```

To measure, replace `actions/checkout` with this action and add `job-footprint` as the last step.

Optional inputs:

- `pnpm-store-dir: <store>` reads the pnpm store's bytes before install. `job-footprint` then reports the store delta at the end of the job.
- `trace-job: "true"` keeps git trace2 on after the checkout. `job-footprint` can then count lazy fetches and fetch retries that later steps cause, for example on a `blob:none` clone.

## Guarantees

- **It never fails a job.** The measuring steps run `if: always()` with `continue-on-error`. A failed checkout still fails the job, as it would without this action.
- **Unknown stays unknown.** A value that was not measured is `null`, and `unknown` says why. `0` always means a measured zero, such as "no lazy fetch ran" or "nothing existed before a cold checkout".
  - Attribution fields are `null` when the runner does not provide them.
  - A directory that cannot be read (under `.git`, or the pnpm store) makes that size `null` with the reason, never a smaller or zero total. A "before" value that was not read is never taken as zero.
  - `sparse_*` fields are `null` when `sparse` is `false`, because they don't apply.
  - `filter` is `null` when `partial` is `false`.
- **Every read is bounded.** One step's reads (trace2 files, git output, the object listing and the size walks) share one 120 s deadline, a 256 MiB byte budget and a 4 million event budget (trace events and directory entries). A git command that outlasts the deadline is killed with its process group. Whatever runs out is `null` with the reason, never a partial count, a crash or a hang. The cheap facts are read first and the size walks last, so a slow walk costs only the sizes.
  - `walk-budget-seconds` further limits the size walks. It must be a finite number of seconds >= 0; `inf`, `NaN` or a negative value is refused with a warning and the default (20) used.
  - trace2 input is capped at 20,000 files, 20,000 git processes and 1 MiB per line; a longer line, or a process id nested deeper than 32 levels, is a bad line. Summarizing the trace is linear in its processes and runs under the same deadline.
- **A truncated tree is never complete.**
  - `completeness` is `complete` only when the tree is not shallow, not partial (filtered) and not sparse, and when submodules were fetched if the repository has them.
  - If any of those facts is unknown, `completeness` is `unknown`.
  - Partial and sparse are recorded separately. `actions/checkout` turns every sparse checkout into a `blob:none` partial clone, so a sparse checkout reports both.
- **Raw traces never leave the runner.**
  - git trace2 events carry argv, remote URLs and error text. They are written to a `0700` directory under `RUNNER_TEMP`, reduced to allow-listed counts, and deleted. The deletion runs in a `finally`, so a trace that cannot be parsed, or any other failure in the step, still removes it. A malformed event (a field of the wrong JSON type, a line nested too deep to parse, a time that is not a finite number >= 0, a counter that is not a non-negative integer) is counted in `measurement.trace.bad_lines`; it never stops the step, and its value is never published. The record is strict JSON: it never holds `NaN` or `Infinity`.
  - The record holds no URL, argv or error message. The only trace strings it publishes, `transfer.protocol_version` and `transfer.filter_effective`, are mapped to a closed form first (`0`, `1`, `2`; `blob:none`, `blob:limit=<n>`, `tree:<n>`, `object:type=<type>`, `sparse:oid` without its rev, and `combine:` of those). Any other value is `other`, never the raw text. `filter`, read from the repository's config, is mapped the same way.
  - A step warning names the exception and where it was raised, never its message, because a message can quote trace content and job logs of a public repository are public.
  - With `trace-job`, the job-wide trace directory is emptied when `job-footprint` parses it. `GIT_TRACE2_EVENT` stays set, so git calls after that (post steps included) still write raw traces there, in the same `0700` directory, until the runner cleans `RUNNER_TEMP`.

## The record (`schema/source-prep.v1.json`, draft)

| Field | Meaning |
|---|---|
| `bytes` | On-disk bytes this preparation added under `.git/objects`: new pack files plus the loose-object delta. For a cold full fetch this equals the pack the server sent. |
| `bytes_detail.git_dir_bytes_after` | Apparent bytes of `.git`: regular files and symlinks, each inode once, directories 0. That equals GNU `du -sb .git` from coreutils 9.2 on (Ubuntu 24.04 ships 9.4). Coreutils 8.x also added directory sizes. |
| `objects` | `git count-objects -v` (`count` + `in-pack`), after minus before. `objects_detail.received` is the sum of the `--pack_header` object counts of every received pack, lazy fetches included. |
| `depth` | Commits reachable from `HEAD` when shallow, otherwise `"full"`. |
| `shallow`, `partial`, `filter`, `sparse`, `sparse_cone`, `sparse_patterns`, `sparse_patterns_sha256` | Read from the repository after the checkout. The `requested` block shows what was asked for. Requested and observed can differ: sparse implies `blob:none`. |
| `files_materialised`, `files_skipped` | Index entries written to disk and entries marked skip-worktree. |
| `checkout.seconds` | Wall time of the checkout step: from the end of the before snapshot to the start of the after step, so it never includes this action's own size walks. `transfer.fetch_seconds` is git's own time for the top-level fetches. |
| `retries` | Failed fetch attempts that were followed by an identical attempt, which is how `actions/checkout` retries. git's own HTTP 429 retries (`http.maxRetries`, git 2.54+, off by default) are not attempts; they show in `transfer.http_429_responses`. |
| `throttle_hits` | Fetch attempts that hit HTTP 429, "Too Many Requests" or a (secondary) rate limit, whether git reported it as an error or (2.54+) as traced 429 data. One attempt counts once, however many of its processes reported it. |
| `transfer.http_429_responses` | Every 429 response git received, including ones it retried itself. `null` before git 2.54, which does not report them. |
| `transfer.lazy_fetches`, `lazy_objects` | Promisor (partial clone) fetches during the checkout and the objects they brought. |
| `transfer.protocol_version`, `negotiation_rounds`, `haves_sent`, `filter_effective` | The fetch negotiation summary from trace2. The two strings are allow-listed: anything else is `other`. |
| `warm` | Whether a repository with objects was already at the path (persistent runners). |
| `measurement.complete` | `false` when the trace was missing or damaged (a process never exited, or a line was unparseable), or a size could not be read (a walk ran out of time, or a directory was unreadable), or the step's read budget ran out. |

`job-telemetry.v1` (`schema/job-telemetry.v1.json`) holds the job's attribution and the cgroup footprint:

- `footprint`: `peak_mib`, `cpu_s`, `mem_limit`, `cpus`, and the `scope` the caller declared (`job` on an ephemeral one-job container, `shared` on a shared VM).
- `source_prep`: every record.
- `after_checkout_git`: populated with `trace-job`.
- `pnpm_store`: before, after and delta.

The artifact is `job-telemetry-<run>-<attempt>-<job>-<random>`. The random suffix keeps matrix legs apart. It is about 2 KB per checkout and is kept 3 days.

Both schemas are drafts. Their canonical home is `vagary-core` `contracts/delivery/v1` (P7-01). When that contract is ratified, this producer moves to it and drops `schema_status: draft`.

## Tests

```sh
python3 -m unittest discover -s actions/source-prep-stats -p 'test_*.py' -v
```

- `test_trace2.py` pins the trace reading on real, sanitized git traces in `fixtures/trace2` and on synthetic edge cases. Regenerate the fixtures with `fixtures/make_trace2_fixtures.py`.
- `test_hermetic.py` runs a local smart-HTTP git server with a 429 injector. It drives the same git sequence as `actions/checkout`, through the action's own entry points. It checks that:
  - bytes match the server's pack within 5%;
  - the injector's 429 counts as one throttle hit and one retry;
  - a depth-0 clone and a `blob:none` clone report different `filter` and `partial`;
  - shallow and sparse are each reported as incomplete;
  - a warm re-fetch counts only new objects;
  - nulls appear where nothing was measured;
  - every document validates against the schemas.
- `.github/workflows/source-prep-stats.yml` runs these tests and dogfoods the action and `job-footprint` on this repository.
