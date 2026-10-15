# Trusted scan workflows

Org ruleset 25117498 runs these workflows from a pinned SHA of this repository in each target repository
(vps-ansible, platform-docs, vagaris, vagary-core, vagary-voice). A PR cannot edit what judges it.

| Workflow | Jobs | Mode |
|---|---|---|
| `trusted-secret-scan.yml` | trusted-gitleaks, trusted-trufflehog | blocking |
| `trusted-code-scan.yml` | trusted-code-scan (semgrep + SCA) | report-only |
| `trusted-workflow-integrity.yml` | trusted-workflow-integrity | blocks on integrity errors only |
| `trusted-protected-paths.yml` | trusted-protected-paths | interim report-only (`classify.py`) |

Edit `trusted/templates/*.yml.in` and `trusted/scanstate.py`, then run `python3 trusted/render.py`. The
workflows carry byte-identical inline copies of the Python sources; `trusted-tests` fails on drift.

## Scan states (ledger C9)

Every scanner job ends in exactly one state. `trusted/scanstate.py` records it in the job summary, as an
annotation, as the step output `state`, and in `scan-result-<scanner>.json` (artifact, 14 days, schema
`vagarylabs.scan-result/v1`).

| State | Meaning | Gate |
|---|---|---|
| PASSED | ran to completion over the declared scope, nothing at threshold | pass |
| FINDINGS | ran, found something at threshold | fail |
| UNAVAILABLE | did not complete or did not cover the scope | fail |
| NOT_APPLICABLE | a printed predicate says the change has nothing for this scanner | pass |
| AUTHORIZED_EXCEPTION | waived by an approved, unexpired register entry | pass |

UNAVAILABLE includes: an empty or unresolvable range, a tool download or checksum failure, a scanner
error exit, a missing or unreadable report, a semgrep error entry, an osv-scanner extraction error, and a
trufflehog candidate whose verification errored (provider unreachable, timeout). A check the gate expects
but nobody recorded (a step that failed or was skipped) is UNAVAILABLE, so a skipped step is never a pass.

| Scanner | Scope | FINDINGS threshold | NOT_APPLICABLE predicate |
|---|---|---|---|
| gitleaks | commits merge-base..head, BASE config | any finding | never |
| trufflehog | commits merge-base..head | a verified credential | never |
| semgrep | changed (A/M) files at head vs the same files at the merge-base | a new ERROR or WARNING finding | no added or modified file |
| SCA (osv-scanner) | changed lockfiles at head vs the merge-base | an advisory the PR introduces | no lockfile or manifest changed |

gitleaks cannot report what an allowlist suppressed, so it never emits AUTHORIZED_EXCEPTION. The
`exceptions` check records how many allowlist entries are active instead.

## Allowlist entries: approver and expiry

Every allowlist table in `.gitleaks.toml` (`[allowlist]`, `[[allowlists]]`, `[rules.allowlist]`,
`[[rules.allowlists]]`) carries two keys. gitleaks 8.30.1 ignores them; scanstate reads them:

```toml
[[allowlists]]
description = "why this is not a secret"
approver = "cc:root (migration 2026-10-15)"
expires = 2027-01-13
paths = ['''...''']
```

Every fingerprint in `.gitleaksignore` sits under an exception line in the same paragraph (no blank
line between them):

```
# exception: approver="cc:root (migration 2026-10-15)" expires=2027-01-13
<commit>:<path>:<rule>:<line>
```

- `expires` is a `YYYY-MM-DD` date in UTC. The entry is valid through that date.
- `expires` may be at most 90 days after the day of the run (UTC). A renewal is a new approval.
- If an entry has no approver, has no expiry, is expired, or has an expiry more than 90 days out, the
  `exceptions` check is FINDINGS. The gitleaks job then fails.
- The check reads HEAD's files as data. An expired entry fails every PR until a PR renews or removes it,
  and that PR passes. The scan itself always uses BASE's configuration, so a change takes effect only after
  merge. `.gitleaks.toml` and `.gitleaksignore` are protected paths.
- Ledger C9 item 4 asks for a human-attributable approver who is not the author. The migration entries
  name `cc:root (migration 2026-10-15)`, as root directed. Each renewal should name a person.

## Report-only to required

`REPORT_ONLY` in `trusted/scanstate.py` holds semgrep and sca at report-only. Flip a scanner (set it to
`False`, re-render, merge, and have root bump the ruleset pin) only when **all** of these hold for it:

1. **N = 20 clean runs per repository.** In each of the five ruleset repositories, the latest 20
   consecutive `trusted-code-scan` runs have `scan-result-<scanner>.json` state PASSED, NOT_APPLICABLE or
   AUTHORIZED_EXCEPTION. That means 0 UNAVAILABLE, and 0 FINDINGS that were not fixed in the same PR or
   registered.
   - At least 5 of the 20 are not NOT_APPLICABLE, so the scanner actually ran.
   - Repositories with a merge queue include at least 5 `merge_group` runs among the 20.
   - A missing artifact counts as UNAVAILABLE.
2. **Fast enough.** The job's p95 duration is under 5 minutes over those runs. vl-light queue wait meets
   root's ruleset criterion (a): p95 under 5 minutes over 1 hour.
3. **Planted proofs on the pinned SHA.** Each runs in one repository and its PR is closed afterwards:
   - planted positive: semgrep, a line that fires a p/owasp-top-ten ERROR rule; SCA, a lockfile pinning a
     package version with a known advisory. Both must show FINDINGS.
   - planted unavailable: semgrep, a ruleset fetch blocked or a file semgrep cannot parse; SCA, a lockfile
     osv-scanner cannot extract. Both must show UNAVAILABLE.
4. **Signed off by root** on the board.

## Runners

Trusted jobs hard-code `[self-hosted, Linux, X64, vl-light]`, the mini-PC bridge. No repository variable
and no hosted fallback can move a judge. The tests forbid `vars.` and `ubuntu-latest` in trusted workflows.
The reusable `secret-scan.yml` still routes through the caller's `SECRET_SCAN_RUNNER` variable.
