# Shared CI distribution and first-party adoption

Vagary owns the execution contract and its qualification. A Git tag names reviewed source; it does not grant execution permission, qualify a consumer, change billing, or authorize a release.

At the October 16, 2026 inventory, `vagarylabs/.github` has no Git tags and no GitHub releases. `PLANNER_VERSION = "1.4.0"` is the planner's internal record version, not a published repository release. No version is assigned by this document. Until a real tag is verified, first-party SHA pins retain the agreed `# main` annotation. That annotation does not make the reference floating.

## Named ownership and triggers

| Responsibility | Owner | Trigger and action |
|---|---|---|
| Shared source release and initial version selection | cc:root, the current shared CI release owner | After a merged exact candidate has reviewed qualification, select a stable semantic version and create its immutable annotated tag. Routine version numbering does not require another operator approval. |
| Planner compatibility and record contracts | SRC-03 planner owner | State affected components, compatibility changes and mandatory consumer adoption in the release notes. Internal component versions remain independent of the repository bundle tag. |
| First-party adoption coordination | cc:root | A security/correctness fix, required contract change or explicitly selected component improvement must reach its consumers. Root opens/routes the bounded pin-bump work to existing owners, rather than treating a shared merge as automatic adoption. |
| Vagaris workflow pin changes | Existing Vagaris CI owner (execnode), with CLI review for release files | Update affected exact SHAs through one normal PR/compatible train. Preserve required contexts and release constraints. |
| Core workflow pin changes | Existing Core CI owner (Codex), with CLI review for release files | Update affected exact SHAs and dependent planner policy/config bindings together through the normal PR path. |
| SHA-pin ratchet | CLI's RU-02 owner | Maintain the existing ratchet and its approved exclusions. This distribution tooling does not implement a second ratchet. |
| Trusted organization workflow pin | cc:root | Update the ruleset only through its existing authority and qualification path. A consumer PR cannot update that trust root. |

If ownership changes, record the handover through the established board/mission path. A silent or paused owner is not permission to push their branch. Version adoption proposals may eventually come from automation; the existing authority and validation remain unchanged.

## Release identity and qualification

Use repository-wide stable `vMAJOR.MINOR.PATCH` tags as immutable source bundle names. Root selects the first version from the reviewed compatibility decision; do not infer it from the planner's internal version or invent a tag in a comment. Record component record/schema versions separately in the release notes. An incompatible contract or changed default is a major-version decision; compatible additions and fixes follow the normal minor/patch distinction.

Before tagging, the release owner must have the exact merged commit, owning review and applicable component qualification receipts. Reuse the existing CI jobs, CodeQL/security evidence, `trusted/render.py --check`, component tests and normal source-review process. Do not substitute whole-workflow green for the required evidence set, and do not count skipped, missing or unavailable required validation as success. Held telemetry or trusted-policy changes are not qualified merely because another component passed. A tag does not resolve a held runner-placement approval.

After that qualification, root may use ordinary Git against the fixed commit:

```sh
# RELEASE_VERSION and QUALIFIED_SHA come from the reviewed release decision.
git tag -a "$RELEASE_VERSION" "$QUALIFIED_SHA" -F "$REVIEWED_RELEASE_NOTES"
git push origin "refs/tags/$RELEASE_VERSION"
```

These are instructions, not an automatic publisher. Confirm the remote tag is absent first. If it already resolves to the same commit, use the existing tag; if it points elsewhere, stop and choose a new version through normal release ownership. Never force or move a tag, create a floating major alias, or silently replace a GitHub release. Re-read the published tag and peel annotated objects to the expected commit. Preserve that receipt alongside the exact qualification references and compatibility notes. GitHub release prose may be published by the same owner after tag verification; it cannot change the tag's meaning.

## Pin-bump path

1. Root names the exact qualified shared SHA, affected components and consumers. Check live consumer pins before editing. The initial inventory found Core services using planner `0d66f84d025a2792932c37f3bc3866ba407a7b8d` and Vagaris PR validation using `451ce35d4919686ed9df08df87a095bf85d7e647`; these are historical observations, not future desired pins.
2. Supply the existing reviewed qualification input and its independently recorded SHA256. The small adapter below binds a candidate to external qualification and review references. Those strings are references, not credentials or proof that the tool authenticated an approval.
3. Produce a read-only diff plan for explicit files/components. A real version comment is emitted only after the remote tag resolves to the requested exact SHA. Without a tag, retain `# main`. `uses:` still points to the full 40-hex SHA, never the tag.
4. The owning lane reviews and applies the change through its normal checkout, hooks and PR. Re-read and compare the original file hashes before application. Preserve explanatory comments manually when the tool refuses an unfamiliar annotation.
5. Update companion inputs through their existing owner/generator: Core's shared-impact action reference and source/workflow/config digests, generated trusted workflows via `trusted/render.py`, and any consumer vendor manifest. The helper does not silently rewrite these policy authorities or claim its line edits are the complete adoption.
6. Run the existing RU-02 ratchet and affected consumer tests. Required merge-group verification, exact-candidate evidence and release gates remain intact. Record shared SHA/tag, consumer commit, checks, compatibility result and rollback pin. Root performs any separately governed ruleset re-pin.

A rollback is a reviewed consumer PR restoring the previously qualified SHA and its companion bindings. The shared tag never moves. Neither publishing nor consuming a shared workflow inherits public-repository runner authorization for private callers.

## Read-only helper

`distribution/shared_ci.py` uses existing `gh` authentication for GET-only tag metadata. It never tags, writes a consumer, starts CI, publishes, or grants authority. Its GitHub reads and explicit input files are bounded. Qualification authentication remains the existing Evidence/release-owner responsibility; the output explicitly states `qualification_verified_by_this_tool: false` and `authorization_evaluated: false`.

The planner recognizes ordinary block-style `jobs.<job>.uses`, `jobs.<job>.steps[*].uses`, and composite `runs.steps[*].uses` references. It preserves literal/folded shell bodies, heredocs and multiline scalar data. Reference-bearing flow mappings, aliases, quoted mapping keys, multiline `uses` values and unfamiliar annotations require an owner edit rather than a guessed rewrite. It does not parse or validate arbitrary YAML, and normal workflow validation remains required.

Qualification and consumer input reads open non-following, nonblocking file descriptors, reject nonregular files (including FIFOs), cap bytes, and detect file replacement or mutation. Consumer descendant paths are opened relative to directory descriptors, with no symlink traversal. The explicitly selected root directory is canonicalized once. Loop deadlines do not promise to interrupt an operating-system stall on a remote filesystem.

The external reviewed input adapter has exactly these fields:

```json
{
  "schema_version": 1,
  "repository": "vagarylabs/.github",
  "candidate_sha": "<actual exact qualified SHA>",
  "qualification_ref": "<existing durable qualification record reference>",
  "review_ref": "<existing owning review reference>"
}
```

These placeholders are not valid release evidence. Root uses actual record references and the input's reviewed SHA256; the helper rejects changed bytes or a different candidate. Do not accept its output as a qualification service or use a caller-written input to bypass release review.

```sh
python3 distribution/shared_ci.py \
  --qualification "$REVIEWED_QUALIFICATION_INPUT" \
  --qualification-sha256 "$REVIEWED_INPUT_SHA256" \
  --sha "$QUALIFIED_SHA" --tag "$PUBLISHED_VERSION" \
  --consumer "$CONSUMER_CHECKOUT" --path .github/workflows/services.yml \
  --component actions/change-impact-plan --from-sha "$OBSERVED_OLD_SHA"
```

Omit `--tag` while no real tag exists. The JSON result contains patches and original file hashes, not an applied change. No automatic pin refresh is introduced, and it never runs another full suite just to discover an unchanged component.

Offline tests use only fixtures:

```sh
python3 -m unittest discover -s distribution -p 'test_*.py' -v
```

Wire these into the existing five-minute `planner-tests` job through its owner's reviewed hunk; no new workflow, runner, permissions, secrets, cache or artifact upload is needed. Native qualification of this helper and the eventual first shared release remains separate from these offline controls.
