# Refresh a selected-source workspace without discarding local edits

`fg_source_workspace.mjs refresh-preview` and `refresh` advance a private editing
materialization to another independently selected commit. This addresses the
working-copy gap between same-commit expansion and exact-draft replay: clean
selected files can update while non-conflicting local content, modes and
selected deletions survive. Related work: FG-026 and the TreeFS/agent bridge.
This external trusted-local adapter does not complete native TreeFS.

## Review, then create a refreshed workspace

Obtain another selected-source package and an independent expectation using the
existing source package workflow. Select the SAME regular-file paths as the
original workspace, in the same native hash domain, at a different commit.
The next expectation is never inferred from the package. Keep all inputs and
parent directories owner-private, as in `SOURCE_EDITING_WORKSPACES.md`.

```sh
node scripts/fg_source_workspace.mjs refresh-preview \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json
```

Review the returned plan, especially the old/local/selected/result byte hashes,
lengths and executable modes for each path. Retain `refresh_sha256` independently.
Preview performs no writes and creates no output slot. A conflicting preview
returns exit 1 and lists every conflicting selected file in byte-path order.
There is no automatic choice of a conflict side or insertion of conflict markers.

```sh
node scripts/fg_source_workspace.mjs refresh \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --approve-refresh-sha256 "$REVIEWED_REFRESH_SHA256" \
  --output /srv/refreshed-editing
```

Refresh re-verifies both source selections and re-reads the original selected
local paths. The complete plan must match the approved hash BEFORE output is
created. A different source package, commit, local content, mode or deletion
requires a new preview. The new directory must be absent and disjoint from the
original. The original workspace is never overwritten or removed.

## Default exact reconciliation, not a text merge

- A locally unchanged file takes the selected source version.
- A selected source file unchanged from the old baseline keeps the local edit
  or local deletion.
- Identical local and source results converge to the selected version.
- Content and executable mode are reconciled independently. A local content edit
  and source chmod, or local chmod and source content change, can coexist.
- Differing content changes on both sides, or local deletion against a changed
  source file, are conflicts. No hunk merge, fuzzy application or rename inference
  is performed by default. Binary/empty/raw-byte files use the same byte-equality rules.

For explicitly opted-in disjoint line merging inside a file, see
[SOURCE_WORKSPACE_TEXT_MERGE.md](SOURCE_WORKSPACE_TEXT_MERGE.md). The default
profile and its approval hashes remain unchanged.

The existing source verifier owns native commit/tree/blob validation. The refresh
adapter does not implement another Git decoder or use Git as a production helper.
No ancestry, branch freshness, semantic compatibility, authority or permission is
established. This can select an independently trusted non-descendant commit too;
review the new source accordingly. Prior draft/candidate consent does not carry
forward to the new baseline. Prepare and review subsequent changes normally.

## Output, scope and interruption

The new directory is an ordinary v1 workspace, usable by existing status and
capture commands. Its `workspace_sha256` pins its immutable NEW source baseline,
not subsequent editor writes. A separate `refresh.json` retains the reviewed
initial materialization plan; its independently retained `refresh_sha256` pins
those bytes. The existing writer syncs and reads back source and carried files,
then publishes `manifest.json` last. It rechecks the original observations before
ownership and again before completion. These are non-atomic filesystem checks,
not protection against a hostile same-UID process or hardware power loss.

Only originally selected paths are read and copied. UNSELECTED LOCAL FILES REMAIN
IN THE ORIGINAL WORKSPACE; do not delete it assuming this is a complete checkout
migration. Upstream deletion or addition of selected paths is not supported by
this profile: changing the selected population refuses rather than interpreting
omitted proof as absence. No directory walk or automatic source fetch occurs.

Bounds remain 32 files, 1 MiB/file, 8 MiB logical source/local/output bytes,
32 KiB path bytes, 64 components and 255 bytes/component. The combined result
also has an 8 MiB ceiling: independently bounded local and source inputs cannot
produce an unbounded merged output. The operation uses one cooperative deadline
(default 30 seconds, `--timeout-ms 1..300000`). Already-started filesystem
write/sync operations drain. A stop or error after output ownership retains the
slot and original pins; exit 4 reports possible/completed local output. Never
reuse or erase an uncertain output to make an automatic retry. Other failures
return 2, or 3 for cancellation before output; successful completion returns 0.

## Focused validation

Run `bash scripts/verify_source_workspace_refresh.sh`.
The suite executes the complete production workspace and command bodies and the
unchanged POSIX custody helper with actual private files, child processes, modes,
links, racing creators and interruptions. Its pre-existing source/codec imports
are explicit contract fixtures: these tests DO NOT execute the native membership
verifier, full Git tree derivation, Rust fg, server admission/CAS or the complete
workspace. They do exercise the new reconciliation, plan consent, file custody,
root-last output and CLI composition; there is no fixture replacement of those
function bodies. This is not a native TreeFS or independent verification claim.

## Resolve a conflicting file explicitly

A conflict need not force you to throw away the workspace or silently overwrite
one side. After a conflicting preview, create an owner-private choices file:

```json
{
  "schema": "frankengit-workspace-refresh-resolutions-v1",
  "plan_sha256": "ORIGINAL_CONFLICT_PREVIEW_SHA256",
  "choices": [
    {"path_hex": "7372632f6d61696e2e7273", "choice": "local"}
  ]
}
```

Replace the example hash with the original preview's `refresh_sha256` and select
actual conflicting byte paths. `local` chooses the complete local file including
its mode, or the local deletion. `selected` chooses the complete new source file
and its mode. The tool does not synthesize replacement contents, infer intent,
or accept `force`. A clean, unknown, repeated or unsafe path refuses.

Preview the explicit choices, then approve that NEW plan:

```sh
node scripts/fg_source_workspace.mjs refresh-preview \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --resolutions /srv/review/choices.json

node scripts/fg_source_workspace.mjs refresh \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --resolutions /srv/review/choices.json \
  --approve-refresh-sha256 "$REVIEWED_RESOLVED_PLAN_SHA256" \
  --output /srv/refreshed-editing
```

Choices pin the original unresolved plan, so a changed local image or new source
requires a new conflict preview and a new choices file. The resolved plan binds
the normalized choices as well as every resulting byte image. An original
unresolved-plan approval cannot authorize the resolved result, and omitting or
changing choices at application time does not preserve the resolved approval.
Input choice order is canonicalized; it does not change semantics or the hash.

Partial choices are permitted in preview, but `conflict_count` counts the
remaining unresolved files and `ready` stays false until all are resolved.
`resolved_conflict_count` and each `resolved_local`/`resolved_selected` entry
identify the deliberate choices. No partial workspace is published for unresolved
conflicts. The selected output still has the same aggregate byte ceiling.
`refresh.json` retains the exact choices under its separate refresh pin; it does
not authorize a repository change or carry forward old publication/retry keys.
Without `--resolutions`, original no-choice plan bytes and defaults are unchanged.

The same repository-owned test lane includes choice/consent tests for both hash
domains, binary data, deletions, mode preservation, partial plans, malformed and
stale choices, copied caller inputs, deterministic order, output capacity, and the
actual preview/resolution/refresh CLI bodies. Its source-service fixture boundary
is unchanged; these tests are not evidence of native Git membership or server
publication.
