# Refresh a selected-source workspace without discarding local edits

`fg_source_workspace.mjs refresh-preview` and `refresh` advance a private editing
materialization to another independently selected commit. This addresses the
working-copy gap between same-commit expansion and exact-draft replay: clean
selected files can update while non-conflicting local content, modes and
selected deletions survive. The same refresh can add independently selected
files, including dependencies introduced in the new source, without first
obtaining another package for the old commit. Related work: FG-026 and the
TreeFS/agent bridge.
This external trusted-local adapter does not complete native TreeFS.

## Review, then create a refreshed workspace

Obtain another selected-source package and an independent expectation using the
existing source package workflow. Retain all regular-file paths selected in the
original workspace, unless explicitly selecting and proving their source deletion
as described below, in the same native hash domain, at a different commit. The
new expectation may also select additional regular files at that commit.
The next expectation is never inferred from the package. Keep all inputs and
parent directories owner-private, as in `SOURCE_EDITING_WORKSPACES.md`.

```sh
node scripts/fg_source_workspace.mjs refresh-preview \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json
```

Review the returned plan, especially the old/local/selected/result byte hashes,
lengths and executable modes for each path. Retain `refresh_sha256` independently.
Newly selected paths have disposition `added`, a null `before` image and a null
`local` image. The null `before` means the path was not selected in the original
workspace; it does not claim that the path was absent from the original Git tree.
The null `local` records checked absence in the original editing directory.
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

Refresh re-verifies both source selections and re-reads every selected local
path, including absence checks for newly selected paths and their ancestors.
The complete plan must match the approved hash BEFORE output is
created. A different source package, commit, local content, mode or deletion
requires a new preview. The new directory must be absent and disjoint from the
original. The original workspace is never overwritten or removed.

A newly selected path already occupied locally refuses, even when its bytes
match the new source. A file or symlink in a required ancestor position also
refuses. Existing private directories may hold newly selected files; unrelated
local siblings remain only in the original workspace. File/directory conflicts
within the combined selection refuse before local content is read. These
observations are rechecked before output ownership and before the final manifest.

## Refresh when the new source deletes a selected file

Use `--deletions PRIVATE_SELECTION` on both refresh commands to name source
deletions deliberately. The private JSON file has this closed format:

```json
{
  "schema": "frankengit-workspace-refresh-deletions-v1",
  "paths_hex": ["7372632f6f6c642e7273"]
}
```

The example path is `src/old.rs`. List byte paths in ascending hex order, without
duplicates. The list must contain **every originally selected path omitted from
the next expectation, and only those paths**. A locally deleted file still
present in the new source belongs in the positive expectation, not this list.
Omitting `--deletions` retains the existing requirement to select every original
file and preserves existing refresh-plan bytes.

```sh
node scripts/fg_source_workspace.mjs refresh-preview \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --deletions /srv/review/deletions.json

node scripts/fg_source_workspace.mjs refresh \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --deletions /srv/review/deletions.json \
  --approve-refresh-sha256 "$REVIEWED_REFRESH_SHA256" \
  --output /srv/refreshed-editing
```

The next package must prove each deletion from its complete, hash-verified parent
trees at the independently selected new commit. A missing package entry, missing
tree proof or HTTP error does not prove absence. If a parent directory survives,
each directory needed to reach the deleted path must already be authenticated by
the package's positively selected files. Select a surviving sibling in that
directory as an anchor. If an earlier ancestor itself is absent, its authenticated
parent can prove the entire missing path without inventing a subtree. An opaque
surviving directory refuses; this option does not broaden the package grammar or
fetch additional source automatically.

**At least one positive successor file is required.** An empty successor package
or a completely empty repository remains outside the existing selected-source
package profile. The combined positive-file and deletion selections share the
32-path and path-byte limits. File/ancestor collisions across the two selections
refuse, including replacement of a deleted file with a directory in the same
refresh.

An unchanged local file takes the verified deletion (`deleted`); a file already
deleted locally converges (`converged`). Local content or executable-mode changes
against source deletion produce `local_modify_source_delete`, even with the text
merge profile. Use the existing explicit resolutions to choose `selected` for
deletion or `local` to preserve the complete local bytes and mode. Preview and
approve the resolved plan with the same `--deletions` and `--resolutions` files.
The reviewed plan binds the deletion selection and each concrete absence witness,
along with the original, local and resulting images.

A preserved local file is a new local creation against the new source baseline.
It is absent from the immutable positive-file manifest, so ordinary `status`
does not list it. Select its path explicitly with `capture` (or use the opt-in
workspace scan) to create a new source draft; capture re-verifies its absence
from the retained next package. The result remains an ordinary v1 workspace and
its capture can be inspected offline. These extra local files share the same
file-size, aggregate output and filesystem recheck limits as all other outputs.

## Default exact reconciliation, not a text merge

- A locally unchanged file takes the selected source version.
- A newly selected file with checked local absence takes its independently
  verified source version. It is not a three-way merge or an adoption of an
  untracked local file.
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

Only the explicitly selected paths are read and copied. UNSELECTED LOCAL FILES REMAIN
IN THE ORIGINAL WORKSPACE; do not delete it assuming this is a complete checkout
migration. Removing an originally selected path requires the explicit deletion
selection and verified source absence described above. A locally deleted file
still present upstream must remain in the positive source expectation.
No directory walk or automatic source fetch occurs.

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
The expansion suite imports the complete production workspace and shared
commit/tree/blob membership verifier. Independently framed SHA-1 and SHA-256
packages exercise additional selections, retained local edits and deletions,
local collisions, path topology, stale approvals, interrupted publication and
resource limits. It uses actual private POSIX files and does not substitute the
verification or publication functions. It does not invoke a native server or
establish repository authority.

The deletion suite also imports the production verifier and capture engine. Real
SHA-1 and SHA-256 packages cover deletion and convergence, local edit/mode
conflicts, preserved local recreations with offline capture inspection, nested
absence witnesses, extant-file and opaque-parent refusals, caller-owned input
mutation, stale reviews, combined limits, deadlines and late filesystem changes.
The production CLI is exercised with deletion, resolution, merge-profile and
timeout options together, including private-file enforcement.

The existing reconciliation suites execute the complete production workspace and command bodies and the
unchanged POSIX custody helper with actual private files, child processes, modes,
links, racing creators and interruptions. Its pre-existing source/codec imports
are explicit contract fixtures: these tests DO NOT execute the native membership
verifier, full Git tree derivation, Rust fg, server admission/CAS or the complete
workspace. They do exercise the new reconciliation, plan consent, file custody,
root-last output and CLI composition; there is no fixture replacement of those
function bodies. This is not a native TreeFS or independent verification claim.

The separate discovered [native workspace lane](../scripts/e2e/suites/operator/source_workspace.sh)
now exercises this existing API with actual native source packages in both hash
domains. An explicitly leased native bundle update advances the branch while the
original editing workspace remains. A separately staged stale proposal receives a
canonical refusal; its original-key recovery preserves that decision. Explicit
index maintenance follows the refusal because an unchanged ref does not imply an
unchanged authority head.

The new source package is independently selected and read through native HTTP and
Rust `verify-read`. Default refresh exposes both content conflicts. The explicit
line profile combines disjoint text and mode changes, while a local deletion
against changed upstream binary content still requires a reviewed choice. Old
approval and changed-editor-image controls refuse before output creation. The
fresh workspace preserves selected edits and leaves unselected local files in
the original; the independently checked publication preserves upstream siblings.
After local terminal records are moved aside, outcomes-only recovery reproduces
both the new commit and historical refusal without another mutation. This adds
native evidence for the existing API, not new refresh semantics, current-source
binary qualification or complete operator/TreeFS acceptance.

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
