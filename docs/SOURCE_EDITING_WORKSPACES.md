# Edit selected verified source with ordinary local tools

`fg_source_workspace.mjs` materializes a selected-source package into a private
editing directory. It is an external trusted-local adapter for the authoring
workflow, not the native TreeFS runtime, a Git checkout, a complete repository,
a process sandbox, or another authority store. It never executes source or
opens a network connection. The package's commit/tree/blob verifier is reused
unchanged. Native source preparation and admission remain the publication engine.

## Create and reopen

Use Node 22.16.0 or later on a POSIX host. Start with the source package and an
independently chosen expectation from `SELECTED_SOURCE_PACKAGE_OPERATOR.md`.
The expectation has `{format, commit, files: [{pathHex, blob}]}`. Keep it separate
from the server or package's assertions; this tool cannot establish how you
obtained that trust anchor.

```bash
umask 077
node scripts/fg_source_workspace.mjs create \
  --package /private/session/source-package.json \
  --expect /private/session/independent-expectation.json \
  --output /private/session/editing
```

The output directory must not exist. Input files must be bounded, owner-private
regular files with one link, inside real owner-private `0700` directories. No
symlink aliases are accepted. The returned `workspace_sha256` pins the exact
last-written `manifest.json`. Retain that hash independently of the workspace.
The root contains immutable baseline inputs `source.json` and `expected.json`,
the manifest, and a mutable `files/` directory. Only selected files and their
parent directories are materialized. Unrelated subtrees are not fetched or
expanded. Sibling metadata already present in the proof remains in source.json.

Edit `files/` using your own trusted editor. Regular files have mode `0600` and
executable files `0700`; directories have mode `0700`. New/replacement files
must remain private. The tool never runs an editor, executable file, Git hook,
source script, build command, or Git subprocess. Arbitrary file bytes, including
binary bytes, are preserved in the materialization. Linux also preserves
non-UTF-8 filename bytes. The macOS sparse-directory profile refuses invalid
UTF-8 names with `source_workspace_host_path_unrepresentable` before acquiring
an output directory, including when a later selected path is unrepresentable.
It checks the original bytes without decoding or normalizing them; no escaped
materialization profile is implied. Other host alias/collision checks still
apply to representable names. Binary change capture requires the explicit profile described below.

```bash
node scripts/fg_source_workspace.mjs status \
  --workspace /private/session/editing \
  --sha256 "$RETAINED_WORKSPACE_SHA256"
```

Reopening verifies the root against that external pin, checks both stored input
hashes and sizes, and redoes commit membership and full blob verification. A
rewritten success flag or a self-consistent replacement baseline cannot pass the
original pin. Status reads only the originally selected file paths and reports
unchanged, modified (including mode changes), or deleted. It does not recursively
scan or report files outside that selection. The baseline is never changed by
editing, inspection or a missing local file.

## Capture explicit local paths into a portable authoring draft

After editing, supply an explicit path selection. For example, this selects
`src/main.rs` and `new/file.rs` (including a possible new file):

```json
{"paths_hex":["7372632f6d61696e2e7273","6e65772f66696c652e7273"]}
```

```bash
node scripts/fg_source_workspace.mjs capture \
  --workspace /private/session/editing \
  --sha256 "$RETAINED_WORKSPACE_SHA256" \
  --paths /private/session/paths.json \
  --output /private/session/captured-change
```

Capture verifies the immutable baseline first and reads ONLY those mutable local
paths. It skips unchanged files, records replacements and mode changes using
exact bytes, and records missing selected originals as deletions. New paths must
be proved absent in the original commit before their local bodies are opened;
omitted original source and unexamined directory contents are not proof of
absence. A new selected file must exist locally. Physical moves can be captured
by explicitly selecting both the old and new paths; this records deletion plus
creation, without claiming inferred rename intent. No glob, ignore file, directory
walk, source script or discovered filename can widen the selection.

The complete existing authoring kernel builds the patch, verifies old blob
identities, proves creations, and independently derives the entire expected root
tree. Its 32-effect, 1 MiB file/patch and 4 MiB before/after byte limits still apply.
Without explicit opt-in, changed NUL-bearing files are refused. Unchanged binary
files may remain selected without becoming patch effects. Include
`"byte_profile":"binary-safe-v1"` beside `paths_hex` in the path selection to
capture arbitrary regular-file bytes. This choice is copied into changes.json,
bound into the reviewed draft and capture root, and checked again on reopening;
see `BINARY_SOURCE_AUTHORING.md`. The default captures keep their existing bytes. No-change and missing-new-file selections refuse
without claiming an output slot. All observed files and parents are checked again
after hashing; quiesce editors first, since this remains a non-atomic filesystem
observation. Once captured, owned bytes—not subsequent edits—determine the draft.

The create-only output contains `source.json`, `expected.json`, `paths.json`,
`changes.json`, `patch.diff`, `draft.json`, and the last-written `manifest.json`.
Retain the returned `capture_sha256` independently. `draft_sha256` is the exact
existing authoring draft hash, and `expected_tree` is the independently derived
candidate root. A capture is self-contained: later workspace deletion does not
prevent replay. It contains the FULL original selected-source package, including
unchanged baseline bodies and parent-tree sibling names, not just changed files.
Keep the capture private even when its change selection is smaller.

```bash
node scripts/fg_source_workspace.mjs inspect-capture \
  --capture /private/session/captured-change \
  --sha256 "$RETAINED_CAPTURE_SHA256"
```

Offline inspection rechecks every fixed payload and its hash, reconstructs the
original workspace commitment, re-verifies the source package, regenerates the
exact patch/draft and expected tree, and checks the selected-path accounting.
Self-consistent rewritten local hashes are not substitutes for regeneration.
The root is a content/provenance binding, not permission, freshness or evidence
that an authority published anything.

Review `changes.json`, `patch.diff` and `draft.json`. The saved inputs work with
the EXISTING authoring CLI, without reading live editor files again:

```bash
node scripts/fg_source_changes.mjs prepare \
  --package /private/session/captured-change/source.json \
  --expect /private/session/captured-change/expected.json \
  --changes /private/session/captured-change/changes.json \
  --selection /private/session/independent-native-target.json \
  --token-file /private/session/read-token \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --output /private/session/candidate
```

Select the native endpoint, namespace, branch, base and metadata independently as
in `SOURCE_CHANGE_AUTHORING.md`. Its `paths_hex` must name the actual effects in
`draft.json`, not every unchanged path examined by capture. Then use the explicit
verified staging command in `VERIFIED_SOURCE_STAGING.md` with the captured source,
expectation and changes, and separately invoke the unchanged apply/recover owner.
Neither create, capture, status nor inspect-capture accepts credentials or makes
network requests. Preparation and staging do not automatically apply anything.
Never create a new publication journal to retry an ambiguous existing one.

## Local integrity and limits

The materialization is bounded to 32 files, 1 MiB per file, 8 MiB of logical
selected bytes, 32 KiB of repository path bytes, 64 path components and 255 bytes
per component. Package/proof limits still apply independently. Input/output paths
for the workspace root are normalized absolute local paths. Repository names
remain validated byte paths, with `.git` (case-insensitive), traversal, NUL,
duplicate and file/ancestor collisions refused. File creation is exclusive; an
alias/collision on the host filesystem cannot overwrite a previous file.

Reads validate every existing parent, refuse non-regular files, symlinks,
hardlinks and non-private modes, and open final files without following links or
blocking on FIFOs. Per-file descriptor/name checks surround bounded reads. A
second metadata check covers every observed file and parent, including missing
paths. Quiesce editors before capturing a set of files: this detects ordinary
concurrent changes but is not an atomic multi-file filesystem snapshot, hostile
same-user protection, openat2 confinement, or a sandbox against parent replacement.
No source is executed by the adapter, but separately invoked editors/tools have
their own ambient permissions and may interpret untrusted repository content.

Creation verifies source before taking a create-only output slot. It writes and
syncs baseline inputs and materialized files, reads them back, syncs directories,
and writes the manifest last. Interrupted slots are retained and cannot be
silently reused. A slot without its valid manifest is incomplete. There is no
automatic cleanup, overwrite, lease repair, rollback or resume-from-partial mode.
After root publication starts, local sync/readback drains; a lost reply or late
stop does not establish that output is absent. These are filesystem API
observations, not universal power-loss or hardware durability guarantees.

Every command accepts `--timeout-ms 1..300000` (default 30000). Checks span
input reads, verification and local work; an already-started operating-system
write/sync is drained, not detached. Exit codes: 0 complete; 2 refusal; 3 stop
before output ownership; 4 retained result or uncertain local publication. After
exit 4 retain the reported path and hash, and inspect rather than overwrite.
Errors do not echo source bytes or parser/OS diagnostics.

## Verification

`bash scripts/verify_source_workspaces.sh` runs complete production JavaScript
modules against actual files and CLI child processes. It covers both Git hash
domains, raw paths, executable/empty/binary bytes, sparse materialization,
independent pins, corruption, link/permission refusals, racing creators, mutable
inputs, interrupted slots and lost stdout. Capture tests additionally exercise
actual edits, independent absence, selected-path isolation, self-contained offline
replay, complete existing authoring CLI preparation/staging, and lost-response
original-key recovery with no second upload. HTTP/TLS peers use native schemas
and real test-only Git-generated candidates, not a running Rust server. The lane
also runs all existing source-authoring regressions. It does not run Rust `fg`, native
TreeFS, policy/CAS, hostile tools, real browsers or the full workspace. This
external consumer advances the selected-source-to-edit workflow; it does not
close FG-026 or the broader agent-execution beads.

### Explicit byte and patch profiles

The path-selection file may include `byte_profile: "binary-safe-v1"` and/or
`patch_profile: "trim-common-lines-v1"` / `"bounded-line-hunks-v1"`. Both are closed, independent choices,
retained in the capture and checked against its saved change request on reopen.
Omit both for unchanged text/full-file defaults. A one-line change in a large
file can use compact encoding without raising the patch-byte ceiling; changed
binary files require separate binary consent. The standard authoring consumer
requires the exact draft hash produced for those choices. See
`BINARY_SOURCE_AUTHORING.md`, `COMPACT_SOURCE_PATCHES.md`, and
`MULTI_HUNK_SOURCE_PATCHES.md`.
