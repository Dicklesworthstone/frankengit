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
binary bytes and non-UTF-8 POSIX filenames, are preserved in the materialization;
this does not add binary editing to the separate exact-patch authoring profile.

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
inputs, interrupted slots and lost stdout. It does not run Rust `fg`, native
TreeFS, policy/CAS, hostile tools, real browsers or the full workspace. This
external consumer advances the selected-source-to-edit workflow; it does not
close FG-026 or the broader agent-execution beads.
