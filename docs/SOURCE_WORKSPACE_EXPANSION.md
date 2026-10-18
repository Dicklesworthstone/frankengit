# Expand selected source without resetting local edits

`expandSourceWorkspace` adds independently selected source to an existing private
editing workspace at the SAME immutable commit. It creates a new workspace and
never modifies the original. This supports discovering additional inputs while
an editor or agent already has changes in progress; it is not branch refresh,
rebase, a complete checkout, a process sandbox or native TreeFS execution.

## Command-line workflow

Obtain the additional selected-source package separately at the original pinned
commit, using the existing source acquisition workflow. The additional expectation
must name exactly the files being admitted; it may overlap already selected paths.
Pause local editors before taking the copy, then run:

```bash
node scripts/fg_source_workspace.mjs expand \
  --workspace /private/session/original \
  --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /private/session/additional-source.json \
  --expect /private/session/independent-additional-expectation.json \
  --output /private/session/expanded
```

Retain the returned NEW `workspace_sha256`. Continue editing `expanded/files/`.
The original workspace and old hash remain valid and are never overwritten. Both
package inputs and all output parents obey the same private POSIX rules as create.
The command accepts only these arguments plus `--timeout-ms`; it has no token,
network, force, automatic discovery, merge or retry option.

```bash
node scripts/fg_source_workspace.mjs status \
  --workspace /private/session/expanded --sha256 "$EXPANDED_WORKSPACE_SHA256"
node scripts/fg_source_workspace.mjs capture \
  --workspace /private/session/expanded --sha256 "$EXPANDED_WORKSPACE_SHA256" \
  --paths /private/session/explicit-changed-paths.json \
  --output /private/session/new-capture
```

Capture still requires explicit paths and explicit binary/compact profiles.
Review the resulting draft and use its new hash with `prepare-packed`,
`inspect-packed` and `stage-packed` from `PACK_VERIFIED_SOURCE_FLOW.md`. Those
commands recheck the combined source, whole-tree effects and actual packed
objects. They do not inherit prior review consent. Publication and original-key
recovery remain separate existing commands, with the unchanged journal format.
Additional expansions can use the newly created workspace and its new pin.

Exit 0 reports a completed expanded workspace. Exit 2 is refusal; exit 3 is a
cancellation without claimed output; exit 4 retains a completed or uncertain
output identity. A lost result on stdout does not erase a successfully written
workspace. The manifest pins immutable source, not subsequent editor activity.

## Library consumer

```js
import { expandSourceWorkspace } from './scripts/operator/source_workspace.mjs';

const result = await expandSourceWorkspace(
  originalDirectory, retainedWorkspaceHash,
  additionalPackageBytes, independentAdditionalExpectation,
  absentOutputDirectory, { timeoutMs: 30000 },
);
// Keep result.workspace_sha256 independently. The new directory uses the same
// source.json / expected.json / manifest.json / mutable files/ layout as create.
```

The additional expectation has the existing `{format, commit, files}` schema,
with sorted `{pathHex, blob}` entries. It must be chosen independently, not copied
from untrusted package assertions. The original retained workspace hash continues
to pin the old expectation. Both packages must verify independently before they
are combined; a missing proof or body in one input cannot be repaired by the
other. They must name the same native hash domain and commit. Matching overlapping
selected files and parent-tree paths are deduplicated; distinct paths referencing
identical subtrees keep distinct membership entries. Overlapping content must
also match byte-for-byte. Source packages are content proofs, not repository
ownership, live branch freshness, permission or signature proofs.

The standard source-package verifier checks the combined package again, including
combined file, logical-byte, tree, entry and encoded-byte budgets. The result is
an ordinary source package and expectation, not a new source format or authority.
`mergeSelectedSourcePackages` in `source_package_union.mjs` exposes this same pure
bounded operation for external consumers; it has no filesystem or network I/O.

## Preserved work and explicit limits

Every originally selected local file is observed. Its exact edited bytes and
executable mode are carried into the result; a deleted original remains deleted.
Newly selected files are materialized from their verified immutable source bytes.
If any newly selected path is already occupied in the original local workspace,
expansion refuses rather than discard potentially untracked work. The additional
package must add at least one selected path. It cannot silently drop old paths.

Only original and explicitly added paths are examined. Unselected local files,
including newly created but uncaptured files, are NOT copied or scanned. They
remain untouched in the original workspace. Capture such work explicitly using
the existing capture command before retiring that original. Expansion does not
infer renames, execute source, discover paths, fetch data, follow links, refresh
credentials or transfer a previous publication journal.

Both source inputs are copied before asynchronous work. Editors should be paused:
the operation rechecks all observed local files and parents before claiming the
output and again before publishing its manifest, but does not take an atomic
filesystem snapshot. A detected edit refuses; it does not silently recapture a
later version. The trusted-local POSIX profile excludes hostile same-user parent
replacement. Public files, hardlinks, symlinks and unsafe parents refuse using
the existing workspace custody rules.

Original files, the baseline package and the original manifest are not written.
The output is create-only. Data and parent directories are written, synced and
read back before the final manifest. Interrupted output slots are retained, not
deleted or reused. Once final manifest publication starts, it is drained even
on a late stop. A returned `publication_unconfirmed` identifies output that may
exist; neither cancellation nor lost stdout proves absence.

The returned expansion context identifies the original workspace hash and both
source/expectation hashes, the added paths and preserved/deleted selected counts.
This context is not part of the unchanged workspace-v1 manifest: that manifest
pins the expanded immutable baseline, not the mutable editor files or a chain of
edit history. Save the returned context separately when provenance is needed.
Ordinary status and capture can reopen the new workspace after the old one and
additional input paths are removed; later edits to either directory do not
propagate to the other. Expanded captures require freshly reviewed draft hashes.

Existing limits are not raised: at most 32 selected files, 1 MiB per materialized
file, 8 MiB logical baseline AND 8 MiB materialized working bytes, 32 KiB selected
path bytes, 128 proved trees and 4 MiB parent-tree bytes. Each encoded package is
at most 32 MiB; both inputs, decoded values, union and working bytes coexist, so
this is not a streaming-memory claim. One deadline spans verification, reads and
local publication (1..300000 ms, default 30000). Current default creation bytes and
manifest hashes remain unchanged.

Run `bash scripts/verify_source_expansion.sh`. Tests use complete production
modules, actual private POSIX files and CLI processes in both native hash domains.
The integration tests run expansion through binary multi-hunk capture, packed
preparation/inspection/staging, and original-key lost-response recovery after
external files are removed. HTTP/TLS peers are native-schema fixtures with
test-only Git-generated objects, not a running Rust fg server. These tests do not
establish native Rust TreeFS, authority/admission/CAS, complete repository closure,
physical power-loss durability, semantic compatibility or hostile-local isolation.
