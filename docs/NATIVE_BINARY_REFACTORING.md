# Explicit native binary relocation

The native patch owner now provides a separately selected binary-refactoring
profile. `UnifiedPatch::parse_with_binary_renames` accepts edited regular-file
moves with compressed Git literal or delta members. The old `parse`,
`parse_with_binary`, `parse_with_renames` and `parse_with_binary_and_renames`
entrypoints retain their admitted grammars; none silently opts into this feature.

`OneNode::prepare_workspace_binary_refactor_in` composes this parser with the
existing capability owner, verified native binary decoder, TreeFS intent log and
candidate exporter. `prepare_trusted_binary_refactor_in` is the corresponding
trusted whole-repository local-owner adapter. The existing patch-preparation
methods retain their old behavior. This is a library capability, not an automatic
publication or a new remote authorization boundary.

Every binary move names two explicit, original-coordinate paths. Both must be
readable and writable under the existing capability before file content is read.
The source must be an existing regular file with the selected mode; the target
must be absent in the original tree. Deletions elsewhere in a batch do not make
a target available. Duplicate endpoints, ancestor overlaps, chains, swaps,
symlinks, gitlinks and copies remain refused. Raw path bytes are not normalized.

Binary moves require full nonzero old/new native object identities in the
repository's hash domain and exactly two framed members: forward and reverse.
The pack crate remains the only decoder. It verifies original and resulting
Git identities, the reverse image, decompression and delta work against one
shared budget. A false `similarity index 100%` cannot bypass the byte-identical
claim. An empty result is a present empty file, not deletion. Mode changes are
independent of the binary image.

Preparation writes no repository refs or forge events. All changes must validate
and export before one candidate bundle is returned; an invalid later section
cannot publish half a move. Unedited siblings survive and emptied directories
are pruned by the existing TreeFS exporter. Publication uses ordinary reviewed
bundle admission with the original expected base, candidate, principal and key.
A fresh-process identical retry recovers that original outcome rather than
reapplying the move against a newer source. The local source need not still exist
once its exact candidate has been admitted.

No dependency, runtime, unsafe code, foreign Git engine or resource allowance
was added. Existing source/finalization, cancellation, visibility, aggregate
expansion and output limits remain mandatory. This is not hostile-code isolation,
remote authorization, a broad Git compatibility claim or whole-product completion.

## Focused evidence

`cargo test --locked -p fgit-diff --lib patch::` includes structural
profile/refusal, exact-budget and cancellation twins. These tests explicitly use
structural fixtures, not real compressed objects. Actual native integration is
covered by `cargo test --locked -p fgit-node --test workspace_binary_patch
--test workspace_patch`: independently encoded literals, captured Git delta
fixtures, old profile refusal, source/target/reverse identity failures, occupied
targets, late-file failure, mode and empty-file behavior, both-path capabilities,
hidden refs, cancellation, exact result trees, ordinary publication and reopened
original-outcome recovery in SHA-1 and SHA-256. These are focused tests, not full
workspace, release, physical-power-loss or hostile-isolation qualification.
