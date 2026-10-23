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
methods retain their old behavior. The CLI selects the new owner only through
`fg patch prepare --profile exact-tree-binary-v1`. This grants no publication
authority or new remote authorization.

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

## Author, prepare and publish separately

The offline author opts in independently of the native preparer:

```sh
node scripts/fg_source_refactor.mjs compile \
  --plan-file /private/edit/refactor.json --output /private/edit/refactor.patch \
  --profile exact-tree-binary-v1 --binary delta

fg patch prepare NODE TENANT REPOSITORY refs/heads/main \
  /private/edit/refactor.patch /private/edit/candidate.bundle \
  --trusted-local --profile exact-tree-binary-v1 --workspace-id WORKSPACE_ID \
  --expected-base BASE_OID --expected-result-tree INDEPENDENT_RESULT_TREE \
  --author 'Author <author@example.invalid>' --timestamp TIMESTAMP \
  --message 'Reviewed binary refactoring'
```

The private plan remains `frankengit-source-refactoring-v1`; the explicitly
selected author receipt is `frankengit-source-refactoring-binary-v1`. The default
and explicit `exact-tree-v1` retain the historical refusal and bytes. Edited
binary moves additionally require `--binary literal`, `delta` or `delta-runs`;
no encoding is silently selected. Both directions reuse the existing bounded
encoder, with no source lookup or rename guessing. The old whole-replacement
compiler rejects the new `nativeProfile` option instead of accepting it globally.

`--expected-result-tree` constrains the complete result before output, including
untouched siblings. The authored plan and patch are not approval. Review the
exact candidate and use normal `fg patch apply` with its expected commit/base,
principal and original idempotency key; apply does not accept a profile flag.
Output remains create-only, synchronized and read-back verified. Lost stdout
cannot authorize deleting a bundle, choosing a new request identity or rerunning
against a newer base. The existing three native profiles remain unchanged.

With prebuilt `FG_BIN`, `scripts/e2e/suites/smokes/source_binary_refactor.sh`
executes the actual Node author and Rust native node in both hash formats using
literal, common-ends delta and aligned-run delta encodings. It independently
constructs whole expected trees, raw names, modes, blobs and candidate commits
before preparation, then inspects native bundles. The fixture combines binary
and text moves, binary edits, addition/deletion and untouched siblings. It checks
legacy refusals, exact input limits, corrupt reverse images, occupied targets,
late-file errors, wrong result roots, lost stdout, ordinary publication and
source-free original-outcome recovery. Node executable/version and native binary
digests are reported. This is not the full live-HTTP/operator qualification bead.
