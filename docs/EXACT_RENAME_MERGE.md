# Exact-identity rename merge preparation

`fgit_forge::preparation::prepare_merge_with_profile` adds an explicit
`MergeProfile::ExactRenamesV1` alternative to `PathMergeV1`. The original
`prepare_merge` entry point keeps its existing behavior and output bytes.
This is a bounded FG-029 merge-preparation capability, not a forge-completion
claim or a replacement for independent merge and publication verification.

The profile pairs one deleted regular file with one added regular file only
when their native content IDs match and the pairing is unique on that side.
It handles cross-directory moves, a rename combined with the opposite side's
content or executable-mode edit, and both sides moving a file to the same
path. Copies are not moves. Newly added siblings do not follow inferred
directory moves. SHA-1 and SHA-256 remain separate native domains.

All correspondence is derived from the actual unique merge base and the two
selected branch trees. Alignment creates ordinary Git tree bytes with NEW
native IDs; it never makes an original object ID resolve to modified bytes.
The existing path/content planner merges the aligned trees. Its original
content, binary, type and mode conflict rules still apply. Candidate commits
retain the original target/source parent order and original merge-base ID.
Only constructed objects reachable from the final tree, plus the final
commit, are returned. Intermediate alignment trees are not published.

## Refusals and bounds

Ambiguous deleted/added identity groups, divergent rename destinations,
rename/delete, an opposite-side type change, destination occupancy and
file/directory collisions refuse automatic preparation without a candidate.
Attribute-bearing source or destination scopes also refuse: moving a file
must not implicitly select or bypass a custom merge/filter interpretation.
The public `PreparationError::Rename` variants preserve typed diagnostics.

Discovery, alignment, reconstruction and final merge share the caller's
aggregate tree-entry and object/output limits. The exact-rename profile also
caps correspondence at 1,024 moves and cumulative retained path-key work at
8 MiB (narrowed by `max_output_bytes`). Depth and individual path bounds are
checked before construction. Source checkpoints cover discovery, alignment,
rebuilding and output pruning; cancellation exposes no partial candidate.
Indexing by native ID avoids a deleted-by-added quadratic similarity scan.

Original trees are read only through the caller's `MergeObjectSource`, whose
contract requires verified identity/kind, selection authorization and bounded
reads. The node integration must select one authenticated snapshot, validate
all generated objects and retain normal fresh-subject admission checks.
Preparation itself does not stage objects, seal a request, grant approval,
move a ref, or alter the canonical publication protocol.

## Scope and evidence

No similarity threshold, rename-with-content-change detection, copy tracking,
symlink/gitlink rename inference, directory-rename inference, attribute
execution or recursive virtual merge-base synthesis is claimed. A rename that
also changes its bytes is not inferred; ordinary path conflict rules apply.
Explicit conflict resolution under PathMergeV1 does not implicitly resolve an
ExactRenamesV1 refusal. The caller must edit/review a new candidate instead.

The focused Rust tests cover both hashes, cross-directory edits and modes,
actual original-parent bindings, unreachable virtual-tree exclusion,
rename/delete, divergent/ambiguous mappings, destination collisions, copies,
attributes/types, raw path bytes, empty trees, resource limits and cancellation
at every exercised source checkpoint. Rust compilation/tests were not run in
the editing environment because Cargo and rustc were unavailable. Independent
flat-path reference checks and source/patch integrity checks do not substitute
for native Rust or pinned real-client conformance evidence.
