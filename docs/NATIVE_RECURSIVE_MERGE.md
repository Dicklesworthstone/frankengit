# Native recursive merge preparation

`recursive-path-merge-v1` prepares exact-path merges when a history has more
than one best common ancestor. It supports both SHA-1 and SHA-256 repositories,
two-parent merge commits, squash commits, and native queue-prefix preparation.
Queue heads and prefixes retain their existing two-parent method.
It uses the same authority-selected object source and native publication path
as the existing profiles. Preparation remains read-only.

## Why the comparison base matters

A criss-cross history can have two incomparable best ancestors: one changes
file `a`, and another changes file `b`. Later tips can independently revert
those changes. Comparing against either ancestor alone can silently lose one
revert. The recursive profile combines the ancestors into a comparison tree,
then merges the final tips against that tree, preserving both reverts.

The existing `path-v1` / `path-merge-v1`, `exact-renames-v1`, and
`builtin-attributes-v1` profiles still require one best ancestor. Their defaults,
successful candidate bytes, and receipt formats are unchanged.

## Select the profile

For the [local preparation command](NATIVE_MERGE_PREPARATION.md), use
`--profile recursive-path-merge-v1`. All other repository, ref, metadata,
artifact, and trust arguments remain mandatory as documented there. Add
`--method squash` for a one-parent candidate.

The same profile token is available through these existing entry points:

| Entry point | Selection |
| --- | --- |
| `fg merge prepare` | `--profile recursive-path-merge-v1` |
| `fg queue prepare` | `--profile recursive-path-merge-v1` |
| PR, queue-head, and queue-prefix HTTP preparation | `profile=recursive-path-merge-v1` form field |
| PR and queue MCP preparation | `"merge_profile":"recursive-path-merge-v1"` |
| Pull-request and queue browser pages | Select `recursive-path-merge-v1` in the merge-profile control |
| Trusted workflow watch | `--merge-profile recursive-path-merge-v1` |
| HTTP service workflow watch | `--workflow-merge-profile recursive-path-merge-v1` |

The profile changes tree construction. It grants no review, check, merge,
workflow, or publication authority. Queue preparation retains the original
queue subjects independently of its projected merge targets.

## Deterministic construction and evidence

The planner computes all real best ancestors in native object-ID order. When
there are several, it folds them in that order. Each unequal-tree fold discovers
the ancestors of its own inputs and recursively constructs their comparison
tree. Request-local virtual graph nodes retain both parents, including when two
snapshots are identical; later folds therefore retain the ancestry of every
base already combined. No synthetic Git commit is created.

The final merge uses the resulting effective tree. Its existing `merge_base`
field remains the smallest real best ancestor, which the admission path can
independently prove is selected and common to both real tips. It is an ancestry
witness, not the source of the effective comparison tree.

Clean and final-conflict results also carry:

```json
"recursive_base": {
  "bases": ["<first real best ancestor>", "<second real best ancestor>"],
  "tree": "<effective comparison tree>"
}
```

The IDs use the repository's native hash format. The bases are nonempty,
strictly sorted, and distinct. A singleton-base recursive result also includes
this field. Older profiles and already-up-to-date results omit it. Queue-prefix
steps and final-conflict stops carry the same evidence; the prefix preparation
identity binds it and the selected profile.

The browser retains this preparation evidence alongside the independently
inspected candidate, and displays and exports it for review. Candidate
inspection verifies bytes, object closure, ordered parents, and the real
ancestry witness. It does not replay the preparation algorithm or independently
authenticate the informational effective-tree receipt.

Comparison-only generated trees and blobs are removed from the candidate
artifact. Generated content that the final tree actually references is retained.
The artifact and subsequent publication contain only candidate dependencies,
including earlier commits required by a prepared queue prefix.

## Refusals and limits

This is a bounded exact-path profile, not a claim of Git `ort` equivalence.
It does not combine recursive bases with rename inference or the built-in
attributes profile. The existing exact-path binary, symlink, gitlink, mode,
attribute-driver, and content-conflict rules apply at every fold and at the
final merge. Rebase and explicit conflict-resolution commands retain their
existing profile restrictions.

If combining the ancestors conflicts, preparation returns the typed
`RecursiveBaseConflict` refusal. HTTP and MCP expose the stable
`recursive_merge_base_conflict` error; HTTP uses status 409. There is no
candidate, partial bundle, or fallback to an arbitrary ancestor. A conflict
between the final tips instead returns the ordinary bounded conflict report,
with the real ancestry witness and effective-tree evidence.

Unrelated histories, unavailable objects, invalid graphs, and cancellation
remain refusals. The [ordinary preparation ceilings](NATIVE_MERGE_PREPARATION.md#finite-profile)
apply to the entire operation: initial and recursive graph queries, decoded
tree entries, content merges, generated objects, and constructed bytes. Recursive
depth and request-local virtual-node allocation are bounded too. Discarding a
comparison-only object does not refund its construction work. A queue prefix
shares these budgets across every entry. Resource exhaustion and cancellation
retain their transport error classifications when raised inside graph queries.

## Focused regression targets

The forge tests independently derive expected final and comparison trees for
criss-cross reversions, nested recursion, three bases, virtual content merges,
conflicts, cancellation, and aggregate limits. The file-backed node test covers
both hash formats and both commit styles through preparation, independent
inspection, atomic ref/PR/outbox publication, reopening, and original-key retry.

```bash
cargo test -p fgit-forge preparation::tests::recursive_base
cargo test -p fgit-forge recursive_prefix
cargo test -p fgit-node --test native_recursive_merge
cargo test -p fgit-node --test queue_prefix_preparation
node --test tests/browser/pulls-*.test.mjs tests/browser/queues-*.test.mjs
```

These are focused feature regressions, not the full Git compatibility or
production release qualification matrix. The introducing commit records the
execution limits; the presence of a regression target is not a passing result.
