# Node-owned exact rename preparation

FG-029's `OneNode::prepare_merge_bundle_with_profile_in` and
`OneNode::prepare_pull_request_bundle_with_profile_in` expose the existing
`fgit_forge::preparation::MergeProfile::ExactRenamesV1` through the real
embedded-node object reader, native validator and Git bundle writer. Existing
`prepare_merge_bundle_in` and `prepare_pull_request_bundle_in` retain the
PathMergeV1 default; there is no automatic retry with different semantics.

For a unique content-identical regular-file move on one side and a content
or mode edit on the other, the candidate carries the edit at the destination.
Correspondence, refusal and resource rules are owned by
[the existing exact-rename planner](EXACT_RENAME_MERGE.md), not duplicated in
node code. Similarity, copies, directory renames, custom drivers, and rename
conflict resolution are not added by this integration.

Both tips are selected from one authenticated head. The node verifies original
objects against its admitted closure and native hash, then independently
validates every generated object and the two-parent merge before packing it.
The PR surface first validates the exact open review subject and requires the
construction head to match that subject's head. A changed version, policy,
branch tip or closure cannot silently select a newer candidate.

Preparation stages no objects, seals no transaction, changes no ref and grants
no approval. The returned native commit/tree/bundle and original subject are
review material. The existing explicit bundle publication operation performs
its normal fresh-subject, policy, native-object and exact-head-CAS checks.
The merge profile is a construction choice, not a new publication authority
or a replacement for binding the exact candidate identity.

## Evidence and boundary

`crates/fgit-node/src/treefs_workspace/merge_prepare/rename_tests.rs` adds five
Rust regression tests over actual embedded-node source import, preparation,
PR metadata, native pack validation, canonical publication and exact retry.
They cover SHA-1/SHA-256, default byte preservation, a rename/modify conflict
that becomes clean only with explicit opt-in, retained edited bytes and parent
order, read-only preparation, stale/closed PR refusal, hidden refs, resource
limits and cancellation. These tests are authored, not reported as executed:
Cargo and rustc were unavailable in the editing environment. Source/blob and
patch checks do not replace compilation or native execution.

This is not full Git merge equivalence, an independently verified release
gate, or completed FG-029 acceptance. HTTP selection is a separate adapter
increment; the legacy endpoint must not advertise this profile until wired.
