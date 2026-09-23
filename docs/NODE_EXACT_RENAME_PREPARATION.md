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
gate, or completed FG-029 acceptance. The HTTP adapter below is
connected to these same node methods, not a second merge implementation.

## Authenticated HTTP selection

The existing body-bearing read endpoint
`POST /<repository>/api/v1/pulls/<number>/prepare` accepts the optional form
field `profile`. Omit it or send `profile=path-merge-v1` for the unchanged
legacy behavior. Add `profile=exact-renames-v1` to the existing explicit
subject/metadata form to select exact-content rename alignment. The original
object format, PR version, policy epoch, source/target refs and tips, author,
committer, timestamp and message remain required. Unknown values, empty values,
extra fields and duplicate selections are refused, never silently downgraded.
The maximum form byte size is unchanged; the field-count ceiling admits only
one extra profile selector.

One credential must still carry both fetch (`read`) and `pulls-read` grants.
Authentication, repository binding, HTTP body framing, exact subject validation,
quotas, cancellation and response byte limits remain the existing boundaries.
An `Idempotency-Key` is still rejected because preparation is not a transaction.
The response's `profile` field names the selected semantics for clean,
conflicted and already-up-to-date results. Clean results retain the existing
JSON-plus-binary-bundle multipart transport and exact candidate identities;
ordinary default responses retain their original bytes.

The existing `/resolve` endpoint remains exact-path resolution only and rejects
`profile` rather than reinterpreting choices against renamed comparison trees.
It is not an automatic fallback from a rename refusal. Rename-specific failures
return HTTP 409 with distinct stable codes:

| Cause | Code |
|---|---|
| Multiple possible exact-content matches | `rename_identity_ambiguous` |
| The two sides choose different destinations | `rename_destinations_diverge` |
| Move on one side, deletion on the other | `rename_delete_conflict` |
| A destination is occupied | `rename_destination_occupied` |
| An entry is unsupported by the rename profile | `rename_entry_unsupported` |
| Attributes prevent safe automatic interpretation | `rename_attributes_require_driver` |

These errors do not reflect raw paths or object IDs, create terminal transaction
refusals, or claim publication ambiguity. Output/work budget and cancellation
errors retain their separate 413/408 mappings. None of these responses grants
review or merge authority; download, inspection, exact-candidate approval and
explicit merge still use the existing workflow.

`crates/fgit-node/tests/exact_rename_preparation_http.rs` adds three actual-TCP
regressions. They cover cross-directory moves with a non-UTF-8 leaf name,
opposite-side content/executable-bit edits, fixed/chunked repeat equivalence,
restart, independent approval, coupled merge and exact retry in both hash
formats. A divergent-move refusal has a permitted legacy-profile twin to detect
silent fallback. Unknown/duplicate profiles, withheld-body authorization,
incomplete framing, stale PRs and resolve-profile refusal are also exercised.
Three additional unit tests cover typed selection/default equivalence, duplicate
and resolution fences, and all sanitized rename-error variants. Together with
the five node tests, this increment brings the authored integration coverage to
11 tests. None was compiled or run in the editing environment (no Cargo/rustc);
independent fixture/grammar checks and source integrity checks are not native
Rust or pinned Git differential evidence.
