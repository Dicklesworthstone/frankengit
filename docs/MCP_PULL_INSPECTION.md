# Inspect the actual PR merge candidate over MCP

`frankengit_source_candidate` supports `operation: "inspect_pull_merge"` for
FG-096 / x2mv.4.24's sponsored local authoring workflow. It completes the
read-only bridge from a native two-parent bundle to the existing independently
sponsored review and merge tools. No remote IAM or autonomous approval is added.

## Exact input, not an implicit latest-PR query

Take `candidate_arguments` from `prepare_pull_merge` (or supply independently
reviewed equivalent coordinates and native bundle bytes), add
`operation: "inspect_pull_merge"`, and optionally add the preparation result's
`snapshot_token` as `expected_head` and `bundle_sha256` as
`expected_bundle_sha256`. The required subject remains the exact PR `number`,
`expected_version`, source/target references and tips, `policy_epoch`,
`candidate_commit`, `merge_base`, and complete `bundle_hex_chunks`.

Each reference uses exactly one plain or `_hex` representation. Native IDs are
nonzero lowercase hex in the repository's SHA-1 or SHA-256 domain. PR versions,
numbers and epochs are exact positive decimal strings, not JSON numbers.
The optional transport digest is lowercase SHA-256 hex. No host path or URL is
read. Pins are preconditions; they cannot authorize an older or hidden subject.

Both `--allow-source` AND `--allow-pulls` are required, even for direct handler
calls with otherwise malformed inputs. Source-write, PR-write, review-write,
merge-write and recovery grants do not imply either read grant. The operation
shares the existing candidate tool name and remains read-only in MCP discovery.

## What is inspected

The adapter calls `OneNode::inspect_pull_request_bundle_in`. The native API
selects the exact open PR and both visible parents, verifies the uploaded pack,
validates the ordered target/source parents and common-base ancestry, and
compares the target-before tree with the ACTUAL uploaded candidate tree at that
same head. It does not replace the upload with the automatically prepared merge
or compare only the source-side PR diff. Parent-closure restrictions, native
object verification, request budgets and cancellation remain in the node.

The result carries the selected `snapshot_token`, complete original commit
body in hex (also UTF-8 when valid), ordered parents, prerequisite frontier,
bundle digest and measurements, and `review` using the existing MCP exact
byte/line-hunk schema. Its `comparison_subject` is
`target_before_to_uploaded_candidate`; both ref labels denote the target.
The native PR number/version association is retained, not erased to reuse a
source-only renderer. Binary and object-only changes remain explicit.

`complete: true` and `completion_scope: "entire_candidate_tree"` concern the
full bounded comparison, not execution, policy compliance, approval, or the
correctness of the algorithm that constructed the candidate.
`merge_algorithm_verified` is false. Preparation, inspection and publication
remain distinct: inspection stages no objects, creates no seal and changes no
refs or forge events.

## Budgets and refusal

`context_lines` defaults to 3 (range 0..20), `max_changes` to 64 (1..64),
`max_blob_bytes` to 1 MiB (1..1 MiB), `max_output_bytes` to 64 KiB (1..128 KiB),
and `max_diff_work` to 1,000,000 (1..1,000,000). The profile also bounds text
files to 32, hunks to 256, and commit metadata to 64 KiB. The existing complete
bundle envelope is three 8 KiB decoded chunks, subject to the 64 KiB whole RPC
input ceiling; the complete tool result is at most 2 MiB. Native pack expansion,
object, ancestry, original-object read and request-context ceilings still apply.

Path filters, merge-base comparison, replacement author/message metadata,
reviewer identities, review decisions, force flags and retry keys are rejected.
Corrupt, stale, missing, hidden or over-budget inputs return an error, never a
successful empty or truncated review. Failure does not stage the candidate or
poison a subsequent successful read. Errors are sanitized rather than exposing
undisclosed native diagnostics.

## Handoff to review and publication

The returned `candidate_arguments` retains the EXACT submitted bundle and
subject in the existing review/merge consumers' format. It contains no snapshot
pin (a review itself advances authority), no principal, no review decision, no
reviewer list, and no idempotency key. Review the actual commit and diff, then
supply the missing caller-owned fields to the named `review_tool` or
`publication_tool` under their independently granted launch identities.

Inspection is not an approval. Review admission checks the exact current
subject and policy, and merge publication must still satisfy the named-reviewer
and current protection contracts. Lost publication replies retain their existing
original-key recovery semantics; an old inspection never authorizes refreshing
tips or replacing a retry key.

## Evidence and limits

Authored tests cover strict parsing/schema/transport boundaries, real persisted
SHA-1/SHA-256 MCP prepare-to-inspect parity, actual target-side comparison,
unstaged candidates, restart, independent grants, stale/corrupt/budget twins,
request cancellation, and shared renderer binding failures. The implementation
session has no Rust toolchain or built `fg`: compilation, Rust tests, Clippy and
real-binary end-to-end execution have not been performed. No passing native gate,
complete agent-day, or bead closure is asserted by this implementation.
