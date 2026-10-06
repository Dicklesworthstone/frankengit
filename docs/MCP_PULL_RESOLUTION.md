# Resolve and inspect conflicted PRs through MCP

`frankengit_source_candidate` accepts `operation: "resolve_pull_merge"` in the
explicitly sponsored local MCP profile. This connects the existing native
PathMergeV1 conflict-resolution engine to complete candidate inspection and the
existing separately authorized review/merge tools (FG-096 / x2mv.4.24). It does
not create a new Git engine, source workspace, publication path or approval.

## Exact subject and explicit choices

Supply the same exact PR subject as `prepare_pull_merge`: positive decimal
strings `number`, `expected_version` and `policy_epoch`; exactly one plain/hex
encoding of each source and target reference; and nonzero native
`expected_source` and `expected_target` commits. Supply the exact `merge_base`
from the conflict report, explicit `author`, `committer`, `timestamp` and
`message_hex`, and a nonempty `resolutions` array. Optional `expected_head`
pins the result to the independently retained authority snapshot.

Each resolution has a raw `path_hex` and one closed `choice`:

- `base`, `ours`, or `theirs` selects that actual conflict's existing entry.
  Ours is the target branch; theirs is the source branch. Selecting a missing
  side is an error, never an implicit deletion.
- `delete` explicitly removes the conflicted path. No content or mode is supplied.
- `file` supplies an explicit regular-file `mode` (`"100644"` or `"100755"`)
  and `bytes_hex_chunks`, preserving exact bytes, including binary content,
  CRLF and missing final newlines. An empty array means an empty regular file;
  it is not deletion. There is no newline or conflict-marker normalization.

For example, the additional fields on an otherwise exact subject can be:

```json
{
  "operation": "resolve_pull_merge",
  "merge_base": "<exact native common-base commit>",
  "resolutions": [
    {
      "path_hex": "524541444d45",
      "choice": "file",
      "mode": "100644",
      "bytes_hex_chunks": ["7265736f6c7665640a"]
    }
  ]
}
```

The example names README and supplies `resolved\n`. It is not a complete RPC:
all exact subject and metadata fields remain required. Read the native conflict
report first, rather than supplying choices for guessed or unconflicted paths.

The parser checks the complete decoded-byte allowance before retaining any
file payload. It rejects duplicate paths, ancestor/descendant overlaps, unsafe
path components (including case-insensitive `.git`), unsupported choices/modes,
missing metadata, and unknown fields. Paths are sorted canonically; request
ordering cannot make one resolution overwrite another. There is no implicit
latest-tip refresh or automatic choice for a missing resolution.

## One native preparation followed by mandatory inspection

The adapter calls `OneNode::prepare_resolved_pull_request_bundle_in`. The native
owner validates the exact open PR, tips, policy epoch and unique common base,
reproduces PathMergeV1 conflicts, and requires every and only those conflicts to
be resolved. Non-conflict edits, missing choices, ambiguous ancestry and unsupported
native cases fail without a candidate. An already clean merge is not a conflict
resolution; use `prepare_pull_merge` instead. `merge_profile` is rejected here:
this operation does not silently reinterpret an exact-renames conflict report.

Returned per-path receipts are checked against the submitted choices, including
the exact blob identity and mode for file bytes. The adapter then passes the
complete generated bundle into the same native `inspect_pull_merge` handler,
pinned to preparation's selecting head. Both phases use the SAME
`NodeRequestContext`; entering inspection does not reset cancellation or the
server-work budget. Generated object bodies are released before pack inspection.
Each native phase retains its own finite object/work ceilings within that shared
request. A concurrent head change refuses the composition rather than combining
preparation at one snapshot with inspection at another.

Only a fully inspected result is returned. It contains the complete actual
target-before-to-candidate diff, original commit body, ordered parents, bundle
measurements, exact `candidate_arguments`, and `resolved_paths` receipts.
`inspection_performed` is true and `completion_scope` is `entire_candidate_tree`.
A choice of ours can legitimately produce an empty tree diff while retaining an
explicit two-parent merge commit. Empty content and binary changes keep their
existing native review representations. `merge_algorithm_verified` remains the
inspector's non-claim; its job is checking uploaded result bytes, not attesting
how an arbitrary bundle was constructed.

## Independent grants and publication

Source AND PR read grants are required before parsing, including direct handler
entry. Review-, merge-, source-write and outcome grants imply neither read grant.
The operation remains read-only and occupies the same existing tool registry
entry. No objects are staged, refs changed, forge events admitted, idempotency keys
minted, or review votes created by preparation/inspection.

Use the exact returned `candidate_arguments` with the existing named `review_tool`
and `publication_tool`, supplying the caller-owned decision/version/reviewer/key
fields under independently launched identities. The PR opener and merge submitter
cannot satisfy the named-reviewer gate with their own votes. A read success grants
no merge permission, and current branch protection still applies. Review changes
authority, so handoff arguments deliberately omit the inspection head pin while
retaining exact PR/tip/epoch/candidate semantics. Original-key retries recover the
existing canonical decision; they never rerun resolution at refreshed tips.

## Bounds

At most 64 choices are accepted. All decoded paths plus all explicit file bytes
share a 24 KiB allowance. A path is at most 4096 bytes; a file has at most three
nonempty 8 KiB decoded chunks, or the explicitly empty array. The existing 64 KiB
whole-RPC bound, 4 KiB commit-message bound and 1024-byte identity strings still
apply. The returned whole native bundle must fit three 8 KiB chunks, and the
complete response must fit the existing 2 MiB tool-result limit.

`max_commits` defaults to 4096 (range 1..4096); `max_tree_entries` defaults to
100,000 (1..100,000). `max_preparation_bytes` defaults to 256 KiB (1..1 MiB);
`max_review_bytes` defaults to 64 KiB (1..128 KiB). `max_changes` defaults to 64
(1..64), `context_lines` to 3 (0..20), and `max_diff_work` to 1,000,000
(1..1,000,000). Preparation additionally caps generated objects at 1024 and
conflicts at 64. Inspection retains its 32 text files, 256 hunks, 1 MiB blob
and 64 KiB commit-metadata bounds plus native pack, ancestry and read ceilings.
No unused allowance is converted into wider permissions or an unbounded fallback.

Exhaustion in either phase fails the entire operation. In particular, a valid
constructed bundle is not returned as publishable when inspection fails or the
head moves. Diagnostic errors are sanitized; no repository paths or content are
copied into an error code.

## Evidence

Authored regressions cover closed shapes, exact/empty/binary payloads, aggregate
byte ceilings, duplicate/overlapping/unsafe paths and native receipt matching.
Persisted SHA-1/SHA-256 tests cover all conflict choices, actual inspection without
staging, stale/base/phase-budget/non-conflict refusal twins, cancellation and
independent grants. The full workflow test resolves and inspects, verifies that
an unapproved candidate cannot commit, obtains a distinct review, publishes the
coupled PR/ref transition, retries the original key, reopens, and reads exact
resolved and untouched sibling bytes.

This session has no Rust toolchain or built `fg`. These tests are authored, not
executed passing evidence; compilation, Rust tests, formatting, Clippy and
real-binary end-to-end validation remain outstanding. No full agent-day or bead
closure is asserted by adding this local workflow integration.
