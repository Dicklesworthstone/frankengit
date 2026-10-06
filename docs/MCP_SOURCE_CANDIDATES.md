# Native source candidates over MCP

`frankengit_source_candidate` closes the local sponsored agent's source-read to
patch-candidate boundary. It is exposed by `--allow-source`, not by source-write,
issue, PR, review or outcome permissions. This remains the explicit trusted-local
MCP profile, not remote IAM or an agent credential issuer (x2mv.4.24 / FG-096).

## Prepare a patch without publication

Call with `operation: "prepare_patch"`, a full `reference` (or lossless
`reference_hex`, never both), and the exact nonzero `expected_base` commit.
Supply `patch` as UTF-8 text, or `patch_hex_chunks` as ordered lowercase-hex
fragments. Supply every commit metadata field explicitly: `author`, `committer`,
`timestamp` (positive exact decimal string, at most i64::MAX), and `message_hex`.
Author/committer strings are untrusted commit metadata, not authenticated actors.

For example, after reading the branch's base commit:

```json
{
  "operation": "prepare_patch",
  "reference": "refs/heads/topic",
  "expected_base": "<exact native base commit>",
  "patch": "diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-before\n+after\n",
  "author": "Author <author@example.invalid>",
  "committer": "Committer <committer@example.invalid>",
  "timestamp": "1",
  "message_hex": "656469740a"
}
```

The existing native TreeFS planner checks the current visible branch, verifies
source objects, applies the whole exact patch, preserves unedited siblings and
constructs a single-parent native Git bundle. There is no host checkout, Git
subprocess, object-fabric staging, seal, ref update, or approval. Native patch
semantics and refusals apply, including regular-file creation/deletion/modes,
explicit supported renames and binary patch records. No fuzzy application or
unsupported fallback is introduced by MCP.

The complete result carries source RCR/base, candidate commit/tree, exact patch
and bundle SHA-256, changed-path blob/mode receipts and `publication_arguments`.
The latter uses the existing `frankengit_source_publish` field names and contains
no idempotency key. A caller must review the candidate, obtain the independent
write grant and supply its own original key before requesting publication.
Preparation success does not imply that current protection will admit it.

A native preparation result identifies an RCR but does not expose its selecting
authority head. Therefore `snapshot_token` is null: the adapter does not attach
an unrelated preliminary or subsequent head read. `expected_head` is rejected
for preparation. The exact base is checked inside native selection; no newest-tip
refresh is performed. A lost preparation response is safe to repeat with the
same explicit inputs while that base remains current. A lost *publication*
response still requires the original publication key and existing recovery rules.

## Inspect the actual candidate before publication

Call the same tool with `operation: "inspect"` and the preparation result's
`publication_arguments` (reference/base/candidate/bundle), without adding an
idempotency key. Optional `expected_bundle_sha256` pins the exact transport;
optional `expected_head` pins the current authority snapshot. These are
preconditions, not selectors that authorize hidden objects or an older branch.

The native inspector verifies the bundle, candidate identity, single parent,
visible base closure and complete base-to-candidate tree comparison without
staging any uploaded objects. The result includes the actual commit body in
hex (and UTF-8 when valid), ordered parents, transport measurements, and the
existing MCP review schema with exact byte/line hunks. Binary and object-only
changes retain their explicit representations. The authenticated snapshot token
comes from this very inspection, not a separate head read.

Inspection does not accept path filters, merge-base comparison, replacement
commit metadata, PR/reviewer identities, or publication fields. `max_changes`,
`max_blob_bytes`, `max_output_bytes`, `max_diff_work` and `context_lines` only
narrow its bounded work/output profile. Exhaustion fails the whole inspection;
there is no successful truncated diff. The shared renderer rechecks repository,
refs, head and commit pins, entry order, types, spans and output bounds.

Review `candidate_commit_body_hex` and `review`, then use the inspected result's
`publication_arguments` with `frankengit_source_publish`, adding your own
original `idempotency_key`. Inspection grants no approval or publication right.
The independent source-write grant, launch-bound sponsor, exact predecessor,
quarantine and branch policy still govern publication. Repeat an ambiguous
publication with identical semantic fields and the original key, never with a
newest-tip refresh. A successful historical retry is not a new inspection.

## Bounds and evidence

Plain patch text is at most 16 KiB; byte-oriented patches and candidate bundles
are at most three 8 KiB chunks (24 KiB decoded). Message bytes are at most 4 KiB,
metadata identities 1024 bytes each, path receipts 64, result bytes 2 MiB. The
MCP parser's aggregate 64 KiB request bound also applies. Inspection permits
at most 64 changes, 32 text files, 256 hunks, 1 MiB per blob, 128 KiB diff
output and 64 KiB candidate commit metadata; its schema lists narrower defaults. Native planner read,
object, expansion and request-context budgets are retained. Oversized results
are refused, never returned as truncated publishable candidates.

The candidate operations share one fixed registry entry; all existing grants
still fit the 32-tool registry. Tests include strict parsing and exact byte
round trips plus persisted SHA-1/SHA-256 MCP preparation, inspection,
publication, same-key retry, reopen, sibling preservation and independent-grant
regressions. Corrupt bundles, mismatched pins and deliberately too-small diff
budgets are paired with successful reads of the same native candidate. These are authored coverage, not an executed native-test claim:
this implementation session had no Rust toolchain or built `fg`. Independent
compilation, native and real-binary verification remain required; no agent-day
or bead closure is asserted.
