# Native pull-request CLI: recovered workflow guide

The PR CLI exposes `fg pr open`, `update`, `close`, `list`, and `show` over
`OneNode`'s canonical PR admission and authenticated reads. It does not own a
second PR database, call Git in production, or turn metadata into a ref update.
The current command contract is also documented in
[`NATIVE_PULL_REQUEST_COMMAND.md`](NATIVE_PULL_REQUEST_COMMAND.md).

This guide reconciles the saved seven-file PR CLI patch with the implementation
that landed concurrently on `main`. The existing implementation, tests, JSON
schema and exit codes were retained rather than replaced. The saved patch's
input spellings, bidirectional-formatting escapes, and fresh-process campaign
are integrated into that implementation. There is no duplicate parser or PR
publication loop.

## Compatibility with the saved patch

`--source-tip` is an alias for `--expected-source`; `--target-tip` is an alias
for `--expected-target`. Both spellings carry the same exact native object ID.
Supplying both spellings of one option refuses as a duplicate, even when the
values are identical. A contradictory alias cannot silently override an
expectation. These flags remain mutation-only.

A saved `head:alg:<code>:<lowercase-hex>` continuation token is accepted as the
same specifically typed head as `alg:<code>:<lowercase-hex>`. Output continues
to emit the latter in `snapshot_token`. Neither spelling authenticates a head;
the node compares it with an independently authenticated snapshot. Other
identity domains, repeated prefixes, malformed numbers and malformed hex refuse.

The saved patch's earlier output draft is **not** a second supported wire
schema. The retained command emits `pull_request` and `data` in mutation
receipts, `kind` in rows, and `snapshot_token` plus `next_after` in list results.
It does not emit the draft `request_data`, `record_kind`, or `next` fields.
Its existing exit codes are preserved:

| Exit | Meaning |
| --- | --- |
| 0 | A mutation committed, or a read completed successfully. |
| 3 | The mutation has a canonical refusal, reported in its JSON receipt. |
| 4 | `show` found no visible native PR with the requested number. |
| 2 | Invalid request, unavailable infrastructure, shutdown or output error. |

A nonzero exit alone is not evidence that no mutation committed. Inspect any
terminal receipt and preserve its transaction identity.

## Explicit local trust

Every command requires `--trusted-local`. This acknowledges an authorized
local operator's access to the specified node; it is not a credential exchange,
remote authorization service, or sandbox. Mutations additionally require an
explicit principal and bounded client idempotency key. Repository text cannot
select a principal, approve itself or alter policy.

All examples assume an existing imported node, known tenant/repository IDs,
and independently selected native commit IDs. Read commands default to SHA-1;
pass `--object-format sha256` for SHA-256. Mutation format is inferred from
both supplied tips, and an explicit format must agree.

## Open a PR

```bash
fg pr open "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key "open-pr-17" \
  --expected-version 0 \
  --source-ref refs/heads/topic \
  --target-ref refs/heads/main \
  --source-tip "$SOURCE_COMMIT" \
  --target-tip "$TARGET_COMMIT" \
  --title "Implement native PR workflow" \
  --body-file ./pr-description.md
```

Opening requires version zero and an unused native aggregate. Both compared
branch tips are explicit; there is no implicit latest-tip lookup in the CLI.
The node validates the command against authority-selected state before
publishing its event, forge position and outbox obligation together. These
metadata operations do not move Git refs.

Title and body are data. Supply exactly one of `--body` or `--body-file`.
`--body ''` explicitly requests an empty body; omission never silently clears
one. Titles must satisfy the native 256-byte bound and text constraints. Body
files must be stable operator-owned regular files, at most 65,536 bytes,
valid UTF-8 and NUL-free. A final symlink, device, directory, oversized or
invalid body refuses before the repository opens. This is not a guarantee
against a malicious host changing parent directories concurrently.

## Update or close

An update supplies the exact positive prior version and the entire intended
data. Use a new key for a new semantic command, but the identical key and
identical data for recovery of that command. Branch identities cannot be
retargeted by an update. Compared tips may be explicitly refreshed through a
new update; metadata is never refreshed during retry.

```bash
fg pr update "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key "update-pr-17-v1" --expected-version 1 \
  --source-ref refs/heads/topic --target-ref refs/heads/main \
  --expected-source "$SOURCE_COMMIT" --expected-target "$TARGET_COMMIT" \
  --title "Revised description" --body-file ./revised-description.md
```

Closing likewise supplies complete metadata and the exact prior version.
Repeat the last recorded title, body and compared tips; closing is not an
implicit metadata edit. The recorded data need not track a subsequently deleted
branch. The native lifecycle rejects stale versions, inconsistent closure data
and attempts to revive terminal streams. Merge publication remains the separate
reviewed `fg merge apply` operation.

## List and show

```bash
fg pr list "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --limit 50

fg pr show "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local
```

Rows are ordered numerically, not lexically by an aggregate label. `show`
returns only the requested number: a next-higher row is not substituted for a
hidden or absent PR. Source and target branches both pass current visibility
checks before disclosure. This view covers native PRs and explicitly identified
native merge-only receipts, not every legacy forge event schema.

A list response carries `count`, `has_more`, `next_after`, `snapshot_token`,
and the selected `source_head`. Use `snapshot_token`, not the display spelling
of `source_head`, as the next page's equality precondition:

```bash
fg pr list "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --limit 50 \
  --after "$NEXT_AFTER" --expected-head "$SNAPSHOT_TOKEN"
```

A nonzero `--after` requires an expected head. The node refuses when that head
no longer equals its selected current snapshot; it does not combine pages
from different repository states or silently restart the query. Keep the
original token for the traversal rather than adopting a newer token midway.

Merged PR rows retain recorded title/body/opener when the native history
contains them. A merge-only receipt has `kind: "merge_receipt"` and does not
invent an opener, title or approval history. A native merge's commit identity
is in the row's `merge.commit` field.

## Exact bytes and safe presentation

Use `--source-ref-hex` or `--target-ref-hex` instead of its text counterpart
for valid non-UTF-8 branch names. Hex must be lowercase and bounded. Output
reference names use `source_reference_hex` and `target_reference_hex` without
lossy conversion.

JSON preserves metadata exactly after decoding. Its shared writer escapes
quotes, backslashes, C0/C1 controls, line separators and explicit bidirectional
formatting characters. Ordinary multilingual text remains intact; escaping
changes presentation bytes, not canonical event bytes or transaction identity.
Reading the output is not permission to execute embedded text or render it as
trusted HTML.

## Terminal decisions and recovery

Mutation receipts bind action, PR number, expected version, complete data,
tenant/repository/principal, native format, transaction ID, decision sequence,
and the committed repository record or canonical refusal. `refs_changed` is
false for PR metadata commands. `delivery_acknowledged` is null: enqueueing
work does not prove that an external destination processed it.

The CLI explicitly closes the node before printing a result. A known terminal
decision survives output/flush/shutdown failure in diagnostics and any emitted
receipt. When no terminal result returns, retry the identical operation,
principal, key, version, branch identities, tips and metadata bytes. Replacing
a key or recomputing current metadata is a new attempt, not reconciliation.
A recovered historical success does not itself imply that the PR remains in
that old state now.

The node's broader admission, serving-state and quota/recovery contracts remain
owned by its existing implementation and verification tasks. This CLI
reconciliation does not claim to close the separately tracked retry-order
finding or the complete forge acceptance gate.

## Code and tests

The existing implementation remains in `fgit-cli/src/pull_request.rs` and its
`options.rs`, `output.rs` and `tests.rs` modules. No production dependency,
lockfile or canonical publication protocol was changed. The `main.rs` dispatch
was already present and was not overwritten.

New parser regressions cover all three mutation verbs in both native hash
domains, equivalent alias inputs, both orders of equal/contradictory duplicate
aliases, read/mutation separation, and typed head-token continuation. The
shared output regression covers C1/bidi escaping and unchanged ordinary
multilingual text. Existing parser, cleanup, row-binding and embedded-authority
tests are retained rather than replaced by the saved patch's parallel copies.

The recovered fresh-process campaign is:

```bash
python3 scripts/e2e/pull_request_cli_smoke.py --fg /absolute/path/to/fg
```

It constructs and hashes native objects independently, invokes fresh CLI
processes for both formats, checks exact metadata/actors/versions, numeric and
pinned pagination, absence handling, original successful/refused retries,
changed-semantics keys, no ref movement from metadata, and reviewed native
merge publication. It also checks that switching tip or head-token spellings
does not change a logical request or snapshot. The existing
`scripts/e2e/pull_request_smoke.py` campaign remains separate and unchanged.

Executed during this reconciliation: Python compilation, help, and the
recovered campaign's fixture/checker self-test, rejecting 30 corrupted receipts:

```bash
python3 scripts/e2e/pull_request_cli_smoke.py --self-test
```

That mode explicitly reports `native_execution: false`. Cargo, rustc and a
built `fg` are unavailable in the editing environment. The newly added Rust
tests and the complete real-binary campaign were **not executed here**. Source
integration and Python fixture checks are not production runtime evidence;
no bead is closed by this guide or these commits.
