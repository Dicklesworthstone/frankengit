# Operator-scoped MCP metadata mutations and recovery

This FG-096 implementation slice connects `fg-mcp` to existing canonical issue
admission and principal-scoped transaction recovery. It is not a new mutation
engine, metadata database, remote authentication system, or Intent Run broker.
The repository's seal, exact-version fold, outbox and authority-head CAS remain
the publication boundary. No dependency is added. Assignment extends the native
issue action tags under [normative §20.2](NORMATIVE_PROTOCOL_CONTRACTS.md#202-native-issue-assignment-deltas),
preserving all earlier event bytes and identities.

## Explicit launch grants

```sh
cargo run --locked -p fgit-cli --bin fg-mcp -- \
  "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --principal "$PRINCIPAL" --expected-incarnation "$INCARNATION" \
  --allow-issue-writes --allow-outcomes --allow-issues
```

Use `--object-format sha256` for that native repository format. The repository
must already exist. A write or outcome grant requires both the principal and
incarnation pin before opening a session. The operator is explicitly sponsoring
all requested mutations as that principal; client arguments never authenticate
or choose another principal. Do not proxy this trusted local process to remote
untrusted clients. This is not per-issue ACL enforcement or full agent authority.

All five grants are independent: issue reads, PR reads, source reads, issue
writes, and outcome recovery. A write-only process cannot list issues or query
outcomes. An outcome-only process cannot mutate. Omitted groups are absent from
tool discovery and rejected at dispatch. No client capability, root, repository
text, tool argument, or annotation can widen the launch grants.

## Issue tools

The write group exposes `frankengit_issue_open`, `frankengit_issue_edit`,
`frankengit_issue_close`, `frankengit_issue_reopen`,
`frankengit_issue_comment`, `frankengit_issue_append_comment`,
`frankengit_issue_assign` and `frankengit_issue_unassign`. Each requires a positive
`number` and `idempotency_key`. All except the explicit append tool require an
exact `expected_version`. Numbers and versions are canonical unsigned decimal
**strings**, not JSON numbers.

Opening requires version `"0"`, `title`, and an explicit `body` (possibly empty).
Other exact-version actions require a positive, nonexhausted predecessor. Editing
accepts one or more of `title`, `body`, and `labels`; omitted fields survive,
`body: ""` clears the body, and `labels: []` clears labels. Commenting requires
nonblank body text. Close/reopen accept none of those content fields.

`frankengit_issue_append_comment` requires only `number`, `body`, and
`idempotency_key`; `expected_version` is rejected. Use it to add discussion to an
existing issue independently of intervening title, body, assignment or state
changes. The node selects the predecessor inside canonical admission and publishes
a regular versioned comment, preserving other issue fields. The result identifies
`action: "append-comment"` and `expected_version: null`.

```json
{"jsonrpc":"2.0","id":"append-attempt-1","method":"tools/call","params":{"name":"frankengit_issue_append_comment","arguments":{"number":"7","idempotency_key":"append-issue-7-details","body":"Additional reproduction details, independent of the title edit."}}}
```

The original `frankengit_issue_comment` remains an exact-version operation. Keep
pending requests bound to their original tool, number, version, body and key;
switching a pending request to the append tool changes its intent. Retrying an
append uses its original number, body and key, even after another writer changes
the issue. Successful recovery returns the original terminal decision without
adding another comment.

Assign/unassign require `assignees`, an array of 1–16 distinct principal IDs
encoded as exactly 32 lowercase hexadecimal characters. IDs are sorted before
sealing. Assignment adds only the named principals; unassignment removes only
those named. Other assignees survive. The complete resulting set has at most
16 IDs. Both actions work on open or closed issues and advance the issue
version, including when the requested membership already holds. Issue list
and show snapshots include the sorted current `assignees` array; histories
retain each original delta. Assignment does not verify account existence or
grant access, membership, credentials, or notification delivery. The process's
launch-bound principal remains the actor and all launch grants remain required.

```json
{"jsonrpc":"2.0","id":"assign-attempt-1","method":"tools/call","params":{"name":"frankengit_issue_assign","arguments":{"number":"7","expected_version":"1","idempotency_key":"assign-issue-7-v2","assignees":["44444444444444444444444444444444"]}}}
```

Labels are a unique set of at most 32 strings of at most 64 UTF-8 bytes; input
order is normalized and duplicate values are rejected. Titles retain the native
256-byte bound. MCP bodies are narrowed to 16 KiB by the existing JSON profile;
NUL is refused. Source text is data, never executable instructions. Unknown or
inapplicable fields, filesystem inputs, ambient principal selectors, and missing
predecessors on exact-version tools are rejected before admission.

After the initialization handshake, an example `tools/call` is:

```json
{"jsonrpc":"2.0","id":"open-attempt-1","method":"tools/call","params":{"name":"frankengit_issue_open","arguments":{"number":"7","expected_version":"0","idempotency_key":"create-issue-7-v1","title":"Investigate timeout","body":"Observed on the selected revision.","labels":["bug"]}}}
```

The durable key is 1..256 printable ASCII bytes without spaces. A retry uses a
**new JSON-RPC ID**, the **same durable key**, and the **identical complete
command** and original tool name. Never refresh the expected version on an
exact-version retry; append retries continue to omit it. Key reuse with changed
semantics cannot alias the original command; it remains an error. Notifications
never execute tools, and duplicate JSON-RPC IDs cannot execute again.

## Terminal decisions and transport failures

A mutation result binds tenant, repository, incarnation, principal, native object
format, transaction ID, exact decision sequence, and committed/refused record
identity. It is a historical fact about that command, not a claim about today's
issue state. `delivery_acknowledged: null` does not invent downstream delivery.
Issue mutations do not move Git refs. Canonical refusals carry their real terminal
fields and MCP `isError: true`; successful publication has `isError: false`.

Malformed inputs are JSON-RPC argument errors. Once admission is entered, an
infrastructure failure is a tool error with `outcome_unknown: true`. A timeout,
EOF, cancellation, or broken stdout does not establish non-commit. The protocol
stops before processing a later request when output fails and still explicitly
closes the node. A known terminal result is retained in a compact error response
if the full tool result exceeds its output bound. The serial protocol does not
preempt an in-flight operation or implement rollback by cancellation.

## Outcome tool

`--allow-outcomes` exposes `frankengit_transaction_outcome`, whose sole argument
is the original `idempotency_key`. This calls the existing read-only canonical
recovery API. It needs no original body, version, bundle, or transaction ID, and
never re-seals, resubmits, stages, or cancels work. Recovery remains available
through a readable authority even when new-publication intake is stopped.

Observations distinguish `key_not_observed`, `seal_not_observed`, `undecided`,
and `decided`. The first three are explicitly nonterminal and never prove
rollback or absence of a concurrent request. A different principal's identical
key does not expose the original principal's result. Recovered seals include
their canonical request digest so an old binding is not confused with a newly
changed command. A successful query of a canonical refusal has `isError: false`:
the read succeeded even though the historical mutation was refused.

## Merge queue management and native landing

Three independent launch grants expose the canonical merge queue APIs:

| Grant | Tools | Effect |
| --- | --- | --- |
| `--allow-queues` | `frankengit_queue_list`, `frankengit_queue_show` | Complete visible snapshots. |
| `--allow-queue-writes` | `frankengit_queue_enqueue`, `frankengit_queue_dequeue`, `frankengit_queue_reorder` | Queue membership and order only. |
| `--allow-queue-landings` | `frankengit_queue_land` | Exact queue-head fast-forward, coupled PR merge and queue completion. |

None implies another grant, PR/source access, approval authority, or outcome
recovery. A queue writer cannot land, and a landing-only process cannot edit
membership. Both mutation grants require a canonical lowercase launch principal
and exact repository incarnation. The existing trusted-local operator sponsors
the action; no client argument authenticates a remote principal.

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --principal "$PRINCIPAL" --expected-incarnation "$INCARNATION" \
  --object-format sha256 --allow-queues --allow-queue-writes \
  --allow-queue-landings --allow-outcomes
```

List accepts `after` as a canonical decimal string, integer `limit` from 1
through 20 (default 5), and `expected_head`. A nonzero cursor requires the first
page's `snapshot_token`. Show requires positive decimal-string `number` and
accepts `expected_head`. Current canonical hidden-ref policy applies to both
current and retained snapshots: a hidden target or any hidden source suppresses
the entire queue. A queue is returned completely or the read fails; no truncated
membership list is presented as canonical state.

Every queue mutation requires `number`, `expected_version`, `idempotency_key`,
`expected_incarnation`, `object_format`, and exactly one of `target_reference`
or `target_reference_hex`. The incarnation and format must match the launch
binding; they cannot select a different repository. Reference fields contain
full `refs/heads/` names, bounded to 1024 raw bytes. The hex alternative is
lowercase and preserves non-UTF-8 bytes. A receipt returns both representations,
with a null text field when the name is not UTF-8.

All queue/PR numbers, versions, priorities, and policy epochs are canonical
unsigned decimal **strings**. Enqueue accepts version `"0"` for a new queue or
the exact positive existing version. Dequeue/reorder require a positive queue
version. Unknown, duplicate, inapplicable, floating-point, or identity override
fields are rejected before admission.

| Tool suffix | Additional arguments |
| --- | --- |
| `enqueue` | `pull_request`, positive `expected_pull_request_version`, exactly one `source_reference` or `source_reference_hex`, `expected_source`, `expected_target`; optional `priority` from `"0"` through `"4294967295"`, default `"0"`. |
| `dequeue` | `pull_request` and `reason`: `withdrawn`, `conflict`, `check-failed`, `base-moved`, `evicted`, or `admin-override`. |
| `reorder` | `order`, the complete desired array of 1–256 distinct positive PR-number strings, without added or omitted members. |
| `land` | The enqueue candidate coordinates without `priority`, plus positive `expected_policy_epoch`. |

The source and target OIDs are explicit nonzero lowercase IDs in the pinned
native hash format. Landing additionally requires distinct tips, the exact
current queue head, exact PR version, two available queue successor versions,
and one available PR successor. The operator must supply observed coordinates;
the adapter never updates a stale observation automatically.

`frankengit_queue_land` invokes the native `FastForwardOnly` profile. Existing
commit ancestry, current required reviews/checks, and protected-ref rules are
enforced by the node. It accepts no bundle, merge-method override, force flag, or
caller assertion that checks passed. One successful canonical decision moves
the target to the existing source tip, advances the PR once, and advances the
queue twice for batch formation/completion. No intermediate active batch is
published. Source refs remain unchanged. See
[NATIVE_MERGE_QUEUE.md](NATIVE_MERGE_QUEUE.md) for the native landing contract.

```json
{"jsonrpc":"2.0","id":"queue-enqueue-1","method":"tools/call","params":{"name":"frankengit_queue_enqueue","arguments":{"number":"1","expected_version":"0","idempotency_key":"queue-1-pr-7","expected_incarnation":"11111111111111111111111111111111","object_format":"sha1","target_reference":"refs/heads/main","pull_request":"7","expected_pull_request_version":"1","source_reference":"refs/heads/topic","expected_source":"2222222222222222222222222222222222222222","expected_target":"3333333333333333333333333333333333333333"}}}
```

Replace every example observation with the actual repository values. Use the
original complete arguments and durable key for a retry, including after later
queue/PR/policy changes or a lost reply. `proposed_action` preserves the exact
requested action and guards; `historical_outcome: true` identifies the original
terminal result. Management receipts have `refs_changed: false`; only a committed
landing reports the target move. Neither a receipt nor `delivery_acknowledged:
null` claims downstream delivery or the latest queue state. Independently grant
`--allow-outcomes` to resolve the same principal's original key without retrying.

The ordinary 64 KiB MCP request and 256-item array bounds remain unchanged.
Complete queue results are limited to 1 MiB. Native queues can hold 1024 entries;
use the CLI or HTTP profile for complete reorders above 256 entries. Oversized
reads fail without a partial result. Multi-PR speculative execution and workflow
execution are not exposed by these tools.

## Verification and remaining scope

Added deterministic parser/protocol tests cover exact integer and key bounds,
field presence, label normalization, mutation annotations, canonical refusals,
ambiguous failures, response limits, notifications and lost output. Real-node
tests cover both native hash formats, lifecycle publication, unchanged exact
retries, stale refusals, principal isolation, stopped intake, reopen recovery,
and a genuinely lost stdio reply after a native issue commit. Append regressions
cover independent edits, preservation of strict-comment refusals, unchanged
retries after close and reopen, changed-key-content refusal, stopped-intake
recovery, explicit schema fields and both native hash formats.

Run `cargo test --locked -p fgit-cli --bin fg-mcp` in the admitted Rust environment.
These Rust tests were written but not executed in the authoring session because
Rust/Cargo are unavailable there. Source inspection is not a passing build,
independent batch gate, or deployed-client conformance result.

FG-096 remains incomplete: broker-backed scoped Intent Runs, preemptive
cancellation, remote sessions, generated registry/public-schema integration and
the full live-client security campaign retain their own acceptance. Git object
publication, reviews, merges, CI execution and secrets are not enabled by these
metadata grants. Canonical workflow-check publication remains separate work.
