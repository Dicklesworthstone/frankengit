# Atomic branch transactions through MCP

`frankengit_branch_transaction` applies 1..4,096 distinct branch creations,
fast-forward updates and deletions as one native atomic transaction. It is
available only under the existing `--allow-source-writes` grant. That grant
does not permit source reads, outcome queries, review, or protection changes.
The principal and repository incarnation stay fixed by the trusted-local
operator at launch; this is not remote IAM or an Intent Run broker.

## Request

```json
{
  "name": "frankengit_branch_transaction",
  "arguments": {
    "idempotency_key": "coordinated-release-1",
    "commands": [
      {"action": "create", "reference": "refs/heads/release-copy", "target": "<native-commit-oid>"},
      {"action": "update", "reference": "refs/heads/release", "expected_old": "<old-native-oid>", "target": "<new-native-oid>"},
      {"action": "delete", "reference": "refs/heads/obsolete", "expected_old": "<old-native-oid>"}
    ]
  }
}
```

Replace OID placeholders with nonzero lowercase SHA-1 or SHA-256 IDs in the
repository's declared format. Each command requires exactly one of `reference`
and `reference_hex`; hex preserves arbitrary valid reference bytes. Full names
must start with `refs/heads/`. New tips must already be visible verified commits.
Create requires absence; update/delete require exact old tips. There is no force,
implicit tip refresh, per-command key, caller identity, object upload, or partial
publication option. Duplicate targets and unknown or inapplicable fields refuse.

The complete request remains subject to the existing 64 KiB JSON frame, decoder
string/nesting bounds, 4,096-command native ceiling and native resource limits. Longer
reference names can exhaust the frame before the command ceiling. Limits never
truncate a request into a smaller transaction. Discovery publishes a closed
schema for each action, with no nested idempotency keys.

## Outcome and recovery

The tool calls `OneNode::admit_branch_transaction_durable_in` once, through the
existing quarantine, seal, policy and authority-CAS path. A stale or protected
member cannot leave a valid prefix published. No forge events or PR retargeting
are manufactured. Single-branch, rename and bundle tools retain their behavior.

The `source_publication` result has `action: "transaction"`, one transaction ID,
one terminal decision, `atomic: true`, and every submitted command. A canonical
refusal returns an error carrying its terminal receipt. `current_refs_asserted`
is false: a recovered historical outcome does not claim today's branch state.
The adapter rejects inconsistent, missing or partial atomic decisions.

An identical retry with a new JSON-RPC ID and the original durable key recovers
that decision across process restart. Reordering distinct commands preserves
canonical request identity; receipt arrays retain caller order. Different
semantics under an already used key refuse. A separately granted
`frankengit_transaction_outcome` reads the original key without resubmitting.
Disconnect, cancellation or response overflow does not establish rollback.

## Verification

`cargo test -p fgit-cli --bin fg mcp:: --locked` checks the real MCP adapters,
protocol, independent grants and catalog parity. `cargo test -p fgit-cli --test
mcp_branch_transaction --locked -- --nocapture` launches real `fg-mcp` processes
through a Python stdio client against persisted SHA-1 and SHA-256 nodes. It
exercises mixed atomic changes, reordered restart retries, canonical refusal,
key conflict, raw names, read-only denial and independent outcome recovery; the
native node is reopened to verify all branch state. The schema registry and its
generated artifacts retain deterministic ordering and the existing contracts.
These are focused integration checks, not a hostile-client isolation proof,
full-workspace release gate, or completion of the broader FG-096 broker work.
