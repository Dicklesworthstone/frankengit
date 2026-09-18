# Operator-scoped MCP metadata mutations and recovery

This FG-096 implementation slice connects `fg-mcp` to existing canonical issue
admission and principal-scoped transaction recovery. It is not a new mutation
engine, metadata database, remote authentication system, or Intent Run broker.
The repository's seal, exact-version fold, outbox and authority-head CAS remain
the publication boundary. No dependency or canonical event encoding changes.

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
`frankengit_issue_close`, `frankengit_issue_reopen` and
`frankengit_issue_comment`. Each requires a positive `number`, exact
`expected_version`, and `idempotency_key`. Numbers and versions are canonical
unsigned decimal **strings**, not JSON numbers or implicit latest values.

Opening requires version `"0"`, `title`, and an explicit `body` (possibly empty).
Other actions require a positive, nonexhausted predecessor version. Editing
accepts one or more of `title`, `body`, and `labels`; omitted fields survive,
`body: ""` clears the body, and `labels: []` clears labels. Commenting requires
nonblank body text. Close/reopen accept none of those content fields.

Labels are a unique set of at most 32 strings of at most 64 UTF-8 bytes; input
order is normalized and duplicate values are rejected. Titles retain the native
256-byte bound. MCP bodies are narrowed to 16 KiB by the existing JSON profile;
NUL is refused. Source text is data, never executable instructions. Unknown or
inapplicable fields, filesystem inputs, ambient principal selectors, and missing
predecessors are rejected before admission.

After the initialization handshake, an example `tools/call` is:

```json
{"jsonrpc":"2.0","id":"open-attempt-1","method":"tools/call","params":{"name":"frankengit_issue_open","arguments":{"number":"7","expected_version":"0","idempotency_key":"create-issue-7-v1","title":"Investigate timeout","body":"Observed on the selected revision.","labels":["bug"]}}}
```

The durable key is 1..256 printable ASCII bytes without spaces. A retry uses a
**new JSON-RPC ID**, the **same durable key**, and the **identical complete
command**. Never refresh the expected version on a retry. Key reuse with changed
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

## Verification and remaining scope

Added deterministic parser/protocol tests cover exact integer and key bounds,
field presence, label normalization, mutation annotations, canonical refusals,
ambiguous failures, response limits, notifications and lost output. Real-node
tests cover both native hash formats, lifecycle publication, unchanged exact
retries, stale refusals, principal isolation, stopped intake, reopen recovery,
and a genuinely lost stdio reply after a native issue commit.

Run `cargo test --locked -p fgit-cli --bin fg-mcp` in the admitted Rust environment.
These Rust tests were written but not executed in the authoring session because
Rust/Cargo are unavailable there. Source inspection is not a passing build,
independent batch gate, or deployed-client conformance result.

FG-096 remains incomplete: broker-backed scoped Intent Runs, preemptive
cancellation, remote sessions, generated registry/public-schema integration and
the full live-client security campaign retain their own acceptance. Git object
publication, reviews, merges, CI execution and secrets are not enabled by these
metadata grants. Canonical workflow-check publication remains separate work.
