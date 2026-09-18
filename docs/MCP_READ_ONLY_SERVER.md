# Repository-scoped read-only MCP server (FG-096 implementation slice)

`fg-mcp` is a real stdio Model Context Protocol server over `OneNode` reads.
It implements the pinned MCP **2025-06-18** initialization handshake, ping,
`tools/list`, and `tools/call`. It does not launch `fg`, Git, or a shell to
answer requests. Its registry and handler permissions are fixed at launch;
repository content, client capabilities, and tool arguments cannot expand them.

## Launch

```sh
cargo run --locked -p fgit-cli --bin fg-mcp -- \
  /absolute/path/to/existing-node TENANT_HEX REPOSITORY_HEX \
  --trusted-local --allow-issues --expected-incarnation INCARNATION_HEX
```

Use `--object-format sha256` for a SHA-256 repository. Ordinary `cargo run -p
fgit-cli -- ...` continues to select `fg`; the second binary does not make the
existing invocation ambiguous. Configuration comes only from launch arguments,
not environment-driven repository discovery, client roots, or request bodies.
The repository must already exist, authenticate, and match its supplied IDs.
An optional incarnation pin is checked before any MCP tool is available.

The connected process receives repository-wide **issue read** access only when
`--allow-issues` is supplied. The local operator must trust the process receiving
these bytes. This is not remote authentication, per-issue ACLs, hostile process
isolation, or a full Intent Run/effect-broker capability. Do not proxy stdio to
untrusted remote clients or treat returned text as executable instructions.

## Tool contracts

`frankengit_issue_list` accepts optional `limit` (integer, 1..20, default 5),
`after` (unsigned decimal string), and `expected_head` (snapshot token).
`frankengit_issue_show` additionally requires `number` (positive decimal string)
and uses `after_version` instead of `after`. Show includes the issue state and
its exact action/comment history. Unknown fields, including principal, storage,
tenant, repository, mutation actions, and retry keys, are rejected.

Every result names the tenant, repository, incarnation, object format, and exact
`snapshot_token`. All 64-bit identifiers/counters/cursors use decimal strings,
not floating-point JSON numbers. A nonzero cursor requires the first page's
head token. Native retained-head readers refuse unavailable snapshots rather
than refreshing silently. `complete=false` and a non-null cursor mean more
source rows remain; they are not complete snapshots. Missing issues are explicit
`found=false` results. Storage/corruption/budget failures are tool errors, not
successful empty lists. Both structured content and JSON text are returned.

## Session and resource boundaries

Messages are UTF-8 JSON objects terminated by newline. The decoder rejects
batches, duplicate decoded keys, invalid UTF-8, malformed escapes, lone UTF-16
surrogates, non-JSON numbers, trailing bytes, excessive nesting, and oversize
collections before accepting a request. Input is capped at 64 KiB, decoded
strings at 16 KiB, depth at 16, collections at 256 entries, and parser nodes at
2048. IDs are bounded strings or exact signed 64-bit integers; reused IDs cannot
reexecute work. Initialization must finish before a tool call; notifications
never execute tools or produce responses.

The native node has two workers. Reads execute serially with native request,
replay, and storage budgets. A cancellation notification read after a completed
operation is late and never cancels a future request with that ID. This bounded
synchronous profile does **not** preempt an in-flight read or provide concurrent
requests, progress, tasks, subscriptions, prompts, sampling, or elicitation.
Clients may terminate the process to stop waiting; there is no mutation to infer
as rolled back. No cancellation/quiescence evidence for mutation is claimed.

A tool result is at most 2 MiB of encoded JSON; a complete protocol response is
at most 8 MiB. Large issue bodies can require a smaller page. No partial success
response is written before the entire result fits. Broken stdout stops the
session before another request executes. EOF, input failure, output failure,
and the message bound all reach explicit node shutdown. The default session
bound is 1024 messages, configurable to 1..100000 with `--max-messages`.
Diagnostics go to stderr; serving stdout contains only protocol messages.

## Verification and remaining FG-096 scope

The checked-in tests cover JSON boundaries, Unicode and exact numbers, handshake,
registry isolation, injection-shaped fields, late notifications, duplicate IDs,
framing, failed output, and response limits. A real-node test seeds canonical
issues, closes/reopens SHA-1 and SHA-256 repositories, calls the MCP handlers,
checks pagination and exact text, and verifies unchanged authority head.

Suggested local command: `cargo test --locked -p fgit-cli --bin fg-mcp`.
These tests have been written but have not been executed in the development
session that introduced this slice; that environment lacked Rust/Cargo. Do not
interpret source inspection as a passing package or independent batch gate.
FG-096 remains open: the full broker-backed mutation/tool registry, generated
public schema/client integration, remote sessions, live-client campaign, and
preemptive cancellation require their own implementation and evidence.

Protocol references: official MCP 2025-06-18 specification, sections
`basic/lifecycle`, `basic/transports`, and `server/tools`, at
`https://modelcontextprotocol.io/specification/2025-06-18/`.
