# Repository-scoped MCP read-only launch profile (FG-096 implementation slice)

`fg-mcp` is a real stdio Model Context Protocol server over `OneNode` operations.
It implements the pinned MCP **2025-06-18** initialization handshake, ping,
`tools/list`, and `tools/call`. It does not launch `fg`, Git, or a shell to
answer requests. Its registry and handler permissions are fixed at launch;
repository content, client capabilities, and tool arguments cannot expand them.

This page describes the **read-only launch profile**. Separately enabled issue
mutations and principal-scoped recovery are documented in
[MCP_METADATA_WRITES.md](MCP_METADATA_WRITES.md). No read flag enables them.
The restrictions below remain the boundary of a read-only launch.

## Launch

```sh
cargo run --locked -p fgit-cli --bin fg-mcp -- \
  /absolute/path/to/existing-node TENANT_HEX REPOSITORY_HEX \
  --trusted-local --allow-issues --allow-pulls --allow-source \
  --expected-incarnation INCARNATION_HEX
```

Use `--object-format sha256` for a SHA-256 repository. Ordinary `cargo run -p
fgit-cli -- ...` continues to select `fg`; the second binary does not make the
existing invocation ambiguous. Configuration comes only from launch arguments,
not environment-driven repository discovery, client roots, or request bodies.
The repository must already exist, authenticate, and match its supplied IDs.
An optional incarnation pin is checked before any read tool is available.

The operator independently selects **issue reads** (`--allow-issues`), **PR reads**
(`--allow-pulls`), and **source reads** (`--allow-source`). At least one grant is
required in this profile. A disabled group is absent from discovery and refused
at dispatch; no group implies another and none permits mutation. The local
operator must trust the process receiving these bytes. This is not remote
authentication, per-issue ACLs, hostile process isolation, or a full Intent
Run/effect-broker capability. Do not proxy stdio to untrusted remote clients or
treat returned text as executable instructions.

## Issue read tools

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

## Source and PR read tools

`frankengit_pull_list` accepts `after`, `limit` and `expected_head` like issue
lists. `frankengit_pull_show` accepts only `number` and optional `expected_head`.
Native metadata and explicit merge-only receipts remain distinct. Reads retain
current canonical hidden-ref filtering even at a retained head; missing and
hidden PRs are not distinguished. Metadata is not an approval count or merge
permission (`merge_permission` is explicitly null).

`frankengit_source_tree` accepts required `reference` (full UTF-8 ref such as
`refs/heads/main`), optional `path_hex` (omitted for the root), `limit` (1..100,
default 50), `after_hex` (one immediate child), `expected_head`, and
`expected_commit`. Directory names are sorted raw bytes and returned as hex.
`frankengit_source_blob` uses the same reference and mandatory `path_hex`, with
`offset` (decimal string, default zero), `max_bytes` (1..65536, default 16384),
and optional expected head/commit. It returns `bytes_hex` without loss and a
convenience `text_utf8` only when the exact slice is valid UTF-8. Byte ranges
can split a Unicode character; concatenate exact bytes, not nullable text.
Symlink payloads are data and never followed; gitlinks cannot be read as files.

Every source reply binds the selected commit, root tree, source RCR, object ID,
and path. `next_after_hex` and `next_offset` require the same head token on the
next call. Unlike metadata retained-head pagination, source browsing uses strict
current-head pins; an intervening publication refuses continuation rather than
mixing snapshots. A supplied commit ID compares the visible ref; it is not an
arbitrary object lookup or a bypass for current hidden-ref policy. Repository
paths never become host paths. Existing native object/read budgets apply in
addition to output page ceilings. All source and PR reads use the same error,
structured-content, and read-only operation boundary as issue reads.

## Session and resource boundaries

Messages are UTF-8 JSON objects terminated by newline. The decoder rejects
batches, duplicate decoded keys, invalid UTF-8, malformed escapes, lone UTF-16
surrogates, non-JSON numbers, trailing bytes, excessive nesting, and oversize
collections before accepting a request. Input is capped at 64 KiB, decoded
strings at 16 KiB, depth at 16, collections at 256 entries, and parser nodes at
2048. IDs are bounded strings or exact signed 64-bit integers; reused IDs cannot
reexecute work. Initialization must finish before a tool call; notifications
never execute tools or produce responses.

The native node has two workers. Operations execute serially with native
request, replay, and storage budgets. A cancellation notification read after a
completed operation is late and never cancels a future request with that ID.
This synchronous profile does **not** preempt an in-flight read or provide
concurrent requests, progress, tasks, subscriptions, prompts, sampling, or
elicitation. In a read-only launch no tool can mutate. For an explicitly enabled
metadata mutation, disconnect or cancellation does not prove rollback; consult
the separate mutation and recovery contract.

A tool result is at most 2 MiB of encoded JSON; a complete protocol response is
at most 8 MiB. Large issue bodies can require a smaller page. No partial success
response is written before the entire result fits. Broken stdout stops the
session before another request executes. EOF, input failure, output failure,
and the message bound all reach explicit node shutdown. The default session
bound is 1024 messages, configurable to 1..100000 with `--max-messages`.
Diagnostics go to stderr; serving stdout contains only protocol messages.

## Verification and remaining FG-096 scope

The checked-in read tests cover JSON boundaries, Unicode and exact numbers,
handshake, registry isolation, injection-shaped fields, late notifications,
duplicate IDs, framing, failed output, and response limits. Real-node tests seed
canonical issues, close/reopen SHA-1 and SHA-256 repositories, call the MCP
handlers, check pagination and exact text, and assert unchanged authority head.
Another test publishes a native initial patch, creates a branch/PR, reopens both
hash domains, reads actual source ranges and PR metadata, and checks strict
source versus retained PR behavior across a later ordinary write. Unit tests
cover all eight read-grant combinations, hostile path/authority arguments,
byte-exact binary results, directory cursors and no implied merge approval.

Suggested command: `cargo test --locked -p fgit-cli --bin fg-mcp`.
These tests were written but were not executed in their authoring sessions;
Rust/Cargo were unavailable. Do not interpret source inspection as a passing
package or independent batch gate. FG-096 remains open: broker-backed tools,
generated public schema/client integration, remote sessions, live-client
campaigns and preemptive cancellation require further implementation/evidence.

Protocol references: official MCP 2025-06-18 specification, sections
`basic/lifecycle`, `basic/transports`, and `server/tools`, at
`https://modelcontextprotocol.io/specification/2025-06-18/`.
