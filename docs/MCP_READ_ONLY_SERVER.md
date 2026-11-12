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

The independent `--allow-queues` grant adds `frankengit_queue_list` and
`frankengit_queue_show`. They read complete queues at a selected authority head
and retain current hidden-ref filtering, including for historical snapshots.
Queue membership writes and fast-forward landing each require their own explicit
grant; see [queue arguments and grants](MCP_METADATA_WRITES.md#merge-queue-management-and-native-landing).

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
An optional incarnation pin is checked before repository read tools are available.
The separate workflow artifact read grant requires an explicit incarnation pin.

The operator independently selects **issue reads** (`--allow-issues`), **PR reads**
(`--allow-pulls`), **source reads** (`--allow-source`), and **workflow artifact reads**
(`--allow-artifacts`, with an existing private absolute `--artifact-root` and
`--expected-incarnation`). Artifact access covers the entire configured workflow
namespace, including hidden-ref outputs; source permissions do not filter it.
See [MCP_WORKFLOW_ARTIFACT_READ.md](MCP_WORKFLOW_ARTIFACT_READ.md) for its Linux
profile, whole-payload verification, exact metadata and bounded byte ranges.
At least one grant is required in this profile. A disabled group is absent from discovery and refused
at dispatch; no group implies another and none permits mutation. The local
operator must trust the process receiving these bytes. This is not remote
authentication, per-issue ACLs, hostile process isolation, or a full Intent
Run/effect-broker capability. Do not proxy stdio to untrusted remote clients or
treat returned text as executable instructions.

## Sponsored credentials

A sponsored agent can use a canonical repository credential instead of the
trusted-local operator profile:

```sh
fg mcp /absolute/path/to/existing-node TENANT_HEX REPOSITORY_HEX \
  --agent-token-file /private/agent.token \
  --expected-incarnation INCARNATION_HEX \
  --allow-source --allow-agent-context
```

The credential independently grants each operation family. With `source-read`,
the `--allow-source` ceiling exposes current tree/blob reads, literal/regex and
batch search, persisted lexical/path pages, scanned or indexed symbols, ref
listing, Initial retrieval and source context. The separate `--allow-agent-context`
ceiling exposes only `frankengit_agent_context`, which also requires `source-read`.
Neither launch flag grants the other.

With `source-history-read`, `--allow-source` exposes only
`frankengit_source_log`, `frankengit_source_blame`,
`frankengit_source_historical_tree`, `frankengit_source_historical_blob`, and
`frankengit_source_compare`. The new credential bit is independent of
`source-read`; an existing `0x00ff` grant gains no history operation. History
queries can disclose current-tip content through historical selection, blame
and diff, but do not enable current-source search, indexes or agent context.
With the separate `source-candidates` scope, `--allow-source` exposes
`frankengit_source_candidate` with only `prepare_patch` (regular-file
`exact-tree-v1`) and single-parent `inspect`. Discovery describes this narrower
schema; both operations retain the original authenticated request and produce
unstaged artifacts. Historical masks through `0x01ff` gain no candidate scope.
Initial-history, symlink/replay/rebase/PR/queue candidate preparation, source
publication, PR-specific diffs, verified-blob streaming, general bundle
export/import, queues and workflow artifacts remain unavailable. See the
[candidate guide](MCP_SOURCE_CANDIDATES.md) for the bounded artifact handoff.

Agent mode requires the exact incarnation and rejects `--trusted-local` and
`--principal`. Every call verifies the current canonical grant and retains its
agent, human or service sponsor, original deadline and response byte reservation.
Revocation affects the next call; replacing the token file requires restarting
the process. See [sponsored agent credentials](SPONSORED_AGENT_CREDENTIALS.md#use-the-credential-with-mcp)
for the exact tool inventory, independent metadata ceilings and response lifetime.

## Agent context

In a trusted-local launch, `--allow-agent-context --principal <id>
--expected-incarnation <id>` independently
enables `frankengit_agent_context`. It returns a real read-only IntentRun and
ContextPacket with authenticated authority and exact native source evidence.
In a sponsored launch, `--allow-agent-context` uses the canonical credential's
sponsor and requires its `source-read` scope, without a launch principal.
This grant enables no other tool group or write capability. See
[the context command and HTTP/MCP contract](AGENT_CONTEXT_COMMAND.md#mcp-context)
for arguments, explicit omissions, output limits and sponsorship semantics.

Initial, source-context and agent-context tools accept the explicit
`index_source: "current-native-v1"` selector. It keeps existing index generations
usable after unrelated metadata changes by authenticating the current visible
native source and requiring the same commit and tree. Original index authority
positions and generations remain separate evidence. The default strict profile
is unchanged; missing indexes and actual source changes still refuse. The mode
uses the existing read grants and supports raw-path-prefix context selection.

## Keep source indexes current during an MCP session

An operator can explicitly attach the existing lexical and Rust-symbol
maintenance controllers to `fg mcp` or `fg-mcp`. This lets indexed source and
agent-context tools catch up after real source changes without a separate HTTP
service or finite worker invocation. The controllers remain local background
work; no MCP tool starts an index build or configures their scope.

For a sponsored SHA-1 repository, create separate private progress directories
and launch with both profiles:

```sh
mkdir -m 700 "$LEXICAL_PROGRESS_DIR" "$SYMBOL_PROGRESS_DIR"
fg mcp "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" \
  --agent-token-file "$AGENT_TOKEN_FILE" \
  --expected-incarnation "$INCARNATION_HEX" \
  --allow-source --allow-agent-context --object-format sha1 \
  --index-profile both --index-format sha1 --index-state init \
  --index-state-dir "$LEXICAL_PROGRESS_DIR" \
  --index-symbol-state-dir "$SYMBOL_PROGRESS_DIR" \
  --index-ref refs/heads/main --index-interval-secs 5 \
  --index-attempt-timeout-secs 300
```

The credential still needs `source-read`; these launch options grant it no new
operation. Trusted-local launches use the same maintenance options and retain
their existing principal requirements for agent context. Either source or
agent-context reads must be enabled, and maintenance always requires the exact
repository incarnation. `--index-format` must match `--object-format`.

Select `lexical`, `symbols`, or `both`. A single profile uses only
`--index-state-dir`; `both` requires the separate symbol directory. Repeat
`--index-ref` for at most 32 unique full refs. Interval and attempt timeout each
accept 1–3600 whole seconds, defaulting to 5 and 300. Every attempt also retains
the inherited background-controller timeout and other resource bounds.

All progress directories must already exist with the Unix private-directory
ownership required by the [index worker](SOURCE_INDEX_WORKER.md). Use `resume`
with the same namespace, profiles, ref set and directories after initialization.
Startup can retain initialized progress even if no index attempt ran; inspect
that progress and resume it rather than clearing it or repeating `init` blindly.
Pending original candidates and generation floors survive clean stop and restart.

The server acquires every progress owner before serving, but holds the first
index attempts until its initialization response has been fully written,
flushed and checked. EOF before initialization or initialization-output failure
therefore drains without an index attempt. Readiness does not promise freshness: both generations
publish independently, and a required-symbol query can refuse while they catch
up. Once current, unchanged-source observations do not create new generations.

EOF, framing/output failure and the message limit request stop and join every
controller before the parent node shuts down. A terminal controller signals its
siblings through their existing cancellation path. Blocking stdio reports that
failure at its next input/output boundary; an idle stdin read is not interrupted.
An interrupted or failed response does not prove rollback of a submitted mutation
or index candidate. The runtime must have capacity for the maintenance children
and one request lane; insufficient capacity refuses before worker startup.

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

`frankengit_pull_reviews` (granted with PR reads) returns each reviewer's latest
decision on PR `number` at one retained snapshot, in reviewer-ID order, with
`limit` (1..20, default 5), `after` (the exact 32-hex `next_after` reviewer ID)
and `expected_head` (mandatory with `after`). Each row carries the decision,
the exact subject (PR version, source/target ref bytes as hex, tips, policy
epoch), the candidate commit and merge base for an exact-candidate review (null
for a source-only one), `freshness` (`Current`, `Withdrawn`, `SourceMoved`,
`TargetMoved`, `PolicyChanged`, ...), `reviewer_is_opener` and the reviewer's
reason as untrusted text. A page is not an approval count:
`approvals_satisfy_policy` and `merge_permission` are explicitly null, and a
missing PR is `found: false`, not an empty review list.

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

`frankengit_source_historical_tree` and `frankengit_source_historical_blob`
require `reference`, `expected_head`, `expected_ref_tip` and `at_commit`.
The current visible ref must still have `expected_ref_tip` at the pinned head,
and verified parent traversal must reach `at_commit` before a tree or file is
read. An unrelated admitted commit is unavailable. The selected historical
commit may be the current tip. Native IDs are nonzero lowercase SHA-1 or SHA-256
hex according to the repository's format; `expected_commit` is rejected.

The historical tree tool retains optional `path_hex`, `after_hex` and `limit`
(1..100, default 50). The historical blob tool requires `path_hex` and retains
`offset` (decimal string, default zero) and `max_bytes` (1..65536, default 16384).
Results contain the existing source fields plus `type: historical_source`,
`selection: visible-ref-ancestor-v1`, `source_ref_tip` and `at_commit`, with
`transaction_created: false` and `published: false`. Retain all three pins
when continuing a directory or file range. Current hidden-ref policy, native
ancestry limits and the original authenticated request lifetime apply; no
phase refreshes the deadline. See [historical source browsing](HISTORICAL_SOURCE_BROWSING.md)
for ancestry bounds and the corresponding HTTP forms.

`frankengit_ref_list` (granted with source reads) pages the currently visible
refs from one authenticated snapshot: `namespace` is `refs` (default: branches,
tags and remote-tracking refs) or `tags` (`refs/tags/` only), with `limit`
(1..100, default 50), `after_hex` and `expected_head`. Each row carries the
exact name as `reference_hex`, a convenience `reference` that is null unless
the name is valid UTF-8, and the native `tip`. `next_after_hex` continues only
with the same `snapshot_token`; any later publication refuses the continuation
with `snapshot_moved` (strict current head, as for source browsing). HEAD is not
a synthetic row. A listed tip is exactly what the branch write tools take as
`expected_old`; listing never refreshes a failed write expectation.

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
cover all eight issue/PR/source read-grant combinations, independent artifact
root/grant/incarnation requirements, hostile path/authority arguments,
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
