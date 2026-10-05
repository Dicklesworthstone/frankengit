# Scoped canonical forge event feed

`frankengit_events` exposes canonical issue and pull-request history to MCP
integrations. Launch `fg mcp` or `fg-mcp` with the existing `--trusted-local`
and `--allow-issues` and/or `--allow-pulls` read grants. Each grant discloses
only its own event family. Write, source, merge and outcome grants do not imply
an event read grant. The fixed tool registry advertises this tool only when
at least one of the two read grants exists.

```json
{"name":"frankengit_events","arguments":{"after":"0","limit":20}}
```

Continue with `next_after` while `has_more` is true. Retain `resume_after` even
when `next_after` is null: it is the watermark for polling after later commits.
An empty event array does **not** mean EOF; a filtered page can still have a
continuation. Omitting `after` or using `"0"` starts from the beginning. Other
cursors are canonical decimal `repository-sequence:event-index` strings,
including the complete u64/u32 ranges without floating-point conversion.

Pass the first response's `snapshot_token` as `expected_head` to require that
same authority head on later pages. A changed head refuses with `snapshot_moved`;
it never silently switches a pinned read. Omit the pin for append-stable polling.
The node reconstructs the cursor from committed history, not process memory, so
restarting a server does not invalidate an existing position. Keep cursors with
the repository incarnation **and** the grant profile. Broadening a grant does
not retroactively return events already skipped by that cursor; restart from
`0` to backfill newly authorized history.

## Disclosure and exact bytes

The `issues-pulls-v1` profile returns native issue lifecycle/comments and native PR lifecycle
and merge events. Review votes have an independent HTTP read scope and are
not implied by PR reads. Review votes, protection, workflow checks, merge queues,
organization, team, legacy and future event families are omitted, even with both grants.
A native PR or merge event is omitted when either of its refs is hidden by the
canonical policy at the same authority basis. Legacy events without complete
native ref coordinates are never used to bypass that disclosure check. This is an
explicitly filtered integration feed, not a complete forge backup. There is no
wildcard authorization, event append, acknowledgement or webhook settlement.

Every returned row contains `event_frame_hex`, the exact canonical event bytes
used by the trusted-local `fg events` command. Authorization filtering precedes
encoding and disclosure. An omitted event's payload, kind, aggregate, actor,
transaction and version are never returned. Repository positions and head tokens
**do reveal activity and gaps**, including positions consumed by filtering; the
response labels this with `cursor_discloses_repository_activity: true`.
This is not a traffic-analysis-resistant cursor or an absence proof.

All sequence, policy and aggregate-version values are decimal **strings** on
this remote profile. `fg events` retains its original numeric presentation;
canonical frame bytes, rather than JSON whitespace or number presentation, are
the parity contract. Repository text remains inert data inside hex frames.

## Bounds and failure semantics

`limit` is 1..100 (default 20) and bounds **canonical events examined** in a page,
not only visible results. Filtering never loops through additional history to
fill a page. A frame is bounded to 256 KiB; retained canonical frame bytes are
bounded to 512 KiB and encoded JSON/tool results to 2 MiB. A page byte boundary
stops before the next event and preserves it for the next cursor. An individual
oversized event refuses rather than being silently skipped. Input, authority,
cancellation and encoding failures return sanitized errors, not empty success.
The MCP adapter constructs response values directly: its small hostile-input
JSON parser is not reused for large output frames and its request bounds are
not relaxed.

## HTTP integration

The same filtered feed is available at
`GET <repository-url>/api/v1/events?after=0&limit=20` through `fg serve-http`.
Use `--credentials-file` with `--allow-issues` and/or `--allow-pulls`. Those
existing endpoint switches are ceilings, not grants: each request also needs
`issues-read` and/or `pulls-read` on its Bearer credential. The response reports
the intersection. Static Git tokens, source reads, metadata writes, reviews,
merge and outcome-recovery permissions never substitute for either read scope.

```text
GET /repo.git/api/v1/events?after=12%3A0&limit=20 HTTP/1.1
Host: 127.0.0.1:9419
Authorization: Bearer <operator-provisioned-token>
```

Use the repository URL from the service's readiness receipt, not the example
route. `after`, `limit` and optional `expected_head` are the only query fields.
The handler rejects duplicate decoded fields, malformed decimal cursors,
unknown parameters, request bodies, `Expect: 100-continue`, and Git protocol
headers. The endpoint accepts GET only and advertises `Allow: GET` on 405.
Unauthorized responses challenge Bearer only; cached browser Basic credentials
are not accepted. Existing cross-site and connection-lifetime handling remains
unchanged, and no CORS permission or TLS implementation is introduced.

The HTTP and MCP response data are identical (JSON key order is irrelevant).
Typed HTTP errors use `type: event_error`, `read_only: true`, and
`outcome_unknown: false`; no event or request body is echoed in a refusal.
Bad input is 400, missing credentials 401, insufficient scope 403, a mismatched
repository route 404, a moved snapshot 409, and an output limit 413. Internal
history/authority errors remain sanitized 503 failures, never empty success.
Responses are length-delimited JSON with `Cache-Control: no-store`,
`Vary: Authorization`, and `X-Content-Type-Options: nosniff`.

Authentication, endpoint ceilings, request validation and read quota precede
node leasing. Event reads share the existing expensive-source-read quota, not
the mutation or outcome-recovery quota. They do not acquire a writer permit.
The handler uses the existing bounded node pool and request/drain lifecycle;
a successfully completed response returns its node to the pool, while a read or
response failure closes that node. A failed output never causes a second,
contradictory response or a publication retry. Credential tables are reloaded by
the existing authentication boundary on each request, including after rotation.

### Real-binary campaign

```bash
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/forge/scoped_event_feed.sh
```

The discovered suite calls `scripts/e2e/scoped_events_smoke.py` and drives only
the supplied prebuilt binary. For SHA-1 and SHA-256 it creates and retries native
issue events, compares exact CLI/HTTP/MCP frames, walks hidden pages, checks
independent credential grants and malformed-query refusals with permitted twins,
restarts both transports, polls after an append, refuses an old snapshot pin,
and checks every HTTP service's drain accounting. Commands and HTTP operations
record their paths, durations, outcomes and retained transcripts; the shared
harness emits `EVENT-FEED-001` through `EVENT-FEED-005` acceptance records.
Missing tooling is a non-pass disposition, never a mock replacement. The
campaign's issue-only fixture does not establish live PR hidden-ref filtering;
that boundary has native unit cases and still needs a real-binary PR campaign.

## Implementation and verification boundary

Owning bead: `frankengit-root-doctrine-x2mv.4.35`; plan §§24 and 31.
The shared node read uses one authenticated head for configuration, disclosure
policy and event history, without materializing unrelated source/outbox state.
Recent-cursor reads walk only the verified decision suffix through that cursor;
initial reads and old-cursor backfills can still be **O(history)**. See
[the cursor-read contract](FORGE_EVENT_CURSOR_READS.md) for required-body checks,
work bounds and explicit non-claims. No second event database or canonical
schema is added. Indexed O(limit) lookup and optional long-poll remain
outstanding. These changes do not close the bead.

Authored tests cover exact cursors, independent grants, hidden-ref filtering, filtering before
encoding, empty-page progression, byte-budget continuation, cancellation,
malformed pages, deterministic output, canonical-frame parity, full tool-registry
capacity, large response frames, and persisted SHA-1/SHA-256 restart/append.
HTTP tests also cover per-request credential reload, endpoint ceilings, typed
response headers, successful reads from persisted SHA-1/SHA-256 nodes, output
failure followed by a safe retry, and response-bound refusal/permitted twins.
These Rust tests and the real-binary campaign are **authored, not executed
evidence** in the toolchain-less editing environment. Python syntax and shell
syntax checks do not establish that the native server compiles or the campaign
passes. Native compilation, rustfmt, Clippy, real-binary execution and independent
batch verification remain required.
