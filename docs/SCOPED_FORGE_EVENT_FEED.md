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

## Implementation and verification boundary

Owning bead: `frankengit-root-doctrine-x2mv.4.35`; plan §§24 and 31.
The shared node read uses one existing authenticated event-page selection and
never creates a second event database or changes canonical schemas. It remains
bounded **O(history)** replay (including existing authority materialization),
not the bead's O(limit) indexed-read acceptance. Indexed event lookup and optional
long-poll remain outstanding. This change does not close the bead.

Authored tests cover exact cursors, independent grants, hidden-ref filtering, filtering before
encoding, empty-page progression, byte-budget continuation, cancellation,
malformed pages, deterministic output, canonical-frame parity, full tool-registry
capacity, large response frames, and persisted SHA-1/SHA-256 restart/append.
They are **not executed evidence** in the toolchain-less editing environment.
Native compilation, rustfmt, Clippy, real-binary E2E and independent batch
verification remain required.
