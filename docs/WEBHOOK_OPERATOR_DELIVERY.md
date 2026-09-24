# Canonical webhook operator delivery

Owning product work: FG-046. This is a trusted-local operator surface, not a
new repository authority or an automatically running webhook service.

## Find a committed delivery

```
fg webhook outbox ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local --limit 20
```

The command opens the existing repository using the supplied tenant/repository
identity. It authenticates the selected head, verifies the outbox and retained
dependencies, and returns bounded JSON with delivery IDs, original destinations,
payload roots, effect-state roots, a snapshot token, and an optional next cursor.
It lists retained entries, including settled entries: it is not a pending queue.

Pass `--after DELIVERY_ID --expected-head SNAPSHOT_TOKEN` for the next page.
Outbox order is canonical delivery-key order, not commit order. An unpinned
cursor is not append-stable; use the snapshot token across pages. A moved pin
refuses instead of mixing snapshots. SHA-256 repositories require
`--object-format sha256` (the default is `sha1`). Limits are 1 through 100.

## Inspect exact native event bytes

```
fg webhook inspect ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --delivery-id DELIVERY_ID --destination CANONICAL_DESTINATION \
  --expected-head SNAPSHOT_TOKEN
```

Use the ID, destination, and token from `outbox`. The selector does not accept a
caller-supplied root or event body. It reads the batch named by the authenticated
outbox, retains every original delivery parameter, and rejects missing keys,
destination mismatches, unsupported effect classes, corrupt/missing bodies,
cancellation, and budget exhaustion. Staging a body without publishing its root
does not make it selectable. Legacy non-native evidence that would require a
replacement/normalized batch is outside this inspection profile and refuses.

The result includes the complete ordered canonical event frames as lowercase
hex. Decode each with `fgit_codec::decode_body::<ForgeEvent>`. This is not the
GitHub webhook JSON schema. Output is capped at 64 MiB. Repository shutdown
must complete before any successful result is emitted. Both commands are
read-only; neither sends a webhook nor acknowledges an obligation.

## Send a selected delivery

```
fg webhook deliver ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --delivery-id DELIVERY_ID --destination CANONICAL_DESTINATION \
  --at-least-once --expected-head SNAPSHOT_TOKEN
```

The registered endpoint is an explicit operator binding for the original
canonical destination. The delivery ID is not a destination, and the command
never rewrites the selected key, destination, or payload commitment. It closes
the repository runtime before invoking the existing signed HTTP adapter with
the verified batch. No caller-supplied event file or dummy batch is accepted.
The registration must be active and must admit every event in the batch.

`--at-least-once` is mandatory: this is **one explicitly requested manual
attempt**, not an automatic worker or an exactly-once guarantee. A successful
HTTP observation is not canonical outbox settlement. Results carry
`canonical_settled:false`, `automatic_retry:false`, the original root and source
snapshot, the observed verdict, and the attempt number. A failed output stream
may lose a receipt after the receiver has already accepted the request.

Supported subscription families are `pull_request`, `pull_request_review`,
`issue`, `review_protection`, `merge_queue`, and `workflow_check` (case-insensitive).
An exact `kind:N` filter selects a canonical numeric event kind. `all`/`*` remains
the wildcard registration. The manual path refuses an entire mixed batch when
any event fails the filter; it does not remove events while retaining the old
batch commitment. This does not yet implement per-subscription canonical fan-out.

Default egress uses the existing strict SSRF policy. `--permissive-for-tests`
permits loopback tests only under the adapter's existing policy. HTTPS still
refuses without verified TLS; no downgrade is performed. No retry is launched
by this command. Exit codes are 0 for observed acceptance, 1 for transient
failure, 2 for refusal/rejection, and 3 for an ambiguous outcome. Do not treat
exit 3 or lost stdout as proof that the receiver did nothing.

## Replay an actual dead letter

```
fg webhook dead-letter replay ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --delivery-id DELIVERY_ID --destination CANONICAL_DESTINATION \
  --at-least-once
```

Replay now reselects the canonical payload and contacts the receiver. It does
not delete a diagnostic and print a fictitious success. The retained record's
delivery ID, webhook ID, exact endpoint URL, and algorithm-tagged payload root
must match the selected request and current registration before any network I/O.
Missing, stale, or retargeted diagnostics refuse. Older records containing
placeholder roots cannot authorize a replay.

Diagnostic dead letters remain retained, including after observed acceptance:
the local diagnostic store is not a canonical settlement ledger. The replay uses the
next diagnostic attempt ordinal (1..16); an explicit `--attempt` must match it.
Attempt headers and local diagnostics do not create a durable retry reservation,
and do not reset or bypass the automatic worker's canonical retry protocol.
Repeated manual invocations can duplicate effects. A retained diagnostic is not
proof that a previous attempt failed, nor proof that the next send is safe.

## Limits and verification

Pagination bounds output, not total verification work: the existing canonical
reader still verifies the retained outbox and its dependencies. This slice does
not remove the repository-history scaling limits, supply TLS, configure a
canonical subscription fan-out, or make generic HTTP receivers strongly idempotent. The separate
canonical settlement worker still requires a strong downstream contract.

Focused tests:

```
cargo test -p fgit-node treefs_workspace::outbox_delivery::selection::tests
cargo test -p fgit-cli webhook_commands::delivery
```

Tests cover SHA-1/SHA-256 selection and reopen, exact event/root preservation,
disjoint pinned pages, stale pins, missing/differently addressed keys, staged-only
bodies, CLI input/output budgets, explicit manual opt-in, bounded attempts,
whole-batch subscription checks, and dead-letter identity mismatch. Additional
Unix CLI-path loopback tests exercise actual committed-event delivery and HMAC,
real replay with diagnostic retention, refusal before connecting, and a lost
receiver acknowledgement without an automatic retry. They were added but not executed in the
implementation session: no Rust compiler or Cargo was available. No gate pass,
FG-046 closure, or production-readiness claim follows from source inspection.
