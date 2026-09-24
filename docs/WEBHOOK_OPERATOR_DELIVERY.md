# Canonical webhook source inspection

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

## Limits and verification

Pagination bounds output, not total verification work: the existing canonical
reader still verifies the retained outbox and its dependencies. This slice does
not remove the repository-history scaling limits, supply TLS, configure a
subscription, or make generic HTTP receivers strongly idempotent. The separate
canonical settlement worker still requires a strong downstream contract.

Focused tests:

```
cargo test -p fgit-node treefs_workspace::outbox_delivery::selection::tests
cargo test -p fgit-cli webhook_commands::delivery::tests
```

Tests cover SHA-1/SHA-256 selection and reopen, exact event/root preservation,
disjoint pinned pages, stale pins, missing/differently addressed keys, staged-only
bodies, and CLI input/output budgets. They were added but not executed in the
implementation session: no Rust compiler or Cargo was available. No gate pass,
FG-046 closure, or production-readiness claim follows from source inspection.
