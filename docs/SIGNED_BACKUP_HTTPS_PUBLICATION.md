# Conditional signed-backup publication over HTTPS

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
This is the off-host publication counterpart of
[SIGNED_BACKUP_HTTPS_ACQUISITION.md](SIGNED_BACKUP_HTTPS_ACQUISITION.md), supporting
independently controlled recovery copies in comprehensive plan section 21.8.
It is a trusted-local operator, not a Rust object-fabric backend, repository
publication protocol, signing service, cloud-provider adapter or native restore.

## Retained jobs for restart and multiple destinations

[Resumable offsite backup publication](RESUMABLE_OFFSITE_BACKUP_PUBLICATION.md)
adds `repository_backup_upload_job.mjs seal|run` around this uploader. Seal
retains a private authenticated archive/approval pair and publishes an immutable
intent last. Each explicit run requires independent trust and policy, accepts
refreshed query capabilities for the exact sealed logical destination set, and
rechecks actual remote objects. Completed-target receipts survive later failures;
original source files are unnecessary after a successful seal. The job keeps
this uploader's conditional archive-before-approval publication and uncertainty
rules, with one aggregate payload budget and deadline across up to 16 targets.

## Explicit conditional object service

The service must implement HTTPS GET and conditional PUT with
`If-None-Match: *`, `Expect: 100-continue`, and exact object readback. PUT success
statuses are 200/201/204; 412 is a conditional conflict that requires independent
GET verification. GET accepts 200 or 404. Every other status refuses: no redirect,
implicit overwrite, delete, fallback endpoint, or automatic uncertain-PUT retry.
A service that withholds Continue is bounded by the same operation deadline.

Choose distinct archive and approval object paths under operator-controlled
storage. GET and PUT for each object must have the same origin and path; query
strings may differ to carry method-specific signed capabilities. The service
must identify the object by that path, not reinterpret query parameters as
another object selector. URLs never supply signing trust or repository identity.

Create a private, singly linked JSON file, at most 16 KiB:

```json
{
  "archive": {
    "get": "https://storage.example/backup/archive?get-capability=...",
    "put": "https://storage.example/backup/archive?put-capability=..."
  },
  "approval": {
    "get": "https://storage.example/backup/approval?get-capability=...",
    "put": "https://storage.example/backup/approval?put-capability=..."
  }
}
```

These endpoints are explicit operator instructions, never repository-discovered
URLs. They may address private services. This is not a server-side arbitrary-URL
fetch endpoint. No ambient cookies, proxy setup, arbitrary authorization headers,
URL user/password fields, fragments, or insecure TLS mode are supported. System
TLS roots and hostname verification remain required even if the process has
`NODE_TLS_REJECT_UNAUTHORIZED=0`; an independent CA file may be selected.

## Command

```sh
node scripts/upload_repository_backup.mjs \
  --input /private/repository.fgbackup \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --target /private/object-capabilities.json \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-bytes 3221225472 \
  --timeout-secs 300 --progress-json
```

The original local Ed25519 approval, namespace, full-width generation floor,
validity and source bytes are verified before remote access. The uploader holds
an open source descriptor, checks its named/open metadata, streams with a 64 KiB
buffer and rechecks its original digest. It never re-signs or modifies the source.
Stable owner-controlled local paths remain required; this is not isolation from
malicious same-user writers or non-cooperating filesystem calls.

The approval is checked for an existing exact copy first, followed by the archive.
Missing archive bytes are conditionally uploaded and then fetched and authenticated
against the original signed length and digest. Only after that readback may the
original approval bytes be conditionally published. Approval readback is always
repeated at the end, including exact retries. An existing approval with a missing
archive refuses rather than silently repairing dependencies under a visible root.
Conflicting objects are never overwritten: nominate different object locations.

## Completion, ambiguity and restart

Exit 0 returns a complete JSON receipt with approval/key equality pins, endpoint
fingerprints, disposition and bounded payload accounting. It contains no raw
signed URL, remote diagnostic body, request object or response headers. With
`--progress-json`, at most four redacted milestones appear on stderr.

Exit 1 means refusal or incomplete delivery, not rollback. `archive_put_unknown`
and `approval_put_unknown` conservatively retain responsibility for attempted
writes. No lost response authorizes an automatic second PUT. An explicit rerun
first checks remote objects and can reuse exact completed work without another
PUT. Add `--checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID` from the original receipt
or progress/error record to restrict the rerun to that original approval. The
pin never bypasses signature, expiry, floor or content checks.

SIGTERM/SIGINT drain the producer, request, response, private agent and socket.
Client-side closure does not prove that a remote handler or storage transaction
has quiesced: a paused receiver can defer observing closure.
SIGKILL can leave remote work whose outcome is unknown; no rollback is attempted.
A broken final output pipe retains `completed_result` when the upload already
completed. The uploader does not create a persistent job journal or retained
checkpoint witness. Keep equality pins and the minimum generation independently;
uploading an old explicit checkpoint is not evidence that it is the newest one.
Use the existing witnessed native verification/restoration commands for recovery.

## Bounds and verification meaning

At most six requests occur. One monotonic deadline spans control intake,
signature verification, local hashing, conditional writes and remote readback.
A fresh N-byte publication reserves exactly 3N archive-payload work: N initial
local hashing bytes, N upload-source bytes and N remote archive-readback bytes.
3N-1 refuses before connecting. An exact retry reads 2N but retains the same
conservative fresh-work reservation. The per-archive cap is 1 TiB and aggregate
cap 3 TiB; the aggregate cap never enlarges the archive cap. Upload-source counts
are conservative source bytes read for sending, not proof of network delivery.
Approval/key reads, bounded HTTP replies, framing and one-byte EOF probes are
separately bounded. Header bytes are capped at 16 KiB, final header pairs at 64,
informational responses at eight, and PUT response bodies at 16 KiB. Transformed,
partial, oversized, truncated and trailer-bearing successful replies refuse.

Conditional semantics are a service requirement, not something a client can
prove about an untrusted endpoint. Exact remote readback is not physical storage
durability, global currentness, independent failure domains, atomic simultaneous
availability, native archive/forge verification, or repository authority. A source
change can leave an unadvertised remote object; no invalid approval is published
to make that object acceptable. A provider's retention and durability policy
must be verified separately. No specific public storage provider is certified.

Focused executable verification:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-upload.test.mjs \
  scripts/tests/repository-backup-upload-cli.test.mjs \
  scripts/tests/repository-backup-upload-network.test.mjs \
  scripts/tests/repository-backup-replication.test.mjs
```

Tests use real loopback TLS, Ed25519 approvals, files, conditional object-service
fixtures and reaped Node subprocesses. They exercise lost PUT responses, early
conditional refusals, exact reruns, stalled Continue/EOF, cancellation, SIGKILL,
source substitution, final approval substitution and broken stdout. Both native
hash declarations complete upload, deletion of the local source, acquisition
through the existing downloader, and selection of identical recovered bytes.
Payloads remain opaque test bytes, not native fg archives. Rust, native admission,
complete capsule/forge recovery, public-provider interoperability, hardware
power-loss and full-workspace acceptance are not established by these tests.

A fully backpressured 32 MiB PUT also exercises producer/socket drain without
waiting for an unread remote handler. The SIGTERM peer test consumes incoming
bytes and awaits an explicit bounded close event; an arbitrary 30 ms sleep is
not used as evidence that remote closure has completed.
