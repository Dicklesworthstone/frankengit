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
These v1 jobs remain **source-only**. They reject the direct uploader's optional
LFS arguments and third target; no existing intent or target schema is widened.

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
An explicit source+LFS pair requires a third distinct `lfs` object with the same
GET/conditional-PUT rules. All three normalized origin/path identities must
differ; a different signed query does not make a shared path a distinct object.

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

Every GET and PUT identifies the project with
`User-Agent: frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)`.
It does not put signed URL capabilities or repository secrets into that header.

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

## Direct publication of a source+LFS pair

The direct command can publish the companion produced by native backup export.
Add the following options to the command above:

```sh
  --lfs-archive /private/repository.fglf \
  --expected-lfs-sha256 "$INDEPENDENT_LFS_SHA256" \
  --fg /opt/frankengit/bin/fg --verification-instance 992 --trusted-local
```

The independently selected digest and companion path are required together.
The trusted `fg` path must be absolute, and the verification instance must be an
explicit valid native instance. Add `lfs` to the private target file:

```json
{
  "archive": {
    "get": "https://storage.example/backup/archive?get-capability=...",
    "put": "https://storage.example/backup/archive?put-capability=..."
  },
  "lfs": {
    "get": "https://storage.example/backup/lfs?get-capability=...",
    "put": "https://storage.example/backup/lfs?put-capability=..."
  },
  "approval": {
    "get": "https://storage.example/backup/approval?get-capability=...",
    "put": "https://storage.example/backup/approval?put-capability=..."
  }
}
```

Before any HTTP request, the uploader authenticates the original signed source,
hashes the independently pinned companion and runs combined native verification
through the existing signed adapter. Native verification must prove that the
companion contains exactly the LFS payloads selected by that source's authentic
pointers. It is not sufficient for two unrelated files to have valid individual
hashes. Missing, changed, unrelated or invalid companions refuse the whole
operation; there is no source-only fallback. A source or companion size ceiling,
alias or byte-budget refusal also precedes networking. Both input descriptors
remain open and their original identities are checked across native verification
and transfer, including before approval publication. Hard-link aliases to the
source, verifier or control files and final-component symlinks are refused.

The original DSSE v1 envelope still signs **only the source archive**. It is
published unchanged. Companion authentication follows the native source-pointer
relationship, narrowed by the independent companion SHA-256. The complete receipt
returns normalized `lfs_companion` digest, byte count, object count, payload count
and exact-snapshot status, plus `lfs_companion_signed: false` and the checked
native verification receipt. Keep the LFS digest/length and endpoints together
with the approval/key checkpoint for recovery. A source checkpoint alone does
not retain the companion selection; an exact retry must repeat its independent
LFS pin.

The uploader first GETs approval, source and companion. If an existing approval
has either dependency missing or corrupt, it refuses before any PUT. In
particular, an existing source-only root does not authorize adding a missing
companion under that root. For a fresh publication, each missing body is
conditionally uploaded and independently fetched and hashed before the original
approval may be published. After callbacks and immediately before each missing
body PUT, the paired path also GETs the exact approval again: a newly observed
root is a refusal, not permission to repair its missing dependency. This bounds
what was observed; it cannot provide atomic remote snapshots or prevent a
non-cooperating writer from changing an object after a GET response.

Exact paired retries run native preflight again and can reuse all three remote
objects with GETs only. `lfs_verified_before_acknowledgement` records the current
operation's successful dependency verification. `lfs_verified_before_approval_put`
is true only if this invocation attempted approval publication after LFS readback;
it is false for an already-existing approval and makes no historical ordering
claim about another publisher. A concurrent exact approval can still win the
conditional PUT. An uncertain native preflight retains its reported verification
scratch path; the uploader does not recursively clean unknown native work.

## Completion, ambiguity and restart

Exit 0 returns a complete JSON receipt with approval/key equality pins, endpoint
fingerprints, disposition and bounded payload accounting. It contains no raw
signed URL, remote diagnostic body, request object or response headers. With
`--progress-json`, at most four source-only or seven paired redacted milestones
appear on stderr.

Exit 1 means refusal or incomplete delivery, not rollback. `archive_put_unknown`,
paired `lfs_put_unknown`, and `approval_put_unknown` conservatively retain responsibility for attempted
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

At most six source-only requests or eleven paired requests occur. The paired
ceiling includes two additional approval GETs immediately before missing body
PUTs. An exact paired retry needs four GETs. One monotonic deadline spans control
intake, signature verification, local hashing, optional native preflight,
conditional writes and remote readback.
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

For a paired source of N bytes and companion of L bytes, set the aggregate budget
to at least **3(N+L)**: one local hash, one upload-source read and one remote
readback for each body. One byte short refuses before native preflight or any
network request. Exact reuse consumes **2(N+L)** but retains that conservative
fresh-work reservation. The per-archive ceiling applies independently to both
bodies, each at most 1 TiB; the paired aggregate ceiling is 6 TiB, with a default
of six times the selected per-archive limit. Payload counting includes both
bodies and never expands either independent limit.

Paired `streaming.byte_budget_scope` is `local_authentication_and_https_transfer`.
The signed native adapter performs additional hashing and native graph/payload
verification; these reads are **outside** this JS payload meter and are reported
as `native_preflight_metered: false`. They are constrained by the same remaining
deadline and the native archive/object limits. No fixed native pass multiplier
or total native-read ceiling is asserted. Control reads and bounded HTTP status
payloads remain separate as in source-only publication.

Conditional semantics are a service requirement, not something a client can
prove about an untrusted endpoint. Exact remote readback is not physical storage
durability, global currentness, independent failure domains, atomic simultaneous
availability, or repository authority. Source-only publication performs no
native archive/forge verification. Paired publication verifies the native
source/LFS relationship locally before HTTP; it does not establish complete
capsule or forge recovery. A source
change can leave an unadvertised remote object; no invalid approval is published
to make that object acceptable. A provider's retention and durability policy
must be verified separately. No specific public storage provider is certified.

Focused executable verification:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-upload.test.mjs \
  scripts/tests/repository-backup-upload-cli.test.mjs \
  scripts/tests/repository-backup-upload-network.test.mjs \
  scripts/tests/repository-backup-upload-lfs.test.mjs \
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

The separate `scripts/e2e/suites/operator/backup_https.sh` campaign uploads actual
signed native SHA-1 and SHA-256 archives with this shipped CLI. It checks exact
budget/pin refusals, archive readback before approval publication and GET-only
exact retries. The upload-job path also loses an approval response after writing
its bytes, retains partial completion, and resumes with renewed capabilities
without another PUT. Downloaded bytes enter actual native signed restore and
separate Rust Git/forge reads. The HTTPS object service is a bounded disk-backed
loopback transport fixture; it is not a native forge or public-provider proof.
The campaign binds a separately qualified prebuilt `FG_BIN` digest and requires
pinned Node, sandboxed Git 2.54.0, Python and test-only OpenSSL for its ephemeral
CA. Original diagnostic bytes remain retained. No independent storage,
destructive/hardware fault, full capsule, independent review, fresh-current-main
build or full-workspace qualification is established.

The paired-upload tests add an explicit child protocol peer that authenticates
real Ed25519 envelopes and checks the native invocation and exact companion pins.
They use real loopback HTTPS, original files and the shipped CLI to cover paired
readback ordering, existing and newly observed incomplete roots, conditional
collisions, lost companion acknowledgements, exact retries, native preflight
refusals, retained scratch, mutation, aliases, cancellation and joint bounds.
The peer models native semantics over opaque fixture bytes: these tests are not
an actual native-LFS integration run or an extension of the source-only e2e
campaign's qualification claims.

`python3 scripts/e2e/selftests/test_backup_https_fixture.py` checks the campaign's
TLS owner using real sockets and filesystem failures. A startup journal failure
must drain its thread/listener before propagating the original error: failed
Python context entry does not automatically call `__exit__`. The tests also
exercise a permitted HTTPS request, body failure and terminal journal failure.
These are harness ownership regressions, not native or provider evidence.
