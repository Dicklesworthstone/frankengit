# Independently approved backup acquisition over HTTPS

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).
Comprehensive plan: §21.5 (portable backup), §21.6 (verified recovery material),
§21.8 (independently controlled recovery copies).

The local recovery tools need archive bytes on disk. This operator retrieves
one explicitly approved archive from up to 16 explicit HTTPS mirrors, then
passes it to the existing [replica publisher](SIGNED_BACKUP_REPLICA_PUBLICATION.md).
An optional paired mode also retrieves an independently pinned LFS companion,
verifies the exact source/LFS snapshot through the trusted local `fg` binary,
and publishes both bodies before creating the original approval root.
The returned candidate can enter the existing signed native verify/restore path.
It neither implements another archive parser nor publishes repository authority.

## Usage

Keep the original signed approval and Ed25519 public trust key independent of
the download endpoints. Select an existing owner-private destination directory.
Put the HTTPS URL or URLs in a private, singly linked JSON file. URLs may contain
bearer capabilities such as pre-signed object-store query strings; do not put
them on the command line. The JSON file is limited to 16 KiB; the library permits
at most 64 KiB of canonical URL text across its 16 explicitly supplied sources.

```sh
node scripts/download_repository_backup.mjs \
  --sources /private/backup-source-urls.json \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --replica-directory /private/recovered-backups \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-read-bytes 4294967296 \
  --timeout-secs 300 --progress-json
```

The source file is a JSON array of strings, not an archive-discovered manifest.
The caller's order is the explicit mirror preference. URL usernames/passwords,
fragments, HTTP, unknown options and duplicate canonical URLs are refused.
The operation never discovers endpoints, follows redirects, uses ambient cookies,
adds arbitrary authorization headers, or retries a native mutation. Pre-signed
URLs are supported; refreshing an expired URL is an explicit operator action.
Normal HTTP 200 fixed-length and chunked responses are supported. Transformed
content, partial-content responses, trailers and protocol upgrades are refused.

Every request identifies the project with
`User-Agent: frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)`.
The header contains no source URL, signed query capability or repository secret.

System TLS roots and hostname verification are enabled. An optional `--ca-file`
selects one independent CA certificate for private storage. There is no insecure
mode. The request explicitly requires verification even when the process has
`NODE_TLS_REJECT_UNAUTHORIZED=0`. This remains a trusted-local operator, not a
server-side URL-fetch endpoint or a sandbox against hostile callers. Explicit
URLs can name private services; never feed it repository-supplied URLs as trusted
operator instructions. Stable owner-controlled parent directories are required.

### Acquire the source and its exact LFS payload companion

Retain the companion's SHA-256 digest and exact byte length independently of the
download service, alongside the source approval. Supply a second private JSON
URL file and every native verification option below. HTTP `Content-Length`, an
endpoint listing and the source approval cannot supply these companion pins.
The existing DSSE v1 statement signs only the source archive; the companion is
independently pinned and checked against that source's exact reachable pointers.

```sh
node scripts/download_repository_backup.mjs \
  --sources /private/source-urls.json \
  --lfs-sources /private/lfs-urls.json \
  --expected-lfs-sha256 "$LFS_SHA256" --expected-lfs-bytes "$LFS_BYTES" \
  --fg /trusted/bin/fg --trusted-local --verification-instance 99001 \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --replica-directory /private/recovered-backups \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-read-bytes 7516192768 \
  --max-requests 2 --timeout-secs 300 --progress-json
```

The library equivalents are `lfsSources`, `expectedLfsSha256`,
`expectedLfsBytes`, `fg`, `trustedLocal: true`, and `verificationInstance`.
Digest, length and instance are canonical strings; `fg` must be an absolute
path to the trusted local executable. Incomplete pair options refuse before
acquisition. Each URL list has its own limit of 16 mirrors and its own order.
The optional `maximumRequests` / `--max-requests` bounds attempts across both
lists together, up to 32; its default is the sum of their lengths. The same
attempt never changes the selected source approval or companion pins.

Success preserves the original two-field `candidate` and returns `lfs_archive`
plus a normalized `lfs_companion` receipt containing the digest, byte length,
object and payload counts, and `exact_snapshot: true`. It reports
`native_content_verified: true`, `lfs_payloads_verified: true` and
`lfs_companion_signed: false`. Pass the retained companion path and digest to
the [signed native verify/restore operator](PAIRED_LFS_BACKUP_RECOVERY.md)
along with the returned source candidate. Acquisition performs verification;
restore independently reauthenticates and rechecks the same pair before its
own authority publication.

The source-only invocation and result remain unchanged. Sealed download and
recovery jobs retain their existing source-only schemas; paired acquisition
requires this explicit direct CLI or library call.

## Trust and publication boundary

Before network access, authenticate the local approval, exact repository identity,
full-width generation floor, validity period and archive limit. Endpoint TLS
identity and HTTP headers cannot select repository state. Every mirror is tried
against the same independently signed artifact length and SHA-256 digest.
Missing, unavailable or corrupt copies may try another explicit mirror. TLS,
authorization, redirect, protocol-policy, cancellation, deadline and local
observer/disk failures refuse; error-code spelling alone cannot enable fallback.
Remote error objects, response headers and signed URLs are not included in
receipts or diagnostics. Attempt records contain canonical URL digests only.

A 64 KiB bounded reader writes an exclusively created, owner-private quarantine
file. Exact length and digest must match before the existing publisher is called.
The publisher reopens the original approval/key with exact equality pins and
performs its existing signature, freshness, source authentication, streaming copy,
destination readback and file/directory synchronization. Original approval bytes
publish last. A changed valid approval or trust key cannot retarget this handoff.
Downloaded bytes are never promoted just because HTTP completed successfully.

Paired acquisition first authenticates the signed source approval, then downloads
both bodies into a private, exclusively owned sibling quarantine outside the
destination. Neither destination body nor a new approval root can publish until
both independent transport pins match and the paired replica publisher completes
signed native source/LFS verification. Missing, truncated, corrupt or wrong-pair
LFS cannot turn a paired request into source-only success. The original approval
and public key, optional CA, and trusted executable must stay outside the writable
destination. The native process receives privately captured approval/key controls;
it does not receive the private URL capability files.

The archive-size ceiling and whole-operation payload-read ceiling are distinct.
For one N-byte source, fresh publication reads N network bytes and 3N local
publisher bytes: exactly 4N fits; 4N-1 refuses before connecting or creating scratch.
A full corrupt mirror followed by a good one needs 5N. Each mirror reserves its
whole signed length plus the publisher's remaining worst-case work before opening.
The default is `(sources + 3) × archive ceiling`; maxima are 1 TiB per archive and
19 TiB aggregate. Fixed small control reads, HTTP/TLS framing and socket buffers
are not payload accounting. One additional EOF byte per attempt is separately
bounded; it detects bodies exceeding signed length. HTTP headers are limited to
16 KiB and 64 pairs, with at most eight informational responses.

For a paired N-byte source and L-byte companion, fresh publication consumes
N + L network bytes and 3N + 2L measured local publisher bytes: exactly **4N + 3L**
fits. One byte less refuses before acquisition, as does a request allowance below
two. Each source attempt reserves one companion attempt and its bytes, plus the
publisher's remaining worst-case work. Corrupt mirrors spend the same measured
byte ledger and request allowance as successful mirrors; no component receives
a fresh operation budget. Each file independently fits the selected archive
ceiling, up to 1 TiB. The default paired aggregate ceiling is
`(source mirrors + LFS mirrors + 5) × archive ceiling`, up to 37 TiB.

Native preflight and the signed native adapter's local hashing are outside the
JavaScript payload ledger and are explicitly reported as
`native_preflight_metered: false`. They remain bounded by the selected per-file
archive ceiling, the native verifier's finite object/format limits and the
remaining original operation deadline. The reported 4N + 3L is the scoped
transport/publisher cost, not a claim about total native I/O.

One monotonic deadline covers local authentication, network work and publication.
The owned request, response, socket and fresh non-pooling agent are closed before
another source is attempted or transfer responsibility is released. A timer also
interrupts silence before headers, between data chunks and after the signed bytes
when the HTTP message has not ended. Callbacks and filesystem operations are
cooperative, not sandboxed or forcibly preempted; trusted callbacks must return.

## Retry and failure behavior

A retry downloads again; no HTTP range resume is claimed. Already published exact
files are reverified and synchronized by the existing publisher without rewriting
their inode. Add `--checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID` from the original
receipt to constrain a subsequent invocation to the exact original approval.
These equality pins never replace independent signature, expiry or floor checks.

SIGINT/SIGTERM request drain. Ordinary failures remove only this invocation's
identifiable quarantine files. SIGKILL can leave partial quarantine; later runs
neither trust, resume nor delete another process's scratch. Existing destination
conflicts refuse rather than overwrite. Errors preserve publication state and any
confirmed completion receipt. Failed final stdout delivery is not rollback.
The CLI emits only bounded redacted milestones when `--progress-json` is selected.

If native child containment cannot be established, paired acquisition retains
**both** downloaded inputs and their private quarantine. The error reports
`native_import_containment_failed`, `retained_download`, `retained_downloads`
and `download_quarantine_retained: true`, plus the native adapter's separately
retained approval scratch when available. It neither deletes inputs a child may
still use nor claims that process work ended. Resolve process ownership before
removing retained material. Ordinary cleanup removes only the owned files and
uses nonrecursive removal of the owned directory; ownership uncertainty also
preserves the path for operator recovery.

## Retained checkpoint witness

Append `--witness /independent/recovery-witness` to use an existing checkpoint
witness initialized by `scripts/repository_backup_witness.mjs init`. The CLI and
`downloadRepositoryBackupWithWitness` library entrypoint retain authenticated
newer or conflicting observations before expiry, archive-size and network checks.
An unavailable, expired, future-dated or over-budget higher checkpoint therefore
cannot be forgotten by omitting its approval on the next invocation. Missing or
corrupt witness state, a weaker retained floor and conflicting statements refuse
before network access. Invalid signatures are never retained as observations.

The existing exclusive witness lease spans HTTPS acquisition, request/socket
drain, approval-last publication and owned-file cleanup. A killed owner leaves a
blocking lease, without automatic lock stealing or reset. Ordinary cancellation
releases the lease after drain but preserves recorded checkpoint evidence. Exact
approval/key pins bind the observed statement to the downloader and publisher;
a valid substituted approval cannot retarget the handoff. A failure releasing a
witness after confirmed publication retains `completed_result` rather than
implying rollback. The result includes the witness snapshot and
`highest_retained_generation_enforced`; global currentness remains unproved.

The witness must be separate from the destination, approval, Ed25519 key, optional
TLS CA, trusted native executable and both private URL files. Lexical and resolved
physical paths are checked before witness ownership and after trusted progress observers, including parent
aliases. Stable owner-controlled ancestors remain required; this is not isolation
against malicious same-user writers. URL contents are neither persisted in the
witness nor included in download diagnostics.

This command processes ONE explicit approval, not the highest checkpoint across
several approval files. Without `--witness`, the original supplied-approval and
external-floor semantics remain unchanged. Neither mode establishes knowledge of
unobserved newer checkpoints. Use the existing witnessed native verify/restore
command for the returned candidate: acquisition success is not restore admission
or complete capsule recovery. Source-only acquisition does not perform a native
archive check; explicit paired acquisition does so before durable publication.

## Verification and non-claims

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-download.test.mjs \
  scripts/tests/repository-backup-download-cli.test.mjs \
  scripts/tests/repository-backup-download-witness.test.mjs \
  scripts/tests/repository-backup-download-lfs.test.mjs \
  scripts/tests/repository-backup-lfs-roundtrip.test.mjs \
  scripts/tests/repository-backup-replication.test.mjs
```

Tests use actual loopback HTTPS servers, Ed25519 signatures, local files, Node
subprocesses, SIGTERM/SIGKILL and reaping. A test-only OpenSSL invocation generates
an ephemeral localhost TLS certificate; production never executes it or accesses
its private key. Tests check corrupt-mirror fallback, exact work budgets, protocol
and trust refusals, redacted diagnostics, post-response substitutions, request
drain, interrupted CLI restart and retention of already published receipts.
Paired tests additionally exercise independently retained companion pins, shared
request and exact byte budgets, SHA-1/SHA-256 signed source identity, missing or
wrong-pair companions, concurrent immutable publication, witness ownership,
actual CLI option propagation and uncertain native-descendant containment.
Their native-schema subprocess peer checks actual Ed25519/source and companion
hash bindings over opaque fixture bytes; it is not the Rust archive verifier.
The paired round-trip suite composes the real HTTPS publisher, acquisition and
approved verification adapter for both Git hash formats, deleting the original
archives and adjacent approval before recovery. It checks identical recovered
bytes and the original signed approval, with the same explicit protocol-peer
limit on native claims.

The initial read-loop implementation waited for a full read size despite smaller
buffered data. A live TLS test exposed a microtask loop that could starve timers.
The implementation now reads available bytes up to the fixed limit; fragmented
and silent-peer tests exercise progress and deadline behavior.

Opaque payload fixtures are NOT native `fg` archives. These tests do not establish
Rust compilation, native archive/forge restoration, complete capsule recovery,
whole-workspace acceptance, public-provider interoperability, hardware power-loss
behavior, independent failure domains or global checkpoint currentness.

The separate `scripts/e2e/suites/operator/backup_https.sh` campaign retrieves real
signed native SHA-1 and SHA-256 archives previously published by the shipped
uploader/upload-job CLIs. It checks wrong-checkpoint and untrusted-TLS refusal,
corrupt-mirror failover constrained to the original approval, exact acquired
bytes, actual native signed restore and independent Rust Git/forge readback.
The recovery CLI also acquires over HTTPS, then resumes from its verified cache
with the fixture stopped and source-URL file absent. The object service is a
bounded disk-backed loopback TLS transport fixture, not a native forge or public
provider. A separately qualified prebuilt `FG_BIN` digest, pinned Node, sandboxed
Git 2.54.0, Python and test-only OpenSSL are required. Diagnostic originals remain
retained; this does not establish independent storage, destructive/hardware
faults, a full capsule, independent review, a fresh-current-main build or the
whole workspace gate.
