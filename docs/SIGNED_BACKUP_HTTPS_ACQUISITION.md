# Independently approved backup acquisition over HTTPS

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).
Comprehensive plan: §21.5 (portable backup), §21.6 (verified recovery material),
§21.8 (independently controlled recovery copies).

The local recovery tools need archive bytes on disk. This operator retrieves
one explicitly approved archive from up to 16 explicit HTTPS mirrors, then
passes it to the existing [replica publisher](SIGNED_BACKUP_REPLICA_PUBLICATION.md).
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

System TLS roots and hostname verification are enabled. An optional `--ca-file`
selects one independent CA certificate for private storage. There is no insecure
mode. The request explicitly requires verification even when the process has
`NODE_TLS_REJECT_UNAUTHORIZED=0`. This remains a trusted-local operator, not a
server-side URL-fetch endpoint or a sandbox against hostile callers. Explicit
URLs can name private services; never feed it repository-supplied URLs as trusted
operator instructions. Stable owner-controlled parent directories are required.

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
identifiable quarantine file. SIGKILL can leave partial quarantine; later runs
neither trust, resume nor delete another process's scratch. Existing destination
conflicts refuse rather than overwrite. Errors preserve publication state and any
confirmed completion receipt. Failed final stdout delivery is not rollback.
The CLI emits only bounded redacted milestones when `--progress-json` is selected.

This command processes ONE explicit approval, not the highest checkpoint across
several approval files. The external minimum generation is mandatory. It does not
modify a retained checkpoint witness or claim knowledge of the newest global
checkpoint. Use the existing witnessed native verify/restore command for the
returned candidate so retained higher/conflicting observations still gate native
restoration. Download success is not restore admission or a native archive check.

## Verification and non-claims

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-download.test.mjs \
  scripts/tests/repository-backup-download-cli.test.mjs \
  scripts/tests/repository-backup-replication.test.mjs
```

Tests use actual loopback HTTPS servers, Ed25519 signatures, local files, Node
subprocesses, SIGTERM/SIGKILL and reaping. A test-only OpenSSL invocation generates
an ephemeral localhost TLS certificate; production never executes it or accesses
its private key. Tests check corrupt-mirror fallback, exact work budgets, protocol
and trust refusals, redacted diagnostics, post-response substitutions, request
drain, interrupted CLI restart and retention of already published receipts.

The initial read-loop implementation waited for a full read size despite smaller
buffered data. A live TLS test exposed a microtask loop that could starve timers.
The implementation now reads available bytes up to the fixed limit; fragmented
and silent-peer tests exercise progress and deadline behavior.

Opaque payload fixtures are NOT native `fg` archives. These tests do not establish
Rust compilation, native archive/forge restoration, complete capsule recovery,
whole-workspace acceptance, public-provider interoperability, hardware power-loss
behavior, independent failure domains or global checkpoint currentness.
