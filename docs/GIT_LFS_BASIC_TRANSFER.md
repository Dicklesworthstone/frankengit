# Git LFS basic and resumable transfer

`fg serve-http --lfs-root <private-directory>` exposes Git LFS basic upload,
resumable Tus upload, download, and verification through the existing immutable artifact
store. This Linux-only profile is opt-in. A Git remote at
`http://127.0.0.1:8080/<repository-id>.git` uses the standard LFS endpoint
`http://127.0.0.1:8080/<repository-id>.git/info/lfs`.

Git commits retain their ordinary LFS pointer blobs. The HTTP adapter transfers
the referenced bytes without rewriting those blobs or creating a second ref
authority. An upload publishes immutable custody of an object; publishing a
Git branch still requires the existing authenticated receive path and its
authority-head compare-and-swap.

## Enable a repository

Start with an initialized FrankenGit repository and an existing private artifact
directory owned by the service operator. The directory must have mode `0700`;
the service refuses unsafe custody roots before reporting readiness.

```sh
mkdir -m 700 /srv/frankengit-lfs
fg serve-http /srv/frankengit-state "$TENANT_ID" "$REPOSITORY_ID" 127.0.0.1:8080 \
  --trusted-local --print-credentials-header
```

Use that command's exact header as the first line of a private credentials file.
It binds the grants to the authenticated repository incarnation. Following rows
have this form:

```text
<sha256-of-token-text> <principal-id> read,receive,lfs-read,lfs-write
```

The token is a secret, 64-character lowercase hexadecimal value. Hash its UTF-8
text without a trailing newline, as for existing HTTP credentials. Store only
the hash in the table; make the table a regular file with mode `0600` or stricter.
Choose only the grants needed by the principal. Scope order is canonical: the
existing scopes come first, then `lfs-read`, then `lfs-write`.

```sh
fg serve-http /srv/frankengit-state "$TENANT_ID" "$REPOSITORY_ID" 127.0.0.1:8080 \
  --trusted-local --credentials-file /srv/frankengit-credentials \
  --lfs-root /srv/frankengit-lfs --allow-receive \
  --continuous --stop-file /srv/frankengit-stop
```

The stop file must initially be absent in an existing operator-owned directory.
Creating it drains the listener through the normal continuous-service lifecycle.
Readiness includes `lfs_enabled: true` only when the profile was explicitly
selected and custody validation succeeded. Omitting `--lfs-root` disables all
LFS transfers. `--token-file` cannot enable LFS: the CLI requires the scoped,
reloadable credentials file.

Configure stock Git and Git LFS to use the same repository URL and a credential
helper that returns the token as the Basic-auth password. A Bearer token is also
accepted. Do not put a token in a remote URL. A normal client workflow is:

```sh
git lfs install --local
git lfs track '*.bin'
git add .gitattributes model.bin
git commit -m 'Track model payload with LFS'
git push origin HEAD:refs/heads/main
```

For externally reachable deployments, place the loopback service behind the
existing TLS terminator and set `--trusted-origin https://git.example.com` to its
public origin. Batch action URLs use only that configured origin or the
accepted socket's loopback address. Request `Host` headers cannot select an
action destination, and action responses do not echo credentials.

## Independent authority and verified custody

| Grant | Capability |
| --- | --- |
| `read` | Git discovery and fetch; no LFS access |
| `receive` | Git receive, subject to the receive enablement and publication policy; no LFS access |
| `lfs-read` | LFS download batches and verified object downloads |
| `lfs-write` | LFS upload batches, immutable uploads, resumable upload status/append, and upload verification |

No scope implies another. `--allow-receive` does not enable LFS, and LFS uploads
remain possible with Git receive disabled. Every batch, object, and verification
request reloads and authenticates the credential table. Atomically replacing
the table revokes subsequent requests; an already authenticated in-flight
request retains its bounded grant.

Object identity is the exact SHA-256 digest and byte length. Storage namespaces
also bind the tenant, repository, and authenticated repository incarnation.
Payload size and digest are checked before publication. Downloads are fully
verified before any payload bytes are disclosed. Corrupt objects are refused;
the service does not turn corrupt custody into an apparent cache miss or serve
a verified prefix followed by unverified bytes.

For a download, the service verifies the complete stored container while
copying its payload into private temporary custody, unlinks the temporary name
before writing payload bytes, and verifies the retained copy again. Only then
does it send the success headers and stream the payload in chunks no larger
than 64 KiB. A later change to the original custody file cannot change this
verified response. Cancellation, an expired deadline, or a write failure ends
the response; a partial binary response never gains an appended error document.

### Resume a verified download

Object downloads advertise `Accept-Ranges: bytes` and a strong `ETag` binding
the complete SHA-256 payload identity and length. A client can resume with
`Range: bytes=<received>-` and the previously returned `If-Range` validator.
Closed ranges (`bytes=100-199`) and suffix ranges (`bytes=-100`) are supported
too. Successful ranges return `206 Partial Content`, an exact `Content-Range`,
and a `Content-Length` equal to the transmitted slice. A range ending beyond
the payload is clipped to its last byte.

The adapter follows the single-range and validator rules in
[RFC 9110 §§13.1.5 and 14](https://www.rfc-editor.org/rfc/rfc9110.html#section-14).
An unknown range unit or multi-range request selects the ordinary full `200`
response. A mismatched or weak `If-Range` tag, or a date validator (no
`Last-Modified` is published), also selects the full response. `If-Range`
without `Range` is ignored. Malformed, reversed, oversized or duplicate range
fields return `400` after authentication. Byte-range syntax is bounded to 256
bytes; large decimal end positions and suffix lengths clamp without integer
overflow. Unsatisfiable single ranges, including a zero-length suffix or a
range on an empty object, return `416` with `Content-Range: bytes */<size>`.

Authentication, LFS scope, quota, and whole-object integrity still precede
representation disclosure. Missing custody returns `404`; corrupt custody
returns `503`, even when the damaged bytes lie outside the requested range or
the requested range is unsatisfiable. The complete verified private copy is
created before any `206` or `416` response. The range sender discards the prefix
and streams the selected bytes in at most 64 KiB chunks under the original
operation deadline. Resume saves network transfer, but does not avoid complete
verification, temporary-disk custody, or the prefix read. Interruption while
skipping emits no successful payload header; interruption after response
output begins terminates it without a second error document. `Range` on PUT
is ignored and never enables partial uploads.

Fixed-length and chunked HTTP request bodies use the existing bounded native
framing parser. Short bodies, malformed chunks, incorrect lengths, and digest
mismatches cannot publish an object. Authentication and the endpoint's required
scope precede `100 Continue`; the batch operation's scope is checked after its
bounded JSON body is decoded. A failed or interrupted upload may be retried with
the same identity and complete payload. A successful upload repeated under the
same identity is idempotent. An upload batch omits upload actions for objects
already present in verified custody.

### Resume an upload with Tus

Enable the Git LFS client's existing resumable upload adapter in the client
repository:

```sh
git config --local lfs.tustransfers true
git push origin HEAD:refs/heads/main
```

The client must also allow advanced transfers (`lfs.basictransfersonly` must not
be true). See the upstream [Git LFS configuration reference](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc)
and [Tus upload adapter](https://github.com/git-lfs/git-lfs/blob/main/tq/tus_upload.go).
When an upload Batch request offers `tus`, the server selects it and returns an
authenticated `/info/lfs/objects/<oid>/<size>/tus` action. Repeating Batch resumes
the same principal's existing session without discarding its acknowledged
prefix. An omitted transfer list still selects `basic`; downloads continue to
select `basic` and retain their range support.

The adapter implements the [Tus 1.0 core protocol](https://tus.io/protocols/resumable-upload).
Batch creates the upload resource, as expected by Git LFS; a separate creation
request is unnecessary.

| Request to the upload action | Result |
| --- | --- |
| `HEAD` with `Tus-Resumable: 1.0.0` | `200`, durable `Upload-Offset`, fixed `Upload-Length`, no body, and `Cache-Control: no-store` |
| `PATCH` with version, exact `Upload-Offset`, and `Content-Type: application/offset+octet-stream` | Streams fixed-length or chunked bytes; `204` and the new durable offset on success |
| `OPTIONS` | `204`, `Tus-Version: 1.0.0`, `Tus-Max-Size`, and the supported methods; ignores the request's Tus version |
| Missing/unsupported version on HEAD or PATCH | `412` and the supported Tus version |
| A stale PATCH offset | `409`, without consuming its body or modifying the upload |

All three methods require a current `lfs-write` grant. Unfinished sessions bind
the exact principal, object digest, length, tenant, repository and incarnation;
another principal cannot inspect or append their prefixes. Credential rotation
that preserves the principal can resume; revoking the grant prevents subsequent
status and append requests. `X-HTTP-Method-Override` is supported, and an override
to PATCH remains subject to the listener's cross-site mutation guard. Version,
scope, size, session existence and offset checks precede `100 Continue`.
No Tus extensions are advertised. Creation, concatenation, deferred length,
metadata, per-request checksum and termination requests are refused. Whole-object
SHA-256 verification is mandatory regardless of the transfer mode.

An interrupted PATCH retains a synced, checked prefix. Reissue HEAD before
retrying, because a failed response does not establish how many bytes became
durable. A process restart may lose only bytes beyond the retained checkpoint;
an acknowledged offset is never inferred from the staging file's length. Every
reopen verifies the checkpoint's prefix digest. A complete offset is reported
only after valid request framing, exact whole-object length and SHA-256,
immutable publication, and canonical readback have all succeeded. HEAD can
finish publication from an already verified final checkpoint after a crash.
Malformed final framing cannot produce a full offset, and a wrong final digest
poisons the session instead of silently resetting or publishing it. Empty objects
complete during Batch only when their digest is SHA-256 of the empty payload.

#### Durable staging and recovery

Staging is derived transfer custody, separate from the immutable artifact
namespace and from Git authority. A private scope directory contains a bounded
catalog and one locked directory per session. Session names are SHA-256 over the
`frankengit/lfs-upload-session/v1` domain separator (including its terminating NUL),
the existing artifact-scope commitment, and the identity record. Files are private
regular files with one link; unexpected entries, symlinks and inconsistent
records fail closed. Locks are nonblocking and shared across service processes.

The versioned identity record is exactly 64 bytes: `FGLFID01`, the 16-byte
principal, the 32-byte LFS SHA-256, and an 8-byte big-endian length. The checkpoint
is exactly 81 bytes: `FGLFCP01`, the 32-byte session-name digest, an 8-byte
big-endian offset, the 32-byte prefix SHA-256, and one state byte (`0` active,
`1` verified and ready for immutable publication, `2` poisoned). Active offsets
must be smaller than the object length; ready offsets equal it and carry the
expected object digest. Poisoned or unknown states refuse further progress.
Payload sync precedes atomic checkpoint replacement and directory sync.

Each scope permits at most 64 unfinished sessions and reserves at most 4 GiB
of their declared lengths, including bytes not yet received. The object limit
remains 512 MiB. A reservation failure produces an individual Batch `429` error;
an occupied lock produces a retryable `503`. Successful completion removes that
principal's staging under the catalog lock and returns its reservation. Crash
residue stays charged until an exact retry completes cleanup. Abandoned or
poisoned sessions do not expire automatically: operator inspection and cleanup
requires stopping writers first. Deleting staging loses resumable progress;
it does not delete immutable payloads or change Git refs. Older basic-only
servers cannot resume these sessions, but already published payloads retain the
same storage identity and remain readable.

## Current bounds and recovery limits

This profile supports `basic` transfers, `tus` uploads, and SHA-256 LFS object IDs for both
SHA-1 and SHA-256 Git repositories. It accepts at most 100 objects per batch,
64 KiB of batch/verification JSON, 512 MiB per object, and 512 MiB of aggregate
declared payload bytes for verification within one batch. Objects outside the
batch verification budget receive individual errors; supported objects retain
their original order and identity. Request deadlines, bounded listener
concurrency, and principal quotas also apply.

Upload, verification, temporary-copy readback, and response delivery share the
original request deadline. Neither `100 Continue` nor the first response write
renews it. Streaming avoids a payload-sized memory allocation; each active
download can require up to 512 MiB of temporary disk space in the selected
private custody root. The complete-verification passes incur additional disk
I/O under that same deadline. A dropped reader or failed request closes the
unlinked file. The existing buffered library read API retains its separate
64 MiB ceiling; the HTTP adapter uses the verified streaming API.

Payload retention is permanent. Pointer-aware garbage collection,
LFS locking, remote object-store backends, and
pointer-availability checks during Git receive are outside this profile. A
client can publish an LFS pointer whose payload has not been uploaded; the
normal Git LFS pre-push hook is responsible for uploading its objects first.
This implementation is a bounded part of `frankengit-fg053-lfs-i3h`, not closure
of that bead's complete acceptance criteria.

Repository authority/source bundles do not include LFS payloads. Use the
[portable LFS companion](GIT_LFS_PORTABILITY.md) to export every supported
pointer selected by native authority and import verified payloads into an
explicitly pinned destination, including a new incarnation. Alternatively,
back up the artifact directory separately and restore it with its matching
tenant, repository, and incarnation. A new incarnation cannot directly read
another incarnation's custody. The service performs no implicit migration,
automatic replication, or deletion of retained payloads.

## Focused verification

The native adapter tests cover fixed/chunked upload and retry, persistent
reopen, empty and binary payloads, verification, corruption refusal, credential
and scope isolation, namespace separation, untrusted Host headers, and bounded
batch parsing. Range tests reconstruct a payload from two separately verified
responses, check exact offsets and lengths, exercise conditional/full fallback,
empty and missing objects, oversized/duplicate fields, corruption outside the
selected slice, bounded streaming, and cancellation before headers and at
response/flush boundaries. Tus storage and adapter tests cover partial and
interrupted uploads, cold reopen, exact offsets, authenticated session isolation,
durable prefix verification, final framing and digest failures, publication
recovery, staging quotas, checked paths and method overrides. The native TCP
test shuts down and reopens the node between an interrupted PATCH and its resume,
then verifies exact downloaded bytes and unchanged repository authority.
These adapter tests are separate from the real-client
campaign, which uses a prebuilt binary and an installed
Git LFS client:

```sh
python3 scripts/e2e/lfs_roundtrip.py --fg /absolute/path/to/fg \
  --artifact-dir /absolute/path/to/new-lfs-evidence-directory
```

It exercises actual Git LFS pre-push, pointer identity, restart, clone, and pull
using a transient Basic credential helper, with separate Bearer API checks for
credential revocation and retry. With Git receive disabled, it requires a stock
push to fail without changing canonical refs while an LFS upload still succeeds.
Both Git object formats are covered. The campaign records client versions and
the binary digest.
Its output is installed-client interoperability evidence, not a pinned-client
differential campaign or proof of the full FG-053 scope.
