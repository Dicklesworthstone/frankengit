# Git LFS basic transfer

`fg serve-http --lfs-root <private-directory>` exposes Git LFS basic upload,
download, and verification through FrankenGit's existing immutable artifact
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
| `lfs-write` | LFS upload batches, immutable uploads, and upload verification |

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

Fixed-length and chunked HTTP request bodies use the existing bounded native
framing parser. Short bodies, malformed chunks, incorrect lengths, and digest
mismatches cannot publish an object. Authentication and the endpoint's required
scope precede `100 Continue`; the batch operation's scope is checked after its
bounded JSON body is decoded. A failed or interrupted upload may be retried with
the same identity and complete payload. A successful upload repeated under the
same identity is idempotent. An upload batch omits upload actions for objects
already present in verified custody.

## Current bounds and recovery limits

This profile supports `basic` transfers and SHA-256 LFS object IDs for both
SHA-1 and SHA-256 Git repositories. It accepts at most 100 objects per batch,
64 KiB of batch/verification JSON, 64 MiB per object, and 64 MiB of aggregate
declared payload bytes for verification within one batch. Objects outside the
batch verification budget receive individual errors; supported objects retain
their original order and identity. Request deadlines, bounded listener
concurrency, and principal quotas also apply.

Payload retention is permanent. Pointer-aware garbage collection, resumable
partial-byte uploads, LFS locking, remote object-store backends, and
pointer-availability checks during Git receive are outside this profile. A
client can publish an LFS pointer whose payload has not been uploaded; the
normal Git LFS pre-push hook is responsible for uploading its objects first.
This implementation is a bounded part of `frankengit-fg053-lfs-i3h`, not closure
of that bead's complete acceptance criteria.

Back up the artifact directory separately from repository authority/source
bundles: those bundles do not currently include LFS payloads. Restore custody
together with the matching tenant, repository, and incarnation; a newly created
incarnation cannot read another incarnation's custody. The service performs no
implicit migration, automatic replication, or deletion of retained payloads.

## Focused verification

The native adapter tests cover fixed/chunked upload and retry, persistent
reopen, empty and binary payloads, verification, corruption refusal, credential
and scope isolation, namespace separation, untrusted Host headers, and bounded
batch parsing. The real-client campaign uses a prebuilt binary and an installed
Git LFS client:

```sh
python3 scripts/e2e/lfs_roundtrip.py --fg /absolute/path/to/fg \
  --artifact-dir /absolute/path/to/new-lfs-evidence-directory
```

It exercises actual Git LFS pre-push, pointer identity, restart, clone, pull,
credential revocation, retry, and independent service enablement for both Git
object formats. The campaign records client versions and the binary digest.
Its output is installed-client interoperability evidence, not a pinned-client
differential campaign or proof of the full FG-053 scope.
