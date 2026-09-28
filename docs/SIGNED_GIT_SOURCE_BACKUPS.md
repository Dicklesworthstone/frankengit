# Signed portable-source backups

The existing source verifier proves that a bundle's bytes and reachable Git
objects are consistent. A detached source attestation additionally binds the
exact artifact to an operator-approved **repository name and backup sequence**.
These are portable-source approvals, not FrankenGit authority-head signatures,
forge-state backups, or repository authorization grants.

## Sign an artifact

Use Node.js 22 or newer and an Ed25519 private key in unencrypted PKCS8
`PRIVATE KEY` PEM format. The corresponding externally distributed public key
uses SPKI `PUBLIC KEY` PEM format. The command does not generate keys, consult a
key server, or infer trust from files shipped with a backup.

```sh
node scripts/attest_git_bundle.mjs sign \
  /backups/repository.bundle /backups/repository.dsse.json \
  --key /private/backup-signing.pem \
  --repository team/repository --sequence 42
```

The private key must be a regular file owned by the current user, single-linked,
and inaccessible to group/other users (for example, mode 0600). Final-component
symlinks are refused. Key contents never enter the attestation or command output.
The command clears its temporary key-byte buffers where practical; this is not a
claim of complete erasure from a managed runtime or the operating system.

Signing records the exact bundle length and SHA-256, repository name, positive
u64 sequence, issuance time, and optional UTC expiration (`--expires-at
2026-12-31T23:59:59Z`). No expiration is invented for archival backups. Sequence
allocation is the operator's responsibility: the tool does not enforce global
uniqueness or maintain another repository authority database.

Signing approves opaque bytes; it does not assert that they are valid Git. Run
the existing verifier before approval and retain its independent result. A
signature must never substitute for object and closure verification on restore.

## Authenticate an artifact

Supply the public key, repository name, and a minimum acceptable sequence from
a **separately trusted source**:

```sh
node scripts/attest_git_bundle.mjs check \
  /backups/repository.bundle /backups/repository.dsse.json \
  --trust-key /trusted/backup-public.pem \
  --repository team/repository --minimum-sequence 42
```

An embedded key or filename never chooses the trusted signer. A valid signature
for another repository fails. A sequence below the supplied floor fails even
with a valid signature. Expired approvals and issuance more than five minutes
in the future fail; the wall clock is checked again after asynchronous work.
The caller must retain the sequence floor outside the backup to prevent rollback.
A stateless check cannot discover a newer backup or guarantee branch freshness.

Authentication happens before opening the bundle. Its exact bytes are then read
once, checked against the signed length/hash, and returned together with the
verified statement. Changed files, wrong keys, malformed records, and hash
mismatches fail without returning a partial success. The standalone `check`
command reports `object_closure_verified: false`: it authenticates the artifact,
not its internal Git graph. Object verification and source recovery remain
separate mandatory steps.

## Signature profile and local publication

The wire envelope uses DSSE v1 pre-authentication encoding and Ed25519. Its
application-specific payload type is
`application/vnd.frankengit.source-backup-attestation.v1+json`. The JSON payload
has a single fixed canonical encoding; duplicate fields, ignored claims,
unknown fields, and alternate signed payload spellings refuse. Standard and
URL-safe base64 are accepted. The profile admits exactly one signature.

The `keyid` hint is a SHA-256 fingerprint of canonical SPKI public-key bytes.
Verification always uses the externally supplied public key and the original
payload bytes, not the hint alone. No signature over untyped JSON is accepted.
No URL in any input is followed. This is not a certificate chain, revocation
service, quorum scheme, or current repository policy check.

Limits are 16 MiB artifact bytes, 16 KiB envelope, 4 KiB signed payload, and 8 KiB
PEM input. Only exact positive decimal sequences through 18446744073709551615
are accepted; they are never rounded through a JavaScript number.

Use an existing operator-controlled, quiescent parent directory on a local POSIX
filesystem. The signer writes a private temporary file, synchronizes and reads
it back, then installs the output by a no-replace hard link. Existing files,
directories and dangling symlinks are never overwritten. Concurrent publishers
cannot both win. After publication, synchronization and owned-temporary cleanup
finish despite cancellation; an I/O failure reports publication uncertainty
rather than claiming rollback. This is not a sandbox against a malicious
same-user process rewriting the parent directory.

## Checks

```sh
node --test tests/browser/bundle-attestation.test.mjs
```

The tests execute real Node Ed25519 signing/verification, filesystem operations,
and the actual standalone command without Git or shell tools on PATH. They test
signature-domain separation, tampering, wrong trust roots, repository confusion,
full-width sequence floors, expiration, canonical payloads, file permissions,
input ownership, cancellation, and competing exclusive output publication.
These are not Rust, native `fg`, full-capsule, power-loss, or repository-gate tests.
