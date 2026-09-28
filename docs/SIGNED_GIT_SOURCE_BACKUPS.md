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
separate mandatory checks; the integrated commands below perform them without
reopening the authenticated bundle.

## Verify and recover with a required approval

Both existing offline commands accept the same four-option group. Supplying any
one requires all four; there is no inferred sidecar, trust key, repository name,
sequence floor, or fallback to unsigned operation after a failure.

```sh
node scripts/verify_git_bundle.mjs /backups/repository.bundle \
  --attestation /backups/repository.dsse.json \
  --trust-key /trusted/backup-public.pem \
  --repository team/repository --minimum-sequence 42

node scripts/recover_git_bundle.mjs \
  /backups/repository.bundle /recovery/repository.git \
  --head refs/heads/main \
  --attestation /backups/repository.dsse.json \
  --trust-key /trusted/backup-public.pem \
  --repository team/repository --minimum-sequence 42
```

The signature, repository, sequence floor and lifetime are checked before the
bundle is opened. The signed length and hash are then checked against one owned
copy of the bytes. The existing object decoder, typed history-closure verifier
and recovery planner consume that exact copy: the path is not reopened between
authentication and use. A genuine signature over malformed Git or a bundle with
missing reachable objects still fails. Existing `--expect-sha256`, native ref
pins and `--exact-refs` remain additional independent constraints, not values a
signature can overwrite. Recovery still requires an explicit advertised HEAD.

Read-only verification checks approval lifetime again after Git verification.
Recovery checks it again after preparing the verified source plan and when
prepublication validation begins, before installing HEAD. If an approval expires
after HEAD has been published, synchronization and ownership cleanup still finish;
expiration does not retroactively roll back visible work. The filesystem, native
object, work-budget and cancellation checks are unchanged.

Success adds a separate `source_attestation` record to the ordinary report. Its
`signature_verified` describes the operator's detached artifact approval; the
ordinary `verification`/closure fields describe Git contents. A Git-native
`signatures_verified: false` remains correct: commit/tag signatures and author
identities have not been authenticated. A repository label is the caller's signed
backup identity, not proof of a native repository incarnation or authority head.

For an interrupted restore, repeat the complete command with `--resume`. Every
invocation reauthenticates the supplied approval, even if HEAD already exists.
Bad or expired approvals, wrong keys, rollback below the supplied floor and
changed bundle bytes fail without modifying destination files or owner records.
Such preflight failures report `existing_unknown`, not a claim that an existing
repository was never published. A newer valid approval for the same exact bundle
can resume the same plan without rewriting recovered files or changing HEAD.

The original receipt and ownership journal remain byte-compatible. They do not
save a new signature trust policy or become an authority for future invocations.
Signed mode is explicit per invocation: workflows that require it must retain
and pass the external key/repository/floor options on **every** verification or
resume. The old unsigned modes still exist for compatibility and make no detached
signature claim. The external sequence floor is not learned from recovered data.

These commands remain the bounded portable-source tools described in
[offline verification](OFFLINE_GIT_BUNDLE_VERIFICATION.md) and
[source recovery](OFFLINE_GIT_SOURCE_RECOVERY.md), not native `fg restore`, signed
capsule recovery, key revocation, quorum signing or recovery of forge state.

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
node --test tests/browser/bundle-attestation.test.mjs tests/browser/bundle-signed-workflow.test.mjs
```

The tests execute real Node Ed25519 signing/verification, filesystem operations,
and the actual standalone command without Git or shell tools on PATH. They test
signature-domain separation, tampering, wrong trust roots, repository confusion,
full-width sequence floors, expiration, canonical payloads, file permissions,
input ownership, cancellation, and competing exclusive output publication.
These are not Rust, native `fg`, full-capsule, power-loss, or repository-gate tests.

The signed-workflow tests execute the actual verification/recovery CLI in both
native hash formats, reject signed-but-incomplete Git, and compare restored
commits, tags and binary/symlink blobs with installed Git using strict fsck and
clone. Real child processes run the production authentication/recovery code and
are killed during a partial pack write, before publication and after publication.
The actual CLI resumes each killed operation, rechecks signature policy, and
preserves source identities. These are bounded installed-Git interoperability
and process/filesystem observations, not native-server or power-loss evidence.
