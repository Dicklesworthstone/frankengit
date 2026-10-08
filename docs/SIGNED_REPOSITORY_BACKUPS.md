# Signed repository-source backup approval

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`; comprehensive plan
21.5–21.8. This operator boundary authenticates `fg backup` archives rather
than the portable Git bundles supported by `attest_git_bundle.mjs`. It is NOT
a signed Repository Capsule, service backup, canonical authorization, or a
replacement for the native authority/graph/payload checks.

## Create and check an independent approval

Export with the native `fg backup export` command. Independently review its
namespace, incarnation, hash format and head-generation receipt. Then:

```sh
node scripts/attest_repository_backup.mjs sign backup.fgit backup.approval.json \
  --private-key /private/backup-signing.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --head-generation "$HEAD_GENERATION"

node scripts/attest_repository_backup.mjs check backup.fgit backup.approval.json \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR"
```

Signing streams actual artifact bytes into SHA-256 and signs the operator's
identity declarations. It does not parse the archive or establish that those
declarations describe valid native state. A native preflight must additionally
verify the archive and compare its actual identity before restore. A check
verifies the separately supplied Ed25519 key, exact namespace/incarnation/format,
minimum generation, lifetime and artifact bytes. Never obtain the trusted key
or the generation floor from an untrusted adjacent file or the approval itself.
An explicit floor is not a claim that the selected checkpoint is the newest.

Both commands default to a 1 GiB archive ceiling and one 300-second deadline.
`--max-archive-bytes` permits at most 1 TiB; `--timeout-secs` at most 3600 seconds.
Only 64 KiB of archive payload is buffered; the report gives observed read counts.
Blocking filesystem calls remain cooperative, not forcibly interruptible.
An unstable file, symlink, wrong signer, foreign incarnation, wrong format,
below-floor generation, expired approval or altered artifact refuses. Unknown
options and incomplete identity declarations are not inferred or defaulted.

`--expires-at` accepts an optional second-precision UTC deadline. Keys are strict
Ed25519 PKCS#8 private / SPKI public PEM; private files require current-user,
owner-only permissions and a single hard link. New approval files are staged,
synchronized, read back, installed without replacement and directory-synchronized.
Their parent must be an existing owner-private directory. SIGKILL can retain a
private staging file. No automatic cleanup or recursive deletion is performed.

## Wire boundary and trust

The distinct payload type is
`application/vnd.frankengit.repository-backup-approval.v1+json`. DSSE v1 PAE signs
that exact type and the original payload bytes. The application payload has one
strict JSON spelling, with positive full-width u64 generations and artifact byte
counts encoded as decimal strings. Its scope is
`authority_and_selected_git_objects`. Source-bundle signatures, alternate scopes,
extra claims and noncanonical signed payloads cannot cross into this profile.
The key ID is SHA-256 of canonical SPKI DER, never a key-discovery mechanism.

The operator chooses the trust key and floor. This does not implement PKI,
revocation distribution, key rotation, canonical permission checking, routing,
external-effect replay, external-artifact restoration, or full capsule recovery.
The native engine's own scope/verification non-claims must remain intact.

## Executable validation

```sh
node --test tests/operator/repository-backup-approval.test.mjs
```

The tests execute actual Ed25519 signatures, standalone command processes,
filesystem operations, a larger-than-16-MiB sparse archive, mutation detection,
resource/cancellation refusals, generation-floor boundaries and no-replace
publication. Their opaque archive fixture is deliberately not valid native
repository state. These are signing/I/O tests, not native recovery, Rust,
full-workspace, power-loss, performance or bead-closure evidence.
