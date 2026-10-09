# Select a signed repository checkpoint without fallback

Related: plan 21.5–21.8 and `frankengit-root-doctrine-x2mv.4.21` / `.4.44`.
This implements selection within an explicit candidate set, not signed Repository
Capsules, a complete archive catalog, key rotation, or the newest global head.

`selectRepositoryBackup(candidates, trustKey, policy, options)` accepts 1–64
explicit `{input, approval}` pairs and the existing independently supplied
public-key, tenant, repository, incarnation, object-format and generation-floor
policy. It reads no directories or remote services. Paths locate bytes; input
order, filenames, timestamps and unsigned metadata never rank checkpoints.
Every descriptor and policy is captured before the first asynchronous operation.

Every supplied approval must authenticate through the existing Ed25519/DSSE
verifier in that exact namespace. Invalid signatures, foreign identities,
unreadable approvals and malformed statements fail the whole selection, rather
than silently removing part of the operator's requested set. The signer and
resource bounds never come from an approval. The detached approval format and
ordinary single-archive verification behavior are unchanged.

Selection compares the authenticated full-width generation integers BEFORE
checking the winner's expiry, external minimum, size or artifact availability.
A newer signed checkpoint with an expired approval, missing/corrupt artifact,
future issue time or over-budget size is a refusal, never a reason to recover
an older checkpoint. Missing or expired *lower* artifacts do not interfere with
a usable higher checkpoint; only the winning artifact is opened and hashed.
The configured byte budget applies to that artifact, while approval inspection
retains the existing absolute one-TiB signed-size ceiling.

Distinct signed statements at the highest generation are ambiguous and refuse.
This is not an accusation of signer misconduct: repeated export or approval
renewal may legitimately differ. This bounded profile does not invent a renewal
or same-generation merge policy. The operator must explicitly narrow the set.
Identical signed statements at different supplied locations are aliases, chosen
in deterministic path order, with their count retained. There is no automatic
replica/path failover; a missing selected alias also refuses.

A shared bounded deadline and cancellation signal cover all approval reads,
signature checks and selected-artifact hashing. Hashing uses the existing 64-KiB
streaming reader, with inode/type/size/change checks. The selected approval's
validity is checked again after hashing and through the returned `checkCurrent`.
Signature-only inspection has a deliberately different return shape and labels
its unchecked validity; ordinary `verifyRepositoryBackupApproval` still checks
validity before returning an authentication result.

The read-only report includes the selected paths, exact approval SHA-256,
trusted-key ID, signed statement, policy, deterministic candidate-set digest and
all inspected candidate identities. `newest_checkpoint_verified` and
`candidate_set_completeness_verified` stay false: an omitted backup cannot be
discovered from supplied files. Retain the independent generation floor elsewhere.
The report is not authority, a native content check or a pinned file handle.
Downstream consumers must reauthenticate and enforce its exact approval/key pins,
then use native archive/authority/graph validation. No saved report alone can
authorize restore, publish routing, or replay external effects.

## Executable coverage

```sh
node --test tests/operator/repository-backup-selection.test.mjs
```

The tests run real Ed25519 operations and filesystem reads, including full-u64
selection, permutations, ambiguity, missing/corrupt/expired newer checkpoints,
old unavailable archives, forged/foreign approvals, cancellation, one deadline,
mutable callers and over-16-MiB hashing. Artifacts are explicitly opaque bytes,
not native archive fixtures. These tests do not establish Rust execution, native
restore correctness, catalog completeness or power-loss durability.
