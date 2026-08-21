//! The rotation, revocation and erasure drills the bead specifies.
//!
//! Each drill is a sequence, not a single assertion, because the properties
//! only mean something in combination: rotation is interesting exactly when
//! the old epoch still verifies, and revocation is interesting exactly when it
//! stops issuance without pretending the key never existed.

use fgit_crypto::{
    Capsule, CodecVersion, IdentityDomain, KeyEpoch, KeyHistory, KeyLifecycle, KeyLifecycleError,
    KeyPurpose, KeyScope, RECEIPT_SCHEMA, Recoverability, RootSecret, SecretKey, TenantEncryption,
    verify_internal_object_id,
};

const ROOT: RootSecret = RootSecret::from_bytes([0x5a; 32]);
const CODEC: CodecVersion = CodecVersion::new(1, 0);

fn key(epoch: KeyEpoch) -> SecretKey<Capsule> {
    SecretKey::<Capsule>::derive(&ROOT, epoch, KeyScope::OPERATOR)
}

const fn epoch(value: u32) -> KeyEpoch {
    KeyEpoch::new(value).expect("a non-zero epoch")
}

#[test]
fn rotation_keeps_old_epochs_verifying_while_only_the_new_one_issues() {
    // The drill from the bead: old-key data readable through key history, new
    // writes use the new key.
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    assert_eq!(history.issuing_epoch(), Ok(KeyEpoch::FIRST));

    let second = epoch(2);
    let receipt = history.rotate(&key(second)).expect("rotation advances");
    assert_eq!(receipt.epoch(), second);
    assert_eq!(receipt.to(), KeyLifecycle::Active);

    // New writes use the new key.
    assert_eq!(history.issuing_epoch(), Ok(second));
    assert_eq!(history.authorize_issue(second), Ok(()));

    // Old data stays readable.
    assert_eq!(history.authorize_verify(KeyEpoch::FIRST), Ok(()));
    assert_eq!(
        history.recoverability(KeyEpoch::FIRST),
        Ok(Recoverability::Recoverable)
    );

    // But the old epoch may no longer issue, and the refusal says why rather
    // than pretending the epoch is gone.
    assert_eq!(
        history.authorize_issue(KeyEpoch::FIRST),
        Err(KeyLifecycleError::EpochRetired {
            epoch: KeyEpoch::FIRST,
            active: second,
        })
    );
}

#[test]
fn rotation_must_advance_and_a_replayed_epoch_is_refused() {
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    history.rotate(&key(epoch(2))).expect("rotation advances");

    // Re-offering an earlier epoch would silently resurrect a retired key.
    let refusal = history
        .rotate(&key(KeyEpoch::FIRST))
        .expect_err("rotation must be monotone");
    assert_eq!(
        refusal,
        KeyLifecycleError::EpochNotMonotone {
            offered: KeyEpoch::FIRST,
            latest: epoch(2),
        }
    );

    // The permitted twin: a strictly later epoch proceeds.
    assert!(history.rotate(&key(epoch(3))).is_ok());
    assert_eq!(history.issuing_epoch(), Ok(epoch(3)));
}

#[test]
fn revocation_cuts_issuance_and_is_receipted() {
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    history.rotate(&key(epoch(2))).expect("rotation advances");

    let receipt = history.revoke(epoch(2)).expect("the active epoch revokes");
    assert_eq!(receipt.epoch(), epoch(2));
    assert_eq!(receipt.from(), KeyLifecycle::Active);
    assert_eq!(receipt.to(), KeyLifecycle::Revoked);
    assert_eq!(receipt.purpose(), KeyPurpose::Capsule);

    // Nothing issues until the caller rotates: the history does not silently
    // fall back to the retired epoch.
    assert_eq!(
        history.issuing_epoch(),
        Err(KeyLifecycleError::NoActiveEpoch)
    );
    assert_eq!(
        history.authorize_verify(epoch(2)),
        Err(KeyLifecycleError::EpochRevoked { epoch: epoch(2) })
    );
    assert_eq!(
        history.recoverability(epoch(2)),
        Ok(Recoverability::WithheldByRevocation)
    );

    // The earlier epoch is untouched by revoking a later one.
    assert_eq!(history.authorize_verify(KeyEpoch::FIRST), Ok(()));
}

#[test]
fn erasure_is_permanent_and_typed_rather_than_an_unknown_key() {
    // Plan 19.4: cryptographic erasure is a deletion state with its own
    // evidence. The refusal must not be "unknown", which would invite a retry.
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    history.rotate(&key(epoch(2))).expect("rotation advances");

    let receipt = history
        .erase(KeyEpoch::FIRST)
        .expect("a retired epoch erases");
    assert_eq!(receipt.from(), KeyLifecycle::Retired);
    assert_eq!(receipt.to(), KeyLifecycle::Erased);

    assert_eq!(
        history.authorize_verify(KeyEpoch::FIRST),
        Err(KeyLifecycleError::MaterialErased {
            epoch: KeyEpoch::FIRST
        })
    );
    assert_eq!(
        history.recoverability(KeyEpoch::FIRST),
        Ok(Recoverability::PermanentlyUnrecoverable)
    );

    // Distinct from an epoch that was never in this history at all.
    assert_eq!(
        history.authorize_verify(epoch(9)),
        Err(KeyLifecycleError::EpochUnknown { epoch: epoch(9) })
    );

    // Terminal: erasing twice is refused rather than reported as fresh.
    assert_eq!(
        history.erase(KeyEpoch::FIRST),
        Err(KeyLifecycleError::MaterialErased {
            epoch: KeyEpoch::FIRST
        })
    );
    // And an erased epoch cannot be revoked back into a lesser state.
    assert_eq!(
        history.revoke(KeyEpoch::FIRST),
        Err(KeyLifecycleError::MaterialErased {
            epoch: KeyEpoch::FIRST
        })
    );

    // The commitment survives, so the destroyed epoch stays identifiable.
    let record = history
        .records()
        .iter()
        .find(|record| record.epoch() == KeyEpoch::FIRST)
        .expect("the erased epoch is still recorded");
    assert_eq!(record.lifecycle(), KeyLifecycle::Erased);
    assert_ne!(record.commitment(), &[0_u8; 32]);
}

#[test]
fn erasing_the_active_epoch_leaves_nothing_issuing() {
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    history
        .erase(KeyEpoch::FIRST)
        .expect("the active epoch erases");
    assert_eq!(
        history.issuing_epoch(),
        Err(KeyLifecycleError::NoActiveEpoch)
    );
    assert_eq!(
        history.authorize_issue(KeyEpoch::FIRST),
        Err(KeyLifecycleError::MaterialErased {
            epoch: KeyEpoch::FIRST
        })
    );
}

#[test]
fn a_receipt_carries_a_verifiable_domain_separated_identity() {
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    let receipt = history.rotate(&key(epoch(2))).expect("rotation advances");

    let identity = receipt.identity(CODEC);
    assert_eq!(
        identity.domain(),
        IdentityDomain::KeyLifecycleReceipt.domain_tag()
    );
    assert_eq!(
        verify_internal_object_id(
            &identity,
            IdentityDomain::KeyLifecycleReceipt,
            RECEIPT_SCHEMA,
            CODEC,
            &receipt.canonical_body(),
        ),
        Ok(())
    );
}

#[test]
fn two_transitions_never_share_a_receipt_identity() {
    let mut history = KeyHistory::new(&key(KeyEpoch::FIRST));
    let rotated = history.rotate(&key(epoch(2))).expect("rotation advances");
    let revoked = history.revoke(epoch(2)).expect("the active epoch revokes");
    assert_ne!(rotated.canonical_body(), revoked.canonical_body());
    assert_ne!(rotated.identity(CODEC), revoked.identity(CODEC));
}

#[test]
fn histories_of_different_purposes_are_different_types() {
    // The history carries the purpose marker, so a capsule history and a
    // tenant-encryption history cannot be interchanged even by a caller that
    // holds both.
    let capsule = KeyHistory::new(&SecretKey::<Capsule>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    ));
    let tenant = KeyHistory::new(&SecretKey::<TenantEncryption>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::tenant(b"tenant-a"),
    ));
    assert_eq!(capsule.issuing_epoch(), Ok(KeyEpoch::FIRST));
    assert_eq!(tenant.issuing_epoch(), Ok(KeyEpoch::FIRST));
    assert_ne!(
        capsule.records()[0].commitment(),
        tenant.records()[0].commitment()
    );
}
