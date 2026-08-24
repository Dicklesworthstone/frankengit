//! Defensive key-lifecycle conformance drills.
//!
//! The tests exercise the public `fgit-crypto` API against hostile lifecycle
//! orderings. They use `fgit-lab` schedules as data, so every ordering is
//! named, materialized, and replayable rather than depending on timing.

use fgit_crypto::{
    Capsule, CodecVersion, EnvelopeNonce, IdentityDomain, KeyEpoch, KeyHistory, KeyLifecycle,
    KeyLifecycleError, KeyPurpose, KeyScope, PurposeMismatch, RECEIPT_SCHEMA, Recoverability,
    RootSecret, SecretKey, TenantEncryption, verify_internal_object_id,
};
use fgit_lab::{LabSchedule, StepId};

const ROOT: RootSecret = RootSecret::from_bytes([0x71; 32]);
const CODEC: CodecVersion = CodecVersion::new(1, 0);

fn tenant_key(epoch: KeyEpoch) -> SecretKey<TenantEncryption> {
    SecretKey::<TenantEncryption>::derive(&ROOT, epoch, KeyScope::tenant(b"key-abuse-tenant"))
}

fn authorized_open(
    history: &KeyHistory<TenantEncryption>,
    key: &SecretKey<TenantEncryption>,
    sealed: &fgit_crypto::SealedEnvelope,
) -> Result<Vec<u8>, KeyLifecycleError> {
    history.authorize_verify(sealed.epoch())?;
    Ok(key
        .open(sealed, b"key-abuse")
        .expect("an authorized envelope in its own key domain opens"))
}

fn step(name: &str) -> StepId {
    StepId::new(name)
}

fn rotation_window_schedule(reader_before_rotation: bool) -> LabSchedule {
    let participants = vec![
        step("reader-before-rotation"),
        step("rotator"),
        step("reader-after-rotation"),
        step("writer"),
        step("revoker"),
        step("post-revocation-reader"),
    ];
    let mut order = Vec::new();
    if reader_before_rotation {
        order.push(step("reader-before-rotation"));
    }
    order.extend([
        step("rotator"),
        step("reader-after-rotation"),
        step("writer"),
        step("revoker"),
        step("post-revocation-reader"),
    ]);
    LabSchedule::explicit(participants, order).expect("the declared schedule is valid")
}

#[test]
fn serialized_cross_purpose_material_is_refused_with_a_same_purpose_twin() {
    // The type-level half is covered by `compile_fail` doctests on
    // `SecretKey`, `KeyPurposeMarker`, and the capability traits. This is the
    // hostile serialized-material half: once a purpose crosses a byte/API
    // boundary, it still cannot acquire tenant-encryption capability.
    let capsule = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let stored = capsule.store();

    assert_eq!(
        stored
            .into_typed::<TenantEncryption>()
            .expect_err("a capsule key cannot become a tenant-encryption key"),
        PurposeMismatch {
            expected: KeyPurpose::TenantEncryption,
            stored: KeyPurpose::Capsule,
        }
    );

    let permitted = capsule
        .store()
        .into_typed::<Capsule>()
        .expect("the same serialized key retains its original purpose");
    assert_eq!(permitted.id(), capsule.id());
}

#[test]
fn rotation_window_interleavings_are_receipted_and_never_fall_back() {
    // These are two reduced race orderings. `KeyHistory` is deliberately
    // single-owner state, so this test does not pretend to race threads; the
    // lab schedule instead makes the observable reader/rotator/revoker order
    // explicit and replayable.
    for schedule in [
        rotation_window_schedule(true),
        rotation_window_schedule(false),
    ] {
        assert!(
            schedule
                .canonical_line()
                .starts_with("fgit-lab-schedule-v1|"),
            "the observed ordering must be a quoteable lab receipt"
        );

        let first = tenant_key(KeyEpoch::FIRST);
        let second_epoch = KeyEpoch::new(2).expect("epoch two exists");
        let second = tenant_key(second_epoch);
        let old = first.seal(
            EnvelopeNonce::from_bytes([0x11; 24]),
            b"key-abuse",
            b"written before rotation",
        );
        let mut history = KeyHistory::new(&first);
        let mut cursor = schedule.cursor();
        let mut rotation = None;
        let mut revocation = None;
        let mut new = None;

        while !cursor.is_exhausted() {
            match cursor
                .next_step()
                .expect("the loop only takes declared schedule steps")
                .as_str()
            {
                "reader-before-rotation" => assert_eq!(
                    authorized_open(&history, &first, &old),
                    Ok(b"written before rotation".to_vec()),
                    "the pre-rotation reader sees the old key"
                ),
                "rotator" => {
                    let receipt = history.rotate(&second).expect("rotation advances");
                    assert_eq!(receipt.epoch(), second_epoch);
                    assert_eq!(receipt.from(), KeyLifecycle::Retired);
                    assert_eq!(receipt.to(), KeyLifecycle::Active);
                    rotation = Some(receipt);
                }
                "reader-after-rotation" => {
                    assert_eq!(history.issuing_epoch(), Ok(second_epoch));
                    assert_eq!(
                        authorized_open(&history, &first, &old),
                        Ok(b"written before rotation".to_vec()),
                        "the retired key remains readable through history"
                    );
                    assert_eq!(
                        history.authorize_issue(KeyEpoch::FIRST),
                        Err(KeyLifecycleError::EpochRetired {
                            epoch: KeyEpoch::FIRST,
                            active: second_epoch,
                        }),
                        "rotation never silently falls back for a new write"
                    );
                }
                "writer" => {
                    history
                        .authorize_issue(second_epoch)
                        .expect("only the rotated epoch issues");
                    let written = second.seal(
                        EnvelopeNonce::from_bytes([0x22; 24]),
                        b"key-abuse",
                        b"written after rotation",
                    );
                    assert_eq!(written.epoch(), second_epoch);
                    new = Some(written);
                }
                "revoker" => {
                    let receipt = history
                        .revoke(KeyEpoch::FIRST)
                        .expect("revoking the retired epoch is receipted");
                    assert_eq!(receipt.from(), KeyLifecycle::Retired);
                    assert_eq!(receipt.to(), KeyLifecycle::Revoked);
                    assert_eq!(
                        history.authorize_issue(KeyEpoch::FIRST),
                        Err(KeyLifecycleError::EpochRevoked {
                            epoch: KeyEpoch::FIRST,
                        }),
                        "revocation cuts issuance rather than merely marking history"
                    );
                    revocation = Some(receipt);
                }
                "post-revocation-reader" => {
                    assert_eq!(
                        authorized_open(&history, &first, &old),
                        Err(KeyLifecycleError::EpochRevoked {
                            epoch: KeyEpoch::FIRST,
                        }),
                        "revocation cuts acceptance of old data"
                    );
                    assert_eq!(
                        authorized_open(
                            &history,
                            &second,
                            new.as_ref().expect("the new write precedes revocation"),
                        ),
                        Ok(b"written after rotation".to_vec()),
                        "revoking the old epoch does not invalidate the replacement"
                    );
                }
                unexpected => panic!("undeclared key-lifecycle actor: {unexpected}"),
            }
        }

        let rotation = rotation.expect("the schedule rotates once");
        let revocation = revocation.expect("the schedule revokes once");
        assert_ne!(rotation.canonical_body(), revocation.canonical_body());
        assert_ne!(rotation.identity(CODEC), revocation.identity(CODEC));
        for receipt in [rotation, revocation] {
            assert_eq!(
                receipt.identity(CODEC).domain(),
                IdentityDomain::KeyLifecycleReceipt.domain_tag(),
                "every scheduled transition has a domain-separated receipt"
            );
            assert_eq!(
                verify_internal_object_id(
                    &receipt.identity(CODEC),
                    IdentityDomain::KeyLifecycleReceipt,
                    RECEIPT_SCHEMA,
                    CODEC,
                    &receipt.canonical_body(),
                ),
                Ok(())
            );
        }
    }
}

#[test]
fn erasure_is_terminal_receipted_and_refuses_every_authorized_read_path() {
    let first = tenant_key(KeyEpoch::FIRST);
    let second_epoch = KeyEpoch::new(2).expect("epoch two exists");
    let second = tenant_key(second_epoch);
    let old = first.seal(
        EnvelopeNonce::from_bytes([0x33; 24]),
        b"key-abuse",
        b"data awaiting deletion",
    );
    let mut history = KeyHistory::new(&first);
    history.rotate(&second).expect("rotation advances");

    assert_eq!(
        authorized_open(&history, &first, &old),
        Ok(b"data awaiting deletion".to_vec()),
        "the old data is recoverable immediately before its deletion state"
    );

    let receipt = history
        .erase(KeyEpoch::FIRST)
        .expect("erasure records evidence");
    assert_eq!(receipt.from(), KeyLifecycle::Retired);
    assert_eq!(receipt.to(), KeyLifecycle::Erased);
    assert_eq!(receipt.purpose(), KeyPurpose::TenantEncryption);
    assert_eq!(
        receipt.identity(CODEC).domain(),
        IdentityDomain::KeyLifecycleReceipt.domain_tag(),
        "the deletion state has a commit-ready, domain-separated receipt"
    );
    assert_eq!(
        verify_internal_object_id(
            &receipt.identity(CODEC),
            IdentityDomain::KeyLifecycleReceipt,
            RECEIPT_SCHEMA,
            CODEC,
            &receipt.canonical_body(),
        ),
        Ok(())
    );

    let erased = KeyLifecycleError::MaterialErased {
        epoch: KeyEpoch::FIRST,
    };
    assert_eq!(authorized_open(&history, &first, &old), Err(erased));
    assert_eq!(history.authorize_verify(KeyEpoch::FIRST), Err(erased));
    assert_eq!(history.authorize_issue(KeyEpoch::FIRST), Err(erased));
    assert_eq!(
        history.recoverability(KeyEpoch::FIRST),
        Ok(Recoverability::PermanentlyUnrecoverable),
        "erasure is a durable typed refusal, never an unknown-key retry"
    );
    assert_eq!(history.erase(KeyEpoch::FIRST), Err(erased));
    assert_eq!(history.revoke(KeyEpoch::FIRST), Err(erased));

    let replacement = second.seal(
        EnvelopeNonce::from_bytes([0x44; 24]),
        b"key-abuse",
        b"data after deletion",
    );
    assert_eq!(
        authorized_open(&history, &second, &replacement),
        Ok(b"data after deletion".to_vec()),
        "erasing one epoch does not make the active replacement unreadable"
    );
}
