//! Key-purpose separation: the acceptance line "cross-purpose key use
//! unrepresentable", checked at both layers.
//!
//! Compile-time separation lives in `compile_fail` doctests on the items it
//! constrains (see `SecretKey`, `MacCapable` and `StoredKey::into_typed`).
//! These are the runtime half plus the permitted twins, so a boundary is never
//! evidenced only by things that fail to compile.

use fgit_crypto::{
    Capsule, Evidence, Identity, KeyEpoch, KeyPurpose, KeyScope, PurposeMismatch, RootSecret,
    SecretKey, TenantEncryption, Webhook, derivation_info,
};

const ROOT: RootSecret = RootSecret::from_bytes([0x5a; 32]);

#[test]
fn the_eight_threat_model_purposes_are_the_closed_set() {
    // Threat model section 8 enumerates exactly these. A ninth is a spec
    // change, not a code change.
    assert_eq!(KeyPurpose::ALL.len(), 8);
    for (index, purpose) in KeyPurpose::ALL.iter().copied().enumerate() {
        assert_eq!(usize::from(purpose.code_point()), index + 1);
        assert_eq!(
            KeyPurpose::from_code_point(purpose.code_point()),
            Some(purpose)
        );
        assert!(purpose.tag().starts_with("frankengit/key/"));
    }
    assert_eq!(KeyPurpose::from_code_point(0), None);
    assert_eq!(KeyPurpose::from_code_point(9), None);
}

#[test]
fn purpose_tags_are_unique() {
    for (index, purpose) in KeyPurpose::ALL.iter().copied().enumerate() {
        for other in KeyPurpose::ALL.iter().copied().skip(index + 1) {
            assert_ne!(purpose.tag(), other.tag());
            assert_ne!(purpose.code_point(), other.code_point());
        }
    }
}

#[test]
fn one_root_derives_unrelated_material_for_every_purpose() {
    // Type-level separation stops a programmer; this is what stops two
    // purposes sharing bytes.
    let identity = SecretKey::<Identity>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let capsule = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let webhook = SecretKey::<Webhook>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let evidence = SecretKey::<Evidence>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);

    let commitments = [
        *identity.id().commitment(),
        *capsule.id().commitment(),
        *webhook.id().commitment(),
        *evidence.id().commitment(),
    ];
    for (index, left) in commitments.iter().enumerate() {
        for right in commitments.iter().skip(index + 1) {
            assert_ne!(left, right, "two purposes must not share material");
        }
    }
}

#[test]
fn a_tenant_key_in_one_scope_is_not_the_key_in_another() {
    // "A ciphertext copied across incompatible key domains is not a valid
    // placement" has to be true of the bytes, not only of the annotations.
    let first = SecretKey::<TenantEncryption>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::tenant(b"tenant-a"),
    );
    let second = SecretKey::<TenantEncryption>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::tenant(b"tenant-b"),
    );
    let scoped = SecretKey::<TenantEncryption>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::repository(b"tenant-a", b"repo-1"),
    );
    assert_ne!(first.id().commitment(), second.id().commitment());
    assert_ne!(first.id().commitment(), scoped.id().commitment());

    // The permitted twin: the same scope derives the same key.
    let again = SecretKey::<TenantEncryption>::derive(
        &ROOT,
        KeyEpoch::FIRST,
        KeyScope::tenant(b"tenant-a"),
    );
    assert_eq!(first.id().commitment(), again.id().commitment());
}

#[test]
fn rotating_the_epoch_changes_the_key_and_keeps_the_purpose() {
    let first = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let second_epoch = KeyEpoch::FIRST.next().expect("epoch two exists");
    let second = SecretKey::<Capsule>::derive(&ROOT, second_epoch, KeyScope::OPERATOR);

    assert_ne!(first.id().commitment(), second.id().commitment());
    assert_eq!(first.id().purpose(), KeyPurpose::Capsule);
    assert_eq!(second.id().purpose(), KeyPurpose::Capsule);
    assert_eq!(first.id().epoch(), KeyEpoch::FIRST);
    assert_eq!(second.id().epoch(), second_epoch);
}

#[test]
fn epoch_zero_is_reserved_and_exhaustion_is_refused() {
    assert_eq!(KeyEpoch::new(0), None);
    assert!(KeyEpoch::new(1).is_some());
    assert_eq!(KeyEpoch::new(u32::MAX).and_then(KeyEpoch::next), None);
}

#[test]
fn a_stored_key_refuses_to_become_another_purpose() {
    // The runtime half: a purpose that arrived as bytes is checked, because
    // the type system never saw it.
    let capsule = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let stored = capsule.store();
    assert_eq!(stored.purpose(), KeyPurpose::Capsule);

    let refusal = stored
        .into_typed::<Webhook>()
        .expect_err("a capsule key is not a webhook key");
    assert_eq!(
        refusal,
        PurposeMismatch {
            expected: KeyPurpose::Webhook,
            stored: KeyPurpose::Capsule,
        }
    );
}

#[test]
fn a_stored_key_round_trips_into_its_own_purpose() {
    // The permitted twin of the refusal above: same call, right purpose.
    let capsule = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let restored = capsule
        .store()
        .into_typed::<Capsule>()
        .expect("a capsule key is a capsule key");
    assert_eq!(restored.id(), capsule.id());
    assert_eq!(restored.id().epoch(), KeyEpoch::FIRST);
}

#[test]
fn a_webhook_key_tags_and_verifies_and_rejects_a_forgery() {
    let webhook = SecretKey::<Webhook>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let tag = webhook.tag(b"delivery body");
    assert!(webhook.verify(b"delivery body", &tag));
    assert!(!webhook.verify(b"tampered body", &tag));

    // A different epoch is a different key, so its tag must not verify.
    let rotated = SecretKey::<Webhook>::derive(
        &ROOT,
        KeyEpoch::FIRST.next().expect("epoch two exists"),
        KeyScope::OPERATOR,
    );
    assert!(!rotated.verify(b"delivery body", &tag));
}

#[test]
fn derivation_info_frames_every_field_so_no_two_triples_collide() {
    // Unframed concatenation is how (tenant "ab", repo "c") and
    // (tenant "a", repo "bc") end up deriving one key.
    let left = derivation_info(
        KeyPurpose::TenantEncryption,
        KeyEpoch::FIRST,
        KeyScope::repository(b"ab", b"c"),
    );
    let right = derivation_info(
        KeyPurpose::TenantEncryption,
        KeyEpoch::FIRST,
        KeyScope::repository(b"a", b"bc"),
    );
    assert_ne!(left, right);

    // And the purpose tag is committed, so two purposes never frame alike.
    let other_purpose = derivation_info(
        KeyPurpose::Capsule,
        KeyEpoch::FIRST,
        KeyScope::repository(b"ab", b"c"),
    );
    assert_ne!(left, other_purpose);
}

#[test]
fn a_key_never_prints_its_material() {
    let capsule = SecretKey::<Capsule>::derive(&ROOT, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let rendered = format!("{capsule:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(format!("{ROOT:?}").contains("redacted"));
    assert!(format!("{:?}", capsule.store()).contains("redacted"));
}
