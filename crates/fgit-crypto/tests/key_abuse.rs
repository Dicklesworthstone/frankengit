//! Defensive cross-purpose key conformance drill.
//!
//! This crate keeps only the pure key-purpose boundary. The lab-scheduled
//! rotation and erasure drills live in `fgit-lab`, an L2 test consumer that
//! depends downward on this L1 crate.

use fgit_crypto::{
    Capsule, KeyEpoch, KeyPurpose, KeyScope, PurposeMismatch, RootSecret, SecretKey,
    TenantEncryption,
};

const ROOT: RootSecret = RootSecret::from_bytes([0x71; 32]);

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
