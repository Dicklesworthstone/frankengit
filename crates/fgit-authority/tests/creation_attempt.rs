#![forbid(unsafe_code)]
//! Repository creation idempotency is an immutable authority record.

use fgit_authority::{
    CreationAttemptOutcome, IdempotencyKey, MemoryAuthorityStore, OutcomeFailure, StoreInstanceId,
    record_creation_attempt,
};
use fgit_codec::CreationAttemptBody;
use fgit_crypto::DigestAlgorithm;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(59))
}

fn key() -> IdempotencyKey {
    IdempotencyKey::new(b"fg-init-lost-response-59".to_vec())
        .expect("the fixed caller key is inside the bound")
}

fn attempt(
    idempotency_key: &IdempotencyKey,
    incarnation: u8,
    object_format: GitHashAlgorithm,
) -> CreationAttemptBody {
    CreationAttemptBody {
        tenant_id: TenantId::from_bytes([0x51; 16]),
        repository_id: RepositoryId::from_bytes([0x59; 16]),
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format,
        idempotency_key_digest: idempotency_key.digest(),
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([incarnation; 16]),
    }
}

#[test]
fn first_writer_mints_and_lost_response_retry_recovers_the_stored_incarnation() {
    let backing = store();
    let caller_key = key();
    let first = attempt(&caller_key, 0xA1, GitHashAlgorithm::Sha256);
    let retry = attempt(&caller_key, 0xB2, GitHashAlgorithm::Sha256);

    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &first)
            .expect("the empty creation slot accepts its first writer"),
        CreationAttemptOutcome::Created(first)
    );
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &retry)
            .expect("a lost-response retry re-reads the immutable attempt"),
        CreationAttemptOutcome::Recovered(first),
        "the retry's locally minted incarnation must never replace the first writer's mint"
    );
}

#[test]
fn key_reuse_with_changed_fixed_fields_refuses_and_preserves_the_original_attempt() {
    let backing = store();
    let caller_key = key();
    let original = attempt(&caller_key, 0xA1, GitHashAlgorithm::Sha256);
    let changed = attempt(&caller_key, 0xB2, GitHashAlgorithm::Sha1);

    record_creation_attempt(&backing, &caller_key, &original)
        .expect("the original attempt occupies its immutable slot");
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &changed),
        Err(OutcomeFailure::CreationAttemptFixedFieldsMismatch),
        "reusing a creation key may not retarget its object format or its incarnation"
    );

    let matching_retry = attempt(&caller_key, 0xC3, GitHashAlgorithm::Sha256);
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &matching_retry)
            .expect("the original fixed fields remain recoverable after a refused reuse"),
        CreationAttemptOutcome::Recovered(original),
        "the mismatch must not overwrite the original immutable creation record"
    );
}

#[test]
fn body_digest_must_match_the_explicit_caller_key_before_any_slot_is_written() {
    let backing = store();
    let caller_key = key();
    let other_key = IdempotencyKey::new(b"different-caller-key".to_vec())
        .expect("the second fixed caller key is inside the bound");
    let mut mismatched = attempt(&other_key, 0xA1, GitHashAlgorithm::Sha256);
    mismatched.idempotency_key_digest = Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[0x99; 32]).expect("fixed SHA-256 digest width"),
    );

    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &mismatched),
        Err(OutcomeFailure::CreationAttemptKeyMismatch),
        "the raw caller key, not a caller-selected digest, determines the attempt slot"
    );
    let honest = attempt(&caller_key, 0xB2, GitHashAlgorithm::Sha256);
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &honest)
            .expect("the rejected body must not occupy the caller key slot"),
        CreationAttemptOutcome::Created(honest)
    );
}
