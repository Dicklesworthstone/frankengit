//! FG-059: creation-attempt recovery under real authority fault scripts.

use fgit_authority::{
    AuthorityFailure, AuthorityOpKind, CreationAttemptOutcome, FaultDirective, FaultKind,
    FaultPlan, FaultPosition, FaultableAuthorityStore, IdempotencyKey, MemoryAuthorityStore,
    OutcomeFailure, SealFailure, StoreInstanceId, record_creation_attempt,
};
use fgit_codec::CreationAttemptBody;
use fgit_types::{
    GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, RootLayoutVersion, TenantId,
};

fn store(instance: u64) -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance))
}

fn key() -> IdempotencyKey {
    IdempotencyKey::new(b"fg059-creation-fault-retry".to_vec())
        .expect("fixed caller key is bounded")
}

fn attempt(key: &IdempotencyKey, incarnation: u8) -> CreationAttemptBody {
    CreationAttemptBody {
        tenant_id: TenantId::from_bytes([0x59; 16]),
        repository_id: RepositoryId::from_bytes([0x60; 16]),
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        idempotency_key_digest: key.digest(),
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([incarnation; 16]),
    }
}

fn is_ambiguous(result: &Result<CreationAttemptOutcome, OutcomeFailure>) -> bool {
    matches!(
        result,
        Err(OutcomeFailure::Seal(error))
            if matches!(error.as_ref(), SealFailure::Store(AuthorityFailure::Ambiguous(_)))
    )
}

#[test]
fn post_write_lost_response_retry_recovers_the_first_writer_mint() {
    let backing = store(0x5901);
    let caller_key = key();
    let first = attempt(&caller_key, 0xA1);
    let retry = attempt(&caller_key, 0xB2);
    backing.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::PutIfAbsent,
        FaultKind::LoseResponse,
    )]));

    assert!(is_ambiguous(&record_creation_attempt(
        &backing,
        &caller_key,
        &first,
    )));

    backing.install_fault_plan(FaultPlan::none());
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &retry)
            .expect("retry resolves the exact occupied creation slot"),
        CreationAttemptOutcome::Recovered(first),
        "the retry-local candidate must never replace the committed first writer mint"
    );
}

#[test]
fn post_write_crash_then_store_restart_recovers_the_first_writer_mint() {
    let backing = store(0x5902);
    let caller_key = key();
    let first = attempt(&caller_key, 0xA3);
    let retry = attempt(&caller_key, 0xB4);
    backing.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::PutIfAbsent,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));

    assert!(is_ambiguous(&record_creation_attempt(
        &backing,
        &caller_key,
        &first,
    )));
    assert!(
        backing.is_crashed(),
        "the fault script really stopped the endpoint"
    );

    backing.restart();
    backing.install_fault_plan(FaultPlan::none());
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &retry)
            .expect("post-restart retry resolves persisted immutable state"),
        CreationAttemptOutcome::Recovered(first),
        "a crash after the put cannot turn a retry into a second incarnation"
    );
}

#[test]
fn pre_write_lost_request_retry_is_the_first_writer_and_not_a_phantom_recovery() {
    let backing = store(0x5903);
    let caller_key = key();
    let lost = attempt(&caller_key, 0xA5);
    let retry = attempt(&caller_key, 0xB6);
    backing.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::PutIfAbsent,
        FaultKind::LoseRequest,
    )]));

    assert!(is_ambiguous(&record_creation_attempt(
        &backing,
        &caller_key,
        &lost,
    )));

    backing.install_fault_plan(FaultPlan::none());
    assert_eq!(
        record_creation_attempt(&backing, &caller_key, &retry)
            .expect("retry reaches the previously untouched attempt slot"),
        CreationAttemptOutcome::Created(retry),
        "a request lost before the effect must not fabricate a recovered mint"
    );
}
