//! Reference-store and shared-core tests, not durable-backend evidence.
use super::*;
use crate::{MemoryAuthorityStore, SealAttempt, SemanticRequest, StoreInstanceId};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_types::{DecisionOutcome, DecisionSequence, GitHashAlgorithm, HeadGeneration,
    InternalObjectId, PolicyEpoch, RefusalRecordId, RegistryEpoch};

fn fixture() -> (MemoryAuthorityStore, HeadKey, RecoveryScope, SealAttempt) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(73));
    let head_key = HeadKey::new(b"recovery-test/head".to_vec()).unwrap();
    let scope = RecoveryScope { tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]), principal_id: PrincipalId::from_bytes([3; 16]) };
    let root = fgit_codec::harness::digest_of(9);
    let head = RepositoryAuthorityHeadBody {
        repository_id: scope.repository_id, generation: HeadGeneration::FIRST,
        predecessor_head_id: None, decision_tail_id: None, latest_decision_sequence: None,
        latest_committed_rcr_id: None, latest_repository_sequence: None,
        ref_root: root, forge_position_root: root, outcome_index_root: crate::outcome_index_root(&[]).unwrap(),
        retention_root: root, outbox_root: root, configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST, format_registry_epoch: RegistryEpoch::FIRST, last_checkpoint_id: None,
    };
    crate::initialize_repository(&store, &head_key, &head).unwrap();
    let request = SemanticRequest::build(crate::RECEIVE_ADMISSION_SCHEMA, GitHashAlgorithm::Sha1,
        true, Vec::new(), Vec::new(), vec![crate::ScopedEntry::new(
            fgit_types::AsciiSlug::from_static("test"), fgit_types::AsciiSlug::from_static("request"), b"payload").unwrap()]).unwrap();
    let attempt = SealAttempt { tenant_id: scope.tenant_id, repository_id: scope.repository_id,
        authenticated_principal_id: scope.principal_id,
        idempotency_key: IdempotencyKey::new(b"lost-response-secret-key".to_vec()).unwrap(), request };
    (store, head_key, scope, attempt)
}

#[test]
fn canonical_head_payload_exceeds_binding_limit_but_remains_recoverable() {
    let (store, head, scope, attempt) = fixture();
    let HeadRead::Present(receipt) = AuthorityStore::read_head(&store, &head).unwrap() else {
        panic!("initialized head");
    };
    // The frame's entire payload is a length-prefixed byte string, not just
    // its individual digests. The former 256-byte limit rejects a valid head.
    let binding_sized = DecodeLimits { byte_string_bytes: 256, ..LIMITS };
    assert!(matches!(
        decode_body::<RepositoryAuthorityHeadBody>(receipt.body(), binding_sized),
        Err(fgit_codec::CodecRefusal::LengthBoundExceeded {
            field: "payload", observed, limit: 256,
        }) if observed > 256
    ));
    let decoded: RepositoryAuthorityHeadBody = decode_body(receipt.body(), LIMITS).unwrap();
    assert_eq!(decoded.repository_id, scope.repository_id);
    assert_eq!(encode_body(&decoded).unwrap(), receipt.body());
    assert_eq!(
        recover_request(&store, &head, scope, &attempt.idempotency_key, &|| Ok(())).unwrap(),
        RequestRecovery::KeyNotObserved
    );
    assert_eq!(AuthorityStore::read_head(&store, &head).unwrap(), HeadRead::Present(receipt));
}

#[test]
fn observations_distinguish_binding_from_seal_without_writing_or_replaying_work() {
    let (store, head, scope, attempt) = fixture();
    let before = AuthorityStore::read_head(&store, &head).unwrap();
    let recover = || recover_request(&store, &head, scope, &attempt.idempotency_key, &|| Ok(())).unwrap();
    assert_eq!(recover(), RequestRecovery::KeyNotObserved);
    let (tx_id, seal) = attempt.derive().unwrap();
    crate::bind_idempotency_key(&store, &attempt, tx_id).unwrap();
    assert_eq!(recover(), RequestRecovery::SealNotObserved);
    let admitted = crate::admit_seal(&store, &seal).unwrap();
    let RequestRecovery::Recovered(recovered) = recover() else { panic!("verified seal"); };
    assert_eq!(recovered.tx_id(), tx_id);
    assert_eq!(recovered.seal_id(), admitted.seal_id());
    assert_eq!(recovered.seal(), &seal);
    assert_eq!(recovered.outcome(), OutcomeLookup::Undecided);
    let different = RecoveryScope { principal_id: PrincipalId::from_bytes([4;16]), ..scope };
    assert_eq!(recover_request(&store, &head, different, &attempt.idempotency_key, &|| Ok(())).unwrap(),
        RequestRecovery::KeyNotObserved);
    let wrong_key = IdempotencyKey::new(b"different-key".to_vec()).unwrap();
    assert_eq!(recover_request(&store, &head, scope, &wrong_key, &|| Ok(())).unwrap(), RequestRecovery::KeyNotObserved);
    assert_eq!(AuthorityStore::read_head(&store, &head).unwrap(), before);
}

#[test]
fn every_scope_and_identity_mismatch_fails_before_outcome_disclosure() {
    let (_, _, scope, attempt) = fixture();
    let (tx, valid) = attempt.derive().unwrap();
    let bytes = encode_body(&valid).unwrap();
    assert!(checked_seal(ImmutableRead::Present(bytes.clone()), scope, &attempt.idempotency_key, tx).unwrap().is_some());
    for field in 0..6 {
        let mut changed = valid.clone();
        match field {
            0 => changed.tenant_id = TenantId::from_bytes([8; 16]),
            1 => changed.repository_id = RepositoryId::from_bytes([8; 16]),
            2 => changed.authenticated_principal_id = PrincipalId::from_bytes([8; 16]),
            3 => changed.idempotency_key_digest = fgit_codec::harness::digest_of(8),
            4 => changed.canonical_request_digest = fgit_codec::harness::digest_of(8),
            _ => { let mut other = attempt.clone(); other.idempotency_key = IdempotencyKey::new(b"other".to_vec()).unwrap();
                changed.tx_id = other.derive().unwrap().0; }
        }
        assert!(matches!(checked_seal(ImmutableRead::Present(encode_body(&changed).unwrap()),
            scope, &attempt.idempotency_key, tx), Err(RecoveryFailure::Integrity { .. })), "field {field}");
    }
    let wrong = IdempotencyKey::new(b"unrelated-client-key".to_vec()).unwrap();
    assert!(checked_seal(ImmutableRead::Present(bytes), scope, &wrong, tx).is_err());
}

#[test]
fn binding_and_seal_decoders_are_strict_bounded_and_domain_pinned() {
    let (_, _, scope, attempt) = fixture();
    let (tx, seal) = attempt.derive().unwrap();
    let mut encoder = Encoder::new(); encoder.write_internal_object_id(tx.as_internal_object_id()).unwrap();
    let bytes = encoder.into_bytes();
    assert_eq!(binding_identity(ImmutableRead::Present(bytes.clone())).unwrap(), Some(tx));
    for end in 0..bytes.len() { assert!(binding_identity(ImmutableRead::Present(bytes[..end].to_vec())).is_err()); }
    let mut trailing = bytes; trailing.push(0);
    assert!(binding_identity(ImmutableRead::Present(trailing)).is_err());
    let root = fgit_codec::harness::digest_of(1);
    let foreign = InternalObjectId::new(root.algorithm(), TransactionSealId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION, *root.bytes());
    let mut encoder = Encoder::new(); encoder.write_internal_object_id(&foreign).unwrap();
    assert!(matches!(binding_identity(ImmutableRead::Present(encoder.into_bytes())), Err(RecoveryFailure::Integrity { .. })));
    assert!(matches!(binding_identity(ImmutableRead::Present(vec![0; MAX_BINDING_BYTES + 1])), Err(RecoveryFailure::BoundExceeded { .. })));
    let bytes = encode_body(&seal).unwrap();
    for end in 0..bytes.len() {
        assert!(checked_seal(ImmutableRead::Present(bytes[..end].to_vec()), scope, &attempt.idempotency_key, tx).is_err());
    }
    let mut trailing = bytes; trailing.push(0);
    assert!(checked_seal(ImmutableRead::Present(trailing), scope, &attempt.idempotency_key, tx).is_err());
    assert!(matches!(checked_seal(ImmutableRead::Present(vec![0; MAX_SEAL_BYTES + 1]),
        scope, &attempt.idempotency_key, tx), Err(RecoveryFailure::BoundExceeded { .. })));
}

#[test]
fn corrupt_binding_and_substituted_seals_do_not_become_absence_or_pending_success() {
    for corruption in 0..3 {
        let (store, head, scope, attempt) = fixture();
        let (tx, mut seal) = attempt.derive().unwrap();
        let binding = idempotency_binding_key(scope.tenant_id, scope.repository_id, scope.principal_id, &attempt.idempotency_key).unwrap();
        if corruption == 0 {
            AuthorityStore::put_if_absent(&store, &binding, b"not an identity").unwrap();
        } else {
            crate::bind_idempotency_key(&store, &attempt, tx).unwrap();
            if corruption == 1 { seal.authenticated_principal_id = PrincipalId::from_bytes([7;16]); }
            else { seal.canonical_request_digest = fgit_codec::harness::digest_of(7); }
            let key = seal_key(scope.tenant_id, scope.repository_id, tx).unwrap();
            AuthorityStore::put_if_absent(&store, &key, &encode_body(&seal).unwrap()).unwrap();
        }
        assert!(recover_request(&store, &head, scope, &attempt.idempotency_key, &|| Ok(())).is_err());
    }
}

#[test]
fn head_scope_and_cancellation_are_checked_even_when_no_binding_exists() {
    let (store, head, scope, attempt) = fixture();
    let wrong = RecoveryScope { repository_id: RepositoryId::from_bytes([8;16]), ..scope };
    assert!(matches!(recover_request(&store, &head, wrong, &attempt.idempotency_key, &|| Ok(())),
        Err(RecoveryFailure::Integrity { field: "head repository" })));
    let absent = HeadKey::new(b"not-created".to_vec()).unwrap();
    assert!(matches!(recover_request(&store, &absent, scope, &attempt.idempotency_key, &|| Ok(())),
        Err(RecoveryFailure::HeadNotObserved)));
    for code in [RefusalCode::CancellationInProgress, RefusalCode::ResourceBudgetExceeded] {
        assert!(matches!(recover_request(&store, &head, scope, &attempt.idempotency_key, &|| Err(code)),
            Err(RecoveryFailure::Interrupted(found)) if found == code));
    }
}

#[test]
fn cancellation_after_terminal_resolution_cannot_erase_a_known_decision() {
    let (_, _, scope, attempt) = fixture();
    let (tx, seal) = attempt.derive().unwrap();
    let (_, seal_id) = checked_seal(ImmutableRead::Present(encode_body(&seal).unwrap()),
        scope, &attempt.idempotency_key, tx).unwrap().unwrap();
    let root = fgit_codec::harness::digest_of(1);
    let refused = crate::TerminalOutcome { decision_sequence: DecisionSequence::FIRST,
        outcome: DecisionOutcome::Refused { code: RefusalCode::EvidenceInvalid,
            refusal_record_id: RefusalRecordId::from_internal_object_id(InternalObjectId::new(
                root.algorithm(), RefusalRecordId::DOMAIN_TAG, CANONICAL_CODEC_VERSION, *root.bytes())).unwrap() } };
    let cancelled = || Err(RefusalCode::CancellationInProgress);
    let report = finish(seal.clone(), seal_id, OutcomeLookup::Decided(refused), &cancelled).unwrap();
    assert_eq!(report.terminal(), Some(refused));
    assert!(matches!(finish(seal, seal_id, OutcomeLookup::Undecided, &cancelled),
        Err(RecoveryFailure::Interrupted(RefusalCode::CancellationInProgress))));
    assert_eq!(RequestRecovery::KeyNotObserved.terminal(), None);
    assert_eq!(RequestRecovery::SealNotObserved.terminal(), None);
}
