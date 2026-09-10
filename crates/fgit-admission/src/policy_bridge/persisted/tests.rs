//! Reference-store behavior tests, not durable-storage or power-loss evidence.
use super::*;
use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
use fgit_policy::{AuthenticationStrength, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, InternalObjectId, PrincipalId, PrincipalSnapshotId, RefName};
use std::cell::Cell;

fn live() -> Result<(), RefusalCode> { Ok(()) }
fn frame(allow: bool) -> PolicyFrame {
    PolicyFrame::compile(if allow { "policy pinned { default allow }" }
        else { "policy pinned { default deny \"review required\" }" }, PolicyStoreLimits::default(), &live).unwrap()
}
fn store() -> MemoryAuthorityStore { MemoryAuthorityStore::new(StoreInstanceId::from_raw(912)) }
fn input() -> PolicyInputRoot {
    let digest = fgit_codec::harness::digest_of(3);
    let snapshot = PrincipalSnapshotId::from_internal_object_id(InternalObjectId::new(
        digest.algorithm(), PrincipalSnapshotId::DOMAIN_TAG, CANONICAL_CODEC_VERSION, *digest.bytes(),
    )).unwrap();
    let principal = PrincipalFacts::try_new(PrincipalId::from_bytes([3; 16]), snapshot,
        PrincipalKind::Human, AuthenticationStrength::MultiFactor, &[], &[]).unwrap();
    let oid = GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap();
    PolicyInputRoot::try_new(principal, vec![RefUpdateFact::try_new(
        RefName::try_new(b"refs/heads/main").unwrap(), None, Some(oid), RefUpdateKind::Create, false,
    ).unwrap()], &[], &[], PolicyInstant::from_seconds(1)).unwrap()
}

#[test]
fn staged_policy_round_trips_and_identical_puts_keep_the_identity() {
    let store = store(); let frame = frame(false); let limits = PolicyStoreLimits::default();
    let first = stage_policy(&store, &frame, &live).unwrap();
    assert_eq!(first.id, frame.id());
    assert_eq!(first.disposition, PolicyStageDisposition::Created);
    assert_eq!(first.encoded_bytes, frame.bytes().len());
    let second = stage_policy(&store, &frame, &live).unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.disposition, PolicyStageDisposition::IdenticalRetry);
    let policy = read_policy(&store, frame.id(), limits, &live).unwrap();
    assert_eq!(policy.id(), frame.id());
    assert_eq!(policy.encode().unwrap(), frame.bytes());
}

#[test]
fn a_valid_wrong_policy_in_the_requested_slot_is_not_an_allow_verdict() {
    let store = store(); let deny = frame(false); let allow = frame(true);
    let key = body_key_for_id(deny.id().as_internal_object_id()).unwrap();
    store.put_if_absent(&key, allow.bytes()).unwrap();
    assert!(matches!(read_policy(&store, deny.id(), PolicyStoreLimits::default(), &live),
        Err(PolicyStoreError::IdentityMismatch { requested, observed })
            if *requested == deny.id() && *observed == allow.id()));
    assert!(matches!(evaluate_stored_policy(&store, deny.id(), &input(), &SubjectCodeMap::default(),
        PolicyStoreLimits::default(), &live), Err(PolicyStoreError::IdentityMismatch { .. })));
    assert!(matches!(stage_policy(&store, &deny, &live), Err(PolicyStoreError::ConflictingSlot { id }) if *id == deny.id()));
    let ImmutableRead::Present(bytes) = store.read_immutable(&key).unwrap() else { panic!("planted slot remains"); };
    assert_eq!(bytes, allow.bytes(), "failure cannot overwrite an immutable slot");
}

#[test]
fn allow_and_deny_evaluations_name_the_actual_persisted_snapshot() {
    let store = store(); let input = input(); let codes = SubjectCodeMap::default();
    for allow in [false, true] {
        let frame = frame(allow); stage_policy(&store, &frame, &live).unwrap();
        let result = evaluate_stored_policy(&store, frame.id(), &input, &codes, PolicyStoreLimits::default(), &live).unwrap();
        assert_eq!(result.snapshot_id, frame.id());
        assert_eq!(result.refusal, if allow { None } else { Some(codes.transition_denied) });
        let repeat = evaluate_stored_policy(&store, frame.id(), &input, &codes, PolicyStoreLimits::default(), &live).unwrap();
        assert_eq!(repeat.trace, result.trace);
        assert_eq!(repeat.snapshot_id, result.snapshot_id);
    }
}

#[test]
fn missing_corrupt_and_oversized_policies_do_not_select_a_fallback() {
    let frame = frame(false); let limits = PolicyStoreLimits::default();
    assert!(matches!(read_policy(&store(), frame.id(), limits, &live), Err(PolicyStoreError::Missing { .. })));
    for end in 0..frame.bytes().len() {
        assert!(PolicyFrame::from_bytes(&frame.bytes()[..end], limits, &live).is_err());
    }
    let mut trailing = frame.bytes().to_vec(); trailing.push(0);
    assert!(PolicyFrame::from_bytes(&trailing, limits, &live).is_err());
    let small = PolicyStoreLimits { frame_bytes: 1, ..limits };
    assert!(matches!(PolicyFrame::from_bytes(frame.bytes(), small, &live), Err(PolicyStoreError::FrameTooLarge { .. })));
    assert!(matches!(PolicyFrame::from_bytes(frame.bytes(), PolicyStoreLimits { elements: 0, ..limits }, &live),
        Err(PolicyStoreError::InvalidLimits)));
    let store = store(); let key = body_key_for_id(frame.id().as_internal_object_id()).unwrap();
    store.put_if_absent(&key, b"not a canonical policy").unwrap();
    assert!(matches!(read_policy(&store, frame.id(), limits, &live), Err(PolicyStoreError::Codec(_))));
}

#[test]
fn cancellation_before_put_changes_nothing_and_after_read_returns_no_verdict() {
    let store = store(); let frame = frame(false); let limits = PolicyStoreLimits::default();
    let stopped = || Err(RefusalCode::CancellationInProgress);
    assert!(matches!(stage_policy(&store, &frame, &stopped), Err(PolicyStoreError::Stopped(RefusalCode::CancellationInProgress))));
    assert!(matches!(read_policy(&store, frame.id(), limits, &live), Err(PolicyStoreError::Missing { .. })));
    stage_policy(&store, &frame, &live).unwrap();
    let calls = Cell::new(0usize);
    let stop_after_read = || {
        let at = calls.get(); calls.set(at + 1);
        if at == 0 { Ok(()) } else { Err(RefusalCode::ResourceBudgetExceeded) }
    };
    assert!(matches!(read_policy(&store, frame.id(), limits, &stop_after_read),
        Err(PolicyStoreError::Stopped(RefusalCode::ResourceBudgetExceeded))));
    assert_eq!(calls.get(), 2);
    assert_eq!(read_policy(&store, frame.id(), limits, &live).unwrap().id(), frame.id());
}

#[test]
fn source_compilation_uses_existing_language_and_refuses_ambient_inputs() {
    let limits = PolicyStoreLimits::default();
    let a = PolicyFrame::compile("policy ordered { rule a { when true then allow } default deny \"no\" }", limits, &live).unwrap();
    let b = PolicyFrame::from_bytes(a.bytes(), limits, &live).unwrap();
    assert_eq!(a.id(), b.id()); assert_eq!(a.bytes(), b.bytes());
    assert!(matches!(PolicyFrame::compile("policy bad { rule x { when env.home == \"x\" then allow } default deny \"no\" }",
        limits, &live), Err(PolicyStoreError::Compile(_))));
    assert!(matches!(PolicyFrame::compile("policy missing_default {}", limits, &live), Err(PolicyStoreError::Compile(_))));
}
