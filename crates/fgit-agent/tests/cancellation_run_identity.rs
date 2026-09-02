#![forbid(unsafe_code)]
//! Public-path tests for complete-run identity in cancellation.

use fgit_agent::{
    AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime,
    OperationClass, RunCancellationCompletionRefusal, RunCancellationIntent,
    RunCancellationRequestRefusal, RunId, RunReconciliationReport, SituationComponent,
    SituationComponentKind, SituationOmissionReason,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x31; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(RepositoryCommitId::from_digest(
            IdentityDomain::RepositoryCommitRecord.algorithm().id(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x32; 32]).expect("fixed-width RCR digest"),
        )),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: digest(0x33),
        outcome_index_root: digest(0x34),
        retention_root: digest(0x35),
        outbox_root: digest(0x36),
        configuration_root: digest(0x37),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1_201));
    let key = HeadKey::new(b"cancellation-run-identity".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(&authenticated, LogicalTime::new(10), [0x71; 32])
        .expect("complete authenticated read")
}

fn run(receipt: &AuthorityReadReceipt, bytes: u64, expiry: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(expiry),
    )
    .expect("authenticated run opens")
}

fn situation(receipt: &AuthorityReadReceipt, run: &IntentRun) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        SituationComponent::omitted(
            kind,
            SituationOmissionReason::NotAvailable,
            [u8::try_from(index + 1).expect("component index fits u8"); 32],
        )
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(20),
        components,
    )
    .expect("complete situation")
}

#[test]
fn same_id_altered_run_cannot_request_or_complete_source_cancellation() {
    let receipt = authority_receipt();
    let source = run(&receipt, 1_000, 100);
    let altered = run(&receipt, 999, 90);
    let situation = situation(&receipt, &source);
    let initial = RunReconciliationReport::build(&source, Vec::new(), LogicalTime::new(20))
        .expect("empty source inventory");
    let expected = source.commitment().expect("source run commitment");
    let observed = altered.commitment().expect("altered run commitment");
    assert_ne!(expected, observed);

    assert_eq!(
        RunCancellationIntent::request(
            &situation,
            &altered,
            initial.clone(),
            None,
            AgentInstanceId::new(1),
            digest(0x81),
        )
        .expect_err("latest situation cannot be paired with a same-ID altered run"),
        RunCancellationRequestRefusal::SituationRunCommitmentMismatch {
            expected: observed,
            observed: Some(expected),
        }
    );

    let intent = RunCancellationIntent::request(
        &situation,
        &source,
        initial,
        None,
        AgentInstanceId::new(1),
        digest(0x81),
    )
    .expect("source cancellation request opens");
    let final_report = RunReconciliationReport::build(&altered, Vec::new(), LogicalTime::new(30))
        .expect("altered run has its own valid empty report");

    assert_eq!(
        intent
            .complete(final_report, None, Vec::new(), Vec::new())
            .expect_err("another complete run cannot finish the source cancellation"),
        RunCancellationCompletionRefusal::RunCommitmentMismatch { expected, observed }
    );
}
