#![forbid(unsafe_code)]
//! Public-path tests for complete-run identity in effect records and replay.

use fgit_agent::{
    AgentInstanceId, AuthorityBasisRef, Capability, CapabilityId, ClassSet, EffectBroker, EffectId,
    EffectJournalRefusal, EffectRequest, IntentRun, LogicalTime, OperationClass, RunId,
};
use fgit_resource::{Grade, RegionId, ResourceVector};

const fn basis() -> AuthorityBasisRef {
    AuthorityBasisRef {
        repository_id: 7,
        authority_head_generation: 3,
        authority_head_digest: [0x11; 32],
        verified_at: LogicalTime::new(1),
    }
}

fn run(bytes: u64) -> IntentRun {
    IntentRun::new(
        RunId::new(1),
        basis(),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(100),
    )
    .expect("read-only run opens")
}

fn capability() -> Capability {
    Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        ResourceVector::single(Grade::Bytes, 1_000),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("read capability issues")
}

fn request(effect_id: u128) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(effect_id),
        parent_effect_id: None,
        operation: OperationClass::ReadCanonicalObject,
        cost: ResourceVector::single(Grade::Bytes, 10),
        input_commitment: [u8::try_from(effect_id).expect("small fixture ID"); 32],
    }
}

#[test]
fn journal_replay_cannot_merge_same_id_runs_with_different_machine_scope() {
    let first_run = run(1_000);
    let second_run = run(900);
    let first_commitment = first_run.commitment().expect("first run commitment");
    let second_commitment = second_run.commitment().expect("second run commitment");
    assert_ne!(first_commitment, second_commitment);

    let mut first = EffectBroker::open(first_run, RegionId::new(1), AgentInstanceId::new(1));
    let mut second = EffectBroker::open(second_run, RegionId::new(2), AgentInstanceId::new(2));
    let first_grant = first
        .request(&capability(), LogicalTime::new(10), &request(1))
        .expect("first effect accepted");
    let second_grant = second
        .request(&capability(), LogicalTime::new(10), &request(2))
        .expect("second effect accepted");
    assert_eq!(first_grant.record().run_commitment, first_commitment);
    assert_eq!(second_grant.record().run_commitment, second_commitment);

    let mut entries = vec![first.journal()[0].clone(), second.journal()[0].clone()];
    entries[1].sequence = 1;
    assert_eq!(
        EffectBroker::replay(&entries)
            .expect_err("same numeric RunId cannot merge distinct complete runs"),
        EffectJournalRefusal::MixedRunCommitment {
            effect_id: EffectId::new(2),
            expected: first_commitment,
            observed: second_commitment,
        }
    );

    let _first = first.abort(first_grant).expect("first reservation aborts");
    let _second = second
        .abort(second_grant)
        .expect("second reservation aborts");
    assert!(first.close().is_quiescent());
    assert!(second.close().is_quiescent());
}
