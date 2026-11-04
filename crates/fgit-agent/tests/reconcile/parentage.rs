#![forbid(unsafe_code)]
//! Live parentage validation and compatibility with complete historical journals.

use super::*;
use fgit_agent::effect_journal::{EffectJournalEncoder, RecoveredEffectJournal};
use fgit_agent::{
    BrokerRefusal, Capability, EffectBroker, EffectJournalEvent, EffectJournalRefusal,
    EffectRequest,
};
use fgit_resource::RegionId;

fn setup() -> (IntentRun, Capability, EffectBroker) {
    let receipt = authority_receipt(901, 0x61);
    let run = run(&receipt, 100);
    let capability = Capability::issue(
        CapabilityId::new(42),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 100),
        LogicalTime::new(10),
        LogicalTime::new(100),
    )
    .unwrap();
    let broker = EffectBroker::open(run.clone(), RegionId::new(9), AgentInstanceId::new(7));
    (run, capability, broker)
}

fn request(id: u128, parent: Option<u128>, bytes: u64) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(id),
        parent_effect_id: parent.map(EffectId::new),
        operation: OperationClass::TreeFsWorkspace,
        cost: ResourceVector::single(Grade::Bytes, bytes),
        input_commitment: [0x42; 32],
    }
}

fn reject_without_change(
    broker: &mut EffectBroker,
    capability: &Capability,
    now: u64,
    request: &EffectRequest,
) {
    let before = broker.journal();
    let records = broker.records();
    let refusal = match broker.request(capability, LogicalTime::new(now), request) {
        Err(refusal) => refusal,
        Ok(grant) => {
            broker.abort(grant).unwrap();
            panic!("an invalid parent must refuse before an effect is accepted");
        }
    };
    assert!(matches!(
        refusal,
        BrokerRefusal::Journal {
            source: EffectJournalRefusal::InvalidParentEffect {
                effect_id,
                parent_effect_id,
            },
        } if effect_id == request.effect_id
            && Some(parent_effect_id) == request.parent_effect_id
    ));
    assert_eq!(broker.journal(), before);
    assert_eq!(broker.records(), records);
}

fn recovered_report(run: &IntentRun, broker: &EffectBroker) -> RunReconciliationReport {
    let (mut encoder, mut bytes) = EffectJournalEncoder::new(run).unwrap();
    for entry in broker.journal() {
        bytes.extend(encoder.encode(&entry).unwrap());
    }
    let expected_tail = encoder.position();
    let recovered = RecoveredEffectJournal::decode(run, &bytes, Some(expected_tail)).unwrap();
    assert!(recovered.is_anchored());
    let report = recovered
        .reconciliation_report(run, LogicalTime::new(50))
        .unwrap();
    assert_eq!(
        report,
        RunReconciliationReport::build(run, broker.records(), LogicalTime::new(50)).unwrap(),
    );
    report
}

#[test]
fn effect_parent_self_reference_cannot_poison_recovery_or_consume_budget() {
    let (run, capability, mut broker) = setup();
    reject_without_change(&mut broker, &capability, 20, &request(1, Some(1), 100));
    // The refused ID and the entire reservation remain available.
    let grant = broker
        .request(&capability, LogicalTime::new(20), &request(1, None, 100))
        .unwrap();
    broker.abort(grant).unwrap();
    assert_eq!(
        recovered_report(&run, &broker).readiness(),
        RunReconciliationReadiness::Ready
    );
    assert!(broker.close().is_quiescent());
}

#[test]
fn effect_parent_missing_reference_cannot_poison_recovery_or_consume_budget() {
    let (run, capability, mut broker) = setup();
    reject_without_change(&mut broker, &capability, 20, &request(2, Some(1), 100));
    let parent = broker
        .request(&capability, LogicalTime::new(20), &request(1, None, 50))
        .unwrap();
    let child = broker
        .request(&capability, LogicalTime::new(20), &request(2, Some(1), 50))
        .unwrap();
    broker.abort(child).unwrap();
    broker.abort(parent).unwrap();
    let report = recovered_report(&run, &broker);
    assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
    assert_eq!(report.counts().aborted(), 2);
    assert!(broker.close().is_quiescent());
}

#[test]
fn effect_parent_time_is_checked_without_imposing_numeric_id_order() {
    let (run, capability, mut broker) = setup();
    let parent = broker
        .request(&capability, LogicalTime::new(30), &request(99, None, 50))
        .unwrap();
    reject_without_change(&mut broker, &capability, 29, &request(1, Some(99), 50));
    // Equal logical times are permitted. Parent IDs need not be smaller.
    let child = broker
        .request(&capability, LogicalTime::new(30), &request(1, Some(99), 50))
        .unwrap();
    broker.abort(parent).unwrap();
    broker.abort(child).unwrap();
    let report = recovered_report(&run, &broker);
    assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
    assert_eq!(
        report.effects()[0].record().parent_effect_id,
        Some(EffectId::new(99))
    );
    assert!(broker.close().is_quiescent());
}

#[test]
fn effect_parent_terminal_parent_remains_valid_and_legacy_complete_replay_is_preserved() {
    let (run, capability, mut broker) = setup();
    let parent = broker
        .request(&capability, LogicalTime::new(20), &request(9, None, 100))
        .unwrap();
    broker.abort(parent).unwrap();
    let child = broker
        .request(&capability, LogicalTime::new(20), &request(1, Some(9), 100))
        .unwrap();
    broker.abort(child).unwrap();
    let expected = recovered_report(&run, &broker);
    assert_eq!(expected.readiness(), RunReconciliationReadiness::Ready);

    // Older writers allowed a child before its parent. Preserve complete
    // historically reconcilable journals while refusing new unsafe prefixes.
    let mut entries = broker.journal();
    assert_eq!(entries.len(), 4);
    assert!(matches!(&entries[0].event, EffectJournalEvent::Accepted(_)));
    assert!(matches!(&entries[2].event, EffectJournalEvent::Accepted(_)));
    entries.swap(0, 2);
    entries.swap(1, 3);
    let (mut encoder, mut bytes) = EffectJournalEncoder::new(&run).unwrap();
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.sequence = u64::try_from(index).expect("four-entry sequence");
        bytes.extend(encoder.encode(entry).unwrap());
    }
    let recovered = RecoveredEffectJournal::decode(&run, &bytes, Some(encoder.position())).unwrap();
    assert_eq!(
        recovered
            .reconciliation_report(&run, LogicalTime::new(50))
            .unwrap(),
        expected
    );
    assert!(broker.close().is_quiescent());
}
