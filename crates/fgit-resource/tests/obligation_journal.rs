//! The obligation journal and its replay (FG-012c).
//!
//! The journal exists so an independent verifier can REPLAY a region's
//! obligation history rather than trust a snapshot of where it ended up: a
//! snapshot cannot distinguish "never reserved" from "reserved and settled",
//! and the properties worth checking are about the sequence.
//!
//! Every test asserting a replay SUCCEEDS is paired with one making the same
//! trace invalid and requiring a refusal. A replay nobody has watched fail is
//! not a verifier.
//!
//! The ledger here uses `RecordAndContinue` so a fixture that drops a
//! reservation records the leak instead of aborting the test process. The
//! leak disposition is not what these tests are about.

use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot, SlotHandedOff};
use fgit_resource::{
    Grade, LeakDisposition, LedgerRecord, LifecycleEvent, ObligationClass, ObligationLedger,
    ObligationState, RecordAmounts, RegionId, ReplayError, ResourceVector, replay_journal,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RepositoryDecisionBatchId, TxId,
};

fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        ResourceVector::single(Grade::MemoryBytes, 1024),
    )
}

fn lane_slot() -> LaneSlot {
    LaneSlot {
        lane: 3,
        transaction: TxId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[7; 32]).expect("32-byte corpus fixture body"),
        ),
    }
}

fn batch_id() -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[9; 32]).expect("32-byte corpus fixture body"),
    )
}

fn unit() -> ResourceVector {
    ResourceVector::single(Grade::MemoryBytes, 4)
}

/// A reservation opens the journal, and the trace replays to Reserved.
#[test]
fn a_reservation_opens_the_journal() {
    let ledger = ledger();
    let grant = ledger.grant(unit()).expect("a grant");
    let reserved = ledger
        .reserve::<PreparedTxnSlot>(lane_slot(), grant)
        .expect("a reservation");

    let journal = ledger.journal();
    assert_eq!(journal.len(), 1, "{journal:?}");
    let opening = journal.first().expect("one record");
    assert_eq!(opening.event(), None, "the opening record carries no event");
    assert_eq!(opening.state(), ObligationState::Reserved);
    assert_eq!(opening.class(), ObligationClass::PreparedTxnSlot);
    assert_eq!(opening.region(), RegionId::new(1));
    assert_eq!(opening.ordinal(), 0);

    let states = replay_journal(&journal).expect("a real trace replays");
    assert_eq!(
        states.get(&opening.obligation()).copied(),
        Some(ObligationState::Reserved),
    );
    drop(reserved);
}

#[test]
fn an_empty_trace_replays_to_nothing_rather_than_refusing() {
    assert!(
        replay_journal(&[])
            .expect("empty is well-formed")
            .is_empty()
    );
}

/// A replay must REFUSE a trace whose recorded state is not what applying the
/// event produces. Without this check the replay is a transcript reader.
#[test]
fn a_recorded_state_that_disagrees_with_apply_is_refused() {
    let ledger = ledger();
    let grant = ledger.grant(unit()).expect("a grant");
    let reserved = ledger
        .reserve::<PreparedTxnSlot>(lane_slot(), grant)
        .expect("a reservation");
    let opening = *ledger.journal().first().expect("one record");

    let forged = LedgerRecord::new(
        opening.region(),
        opening.ordinal() + 1,
        opening.obligation(),
        opening.class(),
        Some(LifecycleEvent::Commit),
        ObligationState::Acknowledged,
        RecordAmounts {
            reserved: ResourceVector::ZERO,
            charged: ResourceVector::ZERO,
        },
    );
    match replay_journal(&[opening, forged]).expect_err("a forged state refuses") {
        ReplayError::StateDisagreement {
            recorded, replayed, ..
        } => {
            assert_eq!(recorded, ObligationState::Acknowledged);
            assert_eq!(
                replayed,
                ObligationState::Committed,
                "Reserved + Commit is Committed; the journal claimed otherwise"
            );
        }
        other => panic!("expected a state disagreement, got {other:?}"),
    }
    drop(reserved);
}

#[test]
fn an_event_for_an_unreserved_obligation_is_refused() {
    let ledger = ledger();
    let grant = ledger.grant(unit()).expect("a grant");
    let reserved = ledger
        .reserve::<PreparedTxnSlot>(lane_slot(), grant)
        .expect("a reservation");
    let opening = *ledger.journal().first().expect("one record");
    let orphan = LedgerRecord::new(
        opening.region(),
        0,
        opening.obligation(),
        opening.class(),
        Some(LifecycleEvent::Commit),
        ObligationState::Committed,
        RecordAmounts {
            reserved: ResourceVector::ZERO,
            charged: ResourceVector::ZERO,
        },
    );
    assert!(matches!(
        replay_journal(&[orphan]).expect_err("an orphan event refuses"),
        ReplayError::UnreservedObligation(_)
    ));
    drop(reserved);
}

#[test]
fn ordinals_that_do_not_advance_are_refused() {
    let ledger = ledger();
    let grant = ledger.grant(unit()).expect("a grant");
    let reserved = ledger
        .reserve::<PreparedTxnSlot>(lane_slot(), grant)
        .expect("a reservation");
    let opening = *ledger.journal().first().expect("one record");
    let stalled = LedgerRecord::new(
        opening.region(),
        opening.ordinal(),
        opening.obligation(),
        opening.class(),
        Some(LifecycleEvent::Commit),
        ObligationState::Committed,
        RecordAmounts {
            reserved: ResourceVector::ZERO,
            charged: ResourceVector::ZERO,
        },
    );
    assert!(matches!(
        replay_journal(&[opening, stalled]).expect_err("a stalled ordinal refuses"),
        ReplayError::NonMonotonicOrdinal { .. }
    ));
    drop(reserved);
}

/// The defect `OliveFortress` found: `mark` applied transitions without
/// journalling them, so defer / acknowledge / escalate / fail-terminally —
/// four of the seven lifecycle events — were invisible to a replay.
///
/// An incomplete trace does not merely lose detail. A verifier asserting over
/// it finds no violation, because the records that would show one were never
/// written. So this drives a real obligation to settlement and requires the
/// journal to carry BOTH the opening reservation and the resulting transition,
/// and requires the replay to agree with the ledger's own state.
#[test]
fn a_settled_obligation_journals_its_transition_and_replays_to_it() {
    let ledger = ledger();
    let grant = ledger.grant(unit()).expect("a grant");
    let obligation = ledger
        .reserve::<PreparedTxnSlot>(lane_slot(), grant)
        .expect("a reservation");
    let id = obligation.id();

    let settled = obligation
        .commit_internal(
            SlotHandedOff {
                batch_attempt: batch_id(),
            },
            &unit(),
        )
        .expect("committing the whole reservation");
    let _ = settled;

    let journal = ledger.journal();
    assert!(
        journal.len() >= 2,
        "the opening reservation AND its transition must both be recorded: {journal:?}"
    );
    let last = journal.last().expect("a last record");
    assert_eq!(last.obligation(), id);
    assert!(
        last.event().is_some(),
        "a transition record must name the event that produced it"
    );

    let states = replay_journal(&journal).expect("a real trace replays");
    assert_eq!(
        states.get(&id).copied(),
        ledger.handle().state_of(id),
        "the replay must agree with the ledger's own state for that obligation"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
