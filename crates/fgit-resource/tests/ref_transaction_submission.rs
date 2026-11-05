//! The agent's submission responsibility has its own observed lifecycle.
//!
//! These fixtures exercise resource ownership only. The agent authority adapter
//! separately authenticates the canonical outcome before supplying observation
//! evidence; a resource receipt alone makes no claim that a ref changed.

use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{
    LeakDisposition, ObligationLedger, ObligationState, RegionCloseOutcome, ReserveError,
};
use fgit_resource::ids::RegionId;
use fgit_resource::kinds::{
    NoCandidateReason, RefTransactionAborted, RefTransactionObserved, RefTransactionRequest,
    RefTransactionSubmission, RefTransactionSubmitted,
};
use fgit_resource::twophase::{
    DeferralReason, ObligationClass, ObligationKind, ObservationMode, TerminalEvidence,
};
use fgit_types::{CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, TxId};

fn budget() -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, 128), (Grade::Objects, 2)])
}

fn request() -> RefTransactionRequest {
    // This reserved fixture algorithm slot has no production authority meaning.
    let algorithm = DigestAlgorithmId::try_new(0xfff1).expect("reserved fixture algorithm");
    RefTransactionRequest {
        transaction: TxId::from_digest(
            algorithm,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x31; 32]).expect("fixture digest width"),
        ),
        seal_commitment: [0x42; 32],
    }
}

fn observed(transaction: TxId) -> RefTransactionObserved {
    RefTransactionObserved {
        transaction,
        outcome_commitment: Digest::new(
            DigestAlgorithmId::try_new(0xfff1).expect("reserved fixture algorithm"),
            DigestBytes::try_new(&[0x53; 32]).expect("fixture digest width"),
        ),
    }
}

#[test]
fn either_missing_grade_refuses_and_pre_submission_abort_returns_the_budget() {
    assert_eq!(
        RefTransactionSubmission::REQUIRED_GRADES,
        &[Grade::Bytes, Grade::Objects]
    );
    assert_eq!(
        RefTransactionSubmission::OBSERVATION,
        ObservationMode::ExternallyObserved
    );
    let ledger = ObligationLedger::root(
        RegionId::new(301),
        LeakDisposition::RecordAndContinue,
        budget(),
    );

    for missing in [Grade::Bytes, Grade::Objects] {
        let grant = ledger
            .grant(budget().with(missing, 0))
            .expect("deficient grant fits capacity");
        assert_eq!(
            ledger
                .reserve::<RefTransactionSubmission>(request(), grant)
                .expect_err("submission requires both budget grades"),
            ReserveError::MissingGrade {
                class: ObligationClass::RefTransactionSubmission,
                grade: missing,
            }
        );
        assert_eq!(ledger.snapshot().available(), budget());
        assert!(ledger.snapshot().is_conserved());
    }

    let grant = ledger.grant(budget()).expect("complete grant");
    let reservation = ledger
        .reserve::<RefTransactionSubmission>(request(), grant)
        .expect("both grades present");
    assert_eq!(reservation.reservation(), &request());
    let aborted = RefTransactionAborted {
        reason: NoCandidateReason::Cancelled,
    };
    let settled = reservation.abort_unused(aborted);
    assert_eq!(settled.state(), ObligationState::Aborted);
    match settled.into_evidence() {
        TerminalEvidence::Aborted(receipt) => assert_eq!(receipt, aborted),
        evidence => panic!("pre-submission abort must retain its evidence: {evidence:?}"),
    }
    assert_eq!(ledger.snapshot().available(), budget());
    assert_eq!(ledger.snapshot().consumed(), ResourceVector::ZERO);
    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn submitted_transaction_remains_owned_until_its_outcome_is_observed() {
    let ledger = ObligationLedger::root(
        RegionId::new(302),
        LeakDisposition::RecordAndContinue,
        budget(),
    );
    let handle = ledger.handle();
    let grant = ledger.grant(budget()).expect("complete grant");
    let reservation = ledger
        .reserve::<RefTransactionSubmission>(request(), grant)
        .expect("both grades present");
    let id = reservation.id();
    let submitted = RefTransactionSubmitted {
        transaction: request().transaction,
    };
    let actual = ResourceVector::from_grades(&[(Grade::Bytes, 96), (Grade::Objects, 1)]);
    let committed = reservation
        .commit(submitted, &actual)
        .expect("submission is bounded by its reservation");
    assert_eq!(committed.receipt(), &submitted);
    assert_eq!(handle.state_of(id), Some(ObligationState::Committed));
    assert_eq!(handle.outstanding().len(), 1);

    let pending = committed.defer_acknowledgement(DeferralReason::AwaitingObservation);
    assert_eq!(pending.receipt(), &submitted);
    assert_eq!(
        handle.state_of(id),
        Some(ObligationState::DeferredExternally)
    );
    assert_eq!(handle.outstanding().len(), 1);
    assert_eq!(ledger.snapshot().consumed(), actual);
    assert_eq!(
        ledger.snapshot().available(),
        ResourceVector::from_grades(&[(Grade::Bytes, 32), (Grade::Objects, 1)])
    );
    assert!(ledger.snapshot().is_conserved());

    let observation = observed(submitted.transaction);
    let settled = pending.acknowledge(observation);
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    match settled.into_evidence() {
        TerminalEvidence::Acknowledged(receipt, evidence) => {
            assert_eq!(receipt, submitted);
            assert_eq!(evidence, observation);
        }
        evidence => panic!("observed submission must retain both receipts: {evidence:?}"),
    }
    assert!(handle.outstanding().is_empty());
    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn cancellation_after_start_keeps_unobserved_submission_outstanding_at_close() {
    let ledger = ObligationLedger::root(
        RegionId::new(303),
        LeakDisposition::RecordAndContinue,
        budget(),
    );
    let handle = ledger.handle();
    let grant = ledger.grant(budget()).expect("complete grant");
    let reservation = ledger
        .reserve::<RefTransactionSubmission>(request(), grant)
        .expect("both grades present");
    let id = reservation.id();
    let submitted = RefTransactionSubmitted {
        transaction: request().transaction,
    };
    let pending = reservation
        .commit(submitted, &budget())
        .expect("submission starts within its budget")
        .defer_acknowledgement(DeferralReason::CancelledAfterCommit);
    assert_eq!(pending.receipt().transaction, request().transaction);
    assert_eq!(
        pending.deferral_reason(),
        DeferralReason::CancelledAfterCommit
    );

    match ledger.close() {
        RegionCloseOutcome::ContainmentFailure(failure) => {
            assert_eq!(failure.unsettled().len(), 1);
            let debt = failure
                .unsettled()
                .first()
                .expect("one unresolved submission");
            assert_eq!(debt.id(), id);
            assert_eq!(debt.class(), ObligationClass::RefTransactionSubmission);
            assert_eq!(debt.state(), ObligationState::DeferredExternally);
            assert_eq!(failure.consumed(), budget());
            assert!(
                failure.leaks().is_empty(),
                "live pending custody is not a leak"
            );
            assert_eq!(failure.outstanding_grants(), 0);
            assert_eq!(failure.accounting_faults(), 0);
        }
        outcome => panic!("unknown authority outcome cannot prove quiescence: {outcome:?}"),
    }

    // A later authority observation may still settle the same owned submission;
    // the earlier close report correctly remains a containment failure.
    let settled = pending.acknowledge(observed(submitted.transaction));
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert!(handle.outstanding().is_empty());
    assert!(handle.leaks().is_empty());
}
