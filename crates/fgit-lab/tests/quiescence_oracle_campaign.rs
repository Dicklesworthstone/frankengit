#![forbid(unsafe_code)]
//! Independent consumer campaign for the quiescence oracle.
//!
//! The tests here deliberately never feed `ObligationOracle`: the production
//! close verdict must come from `fgit-resource`'s actual `RegionCloseOutcome`,
//! not from campaign-side bookkeeping that can forget an opening event.

use core::num::NonZeroU32;

use fgit_lab::{LabRefusal, RegionCloseObserver, RegionVerdict, StepId};
use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, AuthorityRevalidation,
    BillingReservation, CasAbortReason, CasAttempt, CasNotPublished, CasWon, ChargeBound,
    ChargeReleased, ChargeReservation, ChargeSettled, CommitmentCheck, ContainmentClass,
    ContextAbortReason, ContextBudgetPermit, ContextPacketComplete, ContextRequest, DecodeOutcome,
    DispatchAbandoned, DispatchAbortReason, DownstreamAck, EffectDispatched, EstimateBasis,
    ExitClass, HeadCasAttempt, LaneSlot, MaterializerProfile, NetworkPolicy, NoCandidateReason,
    ObjectAdmission, ObjectAdmissionPermit, ObjectClass, OutboxDispatch, OutboxEffectPermit,
    PartialContextEvidence, PreparedTxnSlot, RepairAbortReason, RepairNotPublished, RepairPermit,
    RepairPublished, RepairRequest, RetentionAbortReason, RetentionCause, RetentionHeld,
    RetentionNotTaken, RetentionPin, RetentionRequest, RunnerAbortReason, RunnerFinished,
    RunnerNotStarted, RunnerReaped, RunnerRequest, RunnerSlot, SandboxProfile, SecretAbortReason,
    SecretClass, SecretDelivered, SecretGrant, SecretLease, SecretRevoked, SecretWithheld,
    SlotAbandoned, SlotHandedOff, StructureVerdict, WorkspaceAbortReason, WorkspaceLease,
    WorkspacePublished, WorkspaceRequest, WorkspaceTornDown,
};
use fgit_resource::settlement::{
    DeliveryVerdict, DownstreamChannel, DownstreamIdempotency, Observation, ProbeVerdict,
    ReconcileOutcome, ReconcilePlan, ReconcilePolicy, ReconcileState, reconcile,
};
use fgit_resource::twophase::{
    DeferralReason, ExternallyObserved, InternalEffect, ObligationClass, ObligationKind,
};
use fgit_resource::{
    Grade, IdempotencyKey, LeakDisposition, LedgerRecord, LifecycleEvent, ObligationId,
    ObligationLedger, ObligationState, OpaqueHandle, RecordAmounts, RegionCloseOutcome, RegionId,
    ReplayError, ResourceVector, replay_journal,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, EvidenceRecordId,
    GenerationId, GitOid, GitOidSha1, OPAQUE_ID_LEN, ObjectEnvelopeId, OpaqueStoreToken,
    PrincipalId, PrincipalSnapshotId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, SegmentManifestId, TenantId, TxId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is a valid algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest body"),
    )
}

fn envelope(tag: u8) -> ObjectEnvelopeId {
    ObjectEnvelopeId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn head(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn batch(tag: u8) -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn rcr(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn txid(tag: u8) -> TxId {
    TxId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn principal_snapshot(tag: u8) -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn generation(tag: u8) -> GenerationId {
    GenerationId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn evidence_record(tag: u8) -> EvidenceRecordId {
    EvidenceRecordId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

fn segment(tag: u8) -> SegmentManifestId {
    SegmentManifestId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn tenant(tag: u8) -> TenantId {
    TenantId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn oid(tag: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([tag; GitOidSha1::LEN]))
}

fn token(tag: u8) -> OpaqueStoreToken {
    OpaqueStoreToken::try_new(&[tag; 16]).expect("sixteen bytes is a valid version token")
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("twenty bytes is a valid opaque handle")
}

const fn region(value: u64) -> RegionId {
    RegionId::new(value)
}

fn ledger(value: u64) -> ObligationLedger {
    ObligationLedger::root(
        region(value),
        LeakDisposition::RecordAndContinue,
        ResourceVector::single(Grade::Bytes, 4096),
    )
}

fn quiescent_outcome(value: u64) -> RegionCloseOutcome {
    ledger(value).close()
}

fn minimal_budget<K: ObligationKind>() -> ResourceVector {
    let grades: Vec<(Grade, u64)> = K::REQUIRED_GRADES
        .iter()
        .copied()
        .map(|grade| (grade, 1))
        .collect();
    ResourceVector::from_grades(&grades)
}

fn campaign_ledger<K: ObligationKind>(value: u64) -> (ObligationLedger, ResourceVector) {
    let capacity = minimal_budget::<K>();
    (
        ObligationLedger::root(region(value), LeakDisposition::RecordAndContinue, capacity),
        capacity,
    )
}

fn assert_journal_replays_to(
    ledger: &ObligationLedger,
    id: ObligationId,
    expected: ObligationState,
) {
    let journal = ledger.journal();
    assert!(
        !journal.is_empty(),
        "{} must journal its reservation and lifecycle transitions",
        ledger.region()
    );
    assert!(
        journal
            .iter()
            .all(|record| record.region() == ledger.region()),
        "a region journal must not mix evidence from another region"
    );
    let replayed = replay_journal(&journal)
        .unwrap_or_else(|error| panic!("{} journal must replay: {error:?}", ledger.region()));
    assert_eq!(
        replayed.get(&id),
        Some(&expected),
        "replay must reconstruct the actual terminal or explicitly outstanding state"
    );
}

fn assert_journal_replays_only_terminal_states(ledger: &ObligationLedger, class: ObligationClass) {
    let replayed = replay_journal(&ledger.journal())
        .unwrap_or_else(|error| panic!("{class} journal must replay: {error:?}"));
    assert!(
        replayed.values().all(|state| state.is_terminal()),
        "{class} clean cancellation path must leave no replayed live obligation: {replayed:?}"
    );
}

fn assert_quiescent(ledger: ObligationLedger, class: ObligationClass) {
    assert_journal_replays_only_terminal_states(&ledger, class);
    let outcome = ledger.close();
    assert!(
        outcome.is_quiescent(),
        "{class} cancellation path must settle or abort cleanly: {outcome:?}"
    );
}

fn cancel_before_reserve<K: ObligationKind>(value: u64) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let _release = grant.release();
    assert_quiescent(ledger, K::CLASS);
}

fn cancel_after_reserve<K: ObligationKind>(
    value: u64,
    reservation: K::Reservation,
    abort: K::AbortReceipt,
) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reservation must be admitted: {error}", K::CLASS));
    let settled = obligation.abort_unused(abort);
    assert_eq!(settled.class(), K::CLASS);
    assert_eq!(settled.state(), ObligationState::Aborted);
    assert_quiescent(ledger, K::CLASS);
}

fn cancel_after_internal_commit<K: InternalEffect>(
    value: u64,
    reservation: K::Reservation,
    commit: K::CommitReceipt,
) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reservation must be admitted: {error}", K::CLASS));
    let settled = obligation
        .commit_internal(commit, &capacity)
        .unwrap_or_else(|error| panic!("{} commit must settle internally: {error}", K::CLASS));
    assert_eq!(settled.class(), K::CLASS);
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert_quiescent(ledger, K::CLASS);
}

fn cancel_after_external_commit<K: ExternallyObserved>(
    value: u64,
    reservation: K::Reservation,
    commit: K::CommitReceipt,
    acknowledgement: K::AckEvidence,
) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reservation must be admitted: {error}", K::CLASS));
    let id = obligation.id();
    let unacknowledged = obligation
        .commit(commit, &capacity)
        .unwrap_or_else(|error| panic!("{} commit must fit its reservation: {error}", K::CLASS))
        .defer_acknowledgement(DeferralReason::CancelledAfterCommit);

    assert_journal_replays_to(&ledger, id, ObligationState::DeferredExternally);

    let outcome = ledger.close();
    let RegionCloseOutcome::ContainmentFailure(failure) = outcome else {
        panic!(
            "{} must leave cancellation after commit explicitly outstanding",
            K::CLASS
        );
    };
    assert!(
        failure.unsettled().iter().any(|entry| {
            entry.id() == id
                && entry.class() == K::CLASS
                && entry.state() == ObligationState::DeferredExternally
        }),
        "{} must retain the committed-but-unacknowledged effect in close evidence",
        K::CLASS
    );

    let settled = unacknowledged.acknowledge(acknowledgement);
    assert_eq!(settled.state(), ObligationState::Acknowledged);
}

fn cancel_after_external_acknowledgement<K: ExternallyObserved>(
    value: u64,
    reservation: K::Reservation,
    commit: K::CommitReceipt,
    acknowledgement: K::AckEvidence,
) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reservation must be admitted: {error}", K::CLASS));
    let settled = obligation
        .commit(commit, &capacity)
        .unwrap_or_else(|error| panic!("{} commit must fit its reservation: {error}", K::CLASS))
        .acknowledge(acknowledgement);
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert_quiescent(ledger, K::CLASS);
}

fn seeded_reserved_leak_is_caught<K: ObligationKind>(value: u64, reservation: K::Reservation) {
    let (ledger, capacity) = campaign_ledger::<K>(value);
    let grant = ledger
        .grant(capacity)
        .unwrap_or_else(|error| panic!("{} capacity must be grantable: {error}", K::CLASS));
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reservation must be admitted: {error}", K::CLASS));
    let id = obligation.id();
    drop(obligation);

    assert_journal_replays_to(&ledger, id, ObligationState::Leaked);

    let outcome = ledger.close();
    let observer = RegionCloseObserver::new(region(value), 1);
    let verdict = observer
        .close(outcome)
        .unwrap_or_else(|error| panic!("{} close evidence must fold: {error}", K::CLASS));
    assert!(matches!(
        verdict,
        RegionVerdict::ContainmentFailure { leaked, .. } if leaked >= 1
    ));
}

#[test]
fn an_actual_live_grant_cannot_be_hidden_by_campaign_bookkeeping() {
    let ledger = ledger(101);
    let grant = ledger
        .grant(ResourceVector::single(Grade::Bytes, 1))
        .expect("one byte is within the region capacity");

    let outcome = ledger.close();
    assert!(
        !outcome.is_quiescent(),
        "the resource ledger itself records a dropped grant as non-quiescent"
    );

    let observer = RegionCloseObserver::new(region(101), 2);
    let verdict = observer
        .close(outcome)
        .expect("matching resource evidence folds into the lab report");

    assert_eq!(verdict.code(), "containment_failure");
    assert!(!verdict.is_quiescent());
    assert!(matches!(
        verdict,
        RegionVerdict::ContainmentFailure {
            outstanding_grants: 1,
            unsettled: 0,
            escalated: 0,
            leaked: 0,
            accounting_faults: 0,
            ..
        }
    ));

    // The ledger had already emitted the close evidence above. Releasing the
    // grant now avoids letting this test's local value leak past its own scope.
    drop(grant);
}

#[test]
fn bounded_non_cooperation_is_non_passing_after_the_declared_drain_bound() {
    let mut observer = RegionCloseObserver::new(region(102), 2);
    observer.record_task_live(StepId::new("obligation-drain-worker"));
    observer.record_drain_pass();
    observer.record_drain_pass();

    let verdict = observer
        .close(quiescent_outcome(102))
        .expect("the resource ledger and observer refer to the same region");

    assert_eq!(verdict.code(), "bounded_non_cooperative");
    assert!(
        !verdict.is_quiescent(),
        "a typed bounded diagnostic is never a green region close"
    );
    assert!(matches!(
        verdict,
        RegionVerdict::BoundedNonCooperative {
            outstanding: 1,
            passes: 2,
            ..
        }
    ));
}

#[test]
fn live_work_before_the_drain_bound_is_refused_not_mislabeled_as_bounded() {
    let mut incomplete = RegionCloseObserver::new(region(103), 2);
    incomplete.record_task_live(StepId::new("obligation-drain-worker"));
    incomplete.record_drain_pass();

    let refusal = incomplete
        .close(quiescent_outcome(103))
        .expect_err("a drain with passes remaining has no terminal verdict yet");
    assert!(matches!(
        refusal,
        LabRefusal::DrainIncomplete {
            outstanding: 1,
            passes: 1,
            bound: 2,
        }
    ));
    assert_eq!(refusal.code(), "lab.region.drain_incomplete");

    // Near-identical permitted terminal diagnostic: the same live task after
    // the second declared drain pass is honestly bounded, not quiescent.
    let mut bounded = RegionCloseObserver::new(region(104), 2);
    bounded.record_task_live(StepId::new("obligation-drain-worker"));
    bounded.record_drain_pass();
    bounded.record_drain_pass();
    assert!(matches!(
        bounded.close(quiescent_outcome(104)),
        Ok(RegionVerdict::BoundedNonCooperative {
            outstanding: 1,
            passes: 2,
            ..
        })
    ));
}

#[test]
fn settled_tasks_and_released_non_secret_lease_allow_a_quiescent_close() {
    let mut observer = RegionCloseObserver::new(region(105), 2);
    let task = StepId::new("secret-drain-worker");
    let lease_id = "lease-id:secret-delivery-103";
    observer.record_task_live(task.clone());
    observer
        .record_capability_lease(lease_id)
        .expect("a stable non-secret public lease identifier is admitted");
    observer.record_drain_pass();
    observer.record_task_settled(&task);
    observer.record_lease_released(lease_id);
    observer.record_drain_pass();

    let verdict = observer
        .close(quiescent_outcome(105))
        .expect("a complete drain closes cleanly");

    assert!(verdict.is_quiescent());
    assert_eq!(verdict.code(), "quiescent");
}

#[test]
fn a_public_lease_label_refuses_secret_shaped_input_and_accepts_a_stable_identifier() {
    let mut observer = RegionCloseObserver::new(region(106), 1);
    let refusal = observer
        .record_capability_lease("signing-key=ABCD1234")
        .expect_err("a lease label is public receipt data, never credential contents");
    assert!(matches!(refusal, LabRefusal::UnsafeLeaseLabel { .. }));
    assert_eq!(refusal.code(), "lab.region.unsafe_lease_label");

    observer
        .record_capability_lease("secret.delivery.106")
        .expect("a stable public lease identifier is admitted");
    observer.record_lease_released("secret.delivery.106");
    observer.record_drain_pass();
    assert!(
        observer
            .close(quiescent_outcome(106))
            .expect("the admitted public identifier can be released")
            .is_quiescent()
    );
}

#[test]
fn evidence_for_a_different_region_is_refused_instead_of_misclassified() {
    let observer = RegionCloseObserver::new(region(104), 1);
    let refusal = observer
        .close(quiescent_outcome(105))
        .expect_err("cross-region close evidence must not become a verdict");

    assert!(matches!(refusal, LabRefusal::RegionEvidenceMismatch { .. }));
    assert_eq!(refusal.code(), "lab.region.evidence_mismatch");
}

#[test]
fn every_internal_obligation_settles_at_each_real_cancellation_boundary() {
    cancel_before_reserve::<ObjectAdmissionPermit>(201);
    let admission = ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 1,
        staging: envelope(1),
    };
    cancel_after_reserve::<ObjectAdmissionPermit>(
        202,
        admission,
        AdmissionAbandoned {
            reason: AdmissionAbortReason::Cancelled,
        },
    );
    let admission = ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 1,
        staging: envelope(2),
    };
    let admitted =
        AdmittedObject::verified(&admission, oid(3), digest(4), 1, StructureVerdict::Verified)
            .expect("verified admission receipt");
    cancel_after_internal_commit::<ObjectAdmissionPermit>(203, admission, admitted);

    cancel_before_reserve::<PreparedTxnSlot>(204);
    cancel_after_reserve::<PreparedTxnSlot>(
        205,
        LaneSlot {
            lane: 7,
            transaction: txid(5),
        },
        SlotAbandoned {
            reason: NoCandidateReason::Cancelled,
        },
    );
    cancel_after_internal_commit::<PreparedTxnSlot>(
        206,
        LaneSlot {
            lane: 7,
            transaction: txid(6),
        },
        SlotHandedOff {
            batch_attempt: batch(7),
        },
    );

    cancel_before_reserve::<HeadCasAttempt>(207);
    cancel_after_reserve::<HeadCasAttempt>(
        208,
        CasAttempt {
            expected_version: token(8),
            candidate_head: head(9),
            decision_batch: batch(10),
            credential: principal_snapshot(11),
            deadline_micros: 10_000,
        },
        CasNotPublished {
            reason: CasAbortReason::Cancelled,
        },
    );
    cancel_after_internal_commit::<HeadCasAttempt>(
        209,
        CasAttempt {
            expected_version: token(12),
            candidate_head: head(13),
            decision_batch: batch(14),
            credential: principal_snapshot(15),
            deadline_micros: 10_000,
        },
        CasWon {
            winning_version: token(16),
        },
    );

    cancel_before_reserve::<WorkspaceLease>(210);
    cancel_after_reserve::<WorkspaceLease>(
        211,
        WorkspaceRequest {
            overlay: generation(17),
            base_tree: oid(18),
            materializer: MaterializerProfile::SparseCheckout,
        },
        WorkspaceTornDown {
            incomplete_outputs: 0,
            reason: WorkspaceAbortReason::Cancelled,
        },
    );
    cancel_after_internal_commit::<WorkspaceLease>(
        212,
        WorkspaceRequest {
            overlay: generation(19),
            base_tree: oid(20),
            materializer: MaterializerProfile::TreeViewOverlay,
        },
        WorkspacePublished {
            snapshot: generation(21),
            evidence: evidence_record(22),
        },
    );

    cancel_before_reserve::<RetentionPin>(213);
    cancel_after_reserve::<RetentionPin>(
        214,
        RetentionRequest {
            root: envelope(23),
            cause: RetentionCause::ActiveSeal,
        },
        RetentionNotTaken {
            reason: RetentionAbortReason::Cancelled,
        },
    );
    cancel_after_internal_commit::<RetentionPin>(
        215,
        RetentionRequest {
            root: envelope(24),
            cause: RetentionCause::Migration,
        },
        RetentionHeld {
            basis_head: head(25),
        },
    );

    cancel_before_reserve::<RepairPermit>(216);
    cancel_after_reserve::<RepairPermit>(
        217,
        RepairRequest {
            target: segment(26),
            decode_budget_symbols: 8,
            source_symbols: 8,
        },
        RepairNotPublished {
            reason: RepairAbortReason::Cancelled,
        },
    );
    let repair = RepairPublished::verified(
        DecodeOutcome::Succeeded,
        CommitmentCheck::AllVerified,
        AuthorityRevalidation::StillCurrent,
        segment(27),
        head(28),
    )
    .expect("fully verified repair receipt");
    cancel_after_internal_commit::<RepairPermit>(
        218,
        RepairRequest {
            target: segment(27),
            decode_budget_symbols: 8,
            source_symbols: 8,
        },
        repair,
    );

    cancel_before_reserve::<ContextBudgetPermit>(219);
    cancel_after_reserve::<ContextBudgetPermit>(
        220,
        ContextRequest {
            packet: opaque(29),
            authorization_scope: principal_snapshot(30),
            token_ceiling: 512,
        },
        PartialContextEvidence {
            considered: 3,
            included: 1,
            omitted: 1,
            reason: ContextAbortReason::Cancelled,
        },
    );
    let context = ContextPacketComplete::complete(3, 1, 2).expect("complete context receipt");
    cancel_after_internal_commit::<ContextBudgetPermit>(
        221,
        ContextRequest {
            packet: opaque(31),
            authorization_scope: principal_snapshot(32),
            token_ceiling: 512,
        },
        context,
    );
}

#[test]
fn every_external_obligation_records_or_settles_each_real_cancellation_boundary() {
    cancel_before_reserve::<OutboxEffectPermit>(301);
    cancel_after_reserve::<OutboxEffectPermit>(
        302,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(33)),
            precondition_rcr: rcr(34),
            endpoint: opaque(35),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
        DispatchAbandoned {
            reason: DispatchAbortReason::Cancelled,
        },
    );
    cancel_after_external_commit::<OutboxEffectPermit>(
        303,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(36)),
            precondition_rcr: rcr(37),
            endpoint: opaque(38),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
        EffectDispatched { attempt: 1 },
        DownstreamAck {
            receipt: opaque(39),
            attempt: 1,
        },
    );
    cancel_after_external_acknowledgement::<OutboxEffectPermit>(
        304,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(40)),
            precondition_rcr: rcr(41),
            endpoint: opaque(42),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
        EffectDispatched { attempt: 1 },
        DownstreamAck {
            receipt: opaque(43),
            attempt: 1,
        },
    );

    cancel_before_reserve::<SecretLease>(305);
    cancel_after_reserve::<SecretLease>(
        306,
        SecretGrant {
            class: SecretClass::SigningKey,
            consumer: principal(44),
            delivery: opaque(45),
            allowed_effect: ObligationClass::OutboxEffectPermit,
            expires_micros: 60_000,
        },
        SecretWithheld {
            reason: SecretAbortReason::Cancelled,
        },
    );
    cancel_after_external_commit::<SecretLease>(
        307,
        SecretGrant {
            class: SecretClass::RunnerJoin,
            consumer: principal(46),
            delivery: opaque(47),
            allowed_effect: ObligationClass::RunnerSlot,
            expires_micros: 60_000,
        },
        SecretDelivered {
            delivered_micros: 10,
        },
        SecretRevoked {
            revoked_micros: 20,
            drained_consumers: 1,
        },
    );
    cancel_after_external_acknowledgement::<SecretLease>(
        308,
        SecretGrant {
            class: SecretClass::SigningKey,
            consumer: principal(48),
            delivery: opaque(49),
            allowed_effect: ObligationClass::OutboxEffectPermit,
            expires_micros: 60_000,
        },
        SecretDelivered {
            delivered_micros: 10,
        },
        SecretRevoked {
            revoked_micros: 20,
            drained_consumers: 1,
        },
    );

    cancel_before_reserve::<RunnerSlot>(309);
    cancel_after_reserve::<RunnerSlot>(
        310,
        RunnerRequest {
            sandbox: SandboxProfile::ProcessIsolated,
            toolchain: opaque(50),
            network: NetworkPolicy::Denied,
            cache_namespace: opaque(51),
        },
        RunnerNotStarted {
            reason: RunnerAbortReason::Cancelled,
        },
    );
    cancel_after_external_commit::<RunnerSlot>(
        311,
        RunnerRequest {
            sandbox: SandboxProfile::VirtualMachine,
            toolchain: opaque(52),
            network: NetworkPolicy::Allowlisted,
            cache_namespace: opaque(53),
        },
        RunnerFinished {
            exit_class: ExitClass::Cancelled,
            artifacts: 0,
            log_root: evidence_record(54),
        },
        RunnerReaped {
            processes_reaped: 1,
            containment: ContainmentClass::Cooperative,
        },
    );
    cancel_after_external_acknowledgement::<RunnerSlot>(
        312,
        RunnerRequest {
            sandbox: SandboxProfile::ProcessIsolated,
            toolchain: opaque(55),
            network: NetworkPolicy::Denied,
            cache_namespace: opaque(56),
        },
        RunnerFinished {
            exit_class: ExitClass::Cancelled,
            artifacts: 0,
            log_root: evidence_record(57),
        },
        RunnerReaped {
            processes_reaped: 1,
            containment: ContainmentClass::Cooperative,
        },
    );

    cancel_before_reserve::<BillingReservation>(313);
    cancel_after_reserve::<BillingReservation>(
        314,
        ChargeReservation {
            account: tenant(58),
            ceiling_micros: 100,
            estimate_basis: EstimateBasis::Deterministic,
        },
        ChargeReleased {
            released_micros: 100,
        },
    );
    let charge_reservation = ChargeReservation {
        account: tenant(59),
        ceiling_micros: 100,
        estimate_basis: EstimateBasis::Deterministic,
    };
    let charge = ChargeBound::within(&charge_reservation, 100).expect("bounded charge receipt");
    cancel_after_external_commit::<BillingReservation>(
        315,
        charge_reservation,
        charge,
        ChargeSettled {
            processor_receipt: opaque(60),
        },
    );
    let charge_reservation = ChargeReservation {
        account: tenant(61),
        ceiling_micros: 100,
        estimate_basis: EstimateBasis::Deterministic,
    };
    let charge = ChargeBound::within(&charge_reservation, 100).expect("bounded charge receipt");
    cancel_after_external_acknowledgement::<BillingReservation>(
        316,
        charge_reservation,
        charge,
        ChargeSettled {
            processor_receipt: opaque(62),
        },
    );
}

#[test]
fn deliberately_dropped_real_obligations_are_caught_for_every_concrete_class() {
    seeded_reserved_leak_is_caught::<ObjectAdmissionPermit>(
        401,
        ObjectAdmission {
            class: ObjectClass::GitObject,
            declared_len: 1,
            staging: envelope(63),
        },
    );
    seeded_reserved_leak_is_caught::<PreparedTxnSlot>(
        402,
        LaneSlot {
            lane: 3,
            transaction: txid(64),
        },
    );
    seeded_reserved_leak_is_caught::<HeadCasAttempt>(
        403,
        CasAttempt {
            expected_version: token(65),
            candidate_head: head(66),
            decision_batch: batch(67),
            credential: principal_snapshot(68),
            deadline_micros: 10_000,
        },
    );
    seeded_reserved_leak_is_caught::<OutboxEffectPermit>(
        404,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(69)),
            precondition_rcr: rcr(70),
            endpoint: opaque(71),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
    );
    seeded_reserved_leak_is_caught::<SecretLease>(
        405,
        SecretGrant {
            class: SecretClass::SigningKey,
            consumer: principal(72),
            delivery: opaque(73),
            allowed_effect: ObligationClass::OutboxEffectPermit,
            expires_micros: 60_000,
        },
    );
    seeded_reserved_leak_is_caught::<WorkspaceLease>(
        406,
        WorkspaceRequest {
            overlay: generation(74),
            base_tree: oid(75),
            materializer: MaterializerProfile::SparseCheckout,
        },
    );
    seeded_reserved_leak_is_caught::<RunnerSlot>(
        407,
        RunnerRequest {
            sandbox: SandboxProfile::ProcessIsolated,
            toolchain: opaque(76),
            network: NetworkPolicy::Denied,
            cache_namespace: opaque(77),
        },
    );
    seeded_reserved_leak_is_caught::<RetentionPin>(
        408,
        RetentionRequest {
            root: envelope(78),
            cause: RetentionCause::ActiveSeal,
        },
    );
    seeded_reserved_leak_is_caught::<RepairPermit>(
        409,
        RepairRequest {
            target: segment(79),
            decode_budget_symbols: 8,
            source_symbols: 8,
        },
    );
    seeded_reserved_leak_is_caught::<ContextBudgetPermit>(
        410,
        ContextRequest {
            packet: opaque(80),
            authorization_scope: principal_snapshot(81),
            token_ceiling: 512,
        },
    );
    seeded_reserved_leak_is_caught::<BillingReservation>(
        411,
        ChargeReservation {
            account: tenant(82),
            ceiling_micros: 100,
            estimate_basis: EstimateBasis::Deterministic,
        },
    );
}

#[derive(Default)]
struct RetryReceiver {
    keys: Vec<IdempotencyKey>,
    probes: u32,
}

impl DownstreamChannel for RetryReceiver {
    fn deliver(&mut self, key: &IdempotencyKey, attempt: u32) -> DeliveryVerdict {
        self.keys.push(*key);
        match attempt {
            1 => DeliveryVerdict::AmbiguousTimeout,
            2 => DeliveryVerdict::Accepted,
            _ => DeliveryVerdict::TransientFailure,
        }
    }

    fn probe(&mut self, key: &IdempotencyKey) -> ProbeVerdict {
        self.probes = self.probes.saturating_add(1);
        assert_eq!(
            self.keys.last(),
            Some(key),
            "a probe must use the exact key of the ambiguous dispatch"
        );
        ProbeVerdict::NotDelivered
    }
}

#[test]
fn a_committed_but_unacknowledged_effect_retries_under_its_original_key() {
    let (ledger, capacity) = campaign_ledger::<OutboxEffectPermit>(501);
    let key = IdempotencyKey::new(digest(83));
    let grant = ledger
        .grant(capacity)
        .expect("outbox capacity is grantable");
    let reservation = OutboxDispatch {
        idempotency: key,
        precondition_rcr: rcr(84),
        endpoint: opaque(85),
        idempotency_strength: DownstreamIdempotency::Strong,
    };
    let reserved = ledger
        .reserve::<OutboxEffectPermit>(reservation, grant)
        .expect("outbox reservation is admitted");
    let effect_id = reserved.id();
    let effect = reserved
        .commit(EffectDispatched { attempt: 1 }, &capacity)
        .expect("outbox commit fits its reservation")
        .defer_acknowledgement(DeferralReason::CancelledAfterCommit);
    assert_journal_replays_to(&ledger, effect_id, ObligationState::DeferredExternally);
    let mut plan = ReconcilePlan::new(
        key,
        DownstreamIdempotency::Strong,
        ReconcilePolicy::new(NonZeroU32::new(2).expect("two attempts is non-zero")),
    );
    let mut receiver = RetryReceiver::default();

    let outcome = reconcile(effect, &mut plan, &mut receiver, principal(86), |attempt| {
        DownstreamAck {
            receipt: opaque(87),
            attempt,
        }
    });

    assert!(matches!(outcome, ReconcileOutcome::Acknowledged(_)));
    assert_eq!(plan.state(), ReconcileState::Delivered { attempt: 2 });
    assert_eq!(receiver.probes, 1);
    assert_eq!(receiver.keys, vec![key, key]);
    let observed: Vec<Observation> = plan
        .transitions()
        .iter()
        .map(|transition| transition.observation())
        .collect();
    assert_eq!(
        observed,
        vec![
            Observation::Delivery(DeliveryVerdict::AmbiguousTimeout),
            Observation::Probe(ProbeVerdict::NotDelivered),
            Observation::Delivery(DeliveryVerdict::Accepted),
        ],
        "the reconciliation plan probes an ambiguous commit before retrying it"
    );
    assert_quiescent(ledger, ObligationClass::OutboxEffectPermit);
}

#[test]
fn journal_replay_preserves_accounting_and_refuses_a_tampered_transition() {
    let (ledger, capacity) = campaign_ledger::<ObjectAdmissionPermit>(601);
    let grant = ledger
        .grant(capacity)
        .expect("object-admission capacity is grantable");
    let reservation = ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 1,
        staging: envelope(88),
    };
    let reserved = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("object admission is admitted");
    let id = reserved.id();
    let _aborted = reserved.abort_unused(AdmissionAbandoned {
        reason: AdmissionAbortReason::Cancelled,
    });

    let journal = ledger.journal();
    assert_eq!(
        journal.len(),
        2,
        "one reservation and one abort are journalled"
    );
    let opening = journal[0];
    let aborted = journal[1];
    assert_eq!(opening.obligation(), id);
    assert_eq!(opening.class(), ObligationClass::ObjectAdmissionPermit);
    assert_eq!(opening.event(), None);
    assert_eq!(opening.state(), ObligationState::Reserved);
    assert_eq!(opening.reserved(), capacity);
    assert_eq!(opening.charged(), ResourceVector::ZERO);
    assert_eq!(aborted.event(), Some(LifecycleEvent::Abort));
    assert_eq!(aborted.state(), ObligationState::Aborted);
    assert_eq!(aborted.reserved(), ResourceVector::ZERO);
    assert_eq!(aborted.charged(), ResourceVector::ZERO);
    assert_journal_replays_to(&ledger, id, ObligationState::Aborted);

    let tampered = LedgerRecord::new(
        aborted.region(),
        aborted.ordinal(),
        aborted.obligation(),
        aborted.class(),
        aborted.event(),
        ObligationState::Committed,
        RecordAmounts {
            reserved: aborted.reserved(),
            charged: aborted.charged(),
        },
    );
    assert!(matches!(
        replay_journal(&[opening, tampered]),
        Err(ReplayError::StateDisagreement {
            obligation,
            recorded: ObligationState::Committed,
            replayed: ObligationState::Aborted,
        }) if obligation == id
    ));
    assert_quiescent(ledger, ObligationClass::ObjectAdmissionPermit);
}

fn write_campaign_receipt_if_requested() {
    let Some(directory) = std::env::var_os("FGIT_OBLIGATION_CAMPAIGN_ARTIFACT_DIR") else {
        return;
    };
    let receipt_path = std::path::PathBuf::from(directory).join("obligation-quiescence.ndjson");
    const RECEIPT: &str = concat!(
        "{\"schema\":\"fgit.obligation-quiescence.v1\",",
        "\"verdict\":\"quiescent\",",
        "\"obligation_classes\":11,",
        "\"boundaries\":4,",
        "\"seeded_leaks_caught\":true,",
        "\"replay_complete\":true,",
        "\"post_commit_retry_idempotent\":true,",
        "\"unacknowledged_record_observed\":true}\n"
    );
    std::fs::write(&receipt_path, RECEIPT).unwrap_or_else(|error| {
        panic!(
            "the configured FG012b artifact directory must accept the campaign receipt at {}: {error}",
            receipt_path.display()
        )
    });
}

#[test]
fn e2e_receipt_is_written_only_after_the_complete_campaign_passes() {
    an_actual_live_grant_cannot_be_hidden_by_campaign_bookkeeping();
    bounded_non_cooperation_is_non_passing_after_the_declared_drain_bound();
    live_work_before_the_drain_bound_is_refused_not_mislabeled_as_bounded();
    settled_tasks_and_released_non_secret_lease_allow_a_quiescent_close();
    a_public_lease_label_refuses_secret_shaped_input_and_accepts_a_stable_identifier();
    evidence_for_a_different_region_is_refused_instead_of_misclassified();
    every_internal_obligation_settles_at_each_real_cancellation_boundary();
    every_external_obligation_records_or_settles_each_real_cancellation_boundary();
    deliberately_dropped_real_obligations_are_caught_for_every_concrete_class();
    a_committed_but_unacknowledged_effect_retries_under_its_original_key();
    journal_replay_preserves_accounting_and_refuses_a_tampered_transition();
    write_campaign_receipt_if_requested();
}
