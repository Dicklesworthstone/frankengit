//! Evidence that an ill-formed batch and head pair cannot be built, and that
//! one arriving as data is refused with the same vocabulary.
//!
//! Every forbidden case is paired with the near-identical permitted case that
//! proceeds, so the tests show the boundary rather than only the wall.

use fgit_chronicle::{
    ChronicleRefusal, PublicationBasis, PublicationPlan, ResultingRoots, VerifiedPublication,
    verify_pair,
};
use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecisionBatchBody,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, Digest, DigestAlgorithmId,
    DigestBytes, HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, PrincipalSnapshotId, RefusalCode,
    RefusalRecordId, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, RepositorySequence, TxId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(1).expect("code point one is valid"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("thirty-two bytes is a valid digest"),
        )
    };
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn basis() -> PublicationBasis {
    PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), genesis_head())
}

fn record(tag: u8) -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository(),
        // Overwritten by the plan: a caller may not choose its position.
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, tag),
        principal_snapshot_id: derived!(PrincipalSnapshotId, tag),
        canonical_request_digest: digest(tag),
        ref_delta_root: digest(tag),
        resulting_ref_root: digest(0x30),
        object_closure_root: digest(tag),
        forge_event_batch_root: digest(tag),
        resulting_forge_position_root: digest(0x31),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(tag),
        invariant_evidence_root: digest(tag),
        outbox_effect_root: digest(tag),
        retention_delta_root: digest(tag),
    }
}

fn committed_roots() -> ResultingRoots {
    ResultingRoots {
        ref_root: digest(0x30),
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(0x35),
    }
}

fn refusal_only_roots() -> ResultingRoots {
    ResultingRoots {
        outcome_index_root: digest(0x32),
        batch_evidence_root: digest(0x35),
        ..ResultingRoots::carried_forward(&basis(), digest(0x35))
    }
}

fn seal(plan: PublicationPlan, roots: ResultingRoots) -> VerifiedPublication {
    plan.seal(derived!(RepositoryDecisionBatchId, 0x40), roots)
        .expect("a plan built through the builder is well formed")
}

// ---------------------------------------------------------------------------
// The builder cannot express a malformed pair
// ---------------------------------------------------------------------------

#[test]
fn the_builder_assigns_contiguous_decision_sequence_from_the_basis() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0x50),
        RefusalCode::NonFastForwardRefused,
        derived!(RefusalRecordId, 0x51),
    );
    plan.commit(derived!(RepositoryCommitId, 0x52), record(0x53));
    plan.refuse(
        derived!(TxId, 0x54),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x55),
    );
    let published = seal(plan, committed_roots());
    let batch = published.batch();

    assert_eq!(batch.first_decision_sequence, DecisionSequence::FIRST);
    let positions: Vec<u64> = batch
        .decisions
        .iter()
        .map(|decision| decision.decision_sequence.get())
        .collect();
    assert_eq!(
        positions,
        vec![1, 2, 3],
        "decision sequence is gap-free across refusals and commits alike"
    );
    assert_eq!(
        batch.committed_rcrs.len(),
        1,
        "only the committed decision carries a record"
    );
    assert_eq!(
        batch
            .committed_rcrs
            .first()
            .expect("one record")
            .repository_sequence,
        RepositorySequence::FIRST,
        "repository sequence advances across commits only, so it is still at one"
    );
}

#[test]
fn the_successor_head_binds_the_batch_and_the_predecessor() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(derived!(RepositoryCommitId, 0x60), record(0x61));
    let published = seal(plan, committed_roots());
    let head = published.head();

    assert_eq!(head.predecessor_head_id, Some(basis().id()));
    assert_eq!(
        head.decision_tail_id,
        Some(derived!(RepositoryDecisionBatchId, 0x40))
    );
    assert_eq!(head.latest_decision_sequence, Some(DecisionSequence::FIRST));
    assert_eq!(
        head.latest_repository_sequence,
        Some(RepositorySequence::FIRST)
    );
    assert!(
        head.generation > basis().generation(),
        "the successor generation strictly advances"
    );
    assert_eq!(
        head.configuration_root,
        genesis_head().configuration_root,
        "configuration the batch did not touch is carried forward, not invented"
    );
}

#[test]
fn a_refusal_only_batch_consumes_decision_sequence_and_nothing_else() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0x70),
        RefusalCode::ProtectedRefTransitionDenied,
        derived!(RefusalRecordId, 0x71),
    );
    let published = seal(plan, refusal_only_roots());

    assert!(published.is_refusal_only());
    let head = published.head();
    let previous = genesis_head();
    assert_eq!(head.latest_decision_sequence, Some(DecisionSequence::FIRST));
    assert_eq!(
        head.latest_repository_sequence, None,
        "a refusal does not advance the committed-transition position"
    );
    assert_eq!(head.latest_committed_rcr_id, None);
    assert_eq!(head.ref_root, previous.ref_root, "source root untouched");
    assert_eq!(
        head.forge_position_root, previous.forge_position_root,
        "forge root untouched"
    );
    assert!(published.batch().committed_rcrs.is_empty());
}

#[test]
fn an_empty_plan_refuses_to_seal() {
    let plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    assert!(plan.is_empty());
    assert_eq!(
        plan.seal(
            derived!(RepositoryDecisionBatchId, 0x40),
            refusal_only_roots()
        ),
        Err(ChronicleRefusal::EmptyBatch),
        "a batch that decides nothing consumes no sequence and publishes nothing"
    );
}

#[test]
fn a_second_batch_continues_the_first_without_a_gap() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(derived!(RepositoryCommitId, 0x80), record(0x81));
    plan.refuse(
        derived!(TxId, 0x82),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x83),
    );
    let first = seal(plan, committed_roots());

    let next_basis = PublicationBasis::new(
        derived!(RepositoryAuthorityHeadId, 0x84),
        first.head().clone(),
    );
    let mut plan = PublicationPlan::open(next_basis.clone()).expect("successor basis opens");
    plan.commit(derived!(RepositoryCommitId, 0x85), record(0x86));
    let second = plan
        .seal(derived!(RepositoryDecisionBatchId, 0x87), committed_roots())
        .expect("the successor batch is well formed");

    assert_eq!(
        second.batch().first_decision_sequence.get(),
        3,
        "the second batch starts exactly where the first ended"
    );
    assert_eq!(
        second
            .batch()
            .committed_rcrs
            .first()
            .expect("one record")
            .repository_sequence
            .get(),
        2,
        "repository sequence continues across batches, counting commits only"
    );
    assert_eq!(
        second
            .batch()
            .committed_rcrs
            .first()
            .expect("one record")
            .parent_rcr_id,
        Some(derived!(RepositoryCommitId, 0x80)),
        "the commit chain links to the previous batch's last record"
    );
}

// ---------------------------------------------------------------------------
// A pair arriving as data is refused with the same vocabulary
// ---------------------------------------------------------------------------

fn well_formed_pair() -> (
    PublicationBasis,
    RepositoryDecisionBatchBody,
    RepositoryAuthorityHeadBody,
) {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(derived!(RepositoryCommitId, 0x90), record(0x91));
    let published = seal(plan, committed_roots());
    (basis(), published.batch().clone(), published.head().clone())
}

#[test]
fn a_well_formed_pair_verifies() {
    let (basis, batch, head) = well_formed_pair();
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_decision_sequence_gap_is_refused_and_the_contiguous_twin_is_not() {
    let (basis, mut batch, head) = well_formed_pair();
    batch
        .decisions
        .push(fgit_codec::schema::RepositoryDecision {
            tx_id: derived!(TxId, 0x92),
            // Skips position two.
            decision_sequence: DecisionSequence::try_new(3).expect("three is a valid position"),
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::QuotaExceeded,
                refusal_record_id: derived!(RefusalRecordId, 0x93),
            },
        });
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::DecisionSequenceNotContiguous {
            index: 1,
            expected: DecisionSequence::try_new(2).expect("two is a valid position"),
            observed: DecisionSequence::try_new(3).expect("three is a valid position"),
        }),
        "a gap in the decision sequence is refused, naming the position"
    );

    // Near-identical permitted case: the same appended refusal, in position.
    if let Some(last) = batch.decisions.last_mut() {
        last.decision_sequence = DecisionSequence::try_new(2).expect("two is a valid position");
    }
    let mut head = head;
    head.latest_decision_sequence =
        Some(DecisionSequence::try_new(2).expect("two is a valid position"));
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_batch_prepared_against_another_head_is_refused() {
    let (basis, mut batch, head) = well_formed_pair();
    batch.predecessor_head_id = derived!(RepositoryAuthorityHeadId, 0xA0);
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::PredecessorHeadMismatch)
    );

    // Near-identical permitted case: bound to the basis it was built against.
    batch.predecessor_head_id = basis.id();
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_head_that_does_not_advance_the_generation_is_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.generation = basis.generation();
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::GenerationNotAdvancing {
            predecessor: basis.generation(),
            successor: basis.generation(),
        }),
        "a head that does not strictly advance could roll authority backwards"
    );

    // Near-identical permitted case: one generation later.
    head.generation = basis.successor_generation().expect("generation advances");
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_head_that_names_the_wrong_tail_position_is_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.latest_decision_sequence =
        Some(DecisionSequence::try_new(9).expect("nine is a valid position"));
    assert!(matches!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::DecisionTailSequenceMismatch { .. })
    ));

    head.latest_decision_sequence = Some(DecisionSequence::FIRST);
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_refusal_only_batch_that_moved_the_ref_root_is_refused() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xB0),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xB1),
    );
    let published = seal(plan, refusal_only_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let mut head = published.head().clone();

    // Planted negative: a batch that committed nothing moves the source root.
    batch.resulting_ref_root = digest(0xB2);
    head.ref_root = digest(0xB2);
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_ref_root"
        }),
        "refusals consume decision sequence but never advance the source root"
    );

    // Near-identical permitted case: the same refusal leaving the root alone.
    batch.resulting_ref_root = genesis_head().ref_root;
    head.ref_root = genesis_head().ref_root;
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_batch_and_head_that_disagree_about_a_root_are_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.outbox_root = digest(0xC0);
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "outbox_root"
        }),
        "the head must publish the state the batch resulted in"
    );

    head.outbox_root = batch.resulting_outbox_root;
    assert_eq!(verify_pair(&basis, &batch, &head), Ok(()));
}

#[test]
fn a_commit_record_count_that_disagrees_with_the_decisions_is_refused() {
    let (basis, mut batch, head) = well_formed_pair();
    batch.committed_rcrs.clear();
    assert_eq!(
        verify_pair(&basis, &batch, &head),
        Err(ChronicleRefusal::CommitRecordCountMismatch {
            committed_decisions: 1,
            records: 0,
        }),
        "every committed decision owns exactly one record"
    );
}
