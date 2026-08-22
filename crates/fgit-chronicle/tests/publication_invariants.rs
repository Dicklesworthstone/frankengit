//! Evidence that an ill-formed batch and head pair cannot be built, and that
//! one arriving as data is refused with the same vocabulary.
//!
//! Every forbidden case is paired with the near-identical permitted case that
//! proceeds, so the tests show the boundary rather than only the wall.

use fgit_authority::{
    AuthorityStore, CumulativeOutcomes, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
    collect_cumulative_outcomes, initialize_repository,
};
use fgit_chronicle::{
    ChronicleRefusal, PublicationBasis, PublicationPlan, ResultingRoots, VerifiedPublication,
    batch_evidence_root, batch_identity, repository_commit_identity, verify_pair,
};
use fgit_codec::CryptoBodyIdentity;
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
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

const fn repository() -> RepositoryId {
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
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        policy_epoch: PolicyEpoch::FIRST,
        compaction_generation_link: None,
    }
}

fn refusal_only_roots() -> ResultingRoots {
    ResultingRoots {
        compaction_generation_link: None,
        ..ResultingRoots::carried_forward(&basis())
    }
}

/// Direct constructor tests do not publish their manufactured bases.  This
/// real authority read supplies the same unforgeable cumulative-witness shape
/// production sealing requires, while the dedicated post-stamp test covers a
/// witness and basis from one shared store.
fn fixture_outcomes() -> (CumulativeOutcomes, fgit_authority::AuthorityVersionToken) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5151));
    let head_key = HeadKey::new(b"chronicle/invariants/outcomes".to_vec())
        .expect("fixture head key is admissible");
    initialize_repository(&store, &head_key, &genesis_head()).expect("fixture genesis initializes");
    let receipt = match store.read_head(&head_key).expect("fixture head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("fixture genesis exists"),
    };
    let outcomes =
        collect_cumulative_outcomes(&store, &head_key).expect("fixture outcomes collect");
    (outcomes, receipt.token())
}

fn seal_result(
    plan: PublicationPlan,
    roots: &ResultingRoots,
) -> Result<VerifiedPublication, ChronicleRefusal> {
    let (outcomes, expected) = fixture_outcomes();
    plan.seal(&CryptoBodyIdentity, *roots, &outcomes, expected)
}

fn seal(plan: PublicationPlan, roots: &ResultingRoots) -> VerifiedPublication {
    seal_result(plan, roots).expect("a plan built through the builder is well formed")
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
    plan.commit(record(0x53));
    plan.refuse(
        derived!(TxId, 0x54),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x55),
    );
    let published = seal(plan, &committed_roots());
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
    plan.commit(record(0x61));
    let published = seal(plan, &committed_roots());
    let head = published.head();

    assert_eq!(head.predecessor_head_id, Some(basis().id()));
    assert_eq!(
        head.decision_tail_id,
        Some(
            batch_identity(&CryptoBodyIdentity, published.batch())
                .expect("the batch has an identity")
        ),
        "the head names the batch by its bytes, not by a label the caller chose"
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
    let published = seal(plan, &refusal_only_roots());

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
    assert_eq!(
        published.batch().committed_rcrs,
        [],
        "a refusal-only batch carries no commit record"
    );
}

#[test]
fn an_empty_plan_refuses_to_seal() {
    let plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    assert!(plan.is_empty(), "a freshly opened plan has decided nothing");
    assert_eq!(
        seal_result(plan, &refusal_only_roots()),
        Err(ChronicleRefusal::EmptyBatch),
        "a batch that decides nothing consumes no sequence and publishes nothing"
    );
}

#[test]
fn a_second_batch_continues_the_first_without_a_gap() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(record(0x81));
    plan.refuse(
        derived!(TxId, 0x82),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x83),
    );
    let first = seal(plan, &committed_roots());
    let first_record = first
        .batch()
        .committed_rcrs
        .first()
        .expect("the first batch carries its commit record");
    let first_rcr_id = repository_commit_identity(&CryptoBodyIdentity, first_record)
        .expect("the first record re-identifies from its final bytes");
    assert_eq!(
        first.head().latest_committed_rcr_id,
        Some(first_rcr_id),
        "the first head names the record its batch actually carries"
    );

    let next_basis = PublicationBasis::new(
        derived!(RepositoryAuthorityHeadId, 0x84),
        first.head().clone(),
    );
    let mut plan = PublicationPlan::open(next_basis).expect("successor basis opens");
    plan.commit(record(0x86));
    let second = seal_result(plan, &committed_roots()).expect("the successor batch is well formed");
    let second_record = second
        .batch()
        .committed_rcrs
        .first()
        .expect("the second batch carries its commit record");
    let second_rcr_id = repository_commit_identity(&CryptoBodyIdentity, second_record)
        .expect("the second record re-identifies from its final bytes");

    assert_eq!(
        second.batch().first_decision_sequence.get(),
        3,
        "the second batch starts exactly where the first ended"
    );
    assert_eq!(
        second_record.repository_sequence.get(),
        2,
        "repository sequence continues across batches, counting commits only"
    );
    assert_eq!(
        second_record.parent_rcr_id,
        Some(first_rcr_id),
        "the commit chain links to the previous batch's last record"
    );
    assert_eq!(
        second.head().latest_committed_rcr_id,
        Some(second_rcr_id),
        "the second head names the RCR re-derived from its own batch, not a pre-stamp caller label"
    );
    assert!(matches!(
        second.batch().decisions.first().map(|decision| decision.outcome),
        Some(DecisionOutcome::Committed { repository_commit_id }) if repository_commit_id == second_rcr_id
    ));
}

#[test]
fn an_rcr_identity_binds_the_stamped_sequence_and_predecessor() {
    let first = record(0x87);
    let first_id = repository_commit_identity(&CryptoBodyIdentity, &first)
        .expect("the first stamped record identifies");

    // Near-identical permitted case: an unchanged final record retains its
    // identity, so the check is about the two stamped fields rather than an
    // incidental field in the fixture.
    assert_eq!(
        repository_commit_identity(&CryptoBodyIdentity, &first)
            .expect("the unchanged record identifies"),
        first_id
    );

    let mut different_sequence = first.clone();
    different_sequence.repository_sequence = first
        .repository_sequence
        .next()
        .expect("the first repository sequence has a successor");
    assert_ne!(
        repository_commit_identity(&CryptoBodyIdentity, &different_sequence)
            .expect("the sequence-successor record identifies"),
        first_id,
        "changing the stamped repository sequence alone changes the RCR identity"
    );

    let mut different_parent = first;
    different_parent.parent_rcr_id = Some(first_id);
    assert_ne!(
        repository_commit_identity(&CryptoBodyIdentity, &different_parent)
            .expect("the predecessor-linked record identifies"),
        first_id,
        "changing the stamped predecessor alone changes the RCR identity"
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
    plan.commit(record(0x91));
    let published = seal(plan, &committed_roots());
    (basis(), published.batch().clone(), published.head().clone())
}

#[test]
fn a_well_formed_pair_verifies() {
    let (basis, batch, head) = well_formed_pair();
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_committed_decision_with_a_stale_rcr_identity_is_refused_and_the_reidentified_twin_is_not() {
    let (basis, mut batch, head) = well_formed_pair();
    let expected = repository_commit_identity(
        &CryptoBodyIdentity,
        batch
            .committed_rcrs
            .first()
            .expect("the pair carries one committed record"),
    )
    .expect("the committed record re-identifies");
    batch
        .decisions
        .first_mut()
        .expect("the pair carries the corresponding decision")
        .outcome = DecisionOutcome::Committed {
        repository_commit_id: derived!(RepositoryCommitId, 0x9a),
    };

    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::CommitRecordIdentityMismatch { index: 0 }),
        "a decision may not name an RCR identity that its record's bytes cannot reproduce"
    );

    batch
        .decisions
        .first_mut()
        .expect("the pair carries the corresponding decision")
        .outcome = DecisionOutcome::Committed {
        repository_commit_id: expected,
    };
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "the exact same pair proceeds when the decision names its carried record"
    );
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
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DecisionSequenceNotContiguous {
            index: 1,
            expected: DecisionSequence::try_new(2).expect("two is a valid position"),
            observed: DecisionSequence::try_new(3).expect("three is a valid position"),
        }),
        "a gap in the decision sequence is refused, naming the position"
    );

    // Near-identical permitted case: the same appended refusal, in position.
    // Editing the batch changes its identity, so the head is rebound to the
    // edited bytes. Without that the pair would carry two defects and this
    // would stop being a test about sequence contiguity.
    if let Some(last) = batch.decisions.last_mut() {
        last.decision_sequence = DecisionSequence::try_new(2).expect("two is a valid position");
    }
    batch.batch_evidence_root =
        batch_evidence_root(&batch).expect("the contiguous decision evidence has a canonical root");
    let mut head = head;
    head.latest_decision_sequence =
        Some(DecisionSequence::try_new(2).expect("two is a valid position"));
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_batch_prepared_against_another_head_is_refused() {
    let (basis, mut batch, head) = well_formed_pair();
    batch.predecessor_head_id = derived!(RepositoryAuthorityHeadId, 0xA0);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::PredecessorHeadMismatch)
    );

    // Near-identical permitted case: bound to the basis it was built against.
    batch.predecessor_head_id = basis.id();
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_head_that_does_not_advance_the_generation_is_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.generation = basis.generation();
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::GenerationNotAdvancing {
            predecessor: basis.generation(),
            successor: basis.generation(),
        }),
        "a head that does not strictly advance could roll authority backwards"
    );

    // Near-identical permitted case: one generation later.
    head.generation = basis.successor_generation().expect("generation advances");
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_head_that_names_the_wrong_tail_position_is_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.latest_decision_sequence =
        Some(DecisionSequence::try_new(9).expect("nine is a valid position"));
    assert!(matches!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DecisionTailSequenceMismatch { .. })
    ));

    head.latest_decision_sequence = Some(DecisionSequence::FIRST);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_refusal_only_batch_that_moved_the_ref_root_is_refused() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xB0),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xB1),
    );
    let published = seal(plan, &refusal_only_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let mut head = published.head().clone();

    // Planted negative: a batch that committed nothing moves the source root.
    // The head is rebound to the edited batch so the pair carries exactly one
    // defect and the assertion is about refusal-only semantics, not staleness.
    batch.resulting_ref_root = digest(0xB2);
    head.ref_root = digest(0xB2);
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_ref_root"
        }),
        "refusals consume decision sequence but never advance the source root"
    );

    // Near-identical permitted case: the same refusal leaving the root alone.
    batch.resulting_ref_root = genesis_head().ref_root;
    head.ref_root = genesis_head().ref_root;
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_batch_and_head_that_disagree_about_a_root_are_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    head.outbox_root = digest(0xC0);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "outbox_root"
        }),
        "the head must publish the state the batch resulted in"
    );

    head.outbox_root = batch.resulting_outbox_root;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_commit_record_count_that_disagrees_with_the_decisions_is_refused() {
    let (basis, mut batch, head) = well_formed_pair();
    batch.committed_rcrs.clear();
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::CommitRecordCountMismatch {
            committed_decisions: 1,
            records: 0,
        }),
        "every committed decision owns exactly one record"
    );
}

#[test]
fn a_head_naming_another_batch_is_refused_and_the_bound_twin_is_not() {
    let (basis, batch, mut head) = well_formed_pair();

    // Planted negative: the head names a batch that is not the one it
    // publishes. fgit-authority does not check this — confirmed by its owner —
    // so without this refusal the pair would reach the conditional replacement
    // and become canonical while pointing at somebody else's batch.
    head.decision_tail_id = Some(derived!(RepositoryDecisionBatchId, 0xD0));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DecisionTailMismatch),
        "a head must name the batch whose bytes it publishes"
    );

    // Planted negative: naming no batch at all.
    head.decision_tail_id = None;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DecisionTailNotBound)
    );

    // Near-identical permitted case: the identity recomputed from the batch.
    let rebuilt = {
        let mut plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
        plan.commit(record(0x91));
        seal(plan, &committed_roots())
    };
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, rebuilt.batch(), rebuilt.head()),
        Ok(()),
        "a head built by the plan names the batch the plan built"
    );
    assert!(
        rebuilt.head().decision_tail_id.is_some(),
        "the plan computes the tail identity rather than accepting one"
    );
}

#[test]
fn one_transaction_cannot_be_decided_twice_by_the_builder() {
    // A sealed transaction has at most one terminal decision, ever. Two in one
    // batch would publish both at the same instant, so there would not even be
    // an ordering that let a reader prefer one.
    let reused = derived!(TxId, 0xE0);

    // Planted negative: refused, then committed, under one identity.
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        reused,
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xE1),
    );
    let mut duplicate = record(0xE2);
    duplicate.tx_id = reused;
    plan.commit(duplicate);
    assert_eq!(
        seal_result(plan, &committed_roots()),
        Err(ChronicleRefusal::DuplicateTransaction { index: 1 }),
        "the second decision for one transaction is refused, naming its index"
    );

    // Planted negative: refused twice.
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        reused,
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xE4),
    );
    plan.refuse(
        reused,
        RefusalCode::NonFastForwardRefused,
        derived!(RefusalRecordId, 0xE5),
    );
    assert!(matches!(
        seal_result(plan, &refusal_only_roots()),
        Err(ChronicleRefusal::DuplicateTransaction { .. })
    ));

    // Near-identical permitted case: two DISTINCT transactions, same shapes.
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xE6),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xE7),
    );
    let mut distinct = record(0xE8);
    distinct.tx_id = derived!(TxId, 0xE9);
    plan.commit(distinct);
    let published = seal(plan, &committed_roots());
    assert_eq!(published.batch().decisions.len(), 2);
}

#[test]
fn a_duplicate_transaction_is_refused_in_a_pair_that_arrives_as_data() {
    // The builder is not the only way to make a batch: one can be replayed,
    // recovered, or built straight from fgit-codec, so the checker has to hold
    // the same invariant independently.
    let (basis, mut batch, head) = well_formed_pair();
    let existing = batch
        .decisions
        .first()
        .expect("the pair carries a decision")
        .tx_id;
    batch
        .decisions
        .push(fgit_codec::schema::RepositoryDecision {
            tx_id: existing,
            decision_sequence: DecisionSequence::try_new(2).expect("two is a valid position"),
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::QuotaExceeded,
                refusal_record_id: derived!(RefusalRecordId, 0xEB),
            },
        });
    let mut head = head;
    head.latest_decision_sequence =
        Some(DecisionSequence::try_new(2).expect("two is a valid position"));
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DuplicateTransaction { index: 1 }),
        "a second terminal decision for one transaction is refused on the data path too"
    );

    // Near-identical permitted case: the same appended refusal, distinct id.
    if let Some(last) = batch.decisions.last_mut() {
        last.tx_id = derived!(TxId, 0xEC);
    }
    batch.batch_evidence_root = batch_evidence_root(&batch)
        .expect("the distinct-transaction evidence has a canonical root");
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_committed_decision_bound_to_another_transaction_is_refused_and_the_matching_twin_is_not() {
    // `ChronicleRefusal::CommitRecordNotBound` had no test at all, and after
    // 9aeaa53 it is producible from exactly one place: `verify_pair`, the path
    // that validates a batch arriving as DATA rather than one we sealed
    // ourselves. Sealing can no longer produce it, because
    // `PlannedOutcome::Committed` now owns its record and there is no parallel
    // vector to desynchronise — which is the right fix, and which also makes
    // this the only remaining producer. An unexercised refusal on the
    // untrusted-input path is a §5.2 terminal non-pass.
    //
    // Of the three construction sites in `audit.rs`, only `:221` is reachable:
    // `:219` cannot fire because the count check above the loop already pins
    // `committed.len() == committed_rcrs.len()`, and `:224` cannot fire because
    // `committed` is filtered to `Committed` outcomes and `commit_id_of`
    // returns `None` only for `Refused`. So this is the one axis worth a case,
    // not three.
    let (basis, mut batch, head) = well_formed_pair();

    // The decision and the record it is paired with must name the SAME
    // transaction. Point the decision at a different one and nothing else.
    batch
        .decisions
        .first_mut()
        .expect("the pair carries one committed decision")
        .tx_id = derived!(TxId, 0xC1);

    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::CommitRecordNotBound { index: 0 }),
        "a committed decision may not be paired with a record from a different transaction: the \
         decision would publish an outcome for a transaction whose bytes it does not carry"
    );

    // The near-identical permitted case: restore the binding and the same pair
    // verifies, so the refusal above is about the transaction binding rather
    // than anything else the mutation disturbed.
    let bound = batch
        .committed_rcrs
        .first()
        .expect("the pair carries one committed record")
        .tx_id;
    batch
        .decisions
        .first_mut()
        .expect("the pair carries one committed decision")
        .tx_id = bound;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "the pair is otherwise well formed, so the refusal must be specific to the binding"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

// ---------------------------------------------------------------------------
// Refusals on the batch-as-data path that had no presence case
// ---------------------------------------------------------------------------
//
// These four ChronicleRefusal variants are constructed only in audit.rs, on the
// path that validates a pair arriving as DATA rather than one we sealed. Each
// had zero test occurrences. An unexercised refusal on the untrusted-input path
// is a section 5.2 terminal non-pass, and these are the checks standing between
// a forged pair and acceptance.
//
// Every case mutates exactly one field of a well-formed pair and restores it, so
// the refusal is shown to be specific to that field rather than to anything the
// mutation disturbed in passing.

#[test]
fn each_half_of_the_repository_binding_is_checked_independently() {
    // The guard is a DISJUNCTION -- batch != head OR batch != basis -- and a
    // single mutation of batch.repository_id trips both at once, so it cannot
    // tell either clause from the other. Mutation testing proved that: disabling
    // the first clause left this passing, because the second still fired.
    //
    // So each clause gets a case that only IT can catch.
    let other = RepositoryId::from_bytes([9; OPAQUE_ID_LEN]);

    // Clause one alone: batch still agrees with the basis, but not with the head.
    let (basis, batch, mut head) = well_formed_pair();
    head.repository_id = other;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RepositoryMismatch),
        "a batch and the head it publishes must name the same repository"
    );

    // Clause two alone: batch and head agree with each other, and neither with
    // the basis. The first clause is false here, so only the second can catch it.
    let (basis, mut batch, mut head) = well_formed_pair();
    batch.repository_id = other;
    head.repository_id = other;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RepositoryMismatch),
        "a self-consistent pair may not publish into a repository its basis does not name: \
         agreement between batch and head is not authority"
    );

    // The permitted twin: untouched, the same pair verifies.
    let (basis, batch, head) = well_formed_pair();
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "both refusals above are about the repository binding, not the fixture"
    );
}

#[test]
fn a_batch_built_on_the_wrong_predecessor_generation_is_refused_and_its_twin_is_not() {
    let (basis, mut batch, head) = well_formed_pair();
    let wrong = HeadGeneration::try_new(2).expect("two is a valid generation");
    batch.predecessor_head_generation = wrong;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::PredecessorGenerationMismatch {
            expected: HeadGeneration::FIRST,
            observed: wrong,
        }),
        "the generation a batch claims to extend must be the generation its basis was read at, \
         or a batch built on a stale head could publish over a newer one"
    );

    batch.predecessor_head_generation = HeadGeneration::FIRST;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "the refusal is specific to the generation, not to the predecessor binding as a whole"
    );
}

#[test]
fn a_batch_that_does_not_open_at_the_next_decision_position_is_refused_and_its_twin_is_not() {
    let (basis, mut batch, head) = well_formed_pair();
    let gap = DecisionSequence::try_new(2).expect("two is a valid position");
    batch.first_decision_sequence = gap;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::DecisionSequenceNotContinuing {
            expected: DecisionSequence::FIRST,
            observed: gap,
        }),
        "a batch that opens past the next free position would leave a hole in the decision \
         order that no later batch can fill"
    );

    batch.first_decision_sequence = DecisionSequence::FIRST;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_committed_record_naming_the_wrong_predecessor_is_refused_and_its_twin_is_not() {
    // The parent check sits BEFORE the identity check in the same loop, so this
    // reaches CommitRecordParentBroken rather than CommitRecordIdentityMismatch
    // even though changing the parent also changes the record's identity. That
    // ordering is the point: a broken chain is reported as a broken chain.
    let (basis, mut batch, head) = well_formed_pair();
    let original = batch
        .committed_rcrs
        .first()
        .expect("the pair carries one committed record")
        .parent_rcr_id;
    batch
        .committed_rcrs
        .first_mut()
        .expect("the pair carries one committed record")
        .parent_rcr_id = Some(derived!(RepositoryCommitId, 0x77));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::CommitRecordParentBroken { index: 0 }),
        "the first record of a genesis batch has no predecessor; naming one forges a chain link"
    );

    batch
        .committed_rcrs
        .first_mut()
        .expect("the pair carries one committed record")
        .parent_rcr_id = original;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "restoring the predecessor leaves the pair verifiable"
    );
}

#[test]
fn a_successor_head_not_bound_to_its_predecessor_is_refused_and_the_bound_twin_is_not() {
    // The head must name the exact basis it was built on. Without this a head
    // carrying a valid batch could be re-parented onto a different predecessor
    // and still look internally consistent, which is the shape section 5.1
    // exists to forbid: only replacement of the EXACT predecessor publishes.
    let (basis, batch, mut head) = well_formed_pair();
    head.predecessor_head_id = Some(derived!(RepositoryAuthorityHeadId, 0x66));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::SuccessorPredecessorNotBound),
        "a successor naming a predecessor other than its basis is not a successor to it"
    );

    // The absent case is the same refusal, not a different one: a head that
    // names NO predecessor is equally unbound, and a check written as
    // `is_some()` rather than an equality would let it through.
    head.predecessor_head_id = None;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::SuccessorPredecessorNotBound),
        "a head naming no predecessor at all is unbound in the same way"
    );

    head.predecessor_head_id = Some(basis.id());
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "restoring the exact predecessor leaves the pair verifiable"
    );
}

#[test]
fn a_head_naming_the_wrong_latest_record_is_refused_and_the_matching_twin_is_not() {
    // The head's latest_committed_rcr_id must be the identity the batch's own
    // last record derives to. This is the field a reader follows to walk the
    // chain backwards, so a head that names a plausible-but-wrong record sends
    // every later reader down a chain the batch never published.
    let (basis, batch, mut head) = well_formed_pair();
    let bound = head.latest_committed_rcr_id;
    assert!(
        bound.is_some(),
        "the fixture must publish a committed record, or this proves nothing"
    );

    head.latest_committed_rcr_id = Some(derived!(RepositoryCommitId, 0x67));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::LatestCommittedRecordMismatch),
        "the head's latest record must be the one the batch actually committed"
    );

    // And dropping it entirely is the same refusal: a head that forgets its
    // latest record is as wrong as one that misnames it.
    head.latest_committed_rcr_id = None;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::LatestCommittedRecordMismatch),
        "a head that names no latest record after a committing batch is also a mismatch"
    );

    head.latest_committed_rcr_id = bound;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_batch_not_opening_at_the_next_repository_position_is_refused_and_its_twin_is_not() {
    // The repository sequence is the committed-only order, distinct from the
    // decision order that includes refusals. A batch whose first record does
    // not open at the next free repository position would leave a hole no later
    // batch can fill, exactly as with the decision sequence.
    let (basis, mut batch, head) = well_formed_pair();
    let gap = RepositorySequence::try_new(2).expect("two is a valid repository position");
    batch
        .committed_rcrs
        .first_mut()
        .expect("the pair carries one committed record")
        .repository_sequence = gap;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RepositorySequenceNotContinuing {
            expected: RepositorySequence::FIRST,
            observed: gap,
        }),
        "the first committed record of a genesis batch must occupy the first repository position"
    );

    batch
        .committed_rcrs
        .first_mut()
        .expect("the pair carries one committed record")
        .repository_sequence = RepositorySequence::FIRST;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "the refusal is specific to the position, not to the record"
    );
}

#[test]
fn a_second_committed_record_that_skips_a_repository_position_is_refused_and_its_twin_is_not() {
    // The repository-sequence guard has TWO arms in the same loop, and only the
    // first was covered:
    //
    //   index == 0 && sequence != open   -> RepositorySequenceNotContinuing
    //   sequence != expected             -> RepositorySequenceNotContiguous
    //
    // The first arm only ever sees the opening record, so a batch with one
    // committed record -- which is what every other case here builds -- cannot
    // reach the second arm at all. Removing the contiguity check entirely would
    // leave every existing test green.
    //
    // So this builds a TWO-record batch and skips the second position. The
    // contiguity check sits before both the parent check and the identity
    // check, so a wrong sequence is reported as a wrong sequence rather than as
    // the identity mismatch it also causes.
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(record(0x71));
    plan.commit(record(0x72));
    let published = seal(plan, &committed_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let head = published.head().clone();
    assert_eq!(
        batch.committed_rcrs.len(),
        2,
        "the fixture must publish two records or the second arm is unreachable"
    );

    let skipped = RepositorySequence::try_new(3).expect("three is a valid repository position");
    batch
        .committed_rcrs
        .get_mut(1)
        .expect("the batch carries a second record")
        .repository_sequence = skipped;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RepositorySequenceNotContiguous {
            index: 1,
            expected: RepositorySequence::try_new(2).expect("two follows one"),
            observed: skipped,
        }),
        "the second committed record must occupy the position immediately after the first; a \
         skipped position leaves a hole in the committed-only order that no later batch can fill"
    );

    // The permitted twin: restoring the position leaves the same two-record
    // pair verifiable, so the refusal is about contiguity rather than about
    // second records being rejected generally.
    batch
        .committed_rcrs
        .get_mut(1)
        .expect("the batch carries a second record")
        .repository_sequence = RepositorySequence::try_new(2).expect("two follows one");
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "a contiguous two-record batch verifies"
    );
}

#[test]
fn each_exhausted_counter_refuses_under_its_own_name_and_stops_one_short() {
    // SequenceExhausted had no test, and it is a THREE-axis refusal: three
    // separate counters reach it, each supplying its own `counter` label.
    //
    //   origin.rs:59   open_decision_sequence    -> "decision sequence"
    //   origin.rs:73   open_repository_sequence  -> "repository sequence"
    //   origin.rs:85   successor_generation      -> "head generation"
    //
    // The label is the whole diagnostic value: an operator reading a refusal
    // needs to know WHICH counter ran out, because the three have entirely
    // different consequences. Three near-identical `map_err` closures is
    // exactly the shape a copy-paste mislabels, and a single-axis test would
    // pass with two of the three naming the wrong counter.
    //
    // Each axis is paired with its own boundary twin at MAX - 1, which must
    // succeed. Without the twin these assert only that a saturated counter
    // refuses, not that an unsaturated one still advances.
    let last = u64::MAX;
    let penultimate = u64::MAX - 1;

    // Axis one: the decision order, which counts refusals as well as commits.
    let mut body = genesis_head();
    body.latest_decision_sequence =
        Some(DecisionSequence::try_new(last).expect("the last position is a valid counter"));
    let exhausted = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        exhausted.open_decision_sequence(),
        Err(ChronicleRefusal::SequenceExhausted {
            counter: "decision sequence",
        })
    );

    let mut body = genesis_head();
    body.latest_decision_sequence =
        Some(DecisionSequence::try_new(penultimate).expect("a valid counter"));
    let room = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        room.open_decision_sequence(),
        Ok(DecisionSequence::try_new(last).expect("a valid counter")),
        "one position short of the ceiling must still open"
    );

    // Axis two: the committed-only order, a different counter with a different
    // label, reached through a different accessor.
    let mut body = genesis_head();
    body.latest_repository_sequence =
        Some(RepositorySequence::try_new(last).expect("a valid counter"));
    let exhausted = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        exhausted.open_repository_sequence(),
        Err(ChronicleRefusal::SequenceExhausted {
            counter: "repository sequence",
        })
    );

    let mut body = genesis_head();
    body.latest_repository_sequence =
        Some(RepositorySequence::try_new(penultimate).expect("a valid counter"));
    let room = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        room.open_repository_sequence(),
        Ok(RepositorySequence::try_new(last).expect("a valid counter"))
    );

    // Axis three: the head generation, which is not optional -- it always has a
    // value -- so it exhausts by reaching the ceiling rather than by carrying a
    // saturated predecessor.
    let mut body = genesis_head();
    body.generation = HeadGeneration::try_new(last).expect("a valid counter");
    let exhausted = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        exhausted.successor_generation(),
        Err(ChronicleRefusal::SequenceExhausted {
            counter: "head generation",
        })
    );

    let mut body = genesis_head();
    body.generation = HeadGeneration::try_new(penultimate).expect("a valid counter");
    let room = PublicationBasis::new(derived!(RepositoryAuthorityHeadId, 0x20), body);
    assert_eq!(
        room.successor_generation(),
        Ok(HeadGeneration::try_new(last).expect("a valid counter")),
        "a head one generation short of the ceiling can still be succeeded"
    );
}

/// A [`BodyIdentity`] that refuses everything, so the identity-unavailable arms
/// become reachable.
///
/// These arms map an identity failure into a chronicle refusal, and the failure
/// they map cannot be produced with the real `CryptoBodyIdentity` for a
/// well-formed body -- the domains are registered and the bodies encode. The
/// trait is public and generic, though, so the failure path belongs to the
/// caller's identity rather than to the body, and this reaches it honestly
/// rather than by contriving an unencodable body.
struct RefusingIdentity;

impl fgit_codec::BodyIdentity for RefusingIdentity {
    fn identify(
        &self,
        _domain: fgit_types::DomainTag,
        _schema: fgit_types::SchemaId,
        _codec_version: fgit_types::numeric::CodecVersion,
        _canonical_body: &[u8],
    ) -> Result<fgit_types::identity::InternalObjectId, fgit_codec::CodecRefusal> {
        Err(fgit_codec::CodecRefusal::MagicUnrecognized { observed: *b"NOPE" })
    }
}

#[test]
fn an_unavailable_identity_is_reported_against_the_body_that_needed_it() {
    // `batch_identity` and `repository_commit_identity` sit four lines apart in
    // audit.rs and differ only in which refusal their `map_err` closure names:
    //
    //   audit.rs:77   body_id(identity, batch)  -> BatchIdentityUnavailable
    //   audit.rs:95   body_id(identity, record) -> CommitRecordIdentityUnavailable
    //
    // Neither had a test, and swapping the two closures would compile, keep
    // both functions refusing, and tell an operator that the batch's identity
    // was unavailable when it was the record's. That is the same copy-paste
    // shape as the three SequenceExhausted labels, and it is why both arms are
    // asserted here rather than one standing in for the other.
    let (_, batch, _) = well_formed_pair();
    let record = batch
        .committed_rcrs
        .first()
        .expect("the pair carries one committed record");

    assert_eq!(
        batch_identity(&RefusingIdentity, &batch),
        Err(ChronicleRefusal::BatchIdentityUnavailable),
        "a batch whose identity cannot be produced must be named as the batch"
    );
    assert_eq!(
        repository_commit_identity(&RefusingIdentity, record),
        Err(ChronicleRefusal::CommitRecordIdentityUnavailable),
        "a record whose identity cannot be produced must be named as the record"
    );

    // The permitted twins, which are what make the two assertions above about
    // the LABEL rather than about refusing in general: the same batch and the
    // same record identify cleanly under the real identity.
    assert!(
        batch_identity(&CryptoBodyIdentity, &batch).is_ok(),
        "the fixture batch identifies under the real identity"
    );
    assert!(
        repository_commit_identity(&CryptoBodyIdentity, record).is_ok(),
        "the fixture record identifies under the real identity"
    );
}

// ---------------------------------------------------------------------------
// verify_refusal_only freezes four roots, and leaves a fifth deliberately free
// ---------------------------------------------------------------------------

#[test]
fn a_refusal_only_batch_that_moved_the_forge_position_root_is_refused() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xD0),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xD1),
    );
    let published = seal(plan, &refusal_only_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let mut head = published.head().clone();

    // Planted negative: a batch that committed nothing moves the forge position.
    // The head is rebound to the edited batch so the pair carries exactly one
    // defect and the assertion is about refusal-only semantics, not staleness.
    batch.resulting_forge_position_root = digest(0xD2);
    head.forge_position_root = digest(0xD2);
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_forge_position_root"
        }),
        "refusals consume decision sequence but never advance the forge position"
    );

    // Near-identical permitted case: the same refusal leaving the root alone.
    batch.resulting_forge_position_root = genesis_head().forge_position_root;
    head.forge_position_root = genesis_head().forge_position_root;
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_refusal_only_batch_that_moved_the_retention_root_is_refused() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xD3),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xD4),
    );
    let published = seal(plan, &refusal_only_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let mut head = published.head().clone();

    // Planted negative: retention is committed state, so a refusal cannot move
    // it even though nothing was committed.
    batch.resulting_retention_root = digest(0xD5);
    head.retention_root = digest(0xD5);
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_retention_root"
        }),
        "a refusal cannot advance retention state"
    );

    // Near-identical permitted case.
    batch.resulting_retention_root = genesis_head().retention_root;
    head.retention_root = genesis_head().retention_root;
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn a_refusal_only_batch_that_moved_the_outbox_root_is_refused() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xD6),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xD7),
    );
    let published = seal(plan, &refusal_only_roots());
    let basis = basis();
    let mut batch = published.batch().clone();
    let mut head = published.head().clone();

    // Planted negative: an outbox obligation is an externally observed effect,
    // so a batch that committed nothing may not create one.
    batch.resulting_outbox_root = digest(0xD8);
    head.outbox_root = digest(0xD8);
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_outbox_root"
        }),
        "a refusal cannot create an external-effect obligation"
    );

    // Near-identical permitted case.
    batch.resulting_outbox_root = genesis_head().outbox_root;
    head.outbox_root = genesis_head().outbox_root;
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("the batch has an identity"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

/// The omission is the point. `verify_refusal_only` freezes four roots and
/// leaves `outcome_index_root` free, which matches the normative contract
/// exactly: "Refusals consume decision sequence but do not advance repository
/// sequence or source/forge roots" (`NORMATIVE_PROTOCOL_CONTRACTS.md` line 285).
/// The outcome index is absent from that list and must be, because refusals
/// ARE outcome-index entries -- a refusal-only batch is precisely the batch
/// whose index has to move.
///
/// The three tests above pin the four frozen roots. This one pins the fifth as
/// deliberately free, with every frozen root held at the predecessor's value so
/// the outcome index is the only field that differs. Without it, a fifth entry
/// added to the `unchanged` array would still fail tests, but would fail them
/// as an unexplained break somewhere else rather than here.
#[test]
fn a_refusal_only_batch_may_advance_the_outcome_index_root_alone() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xE0),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xE1),
    );
    let published = seal(plan, &refusal_only_roots());
    let basis = basis();
    let batch = published.batch().clone();
    let head = published.head().clone();
    let previous = genesis_head();

    // Isolate the variable: every root the contract freezes stays put.
    assert_eq!(batch.resulting_ref_root, previous.ref_root);
    assert_eq!(
        batch.resulting_forge_position_root,
        previous.forge_position_root
    );
    assert_eq!(batch.resulting_retention_root, previous.retention_root);
    assert_eq!(batch.resulting_outbox_root, previous.outbox_root);

    // And the index genuinely moves, so a pass here is not vacuous.
    assert_ne!(
        batch.resulting_outcome_index_root, previous.outcome_index_root,
        "the fixture must actually advance the index or this test proves nothing"
    );

    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(()),
        "a refusal-only batch may advance the outcome index: refusals are entries in it"
    );
}

// ---------------------------------------------------------------------------
// verify_roots is an array of six pairs, and a wrong entry is invisible until
// every axis is probed under its own name
// ---------------------------------------------------------------------------

/// `verify_roots` compares six fields and returns the first disagreement under
/// a `&'static str` label. Two defects live in that shape and neither is caught
/// by testing one axis: a missing entry silently permits a root to disagree,
/// and a mislabelled entry -- the retention comparison reported as
/// `"outbox_root"`, say -- sends a reader to the wrong field. Walking every
/// axis and asserting the exact label closes both.
///
/// Each axis is restored before the next is planted, so exactly one pair
/// disagrees at a time and the guard cannot pass by short-circuiting on an
/// earlier failure.
#[test]
fn every_axis_of_the_resulting_root_agreement_is_checked_under_its_own_name() {
    let (basis, batch, mut head) = well_formed_pair();

    // Axis one: the source root.
    head.ref_root = digest(0xF0);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch { field: "ref_root" }),
        "the head must publish the ref state the batch resulted in"
    );
    head.ref_root = batch.resulting_ref_root;

    // Axis two: the forge position.
    head.forge_position_root = digest(0xF1);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "forge_position_root"
        }),
        "the head must publish the forge position the batch resulted in"
    );
    head.forge_position_root = batch.resulting_forge_position_root;

    // Axis three: the outcome index. This is the axis a derived cumulative
    // root would have to satisfy, so it is the one that must be exercised
    // rather than assumed.
    head.outcome_index_root = digest(0xF2);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "outcome_index_root"
        }),
        "the head must publish the outcome index the batch resulted in"
    );
    head.outcome_index_root = batch.resulting_outcome_index_root;

    // Axis four: retention.
    head.retention_root = digest(0xF3);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "retention_root"
        }),
        "the head must publish the retention state the batch resulted in"
    );
    head.retention_root = batch.resulting_retention_root;

    // Axis five: the outbox.
    head.outbox_root = digest(0xF4);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "outbox_root"
        }),
        "the head must publish the outbox state the batch resulted in"
    );
    head.outbox_root = batch.resulting_outbox_root;

    // Axis six: the policy epoch, which is a counter rather than a root and so
    // is the entry most easily left out of a root-shaped array.
    head.policy_epoch = PolicyEpoch::try_new(2).expect("two is a valid epoch");
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "policy_epoch"
        }),
        "the head must publish the policy epoch the batch resulted in"
    );
    head.policy_epoch = batch.resulting_policy_epoch;

    // Permitted twin: with every axis restored the same pair verifies, so each
    // refusal above was caused by the planted field and not by the walk.
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

/// `verify_successor` reports a misreported committed-order position through
/// the same `ResultingRootMismatch` vocabulary as the root array, under the
/// label `"latest_repository_sequence"`. It is the only non-root field routed
/// that way, which is exactly why nothing reached it: a reader scanning for
/// root names does not look for a sequence there.
#[test]
fn a_head_that_misreports_the_latest_repository_sequence_is_refused() {
    let (basis, batch, mut head) = well_formed_pair();
    let committed = batch
        .committed_rcrs
        .last()
        .expect("well_formed_pair commits one record")
        .repository_sequence;

    // Planted negative: the head claims a position the batch did not reach.
    head.latest_repository_sequence =
        Some(RepositorySequence::try_new(2).expect("two is a valid position"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "latest_repository_sequence"
        }),
        "the head must publish the committed position the batch actually reached"
    );

    // Second axis of the same clause: absence is a mismatch too, not a wildcard.
    head.latest_repository_sequence = None;
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Err(ChronicleRefusal::ResultingRootMismatch {
            field: "latest_repository_sequence"
        }),
        "a head that reports no committed position at all is refused, not excused"
    );

    // Near-identical permitted case: the position the batch did reach.
    head.latest_repository_sequence = Some(committed);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &head),
        Ok(())
    );
}

#[test]
fn batch_evidence_root_commits_the_stamped_commit_evidence() {
    let mut plan = PublicationPlan::open(basis()).expect("genesis basis opens");
    plan.commit(record(0xD1));
    let publication = seal(plan, &committed_roots());

    let canonical = batch_evidence_root(publication.batch())
        .expect("the sealed batch carries encodable decision evidence");
    assert_eq!(
        publication.batch().batch_evidence_root,
        canonical,
        "seal derives rather than accepts the batch evidence root"
    );

    let mut evidence_mutated = publication.batch().clone();
    evidence_mutated
        .committed_rcrs
        .first_mut()
        .expect("the committed decision has one RCR")
        .policy_decision_root = digest(0xD2);
    assert_ne!(
        batch_evidence_root(&evidence_mutated)
            .expect("changing evidence leaves a well-shaped commitment input"),
        canonical,
        "a per-decision evidence mutation cannot retain the original batch root"
    );
}

#[test]
fn received_batch_with_mutated_refusal_evidence_is_refused() {
    let basis = basis();
    let mut plan = PublicationPlan::open(basis.clone()).expect("genesis basis opens");
    plan.refuse(
        derived!(TxId, 0xD3),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0xD4),
    );
    let publication = seal(plan, &refusal_only_roots());
    let mut evidence_mutated = publication.batch().clone();
    match &mut evidence_mutated
        .decisions
        .first_mut()
        .expect("the batch has one refusal decision")
        .outcome
    {
        DecisionOutcome::Refused {
            refusal_record_id, ..
        } => *refusal_record_id = derived!(RefusalRecordId, 0xD5),
        DecisionOutcome::Committed { .. } => panic!("the plan recorded a refusal"),
    }

    assert_eq!(
        verify_pair(
            &CryptoBodyIdentity,
            &basis,
            &evidence_mutated,
            publication.head(),
        ),
        Err(ChronicleRefusal::BatchEvidenceRootMismatch),
        "a received batch cannot retain its root after its refusal evidence changes"
    );
}
