//! Evidence that an ill-formed batch and head pair cannot be built, and that
//! one arriving as data is refused with the same vocabulary.
//!
//! Every forbidden case is paired with the near-identical permitted case that
//! proceeds, so the tests show the boundary rather than only the wall.

use fgit_chronicle::{
    ChronicleRefusal, PublicationBasis, PublicationPlan, ResultingRoots, VerifiedPublication,
    batch_identity, repository_commit_identity, verify_pair,
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

fn seal(plan: PublicationPlan, roots: &ResultingRoots) -> VerifiedPublication {
    plan.seal(&CryptoBodyIdentity, *roots)
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
        plan.seal(&CryptoBodyIdentity, refusal_only_roots()),
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
    let second = plan
        .seal(&CryptoBodyIdentity, committed_roots())
        .expect("the successor batch is well formed");
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
        plan.seal(&CryptoBodyIdentity, committed_roots()),
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
        plan.seal(&CryptoBodyIdentity, refusal_only_roots()),
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
