//! The terminal-outcome index, its recovery path, and the fail-closed rule.
//!
//! §8.4 makes the index an accelerator rather than a second truth. That claim
//! is only worth anything if both paths are exercised against the same corpus
//! and if a disagreement is proven to fail closed rather than pick a side.

use fgit_authority::{
    AuthorityStore, CasOutcome, HeadKey, HeadRead, MemoryAuthorityStore, OutcomeFailure,
    OutcomeLookup, PublicationOutcome, StoreInstanceId, TerminalOutcome, body_key,
    canonical_body_id, indexed_outcome, initialize_repository, outcome_key, publish_decisions,
    replay_outcome, resolve_outcome,
};
use fgit_codec::wire::encode_body;
use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{
    RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TenantId, TxId,
};
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode};

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

fn head_slot() -> HeadKey {
    HeadKey::new(b"fg/head/v1/repo-22".to_vec()).expect("an admissible head key")
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn tx(byte: u8) -> TxId {
    TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn commit_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn refusal_id(byte: u8) -> RefusalRecordId {
    RefusalRecordId::from_digest(
        IdentityDomain::RefusalRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
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
        ref_root: digest(0),
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root: digest(0),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_id_of(head: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryAuthorityHead,
            CANONICAL_CODEC_VERSION,
            head,
        )
        .expect("a derivable identity"),
    )
    .expect("the authority-head domain")
}

fn batch_id_of(batch: &RepositoryDecisionBatchBody) -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryDecisionBatch,
            CANONICAL_CODEC_VERSION,
            batch,
        )
        .expect("a derivable identity"),
    )
    .expect("the decision-batch domain")
}

fn batch(
    predecessor: &RepositoryAuthorityHeadBody,
    first_sequence: u64,
    decisions: Vec<RepositoryDecision>,
) -> RepositoryDecisionBatchBody {
    RepositoryDecisionBatchBody {
        repository_id: repository(),
        predecessor_head_id: head_id_of(predecessor),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::try_new(first_sequence).expect("positive"),
        decisions,
        committed_rcrs: Vec::new(),
        resulting_ref_root: digest(1),
        resulting_forge_position_root: digest(1),
        resulting_outcome_index_root: digest(1),
        resulting_retention_root: digest(1),
        resulting_outbox_root: digest(1),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(1),
    }
}

fn successor_head(
    predecessor: &RepositoryAuthorityHeadBody,
    tail: RepositoryDecisionBatchId,
    latest_sequence: u64,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        generation: HeadGeneration::try_new(predecessor.generation.get() + 1).expect("positive"),
        predecessor_head_id: Some(head_id_of(predecessor)),
        decision_tail_id: Some(tail),
        latest_decision_sequence: Some(
            DecisionSequence::try_new(latest_sequence).expect("positive"),
        ),
        ..predecessor.clone()
    }
}

fn committed(tx_id: TxId, sequence: u64, commit: u8) -> RepositoryDecision {
    RepositoryDecision {
        tx_id,
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(commit),
        },
    }
}

fn refused(tx_id: TxId, sequence: u64, record: u8) -> RepositoryDecision {
    RepositoryDecision {
        tx_id,
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::QuotaExceeded,
            refusal_record_id: refusal_id(record),
        },
    }
}

/// Genesis plus one batch deciding `tx(0xA1)` committed and `tx(0xB2)` refused.
fn published_repository() -> (MemoryAuthorityStore, RepositoryAuthorityHeadBody) {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    let first = batch(
        &genesis,
        1,
        vec![committed(tx(0xA1), 1, 0x51), refused(tx(0xB2), 2, 0x52)],
    );
    let head = successor_head(&genesis, batch_id_of(&first), 2);
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("genesis must be published");
    };
    let outcome = publish_decisions(
        &store,
        &head_slot(),
        receipt.token(),
        &first,
        &head,
        tenant(),
    )
    .expect("publication");
    assert!(matches!(outcome, PublicationOutcome::Published { .. }));
    (store, head)
}

#[test]
fn both_paths_agree_over_the_whole_corpus() {
    let (store, _) = published_repository();

    for (tx_id, expected) in [
        (
            tx(0xA1),
            TerminalOutcome {
                decision_sequence: DecisionSequence::try_new(1).expect("positive"),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: commit_id(0x51),
                },
            },
        ),
        (
            tx(0xB2),
            TerminalOutcome {
                decision_sequence: DecisionSequence::try_new(2).expect("positive"),
                outcome: DecisionOutcome::Refused {
                    code: RefusalCode::QuotaExceeded,
                    refusal_record_id: refusal_id(0x52),
                },
            },
        ),
    ] {
        let indexed = indexed_outcome(&store, tenant(), repository(), tx_id).expect("index read");
        let replayed = replay_outcome(&store, &head_slot(), tx_id).expect("stream replay");
        assert_eq!(
            indexed,
            OutcomeLookup::Decided(expected),
            "the accelerator must carry the published decision"
        );
        assert_eq!(
            replayed, indexed,
            "the accelerator and the authenticated stream must agree"
        );
        assert_eq!(
            resolve_outcome(&store, &head_slot(), tenant(), repository(), tx_id)
                .expect("agreement"),
            indexed
        );
    }
}

#[test]
fn an_unsealed_identity_is_undecided_on_both_paths() {
    let (store, _) = published_repository();
    let unknown = tx(0xEE);
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), unknown).expect("index read"),
        OutcomeLookup::Undecided
    );
    assert_eq!(
        replay_outcome(&store, &head_slot(), unknown).expect("stream replay"),
        OutcomeLookup::Undecided,
        "undecided is an answer, not an error: the transaction stays retryable"
    );
}

#[test]
fn replay_walks_back_through_several_batches() {
    let (store, first_head) = published_repository();

    let second = batch(&first_head, 3, vec![committed(tx(0xC3), 3, 0x53)]);
    let second_head = successor_head(&first_head, batch_id_of(&second), 3);
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("the first publication must be visible");
    };
    publish_decisions(
        &store,
        &head_slot(),
        receipt.token(),
        &second,
        &second_head,
        tenant(),
    )
    .expect("the second publication");

    // The newest batch answers directly; the older ones require the walk.
    for tx_id in [tx(0xC3), tx(0xA1), tx(0xB2)] {
        assert!(
            matches!(
                replay_outcome(&store, &head_slot(), tx_id).expect("stream replay"),
                OutcomeLookup::Decided(_)
            ),
            "replay must reach a decision published in an earlier batch"
        );
        assert_eq!(
            replay_outcome(&store, &head_slot(), tx_id).expect("stream replay"),
            indexed_outcome(&store, tenant(), repository(), tx_id).expect("index read"),
        );
    }
}

#[test]
fn replay_answers_when_the_accelerator_was_never_written() {
    // Model the crash between the conditional replacement and indexing: stage
    // the bodies and replace the head, but write no accelerator entry.
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 1);
    let batch_slot = body_key(IdentityDomain::RepositoryDecisionBatch, &first).expect("a key");
    store
        .put_if_absent(&batch_slot, &encode_body(&first).expect("encodable"))
        .expect("staging the batch");
    let head_body_slot = body_key(IdentityDomain::RepositoryAuthorityHead, &head).expect("a key");
    let head_bytes = encode_body(&head).expect("encodable");
    store
        .put_if_absent(&head_body_slot, &head_bytes)
        .expect("staging the head");
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("genesis must be published");
    };
    let CasOutcome::Committed(_) = store
        .compare_exchange_head(
            &head_slot(),
            receipt.token(),
            HeadGeneration::try_new(2).expect("positive"),
            &head_bytes,
        )
        .expect("the conditional replacement")
    else {
        panic!("the replacement must publish");
    };

    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx(0xA1)).expect("index read"),
        OutcomeLookup::Undecided,
        "the accelerator is legitimately behind after a crash"
    );
    let replayed = replay_outcome(&store, &head_slot(), tx(0xA1)).expect("stream replay");
    assert!(
        matches!(replayed, OutcomeLookup::Decided(_)),
        "replay reconstructs the answer without the accelerator"
    );
    assert_eq!(
        resolve_outcome(&store, &head_slot(), tenant(), repository(), tx(0xA1))
            .expect("a missing accelerator is repairable, not a conflict"),
        replayed,
        "a behind accelerator defers to the stream rather than failing closed"
    );
}

#[test]
fn an_accelerator_that_disagrees_with_the_stream_fails_closed() {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    // Plant an accelerator entry claiming a decision the stream will not carry.
    let planted = outcome_key(tenant(), repository(), tx(0xA1)).expect("a key");
    let bogus = TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(99).expect("positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(0xFF),
        },
    };
    store
        .put_if_absent(&planted, &encode_terminal_outcome(&bogus))
        .expect("planting");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 1);
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("genesis must be published");
    };

    let failure = publish_decisions(
        &store,
        &head_slot(),
        receipt.token(),
        &first,
        &head,
        tenant(),
    )
    .expect_err("a second, different terminal decision must not overwrite the first");
    assert!(
        matches!(failure, OutcomeFailure::AcceleratorConflict { .. }),
        "observed {failure:?}"
    );

    let resolution = resolve_outcome(&store, &head_slot(), tenant(), repository(), tx(0xA1))
        .expect_err("a disagreeing accelerator must fail closed, not pick a side");
    assert!(matches!(
        resolution,
        OutcomeFailure::AcceleratorConflict { .. }
    ));
}

#[test]
fn a_second_terminal_decision_for_one_transaction_is_refused() {
    let (store, first_head) = published_repository();

    // The same sealed transaction, decided differently in a later batch.
    let second = batch(&first_head, 3, vec![refused(tx(0xA1), 3, 0x5F)]);
    let second_head = successor_head(&first_head, batch_id_of(&second), 3);
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("the first publication must be visible");
    };

    let failure = publish_decisions(
        &store,
        &head_slot(),
        receipt.token(),
        &second,
        &second_head,
        tenant(),
    )
    .expect_err("one sealed transaction has at most one terminal decision");
    assert!(
        matches!(failure, OutcomeFailure::AcceleratorConflict { .. }),
        "observed {failure:?}"
    );
}

#[test]
fn a_publication_that_loses_the_head_publishes_nothing() {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    // Capture the genesis token, then let another publication supersede it.
    let HeadRead::Present(genesis_receipt) = store.read_head(&head_slot()).expect("readable")
    else {
        panic!("genesis must be published");
    };
    let stale = genesis_receipt.token();

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let first_head = successor_head(&genesis, batch_id_of(&first), 1);
    publish_decisions(&store, &head_slot(), stale, &first, &first_head, tenant())
        .expect("the first publication wins with the current token");

    // A combiner still holding the pre-publication token now loses.
    let second = batch(&first_head, 2, vec![committed(tx(0xC3), 2, 0x53)]);
    let second_head = successor_head(&first_head, batch_id_of(&second), 2);
    let outcome = publish_decisions(&store, &head_slot(), stale, &second, &second_head, tenant())
        .expect("a lost race is an outcome, not an error");

    assert_eq!(
        outcome,
        PublicationOutcome::PredecessorMismatch,
        "a combiner holding a superseded token must lose the head"
    );
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx(0xC3)).expect("index read"),
        OutcomeLookup::Undecided,
        "a lost publication indexes nothing"
    );
    assert_eq!(
        replay_outcome(&store, &head_slot(), tx(0xC3)).expect("stream replay"),
        OutcomeLookup::Undecided,
        "the staged bodies stay staged and unreferenced"
    );
}

/// Reproduce the accelerator entry encoding for planting a conflicting value.
fn encode_terminal_outcome(outcome: &TerminalOutcome) -> Vec<u8> {
    let mut out = fgit_codec::Encoder::new();
    out.write_scalar(outcome.decision_sequence.get());
    out.write_raw_byte(outcome.outcome.discriminant());
    match &outcome.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => out
            .write_internal_object_id(repository_commit_id.as_internal_object_id())
            .expect("encodable"),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => {
            out.write_scalar(code.code_point());
            out.write_internal_object_id(refusal_record_id.as_internal_object_id())
                .expect("encodable");
        }
    }
    out.into_bytes()
}
