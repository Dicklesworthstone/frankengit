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

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

const fn repository() -> RepositoryId {
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
        compaction_generation_link: None,
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
    assert!(matches!(outcome, PublicationOutcome::Published(_)));
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

// --- the outcome-index root ------------------------------------------------

fn entry(tx_byte: u8, sequence: u64, commit: u8) -> (TxId, TerminalOutcome) {
    (
        tx(tx_byte),
        TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
            outcome: DecisionOutcome::Committed {
                repository_commit_id: commit_id(commit),
            },
        },
    )
}

#[test]
fn the_index_root_is_a_function_of_the_set_not_the_order() {
    let ascending = [
        entry(0xA1, 1, 0x51),
        entry(0xB2, 2, 0x52),
        entry(0xC3, 3, 0x53),
    ];
    let shuffled = [
        entry(0xC3, 3, 0x53),
        entry(0xA1, 1, 0x51),
        entry(0xB2, 2, 0x52),
    ];

    let left = fgit_authority::outcome_index_root(&ascending).expect("a computable root");
    let right = fgit_authority::outcome_index_root(&shuffled).expect("a computable root");
    assert_eq!(left, right, "insertion order must not reach the root");
    assert_eq!(
        left,
        fgit_authority::outcome_index_root(&ascending).expect("a computable root"),
        "the root must be deterministic"
    );
}

#[test]
fn the_index_root_changes_with_any_entry() {
    let base = [entry(0xA1, 1, 0x51), entry(0xB2, 2, 0x52)];
    let baseline = fgit_authority::outcome_index_root(&base).expect("a computable root");

    let changed_outcome = [entry(0xA1, 1, 0x5F), entry(0xB2, 2, 0x52)];
    let changed_sequence = [entry(0xA1, 9, 0x51), entry(0xB2, 2, 0x52)];
    let added = [
        entry(0xA1, 1, 0x51),
        entry(0xB2, 2, 0x52),
        entry(0xC3, 3, 0x53),
    ];

    for (what, variant) in [
        ("a changed commit", &changed_outcome[..]),
        ("a changed sequence", &changed_sequence[..]),
        ("an added entry", &added[..]),
    ] {
        assert_ne!(
            baseline,
            fgit_authority::outcome_index_root(variant).expect("a computable root"),
            "{what} must change the index root"
        );
    }
}

#[test]
fn an_odd_level_does_not_collide_with_its_even_prefix() {
    // Promoting an odd node unchanged, rather than pairing it with itself, is
    // what stops two different sets sharing a root. Three entries must not
    // hash to the same root as the two-entry prefix that produced their first
    // interior node.
    let two = [entry(0xA1, 1, 0x51), entry(0xB2, 2, 0x52)];
    let three = [
        entry(0xA1, 1, 0x51),
        entry(0xB2, 2, 0x52),
        entry(0xC3, 3, 0x53),
    ];
    assert_ne!(
        fgit_authority::outcome_index_root(&two).expect("a computable root"),
        fgit_authority::outcome_index_root(&three).expect("a computable root")
    );
}

#[test]
fn the_empty_index_has_a_defined_root_of_its_own() {
    let empty = fgit_authority::outcome_index_root(&[]).expect("a computable root");
    let single =
        fgit_authority::outcome_index_root(&[entry(0xA1, 1, 0x51)]).expect("a computable root");
    assert_ne!(
        empty, single,
        "an empty index and a one-entry index must not share a root"
    );
    assert_eq!(
        empty,
        fgit_authority::outcome_index_root(&[]).expect("a computable root"),
        "the empty root is a fixed value, not an accident"
    );
}

// ---------------------------------------------------------------------------
// Sync/async publication equivalence (t7ip condition 1)
// ---------------------------------------------------------------------------

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, DuplicateAbsenceWitness, HeadInit, HeadReadReceipt, ImmutableKey,
    ImmutableRead, PutOutcome, authority_head_identity, decision_batch_identity,
    initialize_repository_async, publish_decisions_async, read_authority_head_body,
    read_authority_head_body_async, read_decision_batch_body, read_decision_batch_body_async,
    resolve_outcome_async,
};
use fgit_types::numeric::HeadGeneration as AsyncHeadGeneration;
use std::future::Future;

/// An async view over the in-memory reference store, for equivalence only.
///
/// Not a blocking adapter: every operation is already resolved when its future
/// is created, so nothing blocks and no cancellation is silently dropped. It
/// exists so both surfaces can be driven over identically-constructed store
/// state in one test, which is the only way to show they AGREE rather than
/// merely that each works alone. Test-only per the t7ip ruling's condition 4;
/// production async use goes through the fsqlite implementation.
///
/// It DOES override `publish_head_with_outcomes`, and that is a deliberate
/// reversal of the reasoning that (correctly) refused the override in
/// chronicle's `capsule_pointer` view. The objection there was that a
/// delegating implementation would compose a head CAS with separate puts and
/// therefore satisfy the signature without providing atomicity — a fixture that
/// looks like it publishes atomically and does not. That objection was sound
/// while `MemoryAuthorityStore` had no atomic primitive. It now has one, and
/// this delegates to *that*, inside a single mutex-guarded critical section, so
/// the property is real rather than simulated.
struct AsyncView(MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncView {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let resolved = self.0.put_if_absent(key, body);
        async move { resolved }
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_immutable(key);
        async move { resolved }
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: AsyncHeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        let resolved = self.0.initialize_head(key, generation, body);
        async move { resolved }
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_head(key);
        async move { resolved }
    }

    fn compare_exchange_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: AsyncHeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let resolved = self
            .0
            .compare_exchange_head(key, expected, new_generation, new_body);
        async move { resolved }
    }

    fn publish_head_with_outcomes(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: AsyncHeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let resolved = self.0.publish_head_with_outcomes(
            key,
            expected,
            new_generation,
            new_body,
            outcomes,
            witness,
        );
        async move { resolved }
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        let resolved = self.0.authenticate_head_receipt(receipt);
        async move { resolved }
    }
}

/// Drive an already-resolved future to its value.
fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the in-memory async view must never suspend"),
    }
}

/// A stable label for a publication result, so failures compare by shape.
fn label(result: &Result<PublicationOutcome, OutcomeFailure>) -> String {
    match result {
        Ok(PublicationOutcome::Published(published)) => {
            format!("published/{}", published.indexed)
        }
        Ok(PublicationOutcome::PredecessorMismatch) => "predecessor-mismatch".to_owned(),
        Ok(PublicationOutcome::AlreadyDecided { decided }) => {
            format!("already-decided/{}", decided.len())
        }
        Err(OutcomeFailure::AcceleratorConflict { .. }) => "accelerator-conflict".to_owned(),
        Err(other) => format!("failure/{other:?}"),
    }
}

/// Both surfaces must reach the same conclusion from the same state.
fn assert_surfaces_agree(
    sync_result: &Result<PublicationOutcome, OutcomeFailure>,
    async_result: &Result<PublicationOutcome, OutcomeFailure>,
    case: &str,
) {
    assert_eq!(
        label(sync_result),
        label(async_result),
        "{case}: the surfaces disagree"
    );
    if let (Ok(sync_outcome), Ok(async_outcome)) = (sync_result, async_result) {
        // Beyond the shape: the published receipt, batch identity and entry
        // count must match exactly, not merely classify the same way.
        assert_eq!(
            sync_outcome, async_outcome,
            "{case}: the surfaces agree in shape but not in value"
        );
    }
}

/// Publish one batch on each surface, over identically-constructed stores.
fn publish_on_both(
    make: impl Fn() -> (MemoryAuthorityStore, RepositoryAuthorityHeadBody),
    batch_of: impl Fn(&RepositoryAuthorityHeadBody) -> RepositoryDecisionBatchBody,
    generation: u64,
    token_of: impl Fn(&MemoryAuthorityStore) -> AuthorityVersionToken,
) -> (
    Result<PublicationOutcome, OutcomeFailure>,
    Result<PublicationOutcome, OutcomeFailure>,
) {
    let (sync_store, sync_head) = make();
    let sync_batch = batch_of(&sync_head);
    let sync_next = successor_head(&sync_head, batch_id_of(&sync_batch), generation);
    let sync_result = publish_decisions(
        &sync_store,
        &head_slot(),
        token_of(&sync_store),
        &sync_batch,
        &sync_next,
        tenant(),
    );

    let (async_store, async_head) = make();
    let async_batch = batch_of(&async_head);
    let async_next = successor_head(&async_head, batch_id_of(&async_batch), generation);
    let token = token_of(&async_store);
    let view = AsyncView(async_store);
    let async_result = poll_ready(publish_decisions_async(
        &view,
        &(),
        &head_slot(),
        token,
        &async_batch,
        &async_next,
        tenant(),
    ));

    (sync_result, async_result)
}

/// The current head token, which is what a publication conditions on.
fn current_token(store: &MemoryAuthorityStore) -> AuthorityVersionToken {
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("the repository must be published");
    };
    receipt.token()
}

/// A token that no longer names the current head.
const fn stale_token(store: &MemoryAuthorityStore) -> AuthorityVersionToken {
    let _ = store;
    AuthorityVersionToken::from_opaque_bytes([0x7E; 16])
}

#[test]
fn both_publication_surfaces_agree_on_a_fresh_batch() {
    let (sync_result, async_result) = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xC3), 3, 0x53)]),
        3,
        current_token,
    );
    assert_surfaces_agree(&sync_result, &async_result, "a fresh batch");
    assert!(
        matches!(sync_result, Ok(PublicationOutcome::Published(_))),
        "a fresh batch must publish, else this case proves nothing: {sync_result:?}"
    );
}

#[test]
fn both_publication_surfaces_agree_on_an_idempotent_replay() {
    // The SAME decision that already stands, replayed — the lost-response case.
    let (sync_result, async_result) = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xA1), 1, 0x51)]),
        3,
        current_token,
    );
    assert_surfaces_agree(&sync_result, &async_result, "an idempotent replay");
    assert!(
        matches!(sync_result, Ok(PublicationOutcome::AlreadyDecided { .. })),
        "replaying a standing decision is idempotent, not a conflict: {sync_result:?}"
    );
}

#[test]
fn both_publication_surfaces_agree_when_a_second_decision_conflicts() {
    // A DIFFERENT decision for a transaction that is already terminal.
    let (sync_result, async_result) = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![refused(tx(0xA1), 3, 0x5F)]),
        3,
        current_token,
    );
    assert_surfaces_agree(&sync_result, &async_result, "a conflicting second decision");
    assert!(
        matches!(sync_result, Err(OutcomeFailure::AcceleratorConflict { .. })),
        "a different decision for a sealed transaction must fail closed: {sync_result:?}"
    );
}

#[test]
fn both_publication_surfaces_agree_on_a_stale_token() {
    let (sync_result, async_result) = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xC3), 3, 0x53)]),
        3,
        stale_token,
    );
    assert_surfaces_agree(&sync_result, &async_result, "a stale token");
    assert!(
        matches!(sync_result, Ok(PublicationOutcome::PredecessorMismatch)),
        "a stale token loses the race: {sync_result:?}"
    );
}

/// The corpus must be able to tell the surfaces apart.
///
/// Four cases that all produced the same answer would agree trivially, and an
/// async path that returned one constant would pass every case above. This
/// pins that the corpus actually separates them.
#[test]
fn the_publication_equivalence_corpus_is_not_vacuous() {
    let fresh = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xC3), 3, 0x53)]),
        3,
        current_token,
    );
    let replay = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xA1), 1, 0x51)]),
        3,
        current_token,
    );
    let conflict = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![refused(tx(0xA1), 3, 0x5F)]),
        3,
        current_token,
    );
    let stale = publish_on_both(
        published_repository,
        |head| batch(head, 3, vec![committed(tx(0xC3), 3, 0x53)]),
        3,
        stale_token,
    );

    let labels = [
        label(&fresh.1),
        label(&replay.1),
        label(&conflict.1),
        label(&stale.1),
    ];
    let mut distinct = labels.to_vec();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        labels.len(),
        "the async surface answers these four cases identically, so agreement \
         with the sync surface would prove nothing: {labels:?}"
    );
}

// ---------------------------------------------------------------------------
// The §5.2 property itself, under a crash at the publication
// ---------------------------------------------------------------------------

use fgit_authority::{
    AuthorityOpKind, FaultDirective, FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore,
    OpIndex,
};

/// The batch every crash case below publishes.
fn crash_case_batch(head: &RepositoryAuthorityHeadBody) -> RepositoryDecisionBatchBody {
    batch(head, 3, vec![committed(tx(0xC3), 3, 0x53)])
}

/// Find the operation index of the atomic publication, by running it.
///
/// Retained to PIN the ordinal-within-kind selector against an independently
/// derived answer: `nth_of_kind(0, CompareExchangeHead, ..)` and "the absolute
/// index the effect log reports for the first head transition" must name the
/// same operation, and one test below asserts exactly that. Tests themselves
/// use the selector; this is the oracle it is checked against.
fn locate_atomic_publication() -> OpIndex {
    let (twin, head) = published_repository();
    let token = current_token(&twin);
    // Resets the operation counter, so the index is relative to this point and
    // the real run below can reproduce it exactly.
    twin.install_fault_plan(FaultPlan::default());
    let batch_body = crash_case_batch(&head);
    let next = successor_head(&head, batch_id_of(&batch_body), 3);
    publish_decisions(&twin, &head_slot(), token, &batch_body, &next, tenant())
        .expect("the unfaulted twin publishes");

    twin.effect_log()
        .records()
        .iter()
        .find(|record| record.op_kind == AuthorityOpKind::CompareExchangeHead)
        .map(|record| record.at)
        .expect("the publication reaches a head transition")
}

/// Whether the head has advanced past the state `published_repository` leaves.
fn head_generation_now(store: &MemoryAuthorityStore) -> u64 {
    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("the repository must be published");
    };
    receipt.generation().get()
}

/// The §5.2 guarantee, stated as the observation it forbids.
///
/// "If a caller can observe the new head, the outcome records are necessarily
/// observable." The old composition — head CAS, then a loop of accelerator puts
/// — could not offer this: a crash between the two left a transaction
/// canonically decided with no entry, and the next publisher read that absence
/// as "undecided" and published a second terminal decision for the same sealed
/// transaction.
///
/// This drives a crash *after* the publication effect applies, which is the
/// worst case: the effect is real, the caller never learns it, and the
/// accelerator is exactly where the old ordering would have left it empty.
#[test]
fn a_crash_at_the_publication_never_leaves_the_head_ahead_of_its_outcomes() {
    let (store, head) = published_repository();
    let token = current_token(&store);
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));

    let batch_body = crash_case_batch(&head);
    let next = successor_head(&head, batch_id_of(&batch_body), 3);
    let result = publish_decisions(&store, &head_slot(), token, &batch_body, &next, tenant());

    assert!(
        result.is_err(),
        "a crash after the effect hides the outcome from the caller: {result:?}"
    );
    assert!(store.is_crashed(), "the planned crash must fire");
    let fired = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned crash is recorded");
    assert!(
        fired.effect_reached,
        "this case is only meaningful if the crash lands AFTER the effect applied"
    );

    store.restart();

    // The head advanced, because the effect applied before the crash.
    assert_eq!(
        head_generation_now(&store),
        3,
        "the publication effect applied, so the head must carry it"
    );

    // Therefore every terminal outcome in that batch must be observable. Under
    // the old ordering this is precisely where the accelerator was empty.
    let decided = indexed_outcome(&store, tenant(), repository(), tx(0xC3))
        .expect("the accelerator is readable");
    assert!(
        matches!(decided, OutcomeLookup::Decided(_)),
        "the head is canonical at generation 3, so its decisions must be \
         observable — a head ahead of its outcomes is the §5.2 defect: {decided:?}"
    );
}

/// A second, different decision after a lost publication must not be admitted.
///
/// This is the race the campaign named: publisher B's transition linearizes but
/// its response is lost, so B cannot know it won. A second publisher then asks
/// whether the transaction is decided. If it asks the accelerator it may read
/// an absence and publish a second terminal decision; asking the authenticated
/// stream, it cannot.
#[test]
fn a_lost_publication_response_still_refuses_a_second_terminal_decision() {
    let (store, head) = published_repository();
    let token = current_token(&store);
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    )]));

    let batch_body = crash_case_batch(&head);
    let next = successor_head(&head, batch_id_of(&batch_body), 3);
    let lost = publish_decisions(&store, &head_slot(), token, &batch_body, &next, tenant());
    assert!(
        lost.is_err(),
        "a lost response must not be reported as a publication: {lost:?}"
    );

    // Clear the plan so the second publisher runs unfaulted.
    store.install_fault_plan(FaultPlan::default());

    // A second publisher, with a DIFFERENT decision for the same TxId, off the
    // head the winner established.
    let winner_head = successor_head(&head, batch_id_of(&batch_body), 3);
    let second = batch(&winner_head, 4, vec![refused(tx(0xC3), 4, 0x5F)]);
    let second_head = successor_head(&winner_head, batch_id_of(&second), 4);
    let outcome = publish_decisions(
        &store,
        &head_slot(),
        current_token(&store),
        &second,
        &second_head,
        tenant(),
    );

    assert!(
        matches!(outcome, Err(OutcomeFailure::AcceleratorConflict { .. })),
        "one sealed transaction has at most one terminal decision, and the \
         first one linearized even though its response was lost: {outcome:?}"
    );
}

/// The selector and the located index must name the same operation.
///
/// `nth_of_kind(0, CompareExchangeHead, ..)` is a claim about which operation
/// gets the fault. This checks it against an independently derived answer — the
/// absolute index the effect log reports for the first head transition — so the
/// selector is pinned to an oracle rather than trusted.
#[test]
fn the_ordinal_selector_and_the_located_index_name_the_same_operation() {
    let located = locate_atomic_publication();

    let (store, head) = published_repository();
    let token = current_token(&store);
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    )]));
    let batch_body = crash_case_batch(&head);
    let next = successor_head(&head, batch_id_of(&batch_body), 3);
    let _ = publish_decisions(&store, &head_slot(), token, &batch_body, &next, tenant());

    let fired = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the ordinal directive fires");
    assert_eq!(
        fired.at, located,
        "the ordinal selector must land on the same operation the effect log \
         identifies as the first head transition"
    );
}

/// The point of the selector: operations before the target must not move it.
///
/// This reproduces, in miniature, what happened to the FG-007b recovery plans
/// when publication grew a pre-CAS stream walk. The absolute directive does not
/// fire on the wrong operation — the kind filter means it fires NOWHERE, the
/// publication completes normally, and the test truthfully reports a
/// publication it expected to interrupt and did not. The ordinal directive is
/// unmoved.
#[test]
fn an_ordinal_within_kind_directive_is_unmoved_by_operations_before_it() {
    let noise = outcome_key(tenant(), repository(), tx(0xEE)).expect("a key");

    // Ordinal addressing: fires, whatever precedes the head transition.
    let (ordinal_store, ordinal_head) = published_repository();
    let ordinal_token = current_token(&ordinal_store);
    ordinal_store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    )]));
    for _ in 0..5 {
        ordinal_store
            .read_immutable(&noise)
            .expect("a readable slot");
    }
    let ordinal_batch = crash_case_batch(&ordinal_head);
    let ordinal_next = successor_head(&ordinal_head, batch_id_of(&ordinal_batch), 3);
    let ordinal_result = publish_decisions(
        &ordinal_store,
        &head_slot(),
        ordinal_token,
        &ordinal_batch,
        &ordinal_next,
        tenant(),
    );
    assert!(
        ordinal_result.is_err(),
        "the ordinal directive must still fire after unrelated operations: \
         {ordinal_result:?}"
    );

    // Absolute addressing at the same number: silently fires nowhere.
    let (absolute_store, absolute_head) = published_repository();
    let absolute_token = current_token(&absolute_store);
    absolute_store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::from_raw(0), FaultKind::LoseResponse)
            .only_for(AuthorityOpKind::CompareExchangeHead),
    ]));
    for _ in 0..5 {
        absolute_store
            .read_immutable(&noise)
            .expect("a readable slot");
    }
    let absolute_batch = crash_case_batch(&absolute_head);
    let absolute_next = successor_head(&absolute_head, batch_id_of(&absolute_batch), 3);
    let absolute_result = publish_decisions(
        &absolute_store,
        &head_slot(),
        absolute_token,
        &absolute_batch,
        &absolute_next,
        tenant(),
    );
    assert!(
        absolute_result.is_ok(),
        "this case is only meaningful if the absolute directive misses: \
         {absolute_result:?}"
    );
    assert!(
        absolute_store.fault_log().records().is_empty(),
        "the absolute directive fires NOWHERE rather than on a wrong operation \
         — that silence is what makes the miss cost a diagnosis every time"
    );
}

/// A restart after a crashed publication must retry to the SAME decision.
///
/// The open question on the three remaining recovery verifiers: once
/// they are firing again, do they also need the retry/restart read-back to fall
/// through to stream replay, or is retargeting enough? This answers the
/// property directly rather than waiting on the retarget.
///
/// The crash lands after the publication effect, so the endpoint comes back up
/// with the head advanced. The retry must discover the existing terminal
/// decision — from the authenticated stream, which is the only thing that can
/// answer after an index is wiped — and must not publish a second one.
#[test]
fn a_restart_after_a_crashed_publication_retries_to_the_same_terminal_outcome() {
    let (store, head) = published_repository();
    let token = current_token(&store);
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));

    let batch_body = crash_case_batch(&head);
    let next = successor_head(&head, batch_id_of(&batch_body), 3);
    let crashed = publish_decisions(&store, &head_slot(), token, &batch_body, &next, tenant());
    assert!(crashed.is_err(), "the crash hides the outcome: {crashed:?}");
    assert!(store.is_crashed(), "the planned crash must fire");

    store.restart();
    store.install_fault_plan(FaultPlan::default());

    // The endpoint is back. The caller never learned it won, so it retries the
    // SAME sealed batch against whatever head it now finds.
    let retried = publish_decisions(
        &store,
        &head_slot(),
        current_token(&store),
        &batch_body,
        &next,
        tenant(),
    );

    match retried {
        Ok(PublicationOutcome::AlreadyDecided { decided }) => {
            assert_eq!(
                decided.len(),
                1,
                "exactly the transaction this batch decided: {decided:?}"
            );
            assert_eq!(
                decided[0].0,
                tx(0xC3),
                "the retry must recover the decision it made, not another"
            );
        }
        other => panic!(
            "a retry after a crashed publication must resolve to the standing \
             decision, never publish a second one: {other:?}"
        ),
    }

    // And the decision is resolvable, which is what a caller actually asks.
    let resolved = resolve_outcome(&store, &head_slot(), tenant(), repository(), tx(0xC3))
        .expect("the decision resolves after a restart");
    assert!(
        matches!(resolved, OutcomeLookup::Decided(_)),
        "the transaction is terminal and must resolve as such: {resolved:?}"
    );
}

/// The exposed identity helpers must agree with the derivation they replace.
///
/// They exist so a caller need not name an `IdentityDomain` or a codec version
/// to address a body it just built. That is only safe if they produce exactly
/// what the hand derivation produces, so this pins them against the fixtures'
/// own `head_id_of` / `batch_id_of`, which spell the derivation out in full.
#[test]
fn the_exposed_identity_helpers_match_the_hand_derivation() {
    let genesis = genesis_head();
    assert_eq!(
        authority_head_identity(&genesis).expect("a derivable head identity"),
        head_id_of(&genesis),
        "the exposed head identity must be the one publication uses"
    );

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    assert_eq!(
        decision_batch_identity(&first).expect("a derivable batch identity"),
        batch_id_of(&first),
        "the exposed batch identity must be the one publication uses"
    );

    // Distinct bodies must not collide, or agreement above would be trivial.
    let second = batch(&genesis, 2, vec![refused(tx(0xB2), 2, 0x52)]);
    assert_ne!(
        decision_batch_identity(&first).expect("an identity"),
        decision_batch_identity(&second).expect("an identity"),
        "different batches must have different identities"
    );
}

/// An absent accelerator must not admit a second terminal decision.
///
/// This is the property the FG-007b recovery verifiers protect, with its
/// premise CONSTRUCTED rather than crash-produced. A fault at publication can
/// no longer leave the head ahead of its outcomes — that is what the atomic
/// primitive removed — so the wiped-index state is built the way it can still
/// legitimately arise: an index that was never written, rebuilt, or GC'd, and
/// the older publisher that `compare_exchange_head` still serves.
///
/// The distinction matters because the property is unchanged and still load
/// bearing. Only the route to the starting state changed.
#[test]
fn an_absent_accelerator_still_refuses_a_second_terminal_decision() {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    // Publish WITHOUT the accelerator: stage the bodies, move the head.
    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 2);
    let batch_slot = body_key(IdentityDomain::RepositoryDecisionBatch, &first).expect("a key");
    store
        .put_if_absent(&batch_slot, &encode_body(&first).expect("encodable"))
        .expect("staging the batch");
    let head_slot_by_id = body_key(IdentityDomain::RepositoryAuthorityHead, &head).expect("a key");
    let head_bytes = encode_body(&head).expect("encodable");
    store
        .put_if_absent(&head_slot_by_id, &head_bytes)
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

    // The premise: decided in the stream, absent from the accelerator.
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx(0xA1)).expect("index read"),
        OutcomeLookup::Undecided,
        "this case is only meaningful while the accelerator is genuinely empty"
    );
    assert!(
        matches!(
            replay_outcome(&store, &head_slot(), tx(0xA1)).expect("stream replay"),
            OutcomeLookup::Decided(_)
        ),
        "and only meaningful while the stream genuinely carries the decision"
    );

    // A second publisher, different decision, same sealed transaction. It reads
    // an absent accelerator; the walk must still find the standing decision.
    let second = batch(&head, 2, vec![refused(tx(0xA1), 2, 0x5F)]);
    let second_head = successor_head(&head, batch_id_of(&second), 3);
    let outcome = publish_decisions(
        &store,
        &head_slot(),
        current_token(&store),
        &second,
        &second_head,
        tenant(),
    );

    assert!(
        matches!(outcome, Err(OutcomeFailure::AcceleratorConflict { .. })),
        "accelerator absence must never be read as 'not decided' when the \
         authenticated stream says otherwise: {outcome:?}"
    );

    // And the head did not move, so nothing was published on the way to that.
    assert_eq!(
        head_generation_now(&store),
        2,
        "a refused duplicate must not have crossed the head-CAS boundary"
    );
}

// ---------------------------------------------------------------------------
// Sync/async RESOLUTION equivalence (t7ip condition 1, read side)
// ---------------------------------------------------------------------------

/// Build a repository whose head is canonical but whose accelerator is empty.
///
/// Stages the bodies and moves the head with `compare_exchange_head`, writing
/// no outcome entries — the wiped/rebuilt/never-written index state. Returns the
/// store and the transaction the stream decides.
fn store_with_decision_absent_from_accelerator() -> MemoryAuthorityStore {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 2);
    let batch_slot = body_key(IdentityDomain::RepositoryDecisionBatch, &first).expect("a key");
    store
        .put_if_absent(&batch_slot, &encode_body(&first).expect("encodable"))
        .expect("staging the batch");
    let head_slot_by_id = body_key(IdentityDomain::RepositoryAuthorityHead, &head).expect("a key");
    let head_bytes = encode_body(&head).expect("encodable");
    store
        .put_if_absent(&head_slot_by_id, &head_bytes)
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
    store
}

/// A stable label for a resolution result, so failures compare by shape.
fn resolution_label(result: &Result<OutcomeLookup, OutcomeFailure>) -> String {
    match result {
        Ok(OutcomeLookup::Decided(outcome)) => {
            format!("decided/{}", outcome.decision_sequence.get())
        }
        Ok(OutcomeLookup::Undecided) => "undecided".to_owned(),
        Err(OutcomeFailure::AcceleratorConflict { .. }) => "accelerator-conflict".to_owned(),
        Err(other) => format!("failure/{other:?}"),
    }
}

/// Resolve one transaction on both surfaces, over identical store state.
fn resolve_on_both(
    make: impl Fn() -> MemoryAuthorityStore,
    tx_id: TxId,
) -> (
    Result<OutcomeLookup, OutcomeFailure>,
    Result<OutcomeLookup, OutcomeFailure>,
) {
    let sync_result = resolve_outcome(&make(), &head_slot(), tenant(), repository(), tx_id);
    let view = AsyncView(make());
    let async_result = poll_ready(resolve_outcome_async(
        &view,
        &(),
        &head_slot(),
        tenant(),
        repository(),
        tx_id,
    ));
    (sync_result, async_result)
}

/// Both surfaces must reach the same resolution from the same state.
fn assert_resolutions_agree(
    sync_result: &Result<OutcomeLookup, OutcomeFailure>,
    async_result: &Result<OutcomeLookup, OutcomeFailure>,
    case: &str,
) {
    assert_eq!(
        resolution_label(sync_result),
        resolution_label(async_result),
        "{case}: the surfaces resolve differently"
    );
    if let (Ok(left), Ok(right)) = (sync_result, async_result) {
        assert_eq!(left, right, "{case}: same shape, different value");
    }
}

#[test]
fn both_resolution_surfaces_agree_on_a_decided_transaction() {
    let (sync_result, async_result) = resolve_on_both(|| published_repository().0, tx(0xA1));
    assert_resolutions_agree(&sync_result, &async_result, "a decided transaction");
    assert!(
        matches!(sync_result, Ok(OutcomeLookup::Decided(_))),
        "the fixture publishes this transaction: {sync_result:?}"
    );
}

#[test]
fn both_resolution_surfaces_agree_on_an_undecided_transaction() {
    let (sync_result, async_result) = resolve_on_both(|| published_repository().0, tx(0xEE));
    assert_resolutions_agree(&sync_result, &async_result, "an undecided transaction");
    assert_eq!(
        sync_result.expect("resolution runs"),
        OutcomeLookup::Undecided,
        "this transaction was never sealed"
    );
}

/// The requirement-2 case, and the reason `resolve_outcome_async` has to exist.
///
/// The head is canonical and the accelerator holds nothing. A resolver that
/// consulted the accelerator alone would answer `Undecided` and tell a caller to
/// replan a transaction that already committed. Both surfaces must replay.
#[test]
fn both_resolution_surfaces_replay_when_the_accelerator_is_empty() {
    let (sync_result, async_result) =
        resolve_on_both(store_with_decision_absent_from_accelerator, tx(0xA1));
    assert_resolutions_agree(&sync_result, &async_result, "an absent accelerator");
    assert!(
        matches!(sync_result, Ok(OutcomeLookup::Decided(_))),
        "accelerator absence must never be read as 'not decided' when the \
         authenticated stream says otherwise: {sync_result:?}"
    );

    // And the premise is real: the accelerator genuinely holds nothing, so the
    // answer above can only have come from the stream.
    let store = store_with_decision_absent_from_accelerator();
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx(0xA1)).expect("index read"),
        OutcomeLookup::Undecided,
        "this case proves nothing unless the accelerator is genuinely empty"
    );
}

/// The corpus must be able to tell the two surfaces apart.
#[test]
fn the_resolution_equivalence_corpus_is_not_vacuous() {
    let decided = resolve_on_both(|| published_repository().0, tx(0xA1));
    let undecided = resolve_on_both(|| published_repository().0, tx(0xEE));
    let replayed = resolve_on_both(store_with_decision_absent_from_accelerator, tx(0xA1));

    let labels = [resolution_label(&decided.1), resolution_label(&undecided.1)];
    assert_ne!(
        labels[0], labels[1],
        "decided and undecided must differ, or agreement proves nothing: {labels:?}"
    );
    assert_eq!(
        resolution_label(&replayed.1),
        resolution_label(&decided.1),
        "the replayed case must reach the SAME decided answer, by a different route"
    );
}

/// Bootstrap must also agree, or the production surface cannot start a history.
#[test]
fn both_surfaces_initialize_a_repository_identically() {
    let genesis = genesis_head();

    let sync_store = store();
    let sync_init = initialize_repository(&sync_store, &head_slot(), &genesis);

    let view = AsyncView(store());
    let async_init = poll_ready(initialize_repository_async(
        &view,
        &(),
        &head_slot(),
        &genesis,
    ));

    assert_eq!(
        format!("{sync_init:?}"),
        format!("{async_init:?}"),
        "the two surfaces must bring a repository into existence identically"
    );
    assert!(sync_init.is_ok(), "genesis must initialize: {sync_init:?}");
}

// ---------------------------------------------------------------------------
// The public body readers, on the production surface (frankengit-iefx)
// ---------------------------------------------------------------------------
//
// The sync twins and the full refusal matrix live in `body_readers.rs`. These
// cases live here because `AsyncView` does, and a second delegating fixture
// would be free to drift from this one — which is the defect these readers'
// re-identification check exists to prevent, reproduced in the test suite.
//
// What is proven here is that the async surface is not merely present but
// reaches the SAME answers as the deterministic one: the permitted read, and
// the re-identification refusal. A production reader that decoded without
// checking would pass the first and fail the second.

#[test]
fn both_surfaces_read_a_staged_head_body_by_identity() {
    let (verification_store, published_head) = published_repository();
    let on_verification =
        read_authority_head_body(&verification_store, head_id_of(&published_head));

    let view = AsyncView(published_repository().0);
    let on_production = poll_ready(read_authority_head_body_async(
        &view,
        &(),
        head_id_of(&published_head),
    ));

    assert_eq!(
        on_verification, on_production,
        "the surfaces must return the same head body for the same identity"
    );
    assert_eq!(
        on_verification.expect("the published head is readable"),
        published_head,
        "and it must be the body that was published"
    );
}

#[test]
fn both_surfaces_resolve_a_decision_tail_by_identity() {
    let (verification_store, published_head) = published_repository();
    let tail = published_head
        .decision_tail_id
        .expect("a published head names its decision tail");

    let on_verification = read_decision_batch_body(&verification_store, tail);
    let view = AsyncView(published_repository().0);
    let on_production = poll_ready(read_decision_batch_body_async(&view, &(), tail));

    assert_eq!(
        on_verification, on_production,
        "the surfaces must resolve the same decision tail identically"
    );
    let batch = on_verification.expect("the tail resolves");
    assert_eq!(
        batch_id_of(&batch),
        tail,
        "the resolved batch must re-identify as the tail that named it"
    );
}

#[test]
fn the_async_reidentification_actually_fires_too() {
    // The presence case on the production surface. Without it, the agreement
    // asserted above is satisfied by two readers that both skip the check.
    let plant = |store: &MemoryAuthorityStore| {
        let head_b = RepositoryAuthorityHeadBody {
            ref_root: digest(0xB0),
            ..genesis_head()
        };
        let key = body_key(IdentityDomain::RepositoryAuthorityHead, &genesis_head())
            .expect("a derivable body key");
        // Genesis is already staged under its own key by `initialize_repository`,
        // so plant into a store that has published nothing.
        assert_eq!(
            store
                .put_if_absent(&key, &encode_body(&head_b).expect("a head body encodes"))
                .expect("the store accepts the write"),
            PutOutcome::Created,
            "the plant must land, or this test proves nothing"
        );
        head_id_of(&head_b)
    };

    let verification_store = store();
    let planted_id = plant(&verification_store);
    let on_verification =
        read_authority_head_body(&verification_store, head_id_of(&genesis_head()));

    let backing = store();
    plant(&backing);
    let view = AsyncView(backing);
    let on_production = poll_ready(read_authority_head_body_async(
        &view,
        &(),
        head_id_of(&genesis_head()),
    ));

    assert_eq!(
        format!("{on_verification:?}"),
        format!("{on_production:?}"),
        "both surfaces must refuse a misfiled body, and refuse it the same way"
    );
    let Err(OutcomeFailure::BodyIdentityMismatch { identities, .. }) = on_production else {
        panic!("the production surface must refuse a misfiled body: {on_production:?}");
    };
    assert_eq!(
        identities.found,
        planted_id.into_internal_object_id(),
        "the refusal must name the body that was actually found"
    );
}

// ---------------------------------------------------------------------------
// frankengit-boet: properties the cumulative outcome index must have, and the
// one it cannot have.
//
// The index is CUMULATIVE (GoldLotus's triangulated ruling): a batch's
// `resulting_outcome_index_root` is the repository's index AFTER that batch,
// not a root over that batch alone. NPC §10 step 4 consults it for duplicate
// detection, which only a repository-wide index can answer.
//
// These two tests pin what that requires of the root function itself. They are
// independent of where the fold eventually lives and of which retention design
// is chosen, because they are properties of `outcome_index_root`.
// ---------------------------------------------------------------------------

/// A refusal outcome must move the root, so a batch that carries its
/// predecessor's root forward unchanged is DETECTABLY wrong.
///
/// This is the `d6nl` defect expressed as a property. Refusals are terminal
/// outcomes: they consume decision sequence and must be findable by NPC §10.4
/// duplicate detection, so they belong in the index exactly as commits do.
/// `fgit-chronicle`'s `carried_forward` currently propagates the predecessor
/// root verbatim for a refusal-only batch, which this property says cannot be
/// right — whatever the eventual fold looks like.
#[test]
fn a_refusal_outcome_moves_the_index_root_so_carrying_it_forward_is_detectable() {
    let before = [entry(0xA1, 1, 0x51)];
    let after = [entry(0xA1, 1, 0x51), refusal_entry(0xB2, 2, 0x62)];

    let root_before = fgit_authority::outcome_index_root(&before).expect("a computable root");
    let root_after = fgit_authority::outcome_index_root(&after).expect("a computable root");

    assert_ne!(
        root_before, root_after,
        "a refusal must advance the cumulative index; if these were equal, \
         carrying the predecessor root forward would be indistinguishable from \
         folding the refusal in, and the d6nl defect would be untestable"
    );

    // The paired permitted case. Without it the assertion above is satisfied by
    // a root function that changes on any call, which would prove nothing about
    // refusals specifically.
    assert_eq!(
        fgit_authority::outcome_index_root(&after).expect("a computable root"),
        root_after,
        "the root must still be a deterministic function of the entry set"
    );
}

/// The root cannot be folded incrementally from its predecessor, and the
/// obvious attempt is refuted here so nobody has to rediscover it.
///
/// `outcome_index_root` sorts leaves by digest before pairing them, so a new
/// leaf's position — and therefore every interior node above it — depends on
/// comparison against the individual existing leaves. The predecessor root is
/// one digest and does not contain them, so no `f(predecessor_root, new)` can
/// reproduce the cumulative root. An append-only construction would admit such
/// a fold; a sorted-set commitment does not, and that is the trade this design
/// made.
///
/// The consequence, recorded on `frankengit-boet`: the fold needs the whole
/// cumulative leaf set, and the only route to historic outcomes — the decision
/// chain walk — is bounded by `MAX_REPLAY_BATCHES`. Whoever lifts that chooses
/// between retaining a materialised leaf set and changing the commitment; both
/// are normative decisions, not implementation details.
#[test]
fn treating_the_predecessor_root_as_a_leaf_does_not_reproduce_the_cumulative_root() {
    let historic = [entry(0xA1, 1, 0x51), entry(0xB2, 2, 0x52)];
    let fresh = entry(0xC3, 3, 0x53);

    let predecessor = fgit_authority::outcome_index_root(&historic).expect("a computable root");

    let cumulative = fgit_authority::outcome_index_root(&[historic[0], historic[1], fresh])
        .expect("a computable root");

    // The naive fold: stand the predecessor root in for everything behind it
    // and combine it with the new entry. This is the shape someone reaches for
    // when the leaves are no longer to hand.
    let folded = fgit_authority::outcome_index_root(&[
        (
            // The predecessor root, standing in for the leaves behind it.
            TxId::from_digest(
                IdentityDomain::RefTransaction.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                *predecessor.bytes(),
            ),
            historic[1].1,
        ),
        fresh,
    ])
    .expect("a computable root");

    assert_ne!(
        cumulative, folded,
        "standing the predecessor root in for its leaves must not reproduce the \
         cumulative root; if it did, the index would admit a shortcut that skips \
         the history it is supposed to commit to"
    );

    // Paired case: the cumulative root IS reproducible from the full leaf set,
    // in any order. So the failure above is specifically the missing leaves,
    // not an unstable root function.
    assert_eq!(
        cumulative,
        fgit_authority::outcome_index_root(&[fresh, historic[1], historic[0],])
            .expect("a computable root"),
        "the cumulative root must be recoverable from the whole leaf set"
    );
}

/// A refusal-shaped entry, so the refusal property above is not silently
/// testing two commits.
fn refusal_entry(tx_byte: u8, sequence: u64, refusal: u8) -> (TxId, TerminalOutcome) {
    (
        tx(tx_byte),
        TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
            outcome: DecisionOutcome::Refused {
                refusal_record_id: refusal_id(refusal),
                code: RefusalCode::QuotaExceeded,
            },
        },
    )
}

// ---------------------------------------------------------------------------
// frankengit-boet: the authority-owned cumulative outcome-index derivation.
//
// The ruling these exercise: `resulting_outcome_index_root` is the repository's
// CUMULATIVE authenticated outcome index after a batch, not a per-batch root,
// because NPC 10 step 4 consults the index DURING transaction handling to ask
// "does this TxId already have a decision" -- a question only a
// repository-wide index answers.
// ---------------------------------------------------------------------------

fn commit_entry(tx_byte: u8, sequence: u64, commit: u8) -> (TxId, TerminalOutcome) {
    (
        tx(tx_byte),
        TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
            outcome: DecisionOutcome::Committed {
                repository_commit_id: commit_id(commit),
            },
        },
    )
}

/// Acceptance (1): the fold IS the recompute over the cumulative leaf set.
///
/// The two negatives are the load-bearing half. Equality with the recompute
/// alone is also satisfied by a fold that ignores one of its arguments, so each
/// argument is shown to matter: the result differs from the carried set's own
/// root (the batch was absorbed) and from the batch's own root (the result is
/// cumulative, not per-batch -- the ruling's actual claim).
#[test]
fn the_fold_is_a_recompute_over_the_cumulative_leaf_set_and_neither_input_alone() {
    let carried = [commit_entry(0xa1, 1, 0xc1), refusal_entry(0xa2, 2, 0xf2)];
    let stamped = [commit_entry(0xa3, 3, 0xc3)];

    let folded = fgit_authority::fold_outcome_index(&carried, &stamped).expect("a computable root");

    let cumulative: Vec<_> = carried.iter().chain(&stamped).copied().collect();
    assert_eq!(
        folded,
        fgit_authority::outcome_index_root(&cumulative).expect("a computable root"),
        "the fold must equal the recompute over the union of carried and stamped entries",
    );

    assert_ne!(
        folded,
        fgit_authority::outcome_index_root(&carried).expect("a computable root"),
        "a fold that ignored the batch would leave the carried root unchanged",
    );
    assert_ne!(
        folded,
        fgit_authority::outcome_index_root(&stamped).expect("a computable root"),
        "a fold that ignored the carried history would publish a per-batch root, \
         which is the reading the boet ruling rejects",
    );
}

/// Acceptance (2), the `frankengit-d6nl` regression stated as a property.
///
/// Refusals are terminal outcomes: they consume decision sequence and must be
/// found by NPC 10.4 duplicate detection, so a refusal-only batch has entries
/// to fold. `ResultingRoots::carried_forward` publishes the predecessor root
/// unchanged for exactly this case. The first assertion is that behaviour being
/// wrong; the second is what should be published instead.
#[test]
fn a_refusal_only_batch_advances_the_root_so_carrying_it_forward_is_wrong() {
    let carried = [commit_entry(0xb1, 1, 0xc1)];
    let refusals_only = [refusal_entry(0xb2, 2, 0xf2), refusal_entry(0xb3, 3, 0xf3)];

    let folded =
        fgit_authority::fold_outcome_index(&carried, &refusals_only).expect("a computable root");
    let carried_forward = fgit_authority::outcome_index_root(&carried).expect("a computable root");

    assert_ne!(
        folded, carried_forward,
        "carrying the predecessor root forward over a refusal-only batch loses \
         both refusal outcomes from the index that NPC 10.4 queries",
    );

    let cumulative: Vec<_> = carried.iter().chain(&refusals_only).copied().collect();
    assert_eq!(
        folded,
        fgit_authority::outcome_index_root(&cumulative).expect("a computable root"),
        "the recompute over commit + both refusals is what the batch should publish",
    );
}

/// Acceptance (3), the half the derivation owns: a transaction decided in a
/// PRIOR batch is visible to the fold, not just one decided in this batch.
///
/// This is NPC 5.2 -- one sealed transaction has at most one terminal decision
/// -- enforced at the structure that has to hold it. The permitted twin is a
/// different `TxId` in the same position, so the refusal is attributable to the
/// repeat rather than to the batch mixing a refusal into a commit history.
#[test]
fn the_fold_refuses_a_transaction_the_carried_index_already_decided() {
    let already_decided = commit_entry(0xd1, 1, 0xc1);
    let carried = [already_decided, commit_entry(0xd2, 2, 0xc2)];

    // Same TxId as the carried entry, offered again with a different decision.
    let redecided = [refusal_entry(0xd1, 3, 0xf3)];
    let failure = fgit_authority::fold_outcome_index(&carried, &redecided)
        .expect_err("a transaction decided twice must not produce a root");

    let OutcomeFailure::DuplicateTerminalDecision { duplicate } = failure else {
        panic!("expected DuplicateTerminalDecision, got {failure:?}");
    };
    assert_eq!(
        duplicate.tx_id,
        tx(0xd1),
        "the refusal must name the transaction that was decided twice",
    );
    assert_eq!(
        duplicate.existing, already_decided.1,
        "`existing` must be the decision already carried in the index",
    );
    assert_eq!(
        duplicate.offered, redecided[0].1,
        "`offered` must be the decision the batch tried to add",
    );

    // The permitted twin: an undecided TxId in the same slot folds cleanly.
    let fresh = [refusal_entry(0xd9, 3, 0xf3)];
    fgit_authority::fold_outcome_index(&carried, &fresh)
        .expect("a transaction with no prior decision folds");
}

/// A repeat WITHIN one batch is the same violation and is refused identically.
///
/// Checked separately because a duplicate scan that only compared the batch
/// against the carried set would pass the test above and miss this.
#[test]
fn the_fold_refuses_a_transaction_repeated_inside_one_batch() {
    let carried = [commit_entry(0xe1, 1, 0xc1)];
    let repeated_in_batch = [refusal_entry(0xe2, 2, 0xf2), commit_entry(0xe2, 3, 0xc3)];

    let failure = fgit_authority::fold_outcome_index(&carried, &repeated_in_batch)
        .expect_err("one transaction cannot hold two decisions in one batch either");
    let OutcomeFailure::DuplicateTerminalDecision { duplicate } = failure else {
        panic!("expected DuplicateTerminalDecision, got {failure:?}");
    };
    assert_eq!(duplicate.tx_id, tx(0xe2));
}

/// Why the duplicate is REFUSED rather than de-duplicated.
///
/// The presence case for the design decision above. `outcome_index_root`
/// commits to a multiset: a repeated leaf is sorted next to its twin and both
/// are hashed, so the repeat is not inert. Dropping it silently would hide an
/// NPC 5.2 violation behind a well-formed root, and keeping it would publish a
/// root committing to a history where one transaction was decided twice.
/// Without this test, "refuse rather than de-duplicate" would read as mere
/// caution instead of the only correct option.
#[test]
fn a_repeated_leaf_changes_the_root_so_de_duplicating_would_not_be_inert() {
    let single = [commit_entry(0xf1, 1, 0xc1)];
    let repeated = [commit_entry(0xf1, 1, 0xc1), commit_entry(0xf1, 1, 0xc1)];

    assert_ne!(
        fgit_authority::outcome_index_root(&single).expect("a computable root"),
        fgit_authority::outcome_index_root(&repeated).expect("a computable root"),
        "identical leaves are not collapsed by the construction, so a duplicate \
         entry is a different commitment rather than a harmless repeat",
    );
}

/// Acceptance (5): the fold observes the STAMPED RCR identity.
///
/// The ordering requirement is that the fold runs after the RCRs are stamped,
/// because the terminal outcome of a commit names the RCR it produced. Mutating
/// only that identity must move the root; if it did not, a fold running BEFORE
/// stamping would produce the same answer and the ordering would be
/// unobservable. The paired equality is the control: two folds over the same
/// stamped identity agree, so the difference is attributable to the mutation
/// and not to an unstable root.
#[test]
fn the_fold_observes_the_stamped_rcr_identity_so_running_it_pre_stamp_is_detectable() {
    let carried = [refusal_entry(0x91, 1, 0xf1)];

    let stamped = [commit_entry(0x92, 2, 0xc2)];
    let restamped = [commit_entry(0x92, 2, 0xc9)];

    let with_stamp = fgit_authority::fold_outcome_index(&carried, &stamped).expect("a root");
    let with_other_stamp =
        fgit_authority::fold_outcome_index(&carried, &restamped).expect("a root");

    assert_ne!(
        with_stamp, with_other_stamp,
        "the RCR identity is the only difference between these batches, so a fold \
         that did not observe it would publish one root for both",
    );
    assert_eq!(
        with_stamp,
        fgit_authority::fold_outcome_index(&carried, &stamped).expect("a root"),
        "the same stamped identity must fold to the same root",
    );
}

/// The walk yields the cumulative leaf set, refusals included.
///
/// `published_repository` decides `tx(0xA1)` committed and `tx(0xB2)` refused
/// in one batch. Both must come back: a refusal consumes decision sequence and
/// must be found by NPC 10.4 duplicate detection, so an index that collected
/// only commits would answer "undecided" for a transaction that was refused --
/// and a caller acting on that would decide it a second time.
#[test]
fn the_walk_collects_every_terminal_outcome_including_refusals() {
    let (store, _) = published_repository();

    let collected = fgit_authority::collect_cumulative_outcomes(&store, &head_slot())
        .expect("a walk within the replay bound");

    assert_eq!(collected.len(), 2, "the batch decided two transactions");

    assert_eq!(
        collected
            .decision_for(tx(0xA1))
            .expect("the committed transaction must be in the cumulative index")
            .outcome,
        DecisionOutcome::Committed {
            repository_commit_id: commit_id(0x51),
        },
    );
    assert_eq!(
        collected
            .decision_for(tx(0xB2))
            .expect("the REFUSED transaction must be in the cumulative index too")
            .outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::QuotaExceeded,
            refusal_record_id: refusal_id(0x52),
        },
    );

    // The permitted twin for the two lookups above: an undecided transaction
    // answers None, so `decision_for` is discriminating rather than always-Some.
    assert!(
        collected.decision_for(tx(0xEE)).is_none(),
        "a transaction with no decision must not be reported as decided",
    );
}

/// A repository with no head has an empty cumulative index, not an error.
///
/// The genesis case is a real answer: `outcome_index_root(&[])` is defined, so
/// the first batch folds against an empty set rather than against nothing. The
/// paired positive above is what stops this test passing for the wrong reason
/// -- an always-empty collector would satisfy this one alone.
#[test]
fn a_repository_with_no_head_has_an_empty_cumulative_index() {
    let store = store();

    let collected = fgit_authority::collect_cumulative_outcomes(&store, &head_slot())
        .expect("an absent head is not a failure");

    assert!(
        collected.is_empty(),
        "nothing has been decided, so nothing is in the index",
    );
}

/// The absent-head set is bound to a token no publication can match.
///
/// Genesis publishes through `initialize_repository`, not a CAS, so there is no
/// head to condition on and the empty set must not be foldable against one.
/// This is the same fail-closed shape as the absent-head witness in
/// `scan_for_existing_decisions`. Without this the empty set would be a
/// universal donor: foldable against any head, which is exactly the
/// wrong-history root the binding exists to prevent.
#[test]
fn the_absent_head_set_cannot_be_folded_against_any_real_head() {
    let empty = fgit_authority::collect_cumulative_outcomes(&store(), &head_slot())
        .expect("an absent head is not a failure");

    let (store, _) = published_repository();
    let real = current_token(&store);

    let failure = empty
        .fold_against(real, &[commit_entry(0xa8, 1, 0x58)])
        .expect_err("the genesis set must not fold against a published head");
    assert!(
        matches!(failure, OutcomeFailure::CumulativeIndexStale { .. }),
        "expected CumulativeIndexStale, got {failure:?}",
    );
}

/// Acceptance (1) and (2) of v3tc: the fold is checked against the basis.
///
/// POSITIVE -- a set collected at `H`, folded against `H`, produces exactly the
/// root a recompute over the union produces.
///
/// FORBIDDEN -- the same set folded against the head that REPLACED `H` is a
/// typed refusal naming both tokens, not a silently wrong root.
///
/// # Why the head is advanced on the same store
///
/// An earlier version of this test built a second `published_repository()` and
/// used its token as the foreign basis. That was vacuous and the guard below
/// caught it: `store()` hardcodes `StoreInstanceId::from_raw(1)`, and both
/// stores then issue the same per-instance sequence, so the two tokens were
/// byte-identical and the "forbidden" fold was folding against its own basis.
///
/// Advancing the head on one store is also the faithful scenario. The hazard is
/// not a set from another repository -- it is a CAS loser: this transaction
/// collected at `H`, another writer published, and the basis moved underneath
/// it. Same store, same repository, new token.
#[test]
fn a_set_collected_at_one_head_refuses_to_fold_against_the_head_that_replaced_it() {
    let (store, head) = published_repository();
    let collected = fgit_authority::collect_cumulative_outcomes(&store, &head_slot())
        .expect("a walk within the replay bound");
    let basis = current_token(&store);
    let stamped = [commit_entry(0xa9, 4, 0x59)];

    // PERMITTED: the head it was collected from.
    let folded = collected
        .fold_against(basis, &stamped)
        .expect("folding against the head it was collected from is the whole point");

    // Another writer wins the CAS and the basis moves.
    let intervening = batch(&head, 3, vec![committed(tx(0xC3), 3, 0x53)]);
    let advanced = successor_head(&head, batch_id_of(&intervening), 3);
    let outcome = publish_decisions(
        &store,
        &head_slot(),
        basis,
        &intervening,
        &advanced,
        tenant(),
    )
    .expect("the intervening publication");
    assert!(
        matches!(outcome, PublicationOutcome::Published(_)),
        "the intervening batch must actually publish or the head never moves",
    );

    let moved = current_token(&store);
    assert_ne!(
        basis, moved,
        "the head must genuinely have moved or the forbidden case below is vacuous",
    );

    // FORBIDDEN: the stale set against the new basis.
    let failure = collected
        .fold_against(moved, &stamped)
        .expect_err("a CAS loser must not fold its stale set against the new basis");
    let OutcomeFailure::CumulativeIndexStale { observed, expected } = failure else {
        panic!("expected CumulativeIndexStale, got {failure:?}");
    };
    assert_eq!(observed, basis, "the refusal must name the head walked");
    assert_eq!(
        expected, moved,
        "the refusal must name the head the caller tried to publish against",
    );

    // The refusal is about the BINDING, not about the entries being wrong: the
    // set really is stale now -- it predates tx(0xC3) -- and a freshly collected
    // set folds against the new basis without complaint.
    let refreshed = fgit_authority::collect_cumulative_outcomes(&store, &head_slot())
        .expect("a walk within the replay bound");
    assert_eq!(
        refreshed.len(),
        3,
        "the refreshed set must include the intervening decision",
    );
    refreshed
        .fold_against(moved, &stamped)
        .expect("re-collecting per basis read is the correct CAS-loser response");

    // And the permitted half produced the right value, so the refusal above is
    // the binding firing rather than the fold being broken.
    let mut union = vec![
        (
            tx(0xA1),
            TerminalOutcome {
                decision_sequence: DecisionSequence::try_new(1).expect("positive"),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: commit_id(0x51),
                },
            },
        ),
        refusal_entry(0xB2, 2, 0x52),
    ];
    union.extend_from_slice(&stamped);
    assert_eq!(
        folded,
        fgit_authority::outcome_index_root(&union).expect("a computable root"),
    );
}

/// Re-deciding a transaction the walked history already decided is refused.
///
/// Acceptance (3) of boet reached through the real walk: the transaction was
/// decided in a PRIOR batch, recovered from the authenticated stream, and the
/// fold sees it. The permitted twin is a fresh `TxId` through the identical
/// path.
#[test]
fn a_transaction_decided_in_a_prior_batch_is_caught_through_the_real_walk() {
    let (store, _) = published_repository();
    let collected = fgit_authority::collect_cumulative_outcomes(&store, &head_slot())
        .expect("a walk within the replay bound");
    let basis = current_token(&store);

    // `tx(0xB2)` was REFUSED in the published batch. Offering it again --
    // committed this time -- is the two-terminal-decisions violation.
    let failure = collected
        .fold_against(basis, &[commit_entry(0xB2, 3, 0x53)])
        .expect_err("a transaction decided in a prior batch cannot be decided again");
    let OutcomeFailure::DuplicateTerminalDecision { duplicate } = failure else {
        panic!("expected DuplicateTerminalDecision, got {failure:?}");
    };
    assert_eq!(duplicate.tx_id, tx(0xB2));
    assert_eq!(
        duplicate.existing.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::QuotaExceeded,
            refusal_record_id: refusal_id(0x52),
        },
        "the decision recovered from the stream is the one that must be reported",
    );

    collected
        .fold_against(basis, &[commit_entry(0xc7, 3, 0x53)])
        .expect("an undecided transaction folds through the same path");
}

/// The two collector surfaces agree over identically-published history.
///
/// Equivalence is the point: `fgit-node`'s publication path is asynchronous, so
/// if the two walks could disagree the root published in production would
/// differ from the one every synchronous test asserts. Driven over separately
/// constructed stores rather than one shared store, so agreement is a property
/// of the two implementations rather than of a single traversal.
///
/// The length assertion is load-bearing. Two empty sets compare equal, so
/// without it this test passes if BOTH collectors are broken in the same
/// direction -- the likelier failure, since they were written from one
/// template.
#[test]
fn the_two_collector_surfaces_agree_over_the_same_published_history() {
    let (sync_store, _) = published_repository();
    let baseline = fgit_authority::collect_cumulative_outcomes(&sync_store, &head_slot())
        .expect("a walk within the replay bound");

    let (async_store, _) = published_repository();
    let async_basis = current_token(&async_store);
    let view = AsyncView(async_store);
    let mirrored = poll_ready(fgit_authority::collect_cumulative_outcomes_async(
        &view,
        &(),
        &head_slot(),
    ))
    .expect("a walk within the replay bound");

    assert_eq!(
        baseline.len(),
        2,
        "the published batch decided two transactions; an empty result would make \
         the comparisons below vacuous",
    );
    assert_eq!(
        baseline.decision_for(tx(0xB2)),
        mirrored.decision_for(tx(0xB2)),
        "both walks must recover the same decision for the same transaction",
    );

    // The tokens differ because the stores differ, so the sets are NOT equal as
    // values -- which is correct and is why the roots are compared through each
    // set's own basis rather than by comparing the structs.
    let stamped = [commit_entry(0xd5, 3, 0x55)];
    assert_eq!(
        baseline
            .fold_against(current_token(&sync_store), &stamped)
            .expect("a root"),
        mirrored
            .fold_against(async_basis, &stamped)
            .expect("a root"),
        "the asynchronous walk must fold to the same root as the synchronous one, \
         or production publishes a different root than the tests assert",
    );
}

/// Both surfaces agree that an absent head is an empty index.
///
/// The early return is written separately in each twin rather than shared, so
/// it is the kind of thing a port silently gets wrong: an error where the other
/// returns empty would fail genesis publication on the asynchronous path only.
#[test]
fn the_two_collector_surfaces_agree_that_an_absent_head_is_an_empty_index() {
    let baseline = fgit_authority::collect_cumulative_outcomes(&store(), &head_slot())
        .expect("an absent head is not a failure");
    let view = AsyncView(store());
    let mirrored = poll_ready(fgit_authority::collect_cumulative_outcomes_async(
        &view,
        &(),
        &head_slot(),
    ))
    .expect("an absent head is not a failure on the async surface either");

    assert!(
        baseline.is_empty(),
        "an unpublished repository has decided nothing",
    );
    assert_eq!(
        baseline, mirrored,
        "both surfaces mint the same zero-token empty set",
    );
}

// The checkpoint collector is an independently written asynchronous traversal,
// so the sync refusal matrix above does not exercise these branches.  Each
// case names one guard: the payload-less position refusal alone cannot show
// which of its two failure sites was reached.

#[test]
fn async_checkpoint_collector_refuses_same_tail_with_a_different_sequence() {
    let (store, head) = published_repository();
    let view = AsyncView(store);

    assert!(matches!(
        poll_ready(
            fgit_authority::collect_cumulative_outcomes_from_checkpoint_async(
                &view,
                &(),
                &head_slot(),
                &[],
                head.decision_tail_id,
                None,
            )
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn async_checkpoint_collector_refuses_when_no_batch_precedes_the_checkpoint() {
    let store = store();
    let genesis = genesis_head();
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis initializes");
    let unreachable_tail = batch_id_of(&batch(&genesis, 1, vec![committed(tx(0xE1), 1, 0x61)]));
    let view = AsyncView(store);

    assert!(matches!(
        poll_ready(
            fgit_authority::collect_cumulative_outcomes_from_checkpoint_async(
                &view,
                &(),
                &head_slot(),
                &[],
                Some(unreachable_tail),
                None,
            )
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn async_checkpoint_collector_refuses_a_tail_outside_the_head_ancestry() {
    let (store, head) = published_repository();
    let unreachable_tail = batch_id_of(&batch(
        &genesis_head(),
        3,
        vec![committed(tx(0xE2), 3, 0x62)],
    ));
    let view = AsyncView(store);

    assert!(matches!(
        poll_ready(
            fgit_authority::collect_cumulative_outcomes_from_checkpoint_async(
                &view,
                &(),
                &head_slot(),
                &[],
                Some(unreachable_tail),
                head.latest_decision_sequence,
            )
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn async_checkpoint_collector_refuses_position_matched_wrong_leaves() {
    let (store, head) = published_repository();
    let view = AsyncView(store);

    assert!(matches!(
        poll_ready(
            fgit_authority::collect_cumulative_outcomes_from_checkpoint_async(
                &view,
                &(),
                &head_slot(),
                &[],
                head.decision_tail_id,
                head.latest_decision_sequence,
            )
        ),
        Err(OutcomeFailure::CheckpointRootMismatch)
    ));
}

// ---------------------------------------------------------------------------
// frankengit-w95j: the replay bound.
//
// `MAX_REPLAY_BATCHES` is the declared denial-of-service bound on backwards
// decision-chain replay -- "an unbounded backwards walk over an adversarial or
// corrupt chain is a denial-of-service surface" (outcome.rs). Until these
// tests it was exercised by nothing in the workspace: the only occurrence
// outside `src/` was a prose doc comment.
//
// It is also the premise the whole cumulative-index design rests on. The claim
// made repeatedly for `collect_cumulative_outcomes` is that past the bound the
// walk REFUSES rather than truncating, because a short leaf set does not
// produce a short root -- it produces a wrong root indistinguishable from a
// right one, committed to a canonical body field. That argument requires the
// refusal to fire, and to fire in the right place.
//
// The bound looked expensive to test (a 65,537-batch chain). It is not:
// `next_batch_to_replay` takes `walked: &mut usize`, so the counter can be
// seeded at the boundary directly.
// ---------------------------------------------------------------------------

/// A head that HAS a decision tail, so the walk reaches the bound check.
///
/// Load-bearing: the tail check precedes the bound check, so a tail-less head
/// would return `Ok(None)` and these tests would pass while proving nothing.
/// That ordering is itself pinned below.
fn head_with_a_tail() -> RepositoryAuthorityHeadBody {
    let genesis = genesis_head();
    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    successor_head(&genesis, batch_id_of(&first), 1)
}

/// Acceptance (1): the bound refuses, and names the bound it enforced.
///
/// The `limit` assertion is not decoration. A refusal that fires at the right
/// time but reports some other number would satisfy a variant-only check while
/// telling an operator the wrong thing about why their replay stopped.
#[test]
fn the_replay_bound_refuses_once_the_walk_passes_max_replay_batches() {
    let head = head_with_a_tail();
    let mut walked = fgit_authority::MAX_REPLAY_BATCHES;

    let failure = fgit_authority::next_batch_to_replay(&head, &mut walked)
        .expect_err("the walk must refuse rather than return a partial answer");

    let OutcomeFailure::ReplayBoundExceeded { limit } = failure else {
        panic!("expected ReplayBoundExceeded, got {failure:?}");
    };
    assert_eq!(
        limit,
        fgit_authority::MAX_REPLAY_BATCHES,
        "the refusal must report the bound it actually enforced",
    );
}

/// Acceptance (2): the permitted twin, at the exact boundary the comparison
/// flips on.
///
/// The check is `*walked > MAX_REPLAY_BATCHES` AFTER an increment, so entering
/// at `MAX - 1` becomes exactly `MAX` and is the LAST permitted batch. This is
/// the case a `>` -> `>=` slip breaks, and it is what makes the refusal above
/// evidence of a bound rather than evidence of a refusal: without it the bound
/// could be off by one in the conservative direction and nothing would notice.
#[test]
fn the_last_batch_inside_the_replay_bound_is_permitted() {
    let head = head_with_a_tail();
    let expected_tail = head.decision_tail_id.expect("the fixture head has a tail");
    let mut walked = fgit_authority::MAX_REPLAY_BATCHES - 1;

    let next = fgit_authority::next_batch_to_replay(&head, &mut walked)
        .expect("the batch at exactly the bound is inside it");

    assert_eq!(
        next,
        Some(expected_tail),
        "the permitted case must return the tail, not merely avoid refusing",
    );
    assert_eq!(
        walked,
        fgit_authority::MAX_REPLAY_BATCHES,
        "the walk admits exactly MAX_REPLAY_BATCHES batches",
    );
}

/// Acceptance (3): a chain that ends naturally is not a bound violation.
///
/// The tail check runs BEFORE the increment and before the bound check, so a
/// head with no `decision_tail_id` terminates the walk cleanly even with the
/// counter already past the bound. Swapping those two blocks would turn every
/// exhausted chain into a `ReplayBoundExceeded`, reporting a denial-of-service
/// refusal for an ordinary genesis walk. Nothing else pins that order.
#[test]
fn a_chain_that_ends_is_not_reported_as_exceeding_the_bound() {
    let genesis = genesis_head();
    assert!(
        genesis.decision_tail_id.is_none(),
        "the fixture must have no tail or this test proves nothing",
    );
    let mut walked = fgit_authority::MAX_REPLAY_BATCHES + 1_000;

    let next = fgit_authority::next_batch_to_replay(&genesis, &mut walked)
        .expect("an exhausted chain terminates; it does not exceed the bound");

    assert_eq!(next, None, "the walk is over");
    assert_eq!(
        walked,
        fgit_authority::MAX_REPLAY_BATCHES + 1_000,
        "a terminating walk must not consume budget it never spent",
    );
}

/// Acceptance (4): the counter saturates rather than wrapping.
///
/// `saturating_add` is load-bearing. With `wrapping_add`, a counter at
/// `usize::MAX` would roll to 0 and the walk would happily continue -- the
/// bound defeated by the one input most likely to arrive from a corrupt or
/// adversarial chain, which is the case the bound exists for.
#[test]
fn a_saturated_walk_counter_still_refuses_rather_than_wrapping_past_the_bound() {
    let head = head_with_a_tail();
    let mut walked = usize::MAX;

    let failure = fgit_authority::next_batch_to_replay(&head, &mut walked)
        .expect_err("a saturated counter is far past the bound");
    assert!(
        matches!(failure, OutcomeFailure::ReplayBoundExceeded { .. }),
        "expected ReplayBoundExceeded, got {failure:?}",
    );
    assert_eq!(
        walked,
        usize::MAX,
        "the counter saturates; wrapping to 0 here would defeat the bound entirely",
    );
}

/// The publication primitive is reachable by callers other than
/// `publish_decisions`, so the BACKEND must hold the same rule the protocol
/// layer does: two bodies for one key inside ONE atomic call are either
/// byte-identical or a closed refusal. The fsqlite backend already refuses
/// (`PutOutcome::Conflict` on the second write); this pins the reference
/// backend to the same semantics so the two cannot diverge on malformed
/// input. Driven through a delegating wrapper because the absence witness is
/// minted inside the duplicate walk; the wrapper forwards that real witness
/// untouched and only changes the entry slice after that witness exists.
#[derive(Clone, Copy)]
enum DuplicateInjection {
    /// Repeat the canonical entry without changing a byte.
    Identical,
    /// Repeat the entry after changing its final byte.
    Conflicting,
}

struct OutcomeInjector {
    store: MemoryAuthorityStore,
    injection: DuplicateInjection,
}

impl AuthorityStore for OutcomeInjector {
    fn instance_id(&self) -> StoreInstanceId {
        self.store.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.store.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.store.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.store.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.store.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.store.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.store
            .compare_exchange_head(key, expected, new_generation, new_body)
    }

    fn publish_head_with_outcomes(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        let mut injected = outcomes.to_vec();
        if let Some((first_key, first_bytes)) = injected.first().cloned() {
            let duplicate = match self.injection {
                DuplicateInjection::Identical => first_bytes,
                DuplicateInjection::Conflicting => {
                    let mut flipped = first_bytes;
                    let last = flipped.len() - 1;
                    flipped[last] ^= 0xff;
                    flipped
                }
            };
            injected.push((first_key, duplicate));
        }
        self.store.publish_head_with_outcomes(
            key,
            expected,
            new_generation,
            new_body,
            &injected,
            witness,
        )
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.store.authenticate_head_receipt(receipt)
    }
}

#[test]
fn the_reference_backend_refuses_conflicting_duplicate_keys_in_one_call() {
    let injector = OutcomeInjector {
        store: store(),
        injection: DuplicateInjection::Conflicting,
    };
    let genesis = genesis_head();
    initialize_repository(&injector, &head_slot(), &genesis).expect("genesis");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 2);
    let HeadRead::Present(receipt) = injector.read_head(&head_slot()).expect("a readable head")
    else {
        panic!("genesis must be published");
    };
    let failure = publish_decisions(
        &injector,
        &head_slot(),
        receipt.token(),
        &first,
        &head,
        tenant(),
    )
    .expect_err("conflicting duplicates inside one call must fail closed");
    assert!(
        matches!(
            &failure,
            OutcomeFailure::Seal(inner)
                if matches!(inner.as_ref(), fgit_authority::SealFailure::Store(refused)
                    if matches!(refused, fgit_authority::AuthorityFailure::Refused(
                        fgit_authority::AuthorityRefusal::TokenBodyMismatch
                    )))
        ) || matches!(&failure, OutcomeFailure::AcceleratorConflict { .. }),
        "the primitive refusal must surface as the accelerator-conflict shape, got {failure:?}"
    );
}

/// The permitted twin of the conflicting injection above.  Repeating exactly
/// the same key and canonical bytes is an idempotent retry, not a second
/// terminal decision.  This reaches the backend primitive through the same
/// real duplicate-absence witness, so accepting it proves duplicate handling
/// did not regress into a blanket refusal.
#[test]
fn the_reference_backend_deduplicates_identical_keys_in_one_call() {
    let injector = OutcomeInjector {
        store: store(),
        injection: DuplicateInjection::Identical,
    };
    let genesis = genesis_head();
    initialize_repository(&injector, &head_slot(), &genesis).expect("genesis");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1), 1, 0x51)]);
    let head = successor_head(&genesis, batch_id_of(&first), 1);
    let HeadRead::Present(receipt) = injector.read_head(&head_slot()).expect("a readable head")
    else {
        panic!("genesis must be published");
    };
    let publication = publish_decisions(
        &injector,
        &head_slot(),
        receipt.token(),
        &first,
        &head,
        tenant(),
    )
    .expect("an identical duplicate is an idempotent primitive retry");
    assert!(
        matches!(publication, PublicationOutcome::Published(ref batch) if batch.indexed == 1),
        "the duplicate must collapse to one canonical accelerator entry, got {publication:?}",
    );
    assert_eq!(
        indexed_outcome(&injector, tenant(), repository(), tx(0xA1))
            .expect("the single canonical entry is readable"),
        OutcomeLookup::Decided(TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome: DecisionOutcome::Committed {
                repository_commit_id: commit_id(0x51),
            },
        }),
        "the primitive must retain the original decision rather than a duplicate",
    );
}
