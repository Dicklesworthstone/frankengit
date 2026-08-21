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
    ImmutableRead, PutOutcome, publish_decisions_async,
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
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
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
fn stale_token(store: &MemoryAuthorityStore) -> AuthorityVersionToken {
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
