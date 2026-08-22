//! Reading an authority body by the identity that names it.
//!
//! A consumer holding an authenticated head has two identities it cannot use:
//! `decision_tail_id` and `predecessor_head_id`. Turning either into a body
//! means knowing the `fg/body/v1/` key convention, and until now that
//! convention was private — so the only way to walk the stream from outside
//! this crate was to reconstruct the derivation and hope it kept agreeing.
//! `read_authority_head_body` and `read_decision_batch_body` (and their async
//! twins) exist so nobody has to.
//!
//! # The property these readers add over `read_immutable` + `decode_body`
//!
//! The key is derived from the body's own canonical identity, so a read is a
//! request for *the bytes that hash to this*. These readers hold the store to
//! that: the decoded body is re-identified and must equal the identity asked
//! for. Bytes that decode to something else are refused, not returned.
//!
//! Without the check, §4's "a decoder result accepted without original
//! commitments" is exactly what a caller gets, and on the replay path a walk
//! that believes it is proving one repository's decision stream could be
//! reading another's.
//!
//! # The async twins are tested in `outcome_index.rs`
//!
//! Not here, and not because they matter less. The only `AsyncAuthorityStore`
//! implementation in this crate's tests lives in that file, and copying ninety
//! lines of delegation to keep the two surfaces' tests adjacent would create a
//! second fixture free to drift from the first — the defect this bead's
//! re-identification check exists to prevent, reproduced in the test suite.

use fgit_authority::{
    AuthorityStore, CasOutcome, HeadRead, IdentityDisagreement, MemoryAuthorityStore,
    OutcomeFailure, OutcomeLookup, PublicationOutcome, PutOutcome, StoreInstanceId, body_key,
    canonical_body_id, initialize_repository, publish_decisions, read_authority_head_body,
    read_decision_batch_body, replay_outcome,
};
use fgit_authority::{HeadKey, ImmutableKey};
use fgit_codec::wire::encode_body;
use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId,
    TenantId, TxId,
};
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::vocabulary::DecisionOutcome;

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

/// A genesis head whose `ref_root` is `marker`, so two of them differ.
fn genesis_head(marker: u8) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(marker),
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

/// A batch against `predecessor` whose `batch_evidence_root` is `marker`.
fn batch(
    predecessor: &RepositoryAuthorityHeadBody,
    marker: u8,
    decisions: Vec<RepositoryDecision>,
) -> RepositoryDecisionBatchBody {
    RepositoryDecisionBatchBody {
        repository_id: repository(),
        predecessor_head_id: head_id_of(predecessor),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::try_new(1).expect("positive"),
        decisions,
        committed_rcrs: Vec::new(),
        resulting_ref_root: digest(1),
        resulting_forge_position_root: digest(1),
        resulting_outcome_index_root: digest(1),
        resulting_retention_root: digest(1),
        resulting_outbox_root: digest(1),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(marker),
    }
}

fn committed(tx_id: TxId) -> RepositoryDecision {
    RepositoryDecision {
        tx_id,
        decision_sequence: DecisionSequence::try_new(1).expect("positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(0x51),
        },
    }
}

fn successor_head(
    predecessor: &RepositoryAuthorityHeadBody,
    tail: RepositoryDecisionBatchId,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        generation: HeadGeneration::try_new(predecessor.generation.get() + 1).expect("positive"),
        predecessor_head_id: Some(head_id_of(predecessor)),
        decision_tail_id: Some(tail),
        latest_decision_sequence: Some(DecisionSequence::try_new(1).expect("positive")),
        ..predecessor.clone()
    }
}

/// Genesis plus one published batch, and the batch that was published.
fn published() -> (
    MemoryAuthorityStore,
    RepositoryAuthorityHeadBody,
    RepositoryDecisionBatchBody,
    RepositoryAuthorityHeadBody,
) {
    let store = store();
    let genesis = genesis_head(0);
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis publishes");

    let first = batch(&genesis, 1, vec![committed(tx(0xA1))]);
    let head = successor_head(&genesis, batch_id_of(&first));
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
    .expect("publication succeeds");
    assert!(
        matches!(outcome, PublicationOutcome::Published(_)),
        "the fixture must actually publish"
    );
    (store, genesis, first, head)
}

/// The immutable slot a head body occupies, by the crate's public derivation.
fn head_slot_key(head: &RepositoryAuthorityHeadBody) -> ImmutableKey {
    body_key(IdentityDomain::RepositoryAuthorityHead, head).expect("a derivable body key")
}

/// The immutable slot a batch body occupies, by the crate's public derivation.
fn batch_slot_key(batch: &RepositoryDecisionBatchBody) -> ImmutableKey {
    body_key(IdentityDomain::RepositoryDecisionBatch, batch).expect("a derivable body key")
}

// ---------------------------------------------------------------------------
// The permitted cases
// ---------------------------------------------------------------------------

#[test]
fn a_staged_head_body_reads_back_by_its_identity() {
    // This also pins the two key derivations against each other, which is why
    // there is no separate test for that. Publication stages the body under
    // `body_key(domain, body)`; the reader looks under `body_key_for_id(id)`.
    // They are different functions over different inputs. If they ever stopped
    // agreeing this test would fail as StreamBodyMissing, not as a wrong body.
    let (store, genesis, _, head) = published();

    let read = read_authority_head_body(&store, head_id_of(&head)).expect("the published head");
    assert_eq!(
        read, head,
        "the reader must return the body that was staged"
    );

    let read_genesis =
        read_authority_head_body(&store, head_id_of(&genesis)).expect("the genesis head");
    assert_eq!(
        read_genesis, genesis,
        "the predecessor must be reachable too; a walk that can only read the tip cannot walk"
    );
}

#[test]
fn a_staged_batch_body_reads_back_by_its_identity() {
    let (store, _, first, _) = published();

    let read = read_decision_batch_body(&store, batch_id_of(&first)).expect("the published batch");
    assert_eq!(
        read, first,
        "the reader must return the batch that was staged"
    );
    assert_eq!(
        read.decisions.len(),
        1,
        "the decisions must survive the round trip; they are what a consumer resolving \
         decision_tail_id came for"
    );
}

#[test]
fn the_authenticated_heads_decision_tail_resolves_through_the_public_reader() {
    // The whole point, end to end: authenticate a head, take the identity it
    // names, and get the batch — without the caller knowing any key convention.
    let (store, _, first, _) = published();

    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("the fixture publishes a head");
    };
    let authenticated = store
        .authenticate_head_receipt(&receipt)
        .expect("the store authenticates its own receipt");
    let body = authenticated
        .body()
        .expect("an authenticated head decodes to its body");
    let tail = body
        .decision_tail_id
        .expect("a published head names its decision tail");

    let resolved = read_decision_batch_body(&store, tail).expect("the tail resolves");
    assert_eq!(
        resolved, first,
        "the batch reached through the authenticated head must be the one published"
    );
}

// ---------------------------------------------------------------------------
// The refusals, each paired with the permitted case above
// ---------------------------------------------------------------------------

#[test]
fn an_unstaged_body_refuses_as_missing_rather_than_defaulting() {
    let (store, _, _, _) = published();
    // A head that exists as a value but was never staged.
    let never_staged = genesis_head(0xEE);

    let failure = read_authority_head_body(&store, head_id_of(&never_staged))
        .expect_err("a body that was never staged must refuse");

    assert!(
        matches!(
            failure,
            OutcomeFailure::StreamBodyMissing { link: "head body" }
        ),
        "an absent body must refuse as StreamBodyMissing; got {failure:?}"
    );
}

#[test]
fn undecodable_bytes_refuse_as_codec_rather_than_panicking() {
    let store = store();
    let head = genesis_head(0);
    assert_eq!(
        store
            .put_if_absent(&head_slot_key(&head), b"not a head body")
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the plant must land, or this test proves nothing"
    );

    let failure = read_authority_head_body(&store, head_id_of(&head))
        .expect_err("bytes that are not a head body must be refused, not decoded");

    assert!(
        matches!(failure, OutcomeFailure::Codec(_)),
        "undecodable bytes must refuse as Codec; got {failure:?}"
    );
}

#[test]
fn the_head_reidentification_actually_fires() {
    // The presence case for the check itself.
    //
    // Every assertion above is satisfied by a reader that decodes and returns
    // whatever it found, because in those tests the slot always holds the right
    // body. This is the test that separates the two: a slot filed under head
    // A's identity that actually contains head B.
    //
    // It models a corrupted slot, a backend that resolved a key loosely, or an
    // identity handed in from another repository. The reader must not care
    // which — it asked for the bytes that hash to A and did not get them.
    let store = store();
    let head_a = genesis_head(0xA0);
    let head_b = genesis_head(0xB0);
    assert_ne!(
        head_id_of(&head_a),
        head_id_of(&head_b),
        "the two fixtures must have distinct identities, or the plant is not a mismatch"
    );

    // B's bytes, filed under A's key.
    assert_eq!(
        store
            .put_if_absent(
                &head_slot_key(&head_a),
                &encode_body(&head_b).expect("a head body encodes"),
            )
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the plant must land, or this test proves nothing"
    );

    let failure = read_authority_head_body(&store, head_id_of(&head_a))
        .expect_err("bytes that decode to a different head must be refused, not returned");

    assert_eq!(
        failure,
        OutcomeFailure::BodyIdentityMismatch {
            link: "head body",
            identities: Box::new(IdentityDisagreement {
                requested: head_id_of(&head_a).into_internal_object_id(),
                found: head_id_of(&head_b).into_internal_object_id(),
            }),
        },
        "the refusal must name both identities: an operator who cannot see which body was found \
         cannot tell a corrupted slot from a caller passing an identity from another repository"
    );
}

#[test]
fn the_batch_reidentification_actually_fires() {
    // The same presence case on the other surface. Stated separately because
    // the two readers re-identify through different domain-pinned derivations,
    // and a check that held for heads and silently lapsed for batches would be
    // invisible to a test of heads alone.
    let store = store();
    let genesis = genesis_head(0);
    let batch_a = batch(&genesis, 0xA0, vec![committed(tx(0xA1))]);
    let batch_b = batch(&genesis, 0xB0, vec![committed(tx(0xB2))]);
    assert_ne!(
        batch_id_of(&batch_a),
        batch_id_of(&batch_b),
        "the two fixtures must have distinct identities, or the plant is not a mismatch"
    );

    assert_eq!(
        store
            .put_if_absent(
                &batch_slot_key(&batch_a),
                &encode_body(&batch_b).expect("a batch body encodes"),
            )
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the plant must land, or this test proves nothing"
    );

    let failure = read_decision_batch_body(&store, batch_id_of(&batch_a))
        .expect_err("bytes that decode to a different batch must be refused, not returned");

    let OutcomeFailure::BodyIdentityMismatch { link, identities } = failure else {
        panic!("a misfiled batch must refuse as BodyIdentityMismatch; got {failure:?}");
    };
    assert_eq!(link, "decision batch", "the refusal must name the link");
    assert_eq!(
        *identities,
        IdentityDisagreement {
            requested: batch_id_of(&batch_a).into_internal_object_id(),
            found: batch_id_of(&batch_b).into_internal_object_id(),
        },
        "the refusal must name both identities"
    );
}

#[test]
fn the_mismatch_refusal_renders_both_identities() {
    // The Display impl is the operator-facing half of the refusal. A message
    // that dropped one side would leave "these two disagree" with only one of
    // them, which is the shape of an error nobody can act on.
    let head_a = genesis_head(0xA0);
    let head_b = genesis_head(0xB0);
    let rendered = OutcomeFailure::BodyIdentityMismatch {
        link: "head body",
        identities: Box::new(IdentityDisagreement {
            requested: head_id_of(&head_a).into_internal_object_id(),
            found: head_id_of(&head_b).into_internal_object_id(),
        }),
    }
    .to_string();

    assert!(
        rendered.contains(&head_id_of(&head_a).to_string()),
        "the message must name the requested identity: {rendered}"
    );
    assert!(
        rendered.contains(&head_id_of(&head_b).to_string()),
        "the message must name the identity actually found: {rendered}"
    );
    assert!(
        rendered.contains("head body"),
        "the message must name the link being resolved: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// The check is on the replay path, not only behind the new entry points
// ---------------------------------------------------------------------------
//
// `read_decision_batch_body` is shared: `replay_outcome` resolves every batch
// through it. So publishing these readers did not only add a surface, it
// strengthened an existing one — and a strengthening asserted in a commit
// message and nowhere else is a claim, not a property.
//
// These two cases execute it. They are the difference between "the branch
// exists" and "the branch is reachable from the function that matters".

/// Genesis, then a head whose decision tail names `named` while the slot for
/// that identity holds `stored`.
///
/// With the same batch twice this is an ordinary published history. With two
/// different batches it is a misfiled slot: the head commits to `named`, and
/// the store hands back `stored` when asked for it.
fn repository_whose_tail_slot_holds(
    named: &RepositoryDecisionBatchBody,
    stored: &RepositoryDecisionBatchBody,
) -> MemoryAuthorityStore {
    let store = store();
    let genesis = genesis_head(0);
    initialize_repository(&store, &head_slot(), &genesis).expect("genesis publishes");

    // The tail slot, filled before the head points at it.
    assert_eq!(
        store
            .put_if_absent(
                &batch_slot_key(named),
                &encode_body(stored).expect("a batch body encodes"),
            )
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the tail slot must be the one this fixture wrote"
    );

    let head = successor_head(&genesis, batch_id_of(named));
    let head_bytes = encode_body(&head).expect("a head body encodes");
    assert_eq!(
        store
            .put_if_absent(&head_slot_key(&head), &head_bytes)
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the successor head body must be staged, or the walk cannot resolve it"
    );

    let HeadRead::Present(receipt) = store.read_head(&head_slot()).expect("a readable head") else {
        panic!("genesis must be published");
    };
    let advanced = store
        .compare_exchange_head(&head_slot(), receipt.token(), head.generation, &head_bytes)
        .expect("the store accepts the exchange");
    assert!(
        matches!(advanced, CasOutcome::Committed(_)),
        "the fixture must advance the head, or replay walks the genesis tip: {advanced:?}"
    );
    store
}

#[test]
fn replay_resolves_a_correctly_filed_tail_and_answers_from_it() {
    // The permitted case, and the control for the one below. It fixes what a
    // sound history says about BOTH transactions: 0xA1 is in the tail and
    // decided, 0xB2 is in no batch this head commits to and is undecided.
    let genesis = genesis_head(0);
    let batch_a = batch(&genesis, 0xA0, vec![committed(tx(0xA1))]);
    let store = repository_whose_tail_slot_holds(&batch_a, &batch_a);

    assert!(
        matches!(
            replay_outcome(&store, &head_slot(), tx(0xA1)).expect("the walk completes"),
            OutcomeLookup::Decided(_)
        ),
        "the transaction the tail decides must replay as decided"
    );
    assert_eq!(
        replay_outcome(&store, &head_slot(), tx(0xB2)).expect("the walk completes"),
        OutcomeLookup::Undecided,
        "a transaction this history never decided must replay as undecided"
    );
}

#[test]
fn a_misfiled_tail_makes_replay_refuse_instead_of_answering_from_the_wrong_batch() {
    // The consequence, stated as the canonical-state violation it is.
    //
    // The head commits to batch A. The slot for A's identity holds batch B,
    // which decides tx(0xB2) — a transaction the control above proves this
    // history does NOT decide. A replay that decoded without re-identifying
    // would walk to B, find 0xB2, and return Decided: §5.1 truth invented from
    // bytes the authority head never committed to, reported to a caller with
    // no way to tell.
    let genesis = genesis_head(0);
    let batch_a = batch(&genesis, 0xA0, vec![committed(tx(0xA1))]);
    let batch_b = batch(&genesis, 0xB0, vec![committed(tx(0xB2))]);
    let store = repository_whose_tail_slot_holds(&batch_a, &batch_b);

    let failure = replay_outcome(&store, &head_slot(), tx(0xB2))
        .expect_err("replay must refuse a tail whose bytes are a different batch");

    assert_eq!(
        failure,
        OutcomeFailure::BodyIdentityMismatch {
            link: "decision batch",
            identities: Box::new(IdentityDisagreement {
                requested: batch_id_of(&batch_a).into_internal_object_id(),
                found: batch_id_of(&batch_b).into_internal_object_id(),
            }),
        },
        "replay must refuse with the identity disagreement, naming both sides"
    );
}
