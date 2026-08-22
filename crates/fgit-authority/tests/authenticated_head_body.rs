//! `AuthenticatedHead::body()` — the decode-and-cross-check that used to be the
//! caller's problem.
//!
//! Authentication proves the store issued a receipt. It does **not** prove the
//! bytes inside describe the head that receipt names, so a caller who decodes
//! without comparing generations can act on a body one generation away from the
//! head it just authenticated — and §5.1 admits only the exact predecessor.
//!
//! `fgit-admission` performs that comparison today, correctly, in its own
//! fifteen lines. The reader FG-028a is blocked on would have been the second
//! copy. Two implementations of "what does this head say" are free to disagree,
//! which is `frankengit-0kqi` one crate over.
//!
//! Every check here that asserts a refusal is paired with the permitted case,
//! and the cross-check is shown *firing* rather than merely being present.

use fgit_authority::{
    AuthenticatedHead, AuthorityVersionToken, HeadBodyRefusal, HeadKey, HeadReadReceipt,
    StoreInstanceId, VERSION_TOKEN_BYTES,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_codec::wire::encode_body;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryId;
use fgit_types::numeric::HeadGeneration;
use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::RepositoryAuthorityHead
            .algorithm()
            .id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

/// A head body at `generation`, with a recognisable `ref_root`.
fn head_at(generation: HeadGeneration, ref_root: u8) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(ref_root),
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

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

const fn token() -> AuthorityVersionToken {
    AuthorityVersionToken::from_opaque_bytes([3_u8; VERSION_TOKEN_BYTES])
}

/// An authenticated head whose receipt claims `receipt_generation` while its
/// body carries `body_generation`.
fn authenticated(
    receipt_generation: HeadGeneration,
    body: &RepositoryAuthorityHeadBody,
) -> AuthenticatedHead {
    let bytes = encode_body(body).expect("a head body encodes");
    AuthenticatedHead::new(
        HeadReadReceipt::new(head_key(), token(), receipt_generation, bytes),
        StoreInstanceId::from_raw(1),
    )
}

#[test]
fn an_authenticated_head_reads_back_as_its_typed_body() {
    // The permitted case. Without it, every refusal below would be satisfied by
    // an accessor that refused everything.
    let generation = HeadGeneration::try_new(4).expect("a small generation is admissible");
    let expected = head_at(generation, 9);

    let body = authenticated(generation, &expected)
        .body()
        .expect("a head whose receipt and body agree must decode");

    assert_eq!(
        body, expected,
        "the decoded body must be the one that was encoded"
    );
    assert_eq!(
        body.ref_root,
        digest(9),
        "ref_root must survive the round trip; it is the field FG-028a's reader needs and the \
         reason this accessor exists rather than callers reading opaque bytes"
    );
}

#[test]
fn the_generation_cross_check_actually_fires() {
    // The presence case for the check itself, not for the accessor.
    //
    // This is the assertion that makes the permitted case above mean something.
    // An accessor that decoded and never compared would pass that test forever,
    // and would hand a caller a body from a different head than the one it
    // authenticated — which is the failure the cross-check exists to prevent.
    let receipt_generation = HeadGeneration::try_new(4).expect("admissible");
    let body_generation = HeadGeneration::try_new(5).expect("admissible");
    let skewed = head_at(body_generation, 9);

    let refusal = authenticated(receipt_generation, &skewed)
        .body()
        .expect_err("a body one generation away from its receipt must be refused");

    assert_eq!(
        refusal,
        HeadBodyRefusal::GenerationMismatch {
            receipt: receipt_generation,
            body: body_generation,
        },
        "the refusal must name both generations: a caller that cannot see which side moved \
         cannot tell a stale read from a corrupted body"
    );
}

#[test]
fn undecodable_bytes_are_refused_as_codec_rather_than_panicking() {
    // Authentication says nothing about whether the bytes parse. A store that
    // returned a truncated body would otherwise reach a decode that panics or,
    // worse, a caller's `unwrap`.
    let authenticated = AuthenticatedHead::new(
        HeadReadReceipt::new(
            head_key(),
            token(),
            HeadGeneration::FIRST,
            b"not a head body".to_vec(),
        ),
        StoreInstanceId::from_raw(1),
    );

    let refusal = authenticated
        .body()
        .expect_err("bytes that are not a head body must be refused, not decoded");

    assert!(
        matches!(refusal, HeadBodyRefusal::Codec(_)),
        "undecodable bytes must refuse as Codec rather than as a generation mismatch; got \
         {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// The same cross-check, on the replay path (frankengit-cnsi)
// ---------------------------------------------------------------------------
//
// The accessor above is not the only place this crate turns a head receipt into
// a body. `replay_outcome` and `scan_for_existing_decisions` do it too, on both
// surfaces — four sites that decoded with no comparison at all while this file
// documented why the comparison matters.
//
// Worth being precise about what is being defended. Those four sites take the
// receipt straight from `read_head` and never call `authenticate_head_receipt`,
// so they hold a receipt whose authenticity was never established. The store
// itself is the thing making two separate claims — "this slot is at generation
// N" and "these are its bytes" — and nothing outside the store makes it keep
// them consistent. This check is a cheap partial substitute for authentication
// at those sites, not a replacement for it.

use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, CasOutcome, DuplicateAbsenceWitness,
    HeadInit, HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore, OutcomeFailure,
    OutcomeLookup, PublicationOutcome, PutOutcome, initialize_repository, publish_decisions,
    replay_outcome,
};
use fgit_codec::{RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_types::identity::{RepositoryCommitId, RepositoryDecisionBatchId, TenantId};
use fgit_types::numeric::DecisionSequence;
use fgit_types::vocabulary::DecisionOutcome;

/// A store that reports one generation for the slot and returns bytes carrying
/// another.
///
/// It delegates everything to a real store and skews exactly one thing: the
/// generation on the receipt `read_head` hands back. That models a backend
/// whose slot metadata and slot bytes have drifted apart — a class this
/// workspace verifies empirically per backend rather than assuming away.
struct SkewedHeadStore {
    inner: MemoryAuthorityStore,
    skew: bool,
}

impl AuthorityStore for SkewedHeadStore {
    fn instance_id(&self) -> fgit_authority::StoreInstanceId {
        self.inner.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.inner.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        let read = self.inner.read_head(key)?;
        if !self.skew {
            return Ok(read);
        }
        let HeadRead::Present(receipt) = read else {
            return Ok(read);
        };
        // Same key, same token, same bytes — only the declared generation moves.
        let bumped = HeadGeneration::try_new(receipt.generation().get().saturating_add(1))
            .expect("a successor generation is admissible");
        Ok(HeadRead::Present(HeadReadReceipt::new(
            key.clone(),
            receipt.token(),
            bumped,
            receipt.body().to_vec(),
        )))
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.inner
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
        self.inner.publish_head_with_outcomes(
            key,
            expected,
            new_generation,
            new_body,
            outcomes,
            witness,
        )
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

fn slot() -> HeadKey {
    HeadKey::new(b"fg/head/v1/repo-22".to_vec()).expect("an admissible head key")
}

fn tx(byte: u8) -> fgit_types::identity::TxId {
    fgit_types::identity::TxId::from_digest(
        fgit_crypto::IdentityDomain::RefTransaction.algorithm().id(),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

/// Genesis plus one published batch deciding `tx(0xA1)`, over `store`.
fn publish_one(store: &SkewedHeadStore) {
    let genesis = head_at(HeadGeneration::FIRST, 0);
    initialize_repository(store, &slot(), &genesis).expect("genesis publishes");

    let batch = RepositoryDecisionBatchBody {
        repository_id: repository(),
        predecessor_head_id: fgit_authority::authority_head_identity(&genesis)
            .expect("genesis identifies"),
        predecessor_head_generation: genesis.generation,
        first_decision_sequence: DecisionSequence::try_new(1).expect("positive"),
        decisions: vec![RepositoryDecision {
            tx_id: tx(0xA1),
            decision_sequence: DecisionSequence::try_new(1).expect("positive"),
            outcome: DecisionOutcome::Committed {
                repository_commit_id: RepositoryCommitId::from_digest(
                    fgit_crypto::IdentityDomain::RepositoryCommitRecord
                        .algorithm()
                        .id(),
                    fgit_types::CANONICAL_CODEC_VERSION,
                    DigestBytes::try_new(&[0x51; 32]).expect("a bounded digest"),
                ),
            },
        }],
        committed_rcrs: Vec::new(),
        resulting_ref_root: digest(1),
        resulting_forge_position_root: digest(1),
        resulting_outcome_index_root: digest(1),
        resulting_retention_root: digest(1),
        resulting_outbox_root: digest(1),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(1),
        compaction_generation_link: None,
    };
    let batch_id: RepositoryDecisionBatchId =
        fgit_authority::decision_batch_identity(&batch).expect("the batch identifies");
    let successor = RepositoryAuthorityHeadBody {
        generation: HeadGeneration::try_new(2).expect("positive"),
        predecessor_head_id: Some(
            fgit_authority::authority_head_identity(&genesis).expect("genesis identifies"),
        ),
        decision_tail_id: Some(batch_id),
        latest_decision_sequence: Some(DecisionSequence::try_new(1).expect("positive")),
        ..genesis.clone()
    };
    let HeadRead::Present(receipt) = store.read_head(&slot()).expect("a readable head") else {
        panic!("genesis must be published");
    };
    let outcome = publish_decisions(
        store,
        &slot(),
        receipt.token(),
        &batch,
        &successor,
        tenant(),
    )
    .expect("publication succeeds");
    assert!(
        matches!(outcome, PublicationOutcome::Published(_)),
        "the fixture must actually publish"
    );
}

#[test]
fn replay_answers_normally_when_the_receipt_and_its_body_agree() {
    // The control. Without it the refusal below is satisfied by a replay that
    // refuses everything, and the fixture itself would be unproven.
    let store = SkewedHeadStore {
        inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(1)),
        skew: false,
    };
    publish_one(&store);

    assert!(
        matches!(
            replay_outcome(&store, &slot(), tx(0xA1)).expect("the walk completes"),
            OutcomeLookup::Decided(_)
        ),
        "a consistent store must replay to the decision it published"
    );
}

#[test]
fn replay_refuses_a_head_receipt_whose_generation_disagrees_with_its_body() {
    // The presence case for the check on the replay path. Before this, all four
    // replay sites decoded the receipt with no comparison; the identical fixture
    // returned Decided and the skew was invisible.
    let store = SkewedHeadStore {
        inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(1)),
        skew: false,
    };
    publish_one(&store);
    let skewed = SkewedHeadStore {
        inner: store.inner,
        skew: true,
    };

    let failure = replay_outcome(&skewed, &slot(), tx(0xA1))
        .expect_err("a self-inconsistent head receipt must be refused, not walked");

    let OutcomeFailure::HeadGenerationSkew { receipt, body } = failure else {
        panic!("the skew must refuse as HeadGenerationSkew; got {failure:?}");
    };
    assert_eq!(
        receipt.get(),
        body.get() + 1,
        "the refusal must name both generations so an operator can tell which side moved: \
         receipt {receipt:?}, body {body:?}"
    );
}

#[test]
fn the_accessor_and_the_replay_path_refuse_the_same_skew() {
    // The two used to be separate implementations of "what does this head say".
    // This is what holds them to one answer.
    let generation = HeadGeneration::try_new(4).expect("admissible");
    let skewed_body = head_at(HeadGeneration::try_new(5).expect("admissible"), 9);

    let via_accessor = authenticated(generation, &skewed_body)
        .body()
        .expect_err("the accessor refuses a skewed body");
    let lifted: OutcomeFailure = via_accessor.into();

    assert_eq!(
        lifted,
        OutcomeFailure::HeadGenerationSkew {
            receipt: generation,
            body: HeadGeneration::try_new(5).expect("admissible"),
        },
        "the accessor's refusal must lift into the replay path's vocabulary unchanged; two \
         refusals for one condition is the drift this consolidation removes"
    );
}
