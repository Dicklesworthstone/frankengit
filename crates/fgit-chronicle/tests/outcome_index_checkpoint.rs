//! Retained-leaf outcome-index checkpoints remain authority-verified evidence.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, OutcomeFailure, StoreInstanceId,
    TerminalOutcome, authority_head_identity, collect_cumulative_outcomes, initialize_repository,
    outcome_index_root, publish_decisions,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, LiveCapsuleRefusal, OutcomeIndexCheckpointBody,
    PublicationBasis, PublicationPlan, ResultingRoots, activate_frozen_capsule,
    collect_cumulative_outcomes_from_capsule_checkpoint,
    freeze_capsule_with_outcome_index_checkpoint,
};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, decode_body};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, RefusalCode, RefusalRecordId, RegistryEpoch, RepositoryId, TenantId, TxId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture algorithm is reserved"),
        DigestBytes::try_new(&[tag; 32]).expect("fixture digest is 32 bytes"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("fixture algorithm is reserved"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("fixture digest is 32 bytes"),
        )
    };
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x61; OPAQUE_ID_LEN])
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x62; OPAQUE_ID_LEN])
}

fn head_key() -> HeadKey {
    HeadKey::new(b"chronicle/outcome-index-checkpoint".to_vec())
        .expect("fixture head key is admissible")
}

fn genesis() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(2),
        outcome_index_root: outcome_index_root(&[]).expect("empty outcome index is defined"),
        retention_root: digest(3),
        outbox_root: digest(4),
        configuration_root: digest(5),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

const fn roots(basis: &PublicationBasis) -> ResultingRoots {
    ResultingRoots::carried_forward(basis)
}

fn publish_first_refusal(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
) -> (
    fgit_chronicle::VerifiedPublication,
    fgit_authority::HeadReadReceipt,
) {
    let initial = genesis();
    initialize_repository(store, key, &initial).expect("genesis initializes");
    let receipt = match store.read_head(key).expect("genesis reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized genesis is present"),
    };
    let basis = PublicationBasis::new(
        authority_head_identity(&initial).expect("genesis identity"),
        initial,
    );
    let outcomes = collect_cumulative_outcomes(store, key).expect("genesis collects");
    let mut plan = PublicationPlan::open(basis.clone()).expect("genesis opens");
    plan.refuse(
        derived!(TxId, 0x11),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x12),
    );
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            roots(&basis),
            &outcomes,
            receipt.token(),
        )
        .expect("a correctly stamped refusal seals");
    publish_decisions(
        store,
        key,
        receipt.token(),
        publication.batch(),
        publication.head(),
        tenant(),
    )
    .expect("first terminal decision publishes");
    let first_receipt = match store.read_head(key).expect("first head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("published first head is present"),
    };
    (publication, first_receipt)
}

fn closure() -> CapsuleClosure {
    CapsuleClosure {
        object_closure_root: digest(0x31),
        segment_manifest_root: digest(0x32),
        backup_profile: BackupProfile::FullClosure,
    }
}

fn root_of(decisions: &[fgit_codec::RepositoryDecision]) -> Digest {
    outcome_index_root(
        &decisions
            .iter()
            .map(|decision| {
                (
                    decision.tx_id,
                    TerminalOutcome {
                        decision_sequence: decision.decision_sequence,
                        outcome: decision.outcome,
                    },
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("terminal decisions form an outcome-index root")
}

#[test]
fn capsule_bound_checkpoint_replays_only_the_tail_and_preserves_the_root() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6161));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let carried = collect_cumulative_outcomes(&store, &key).expect("first decision collects");
    let checkpoint = OutcomeIndexCheckpointBody::new(
        repository(),
        publication.head().decision_tail_id,
        publication.head().latest_decision_sequence,
        None,
        carried
            .checkpoint_decisions_against(first_receipt.token())
            .expect("carried decisions remain bound to the first head"),
    )
    .expect("authority order forms a checkpoint");

    let frozen = freeze_capsule_with_outcome_index_checkpoint(
        &store,
        &CryptoBodyIdentity,
        &first_receipt,
        None,
        closure(),
        &checkpoint,
    )
    .expect("checkpoint stages before a capsule binds its digest");
    assert!(
        frozen.capsule().outcome_index_checkpoint_root.is_some(),
        "the capsule binds retained leaves by their checkpoint digest, never by outcome_index_root"
    );
    let activated = activate_frozen_capsule(&store, &first_receipt, &frozen)
        .expect("the capsule pointer advances only after staging");

    let checkpointed =
        collect_cumulative_outcomes_from_capsule_checkpoint(&store, &CryptoBodyIdentity, &key)
            .expect("a capsule-bound checkpoint is usable evidence");
    assert_eq!(
        checkpointed
            .checkpoint_decisions_against(activated.head().token())
            .expect("checkpointed leaves stay token-bound"),
        checkpoint.decisions(),
        "no tail means the checkpoint leaves exactly reproduce the cumulative index"
    );
    assert_eq!(
        root_of(&publication.batch().decisions),
        publication.head().outcome_index_root,
        "the retained leaf set preserves the existing outcome-index commitment"
    );

    let activated_head: RepositoryAuthorityHeadBody =
        decode_body(activated.head().body(), DecodeLimits::DEFAULT)
            .expect("activated receipt carries a canonical head");
    let activated_basis = PublicationBasis::new(
        authority_head_identity(&activated_head).expect("activated head identity"),
        activated_head,
    );
    let mut tail_plan =
        PublicationPlan::open(activated_basis.clone()).expect("activated head opens");
    tail_plan.refuse(
        derived!(TxId, 0x21),
        RefusalCode::ProtectedRefTransitionDenied,
        derived!(RefusalRecordId, 0x22),
    );
    let tail_publication = tail_plan
        .seal(
            &CryptoBodyIdentity,
            roots(&activated_basis),
            &checkpointed,
            activated.head().token(),
        )
        .expect("a post-checkpoint terminal decision seals");
    publish_decisions(
        &store,
        &key,
        activated.head().token(),
        tail_publication.batch(),
        tail_publication.head(),
        tenant(),
    )
    .expect("the post-checkpoint tail publishes");
    let tail_receipt = match store.read_head(&key).expect("tail head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("published tail head is present"),
    };
    let folded_tail =
        collect_cumulative_outcomes_from_capsule_checkpoint(&store, &CryptoBodyIdentity, &key)
            .expect("checkpoint leaves plus the new tail collect");
    let folded_decisions = folded_tail
        .checkpoint_decisions_against(tail_receipt.token())
        .expect("folded checkpoint-plus-tail decisions remain token-bound");
    assert_eq!(
        folded_decisions.len(),
        2,
        "exactly the retained leaf and tail remain"
    );
    assert_eq!(
        root_of(&folded_decisions),
        tail_publication.head().outcome_index_root,
        "checkpoint leaves plus a tail produce the same committed outcome-index root"
    );
}

#[test]
fn checkpoint_with_wrong_leaves_cannot_be_capsule_bound_at_a_real_position() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6262));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let wrong = OutcomeIndexCheckpointBody::new(
        repository(),
        publication.head().decision_tail_id,
        publication.head().latest_decision_sequence,
        None,
        Vec::new(),
    )
    .expect("an empty retained set is structurally canonical");

    assert!(matches!(
        freeze_capsule_with_outcome_index_checkpoint(
            &store,
            &CryptoBodyIdentity,
            &first_receipt,
            None,
            closure(),
            &wrong,
        ),
        Err(LiveCapsuleRefusal::OutcomeIndexCheckpointPosition(error))
            if matches!(*error, OutcomeFailure::CheckpointRootMismatch)
    ));
}
