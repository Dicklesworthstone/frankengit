//! The outcome-index root is a post-stamp authority derivation, not provider input.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId, TerminalOutcome,
    authority_head_identity, collect_cumulative_outcomes, fold_outcome_index,
    initialize_repository, outcome_index_root, publish_decisions,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots, verify_pair};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes,
    HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, RefusalCode, RefusalRecordId, RegistryEpoch,
    RepositoryId, TenantId, TxId,
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
    RepositoryId::from_bytes([0x51; OPAQUE_ID_LEN])
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x52; OPAQUE_ID_LEN])
}

fn head_key() -> HeadKey {
    HeadKey::new(b"chronicle/post-stamp-outcome-index".to_vec())
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

fn roots(basis: &PublicationBasis) -> ResultingRoots {
    ResultingRoots::carried_forward(basis)
}

fn seal_refusal(
    basis: &PublicationBasis,
    outcomes: &fgit_authority::CumulativeOutcomes,
    expected: fgit_authority::AuthorityVersionToken,
    tx_id: TxId,
    code: RefusalCode,
    refusal_record_id: RefusalRecordId,
) -> fgit_chronicle::VerifiedPublication {
    let mut plan = PublicationPlan::open(basis.clone()).expect("genesis basis opens");
    plan.refuse(tx_id, code, refusal_record_id);
    plan.seal(&CryptoBodyIdentity, roots(basis), outcomes, expected)
        .expect("authority witness seals a well-formed publication")
}

#[test]
fn authority_fold_uses_stamped_terminal_outcomes_and_survives_head_decode() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5151));
    let key = head_key();
    let genesis = genesis();
    initialize_repository(&store, &key, &genesis).expect("genesis initializes");
    let receipt = match store.read_head(&key).expect("genesis head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized genesis must be readable"),
    };
    let basis = PublicationBasis::new(
        authority_head_identity(&genesis).expect("genesis has a canonical identity"),
        genesis,
    );
    let cumulative = collect_cumulative_outcomes(&store, &key)
        .expect("the actual authority stream yields the carried leaf set");

    let first = seal_refusal(
        &basis,
        &cumulative,
        receipt.token(),
        derived!(TxId, 0x11),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x12),
    );
    let decision = first
        .batch()
        .decisions
        .first()
        .expect("one stamped decision");
    let expected = fold_outcome_index(
        &[],
        &[(
            decision.tx_id,
            TerminalOutcome {
                decision_sequence: decision.decision_sequence,
                outcome: decision.outcome,
            },
        )],
    );
    let expected = expected.expect("the authority fold accepts one terminal outcome");
    assert_eq!(first.batch().resulting_outcome_index_root, expected);
    assert_eq!(first.head().outcome_index_root, expected);
    verify_pair(&CryptoBodyIdentity, &basis, first.batch(), first.head())
        .expect("the derived root satisfies the batch/head invariant");
    let head_bytes = encode_body(first.head()).expect("derived successor head encodes");
    let decoded: RepositoryAuthorityHeadBody =
        decode_body(&head_bytes, DecodeLimits::DEFAULT).expect("derived successor head decodes");
    assert_eq!(decoded, *first.head());

    publish_decisions(
        &store,
        &key,
        receipt.token(),
        first.batch(),
        first.head(),
        tenant(),
    )
    .expect("the first derived pair publishes through the exact-head CAS");
    let successor_receipt = match store.read_head(&key).expect("successor head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("published successor must be readable"),
    };
    let successor_basis = PublicationBasis::new(
        authority_head_identity(first.head()).expect("successor head has a canonical identity"),
        first.head().clone(),
    );
    let successor_outcomes = collect_cumulative_outcomes(&store, &key)
        .expect("the authority stream carries the first terminal outcome");
    let carried_then_stamped = seal_refusal(
        &successor_basis,
        &successor_outcomes,
        successor_receipt.token(),
        derived!(TxId, 0x31),
        RefusalCode::ProtectedRefTransitionDenied,
        derived!(RefusalRecordId, 0x32),
    );
    let first_decision = first.batch().decisions.first().expect("one first decision");
    let second_decision = carried_then_stamped
        .batch()
        .decisions
        .first()
        .expect("one second decision");
    let expected_cumulative = fold_outcome_index(
        &[terminal_outcome(first_decision)],
        &[terminal_outcome(second_decision)],
    )
    .expect("authority fold accepts carried and stamped terminal outcomes");
    assert_eq!(
        carried_then_stamped.batch().resulting_outcome_index_root,
        expected_cumulative,
        "the post-stamp fold includes the predecessor's cumulative leaf set"
    );

    let changed = seal_refusal(
        &basis,
        &cumulative,
        receipt.token(),
        derived!(TxId, 0x21),
        RefusalCode::NonFastForwardRefused,
        derived!(RefusalRecordId, 0x22),
    );
    assert_ne!(
        first.batch().resulting_outcome_index_root,
        changed.batch().resulting_outcome_index_root,
        "changing a stamped terminal outcome changes the cumulative index root"
    );
}

fn terminal_outcome(decision: &fgit_codec::RepositoryDecision) -> (TxId, TerminalOutcome) {
    (
        decision.tx_id,
        TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        },
    )
}
