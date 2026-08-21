//! Cross-implementation agreement with the reference model.
//!
//! `fgit-reference` computes the next decision position, the next
//! committed-transition position, and the next head generation from an
//! authority head. `fgit-chronicle` computes the same three things
//! independently, in different code, to decide where a batch starts. Two
//! independent implementations of the same clause are only useful if they
//! agree, so this file drives both over the same range of head states —
//! including the boundaries where a counter is absent and where it is
//! exhausted — and asserts they answer identically.
//!
//! This is bounded-model evidence over the sequencing clause, not a proof and
//! not a whole-trace refinement: the model's roots are structured state while
//! a canonical head carries digests, so only the sequencing fields are
//! comparable here.

use fgit_chronicle::PublicationBasis;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_reference::state::{AuthorityHeadBody, PolicySnapshot, RepositoryRoots};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes,
    HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
    RepositoryId, RepositorySequence,
};
use std::collections::{BTreeMap, BTreeSet};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn head_id() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x20; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn policy() -> PolicySnapshot {
    PolicySnapshot {
        epoch: PolicyEpoch::FIRST,
        protected_scopes: BTreeSet::new(),
        principals: BTreeMap::new(),
        max_intents_per_transaction: 8,
        supported_schemas: BTreeSet::new(),
        supported_durability: BTreeSet::new(),
    }
}

/// The model's head at one position.
fn model_head(
    generation: HeadGeneration,
    decisions: Option<DecisionSequence>,
    commits: Option<RepositorySequence>,
) -> AuthorityHeadBody {
    AuthorityHeadBody {
        repository: repository(),
        generation,
        predecessor: None,
        decision_tail: None,
        latest_decision_sequence: decisions,
        latest_committed_rcr: None,
        latest_repository_sequence: commits,
        roots: RepositoryRoots::default(),
        configuration: policy(),
        format_registry_epoch: RegistryEpoch::FIRST,
    }
}

/// The canonical head at the same position.
fn canonical_head(
    generation: HeadGeneration,
    decisions: Option<DecisionSequence>,
    commits: Option<RepositorySequence>,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: decisions,
        latest_committed_rcr_id: None,
        latest_repository_sequence: commits,
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

fn sequence(value: u64) -> DecisionSequence {
    DecisionSequence::try_new(value).expect("a non-zero position")
}

fn commit_sequence(value: u64) -> RepositorySequence {
    RepositorySequence::try_new(value).expect("a non-zero position")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a non-zero generation")
}

/// The positions worth disagreeing at: absent, first, ordinary, and the
/// ceiling where both implementations must refuse rather than wrap.
const POSITIONS: [Option<u64>; 6] = [
    None,
    Some(1),
    Some(2),
    Some(1_000),
    Some(u64::MAX - 1),
    Some(u64::MAX),
];

const GENERATIONS: [u64; 5] = [1, 2, 1_000, u64::MAX - 1, u64::MAX];

#[test]
fn the_next_decision_position_agrees_with_the_reference_model() {
    for slot in POSITIONS {
        let decisions = slot.map(sequence);
        let model = model_head(HeadGeneration::FIRST, decisions, None);
        let basis = PublicationBasis::new(
            head_id(),
            canonical_head(HeadGeneration::FIRST, decisions, None),
        );

        match (
            model.next_decision_sequence(),
            basis.open_decision_sequence(),
        ) {
            (Ok(expected), Ok(observed)) => assert_eq!(
                expected,
                observed,
                "at latest decision {slot:?} the model says {} and the chronicle says {}",
                expected.get(),
                observed.get()
            ),
            (Err(_), Err(_)) => {
                assert_eq!(
                    slot,
                    Some(u64::MAX),
                    "only an exhausted counter may refuse, but {slot:?} did"
                );
            }
            (model_answer, chronicle_answer) => panic!(
                "at latest decision {slot:?} the two disagree about whether the repository can advance: model {model_answer:?}, chronicle {chronicle_answer:?}"
            ),
        }
    }
}

#[test]
fn the_next_committed_position_agrees_with_the_reference_model() {
    for slot in POSITIONS {
        let commits = slot.map(commit_sequence);
        let model = model_head(HeadGeneration::FIRST, None, commits);
        let basis = PublicationBasis::new(
            head_id(),
            canonical_head(HeadGeneration::FIRST, None, commits),
        );

        match (
            model.next_repository_sequence(),
            basis.open_repository_sequence(),
        ) {
            (Ok(expected), Ok(observed)) => assert_eq!(
                expected,
                observed,
                "at latest commit {slot:?} the model says {} and the chronicle says {}",
                expected.get(),
                observed.get()
            ),
            (Err(_), Err(_)) => {
                assert_eq!(slot, Some(u64::MAX), "only exhaustion may refuse");
            }
            (model_answer, chronicle_answer) => panic!(
                "at latest commit {slot:?} the two disagree: model {model_answer:?}, chronicle {chronicle_answer:?}"
            ),
        }
    }
}

#[test]
fn the_successor_generation_agrees_with_the_reference_model() {
    for value in GENERATIONS {
        let current = generation(value);
        let model = model_head(current, None, None);
        let basis = PublicationBasis::new(head_id(), canonical_head(current, None, None));

        match (model.next_generation(), basis.successor_generation()) {
            (Ok(expected), Ok(observed)) => {
                assert_eq!(
                    expected,
                    observed,
                    "at generation {value} the model says {} and the chronicle says {}",
                    expected.get(),
                    observed.get()
                );
                assert!(
                    observed > current,
                    "a successor generation must strictly advance"
                );
            }
            (Err(_), Err(_)) => assert_eq!(value, u64::MAX, "only exhaustion may refuse"),
            (model_answer, chronicle_answer) => panic!(
                "at generation {value} the two disagree: model {model_answer:?}, chronicle {chronicle_answer:?}"
            ),
        }
    }
}

#[test]
fn a_repository_that_has_refused_but_never_committed_agrees_on_both_counters() {
    // The asymmetry §8.1 requires: refusals consume decision sequence, so a
    // repository can be deep into its decision history with nothing committed.
    // A disagreement here would mean one of the two implementations lets a
    // refusal consume a committed-transition position.
    let decisions = Some(sequence(41));
    let model = model_head(generation(9), decisions, None);
    let basis = PublicationBasis::new(head_id(), canonical_head(generation(9), decisions, None));

    assert_eq!(
        basis
            .open_decision_sequence()
            .expect("the chronicle can advance"),
        model
            .next_decision_sequence()
            .expect("the model can advance"),
    );
    assert_eq!(
        basis
            .open_repository_sequence()
            .expect("the chronicle can advance")
            .get(),
        1,
        "nothing has committed, so the next commit is still the first"
    );
    assert_eq!(
        basis
            .open_repository_sequence()
            .expect("the chronicle can advance"),
        model
            .next_repository_sequence()
            .expect("the model can advance"),
    );
}
