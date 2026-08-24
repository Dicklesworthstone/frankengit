#![forbid(unsafe_code)]
//! A tampering-mirror corpus, and what a 100% detection rate is worth.
//!
//! `frankengit-fg037b`, acceptance line 1.
//!
//! # Why a corpus rather than more individual tests
//!
//! Around twenty tamper cases already exist as individual tests — in
//! `fgit-crypto`'s `merkle_layout.rs`, `fgit-authority`'s
//! `outcome_inclusion_proofs.rs`, and this crate's `verified_read.rs`. Instances
//! catch instances. A corpus catches a *class* being unhandled: it enumerates
//! the tamper space, runs the whole client over it, and asserts a rate.
//!
//! # The trap a 100% rate walks into, and the guard against it
//!
//! "Every case rejected" is satisfied by a client that rejects everything, and
//! it is *also* satisfied when one over-broad check happens to catch all of
//! them — at which point the rate says nothing about the other checks and would
//! not move if they were deleted. So this corpus records **which refusal caught
//! each case** and asserts that the detections are spread across distinct
//! refusals, not funnelled through one. That attribution is the difference
//! between a measurement and a slogan.
//!
//! # The class that `verify_envelope` cannot catch, stated plainly
//!
//! `StaleHeadReplay` is detected by [`HeadChainFloor`] and by nothing else.
//! `verify_envelope` accepts it — correctly, because the proof genuinely is
//! valid against the head it names. The corpus therefore runs the *combined*
//! client (freshness, then envelope), and asserts explicitly that this one class
//! survives envelope verification alone. Delete `freshness.rs` and the rate
//! drops below 100%; that dependency is what the assertion pins.

use std::collections::BTreeMap;

use fgit_authority::{TerminalOutcome, outcome_index_proof, outcome_index_root};
use fgit_codec::RepositoryIncarnationConfigurationBody;
use fgit_codec::{
    CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryConfigurationBody, body_id,
};
use fgit_crypto::{IdentityDomain, MerkleProof, ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId};
use fgit_types::identity::{RepositoryCommitId, TxId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::DecisionSequence;
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;
use fgit_verified_read::freshness::HeadChainFloor;
use fgit_verified_read::{
    PinnedAuthorityHead, VerifiedMembership, VerifiedReadAnswer, VerifiedReadConfiguration,
    VerifiedReadEnvelope, VerifiedReadRefusal, verify_envelope,
};

/// What a tampering mirror altered.
///
/// [`TamperClass::ALL`] is the corpus DENOMINATOR, and it exists because a
/// detection rate over a shrinkable set is not a measurement. With the classes
/// living only inside `corpus()`, deleting one would keep the rate at 100% and
/// keep every test-function count unchanged -- the coverage would fall silently.
/// `ALL` plus the coverage assertion below make a removed class a failure and an
/// added variant without a case a failure too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TamperClass {
    RefName,
    RefIdentity,
    ProofSibling,
    ProofIndex,
    ProofLeafCount,
    HeadRefRoot,
    HeadConfigurationRoot,
    ConfigurationSubstituted,
    ConfigurationRemoved,
    StaleHeadReplay,
    /// A transaction the outcome index does not hold, with a real proof.
    OutcomeTxId,
    /// The right transaction, a different terminal outcome.
    OutcomeSubstituted,
    /// An outcome answer pinned against the head's REF root instead of its
    /// outcome-index root.
    ///
    /// The family's own risk, and the one a shared Merkle verifier cannot
    /// catch: every proof-structure class above tests the same path code, so
    /// none of them can see an answer being checked against the wrong root.
    OutcomeRootConfusion,
}

impl TamperClass {
    /// Every class the corpus must exercise.
    const ALL: [Self; 13] = [
        Self::RefName,
        Self::RefIdentity,
        Self::ProofSibling,
        Self::ProofIndex,
        Self::ProofLeafCount,
        Self::HeadRefRoot,
        Self::HeadConfigurationRoot,
        Self::ConfigurationSubstituted,
        Self::ConfigurationRemoved,
        Self::StaleHeadReplay,
        Self::OutcomeTxId,
        Self::OutcomeSubstituted,
        Self::OutcomeRootConfusion,
    ];

    /// Ties `ALL` to the enum, which the array alone does not do.
    ///
    /// `ALL` is hand-written. DELETING a variant breaks the build, because the
    /// array names it. ADDING one did not: the array stayed length 10, the
    /// coverage assertion below still passed, and the new class was never
    /// exercised. Measured before this existed -- an eleventh variant compiled
    /// with nothing but a dead-code warning, and
    /// `the_corpus_covers_every_declared_tamper_class_exactly_once` stayed
    /// green. A denominator that cannot see the numerator grow is not a
    /// denominator.
    ///
    /// This match has no wildcard arm, so adding a variant makes it
    /// non-exhaustive and the build stops HERE, next to `ALL` and the corpus,
    /// which is the one place that says what the new variant still owes:
    /// an entry in `ALL` and a case in `corpus()`.
    const fn is_declared(self) {
        match self {
            Self::RefName
            | Self::RefIdentity
            | Self::ProofSibling
            | Self::ProofIndex
            | Self::ProofLeafCount
            | Self::HeadRefRoot
            | Self::HeadConfigurationRoot
            | Self::ConfigurationSubstituted
            | Self::ConfigurationRemoved
            | Self::StaleHeadReplay
            | Self::OutcomeTxId
            | Self::OutcomeSubstituted
            | Self::OutcomeRootConfusion => (),
        }
    }
}

/// How the combined client rejected a tampered answer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Detection {
    /// Caught by `verify_envelope`, named by its refusal discriminant.
    Envelope(String),
    /// Caught by the head-chain floor, which `verify_envelope` cannot see.
    Freshness,
    /// The client accepted the answer. Correct for the honest case; a hole in
    /// the client for any tampered one. Named for what happened rather than for
    /// what it means, because the meaning depends on the input.
    Accepted,
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn ref_state() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/tags/v1"), oid(0x33)),
    ]
}

fn configuration() -> RepositoryConfigurationBody {
    RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: vec![b"refs/secret".to_vec()],
    }
}

/// A configuration with the hidden-ref policy STRIPPED, and otherwise identical.
///
/// This is the substitution worth testing now that the policy lives in the
/// configuration body. The layout still admits proofs, so
/// nothing about the answer looks wrong; the only change is that a mirror has
/// removed the rules that withhold `refs/secret`. If the body were accepted
/// without identifying to the head, a mirror could widen disclosure without
/// touching a single proof.
const fn other_configuration() -> RepositoryConfigurationBody {
    RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    }
}

fn configuration_root(body: &RepositoryConfigurationBody) -> Digest {
    let identity = body_id(&CryptoBodyIdentity, body).expect("a canonical configuration identity");
    Digest::new(identity.algorithm(), *identity.digest())
}

fn head(
    generation: u64,
    predecessor: Option<RepositoryAuthorityHeadId>,
    ref_root: Digest,
    config_root: Digest,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x22; 16]),
        generation: HeadGeneration::try_new(generation).expect("positive"),
        predecessor_head_id: predecessor,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root,
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root: config_root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

/// The genuine article: a real ref-state root, a real membership proof, and a
/// head whose `configuration_root` really identifies the carried configuration.
struct Honest {
    head: RepositoryAuthorityHeadBody,
    configuration: RepositoryConfigurationBody,
    queried: RefName,
    oid: GitOid,
    proof: MerkleProof,
}

/// The single outcome index the pinned head commits to.
fn outcome_index() -> Vec<(TxId, TerminalOutcome)> {
    vec![(tx(0xA1), committed(1, 0x55))]
}

fn honest() -> Honest {
    let entries = ref_state();
    let root = ref_state_merkle_root(&entries).expect("a ref root");
    let configuration = configuration();
    let queried = name("refs/heads/main");
    let (found, proof) =
        ref_state_membership_proof(&entries, &queried).expect("a membership proof");
    let mut base = head(2, None, root, configuration_root(&configuration));
    // The pinned head carries the REAL outcome-index root as well as the ref
    // root. Without this, an outcome case has to move the head to publish its
    // root -- and a moved head is refused by the FRESHNESS floor before the
    // proof is ever examined. Measured when this fixture was first written:
    // all three outcome classes came back detected, every one of them by
    // Freshness, so the outcome proof path was never reached and the family
    // would have been coverage in name only.
    base.outcome_index_root =
        outcome_index_root(&outcome_index()).expect("a terminal outcome has a canonical root");
    Honest {
        head: base,
        configuration,
        queried,
        oid: found,
        proof,
    }
}

fn membership(name_value: RefName, oid_value: GitOid, proof: MerkleProof) -> VerifiedReadAnswer {
    VerifiedReadAnswer::RefMembership {
        name: name_value,
        oid: oid_value,
        proof: Box::new(proof),
    }
}

/// Run the combined client: freshness first, then envelope verification.
fn combined_client(
    floor: &HeadChainFloor,
    pinned: &PinnedAuthorityHead,
    envelope: &VerifiedReadEnvelope,
) -> Detection {
    if floor.judge(envelope.head()).is_err() {
        return Detection::Freshness;
    }
    match verify_envelope(pinned, envelope) {
        Err(refusal) => Detection::Envelope(refusal_name(&refusal)),
        Ok(_) => Detection::Accepted,
    }
}

/// The refusal's discriminant name, so attribution does not depend on Display.
fn refusal_name(refusal: &VerifiedReadRefusal) -> String {
    match refusal {
        VerifiedReadRefusal::UnsupportedEnvelopeVersion { .. } => "UnsupportedEnvelopeVersion",
        VerifiedReadRefusal::PinnedHeadMismatch => "PinnedHeadMismatch",
        VerifiedReadRefusal::ConfigurationIdentityUnavailable => "ConfigurationIdentityUnavailable",
        VerifiedReadRefusal::ConfigurationRootMismatch => "ConfigurationRootMismatch",
        VerifiedReadRefusal::WireDecode(_) => "WireDecode",
        VerifiedReadRefusal::RefLayout(_) => "RefLayout",
        VerifiedReadRefusal::ProofRejected => "ProofRejected",
        VerifiedReadRefusal::Outcome(_) => "Outcome",
        VerifiedReadRefusal::RefNotFoundOrUnauthorized => "RefNotFoundOrUnauthorized",
        VerifiedReadRefusal::RefPresent => "RefPresent",
        VerifiedReadRefusal::ForgePositionProofUnavailable => "ForgePositionProofUnavailable",
        // Exhaustive on purpose. A wildcard would map a newly added refusal to
        // one bucket, and this corpus's whole claim is that detections are
        // SPREAD across distinct checks -- a silent merge would weaken that
        // measurement without failing anything.
    }
    .to_owned()
}

/// A transaction identity for the outcome-index fixtures.
fn tx(byte: u8) -> TxId {
    TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
    )
}

/// A committed terminal outcome.
fn committed(sequence: u64, byte: u8) -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence)
            .expect("fixture sequence is positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
            ),
        },
    }
}

/// The honest outcome-membership answer these cases tamper with.
///
/// A SECOND family in this corpus, and the reason it is worth having: every
/// class above rides the ref path, so the whole corpus shared one root, one
/// layout and one answer variant. A verifier that checked the right structure
/// against the wrong root would have been detected by nothing here.
struct HonestOutcome {
    head: RepositoryAuthorityHeadBody,
    tx_id: TxId,
    outcome: TerminalOutcome,
    proof: MerkleProof,
}

fn honest_outcome() -> HonestOutcome {
    let entries = outcome_index();
    let (tx_id, outcome) = entries[0];
    let proof = outcome_index_proof(&entries, tx_id, &outcome)
        .expect("the indexed terminal outcome has a membership proof");
    // The UNMODIFIED pinned head: it already commits to this index, so
    // freshness passes and whatever refuses below is the envelope verifier.
    HonestOutcome {
        head: honest().head,
        tx_id,
        outcome,
        proof,
    }
}

/// The incarnation-bound configuration a real node publishes.
///
/// `OneNode`'s genesis writes a `RepositoryIncarnationConfigurationBody`, so
/// this -- not `RepositoryConfigurationBody` -- is the variant a served
/// envelope actually carries in production. The corpus covered only the v1
/// body until this was added.
const fn incarnation_configuration() -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x7A; 16]),
    }
}

fn incarnation_configuration_root(body: &RepositoryIncarnationConfigurationBody) -> Digest {
    let identity = body_id(&CryptoBodyIdentity, body).expect("an incarnation body identifies");
    Digest::new(identity.algorithm(), *identity.digest())
}

/// Every tampered envelope, paired with the class it represents.
fn corpus() -> Vec<(TamperClass, VerifiedReadEnvelope)> {
    let base = honest();
    let good_proof = base.proof.clone();
    // Kept for the cross-root case at the end, which needs a genuine REF proof.
    let ref_proof_for_cross_root = base.proof.clone();
    let good_head = base.head.clone();
    let good_config = base.configuration.clone();

    let mut cases = Vec::new();

    // A ref the state does not hold, presented with a real proof.
    cases.push((
        TamperClass::RefName,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(name("refs/heads/injected"), base.oid, good_proof.clone()),
        ),
    ));

    // The right ref, the wrong object.
    cases.push((
        TamperClass::RefIdentity,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(base.queried.clone(), oid(0xFF), good_proof.clone()),
        ),
    ));

    // A flipped byte in the first sibling.
    let mut siblings = good_proof.siblings().to_vec();
    if let Some(first) = siblings.first_mut() {
        let mut bytes = first.as_bytes().to_vec();
        bytes[0] ^= 0xFF;
        *first = DigestBytes::try_new(&bytes).expect("still a bounded digest");
    }
    cases.push((
        TamperClass::ProofSibling,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(
                base.queried.clone(),
                base.oid,
                MerkleProof::new(good_proof.index(), good_proof.leaf_count(), siblings),
            ),
        ),
    ));

    // The right leaf, claimed at the wrong position.
    cases.push((
        TamperClass::ProofIndex,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(
                base.queried.clone(),
                base.oid,
                MerkleProof::new(
                    good_proof.index().saturating_add(1),
                    good_proof.leaf_count(),
                    good_proof.siblings().to_vec(),
                ),
            ),
        ),
    ));

    // A different tree shape, which changes how the fold pairs and promotes.
    cases.push((
        TamperClass::ProofLeafCount,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(
                base.queried.clone(),
                base.oid,
                MerkleProof::new(
                    good_proof.index(),
                    good_proof.leaf_count().saturating_add(2),
                    good_proof.siblings().to_vec(),
                ),
            ),
        ),
    ));

    // A head whose ref_root is not the root the proof was built against.
    cases.push((
        TamperClass::HeadRefRoot,
        VerifiedReadEnvelope::new(
            head(2, None, digest(0xAB), configuration_root(&good_config)),
            Some(good_config.clone()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        ),
    ));

    // A head whose configuration_root does not identify the carried body.
    cases.push((
        TamperClass::HeadConfigurationRoot,
        VerifiedReadEnvelope::new(
            head(2, None, good_head.ref_root, digest(0xCD)),
            Some(good_config.clone()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        ),
    ));

    // A different configuration body under the honest head.
    cases.push((
        TamperClass::ConfigurationSubstituted,
        VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(other_configuration()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        ),
    ));

    // No configuration at all, which forces the legacy layout that admits no
    // ref-state membership proof.
    cases.push((
        TamperClass::ConfigurationRemoved,
        VerifiedReadEnvelope::new(
            good_head,
            None,
            membership(base.queried.clone(), base.oid, good_proof),
        ),
    ));

    // A genuine, fully valid answer about an OLDER head. Nothing here is
    // forged; this is the replay.
    let old_root = ref_state_merkle_root(&[(name("refs/heads/main"), oid(0x11))]).expect("a root");
    let old_head = head(1, None, old_root, configuration_root(&good_config));
    let old_entries = vec![(name("refs/heads/main"), oid(0x11))];
    let (old_oid, old_proof) =
        ref_state_membership_proof(&old_entries, &name("refs/heads/main")).expect("a proof");
    cases.push((
        TamperClass::StaleHeadReplay,
        VerifiedReadEnvelope::new(
            old_head,
            Some(good_config),
            membership(name("refs/heads/main"), old_oid, old_proof),
        ),
    ));

    // --- the outcome-membership family ---------------------------------
    //
    // Everything above rides the REF path, so until here the corpus shared one
    // root, one layout and one answer variant. These pin the second verified
    // answer type, which is checked against `outcome_index_root` rather than
    // `ref_root`.
    let honest_outcome = honest_outcome();

    // A transaction the index does not hold, carried by a real proof. The
    // outcome analogue of RefName.
    cases.push((
        TamperClass::OutcomeTxId,
        VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: tx(0xB2),
                outcome: Box::new(honest_outcome.outcome),
                proof: Box::new(honest_outcome.proof.clone()),
            },
        ),
    ));

    // The right transaction, a different terminal outcome: the answer that
    // matters most to a client, since it changes what it believes happened.
    cases.push((
        TamperClass::OutcomeSubstituted,
        VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: honest_outcome.tx_id,
                outcome: Box::new(committed(2, 0x66)),
                proof: Box::new(honest_outcome.proof.clone()),
            },
        ),
    ));

    // CROSS-ROOT CONFUSION, and the reason this family earns its place: a
    // genuine REF proof presented as an OUTCOME answer.
    //
    // The head is UNTOUCHED, which is the whole design of this case. The
    // obvious version -- swap the head's outcome-index root for its ref root --
    // is a head change, so the freshness floor refuses it before the verifier
    // runs; measured, it came back detected by Freshness and the proof path was
    // never reached. Leaving the head alone makes freshness pass and forces the
    // envelope verifier to be the thing that answers, which is the only way to
    // learn whether it checks a proof against the root its ANSWER TYPE names
    // rather than whichever root happens to verify.
    //
    // No proof-structure class above can see this: they all ride the ref path,
    // so a verifier that checked every outcome answer against `ref_root` would
    // satisfy the entire pre-existing corpus.
    assert_ne!(
        base.head.ref_root, base.head.outcome_index_root,
        "the two roots must genuinely differ, or routing to the wrong one is undetectable"
    );
    cases.push((
        TamperClass::OutcomeRootConfusion,
        VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: honest_outcome.tx_id,
                outcome: Box::new(honest_outcome.outcome),
                // A real ref-membership proof, valid under `ref_root`, offered
                // where an outcome-index proof belongs.
                proof: Box::new(ref_proof_for_cross_root),
            },
        ),
    ));

    cases
}

/// Freshness floor and pin for a client that has accepted the honest head.
fn client() -> (HeadChainFloor, PinnedAuthorityHead) {
    let base = honest();
    let floor = HeadChainFloor::anchored_to(&base.head).expect("anchors");
    (floor, PinnedAuthorityHead::new(base.head))
}

#[test]
fn an_unsupported_envelope_version_cannot_even_be_constructed() {
    // Stronger than "it is rejected at verification": the checked constructor
    // refuses it, and `new` hardcodes V1, so there is no public path that
    // produces an envelope carrying an unknown version. A mirror cannot present
    // one at all. That is why this class is absent from the corpus rather than
    // scored in it -- scoring it would imply it had reached the verifier.
    let base = honest();
    let refused = VerifiedReadEnvelope::from_versioned_parts(
        99,
        base.head.clone(),
        Some(base.configuration.clone()),
        membership(base.queried.clone(), base.oid, base.proof.clone()),
    );
    assert!(matches!(
        refused,
        Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion { observed: 99 })
    ));

    // The permitted twin at the exact boundary: version 1 constructs.
    assert!(
        VerifiedReadEnvelope::from_versioned_parts(
            1,
            base.head,
            Some(base.configuration.clone()),
            membership(base.queried, base.oid, base.proof),
        )
        .is_ok()
    );
}

#[test]
fn the_corpus_covers_every_declared_tamper_class_exactly_once() {
    // The denominator guard. Asserted BEFORE the rate, because a rate over an
    // unpinned set says nothing: drop a class from `corpus()` and detection stays
    // at 100% while coverage quietly falls. This is the assertion that fails
    // instead.
    let mut present: Vec<TamperClass> = corpus().into_iter().map(|(class, _)| class).collect();
    let built = present.len();
    present.sort_unstable();
    present.dedup();

    assert_eq!(
        built,
        present.len(),
        "a class appears twice in the corpus, which would double-count it in the rate"
    );
    // Compile-time half: every declared class is named in the wildcard-free
    // match, so a variant cannot be added without the build stopping there.
    for class in TamperClass::ALL {
        class.is_declared();
    }

    let mut declared = TamperClass::ALL.to_vec();
    declared.sort_unstable();
    assert_eq!(
        present, declared,
        "the corpus and the declared class list disagree; a class was added or removed \
         without the other being updated"
    );
    assert_eq!(
        built,
        TamperClass::ALL.len(),
        "the corpus must build exactly one case per declared class"
    );

    // Emitted so the e2e can assert the TAMPER-CLASS count rather than the
    // test-function count. Counting functions cannot see a class being deleted
    // from `corpus()` -- the review's point -- because ten classes live inside
    // one function. This marker is the denominator made visible one layer up.
    println!("fg037b.tamper_classes={}", TamperClass::ALL.len());
}

#[test]
fn every_tampered_answer_in_the_corpus_is_rejected() {
    let (floor, pinned) = client();
    let mut undetected = Vec::new();
    for (class, envelope) in corpus() {
        if combined_client(&floor, &pinned, &envelope) == Detection::Accepted {
            undetected.push(class);
        }
    }
    assert!(
        undetected.is_empty(),
        "the combined client ACCEPTED tampered answers: {undetected:?}"
    );
}

#[test]
fn the_honest_answer_is_accepted_so_the_rate_is_not_a_client_that_refuses_everything() {
    // Without this, a 100% detection rate is equally satisfied by a verifier
    // that rejects its own valid input, which would be a broken client rather
    // than a safe one.
    let base = honest();
    let (floor, pinned) = client();
    let genuine = VerifiedReadEnvelope::new(
        base.head.clone(),
        Some(base.configuration.clone()),
        membership(base.queried, base.oid, base.proof),
    );
    assert_eq!(
        combined_client(&floor, &pinned, &genuine),
        Detection::Accepted,
        "the client must accept its own genuine answer, or a 100% detection rate is \
         just a broken verifier"
    );
}

#[test]
fn detections_are_spread_across_distinct_checks_not_funnelled_through_one() {
    // The guard that makes the rate mean something. If every case were caught
    // by the same refusal, the rate would not move if the other checks were
    // deleted, and it would be reporting one assertion wearing a corpus
    // costume.
    let (floor, pinned) = client();
    let mut by_class: BTreeMap<TamperClass, Detection> = BTreeMap::new();
    for (class, envelope) in corpus() {
        by_class.insert(class, combined_client(&floor, &pinned, &envelope));
    }

    let distinct: std::collections::BTreeSet<&Detection> = by_class.values().collect();
    assert!(
        distinct.len() >= 4,
        "detections funnelled through too few checks: {by_class:?}"
    );

    // And the class that only freshness can catch must be attributed to it.
    assert_eq!(
        by_class.get(&TamperClass::StaleHeadReplay),
        Some(&Detection::Freshness),
        "a replayed valid head must be caught by the floor"
    );
}

#[test]
fn envelope_verification_alone_accepts_the_replay_which_is_why_freshness_exists() {
    // The dependency made explicit. verify_envelope is CORRECT to accept this:
    // the proof really is valid against the head it names. Detection requires
    // memory of what the client already saw, which lives in the floor. Delete
    // freshness.rs and the corpus rate drops below 100%; this is the assertion
    // that would fail.
    let (_, pinned) = client();
    let replay = corpus()
        .into_iter()
        .find(|(class, _)| *class == TamperClass::StaleHeadReplay)
        .map(|(_, envelope)| envelope)
        .expect("the corpus contains a replay case");

    // Pinning the OLD head is what a client tricked into re-pinning would do,
    // and then the envelope verifies perfectly.
    let old_pin = PinnedAuthorityHead::new(replay.head().clone());
    assert!(
        verify_envelope(&old_pin, &replay).is_ok(),
        "the replayed answer must be internally valid, or it is not a replay"
    );

    // Against the client's actual pin it fails for a different reason -- the
    // head does not match -- which is not the same protection: a client that
    // re-pins on what the mirror hands it has no mismatch to notice.
    assert!(verify_envelope(&pinned, &replay).is_err());
}

#[test]
fn an_outcome_envelope_is_checked_against_the_outcome_index_root_not_whichever_root_verifies() {
    // Stated on its own because it is the one property of the outcome family
    // that no ref-path case can reach, and because "detected" is not the claim
    // -- "detected by the verifier, on the right root" is.
    //
    // The head is IDENTICAL in both halves, deliberately. Move it and the
    // freshness floor answers first: the obvious version of this case swapped
    // the head's outcome-index root for its ref root, and came back detected by
    // Freshness with the proof path never reached. Holding the head still is
    // what forces the envelope verifier to be the thing that answers.
    let base = honest();
    let outcome = honest_outcome();
    let pinned = PinnedAuthorityHead::new(base.head.clone());

    assert_ne!(
        base.head.ref_root, base.head.outcome_index_root,
        "the two roots must differ, or routing to the wrong one could not be observed"
    );

    // PERMITTED: the genuine outcome answer under the pinned head.
    let genuine = VerifiedReadEnvelope::new(
        outcome.head.clone(),
        None,
        VerifiedReadAnswer::OutcomeMembership {
            tx_id: outcome.tx_id,
            outcome: Box::new(outcome.outcome),
            proof: Box::new(outcome.proof),
        },
    );
    assert_eq!(
        verify_envelope(&pinned, &genuine),
        Ok(VerifiedMembership::Outcome),
        "the honest outcome answer must verify, or the refusal below proves only that \
         the verifier rejects everything"
    );

    // REFUSED: a real ref-membership proof, valid under `ref_root`, offered
    // where an outcome-index proof belongs. A verifier that tried each root
    // until one matched would accept this.
    let cross_root = VerifiedReadEnvelope::new(
        base.head.clone(),
        None,
        VerifiedReadAnswer::OutcomeMembership {
            tx_id: outcome.tx_id,
            outcome: Box::new(outcome.outcome),
            proof: Box::new(base.proof.clone()),
        },
    );
    assert_eq!(
        verify_envelope(&pinned, &cross_root),
        Err(VerifiedReadRefusal::ProofRejected),
        "a ref proof presented as an outcome answer must be refused"
    );

    // And the mirror, so this is a statement about ROUTING rather than about
    // outcome answers being fussy: the genuine OUTCOME proof offered as a REF
    // answer is refused too.
    let mirrored = VerifiedReadEnvelope::new(
        base.head.clone(),
        Some(base.configuration.clone()),
        membership(base.queried.clone(), base.oid, honest_outcome().proof),
    );
    assert_eq!(
        verify_envelope(&pinned, &mirrored),
        Err(VerifiedReadRefusal::ProofRejected),
        "and an outcome proof presented as a ref answer must be refused"
    );
}

#[test]
fn a_v1_configuration_cannot_stand_in_for_the_incarnation_body_the_head_selected() {
    // The variant a real node actually serves, which the corpus above never
    // reaches. `OneNode`'s genesis publishes a
    // `RepositoryIncarnationConfigurationBody`, so a production envelope
    // carries `RepositoryIncarnationV2`; every case in the corpus carries
    // `RepositoryV1`, because `VerifiedReadEnvelope::new` wraps it that way.
    //
    // NOT IN THE CORPUS, deliberately. A head whose `configuration_root` names
    // a different body is a different head, so the freshness floor answers
    // first: measured, the corpus version came back detected by Freshness with
    // the verifier never consulted, which made it an unlabelled duplicate of
    // `HeadConfigurationRoot` rather than a new class. Giving it its own pinned
    // head is what lets the configuration check be the thing that answers.
    let incarnation = incarnation_configuration();
    let pinned_head = head(
        2,
        None,
        honest().head.ref_root,
        incarnation_configuration_root(&incarnation),
    );
    let pinned = PinnedAuthorityHead::new(pinned_head.clone());
    let base = honest();

    // THE SEPARATION THIS RESTS ON, asserted rather than assumed. The two
    // configuration bodies share a DOMAIN ("frankengit/repository-configuration/v1")
    // AND a SCHEMA_FAMILY ("repository-configuration"); only SCHEMA_MAJOR
    // differs, 1 against 2. So nothing but the schema major reaching the digest
    // keeps a v1 body from standing in for a v2 one, and every other
    // configuration case in this file substitutes one v1 body for another,
    // which cannot test that.
    let v1_identity = body_id(&CryptoBodyIdentity, &base.configuration).expect("v1 identifies");
    let v2_identity = body_id(&CryptoBodyIdentity, &incarnation).expect("v2 identifies");
    assert_ne!(
        (v1_identity.algorithm(), v1_identity.digest()),
        (v2_identity.algorithm(), v2_identity.digest()),
        "the two configuration schemas share a domain and family, so if the major did not \
         reach the digest a v1 body could impersonate the incarnation the head bound"
    );

    // PERMITTED: the exact incarnation body the head selected.
    let genuine = VerifiedReadEnvelope::new_with_exact_configuration(
        pinned_head.clone(),
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2(
            incarnation,
        )),
        membership(base.queried.clone(), base.oid, base.proof.clone()),
    );
    assert_eq!(
        verify_envelope(&pinned, &genuine),
        Ok(VerifiedMembership::Ref),
        "the incarnation-bound answer must verify, or the refusal below proves only that \
         this head rejects everything"
    );

    // REFUSED: a v1 body in its place, carrying the same root layout so the
    // substitution is otherwise invisible.
    let swapped = VerifiedReadEnvelope::new(
        pinned_head,
        Some(base.configuration.clone()),
        membership(base.queried.clone(), base.oid, base.proof),
    );
    assert_eq!(
        verify_envelope(&pinned, &swapped),
        Err(VerifiedReadRefusal::ConfigurationRootMismatch),
        "a v1 configuration must not satisfy a head that bound an incarnation"
    );
}
