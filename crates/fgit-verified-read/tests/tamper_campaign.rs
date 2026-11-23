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
    CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
    RepositoryConfigurationBody, body_id, harness::commit_record,
};
use fgit_crypto::{
    IdentityDomain, MerkleProof, ObjectClosureNeighbour, ObjectClosureNonMembershipProof,
    object_closure_membership_proof, object_closure_merkle_root,
    object_closure_non_membership_proof, ref_state_membership_proof_v2, ref_state_merkle_root_v2,
};
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
    ObjectClosureWitness, PinnedAuthorityHead, VerifiedMembership, VerifiedReadAnswer,
    VerifiedReadAnswerV2, VerifiedReadConfiguration, VerifiedReadEnvelope, VerifiedReadEnvelopeV2,
    VerifiedReadRefusal, verify_envelope, verify_envelope_v2,
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
    OutcomeRootConfusion,
    /// An object closure membership answer with wrong object identity.
    ObjectIdentity,
    /// An object closure membership proof with tampered sibling.
    ObjectProofSibling,
    /// An object closure membership proof with wrong index.
    ObjectProofIndex,
    /// An object closure membership proof with wrong leaf count.
    ObjectProofLeafCount,
    /// An object proof presented as a ref membership proof.
    ObjectRootConfusion,
    /// An object non-membership proof with tampered predecessor neighbour.
    ObjectAbsencePredecessorTampered,
    /// An object non-membership proof with tampered successor neighbour.
    ObjectAbsenceSuccessorTampered,
    /// A forged commit-record witness substituted for the head-selected RCR.
    ObjectCommitWitnessSubstituted,
    /// A genesis-empty object witness claimed against a committed authority head.
    ObjectGenesisWitnessOnCommittedHead,
}

impl TamperClass {
    /// Every class the corpus must exercise.
    const ALL: [Self; 22] = [
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
        Self::ObjectIdentity,
        Self::ObjectProofSibling,
        Self::ObjectProofIndex,
        Self::ObjectProofLeafCount,
        Self::ObjectRootConfusion,
        Self::ObjectAbsencePredecessorTampered,
        Self::ObjectAbsenceSuccessorTampered,
        Self::ObjectCommitWitnessSubstituted,
        Self::ObjectGenesisWitnessOnCommittedHead,
    ];

    /// Ties `ALL` to the enum, which the array alone does not do.
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
            | Self::OutcomeRootConfusion
            | Self::ObjectIdentity
            | Self::ObjectProofSibling
            | Self::ObjectProofIndex
            | Self::ObjectProofLeafCount
            | Self::ObjectRootConfusion
            | Self::ObjectAbsencePredecessorTampered
            | Self::ObjectAbsenceSuccessorTampered
            | Self::ObjectCommitWitnessSubstituted
            | Self::ObjectGenesisWitnessOnCommittedHead => (),
        }
    }
}

#[derive(Clone, Debug)]
enum CorpusEnvelope {
    V1(VerifiedReadEnvelope),
    V2(VerifiedReadEnvelopeV2),
}

impl CorpusEnvelope {
    const fn head(&self) -> &RepositoryAuthorityHeadBody {
        match self {
            Self::V1(envelope) => envelope.head(),
            Self::V2(envelope) => envelope.head(),
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

/// The corpus's honest configuration carries the cumulative layout: the
/// object-family cases verify object-closure proofs, and per
/// `RootLayoutVersion::admits_object_closure_membership_proof` only
/// `RefStateAndObjectClosureMerkleV1` admits those — under the ref-only V1
/// layout the object closure root is still a whole-body digest, and the
/// verifier must refuse every honest object answer with
/// `ObjectLayout(LayoutAdmitsNoProof)`. The cumulative layout inherits V1's
/// ref-state tree, so the ref and outcome families verify identically under
/// it; production genesis (fgit-node) publishes this layout too.
fn configuration() -> RepositoryConfigurationBody {
    RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::AuthorityBoundObjectClosureMerkleV2,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: vec![b"refs/secret".to_vec()],
    }
}

/// A configuration with the hidden-ref policy STRIPPED, and otherwise identical.
const fn other_configuration() -> RepositoryConfigurationBody {
    RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::AuthorityBoundObjectClosureMerkleV2,
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

fn object_closure_oids() -> Vec<GitOid> {
    vec![oid(0x10), oid(0x20), oid(0x30), oid(0x40)]
}

fn committed_rcr_for(
    head: &RepositoryAuthorityHeadBody,
    object_root: Digest,
) -> RepositoryCommitRecord {
    let mut rcr = commit_record();
    rcr.repository_id = head.repository_id;
    rcr.resulting_ref_root = head.ref_root;
    rcr.object_closure_root = object_root;
    rcr.policy_epoch = head.policy_epoch;
    rcr
}

fn honest() -> Honest {
    let entries = ref_state();
    let root = ref_state_merkle_root_v2(&entries, None).expect("a v2 ref root");
    let configuration = configuration();
    let queried = name("refs/heads/main");
    let (found, proof) =
        ref_state_membership_proof_v2(&entries, None, &queried).expect("a membership proof");
    let mut base = head(2, None, root, configuration_root(&configuration));
    base.outcome_index_root =
        outcome_index_root(&outcome_index()).expect("a terminal outcome has a canonical root");
    let obj_root = object_closure_merkle_root(&object_closure_oids()).expect("object closure root");
    let rcr = committed_rcr_for(&base, obj_root);
    let rcr_id =
        RepositoryCommitId::from_internal_object_id(body_id(&CryptoBodyIdentity, &rcr).unwrap())
            .unwrap();
    base.latest_committed_rcr_id = Some(rcr_id);
    base.latest_repository_sequence = Some(rcr.repository_sequence);
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
    envelope: &CorpusEnvelope,
) -> Detection {
    if floor.judge(envelope.head()).is_err() {
        return Detection::Freshness;
    }
    let result = match envelope {
        CorpusEnvelope::V1(envelope) => verify_envelope(pinned, envelope),
        CorpusEnvelope::V2(envelope) => verify_envelope_v2(pinned, envelope),
    };
    match result {
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
        VerifiedReadRefusal::CommitRecordIdentityUnavailable => "CommitRecordIdentityUnavailable",
        VerifiedReadRefusal::ObjectWitnessHeadMismatch => "ObjectWitnessHeadMismatch",
        VerifiedReadRefusal::WireDecode(_) => "WireDecode",
        VerifiedReadRefusal::RefLayout(_) => "RefLayout",
        VerifiedReadRefusal::ObjectLayout(_) => "ObjectLayout",
        VerifiedReadRefusal::ProofRejected => "ProofRejected",
        VerifiedReadRefusal::Outcome(_) => "Outcome",
        VerifiedReadRefusal::RefNotFoundOrUnauthorized => "RefNotFoundOrUnauthorized",
        VerifiedReadRefusal::RefPresent => "RefPresent",
        VerifiedReadRefusal::ObjectNotFoundOrUnauthorized => "ObjectNotFoundOrUnauthorized",
        VerifiedReadRefusal::ObjectPresent => "ObjectPresent",
        VerifiedReadRefusal::ForgePositionProofUnavailable => "ForgePositionProofUnavailable",
    }
    .to_owned()
}

struct AllowAllObjectPolicy;

impl fgit_verified_read::ObjectDisclosurePolicy for AllowAllObjectPolicy {
    fn permits_object_disclosure(&self, _oid: &GitOid) -> bool {
        true
    }
}

/// The honest object-membership and non-membership answers these cases tamper with.
struct HonestObject {
    head: RepositoryAuthorityHeadBody,
    rcr: RepositoryCommitRecord,
    queried: GitOid,
    proof: MerkleProof,
    objects: Vec<GitOid>,
}

fn honest_object() -> HonestObject {
    let oids = object_closure_oids();
    let root = object_closure_merkle_root(&oids).expect("object closure root");
    let queried = oids[1];
    let proof = object_closure_membership_proof(&oids, &queried).expect("object membership proof");
    let head = honest().head;
    let rcr = committed_rcr_for(&head, root);
    HonestObject {
        head,
        rcr,
        queried,
        proof,
        objects: oids,
    }
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
        root_layout: RootLayoutVersion::AuthorityBoundObjectClosureMerkleV2,
        object_format: GitHashAlgorithm::Sha1,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x7A; 16]),
    }
}

fn incarnation_configuration_root(body: &RepositoryIncarnationConfigurationBody) -> Digest {
    let identity = body_id(&CryptoBodyIdentity, body).expect("an incarnation body identifies");
    Digest::new(identity.algorithm(), *identity.digest())
}

/// Every tampered envelope, paired with the class it represents.
fn corpus() -> Vec<(TamperClass, CorpusEnvelope)> {
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
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(name("refs/heads/injected"), base.oid, good_proof.clone()),
        )),
    ));

    // The right ref, the wrong object.
    cases.push((
        TamperClass::RefIdentity,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(base.queried.clone(), oid(0xFF), good_proof.clone()),
        )),
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
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(good_config.clone()),
            membership(
                base.queried.clone(),
                base.oid,
                MerkleProof::new(good_proof.index(), good_proof.leaf_count(), siblings),
            ),
        )),
    ));

    // The right leaf, claimed at the wrong position.
    cases.push((
        TamperClass::ProofIndex,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
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
        )),
    ));

    // A different tree shape, which changes how the fold pairs and promotes.
    cases.push((
        TamperClass::ProofLeafCount,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
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
        )),
    ));

    // A head whose ref_root is not the root the proof was built against.
    cases.push((
        TamperClass::HeadRefRoot,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            head(2, None, digest(0xAB), configuration_root(&good_config)),
            Some(good_config.clone()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        )),
    ));

    // A head whose configuration_root does not identify the carried body.
    cases.push((
        TamperClass::HeadConfigurationRoot,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            head(2, None, good_head.ref_root, digest(0xCD)),
            Some(good_config.clone()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        )),
    ));

    // A different configuration body under the honest head.
    cases.push((
        TamperClass::ConfigurationSubstituted,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            good_head.clone(),
            Some(other_configuration()),
            membership(base.queried.clone(), base.oid, good_proof.clone()),
        )),
    ));

    // No configuration at all, which forces the legacy layout that admits no
    // ref-state membership proof.
    cases.push((
        TamperClass::ConfigurationRemoved,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            good_head,
            None,
            membership(base.queried.clone(), base.oid, good_proof),
        )),
    ));

    // A genuine, fully valid answer about an OLDER head. Nothing here is
    // forged; this is the replay.
    let old_entries = vec![(name("refs/heads/main"), oid(0x11))];
    let old_root = ref_state_merkle_root_v2(&old_entries, None).expect("a v2 root");
    let old_head = head(1, None, old_root, configuration_root(&good_config));
    let (old_oid, old_proof) =
        ref_state_membership_proof_v2(&old_entries, None, &name("refs/heads/main"))
            .expect("a v2 proof");
    cases.push((
        TamperClass::StaleHeadReplay,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            old_head,
            Some(good_config.clone()),
            membership(name("refs/heads/main"), old_oid, old_proof),
        )),
    ));

    // --- the outcome-membership family ---------------------------------
    let honest_outcome = honest_outcome();

    cases.push((
        TamperClass::OutcomeTxId,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: tx(0xB2),
                outcome: Box::new(honest_outcome.outcome),
                proof: Box::new(honest_outcome.proof.clone()),
            },
        )),
    ));

    cases.push((
        TamperClass::OutcomeSubstituted,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: honest_outcome.tx_id,
                outcome: Box::new(committed(2, 0x66)),
                proof: Box::new(honest_outcome.proof.clone()),
            },
        )),
    ));

    assert_ne!(
        base.head.ref_root, base.head.outcome_index_root,
        "the two roots must genuinely differ, or routing to the wrong one is undetectable"
    );
    cases.push((
        TamperClass::OutcomeRootConfusion,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            honest_outcome.head.clone(),
            None,
            VerifiedReadAnswer::OutcomeMembership {
                tx_id: honest_outcome.tx_id,
                outcome: Box::new(honest_outcome.outcome),
                proof: Box::new(ref_proof_for_cross_root),
            },
        )),
    ));

    // --- the authority-bound object-closure family (Envelope V2) -------
    let honest_object = honest_object();
    let witness = ObjectClosureWitness::SelectedCommitRecord(Box::new(honest_object.rcr.clone()));

    // Wrong object identity.
    cases.push((
        TamperClass::ObjectIdentity,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: oid(0x99),
                witness: witness.clone(),
                proof: Box::new(honest_object.proof.clone()),
            },
        )),
    ));

    // A flipped byte in the first sibling of object proof.
    let mut obj_siblings = honest_object.proof.siblings().to_vec();
    if let Some(first) = obj_siblings.first_mut() {
        let mut bytes = first.as_bytes().to_vec();
        bytes[0] ^= 0xFF;
        *first = DigestBytes::try_new(&bytes).expect("bounded");
    }
    cases.push((
        TamperClass::ObjectProofSibling,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: honest_object.queried,
                witness: witness.clone(),
                proof: Box::new(MerkleProof::new(
                    honest_object.proof.index(),
                    honest_object.proof.leaf_count(),
                    obj_siblings,
                )),
            },
        )),
    ));

    // Wrong index in object proof.
    cases.push((
        TamperClass::ObjectProofIndex,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: honest_object.queried,
                witness: witness.clone(),
                proof: Box::new(MerkleProof::new(
                    honest_object.proof.index().saturating_add(1),
                    honest_object.proof.leaf_count(),
                    honest_object.proof.siblings().to_vec(),
                )),
            },
        )),
    ));

    // Wrong leaf count in object proof.
    cases.push((
        TamperClass::ObjectProofLeafCount,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: honest_object.queried,
                witness: witness.clone(),
                proof: Box::new(MerkleProof::new(
                    honest_object.proof.index(),
                    honest_object.proof.leaf_count().saturating_add(2),
                    honest_object.proof.siblings().to_vec(),
                )),
            },
        )),
    ));

    // Object proof presented as a ref membership proof.
    cases.push((
        TamperClass::ObjectRootConfusion,
        CorpusEnvelope::V1(VerifiedReadEnvelope::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            membership(
                name("refs/heads/main"),
                honest_object.queried,
                honest_object.proof.clone(),
            ),
        )),
    ));

    // Non-membership proof with tampered predecessor neighbour.
    let absence_target = oid(0x25);
    let honest_absence_proof =
        object_closure_non_membership_proof(&honest_object.objects, &absence_target)
            .expect("absence proof");
    let tampered_pred = match honest_absence_proof.clone() {
        ObjectClosureNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            let bad_pred = ObjectClosureNeighbour::new(oid(0x19), predecessor.proof().clone());
            ObjectClosureNonMembershipProof::Between {
                predecessor: Box::new(bad_pred),
                successor,
            }
        }
        _ => unreachable!(),
    };
    let absence =
        fgit_verified_read::authorize_object_absence(&AllowAllObjectPolicy, absence_target, |_| {
            false
        })
        .expect("authorized absence");
    cases.push((
        TamperClass::ObjectAbsencePredecessorTampered,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::AuthorizedObjectAbsence {
                absence: absence.clone(),
                witness: witness.clone(),
                proof: Box::new(tampered_pred),
            },
        )),
    ));

    // Non-membership proof with tampered successor neighbour.
    let tampered_succ = match honest_absence_proof {
        ObjectClosureNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            let bad_succ = ObjectClosureNeighbour::new(oid(0x35), successor.proof().clone());
            ObjectClosureNonMembershipProof::Between {
                predecessor,
                successor: Box::new(bad_succ),
            }
        }
        _ => unreachable!(),
    };
    cases.push((
        TamperClass::ObjectAbsenceSuccessorTampered,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::AuthorizedObjectAbsence {
                absence,
                witness,
                proof: Box::new(tampered_succ),
            },
        )),
    ));

    // Forged commit-record witness substituted by the mirror for a forged proof.
    let mut forged_rcr = honest_object.rcr.clone();
    forged_rcr.object_closure_root =
        object_closure_merkle_root(&[oid(0x99)]).expect("forged object closure root");
    let forged_proof =
        object_closure_membership_proof(&[oid(0x99)], &oid(0x99)).expect("forged proof");
    cases.push((
        TamperClass::ObjectCommitWitnessSubstituted,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head.clone(),
            Some(good_config.clone()),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: oid(0x99),
                witness: ObjectClosureWitness::SelectedCommitRecord(Box::new(forged_rcr)),
                proof: Box::new(forged_proof),
            },
        )),
    ));

    // Genesis-empty witness claimed against a committed authority head.
    cases.push((
        TamperClass::ObjectGenesisWitnessOnCommittedHead,
        CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
            honest_object.head,
            Some(good_config),
            VerifiedReadAnswerV2::ObjectMembership {
                oid: honest_object.queried,
                witness: ObjectClosureWitness::GenesisEmpty,
                proof: Box::new(honest_object.proof),
            },
        )),
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

    assert!(
        VerifiedReadEnvelope::from_versioned_parts(
            1,
            base.head.clone(),
            Some(base.configuration.clone()),
            membership(base.queried.clone(), base.oid, base.proof.clone()),
        )
        .is_ok()
    );

    let refused_v2 = VerifiedReadEnvelopeV2::from_versioned_parts(
        1,
        base.head.clone(),
        Some(base.configuration.clone()),
        VerifiedReadAnswerV2::RefMembership {
            name: base.queried.clone(),
            oid: base.oid,
            proof: Box::new(base.proof.clone()),
        },
    );
    assert!(matches!(
        refused_v2,
        Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion { observed: 1 })
    ));
    assert!(
        VerifiedReadEnvelopeV2::from_versioned_parts(
            2,
            base.head,
            Some(base.configuration),
            VerifiedReadAnswerV2::RefMembership {
                name: base.queried,
                oid: base.oid,
                proof: Box::new(base.proof),
            },
        )
        .is_ok()
    );
}

#[test]
fn the_corpus_covers_every_declared_tamper_class_exactly_once() {
    let mut present: Vec<TamperClass> = corpus().into_iter().map(|(class, _)| class).collect();
    let built = present.len();
    present.sort_unstable();
    present.dedup();

    assert_eq!(
        built,
        present.len(),
        "a class appears twice in the corpus, which would double-count it in the rate"
    );
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
    let base = honest();
    let (floor, pinned) = client();
    let genuine = CorpusEnvelope::V1(VerifiedReadEnvelope::new(
        base.head.clone(),
        Some(base.configuration.clone()),
        membership(base.queried, base.oid, base.proof),
    ));
    assert_eq!(
        combined_client(&floor, &pinned, &genuine),
        Detection::Accepted,
        "the client must accept its own genuine answer, or a 100% detection rate is \
         just a broken verifier"
    );
}

#[test]
fn detections_are_spread_across_distinct_checks_not_funnelled_through_one() {
    let (floor, pinned) = client();
    let mut by_class: BTreeMap<TamperClass, Detection> = BTreeMap::new();
    for (class, envelope) in corpus() {
        by_class.insert(class, combined_client(&floor, &pinned, &envelope));
    }

    let distinct: std::collections::BTreeSet<&Detection> = by_class.values().collect();
    assert!(
        distinct.len() >= 5,
        "detections funnelled through too few checks: {by_class:?}"
    );

    assert_eq!(
        by_class.get(&TamperClass::StaleHeadReplay),
        Some(&Detection::Freshness),
        "a replayed valid head must be caught by the floor"
    );
    assert_eq!(
        by_class.get(&TamperClass::ObjectCommitWitnessSubstituted),
        Some(&Detection::Envelope("ObjectWitnessHeadMismatch".to_owned())),
        "a forged commit-record witness must be caught by authority-head RCR binding"
    );
}

#[test]
fn envelope_verification_alone_accepts_the_replay_which_is_why_freshness_exists() {
    let (_, pinned) = client();
    let CorpusEnvelope::V1(replay) = corpus()
        .into_iter()
        .find(|(class, _)| *class == TamperClass::StaleHeadReplay)
        .map(|(_, envelope)| envelope)
        .expect("the corpus contains a replay case")
    else {
        panic!("stale head replay case uses a V1 envelope");
    };

    let old_pin = PinnedAuthorityHead::new(replay.head().clone());
    assert!(
        verify_envelope(&old_pin, &replay).is_ok(),
        "the replayed answer must be internally valid, or it is not a replay"
    );

    assert!(verify_envelope(&pinned, &replay).is_err());
}

#[test]
fn an_outcome_envelope_is_checked_against_the_outcome_index_root_not_whichever_root_verifies() {
    let base = honest();
    let outcome = honest_outcome();
    let pinned = PinnedAuthorityHead::new(base.head.clone());

    assert_ne!(
        base.head.ref_root, base.head.outcome_index_root,
        "the two roots must differ, or routing to the wrong one could not be observed"
    );

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
    );

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
    let incarnation = incarnation_configuration();
    let pinned_head = head(
        2,
        None,
        honest().head.ref_root,
        incarnation_configuration_root(&incarnation),
    );
    let pinned = PinnedAuthorityHead::new(pinned_head.clone());
    let base = honest();

    let v1_identity = body_id(&CryptoBodyIdentity, &base.configuration).expect("v1 identifies");
    let v2_identity = body_id(&CryptoBodyIdentity, &incarnation).expect("v2 identifies");
    assert_ne!(
        (v1_identity.algorithm(), v1_identity.digest()),
        (v2_identity.algorithm(), v2_identity.digest()),
    );

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
    );

    let swapped = VerifiedReadEnvelope::new(
        pinned_head,
        Some(base.configuration.clone()),
        membership(base.queried.clone(), base.oid, base.proof),
    );
    assert_eq!(
        verify_envelope(&pinned, &swapped),
        Err(VerifiedReadRefusal::ConfigurationRootMismatch),
    );
}

#[test]
fn the_honest_object_answers_are_accepted() {
    let (floor, pinned) = client();
    let obj = honest_object();
    let witness = ObjectClosureWitness::SelectedCommitRecord(Box::new(obj.rcr));
    let genuine_membership = CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
        obj.head.clone(),
        Some(honest().configuration),
        VerifiedReadAnswerV2::ObjectMembership {
            oid: obj.queried,
            witness: witness.clone(),
            proof: Box::new(obj.proof),
        },
    ));
    assert_eq!(
        combined_client(&floor, &pinned, &genuine_membership),
        Detection::Accepted,
        "the client must accept honest authority-bound object membership"
    );

    let absence_target = oid(0x25);
    let absence_proof =
        object_closure_non_membership_proof(&obj.objects, &absence_target).expect("absence proof");
    let absence =
        fgit_verified_read::authorize_object_absence(&AllowAllObjectPolicy, absence_target, |_| {
            false
        })
        .expect("authorized absence");
    let genuine_absence = CorpusEnvelope::V2(VerifiedReadEnvelopeV2::new(
        obj.head,
        Some(honest().configuration),
        VerifiedReadAnswerV2::AuthorizedObjectAbsence {
            absence,
            witness,
            proof: Box::new(absence_proof),
        },
    ));
    assert_eq!(
        combined_client(&floor, &pinned, &genuine_absence),
        Detection::Accepted,
        "the client must accept honest authority-bound object absence"
    );
}

#[test]
fn an_object_envelope_is_checked_against_the_authority_bound_commit_witness() {
    let base = honest();
    let obj = honest_object();
    let pinned = PinnedAuthorityHead::new(base.head.clone());

    let genuine = VerifiedReadEnvelopeV2::new(
        base.head.clone(),
        Some(base.configuration.clone()),
        VerifiedReadAnswerV2::ObjectMembership {
            oid: obj.queried,
            witness: ObjectClosureWitness::SelectedCommitRecord(Box::new(obj.rcr.clone())),
            proof: Box::new(obj.proof.clone()),
        },
    );
    assert_eq!(
        verify_envelope_v2(&pinned, &genuine),
        Ok(VerifiedMembership::Object),
    );

    // Refused: non-authority-bound layout (`RefStateAndObjectClosureMerkleV2`) cannot verify object proofs.
    let legacy_config = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    };
    let mut legacy_head = base.head.clone();
    legacy_head.configuration_root = configuration_root(&legacy_config);
    let mut legacy_rcr = obj.rcr.clone();
    let legacy_rcr_id = RepositoryCommitId::from_internal_object_id(
        body_id(&CryptoBodyIdentity, &legacy_rcr).unwrap(),
    )
    .unwrap();
    legacy_head.latest_committed_rcr_id = Some(legacy_rcr_id);
    let legacy_pin = PinnedAuthorityHead::new(legacy_head.clone());
    let legacy_envelope = VerifiedReadEnvelopeV2::new(
        legacy_head,
        Some(legacy_config),
        VerifiedReadAnswerV2::ObjectMembership {
            oid: obj.queried,
            witness: ObjectClosureWitness::SelectedCommitRecord(Box::new(legacy_rcr.clone())),
            proof: Box::new(obj.proof.clone()),
        },
    );
    assert!(matches!(
        verify_envelope_v2(&legacy_pin, &legacy_envelope),
        Err(VerifiedReadRefusal::ObjectLayout(_))
    ));

    // Refused: tampered object_closure_root inside carried commit record fails head RCR ID binding.
    legacy_rcr.object_closure_root = digest(0xEE);
    let tampered_witness = VerifiedReadEnvelopeV2::new(
        base.head,
        Some(base.configuration),
        VerifiedReadAnswerV2::ObjectMembership {
            oid: obj.queried,
            witness: ObjectClosureWitness::SelectedCommitRecord(Box::new(legacy_rcr)),
            proof: Box::new(obj.proof),
        },
    );
    assert_eq!(
        verify_envelope_v2(&pinned, &tampered_witness),
        Err(VerifiedReadRefusal::ObjectWitnessHeadMismatch),
    );
}
