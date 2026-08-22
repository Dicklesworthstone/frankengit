//! FG-022b: summary poisoning — the harm is efficiency, and only efficiency.
//!
//! The bead's campaign line is *"summary poisoning (efficiency-only harm
//! proven)"*. A have-summary is a **hint supplied by the other side**, so the
//! interesting question is not whether it can be wrong — it can, trivially —
//! but what a wrong one is able to cost.
//!
//! `HaveSummary::Probabilistic` filters out every object the summary
//! `may_contain`, so a false positive **omits an object from the transfer**. An
//! attacker who sets every bit therefore causes the sender to select *nothing*.
//! That is the maximum available harm, and this file's job is to show it stops
//! at "a wasted round trip" rather than reaching "a receiver that believes it
//! has an object it does not".
//!
//! The mechanism that bounds it is one flag: probabilistic selection sets
//! `requires_exact_closure_repair`, and the reconstruction pipeline validates
//! every manifest entry against real payloads or real locally-verified objects
//! regardless of what the summary claimed. A positive answer from a Bloom
//! filter proves nothing and is never allowed to stand in for that check.
//!
//! # Why the poisoned case needs the honest case beside it
//!
//! "The poisoned summary produced a repair request" is satisfied by a pipeline
//! that requests repair unconditionally, which would be useless in a different
//! direction. `an_honest_summary_completes_without_repair` is the control, and
//! it is what makes the poisoning result mean the summary caused the change.
//!
//! # Non-claims
//!
//! This covers a summary that lies by **over-claiming** — the direction that
//! omits objects. A summary that under-claims costs the sender bytes it did not
//! need to send, which is a bandwidth question rather than a correctness one
//! and is not exercised here. Nothing touches `fgit-atp-git/src`.

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, BloomHaveSummary, HaveSummary,
    PeerCapabilities, PeerCapabilityVerifier, PeerIdentity, PlanSelector, ReconstructionOutcome,
    ReconstructionPipeline, TransferLimits, TransferManifest, TransferObjectEntry, TransferPayload,
    TransferPlan, TransferPlanKind, VerifiedObjectLookup,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_object_fabric::fabric::VerifiedObject;
use fgit_object_fabric::{ObjectKind, SegmentLimits};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId};

struct AcceptingVerifier;

impl PeerCapabilityVerifier for AcceptingVerifier {
    fn verify(&self, _offered: &PeerCapabilities) -> Result<(), AtpRefusal> {
        Ok(())
    }
}

/// A receiver that has verified nothing locally.
///
/// Load-bearing here: if the lookup could satisfy an object, a poisoned summary
/// would be rescued by local storage and the test would measure the lookup
/// rather than the summary.
struct KnowsNothing;

impl VerifiedObjectLookup for KnowsNothing {
    fn read_verified(&self, _identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct Quarantine(Vec<GitOid>);

impl fgit_atp_git::QuarantineSink for Quarantine {
    fn stage_verified(&mut self, object: VerifiedObject) -> Result<(), AtpRefusal> {
        self.0.push(object.identity());
        Ok(())
    }
}

fn limits() -> TransferLimits {
    TransferLimits::new(64, 1 << 20, 1 << 24, 64).expect("positive bounds are admissible")
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

fn capable(byte: u8) -> AuthenticatedPeerCapabilities {
    let offered = PeerCapabilities::new(
        PeerIdentity::from_bytes([byte; 32]),
        repository(),
        [AtpGitProfile::ConservativeInterimV1],
        true,
    );
    AuthenticatedPeerCapabilities::verify(offered, &AcceptingVerifier).expect("accepting verifier")
}

const CONTENTS: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];

fn entry(payload: &[u8]) -> TransferObjectEntry {
    let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, payload);
    TransferObjectEntry::from_payload(identity, ObjectKind::Blob, payload, None)
        .expect("a payload identified by its own digest is a valid entry")
}

fn manifest() -> TransferManifest {
    let mut entries: Vec<TransferObjectEntry> = CONTENTS.iter().map(|c| entry(c)).collect();
    entries.sort_by_key(TransferObjectEntry::identity);
    let roots = vec![entries.last().expect("three entries").identity()];
    TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        roots,
        entries,
        limits(),
    )
    .expect("canonical manifest")
}

/// Every bit set: the filter answers "may contain" for every identity.
///
/// This is the strongest lie the summary format can tell in the direction that
/// removes work, and therefore the right adversary to measure against. A
/// subtler poisoning is strictly weaker.
fn poisoned_summary() -> HaveSummary {
    let bytes = vec![0xFF_u8; limits().max_probabilistic_summary_bytes()];
    let bit_count = u32::try_from(bytes.len() * 8).expect("a small bit count");
    HaveSummary::Probabilistic(
        BloomHaveSummary::from_wire(bit_count, &bytes, limits()).expect("within the request bound"),
    )
}

/// An all-zero filter: claims nothing, so it removes no work.
fn honest_summary() -> HaveSummary {
    let bytes = vec![0x00_u8; limits().max_probabilistic_summary_bytes()];
    let bit_count = u32::try_from(bytes.len() * 8).expect("a small bit count");
    HaveSummary::Probabilistic(
        BloomHaveSummary::from_wire(bit_count, &bytes, limits()).expect("within the request bound"),
    )
}

fn plan_for(manifest: &TransferManifest, have: &HaveSummary) -> TransferPlan {
    PlanSelector::new(limits()).select(manifest, &capable(1), &capable(2), have)
}

fn pipeline() -> ReconstructionPipeline {
    ReconstructionPipeline::new(b"fg022b".to_vec(), SegmentLimits::default(), limits())
        .expect("a named namespace inside the envelope bound")
}

/// Send exactly the payloads the plan asked for — an honest sender obeying a
/// possibly-poisoned plan.
fn payloads_for(plan: &TransferPlan) -> Vec<TransferPayload> {
    let wanted: Vec<GitOid> = plan
        .payloads()
        .iter()
        .flat_map(|payload| payload.object_identities().iter().copied())
        .collect();
    CONTENTS
        .iter()
        .filter(|content| {
            let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, content);
            wanted.contains(&identity)
        })
        .map(|content| TransferPayload::new(content.to_vec()).expect("a valid payload"))
        .collect()
}

// ---------------------------------------------------------- the honest control

#[test]
fn an_honest_summary_completes_without_repair() {
    // THE CONTROL. "The poisoned summary asked for repair" is also satisfied by
    // a pipeline that asks for repair unconditionally, which would be broken in
    // the other direction. This is what makes the poisoning result attributable
    // to the summary.
    let manifest = manifest();
    let plan = plan_for(&manifest, &honest_summary());
    let mut quarantine = Quarantine::default();

    let outcome = pipeline()
        .reconstruct(
            &manifest,
            &plan,
            payloads_for(&plan),
            &KnowsNothing,
            &mut quarantine,
        )
        .expect("an honest summary and a complete payload set must not be refused");

    match outcome {
        ReconstructionOutcome::Complete(receipt) => assert_eq!(
            receipt.staged().len(),
            CONTENTS.len(),
            "an honest all-zero filter removes no work, so every object must be transferred and \
             staged; got {:?}",
            receipt.staged()
        ),
        ReconstructionOutcome::Repair(request) => panic!(
            "an honest summary must not need repair; it wants {:?}",
            request.missing()
        ),
    }
}

// ------------------------------------------------------------- the poisoning

#[test]
fn a_poisoned_summary_removes_every_object_from_the_plan() {
    // The harm, measured at its maximum. Every bit set means `may_contain` is
    // true for every identity, so the sender selects nothing at all.
    let manifest = manifest();
    let plan = plan_for(&manifest, &poisoned_summary());

    assert!(
        plan.payloads().is_empty(),
        "a filter claiming everything must remove every object from the plan -- otherwise this \
         test is not measuring the worst case; it planned {:?}",
        plan.payloads().len()
    );

    // And the plan says so. This flag is the entire reason the lie is bounded.
    assert!(
        plan.receipt().requires_exact_closure_repair(),
        "a probabilistic selection must mark itself as requiring the exact closure check; without \
         that flag a poisoned summary would silently become a truncated transfer"
    );

    // It must NOT be reported as already in sync. That plan class asserts the
    // receiver needs nothing, which is precisely the lie being told.
    assert_ne!(
        plan.receipt().plan_kind(),
        TransferPlanKind::AlreadyInSync,
        "an empty selection driven by a probabilistic hint must not be reported as AlreadyInSync; \
         a positive Bloom answer proves nothing and cannot license that conclusion"
    );
}

#[test]
fn a_poisoned_summary_costs_a_round_trip_and_never_a_wrong_end_state() {
    // The property the bead asks for, stated as an outcome rather than an
    // intention: the receiver, having been lied to as hard as the format
    // allows, ends up with NOTHING STAGED and an exact list of what it still
    // needs. The cost is one more exchange. The end state is not wrong.
    let manifest = manifest();
    let plan = plan_for(&manifest, &poisoned_summary());
    let mut quarantine = Quarantine::default();

    let outcome = pipeline()
        .reconstruct(
            &manifest,
            &plan,
            payloads_for(&plan),
            &KnowsNothing,
            &mut quarantine,
        )
        .expect("a poisoned summary is a bad hint, not a protocol violation");

    match outcome {
        ReconstructionOutcome::Repair(request) => {
            let mut wanted: Vec<GitOid> = CONTENTS
                .iter()
                .map(|c| git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, c))
                .collect();
            wanted.sort();
            let mut missing = request.missing().to_vec();
            missing.sort();
            assert_eq!(
                missing, wanted,
                "the repair request must name every object the lie removed, so the next exchange \
                 is exact rather than a retry from scratch"
            );
        }
        ReconstructionOutcome::Complete(receipt) => panic!(
            "the receiver must not conclude it is complete on the strength of a filter it did not \
             produce; it staged {:?}",
            receipt.staged()
        ),
    }

    assert!(
        quarantine.0.is_empty(),
        "nothing may reach quarantine from a transfer that carried no verified payloads; it \
         received {:?}",
        quarantine.0
    );
}
