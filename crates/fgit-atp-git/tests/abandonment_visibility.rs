//! FG-022b: cancellation mid-transfer — what ATP-Git can and cannot promise.
//!
//! The bead's campaign line is *"cancellation mid-transfer (quiescent, no
//! partial visibility)"*. That decomposes into two halves with different
//! owners, and conflating them would let this crate claim something it does not
//! implement.
//!
//! # Measured: there is no cancellation surface in this crate
//!
//! `fgit-atp-git` is entirely synchronous. Its `src/lib.rs` contains **zero**
//! occurrences of `async fn`, `await`, `Cx`, or `cancel`, and its dependency
//! list is `fgit-crypto`, `fgit-object-fabric`, `fgit-types` with no runtime.
//!
//! Checked one layer down as well, because on a sibling bead I concluded five
//! separate times that something was undrivable by reading a single layer and
//! was wrong every time. `fgit-object-fabric` *does* carry a cancellation
//! surface — an `asupersync` dependency, a `cx: &Cx<Caps>` parameter at
//! `fabric.rs:908`, and `async fn open_verified_stream` at `local.rs:670`. But
//! that surface is in its **storage** layer, and ATP imports only
//! `Commitment`, `CryptoDigest`, `DigestAlgorithm`, `DigestDomain`,
//! `FabricError`, `ObjectEnvelope`, `ObjectKind`, `SegmentLimits`,
//! `StoreRefusal` and `VerifiedObject` — none of which is async or takes a
//! context. ATP reaches storage only through `VerifiedObjectLookup`, a
//! synchronous trait it defines itself.
//!
//! So **"quiescent" is not ATP's property to hold**. It belongs to whichever
//! runtime drives the caller, and a test here asserting it would be measuring
//! its own harness.
//!
//! # What IS ATP's half, and it is testable
//!
//! "No partial visibility" is entirely ATP's, and abandoning a transfer is
//! observationally the same as any other early exit: the question is what the
//! receiver's quarantine holds when the call does not complete. `reconstruct`
//! validates every manifest entry before it stages anything, so an abandonment
//! before that point leaves nothing behind — already measured across five
//! refusal paths in `payload_integrity.rs`.
//!
//! This file probes the one place where the property is **not** structural: the
//! final staging loop calls `QuarantineSink::stage_verified` per object and
//! propagates its error with `?`. An abandonment there is mid-loop, and some
//! objects are already in.
//!
//! That is not filed as a defect. Quarantine is by definition the unpublished
//! area, and NPC §5.5 puts the check on publication rather than on staging.
//! But it is a real boundary on the phrase "no partial visibility", and the
//! difference between a bounded property and an unbounded one is exactly what
//! the acceptance line is asking for — so it is measured and named rather than
//! left for a reader to assume.

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, HaveSummary, PeerCapabilities,
    PeerCapabilityVerifier, PeerIdentity, PlanSelector, QuarantineSink, ReconstructionOutcome,
    ReconstructionPipeline, TransferLimits, TransferManifest, TransferObjectEntry, TransferPayload,
    TransferPlan, VerifiedObjectLookup,
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

struct KnowsNothing;

impl VerifiedObjectLookup for KnowsNothing {
    fn read_verified(&self, _identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal> {
        Ok(None)
    }
}

/// A receiver that abandons the transfer after accepting `accept_first`
/// objects, standing in for a caller cancelled mid-staging.
#[derive(Debug)]
struct AbandonsAfter {
    accept_first: usize,
    accepted: Vec<GitOid>,
}

impl AbandonsAfter {
    const fn new(accept_first: usize) -> Self {
        Self {
            accept_first,
            accepted: Vec::new(),
        }
    }
}

impl QuarantineSink for AbandonsAfter {
    fn stage_verified(&mut self, object: VerifiedObject) -> Result<(), AtpRefusal> {
        if self.accepted.len() >= self.accept_first {
            return Err(AtpRefusal::EmptyNamespace);
        }
        self.accepted.push(object.identity());
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

fn plan(manifest: &TransferManifest) -> TransferPlan {
    let have = HaveSummary::exact_objects(Vec::new(), limits()).expect("an empty inventory");
    PlanSelector::new(limits()).select(manifest, &capable(1), &capable(2), &have)
}

fn pipeline() -> ReconstructionPipeline {
    ReconstructionPipeline::new(b"fg022b".to_vec(), SegmentLimits::default(), limits())
        .expect("a named namespace inside the envelope bound")
}

fn all_payloads() -> Vec<TransferPayload> {
    CONTENTS
        .iter()
        .map(|c| TransferPayload::new(c.to_vec()).expect("a valid payload"))
        .collect()
}

fn run_with(sink: &mut AbandonsAfter) -> Result<ReconstructionOutcome, AtpRefusal> {
    let manifest = manifest();
    let plan = plan(&manifest);
    pipeline().reconstruct(&manifest, &plan, all_payloads(), &KnowsNothing, sink)
}

// ------------------------------------------------------------- the control

#[test]
fn a_receiver_that_never_abandons_takes_the_whole_closure() {
    // THE CONTROL. The two tests below assert that abandonment limits what is
    // staged, and both would pass against a pipeline that staged nothing at
    // all. This is what makes the counts underneath meaningful.
    let mut sink = AbandonsAfter::new(usize::MAX);

    let outcome = run_with(&mut sink).expect("a receiver that accepts everything must complete");

    assert!(
        matches!(outcome, ReconstructionOutcome::Complete(_)),
        "an unabandoned transfer with a complete payload set must complete; got {outcome:?}"
    );
    assert_eq!(
        sink.accepted.len(),
        CONTENTS.len(),
        "every object must reach quarantine when nothing interrupts; got {:?}",
        sink.accepted
    );
}

// -------------------------------------------- abandonment before any staging

#[test]
fn abandoning_before_the_first_object_leaves_quarantine_empty() {
    // The property in its strong form. A receiver that refuses the very first
    // staging call has, from its own point of view, cancelled the transfer
    // before any of it became visible — and nothing is left behind.
    let mut sink = AbandonsAfter::new(0);

    let outcome = run_with(&mut sink);

    assert!(
        outcome.is_err(),
        "a receiver that refuses staging must not be told the transfer completed; got {outcome:?}"
    );
    assert!(
        sink.accepted.is_empty(),
        "nothing may be visible after an abandonment that preceded all staging; it holds {:?}",
        sink.accepted
    );
}

// -------------------------------------------- abandonment part-way through

#[test]
fn abandoning_mid_staging_leaves_exactly_what_was_already_accepted_and_no_more() {
    // THE BOUNDARY, measured rather than assumed, and the reason this file
    // exists rather than deferring to `payload_integrity.rs`.
    //
    // Every refusal path *before* the staging loop leaves quarantine empty --
    // that is structural and already proved. The staging loop itself is
    // different: it calls `stage_verified` per object and propagates with `?`,
    // so a receiver abandoning at object two has object one in hand.
    //
    // This is NOT filed as a defect. Quarantine is by definition the
    // unpublished area and §5.5 puts the check on publication, so a partially
    // populated quarantine is not partial *visibility* in the sense that
    // matters. But "no partial visibility" is bounded rather than absolute, and
    // the bound belongs in evidence rather than in a reader's assumption.
    let mut sink = AbandonsAfter::new(1);

    let outcome = run_with(&mut sink);

    assert!(
        outcome.is_err(),
        "an abandoned transfer must never report completion; got {outcome:?}"
    );
    assert_eq!(
        sink.accepted.len(),
        1,
        "the receiver accepted exactly one object before abandoning, so exactly one may have \
         reached it -- more would mean staging continued past the abandonment, which is the \
         failure this test exists to exclude; it holds {:?}",
        sink.accepted
    );

    // And no receipt exists, so nothing downstream can treat the partial set as
    // a closure. That is what keeps the partial staging harmless.
    assert!(
        !matches!(outcome, Ok(ReconstructionOutcome::Complete(_))),
        "a partial stage must not yield a completion receipt, or the caller could publish an \
         incomplete closure"
    );
}
