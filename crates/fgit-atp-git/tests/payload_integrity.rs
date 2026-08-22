//! FG-022b: corrupted, truncated, reordered, duplicated and omitted payloads.
//!
//! The bead's first campaign line is *"corrupted/truncated/reordered transfer
//! payloads (verification refuses)"*. Two properties are under test, and the
//! second matters more than the first:
//!
//! 1. **verification refuses** — a payload that is not exactly what the
//!    manifest asked for does not become an object; and
//! 2. **nothing reaches quarantine on the way to refusing.** A pipeline that
//!    staged three objects and then rejected the fourth would satisfy (1) while
//!    leaving three unrequested objects in the receiver's quarantine. Every
//!    refusal test below therefore asserts an empty sink, not just an `Err`.
//!
//! `ReconstructionPipeline::reconstruct` is structured to make (2) hold: it
//! accumulates into a request-local map, validates every manifest entry, and
//! only then loops over `QuarantineSink::stage_verified`. The tests pin the
//! behaviour rather than the structure, so a refactor that moved staging
//! earlier would fail them.
//!
//! # What corruption actually produces, measured rather than assumed
//!
//! I expected corrupt bytes to surface as a payload/identity mismatch. They do
//! not. `collect_payloads` re-derives the content identity from the bytes and
//! then checks it against the manifest's expected set, so **corrupt bytes have
//! an identity nobody asked for** and the refusal is `UnrequestedPayload`.
//! `PayloadIdentityMismatch` is a different, defensive check for a payload
//! whose *carried* identity disagrees with its own bytes — unreachable through
//! `TransferPayload::new`, which derives it.
//!
//! That distinction is the reason this file asserts specific refusals rather
//! than `is_err()`: the two conditions are different failures and a test that
//! accepted either would not notice them swapping.
//!
//! # Non-claims
//!
//! Nothing here says the *accepted* path produces an end state equal to the
//! ordinary pack path — that is the bead's semantic-identity line and needs a
//! differential, not a refusal suite. Nothing here touches `fgit-atp-git/src`.

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, HaveSummary, PeerCapabilities,
    PeerCapabilityVerifier, PeerIdentity, PlanSelector, ReconstructionOutcome,
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

/// A receiver that has verified nothing locally.
///
/// Deliberately empty: if the lookup could supply objects, a missing payload
/// would be satisfied from local storage and the omission tests would measure
/// the lookup instead of the pipeline.
struct KnowsNothing;

impl VerifiedObjectLookup for KnowsNothing {
    fn read_verified(&self, _identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal> {
        Ok(None)
    }
}

/// Records what actually reached quarantine, in the order it arrived.
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

/// The three payloads the manifest is built from.
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

fn payloads_from(contents: &[Vec<u8>]) -> Vec<TransferPayload> {
    contents
        .iter()
        .map(|bytes| TransferPayload::new(bytes.clone()).expect("a payload binds its own identity"))
        .collect()
}

fn clean_contents() -> Vec<Vec<u8>> {
    CONTENTS.iter().map(|c| c.to_vec()).collect()
}

/// Drive the pipeline and report both the outcome and what reached quarantine.
fn run(contents: &[Vec<u8>]) -> (Result<ReconstructionOutcome, AtpRefusal>, Vec<GitOid>) {
    let manifest = manifest();
    let plan = plan(&manifest);
    let mut quarantine = Quarantine::default();
    let outcome = pipeline().reconstruct(
        &manifest,
        &plan,
        payloads_from(contents),
        &KnowsNothing,
        &mut quarantine,
    );
    (outcome, quarantine.0)
}

// --------------------------------------------------------- the permitted case

#[test]
fn a_complete_and_correct_payload_set_stages_every_object() {
    // THE PRESENCE CASE. Every refusal test below asserts an empty quarantine,
    // and all of them would pass against a pipeline that staged nothing ever.
    // This is what distinguishes "refused correctly" from "inert".
    let (outcome, staged) = run(&clean_contents());

    match outcome.expect("a correct payload set must not be refused") {
        ReconstructionOutcome::Complete(receipt) => {
            assert_eq!(
                receipt.staged().len(),
                CONTENTS.len(),
                "every manifest object must be staged; receipt says {:?}",
                receipt.staged()
            );
        }
        ReconstructionOutcome::Repair(request) => panic!(
            "a complete payload set must not ask for repair; it wants {:?}",
            request.missing()
        ),
    }

    assert_eq!(
        staged.len(),
        CONTENTS.len(),
        "the quarantine sink must actually receive the objects, not merely be promised them"
    );

    // Staging is documented as OID order. A receiver that batches by arrival
    // order would still pass the count check above.
    let mut sorted = staged.clone();
    sorted.sort();
    assert_eq!(
        staged, sorted,
        "objects must reach quarantine in canonical identity order, not arrival order"
    );
}

// ------------------------------------------------------------- corruption

#[test]
fn a_corrupted_payload_is_refused_and_stages_nothing() {
    // One byte flipped. The content identity changes, so the manifest never
    // asked for this payload -- which is why the refusal is UnrequestedPayload
    // rather than a mismatch. Asserting the specific variant matters: the two
    // conditions are different failures and `is_err()` would not notice them
    // swapping.
    let mut contents = clean_contents();
    contents[1] = b"beta-corrupted".to_vec();

    let (outcome, staged) = run(&contents);

    assert!(
        matches!(outcome, Err(AtpRefusal::UnrequestedPayload)),
        "corrupt bytes carry an identity the manifest never requested; got {outcome:?}"
    );
    assert!(
        staged.is_empty(),
        "a refused transfer must leave quarantine untouched, but it received {staged:?}"
    );
}

#[test]
fn a_truncated_payload_is_refused_and_stages_nothing() {
    // Truncation is corruption with a shorter length, and it reaches the same
    // gate for the same reason -- worth its own case because a length-based
    // check and an identity-based check would diverge here, and the bead names
    // truncation separately.
    let mut contents = clean_contents();
    contents[2] = b"gam".to_vec();

    let (outcome, staged) = run(&contents);

    assert!(
        matches!(outcome, Err(AtpRefusal::UnrequestedPayload)),
        "a truncated payload is not the object that was requested; got {outcome:?}"
    );
    assert!(
        staged.is_empty(),
        "a refused transfer must leave quarantine untouched, but it received {staged:?}"
    );
}

#[test]
fn a_duplicated_payload_is_refused_and_stages_nothing() {
    // Not in the bead's list, but it is the same family and the pipeline has a
    // named refusal for it, so leaving it unexercised would be a control that
    // exists only on paper.
    let mut contents = clean_contents();
    contents.push(CONTENTS[0].to_vec());

    let (outcome, staged) = run(&contents);

    assert!(
        matches!(outcome, Err(AtpRefusal::DuplicatePayload)),
        "the same payload twice must be refused rather than silently deduplicated; got {outcome:?}"
    );
    assert!(
        staged.is_empty(),
        "a refused transfer must leave quarantine untouched, but it received {staged:?}"
    );
}

// -------------------------------------------------------------- reordering

#[test]
fn payload_order_does_not_change_the_outcome() {
    // "reordered payloads" from the bead's list. The pipeline collects into a
    // map keyed by content identity, so order should be irrelevant -- but that
    // is a property of the implementation today, and the bead asks for it to be
    // evidence rather than an inference from reading the code.
    let forward = clean_contents();
    let mut reversed = forward.clone();
    reversed.reverse();

    let (forward_outcome, forward_staged) = run(&forward);
    let (reversed_outcome, reversed_staged) = run(&reversed);

    assert!(
        matches!(forward_outcome, Ok(ReconstructionOutcome::Complete(_)))
            && matches!(reversed_outcome, Ok(ReconstructionOutcome::Complete(_))),
        "both orders must complete; got {forward_outcome:?} and {reversed_outcome:?}"
    );
    assert_eq!(
        forward_staged, reversed_staged,
        "the same payloads in a different order must stage the same objects in the same canonical \
         order; wire order must not be observable in the receiver's quarantine"
    );
}

// ---------------------------------------------------------------- omission

#[test]
fn an_omitted_payload_asks_for_repair_rather_than_staging_a_partial_closure() {
    // The distinction that makes the refusals above meaningful: an INCOMPLETE
    // set is not the same as a CORRUPT one. A missing object is a legitimate
    // state the sender can fix, so it returns a repair request naming exactly
    // what is absent -- and still stages nothing, because a partial closure is
    // not a closure.
    let mut contents = clean_contents();
    let dropped = contents.remove(1);
    let dropped_identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &dropped);

    let (outcome, staged) = run(&contents);

    match outcome.expect("an incomplete set is a repair request, not a refusal") {
        ReconstructionOutcome::Repair(request) => {
            assert_eq!(
                request.missing(),
                [dropped_identity],
                "the repair request must name exactly the omitted object, so the sender can \
                 supply it without guessing"
            );
        }
        ReconstructionOutcome::Complete(receipt) => panic!(
            "an incomplete payload set must not complete; it staged {:?}",
            receipt.staged()
        ),
    }

    assert!(
        staged.is_empty(),
        "two of three objects verified is still not a closure, and none may reach quarantine; it \
         received {staged:?}"
    );
}
