//! FG-022b: trust-scope isolation — probed against the mechanism that exists.
//!
//! # The acceptance line, and the part of it that cannot be probed
//!
//! FG-022b asks for *"cache trust-scope isolation probes"* and *"zero
//! cross-trust cache hits in isolation probes"*. The parent epic FG-022 lists
//! *"trust-scoped cache keys (peer trust domain in the key — no cross-trust
//! cache pollution)"*.
//!
//! **There is no cache.** Measured: `fgit-atp-git/src/lib.rs` contains zero
//! occurrences of "cache", and `trust.?scope`, `trust.?domain` and
//! `cross.?trust` match nothing in any crate's `src/` in the workspace.
//! FG-022a — the implementation bead, now closed — does not have a cache in its
//! scope either: it covers capability records, inventory summaries, the plan
//! selector, and the reconstruction pipeline. So the epic names a component
//! that neither child was asked to build, and the literal probe has no subject.
//! That contradiction is recorded on the bead rather than papered over with a
//! fixture, and **no cache is invented here to test** — an empty scaffold built
//! to satisfy an acceptance line is exactly what §4 forbids.
//!
//! # What the property becomes against what is actually implemented
//!
//! Strip the word "cache" and the requirement is: **an object already held
//! locally must never be served into a transfer on the strength of its key
//! alone.** That is precisely what cross-trust pollution means — an object
//! deposited by one peer being reused for another peer's closure without being
//! re-checked — and ATP does implement it, in `verify_existing`.
//!
//! Every reuse re-verifies five independent properties against the manifest
//! entry: native identity, object kind, declared length, payload commitment,
//! and the content identity re-derived from the bytes. A store hit that
//! disagrees on any of them is refused with `ExistingObjectMismatch`.
//!
//! # The adversary I tried to build does not exist, which is the better answer
//!
//! The first version of this file constructed the strong lie — an object whose
//! envelope claims one identity while its bytes are another — and it **could
//! not be built**. `VerifiedObject::new` re-derives the declared length, the
//! payload commitment and the native identity from the bytes and refuses;
//! measured, it returns `StoreRefusal::PayloadCommitmentMismatch`.
//!
//! So that pollution is **unrepresentable rather than detected**, and
//! `verify_existing` is defence in depth behind a type that already cannot hold
//! the bad value. Worth recording because it is the same principle the
//! workspace has now arrived at independently in several places: a forbidden
//! state that can be constructed eventually will be.
//!
//! What remains constructible is the realistic cross-trust hit: **a genuine
//! object reached under the wrong key.** That is what these tests use, and
//! `verify_existing` refuses it on the identity check.
//!
//! What this file cannot claim is anything about key derivation, since there
//! are no keys.
//!
//! Nothing here touches `fgit-atp-git/src`.

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, HaveSummary, PeerCapabilities,
    PeerCapabilityVerifier, PeerIdentity, PlanSelector, ReconstructionOutcome,
    ReconstructionPipeline, TransferLimits, TransferManifest, TransferObjectEntry, TransferPayload,
    TransferPlan, VerifiedObjectLookup,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_object_fabric::fabric::VerifiedObject;
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId};

const NAMESPACE: &[u8] = b"fg022b";
const PROFILE_TAG: &[u8] = b"atp-git/conservative-interim-v1";

struct AcceptingVerifier;

impl PeerCapabilityVerifier for AcceptingVerifier {
    fn verify(&self, _offered: &PeerCapabilities) -> Result<(), AtpRefusal> {
        Ok(())
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

/// A local store that answers `wanted` with whatever object it was given.
///
/// An honest store returns the object that genuinely has that identity. A
/// polluted one — an object deposited under another peer's transfer, or a key
/// collision across trust domains — returns something else. Both are expressed
/// by choosing what `holds` contains.
struct LocalStore {
    wanted: GitOid,
    holds: VerifiedObject,
}

impl VerifiedObjectLookup for LocalStore {
    fn read_verified(&self, identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal> {
        if identity == self.wanted {
            Ok(Some(self.holds.clone()))
        } else {
            Ok(None)
        }
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

const CONTENTS: [&[u8]; 2] = [b"alpha", b"beta"];

fn entry(payload: &[u8]) -> TransferObjectEntry {
    let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, payload);
    TransferObjectEntry::from_payload(identity, ObjectKind::Blob, payload, None)
        .expect("a payload identified by its own digest is a valid entry")
}

fn manifest() -> TransferManifest {
    let mut entries: Vec<TransferObjectEntry> = CONTENTS.iter().map(|c| entry(c)).collect();
    entries.sort_by_key(TransferObjectEntry::identity);
    let roots = vec![entries.last().expect("two entries").identity()];
    TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        roots,
        entries,
        limits(),
    )
    .expect("canonical manifest")
}

/// A genuine verified object for `entry`, carrying its own content.
///
/// It cannot be made to lie. `VerifiedObject::new` re-derives the payload
/// commitment and the native identity from the bytes and refuses on either
/// mismatch — measured: handing it `entry`'s envelope with another object's
/// bytes returns `StoreRefusal::PayloadCommitmentMismatch`. So the strong form
/// of pollution, an object whose envelope disagrees with its contents, is
/// **unrepresentable** rather than merely detected downstream.
///
/// The constructible pollution is therefore the other shape: a genuine object
/// reached under the WRONG KEY, which is what a cross-trust cache hit would
/// actually look like.
fn stored_object(entry: &TransferObjectEntry, payload: &[u8]) -> VerifiedObject {
    let envelope = ObjectEnvelope::new(
        NAMESPACE.to_vec(),
        entry.identity(),
        entry.object_kind(),
        entry.logical_size(),
        entry.payload_commitment(),
        PROFILE_TAG.to_vec(),
        entry.payload_identity(),
        None,
        &SegmentLimits::default(),
    )
    .expect("an envelope inside the default segment bounds");
    VerifiedObject::new(envelope, payload.to_vec()).expect("a verified object")
}

fn pipeline() -> ReconstructionPipeline {
    ReconstructionPipeline::new(NAMESPACE.to_vec(), SegmentLimits::default(), limits())
        .expect("a named namespace inside the envelope bound")
}

fn plan(manifest: &TransferManifest) -> TransferPlan {
    let have = HaveSummary::exact_objects(Vec::new(), limits()).expect("an empty inventory");
    PlanSelector::new(limits()).select(manifest, &capable(1), &capable(2), &have)
}

/// Send every object EXCEPT `withheld`, forcing the pipeline to consult the
/// local store for that one.
fn payloads_except(withheld: GitOid) -> Vec<TransferPayload> {
    CONTENTS
        .iter()
        .filter(|content| {
            git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, content) != withheld
        })
        .map(|content| TransferPayload::new(content.to_vec()).expect("a valid payload"))
        .collect()
}

// ------------------------------------------------------------ the honest hit

#[test]
fn an_honest_local_object_is_reused_rather_than_retransferred() {
    // THE PRESENCE CASE, and it carries the efficiency claim too: a store hit
    // that genuinely matches is reused, so the object is neither refused nor
    // re-staged. Without this, the pollution test below would pass against a
    // pipeline that refused every store hit — which would be "safe" and
    // useless.
    let manifest = manifest();
    let held = entry(CONTENTS[0]);
    let store = LocalStore {
        wanted: held.identity(),
        holds: stored_object(&held, CONTENTS[0]),
    };
    let mut quarantine = Quarantine::default();

    let outcome = pipeline()
        .reconstruct(
            &manifest,
            &plan(&manifest),
            payloads_except(held.identity()),
            &store,
            &mut quarantine,
        )
        .expect("an honest store hit must not be refused");

    match outcome {
        ReconstructionOutcome::Complete(receipt) => {
            assert_eq!(
                receipt.reused_verified(),
                [held.identity()],
                "the locally held object must be reused and named as reused, not re-transferred"
            );
            assert!(
                !receipt.staged().contains(&held.identity()),
                "an object satisfied from the local store must not also be staged; receipt \
                 staged {:?}",
                receipt.staged()
            );
        }
        ReconstructionOutcome::Repair(request) => panic!(
            "a store holding the object must satisfy it rather than request repair; it wants {:?}",
            request.missing()
        ),
    }
}

// -------------------------------------------------------- the polluted hit

#[test]
fn a_local_object_that_lies_about_its_identity_is_refused_and_stages_nothing() {
    // THE PROBE. The store answers the requested identity with an object whose
    // envelope claims that identity while its bytes are a different object --
    // exactly what a cross-trust cache hit would look like if a key could be
    // reached from the wrong trust domain.
    //
    // It must not be believed. `verify_existing` re-derives the content
    // identity from the bytes rather than trusting the envelope, so the lie is
    // caught at the only place it could matter.
    let manifest = manifest();
    let held = entry(CONTENTS[0]);
    let other = entry(CONTENTS[1]);
    let store = LocalStore {
        // Asked for one identity, answers with a genuine object that has a
        // different one: a real object from elsewhere, reached under this key.
        wanted: held.identity(),
        holds: stored_object(&other, CONTENTS[1]),
    };
    let mut quarantine = Quarantine::default();

    let outcome = pipeline().reconstruct(
        &manifest,
        &plan(&manifest),
        payloads_except(held.identity()),
        &store,
        &mut quarantine,
    );

    assert!(
        matches!(
            outcome,
            Err(AtpRefusal::ExistingObjectMismatch { identity }) if identity == held.identity()
        ),
        "a local object whose bytes do not match the identity it is filed under must be refused, \
         naming that identity so an operator can find the polluted entry; got {outcome:?}"
    );
    assert!(
        quarantine.0.is_empty(),
        "a transfer refused for a bad store hit must leave quarantine untouched; it received {:?}",
        quarantine.0
    );
}

#[test]
fn the_local_store_is_never_consulted_for_an_object_the_sender_supplied() {
    // The other half of isolation: a supplied payload takes precedence, so a
    // polluted store entry for an object that IS being transferred cannot
    // influence the result at all.
    //
    // Same poisoned store as above, but this time every payload is sent. If the
    // pipeline consulted the store anyway the run would fail with
    // ExistingObjectMismatch; completing proves the supplied bytes won.
    let manifest = manifest();
    let held = entry(CONTENTS[0]);
    let other = entry(CONTENTS[1]);
    let store = LocalStore {
        wanted: held.identity(),
        holds: stored_object(&other, CONTENTS[1]),
    };
    let mut quarantine = Quarantine::default();

    let all: Vec<TransferPayload> = CONTENTS
        .iter()
        .map(|c| TransferPayload::new(c.to_vec()).expect("a valid payload"))
        .collect();

    let outcome = pipeline()
        .reconstruct(&manifest, &plan(&manifest), all, &store, &mut quarantine)
        .expect("supplied payloads must not be affected by an unrelated bad store entry");

    assert!(
        matches!(outcome, ReconstructionOutcome::Complete(_)),
        "every object was supplied, so the transfer must complete without consulting the store; \
         got {outcome:?}"
    );
    assert_eq!(
        quarantine.0.len(),
        CONTENTS.len(),
        "all supplied objects must be staged; quarantine holds {:?}",
        quarantine.0
    );
}
