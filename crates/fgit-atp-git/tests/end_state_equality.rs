//! FG-022b: the ATP-Git path and the ordinary pack path end in the same place.
//!
//! This is the bead's headline acceptance line — *"end-state object/ref
//! equality between ATP-Git path and ordinary pack path for every corpus repo
//! (semantic identity requirement of plan section 18.4)"* — and it is the only
//! one that cannot be demonstrated from inside either path. Every other file in
//! this campaign asks whether ATP behaves correctly by its own lights. This one
//! asks whether behaving correctly gets you to the same repository state as not
//! using ATP at all, which is the entire premise of shipping it.
//!
//! # Why the comparison is exact rather than approximate
//!
//! `fgit-pack` re-exports `GitOid` as `ObjectId`, so both paths speak the same
//! identity type and the end states can be compared directly rather than
//! through a mapping that could itself be wrong. That is worth stating: a
//! differential whose two sides need a translation layer is partly testing the
//! translation.
//!
//! # The shape, and the trap it avoids
//!
//! One corpus of real Git blobs is driven through both paths:
//!
//! * **ordinary pack** — `PackPlanner` plans it, `PackWriter` emits real pack
//!   bytes, and `read_verified_pack` reads them back into quarantined entries;
//! * **ATP-Git** — the same objects become a manifest, a plan, and payloads,
//!   and `ReconstructionPipeline` stages them into quarantine.
//!
//! The trap is comparing each path against its own expectations, which two
//! implementations sharing one wrong assumption both satisfy. So the assertion
//! is between the two *observed* end states, and separately each is checked
//! against the corpus, so a run where both paths silently produced nothing
//! cannot pass as agreement.
//!
//! # Non-claims
//!
//! *Objects*, not refs: ATP-Git transfers objects and neither path here
//! publishes a reference, so the "ref equality" half of the acceptance line is
//! **not** covered and is not implied. One corpus of blobs, not "every corpus
//! repo" — trees and commits reach the same pipeline through the same entry
//! constructor, but that is an argument, not a measurement, and this file does
//! not make it. Nothing here touches `fgit-atp-git/src`.

use std::collections::BTreeMap;

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, HaveSummary, PeerCapabilities,
    PeerCapabilityVerifier, PeerIdentity, PlanSelector, ReconstructionOutcome,
    ReconstructionPipeline, TransferLimits, TransferManifest, TransferObjectEntry, TransferPayload,
    VerifiedObjectLookup,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_object_fabric::fabric::VerifiedObject;
use fgit_object_fabric::{ObjectKind, SegmentLimits};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, NativeChecksumVerifier, ObjectFormat, ObjectId,
    PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter, read_verified_pack,
};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId};

/// The corpus both paths carry. Real Git blobs, identified by real Git hashing.
const CORPUS: [&[u8]; 4] = [
    b"the first object",
    b"a second, longer object with different bytes",
    b"third",
    b"a fourth object so the pack has something to order",
];

// ---------------------------------------------------------- ordinary pack path

struct CorpusSource {
    objects: BTreeMap<ObjectId, (Vec<u8>, u64)>,
}

impl CorpusSource {
    fn new() -> Self {
        let mut objects = BTreeMap::new();
        for (index, content) in CORPUS.iter().enumerate() {
            let body = content.to_vec();
            let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body));
            let recency = u64::try_from(index).unwrap_or(u64::MAX);
            objects.insert(id, (body, recency));
        }
        Self { objects }
    }

    fn roots(&self) -> Vec<ObjectId> {
        self.objects.keys().copied().collect()
    }
}

impl CanonicalObjectSource for CorpusSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let (body, recency) = self
            .objects
            .get(id)
            .unwrap_or_else(|| panic!("the corpus is missing an object it referenced: {id:?}"));
        // A deterministic spread, not a digest: it feeds only the profile's
        // grouping heuristic and nothing downstream reads it as identity.
        let mut path_hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in body {
            path_hash ^= u64::from(*byte);
            path_hash = path_hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body.clone(),
            Vec::new(),
            *recency,
            path_hash,
        ))
    }
}

/// Everything the ordinary pack path leaves in quarantine, in canonical order.
fn ordinary_pack_end_state() -> Vec<GitOid> {
    let source = CorpusSource::new();
    let pack_limits = PackLimits::default();
    let mut deadline = || true;

    let plan = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        pack_limits.clone(),
    )
    .plan(&source, &source.roots(), &mut deadline)
    .expect("the corpus plans");

    let (bytes, _receipt) = PackWriter::new(pack_limits.clone())
        .write(&plan, &mut deadline)
        .expect("the plan writes");

    let quarantined = read_verified_pack(
        &bytes,
        ObjectFormat::Sha1,
        &pack_limits,
        &mut deadline,
        &NativeChecksumVerifier,
    )
    .expect("our own reader accepts our own pack");

    // Quarantine is pre-identity BY DESIGN -- a `QuarantinedEntry` carries the
    // inflated bytes and deliberately not an identity, because native identity
    // verification is the step that comes after framing. So the identity of
    // each delivered object is derived from the bytes that were delivered,
    // which is precisely what that verification does, rather than read off a
    // field the reader has not yet earned the right to fill in.
    //
    // The profile is STORED_V1 and the corpus is blobs, so every entry is a
    // base object and `inflated` is the object body.
    let mut identities: Vec<GitOid> = quarantined
        .entries()
        .iter()
        .map(|entry| ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &entry.inflated)))
        .collect();
    identities.sort();
    identities
}

// -------------------------------------------------------------- ATP-Git path

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

#[derive(Debug, Default)]
struct Quarantine(Vec<GitOid>);

impl fgit_atp_git::QuarantineSink for Quarantine {
    fn stage_verified(&mut self, object: VerifiedObject) -> Result<(), AtpRefusal> {
        self.0.push(object.identity());
        Ok(())
    }
}

fn atp_limits() -> TransferLimits {
    TransferLimits::new(64, 1 << 20, 1 << 24, 64).expect("positive bounds are admissible")
}

fn capable(byte: u8) -> AuthenticatedPeerCapabilities {
    let offered = PeerCapabilities::new(
        PeerIdentity::from_bytes([byte; 32]),
        RepositoryId::from_bytes([7; 16]),
        [AtpGitProfile::ConservativeInterimV1],
        true,
    );
    AuthenticatedPeerCapabilities::verify(offered, &AcceptingVerifier).expect("accepting verifier")
}

/// Everything the ATP-Git path leaves in quarantine, in canonical order.
fn atp_end_state() -> Vec<GitOid> {
    let mut entries: Vec<TransferObjectEntry> = CORPUS
        .iter()
        .map(|content| {
            let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, content);
            TransferObjectEntry::from_payload(identity, ObjectKind::Blob, content, None)
                .expect("a payload identified by its own digest")
        })
        .collect();
    entries.sort_by_key(TransferObjectEntry::identity);
    let roots = vec![entries.last().expect("a non-empty corpus").identity()];

    let manifest = TransferManifest::new(
        RepositoryId::from_bytes([7; 16]),
        GitHashAlgorithm::Sha1,
        roots,
        entries,
        atp_limits(),
    )
    .expect("canonical manifest");

    let have = HaveSummary::exact_objects(Vec::new(), atp_limits()).expect("an empty inventory");
    let plan = PlanSelector::new(atp_limits()).select(&manifest, &capable(1), &capable(2), &have);

    let payloads: Vec<TransferPayload> = CORPUS
        .iter()
        .map(|content| TransferPayload::new(content.to_vec()).expect("a valid payload"))
        .collect();

    let mut quarantine = Quarantine::default();
    let outcome = ReconstructionPipeline::new(
        b"fg022b-differential".to_vec(),
        SegmentLimits::default(),
        atp_limits(),
    )
    .expect("a named namespace")
    .reconstruct(&manifest, &plan, payloads, &KnowsNothing, &mut quarantine)
    .expect("a complete payload set reconstructs");

    assert!(
        matches!(outcome, ReconstructionOutcome::Complete(_)),
        "the ATP path must complete for the differential to compare end states; got {outcome:?}"
    );

    let mut identities = quarantine.0;
    identities.sort();
    identities
}

// ------------------------------------------------------------- the corpus itself

/// What both paths are supposed to arrive at, derived from the corpus alone.
fn expected_identities() -> Vec<GitOid> {
    let mut identities: Vec<GitOid> = CORPUS
        .iter()
        .map(|content| git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, content))
        .collect();
    identities.sort();
    identities
}

// --------------------------------------------------------------- the assertions

#[test]
fn both_paths_carry_the_whole_corpus_and_neither_is_empty() {
    // THE NON-VACUITY GUARD, and it has to come first. Two paths that both
    // produced nothing would compare equal, and the differential below would
    // report agreement about a transfer that never happened. So each side is
    // checked against the corpus independently before they are checked against
    // each other.
    let expected = expected_identities();

    assert_eq!(
        ordinary_pack_end_state(),
        expected,
        "the ordinary pack path must carry exactly the corpus"
    );
    assert_eq!(
        atp_end_state(),
        expected,
        "the ATP-Git path must carry exactly the corpus"
    );
}

#[test]
fn the_atp_path_and_the_ordinary_pack_path_end_in_the_same_object_state() {
    // The acceptance line. Both sides are OBSERVED end states rather than
    // expectations: comparing each path against its own idea of success is
    // satisfied by two implementations sharing one wrong assumption.
    //
    // `fgit-pack` re-exports GitOid as ObjectId, so this is an exact comparison
    // of the same type rather than one mediated by a translation that could
    // itself be wrong.
    let ordinary = ordinary_pack_end_state();
    let atp = atp_end_state();

    assert_eq!(
        atp, ordinary,
        "ATP-Git and the ordinary pack path must leave the receiver holding the same objects; \
         ATP staged {atp:?} while the pack path produced {ordinary:?}"
    );

    // And the agreement must be about something. A shared empty result is the
    // one way equality above could hold while proving nothing.
    assert_eq!(
        atp.len(),
        CORPUS.len(),
        "the agreed end state must contain the whole corpus, not be an agreed emptiness"
    );
}
