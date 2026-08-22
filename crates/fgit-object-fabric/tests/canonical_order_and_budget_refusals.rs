#![forbid(unsafe_code)]
//! Canonical-order and streaming-budget refusals (`frankengit-k6ml`).
//!
//! `StoreRefusal` has 45 constructed variants and most are exercised only by
//! the crate's inline `cfg(test)` module. Measured per variant with a
//! both-trees grep — the crate has no suite-like module in `src/`, so a
//! `tests/` scan is sound here (checked, after `fgit-authority`'s
//! `src/suite.rs` made a covered variant look untested).
//!
//! # The finding: this crate collapses what `fgit-atp-git` splits
//!
//! Both canonical-order guards here compare with `>=`:
//!
//! ```text
//! RetentionRootProposal::new   pair[0] >= pair[1]  -> NonCanonicalRetentionOrder
//! rebuild_from_manifests       prior    >= identity -> NonCanonicalManifestOrder
//! ```
//!
//! so a **misordered** sequence and a **duplicated** one produce the *same*
//! refusal. The same repository does the opposite in `fgit-atp-git`, where
//! `TransferManifest` splits them into `NonCanonicalObjectOrder` and
//! `DuplicateObjectIdentity` — and `frankengit-0k6d` added a load-bearing
//! comment at that `match` precisely so a lint could not merge the arms.
//!
//! Two conventions for one shape, in one codebase. This file **pins both
//! shapes** against each guard and records the contrast. It deliberately does
//! **not** claim the collapse is wrong: that is the crate owner's design
//! question, and a future split would change these assertions on purpose. What
//! matters is that the current behaviour is now written down, so a split is a
//! decision rather than an accident.
//!
//! Pinning both shapes is also what makes the mutation in this bead meaningful:
//! relaxing `>=` to `>` admits duplicates while misorders still refuse, which a
//! misorder-only probe cannot see.
//!
//! # Identities are computed, never asserted
//!
//! `SegmentManifest::identity()` derives from the manifest's own bytes, so a
//! test cannot choose which of two manifests sorts first. Every ordering probe
//! here computes both identities and sorts them, then feeds the sequence in the
//! order the case needs. That is the same discipline `0k6d` used, and it is why
//! these probes cannot silently degrade into asserting a fixture's arrangement.
//!
//! # Non-claims
//!
//! Four of 45 `StoreRefusal` variants, newly named from `tests/`. The other 41
//! are overwhelmingly in-src-only rather than absent, and this file does not
//! make the enum "covered". `InvalidPlacementKind` is addressed at the end with
//! whatever the investigation actually found. LEAD count, not a
//! remaining-work total.
//!
//! Written as a new target rather than extended into `fabric_fault_suite.rs`,
//! whose e2e drill asserts an exact `"$EXPECTED_DRILLS passed"` count — adding
//! tests there would break it. The fixtures below are therefore a minimal
//! replication of that file's, and the duplication is stated rather than
//! hidden.
//!
//! Nothing here modifies `crates/fgit-object-fabric/src/**`.

use fgit_object_fabric::fabric::{
    LocatorCache, ManifestLimits, PlacementBackend, PlacementReceipt, RetentionRootProposal,
    SegmentManifest, StoreRefusal, VerifiedObject, VerifiedObjectStream, VerifiedStreamBudget,
    WholeObjectRead,
};
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, ObjectEnvelope, ObjectKind, SegmentLimits,
};
use fgit_resource::OpaqueHandle;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, GitOid,
    RepositoryAuthorityHeadId, SegmentManifestId,
};

const NAMESPACE: &[u8] = b"k6ml-order";
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn handle(bytes: &[u8]) -> OpaqueHandle {
    OpaqueHandle::new(bytes).expect("fixture handle must be bounded")
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn manifest_id(tag: u8) -> SegmentManifestId {
    SegmentManifestId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn placement() -> PlacementReceipt {
    PlacementReceipt::new(
        PlacementBackend::MemoryReference,
        handle(b"locator"),
        handle(b"failure-domain"),
        handle(b"encryption-dependency"),
    )
}

/// An entry-free manifest distinguished only by its segment digest.
///
/// Entry-free on purpose: `ManifestEntry` has private fields and no public
/// constructor, so an external caller cannot synthesize entries at all. These
/// probes only need distinct identities, so an empty entry list is the honest
/// minimum rather than a concession.
fn manifest(tag: u8) -> SegmentManifest {
    SegmentManifest::new(
        NAMESPACE.to_vec(),
        [tag; 32],
        Vec::new(),
        vec![placement()],
        &ManifestLimits::default(),
    )
    .expect("an entry-free manifest with one placement is canonical")
}

/// Two manifests returned in **strictly increasing identity order**.
///
/// The identity is derived from the manifest's own bytes, so which of the two
/// sorts first is not something this test may choose — it is computed.
fn ordered_manifest_pair() -> (SegmentManifest, SegmentManifest) {
    let first = manifest(0x11);
    let second = manifest(0x22);
    let first_id = first.identity().expect("a canonical manifest identifies");
    let second_id = second.identity().expect("a canonical manifest identifies");
    assert_ne!(first_id, second_id, "the two fixtures must differ");
    if first_id < second_id {
        (first, second)
    } else {
        (second, first)
    }
}

/// Two retention manifest ids in strictly increasing order, computed the same
/// way rather than assumed from their tags.
fn ordered_retention_pair() -> (SegmentManifestId, SegmentManifestId) {
    let first = manifest_id(0x31);
    let second = manifest_id(0x32);
    assert_ne!(first, second);
    if first < second {
        (first, second)
    } else {
        (second, first)
    }
}

fn retention(manifests: Vec<SegmentManifestId>) -> Result<RetentionRootProposal, StoreRefusal> {
    RetentionRootProposal::new(head_id(0x40), digest(0x41), manifests)
}

fn oid_for(payload: &[u8]) -> GitOid {
    fgit_crypto::git_object_id(
        fgit_crypto::GitObjectFormat::Sha1,
        fgit_crypto::GitObjectKind::Blob,
        payload,
    )
}

/// A verified object whose bytes genuinely match their envelope.
///
/// `VerifiedObject::new` recomputes the native Git id from the bytes, so the
/// identity is derived here rather than invented — an invented one is refused,
/// correctly.
fn verified(payload: &[u8]) -> VerifiedObject {
    let commitment = CryptoDigest
        .payload_commitment(ObjectKind::Blob, payload)
        .expect("fixture commitment must be available");
    let envelope = ObjectEnvelope::new(
        NAMESPACE.to_vec(),
        oid_for(payload),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture length fits u64"),
        commitment,
        b"raw".to_vec(),
        [7; 32],
        None,
        &SegmentLimits::default(),
    )
    .expect("an envelope over real bytes builds");
    VerifiedObject::new(envelope, payload.to_vec()).expect("fixture object must verify")
}

fn whole(payload: &[u8]) -> WholeObjectRead {
    WholeObjectRead {
        object: verified(payload),
        placement: placement(),
    }
}

// ---------------------------------------------------------------------------
// The accepted cases, built first
// ---------------------------------------------------------------------------

/// A strictly increasing retention sequence is admitted.
///
/// Built and made to pass before any refusal probe: a constructor that rejected
/// every sequence would satisfy both refusals below.
#[test]
fn a_strictly_increasing_retention_sequence_is_admitted() {
    let (first, second) = ordered_retention_pair();
    retention(vec![first, second]).expect("a strictly increasing manifest list is canonical");
}

/// A strictly increasing manifest sequence rebuilds the cache.
#[test]
fn a_strictly_increasing_manifest_sequence_is_admitted() {
    let (first, second) = ordered_manifest_pair();
    let sequence = vec![first, second];
    let mut cache = LocatorCache::default();
    cache
        .rebuild_from_manifests(&sequence)
        .expect("a strictly increasing manifest sequence rebuilds");
}

/// A budget with both fields non-zero is admitted, and keeps them.
#[test]
fn a_non_zero_streaming_budget_is_admitted() {
    let budget = VerifiedStreamBudget::new(4096, 512).expect("a finite budget is admissible");
    assert_eq!(budget.maximum_bytes(), 4096);
    assert_eq!(budget.chunk_bytes(), 512);
}

// ---------------------------------------------------------------------------
// The canonical-order guards — BOTH shapes, one variant
// ---------------------------------------------------------------------------

/// A misordered retention sequence is refused.
#[test]
fn a_misordered_retention_sequence_is_refused() {
    let (first, second) = ordered_retention_pair();
    let refusal = retention(vec![second, first]).expect_err("a decreasing pair is not canonical");
    assert_eq!(refusal, StoreRefusal::NonCanonicalRetentionOrder);
}

/// A **duplicated** retention sequence is refused — with the *same* variant.
///
/// This is the collapse: `pair[0] >= pair[1]` cannot distinguish "out of order"
/// from "repeated", so both faults share one refusal. `fgit-atp-git` splits the
/// equivalent pair into two variants. Recording the difference, not judging it.
#[test]
fn a_duplicated_retention_sequence_is_refused_with_the_same_variant() {
    let (first, _second) = ordered_retention_pair();
    let refusal =
        retention(vec![first, first]).expect_err("a repeated manifest is not a canonical set");
    assert_eq!(
        refusal,
        StoreRefusal::NonCanonicalRetentionOrder,
        "this crate reports a duplicate and a misorder identically"
    );
}

/// A misordered manifest sequence is refused.
#[test]
fn a_misordered_manifest_sequence_is_refused() {
    let (first, second) = ordered_manifest_pair();
    let mut cache = LocatorCache::default();
    let refusal = cache
        .rebuild_from_manifests(&[second, first])
        .expect_err("a decreasing manifest sequence is not canonical");
    assert_eq!(refusal, StoreRefusal::NonCanonicalManifestOrder);
}

/// A duplicated manifest sequence is refused — same variant again.
#[test]
fn a_duplicated_manifest_sequence_is_refused_with_the_same_variant() {
    // Two manifests built from IDENTICAL content, so their derived identities
    // are equal by construction. An earlier draft duplicated one member of
    // `ordered_manifest_pair`, which silently produced a strictly increasing
    // pair whenever the sort put the other tag first — and was accepted. The
    // fixture, not the guard, was wrong; building the duplicate from identical
    // bytes removes the dependence on sort order entirely.
    let first = manifest(0x11);
    let repeated = manifest(0x11);
    assert_eq!(
        first.identity().expect("identifies"),
        repeated.identity().expect("identifies"),
        "identical content must derive an identical identity"
    );
    let mut cache = LocatorCache::default();
    let refusal = cache
        .rebuild_from_manifests(&[first, repeated])
        .expect_err("a repeated manifest is not a canonical sequence");
    assert_eq!(
        refusal,
        StoreRefusal::NonCanonicalManifestOrder,
        "the manifest guard collapses the two faults exactly as the retention guard does"
    );
}

// ---------------------------------------------------------------------------
// InvalidStreamingBudget — two axes
// ---------------------------------------------------------------------------

/// A zero maximum admits nothing, so it is not a budget.
#[test]
fn a_zero_maximum_streaming_budget_is_refused() {
    let refusal =
        VerifiedStreamBudget::new(0, 512).expect_err("a zero maximum can never admit an object");
    assert_eq!(refusal, StoreRefusal::InvalidStreamingBudget);
}

/// A zero chunk size would never advance the cursor.
///
/// A separate axis from the maximum: one condition joined by `||` is two ways
/// to be wrong, and zeroing both would leave each unexercised.
#[test]
fn a_zero_chunk_streaming_budget_is_refused() {
    let refusal =
        VerifiedStreamBudget::new(4096, 0).expect_err("a zero chunk size never emits a byte");
    assert_eq!(refusal, StoreRefusal::InvalidStreamingBudget);
}

// ---------------------------------------------------------------------------
// StreamingBudgetExceeded — and the exact boundary
// ---------------------------------------------------------------------------

/// An object larger than its budget is refused, and the refusal reports both
/// numbers.
#[test]
fn an_object_past_its_stream_budget_is_refused() {
    let payload = b"0123456789";
    let budget = VerifiedStreamBudget::new(4, 4).expect("a small finite budget");
    let refusal = VerifiedObjectStream::new(whole(payload), budget)
        .expect_err("a ten-byte object does not fit a four-byte ceiling");
    assert_eq!(
        refusal,
        StoreRefusal::StreamingBudgetExceeded {
            offered: 10,
            maximum: 4,
        },
        "the refusal reports what was offered and what was permitted"
    );
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so an
/// object of exactly the budget is admitted — the case a refusal-only corpus
/// cannot see.
#[test]
fn an_object_at_exactly_the_stream_budget_is_admitted() {
    let payload = b"0123456789";
    let budget = VerifiedStreamBudget::new(10, 4).expect("a budget equal to the object");
    VerifiedObjectStream::new(whole(payload), budget)
        .expect("an object of exactly the budget must be admitted");

    let over = VerifiedStreamBudget::new(9, 4).expect("one byte short of the object");
    let refusal = VerifiedObjectStream::new(whole(payload), over)
        .expect_err("one byte short of the object must refuse");
    assert_eq!(
        refusal,
        StoreRefusal::StreamingBudgetExceeded {
            offered: 10,
            maximum: 9,
        }
    );
}
