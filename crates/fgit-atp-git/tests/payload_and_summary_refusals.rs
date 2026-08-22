#![forbid(unsafe_code)]
//! Payload-identity and probabilistic-summary refusals (`frankengit-xh96`).
//!
//! Measured per variant with a both-trees grep; the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here (checked). After `0k6d`,
//! `78ra`, `sezr` and `2gzj`, this is the last `AtpRefusal` cluster reachable
//! through public API without disproportionate fixtures.
//!
//! # The property everything else leans on, and nothing tested
//!
//! `TransferObjectEntry::from_payload` **re-derives** the native Git object id
//! from the bytes and refuses a mismatch. An identity is therefore not
//! something a caller gets to assert — which is exactly why `0k6d` computed its
//! orderings instead of assuming them, and why the fixture in
//! `fabric_fault_suite.rs` records the same lesson from the other side: its
//! first version invented an identity and was correctly refused.
//!
//! That property was load-bearing for two earlier beads and named by no test.
//! [`a_payload_under_another_objects_identity_is_refused`] pins it — and hands
//! a **different real identity** rather than random bytes, so the refusal is
//! about mismatch rather than about malformed input.
//!
//! # Three axes, and two call sites
//!
//! `InvalidProbabilisticSummary` fires three ways from `from_wire`: a zero bit
//! count, a bit count that is not a multiple of eight, and a byte slice whose
//! length disagrees with the bit count. Each gets a probe; a corpus using only
//! the zero axis would miss the other two entirely — and the mutation recorded
//! in the bead is chosen to be invisible to exactly that corpus.
//!
//! `InventoryTooLarge` is reached from **both** `HaveSummary::exact_objects`
//! and `HaveSummary::exact_segments`. A refusal through one says nothing about
//! the other.
//!
//! # Non-claims
//!
//! Newly covered: `NativeObjectIdentityMismatch`, `InvalidProbabilisticSummary`,
//! `InventoryTooLarge`. **Left open on purpose:** `PayloadLengthMismatch` and
//! `PlanManifestMismatch` are reachable only through
//! `ReconstructionPipeline::reconstruct`, which needs a full plan, manifest and
//! payload set — a different fixture from anything here. `9xyg` left the
//! signed-push certificate pair open for the same reason, and stretching a file
//! past what its fixtures honestly reach is how a corpus starts proving things
//! about itself. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-atp-git/src/**`.

use fgit_atp_git::{
    AtpRefusal, BloomHaveSummary, HaveSummary, TransferLimits, TransferObjectEntry,
};
use fgit_crypto::{GitObjectFormat, GitObjectKind, git_object_id};
use fgit_object_fabric::ObjectKind;
use fgit_types::GitOid;

fn limits() -> TransferLimits {
    TransferLimits::new(4, 1 << 20, 1 << 24, 4096).expect("a non-degenerate transfer profile")
}

/// The **real** native Git identity of a payload.
///
/// Derived, never invented: `from_payload` recomputes this and refuses anything
/// else, so a fixture that made one up would be refused for the wrong reason.
fn oid_for(payload: &[u8]) -> GitOid {
    git_object_id(GitObjectFormat::Sha1, GitObjectKind::Blob, payload)
}

/// `count` distinct object identities in strictly increasing order.
///
/// Sorted rather than assumed: the identities are digests, so their order is
/// not the caller's to choose, and `exact_objects` refuses a sequence that is
/// not strictly increasing before it ever reaches the count bound.
fn sorted_oids(count: usize) -> Vec<GitOid> {
    let mut oids: Vec<GitOid> = (0..count)
        .map(|index| oid_for(format!("object-{index}").as_bytes()))
        .collect();
    oids.sort_unstable();
    oids.dedup();
    assert_eq!(oids.len(), count, "the fixture payloads must be distinct");
    oids
}

// ---------------------------------------------------------------------------
// The accepted paths, built first
// ---------------------------------------------------------------------------

/// A payload under its own derived identity constructs.
///
/// Built and made to pass before any refusal probe: without it the mismatch
/// probe below could be `from_payload` rejecting every entry rather than
/// rejecting the wrong identity.
#[test]
fn a_payload_under_its_own_derived_identity_is_admitted() {
    let payload = b"the exact bytes";
    let entry =
        TransferObjectEntry::from_payload(oid_for(payload), ObjectKind::Blob, payload, None)
            .expect("a payload under its own derived identity is canonical");
    assert_eq!(entry.identity(), oid_for(payload));
    assert_eq!(entry.logical_size(), payload.len() as u64);
}

/// A well-formed summary and a canonical inventory both construct.
#[test]
fn a_well_formed_summary_and_inventory_are_admitted() {
    let summary = BloomHaveSummary::from_wire(64, &[0u8; 8], limits())
        .expect("a multiple-of-eight bit count with matching bytes is well formed");
    assert!(!summary.may_contain(oid_for(b"absent")));

    HaveSummary::exact_objects(sorted_oids(2), limits())
        .expect("a sorted distinct inventory within the bound is canonical");
}

/// **The permitted twin at the exact bound.** `ensure_inventory_count` reads
/// `>`, so an inventory of exactly `max_objects` is admitted.
#[test]
fn an_inventory_at_exactly_the_bound_is_admitted() {
    let bound = usize::try_from(limits().max_objects()).expect("the fixture bound fits usize");
    HaveSummary::exact_objects(sorted_oids(bound), limits())
        .expect("an inventory of exactly the bound must be admitted");
}

// ---------------------------------------------------------------------------
// NativeObjectIdentityMismatch — identities cannot be asserted
// ---------------------------------------------------------------------------

/// A payload presented under **another real object's** identity is refused.
///
/// The claimed identity is a genuine Git object id for different bytes, not
/// random noise — so this refusal is about the mismatch rather than about a
/// malformed identity, and the refusal carries the identity that was claimed.
#[test]
fn a_payload_under_another_objects_identity_is_refused() {
    let payload = b"the exact bytes";
    let impostor = oid_for(b"entirely different bytes");
    assert_ne!(impostor, oid_for(payload), "the two fixtures must differ");

    let error = TransferObjectEntry::from_payload(impostor, ObjectKind::Blob, payload, None)
        .expect_err("an identity is derived from the bytes, not asserted by the caller");
    assert_eq!(
        error,
        AtpRefusal::NativeObjectIdentityMismatch { identity: impostor },
        "the refusal names the identity that was claimed"
    );
}

/// The same property stated as a difference: one byte changed produces a
/// different identity, so the old one no longer describes the payload.
///
/// This is the shape `0k6d` and the fabric fixtures both depend on, and it is
/// what makes "compute the ordering, never assume it" the only sound way to
/// build identity fixtures.
#[test]
fn one_changed_byte_invalidates_the_previous_identity() {
    let original = b"payload-v1";
    let amended = b"payload-v2";
    let stale = oid_for(original);

    TransferObjectEntry::from_payload(stale, ObjectKind::Blob, original, None)
        .expect("the identity describes the original bytes");

    let error = TransferObjectEntry::from_payload(stale, ObjectKind::Blob, amended, None)
        .expect_err("the identity no longer describes the amended bytes");
    assert_eq!(
        error,
        AtpRefusal::NativeObjectIdentityMismatch { identity: stale }
    );
}

// ---------------------------------------------------------------------------
// InvalidProbabilisticSummary — three axes
// ---------------------------------------------------------------------------

/// Axis 1: a zero bit count addresses no bits at all.
#[test]
fn a_zero_bit_count_summary_is_refused() {
    let error = BloomHaveSummary::from_wire(0, &[], limits())
        .expect_err("a summary with no bits can never be consulted");
    assert_eq!(error, AtpRefusal::InvalidProbabilisticSummary);
}

/// Axis 2: a bit count that is not a whole number of bytes.
///
/// Non-zero and therefore past the first axis — a probe using only zero would
/// leave this unexercised, and it is the axis the bead's mutation removes.
#[test]
fn a_misaligned_bit_count_summary_is_refused() {
    for bits in [1_u32, 7, 63, 65] {
        let error = BloomHaveSummary::from_wire(bits, &[0u8; 8], limits())
            .expect_err("a bit count must be a whole number of bytes");
        assert_eq!(
            error,
            AtpRefusal::InvalidProbabilisticSummary,
            "a bit count of {bits} is not byte-aligned"
        );
    }
}

/// Axis 3: the byte slice disagrees with the declared bit count.
///
/// Both fields are individually well formed here; only their relation is
/// wrong, which a corpus checking each field alone would never reach.
#[test]
fn a_summary_whose_bytes_contradict_its_bit_count_is_refused() {
    let error = BloomHaveSummary::from_wire(64, &[0u8; 4], limits())
        .expect_err("sixty-four bits is eight bytes, not four");
    assert_eq!(error, AtpRefusal::InvalidProbabilisticSummary);
}

// ---------------------------------------------------------------------------
// InventoryTooLarge — two call sites
// ---------------------------------------------------------------------------

/// Site 1: an object inventory past the bound.
#[test]
fn an_object_inventory_past_the_bound_is_refused() {
    let bound = usize::try_from(limits().max_objects()).expect("the fixture bound fits usize");
    let error = HaveSummary::exact_objects(sorted_oids(bound + 1), limits())
        .expect_err("one object past the bound must refuse");
    assert_eq!(
        error,
        AtpRefusal::InventoryTooLarge {
            offered: (bound + 1) as u64,
            maximum: u64::from(limits().max_objects()),
        },
        "the refusal reports what was offered and what was permitted"
    );
}

/// Site 2: **a segment inventory** past the same bound.
///
/// Probed separately because a refusal reached through `exact_objects` says
/// nothing about `exact_segments` — they are different constructors sharing one
/// helper, and the pairing is the same discipline `0k6d` applied to
/// `ensure_strictly_sorted`.
#[test]
fn a_segment_inventory_past_the_bound_is_refused() {
    let bound = usize::try_from(limits().max_objects()).expect("the fixture bound fits usize");
    let segments = sorted_segment_ids(bound + 1);
    let error = HaveSummary::exact_segments(segments, limits())
        .expect_err("one segment past the bound must refuse");
    assert_eq!(
        error,
        AtpRefusal::InventoryTooLarge {
            offered: (bound + 1) as u64,
            maximum: u64::from(limits().max_objects()),
        }
    );
}

/// The count bound is checked **before** the ordering walk.
///
/// This inventory is wrong twice — past the bound *and* not strictly increasing
/// — and must report the count. The single-site probes cannot see this: each
/// supplies a sorted sequence by construction and so always reaches the count
/// check first anyway, which is precisely why the two-fault case is needed to
/// establish the order.
#[test]
fn the_inventory_bound_outranks_the_ordering_walk() {
    let bound = usize::try_from(limits().max_objects()).expect("the fixture bound fits usize");
    let mut unsorted = sorted_oids(bound + 1);
    unsorted.reverse();

    let error = HaveSummary::exact_objects(unsorted, limits())
        .expect_err("an inventory wrong in two ways must still refuse");
    assert_eq!(
        error,
        AtpRefusal::InventoryTooLarge {
            offered: (bound + 1) as u64,
            maximum: u64::from(limits().max_objects()),
        },
        "the count bound runs before the ordering comparison"
    );
}

/// `count` distinct segment manifest identities in strictly increasing order,
/// computed the same way the object ids are.
fn sorted_segment_ids(count: usize) -> Vec<fgit_types::SegmentManifestId> {
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, SegmentManifestId};
    const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
    let mut ids: Vec<SegmentManifestId> = (0..count)
        .map(|index| {
            let tag = u8::try_from(index).expect("the fixture count fits a byte");
            SegmentManifestId::from_digest(
                DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                    .expect("nonzero corpus fixture algorithm slot"),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
            )
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "the fixture identities must be distinct");
    ids
}
