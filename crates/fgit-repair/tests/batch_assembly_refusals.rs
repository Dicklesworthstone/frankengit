#![forbid(unsafe_code)]
//! Batch and target assembly refusals, and the discrimination between two
//! adjacent guards (`frankengit-soty`).
//!
//! Third and last cluster in the `fgit-repair` refusal sweep, after
//! `frankengit-bq4b` and `frankengit-33ib`.
//!
//! # Why these two guards are worth pinning
//!
//! `BatchAuthorityMismatch` is what stops one batch mixing targets read against
//! **different authority bases**. A batch spanning two bases would let a scrub
//! decision rest on state no single authenticated head ever held.
//!
//! `DuplicateTarget` is what stops one manifest appearing twice in a page,
//! which would double-count it in sampling and ordering.
//!
//! # The sharp part: adjacent guards over the same comparison
//!
//! `AuthenticatedScrubBatch::new` checks equality **before** less-than:
//!
//! ```text
//! if target.identity() == previous  -> DuplicateTarget
//! if target.identity() <  previous  -> NonCanonicalTargetOrder
//! ```
//!
//! So a duplicate must surface as `DuplicateTarget` and **not** as
//! `NonCanonicalTargetOrder`. Reorder those two arms, or widen the ordering
//! guard from `<` to `<=`, and a duplicate reports the wrong code **while still
//! refusing** — which a test asserting only "assembly refused" would happily
//! pass. Every probe here therefore asserts the exact variant, and
//! [`a_duplicate_and_a_misordering_are_told_apart`] pins the two against each
//! other directly.
//!
//! The guards are also ordered relative to the basis check, so a probe for a
//! later guard must satisfy the earlier one — every duplicate and ordering
//! probe below uses targets that all share the batch's declared basis.
//!
//! # What is not covered, and why no fixture was manufactured for it
//!
//! `ManifestIdentityUnavailable` (`lib.rs:206`) needs a `SegmentManifest` whose
//! `identity()` fails. Every manifest reachable through the public API here is
//! built by `SegmentManifest::from_verified_segment` from a segment that just
//! verified, and its identity is available by construction. Rather than
//! manufacture a fixture to force that arm, it is recorded as unreached: a
//! fabricated probe for an arm no caller can produce would assert coverage that
//! does not exist.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-repair/src/**`.

use asupersync::security::SecurityContext;
use fgit_object_fabric::fabric::{ManifestLimits, SegmentManifest};
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope,
    ObjectKind, SegmentLimits, SegmentRecordInput,
};
use fgit_raptorq::{ProtectedMicrosegment, protect_microsegment};
use fgit_repair::{AuthenticatedScrubBatch, AuthenticatedScrubTarget, ScrubRefusal};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1,
    RepositoryAuthorityHeadId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn security() -> SecurityContext {
    SecurityContext::for_testing(78)
}

fn head(value: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[value; 32]).expect("32-byte corpus fixture body"),
    )
}

fn canonical_segment(fill: u8) -> Vec<u8> {
    let limits = SegmentLimits::default();
    let payload = format!("scrub protected payload {fill}").into_bytes();
    let digest = CryptoDigest;
    let envelope = ObjectEnvelope::new(
        b"scrub-tenant".to_vec(),
        GitOid::Sha1(GitOidSha1::from_bytes([fill; GitOidSha1::LEN])),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("test payload fits u64"),
        digest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("canonical payload has a commitment"),
        b"canonical-codec".to_vec(),
        [fill; 32],
        None,
        &limits,
    )
    .expect("canonical test envelope builds");
    let mut builder = MicrosegmentBuilder::new(&digest, limits);
    builder
        .push(SegmentRecordInput { envelope, payload })
        .expect("canonical test record builds");
    builder
        .build()
        .expect("canonical test segment builds")
        .as_bytes()
        .to_vec()
}

/// The protected segment and the manifest describing the *same* bytes.
///
/// Kept together so a probe can deliberately cross one segment's scope with
/// another's manifest, which is the only way to reach `ManifestScopeMismatch`
/// through the public API.
fn material(fill: u8) -> (ProtectedMicrosegment, SegmentManifest) {
    let bytes = canonical_segment(fill);
    let context = security();
    let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &context)
        .expect("canonical segment is RaptorQ protected");
    let reader = MicrosegmentReader::open(&bytes, &CryptoDigest, &SegmentLimits::default())
        .expect("canonical segment is readable");
    let manifest =
        SegmentManifest::from_verified_segment(&reader, Vec::new(), &ManifestLimits::default())
            .expect("verified segment produces a manifest");
    (protected, manifest)
}

fn target(fill: u8, basis: RepositoryAuthorityHeadId) -> AuthenticatedScrubTarget {
    let (protected, manifest) = material(fill);
    AuthenticatedScrubTarget::new(
        protected.scope().clone(),
        manifest,
        basis,
        protected.symbols().to_vec(),
    )
    .expect("manifest and protected scope agree")
}

/// Two distinct targets on one basis, returned in canonical identity order.
///
/// The order is computed rather than assumed: identities are digests, so which
/// fill sorts first is not something a test may hard-code.
fn ordered_pair(
    basis: RepositoryAuthorityHeadId,
) -> (AuthenticatedScrubTarget, AuthenticatedScrubTarget) {
    let first = target(7, basis);
    let second = target(9, basis);
    assert_ne!(
        first.identity(),
        second.identity(),
        "the two fixture fills must produce distinct manifests, or the ordering probes below \
         would silently become duplicate probes"
    );
    if first.identity() < second.identity() {
        (first, second)
    } else {
        (second, first)
    }
}

// ---------------------------------------------------------------------------
// Guard 1 — every target must name the batch's declared basis
// ---------------------------------------------------------------------------

#[test]
fn a_target_naming_a_different_authority_basis_is_refused() {
    let declared = head(13);
    let other = head(14);
    assert_ne!(declared, other, "the two fixture bases must differ");

    let refusal = AuthenticatedScrubBatch::new(declared, 1, 0, vec![target(7, other)])
        .expect_err("a target read against another basis must not join this batch");
    assert_eq!(
        refusal,
        ScrubRefusal::BatchAuthorityMismatch,
        "a basis disagreement must refuse as itself"
    );
}

/// The permitted twin: targets that share the declared basis assemble.
#[test]
fn targets_sharing_the_declared_basis_are_admitted() {
    let basis = head(13);
    let (first, second) = ordered_pair(basis);
    AuthenticatedScrubBatch::new(basis, 1, 0, vec![first, second])
        .expect("targets read against the declared basis must assemble");
}

// ---------------------------------------------------------------------------
// Guard 2 — a repeated manifest, and telling it apart from a misordering
// ---------------------------------------------------------------------------

/// A repeated target refuses as a **duplicate**, not as an ordering violation.
///
/// Asserting the exact variant is the whole point: equality is checked before
/// less-than, so swapping those arms would still refuse while reporting the
/// wrong reason.
#[test]
fn a_repeated_target_is_refused_as_a_duplicate() {
    let basis = head(13);
    let refusal =
        AuthenticatedScrubBatch::new(basis, 1, 0, vec![target(7, basis), target(7, basis)])
            .expect_err("one manifest must not appear twice in a page");
    assert_eq!(
        refusal,
        ScrubRefusal::DuplicateTarget,
        "a repeat must refuse as a duplicate, never as an ordering violation"
    );
}

/// Genuinely out-of-order targets refuse as an ordering violation.
#[test]
fn targets_out_of_canonical_order_are_refused_as_a_misordering() {
    let basis = head(13);
    let (first, second) = ordered_pair(basis);
    let refusal = AuthenticatedScrubBatch::new(basis, 1, 0, vec![second, first])
        .expect_err("a descending page must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::NonCanonicalTargetOrder,
        "a descending pair must refuse as an ordering violation"
    );
}

/// The two adjacent guards are told apart, not collectively satisfied.
///
/// This is the discrimination the bead exists for. Both inputs refuse; what is
/// asserted is that they refuse **differently**. A single test showing "a
/// duplicate is refused" cannot distinguish a correct implementation from one
/// whose equality arm was deleted and whose ordering guard was widened to `<=`.
#[test]
fn a_duplicate_and_a_misordering_are_told_apart() {
    let basis = head(13);
    let (first, second) = ordered_pair(basis);

    let duplicate =
        AuthenticatedScrubBatch::new(basis, 1, 0, vec![target(7, basis), target(7, basis)])
            .expect_err("a duplicate must refuse");
    let misordered = AuthenticatedScrubBatch::new(basis, 1, 0, vec![second, first])
        .expect_err("a misordering must refuse");

    assert_ne!(
        duplicate, misordered,
        "a duplicate and a misordering both refuse, but they must not report the same code — \
         collapsing them would hide the equality guard entirely"
    );
    assert_eq!(duplicate, ScrubRefusal::DuplicateTarget);
    assert_eq!(misordered, ScrubRefusal::NonCanonicalTargetOrder);
}

/// The permitted twin for both guards above: two distinct targets in canonical
/// order assemble.
///
/// Without it, every refusal in this section could be an assembler that rejects
/// any page with more than one target.
#[test]
fn two_distinct_targets_in_canonical_order_are_admitted() {
    let basis = head(13);
    let (first, second) = ordered_pair(basis);
    AuthenticatedScrubBatch::new(basis, 1, 0, vec![first, second])
        .expect("a canonically ordered page of distinct targets must assemble");
}

// ---------------------------------------------------------------------------
// Target assembly — manifest and scope must describe the same segment
// ---------------------------------------------------------------------------

/// A manifest crossed with another segment's scope is refused.
///
/// Built by taking the manifest of one segment and the protected scope of a
/// different one, which is the only route to this guard through the public API:
/// a manifest built from its own verified segment always agrees with its own
/// scope.
#[test]
fn a_manifest_crossed_with_another_segments_scope_is_refused() {
    let (_, manifest) = material(7);
    let (other, _) = material(9);

    let refusal = AuthenticatedScrubTarget::new(
        other.scope().clone(),
        manifest,
        head(13),
        other.symbols().to_vec(),
    )
    .expect_err("a manifest describing a different segment than its scope must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::ManifestScopeMismatch,
        "a scope disagreement must refuse as itself"
    );
}

/// The permitted twin: a manifest with its own segment's scope is admitted, so
/// the refusal above is attributable to the crossing rather than to a
/// constructor that rejects everything.
#[test]
fn a_manifest_with_its_own_scope_is_admitted() {
    let (protected, manifest) = material(7);
    AuthenticatedScrubTarget::new(
        protected.scope().clone(),
        manifest,
        head(13),
        protected.symbols().to_vec(),
    )
    .expect("a manifest and the scope of its own segment must agree");
}
