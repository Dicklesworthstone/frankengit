#![forbid(unsafe_code)]
//! V1 advertisement ordering and bounded-name refusals (`frankengit-dy7z`).
//!
//! `V1Advertisement::new` is both a public encoder boundary and the
//! re-validation boundary for repository-supplied advertisements. The accepted
//! twins come first so each refusal below is attributable to its named fault,
//! rather than to an encoder that rejects every input.
//!
//! `UnsortedOrDuplicateAdvertisement` deliberately covers two shapes: a
//! descending pair and an equal pair. Its name tells the caller about that
//! collapse, and the probe pins it with an equality assertion rather than
//! treating either shape as representative of the other.
//!
//! `AdvertisedRef::oid` and `AdvertisedRef::name` are public fields. The
//! `RefNameTooLarge` probe therefore uses a struct literal deliberately: an
//! upstream repository can bypass `AdvertisedRef::new`, so
//! `V1Advertisement::new` must re-validate the supplied name. That validation
//! is load-bearing, not a defensive duplicate of the constructor.
//!
//! The count ceiling runs before the per-ref walk. The count probe supplies an
//! oversized name too and still expects `TooManyAdvertisedRefs`; it is wrong
//! twice, which makes an order swap observable.
//!
//! # Non-claims
//!
//! At authoring time, six `WireError` variants remain unnamed by an
//! enum-qualified integration-test reference: `InvalidLimit`,
//! `AllocationFailure`, `ObjectFormatMismatch`, `MissingWant`,
//! `TooManyFilterParts`, and `PackSourceRefused`. This is not a claim that the
//! enum is complete. This file also deliberately leaves the receive-pack probe
//! files untouched because the e2e suite asserts their counts exactly.

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, V1Advertisement, WireError, WireLimits,
};

const TIP: &str = "1111111111111111111111111111111111111111";

fn limits(max_advertised_refs: usize, max_ref_name_bytes: usize) -> WireLimits {
    WireLimits {
        max_advertised_refs,
        max_ref_name_bytes,
        ..WireLimits::default()
    }
}

fn oid() -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, TIP).expect("fixture object id")
}

fn checked_ref(name: &[u8], limits: &WireLimits) -> AdvertisedRef {
    AdvertisedRef::new(oid(), name, limits).expect("fixture advertised ref")
}

fn advertisement(
    refs: Vec<AdvertisedRef>,
    limits: &WireLimits,
) -> Result<V1Advertisement, WireError> {
    V1Advertisement::new(refs, Capabilities::default(), GitObjectFormat::Sha1, limits)
}

// ---------------------------------------------------------------------------
// Permitted twins first
// ---------------------------------------------------------------------------

#[test]
fn a_sorted_duplicate_free_advertisement_at_its_count_limit_is_admitted() {
    let limits = limits(2, 64);
    advertisement(
        vec![
            checked_ref(b"refs/heads/a", &limits),
            checked_ref(b"refs/heads/b", &limits),
        ],
        &limits,
    )
    .expect("the exact advertised-ref count limit is admitted");
}

#[test]
fn an_advertised_ref_name_at_its_exact_byte_limit_is_admitted() {
    let name = b"refs/heads/exact";
    let limits = limits(1, name.len());
    advertisement(vec![checked_ref(name, &limits)], &limits)
        .expect("the exact advertised-ref name limit is admitted");
}

// ---------------------------------------------------------------------------
// TooManyAdvertisedRefs — count bound before the per-ref walk
// ---------------------------------------------------------------------------

#[test]
fn advertisement_count_ceiling_precedes_per_ref_name_validation() {
    let limits = limits(1, 16);
    let oversized = AdvertisedRef {
        oid: oid(),
        name: b"refs/heads/name-beyond-the-bound".to_vec(),
    };
    let error = advertisement(
        vec![oversized, checked_ref(b"refs/heads/a", &limits)],
        &limits,
    )
    .expect_err("two refs exceed the count ceiling before the oversized name is inspected");

    assert_eq!(error, WireError::TooManyAdvertisedRefs { limit: 1 });
}

// ---------------------------------------------------------------------------
// UnsortedOrDuplicateAdvertisement — both shapes of the intentional collapse
// ---------------------------------------------------------------------------

#[test]
fn unsorted_and_duplicate_advertisements_share_the_named_refusal() {
    let limits = limits(2, 64);
    let unsorted = advertisement(
        vec![
            checked_ref(b"refs/heads/z", &limits),
            checked_ref(b"refs/heads/a", &limits),
        ],
        &limits,
    )
    .expect_err("a descending advertisement must be refused");

    let first = checked_ref(b"refs/heads/main", &limits);
    let duplicate = advertisement(vec![first.clone(), first], &limits)
        .expect_err("a duplicate advertisement must be refused");

    let expected = WireError::UnsortedOrDuplicateAdvertisement;
    assert_eq!(unsorted, expected);
    assert_eq!(duplicate, expected);
    assert_eq!(
        unsorted, duplicate,
        "the two advertised shapes intentionally collapse"
    );
}

// ---------------------------------------------------------------------------
// RefNameTooLarge — public-field construction must still be re-validated
// ---------------------------------------------------------------------------

#[test]
fn a_struct_literal_advertised_ref_still_hits_the_ref_name_ceiling() {
    let limits = limits(1, 16);
    // This bypasses `AdvertisedRef::new` on purpose. Its public fields are the
    // repository-facing contract, so `V1Advertisement::new` must validate it.
    let unvalidated = AdvertisedRef {
        oid: oid(),
        name: b"refs/heads/name-beyond-the-bound".to_vec(),
    };
    let error = advertisement(vec![unvalidated], &limits)
        .expect_err("the public-field path must not bypass the name ceiling");

    assert_eq!(error, WireError::RefNameTooLarge { limit: 16 });
}
