#![forbid(unsafe_code)]

//! frankengit-6qpz: `ScalarResolver`'s two duplicate-entry guards.
//!
//! The resolver is handed a caller-supplied slice of `PackObject` and looks
//! entries up by offset or by id with a linear scan. Both scans refuse when a
//! key matches twice:
//!
//! ```text
//! delta.rs:234  find_by_offset  second match -> DuplicateObjectOffset(offset)
//! delta.rs:254  find_by_id      second match -> DuplicateObjectId
//! ```
//!
//! Neither had a test. They matter because `ScalarResolver::new` validates only
//! the entry COUNT and per-object sizes — it does not check key uniqueness — so
//! nothing between a caller and a resolve call rejects a slice with two entries
//! claiming the same offset. Silently taking the first would make delta
//! resolution depend on slice order, which is exactly the kind of
//! order-dependent answer §8 rules out for anything that decides placement.
//!
//! # Why these are reachable at all
//!
//! `PackObject` is a public enum with public fields, and `new` takes
//! `&[PackObject]` from the caller. A slice with duplicate keys is therefore
//! constructible through the public API by anyone assembling objects from a
//! source other than `parse_quarantined_pack` — which is the case the guards
//! exist for.

use fgit_pack::{ObjectId, PackError, PackLimits, PackObject, ScalarResolver};
use fgit_types::native::GitOidSha1;

const fn never_expires() -> bool {
    true
}

fn oid(byte: u8) -> ObjectId {
    GitOidSha1::from_bytes([byte; 20]).into()
}

fn base(offset: u64, id: Option<ObjectId>, body: &[u8]) -> PackObject {
    PackObject::Base {
        offset,
        id,
        data: body.to_vec(),
    }
}

/// The limits must outlive the resolver, so the caller owns them and passes a
/// reference in; a `PackLimits::default()` temporary cannot be borrowed here.
fn resolver_over<'a>(
    objects: &'a [PackObject],
    limits: &'a PackLimits,
) -> ScalarResolver<'a, 'a, ()> {
    ScalarResolver::new(objects, &(), limits, &mut never_expires)
        .expect("a small object slice is within default limits")
}

/// Two entries at the same offset are refused, and the refusal names it.
///
/// The bodies differ, so "take the first" and "take the last" would produce
/// different results — which is precisely why refusing is the only safe answer.
#[test]
fn two_entries_at_the_same_offset_are_refused() {
    let objects = vec![
        base(12, Some(oid(0xaa)), b"first"),
        base(12, Some(oid(0xbb)), b"second"),
    ];

    assert_eq!(
        resolver_over(&objects, &PackLimits::default()).resolve_offset(12, &mut never_expires),
        Err(PackError::DuplicateObjectOffset(12)),
    );
}

/// The permitted twin: distinct offsets resolve, and resolve to the right body.
///
/// Asserted on the returned bytes rather than `is_ok`. A resolver that refused
/// every multi-entry slice would satisfy the probe above and be useless; one
/// that returned the wrong entry would satisfy a weaker check here.
#[test]
fn distinct_offsets_resolve_to_their_own_entries() {
    let objects = vec![
        base(12, Some(oid(0xaa)), b"first"),
        base(34, Some(oid(0xbb)), b"second"),
    ];
    let limits = PackLimits::default();
    let resolver = resolver_over(&objects, &limits);

    assert_eq!(
        resolver.resolve_offset(12, &mut never_expires),
        Ok(b"first".to_vec()),
    );
    assert_eq!(
        resolver.resolve_offset(34, &mut never_expires),
        Ok(b"second".to_vec()),
    );
}

/// Two entries carrying the same id are refused.
///
/// The sibling guard, on the by-id scan. Their offsets differ, so the
/// offset guard cannot be what fires — only the id collision.
#[test]
fn two_entries_with_the_same_id_are_refused() {
    let shared = oid(0xcc);
    let objects = vec![
        base(12, Some(shared), b"first"),
        base(34, Some(shared), b"second"),
    ];

    assert_eq!(
        resolver_over(&objects, &PackLimits::default()).resolve_id(&shared, &mut never_expires),
        Err(PackError::DuplicateObjectId),
    );
}

/// The permitted twin for the by-id scan: distinct ids resolve correctly.
#[test]
fn distinct_ids_resolve_to_their_own_entries() {
    let objects = vec![
        base(12, Some(oid(0xaa)), b"first"),
        base(34, Some(oid(0xbb)), b"second"),
    ];
    let limits = PackLimits::default();
    let resolver = resolver_over(&objects, &limits);

    assert_eq!(
        resolver.resolve_id(&oid(0xbb), &mut never_expires),
        Ok(b"second".to_vec()),
    );
}

/// An entry with no id is invisible to the by-id scan rather than matching.
///
/// `find_by_id` filters on `id().is_some_and(..)`. An entry whose id is `None`
/// must not collide with anything, so a slice mixing one identified and one
/// anonymous entry resolves rather than reporting a duplicate — the axis that
/// distinguishes "two ids matched" from "two entries were scanned".
#[test]
fn an_entry_without_an_id_does_not_collide() {
    let named = oid(0xaa);
    let objects = vec![
        base(12, Some(named), b"first"),
        base(34, None, b"anonymous"),
    ];

    assert_eq!(
        resolver_over(&objects, &PackLimits::default()).resolve_id(&named, &mut never_expires),
        Ok(b"first".to_vec()),
    );
}
