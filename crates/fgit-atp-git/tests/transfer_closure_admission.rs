#![forbid(unsafe_code)]
//! The `TransferManifest::new` refusal chain, and the inventory constructors
//! that share its sorting helper (`frankengit-0k6d`).
//!
//! `AtpRefusal` has 39 constructed variants no test names. This file takes the
//! ones reachable through one public constructor, which is an **ordered** chain:
//!
//! ```text
//! objects over the limit              -> TooManyObjects
//! roots not strictly sorted           -> NonCanonicalRootOrder / DuplicateRequestedRoot
//! per object:
//!   identity algorithm mismatch       -> ObjectFormatMismatch{identity, expected}
//!   logical size over the limit       -> PayloadTooLarge{offered, maximum}
//!   running total over the budget     -> ReconstructionBudgetExceeded{offered, maximum}
//!   ordering Greater                  -> NonCanonicalObjectOrder
//!   ordering Equal                    -> DuplicateObjectIdentity
//! per requested root:
//!   algorithm mismatch                -> ObjectFormatMismatch{identity, expected}  (second site)
//!   root absent from the closure      -> RequestedRootAbsent{identity}
//! ```
//!
//! # Three structural properties a coarse test would miss
//!
//! **Adjacent guards over one comparison.** `previous.cmp(&entry.identity)`
//! sends `Greater` to `NonCanonicalObjectOrder` and `Equal` to
//! `DuplicateObjectIdentity`. A duplicate must not surface as a misordering:
//! swap those arms and a duplicate *still refuses*, just for the wrong reason,
//! which a test asserting only failure would pass.
//!
//! **One variant, two sites, different payload.** `ObjectFormatMismatch` fires
//! in the object loop and again in the requested-root loop, carrying a
//! different `identity` each time. Both are probed, and each asserts *which*
//! identity was rejected.
//!
//! **One helper, different refusals per caller.** `ensure_strictly_sorted` is
//! called with `(NonCanonicalRootOrder, DuplicateRequestedRoot)` from
//! `TransferManifest` and with `(NonCanonicalInventoryOrder,
//! DuplicateInventoryIdentity)` from `HaveSummary`. The helper is shared; the
//! refusals are not, and swapping a caller's pair would be invisible to a test
//! that only checked that sorting is enforced.
//!
//! # Identities cannot be fabricated, so ordering is computed
//!
//! `TransferObjectEntry::from_payload` re-derives the Git object id from the
//! payload and refuses a mismatch, so a test cannot choose an identity. Every
//! ordering case here therefore **sorts real entries** and indexes into the
//! result rather than assuming which payload hashes lower.
//!
//! # Two arms are deliberately not probed
//!
//! `LengthOverflow` needs a payload longer than `u64::MAX` bytes.
//! `PayloadIdentitySizeMismatch` needs two entries sharing a payload identity
//! while disagreeing on logical size — but the payload identity *is* derived
//! from the same bytes that fix the size, so equal identity implies equal size.
//! Both are defensive; recorded here rather than given manufactured fixtures.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-atp-git/src/**`.

use fgit_atp_git::{
    AtpRefusal, HaveSummary, TransferLimits, TransferManifest, TransferObjectEntry,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_object_fabric::ObjectKind;
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId};

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x71; 16])
}

fn limits() -> TransferLimits {
    TransferLimits::new(64, 1 << 20, 1 << 24, 64).expect("positive bounds are admissible")
}

fn entry(payload: &[u8]) -> TransferObjectEntry {
    let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, payload);
    TransferObjectEntry::from_payload(identity, ObjectKind::Blob, payload, None)
        .expect("a payload matching its own identity describes an object")
}

/// Entries in canonical identity order.
///
/// The order is computed, never assumed: identities are digests, so which
/// payload sorts first is not something a test may hard-code.
fn sorted_entries(payloads: &[&[u8]]) -> Vec<TransferObjectEntry> {
    let mut entries: Vec<_> = payloads.iter().map(|p| entry(p)).collect();
    entries.sort_by_key(TransferObjectEntry::identity);
    entries
}

fn closure(
    roots: Vec<GitOid>,
    objects: Vec<TransferObjectEntry>,
) -> Result<TransferManifest, AtpRefusal> {
    TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        roots,
        objects,
        limits(),
    )
}

/// A closure that passes every stage: two canonically ordered objects, both
/// requested as roots in the same order.
fn coherent() -> (Vec<GitOid>, Vec<TransferObjectEntry>) {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let roots = objects.iter().map(TransferObjectEntry::identity).collect();
    (roots, objects)
}

/// The base passes every stage.
///
/// Without this, every refusal below is consistent with a constructor that
/// rejects everything.
#[test]
fn a_coherent_closure_is_admitted() {
    let (roots, objects) = coherent();
    closure(roots, objects).expect("a canonical closure whose roots are all present must build");
}

// ---------------------------------------------------------------------------
// The object comparison — two adjacent guards
// ---------------------------------------------------------------------------

/// One object listed twice is refused as a duplicate.
#[test]
fn a_repeated_object_is_refused_as_a_duplicate() {
    let objects = sorted_entries(&[b"alpha"]);
    let repeated = vec![objects[0].clone(), objects[0].clone()];
    let refusal = closure(Vec::new(), repeated)
        .expect_err("one object listed twice is not a canonical closure");
    assert!(
        matches!(refusal, AtpRefusal::DuplicateObjectIdentity),
        "a repeat must refuse as a duplicate, never as a misordering, got {refusal:?}"
    );
}

/// Objects in descending identity order are refused as non-canonical.
#[test]
fn objects_in_descending_order_are_refused_as_non_canonical() {
    let mut objects = sorted_entries(&[b"alpha", b"beta"]);
    objects.reverse();
    let refusal =
        closure(Vec::new(), objects).expect_err("a descending object list is not canonical");
    assert!(
        matches!(refusal, AtpRefusal::NonCanonicalObjectOrder),
        "a descending list must refuse as a misordering, got {refusal:?}"
    );
}

/// The two adjacent guards are told apart, not collectively satisfied.
///
/// Both inputs refuse; what is asserted is that they refuse **differently**. A
/// single test showing "a duplicate is refused" cannot distinguish a correct
/// implementation from one whose `Equal` arm was deleted.
#[test]
fn a_duplicate_and_a_misordering_refuse_differently() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let duplicated = vec![objects[0].clone(), objects[0].clone()];
    let mut misordered = objects;
    misordered.reverse();

    let duplicate = closure(Vec::new(), duplicated).expect_err("a duplicate must refuse");
    let misorder = closure(Vec::new(), misordered).expect_err("a misordering must refuse");

    assert!(
        matches!(duplicate, AtpRefusal::DuplicateObjectIdentity),
        "got {duplicate:?}"
    );
    assert!(
        matches!(misorder, AtpRefusal::NonCanonicalObjectOrder),
        "got {misorder:?}"
    );
}

// ---------------------------------------------------------------------------
// The requested-root list — the same shape, a different refusal pair
// ---------------------------------------------------------------------------

/// A root listed twice is refused, and with the *root* duplicate variant rather
/// than the object one.
///
/// The root list is checked before the object loop, so this also pins the
/// ordering of the two checks.
#[test]
fn a_repeated_requested_root_is_refused() {
    let objects = sorted_entries(&[b"alpha"]);
    let root = objects[0].identity();
    let refusal = closure(vec![root, root], objects)
        .expect_err("one root requested twice is not a canonical request");
    assert!(
        matches!(refusal, AtpRefusal::DuplicateRequestedRoot),
        "a repeated root must refuse as a root duplicate, got {refusal:?}"
    );
}

/// Roots in descending order are refused as non-canonical.
#[test]
fn requested_roots_in_descending_order_are_refused() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let mut roots: Vec<GitOid> = objects.iter().map(TransferObjectEntry::identity).collect();
    roots.reverse();
    let refusal = closure(roots, objects).expect_err("a descending root list is not canonical");
    assert!(
        matches!(refusal, AtpRefusal::NonCanonicalRootOrder),
        "a descending root list must refuse as a root misordering, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Format agreement — one variant, two sites
// ---------------------------------------------------------------------------

/// An object whose identity is in a different hash domain than the declared
/// format is refused, naming that identity.
#[test]
fn an_object_in_another_hash_domain_is_refused_naming_it() {
    let payload: &[u8] = b"alpha";
    let foreign = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, payload);
    let entry = TransferObjectEntry::from_payload(foreign, ObjectKind::Blob, payload, None)
        .expect("a sha256 payload matching its own identity describes an object");

    let refusal = closure(Vec::new(), vec![entry])
        .expect_err("an object in another hash domain does not belong to this closure");
    assert!(
        matches!(
            refusal,
            AtpRefusal::ObjectFormatMismatch { identity, expected }
                if identity == foreign && expected == GitHashAlgorithm::Sha1
        ),
        "the refusal must name the offending identity and the expected format, got {refusal:?}"
    );
}

/// The **second** site: a requested root in another hash domain, reached only
/// once every object has passed.
///
/// Same variant as above, different loop, different identity in the payload —
/// which is how the two sites are told apart.
#[test]
fn a_requested_root_in_another_hash_domain_is_refused_naming_it() {
    let objects = sorted_entries(&[b"alpha"]);
    let foreign = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, b"beta");

    let refusal = closure(vec![foreign], objects)
        .expect_err("a root in another hash domain cannot be requested here");
    assert!(
        matches!(
            refusal,
            AtpRefusal::ObjectFormatMismatch { identity, expected }
                if identity == foreign && expected == GitHashAlgorithm::Sha1
        ),
        "the root-loop refusal must name the ROOT identity, distinguishing it from the object \
         loop, got {refusal:?}"
    );
}

/// A requested root that no object in the closure provides is refused, naming
/// it.
///
/// Passes every earlier guard: the roots are canonical and every object is
/// well formed and correctly ordered. Only the cross-reference fails.
#[test]
fn a_requested_root_absent_from_the_closure_is_refused() {
    let objects = sorted_entries(&[b"alpha"]);
    let absent = git_object_id(
        GitHashAlgorithm::Sha1,
        GitObjectKind::Blob,
        b"never-included",
    );

    let refusal = closure(vec![absent], objects)
        .expect_err("a root the closure does not carry cannot be satisfied");
    assert!(
        matches!(refusal, AtpRefusal::RequestedRootAbsent { identity } if identity == absent),
        "an absent root must refuse naming that root, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// More objects than the limit admits is refused.
#[test]
fn more_objects_than_the_limit_admits_is_refused() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let refusal = TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        Vec::new(),
        objects,
        TransferLimits::new(1, 1 << 20, 1 << 24, 64).expect("positive bounds"),
    )
    .expect_err("two objects under a one-object limit must be refused");
    assert!(
        matches!(refusal, AtpRefusal::TooManyObjects),
        "an over-limit closure must refuse as TooManyObjects, got {refusal:?}"
    );
}

/// An object larger than the per-payload limit is refused, naming both sides of
/// the bound.
#[test]
fn an_object_over_the_payload_limit_is_refused_naming_the_bound() {
    let objects = sorted_entries(&[b"alpha"]);
    let offered = objects[0].logical_size();
    let refusal = TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        Vec::new(),
        objects,
        TransferLimits::new(64, 1, 1 << 24, 64).expect("positive bounds"),
    )
    .expect_err("a payload over the per-object bound must be refused");
    assert!(
        matches!(
            refusal,
            AtpRefusal::PayloadTooLarge { offered: o, maximum } if o == offered && maximum == 1
        ),
        "the refusal must report the offered size and the maximum, got {refusal:?}"
    );
}

/// A closure whose objects sum past the reconstruction budget is refused,
/// naming the running total rather than any single object.
///
/// The per-payload limit is left generous so this is attributable to the budget
/// rather than to the earlier guard.
#[test]
fn a_closure_over_the_reconstruction_budget_is_refused() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let first = objects[0].logical_size();
    let refusal = TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        Vec::new(),
        objects,
        TransferLimits::new(64, 1 << 20, first, 64).expect("positive bounds"),
    )
    .expect_err("a closure summing past the reconstruction budget must be refused");
    assert!(
        matches!(refusal, AtpRefusal::ReconstructionBudgetExceeded { .. }),
        "an over-budget closure must refuse as ReconstructionBudgetExceeded, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// The shared sorting helper, called with a different refusal pair
// ---------------------------------------------------------------------------

/// A duplicated inventory entry refuses with the **inventory** duplicate, not
/// the closure one.
///
/// `ensure_strictly_sorted` is shared between `TransferManifest` and
/// `HaveSummary`; only the refusal pair each caller supplies differs. Swapping
/// a caller's pair would be invisible to a test that only checked that sorting
/// is enforced somewhere.
#[test]
fn a_duplicated_inventory_entry_refuses_with_the_inventory_variant() {
    let objects = sorted_entries(&[b"alpha"]);
    let id = objects[0].identity();
    let refusal = HaveSummary::exact_objects(vec![id, id], limits())
        .expect_err("one inventory entry listed twice is not canonical");
    assert!(
        matches!(refusal, AtpRefusal::DuplicateInventoryIdentity),
        "an inventory duplicate must refuse with the INVENTORY variant, not the closure's, \
         got {refusal:?}"
    );
}

/// A descending inventory refuses with the inventory ordering variant.
#[test]
fn a_descending_inventory_refuses_with_the_inventory_variant() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let mut ids: Vec<GitOid> = objects.iter().map(TransferObjectEntry::identity).collect();
    ids.reverse();
    let refusal = HaveSummary::exact_objects(ids, limits())
        .expect_err("a descending inventory is not canonical");
    assert!(
        matches!(refusal, AtpRefusal::NonCanonicalInventoryOrder),
        "a descending inventory must refuse with the INVENTORY ordering variant, got {refusal:?}"
    );
}

/// The permitted twin for both inventory guards.
#[test]
fn a_canonical_inventory_is_admitted() {
    let objects = sorted_entries(&[b"alpha", b"beta"]);
    let ids: Vec<GitOid> = objects.iter().map(TransferObjectEntry::identity).collect();
    HaveSummary::exact_objects(ids, limits())
        .expect("a strictly increasing inventory must be admissible");
}

/// The closure and the inventory report **different** duplicate refusals for
/// the same shape of fault.
///
/// This is what pins the helper's two callers apart. Both refuse a repeated
/// identity; only the variant says which surface was asked.
#[test]
fn the_closure_and_the_inventory_report_different_duplicate_variants() {
    let objects = sorted_entries(&[b"alpha"]);
    let id = objects[0].identity();

    let in_closure = closure(vec![id, id], objects).expect_err("a repeated root must refuse");
    let in_inventory = HaveSummary::exact_objects(vec![id, id], limits())
        .expect_err("a repeated entry must refuse");

    assert!(
        matches!(in_closure, AtpRefusal::DuplicateRequestedRoot),
        "got {in_closure:?}"
    );
    assert!(
        matches!(in_inventory, AtpRefusal::DuplicateInventoryIdentity),
        "got {in_inventory:?}"
    );
}
