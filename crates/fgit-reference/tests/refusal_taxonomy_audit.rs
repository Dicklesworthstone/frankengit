#![forbid(unsafe_code)]
//! The refusal-enum audit, applied to this crate's own taxonomy.
//!
//! The method — look for enum variants that are **never constructed** and
//! variants that are **never tested** — was adopted swarm-wide after it found
//! a decorative repository binding in `fgit-treefs`. This applies it to
//! `RefusalClass`, which is `fgit-reference`'s own surface and which I own,
//! rather than only to other people's crates.
//!
//! Attribution for the method is in this file's commit message and on the
//! fg019c bead, not inline: backticking a person's name to satisfy
//! `doc_markdown` asserts it is a code item, which is a worse doc than putting
//! the credit where it is durable and does not decay when a pane is renamed.
//!
//! ## What the existing in-crate tests do and do not establish
//!
//! `refusal.rs` already asserts that every published `RefusalCode` can be
//! classified. That test's own body is `of(code) == of(code)`: it establishes
//! determinism, which a `const fn` match gives for free, and callability, which
//! the exhaustive match already guarantees at compile time. It is worth keeping
//! and it is not worth much.
//!
//! The property it does **not** establish is the one this file adds: that every
//! class in the taxonomy is actually *reachable*. A class no code maps to is a
//! decorative distinction — it reads as coverage in a taxonomy of thirteen,
//! documents a security posture nothing enforces, and would be cited as
//! evidence that some category of refusal is handled.
//!
//! ## What this file does NOT prove, and where that check actually lives
//!
//! `RefusalCode::ALL` completeness is **not proved here** — but it *is* proved,
//! in `fgit-types/tests/vocabulary_all_membership.rs`, which asserts that
//! `ALL`'s distinct members number exactly `core::mem::variant_count::<RefusalCode>()`.
//! Distinct members equalling the type's own variant total leaves no variant
//! unlisted, and the total is read **from the type**, so that corpus cannot
//! drift the way a hand-written one does. The same file covers
//! `RequestRejectionCode`, `MismatchPolicy` and `PublicationEpoch`. It needs
//! `#![feature(variant_count)]`, which was this repository's first `#![feature]`
//! gate — worth knowing if you are weighing the approach elsewhere.
//!
//! The trap that makes it look impossible is still worth stating, because the
//! obvious attempt is circular: `RefusalCode::from_code_point` is implemented by
//! *searching* `ALL`, so a test comparing the decodable surface against `ALL`
//! compares `ALL` with itself and passes no matter what is missing.
//! `variant_count` escapes that by not consulting `ALL` at all.
//!
//! A second, source-level check also exists and remains valid: `RefusalClass::of`
//! is an **exhaustive match**, so the compiler forces every real variant to
//! appear in `refusal.rs`, making that file an independent enumeration to
//! compare `ALL` against. That one is over source text, so it belongs in a
//! checker or constitution-lane rule rather than in a Rust test.
//!
//! **This paragraph has now been wrong twice, in opposite directions**, and that
//! is the part worth keeping. An early draft called the check *unenforceable*;
//! the next called it *not provable at runtime and belonging in a checker*.
//! Both were claims about what could not be done, and both aged silently while
//! the codebase moved. A claim that something IS done gets checked by the
//! compiler; a claim that something CANNOT be done gets checked by nobody, and
//! a stale impossibility claim is how a gap stops being looked at.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::refusal::RefusalClass;
use fgit_types::vocabulary::RefusalCode;

/// The vocabulary floor both tests below are pinned against.
///
/// Every test in this file iterates `RefusalCode::ALL`, so its coverage is
/// exactly `ALL.len()`. That makes a *shrinking* vocabulary the silent failure:
/// the reachability audit still passes if a reduced set happens to touch all
/// thirteen classes, and the range check still passes because its only assertion
/// is inside the loop and a shorter loop simply asserts fewer times. Neither
/// reports that it now covers less, which is coverage evaporating rather than
/// breaking.
///
/// `ALL` is a `const`, so its length is known at compile time and this cannot be
/// a runtime assertion without being a tautology — it is a build-time gate, and
/// a vocabulary that shrinks below the measured floor fails the build.
///
/// This is **not** the completeness check described above and does not stand in
/// for it: it bounds the size of `ALL` from below, and says nothing about
/// whether `ALL` names every variant of the enum. That check is still owed to a
/// checker or constitution-lane rule.
///
/// Measured at the time of writing: 61 codes in `RefusalCode::ALL`, 13 classes
/// in `RefusalClass::ALL`. `>=` rather than `==` so adding a code is an ordinary
/// change and only removal trips the gate.
const _: () = assert!(
    RefusalCode::ALL.len() >= 61,
    "the published refusal vocabulary shrank below the 61 codes this audit was \
     pinned against; every test here iterates ALL, so a shorter vocabulary would \
     pass while covering less"
);

/// Every class in the taxonomy is reachable from at least one published code.
///
/// A class nothing maps to is decorative: it inflates a taxonomy that other
/// crates read as a coverage map, and it is exactly the never-constructed
/// variant the adopted audit method looks for.
#[test]
fn every_refusal_class_is_reachable_from_a_published_code() {
    let mut reached: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    for code in RefusalCode::ALL {
        reached
            .entry(RefusalClass::of(*code).as_str())
            .or_default()
            .push(code.as_str());
    }

    let orphans: Vec<&'static str> = RefusalClass::ALL
        .iter()
        .map(|class| class.as_str())
        .filter(|name| !reached.contains_key(name))
        .collect();

    assert!(
        orphans.is_empty(),
        "these refusal classes are declared but no published code maps to them, \
         so the taxonomy claims coverage it does not have: {orphans:?}"
    );
}

/// The audit above can fail.
///
/// Its assertion is an absence — "no orphan classes" — and an absence assertion
/// that has never been seen firing is a sentence, not a test. This constructs
/// the orphan condition over the same computation and requires it to be
/// detected, so the green above means the check looked rather than that it
/// could not look.
#[test]
fn the_orphan_detection_finds_an_orphan_when_one_exists() {
    let reached: BTreeSet<&'static str> = RefusalCode::ALL
        .iter()
        .map(|code| RefusalClass::of(*code).as_str())
        .collect();

    // A name that is deliberately not in the taxonomy, standing in for a class
    // that nothing classifies into.
    let orphans: Vec<&str> = std::iter::once("a-class-no-code-maps-to")
        .filter(|name| !reached.contains(name))
        .collect();

    assert_eq!(
        orphans,
        vec!["a-class-no-code-maps-to"],
        "the orphan filter failed to flag a class with no mapping, so the audit \
         above cannot fail in the direction that matters"
    );

    // And the permitted twin: a class that IS reached must not be flagged.
    let reached_example = RefusalClass::of(RefusalCode::RefNameInvalid).as_str();
    let false_positives: Vec<&str> = std::iter::once(reached_example)
        .filter(|name| !reached.contains(name))
        .collect();
    assert!(
        false_positives.is_empty(),
        "the orphan filter flagged {reached_example}, which a published code does map to"
    );
}

/// Classification is total over the published surface, and every code's class
/// is one of the declared thirteen.
///
/// Distinct from the in-crate determinism test: this asserts the *range* of
/// `of` stays inside `RefusalClass::ALL`. A class returned by `of` but missing
/// from `ALL` would make every consumer that iterates `ALL` — including the
/// audit above — silently blind to it.
#[test]
fn no_code_classifies_into_a_class_outside_the_declared_taxonomy() {
    let declared: BTreeSet<&'static str> = RefusalClass::ALL
        .iter()
        .map(|class| class.as_str())
        .collect();

    for code in RefusalCode::ALL {
        let class = RefusalClass::of(*code);
        assert!(
            declared.contains(class.as_str()),
            "{} classifies into {}, which is not in RefusalClass::ALL",
            code.as_str(),
            class.as_str()
        );
    }
}

/// A published code maps to exactly one class name, and distinct classes keep
/// distinct names.
///
/// Two classes sharing a name would collapse silently in every map keyed by
/// `as_str` — including the reachability audit above, which would then report a
/// class as reached because its twin was.
#[test]
fn class_names_do_not_collide_so_the_audit_cannot_be_fooled_by_a_shared_name() {
    let names: BTreeSet<&'static str> = RefusalClass::ALL
        .iter()
        .map(|class| class.as_str())
        .collect();
    assert_eq!(
        names.len(),
        RefusalClass::ALL.len(),
        "two refusal classes share a name, so any audit keyed on the name \
         under-counts the taxonomy"
    );
}
