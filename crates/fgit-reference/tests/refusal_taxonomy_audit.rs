#![forbid(unsafe_code)]
//! The refusal-enum audit, applied to this crate's own taxonomy.
//!
//! SnowyFortress's method — look for enum variants that are **never
//! constructed** and variants that are **never tested** — was adopted
//! swarm-wide after it found a decorative repository binding in `fgit-treefs`.
//! This applies it to `RefusalClass`, which is `fgit-reference`'s own surface
//! and which I own, rather than only to other people's crates.
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
//! ## What this file deliberately does NOT try to prove
//!
//! **`RefusalCode::ALL` completeness is not checkable here, and pretending
//! otherwise would be the circular-check trap.** `RefusalCode::from_code_point`
//! is implemented by searching `ALL`, so any test comparing the decodable
//! surface against `ALL` compares `ALL` with itself and passes no matter what
//! is missing. Rust offers no variant reflection, so a forgotten `ALL` entry is
//! unenforceable from this crate. See the module note below — it is reported to
//! the `fgit-types` owner rather than papered over with a test that cannot
//! fail.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::refusal::RefusalClass;
use fgit_types::vocabulary::RefusalCode;

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
    let orphans: Vec<&str> = ["a-class-no-code-maps-to"]
        .into_iter()
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
    let false_positives: Vec<&str> = [reached_example]
        .into_iter()
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
