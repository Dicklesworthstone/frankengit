//! `apply_net_effects` per target class, including the two arms nothing reached.
//!
//! FG-008's second acceptance line — `apply(normal_form, basis) ==
//! evaluator-final-workspace` — is exercised end to end by
//! `normal_form_corpus.rs`, over generated programs, against an independent
//! ordered-evaluation oracle. That is the stronger test and this does not
//! replace it.
//!
//! It exists because the corpus generates **ref, forge and outbox** intents and
//! deliberately does not generate retention ones (its oracle panics loudly if
//! one appears). So `RetentionEffect::Add` and `RetentionEffect::Remove` inside
//! `apply_net_effects` had **zero** coverage: both call sites in the workspace
//! pass a basis whose retention set is empty and effects whose retention map is
//! empty, and the round-trip compared two empty sets every time.
//!
//! Two empty sets comparing equal is not evidence about a branch. The corpus
//! was right to declare retention unmodelled rather than fake it; the gap is
//! that nothing else closed it either.
//!
//! # What each case here is for
//!
//! Every target class gets its *pair* — the arm that adds and the arm that
//! removes — because a `Remove` implemented as a no-op passes any test that
//! only ever adds, and an `Add` implemented as "insert everything" passes any
//! test that only ever removes.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::effect::{NetEffects, RefEffect, RetentionEffect};
use fgit_reference::intent::{RetentionClass, RetentionRoot};
use fgit_txn::{Workspace, apply_net_effects};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("a well-formed ref name")
}

const fn root(seed: u8, class: RetentionClass) -> RetentionRoot {
    RetentionRoot {
        object: oid(seed),
        class,
    }
}

/// A basis holding one ref and two retention roots.
fn basis() -> Workspace {
    Workspace {
        refs: BTreeMap::from([(name("refs/heads/main"), oid(0x11))]),
        forge: BTreeMap::new(),
        retention: BTreeSet::from([
            root(0xA0, RetentionClass::ReferencedByRef),
            root(0xB0, RetentionClass::LegalHold),
        ]),
        outbox: BTreeMap::new(),
    }
}

#[test]
fn an_empty_normal_form_leaves_the_basis_exactly_as_it_was() {
    // The identity case, and the control for everything below. Without it a
    // function that returned the basis unchanged would satisfy nothing here,
    // but a function that returned `Workspace::default()` would still pass the
    // "removed" half of every pair.
    let before = basis();
    let after = apply_net_effects(&before, &NetEffects::default());

    assert_eq!(
        after, before,
        "an empty normal form publishes nothing, so the basis must survive intact"
    );
    assert_eq!(
        after.retention.len(),
        2,
        "the basis's retention roots in particular must survive; the corpus never carries any, so \
         this is the only place their preservation is checked"
    );
}

#[test]
fn a_retention_add_holds_a_root_the_basis_did_not() {
    let effects = NetEffects {
        retention: BTreeMap::from([(
            root(0xC0, RetentionClass::GraceTombstone),
            RetentionEffect::Add,
        )]),
        ..NetEffects::default()
    };

    let after = apply_net_effects(&basis(), &effects);

    assert!(
        after
            .retention
            .contains(&root(0xC0, RetentionClass::GraceTombstone)),
        "RetentionEffect::Add must leave the root held"
    );
    assert_eq!(
        after.retention.len(),
        3,
        "adding one root to a basis holding two must yield three; a wholesale replace would yield \
         one and still satisfy the contains check above"
    );
}

#[test]
fn a_retention_remove_releases_a_root_the_basis_held() {
    // The paired arm. Without it, `Remove` implemented as a no-op passes every
    // other test in this file.
    let effects = NetEffects {
        retention: BTreeMap::from([(
            root(0xA0, RetentionClass::ReferencedByRef),
            RetentionEffect::Remove,
        )]),
        ..NetEffects::default()
    };

    let after = apply_net_effects(&basis(), &effects);

    assert!(
        !after
            .retention
            .contains(&root(0xA0, RetentionClass::ReferencedByRef)),
        "RetentionEffect::Remove must release the root"
    );
    assert!(
        after
            .retention
            .contains(&root(0xB0, RetentionClass::LegalHold)),
        "removing one root must not disturb another; a `clear()` would pass the assertion above"
    );
}

#[test]
fn retention_roots_are_distinguished_by_class_and_not_only_by_object() {
    // `RetentionRoot` is (object, class). Removing the root for one class must
    // not release the root protecting the same object under another — a legal
    // hold surviving an ordinary release is the whole reason the class is part
    // of the key rather than metadata beside it.
    let same_object_two_classes = Workspace {
        retention: BTreeSet::from([
            root(0xD0, RetentionClass::ReferencedByRef),
            root(0xD0, RetentionClass::LegalHold),
        ]),
        ..Workspace::default()
    };
    let effects = NetEffects {
        retention: BTreeMap::from([(
            root(0xD0, RetentionClass::ReferencedByRef),
            RetentionEffect::Remove,
        )]),
        ..NetEffects::default()
    };

    let after = apply_net_effects(&same_object_two_classes, &effects);

    assert!(
        after
            .retention
            .contains(&root(0xD0, RetentionClass::LegalHold)),
        "the legal hold on the same object must survive a ReferencedByRef release"
    );
    assert_eq!(
        after.retention.len(),
        1,
        "exactly the named root is released, not every root over that object"
    );
}

#[test]
fn a_remove_for_a_root_the_basis_never_held_is_not_an_error() {
    // The normal form is target-disjoint and carries what the evaluator
    // decided; it is not re-evaluated here. A Remove whose root is absent is
    // therefore an ordinary no-op rather than a condition to detect, and this
    // pins that reading so nobody later "fixes" it into a panic.
    let effects = NetEffects {
        retention: BTreeMap::from([(
            root(0xEE, RetentionClass::LegalHold),
            RetentionEffect::Remove,
        )]),
        ..NetEffects::default()
    };

    let after = apply_net_effects(&basis(), &effects);

    assert_eq!(
        after.retention,
        basis().retention,
        "removing an absent root changes nothing"
    );
}

#[test]
fn ref_set_and_delete_are_both_applied() {
    // The other pair, included because these two arms are reached by the
    // corpus only through generated programs — nothing states them directly,
    // so a reader cannot see the contract without running a fuzzer.
    let effects = NetEffects {
        refs: BTreeMap::from([
            (name("refs/heads/main"), RefEffect::Delete),
            (name("refs/heads/next"), RefEffect::Set(oid(0x22))),
        ]),
        ..NetEffects::default()
    };

    let after = apply_net_effects(&basis(), &effects);

    assert!(
        !after.refs.contains_key(&name("refs/heads/main")),
        "RefEffect::Delete must remove the ref"
    );
    assert_eq!(
        after.refs.get(&name("refs/heads/next")),
        Some(&oid(0x22)),
        "RefEffect::Set must publish the new value"
    );
    assert_eq!(after.refs.len(), 1, "one deleted, one created");
}

#[test]
fn effects_over_disjoint_targets_compose_without_interfering() {
    // The property the normal form exists to guarantee, stated directly rather
    // than inferred from a corpus run: every effect lands on a distinct target,
    // so applying all of them together equals applying each in isolation.
    let effects = NetEffects {
        refs: BTreeMap::from([(name("refs/heads/next"), RefEffect::Set(oid(0x33)))]),
        retention: BTreeMap::from([
            (
                root(0xA0, RetentionClass::ReferencedByRef),
                RetentionEffect::Remove,
            ),
            (
                root(0xC0, RetentionClass::GraceTombstone),
                RetentionEffect::Add,
            ),
        ]),
        ..NetEffects::default()
    };

    let together = apply_net_effects(&basis(), &effects);

    let refs_only = apply_net_effects(
        &basis(),
        &NetEffects {
            refs: effects.refs.clone(),
            ..NetEffects::default()
        },
    );
    let both = apply_net_effects(
        &refs_only,
        &NetEffects {
            retention: effects.retention,
            ..NetEffects::default()
        },
    );

    assert_eq!(
        together, both,
        "applying a target-disjoint normal form at once must equal applying its parts in \
         sequence; if these differ, some effect observed another's result and the set was not \
         disjoint after all"
    );
    assert_ne!(
        together,
        basis(),
        "the composition must actually change something, or this compared the basis with itself"
    );
}
