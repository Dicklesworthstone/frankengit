#![forbid(unsafe_code)]
//! Push-advertisement visibility filtering for the receive path
//! (`frankengit-eeb8` part (a)).
//!
//! The property under test is that a ref hidden from a principal never reaches
//! that principal's push advertisement, and — the half that is easy to lose —
//! that a ref the principal *may* see still does. A suite containing only the
//! refusal passes equally well against an implementation that advertises
//! nothing, so every hiding assertion here is paired with its permitted twin.
//!
//! The bound tests exist for a specific, non-obvious reason documented on
//! [`AdmissionReceivePackAdvertisement`]: if `max_advertised_refs` were applied
//! to the whole snapshot rather than to the visible subset, the resulting
//! `TooManyAdvertisedRefs` refusal would tell a principal that refs it cannot
//! see exist. The refusal itself becomes an enumeration oracle. Those two tests
//! are what stop that ordering being "simplified" back in.

use std::collections::BTreeMap;

use fgit_admission::AdmissionSnapshot;
use fgit_node::AdmissionReceivePackAdvertisement;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;

fn oid(nibble: char) -> GitOid {
    GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        &std::iter::repeat_n(nibble, 40).collect::<String>(),
    )
    .expect("a fixed 40-nibble SHA-1 object id")
}

fn snapshot_with(names: &[(&[u8], char)]) -> AdmissionSnapshot {
    let mut refs = BTreeMap::new();
    for (name, nibble) in names {
        refs.insert(
            RefName::try_new(name).expect("a fixed valid ref name"),
            oid(*nibble),
        );
    }
    AdmissionSnapshot {
        refs,
        ..AdmissionSnapshot::default()
    }
}

fn hiding(rules: &[&[u8]]) -> RefVisibility {
    let limits = WireLimits::default();
    let mut visibility = RefVisibility::new();
    for rule in rules {
        visibility
            .push_rule(rule, &limits)
            .expect("a fixed valid hide rule");
    }
    visibility
}

fn advertised(
    snapshot: &AdmissionSnapshot,
    visibility: &RefVisibility,
    limits: &WireLimits,
) -> Vec<Vec<u8>> {
    AdmissionReceivePackAdvertisement::from_snapshot(
        snapshot,
        visibility,
        GitHashAlgorithm::Sha1,
        limits,
    )
    .expect("a bounded SHA-1 snapshot becomes a push advertisement")
    .advertised_refs()
    .iter()
    .map(|reference| reference.name.clone())
    .collect()
}

// ---------------------------------------------------------------------------
// The property, and its permitted twin
// ---------------------------------------------------------------------------

#[test]
fn a_hidden_ref_is_absent_from_the_push_advertisement() {
    let snapshot = snapshot_with(&[(b"refs/heads/main", '1'), (b"refs/internal/secret", '2')]);

    let names = advertised(
        &snapshot,
        &hiding(&[b"refs/internal"]),
        &WireLimits::default(),
    );

    assert_eq!(
        names,
        vec![b"refs/heads/main".to_vec()],
        "a hidden ref must not appear in the advertisement a principal receives"
    );
}

#[test]
fn the_permitted_twin_an_empty_policy_advertises_every_canonical_ref() {
    // Without this the suite above is satisfied by an implementation that
    // advertises nothing at all.
    let snapshot = snapshot_with(&[(b"refs/heads/main", '1'), (b"refs/internal/secret", '2')]);

    let names = advertised(&snapshot, &RefVisibility::new(), &WireLimits::default());

    assert_eq!(
        names,
        vec![
            b"refs/heads/main".to_vec(),
            b"refs/internal/secret".to_vec(),
        ],
        "an empty policy hides nothing, so both canonical refs are advertised"
    );
}

#[test]
fn a_negation_rule_re_exposes_one_ref_under_a_hidden_prefix() {
    // Proves the filter consults the ordered policy rather than matching a
    // prefix once: `hides` is last-match-wins, so a later negation re-exposes.
    let snapshot = snapshot_with(&[
        (b"refs/internal/public", '1'),
        (b"refs/internal/secret", '2'),
    ]);

    let names = advertised(
        &snapshot,
        &hiding(&[b"refs/internal", b"!refs/internal/public"]),
        &WireLimits::default(),
    );

    assert_eq!(
        names,
        vec![b"refs/internal/public".to_vec()],
        "the negation must re-expose exactly the ref it names and no other"
    );
}

// ---------------------------------------------------------------------------
// The bound is evaluated on the VISIBLE count — the enumeration oracle
// ---------------------------------------------------------------------------

#[test]
fn hidden_refs_do_not_consume_the_advertisement_bound() {
    // THE ORACLE TEST. Three canonical refs, two of them hidden, and a limit of
    // one. The principal sees exactly one ref, so this must succeed.
    //
    // An implementation that checks `max_advertised_refs` against the whole
    // snapshot — which is what the upload-pack view correctly does, because it
    // hides nothing — refuses here with TooManyAdvertisedRefs. That refusal
    // would tell the principal that refs it cannot see exist, which is the
    // disclosure this type exists to prevent. Single variable: only the
    // visibility policy differs from the test below.
    let snapshot = snapshot_with(&[
        (b"refs/heads/main", '1'),
        (b"refs/internal/a", '2'),
        (b"refs/internal/b", '3'),
    ]);
    let limits = WireLimits {
        max_advertised_refs: 1,
        ..WireLimits::default()
    };

    let names = advertised(&snapshot, &hiding(&[b"refs/internal"]), &limits);

    assert_eq!(
        names,
        vec![b"refs/heads/main".to_vec()],
        "two hidden refs must not consume a bound the principal cannot observe"
    );
}

#[test]
fn the_bound_still_refuses_when_the_visible_set_exceeds_it() {
    // The permitted twin of the oracle test: the bound must still be a bound.
    // Same three refs and the same limit of one, but nothing is hidden, so the
    // visible set is three and the refusal is correct.
    let snapshot = snapshot_with(&[
        (b"refs/heads/main", '1'),
        (b"refs/internal/a", '2'),
        (b"refs/internal/b", '3'),
    ]);
    let limits = WireLimits {
        max_advertised_refs: 1,
        ..WireLimits::default()
    };

    let refusal = AdmissionReceivePackAdvertisement::from_snapshot(
        &snapshot,
        &RefVisibility::new(),
        GitHashAlgorithm::Sha1,
        &limits,
    )
    .expect_err("three visible refs exceed a bound of one");

    assert!(
        format!("{refusal}").contains("advertised"),
        "the refusal must name the advertisement bound it enforced, got {refusal}"
    );
}

#[test]
fn the_visible_set_at_exactly_the_bound_is_accepted() {
    // The inclusive boundary. Without this, an implementation refusing at
    // `visible >= limit` passes every test above.
    let snapshot = snapshot_with(&[(b"refs/heads/main", '1'), (b"refs/internal/a", '2')]);
    let limits = WireLimits {
        max_advertised_refs: 1,
        ..WireLimits::default()
    };

    let names = advertised(&snapshot, &hiding(&[b"refs/internal"]), &limits);

    assert_eq!(
        names.len(),
        1,
        "a visible set exactly at the bound is admissible, not one over it"
    );
}

// ---------------------------------------------------------------------------
// No refusal may be caused by a hidden ref
// ---------------------------------------------------------------------------

fn foreign_oid() -> GitOid {
    GitOid::from_hex(
        GitHashAlgorithm::Sha256,
        &std::iter::repeat_n('a', 64).collect::<String>(),
    )
    .expect("a fixed 64-nibble SHA-256 object id")
}

fn snapshot_with_foreign(hidden: bool) -> AdmissionSnapshot {
    let mut refs = BTreeMap::new();
    refs.insert(
        RefName::try_new(b"refs/heads/main").expect("a fixed valid ref name"),
        oid('1'),
    );
    let foreign_name: &[u8] = if hidden {
        b"refs/internal/foreign"
    } else {
        b"refs/heads/foreign"
    };
    refs.insert(
        RefName::try_new(foreign_name).expect("a fixed valid ref name"),
        foreign_oid(),
    );
    AdmissionSnapshot {
        refs,
        ..AdmissionSnapshot::default()
    }
}

#[test]
fn a_hidden_ref_with_a_foreign_object_format_causes_no_refusal() {
    // THE INVARIANT: no refusal may be caused by a ref the principal cannot see.
    // The object-format check runs only over the visible set for exactly this
    // reason. If it ran before the visibility filter, a principal could learn a
    // hidden ref exists by receiving ObjectFormatMismatch for it — the refusal
    // becomes an oracle, the same way an unfiltered bound would.
    let names = advertised(
        &snapshot_with_foreign(true),
        &hiding(&[b"refs/internal"]),
        &WireLimits::default(),
    );

    assert_eq!(
        names,
        vec![b"refs/heads/main".to_vec()],
        "a hidden ref's object format must not be inspected, let alone refused"
    );
}

#[test]
fn the_permitted_twin_a_visible_ref_with_a_foreign_format_still_refuses() {
    // Without this, the test above is satisfied by dropping the format check
    // altogether. The same foreign oid under a VISIBLE name must still refuse:
    // the check is skipped for hidden refs, not disabled.
    let refusal = AdmissionReceivePackAdvertisement::from_snapshot(
        &snapshot_with_foreign(false),
        &hiding(&[b"refs/internal"]),
        GitHashAlgorithm::Sha1,
        &WireLimits::default(),
    )
    .expect_err("a visible ref in a foreign identity domain is not advertisable");

    assert!(
        format!("{refusal}").contains("format"),
        "the refusal must name the object-format mismatch it found, got {refusal}"
    );
}
