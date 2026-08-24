//! A stale answer must never widen disclosure. `frankengit-fg036a`, line 2.
//!
//! Plan §22.5: "a stale projection never expands disclosure." The interesting
//! case is not that hidden refs are hidden — `filter_advertised_refs` already
//! does that — but that the policy applied is the one in force NOW, not the one
//! that was in force at the head being served.

use core::time::Duration;

use fgit_types::cell::{ReadLabel, ReadMode, ServingCell, StalenessBound, StalenessObservation};
use fgit_types::hint::{Hint, HintSource};
use fgit_types::identity::CellId;
use fgit_wire::stale_disclosure::{
    advertise_under_read_label, advertise_under_read_label_served_by,
};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{AdvertisedRef, AnyGitOid, GitObjectFormat, WireLimits};

const TIP: &str = "1111111111111111111111111111111111111111";

fn oid() -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, TIP).expect("fixture oid")
}

fn advertised(name: &str) -> AdvertisedRef {
    AdvertisedRef {
        oid: oid(),
        name: name.as_bytes().to_vec(),
    }
}

/// The policy in force at the older head: nothing hidden.
const fn permissive_policy() -> RefVisibility {
    RefVisibility::new()
}

/// The policy in force now: `refs/secret` was withdrawn since that head.
fn current_policy() -> RefVisibility {
    let mut policy = RefVisibility::new();
    policy
        .push_rule(b"refs/secret", &WireLimits::default())
        .expect("a valid hide rule");
    policy
}

fn served() -> Vec<AdvertisedRef> {
    vec![advertised("refs/heads/main"), advertised("refs/secret/key")]
}

fn names(refs: &[AdvertisedRef]) -> Vec<String> {
    refs.iter()
        .map(|reference| String::from_utf8_lossy(&reference.name).into_owned())
        .collect()
}

fn bounded_stale_label() -> ReadLabel {
    ReadLabel::bounded_stale(
        StalenessBound::new(Duration::from_secs(30), 5),
        StalenessObservation::new(Duration::from_secs(4), 2),
    )
    .expect("inside the bound")
}

#[test]
fn a_ref_withdrawn_since_the_served_head_is_not_advertised() {
    // The whole point. `refs/secret/key` was legitimately visible at the head
    // this answer comes from, and the cell still holds it. The current policy
    // hides it, so a bounded-stale answer must not carry it.
    let advertisement =
        advertise_under_read_label(&served(), &current_policy(), bounded_stale_label());

    assert_eq!(
        names(advertisement.refs()),
        vec!["refs/heads/main".to_owned()],
        "a stale projection must not re-advertise a ref the current policy withdrew"
    );

    // The permitted twin, and the reason this test is not vacuous: under the
    // policy that WAS in force at that head, the same served set discloses both.
    // So the filtering is doing work, and the thing being tested is WHICH policy
    // was applied, not merely that some filter ran.
    let under_old_policy =
        advertise_under_read_label(&served(), &permissive_policy(), bounded_stale_label());
    assert_eq!(
        names(under_old_policy.refs()),
        vec!["refs/heads/main".to_owned(), "refs/secret/key".to_owned()],
        "the served set really does contain the withdrawn ref"
    );
}

#[test]
fn the_gate_applies_to_every_mode_not_only_bounded_stale() {
    // Snapshot and offline answers are staler than bounded-stale ones, not
    // fresher. Exempting them would confuse how old the content is with who may
    // see it, and would leave the widest disclosure hole on the mode that makes
    // the weakest currentness claim.
    for label in [
        ReadLabel::current(),
        bounded_stale_label(),
        ReadLabel::snapshot(),
        ReadLabel::offline(),
    ] {
        let advertisement = advertise_under_read_label(&served(), &current_policy(), label);
        assert_eq!(
            names(advertisement.refs()),
            vec!["refs/heads/main".to_owned()],
            "{:?} must not disclose a withdrawn ref",
            label.mode()
        );
    }
}

#[test]
fn the_label_travels_with_the_refs_and_keeps_its_exact_bound() {
    // Acceptance line 2's two halves meet here: the answer is narrowed by the
    // current policy AND carries the bound it was served under. A caller that
    // received the refs without the label could present a stale answer as fresh.
    let label = bounded_stale_label();
    let advertisement = advertise_under_read_label(&served(), &current_policy(), label);

    let (refs, carried) = advertisement.into_parts();
    assert_eq!(names(&refs), vec!["refs/heads/main".to_owned()]);

    let ReadMode::BoundedStale(bound) = carried.mode() else {
        panic!("the label must survive the disclosure gate intact");
    };
    assert_eq!(bound.max_age(), Duration::from_secs(30));
    assert_eq!(bound.max_generation_lag(), 5);
    let observed = carried.observed().expect("a bounded-stale label measures");
    assert_eq!(observed.age(), Duration::from_secs(4));
    assert_eq!(observed.generation_lag(), 2);
    assert!(
        !carried.mode().claims_currentness(),
        "a narrowed stale answer is still a stale answer"
    );
}

#[test]
fn narrowing_never_adds_and_preserves_order() {
    // Two properties a filter can quietly lose. Order matters because the
    // advertisement is a wire sequence, and "never expands" has to mean the
    // output is a subsequence of the input rather than merely no longer.
    let advertisement =
        advertise_under_read_label(&served(), &current_policy(), bounded_stale_label());
    let output = names(advertisement.refs());
    let input = names(&served());

    assert!(
        output.len() <= input.len(),
        "disclosure must only ever narrow"
    );
    let mut remaining = input.iter();
    for disclosed in &output {
        assert!(
            remaining.any(|candidate| candidate == disclosed),
            "{disclosed} was advertised but is not a member of the served set, in order"
        );
    }
}

// ---------------------------------------------------------------------------
// Which cell answered. `frankengit-1egm`.
//
// The bead: in a multi-cell deployment nothing in a served answer said which
// cell produced it. These cases pin that the provenance travels with the
// advertisement, that its absence is a recorded fact rather than a gap, and --
// the property that keeps it honest -- that naming a cell changes nothing
// about what is disclosed.

#[test]
fn an_advertisement_records_the_cell_that_served_it() {
    let cell = Hint::new(CellId::from_bytes([0x0c; 16]), HintSource::LocalProjection);
    let labelled = advertise_under_read_label_served_by(
        &served(),
        &current_policy(),
        ReadLabel::current(),
        ServingCell::identified(cell),
    );
    assert_eq!(
        labelled.served_by().claimed().map(|hint| *hint.peek()),
        Some(CellId::from_bytes([0x0c; 16]))
    );
    assert!(labelled.served_by().is_identified());
}

#[test]
fn an_unnamed_cell_is_a_recorded_fact_not_a_gap() {
    // The permitted twin of the case above, and the reason ServingCell is an
    // enum rather than Option: a reader can tell "this deployment does not name
    // its cells" from "someone dropped it on the way".
    let labelled = advertise_under_read_label(&served(), &current_policy(), ReadLabel::current());
    assert_eq!(labelled.served_by(), ServingCell::Unidentified);
    assert!(labelled.served_by().claimed().is_none());
    assert!(!labelled.served_by().is_identified());
}

#[test]
fn naming_the_cell_changes_nothing_about_what_is_disclosed() {
    // The property that matters most here. Provenance is not authorization: if
    // attaching an identity could widen or narrow the ref set, a cell could
    // name itself into a disclosure. Same inputs, same policy, same label --
    // only the cell differs -- and the refs must be identical.
    let anonymous = advertise_under_read_label(&served(), &current_policy(), bounded_stale_label());
    let named = advertise_under_read_label_served_by(
        &served(),
        &current_policy(),
        bounded_stale_label(),
        ServingCell::identified(Hint::new(
            CellId::from_bytes([0xff; 16]),
            HintSource::Gossip,
        )),
    );

    assert_eq!(names(anonymous.refs()), names(named.refs()));
    assert_eq!(anonymous.label(), named.label());
    assert!(
        !names(named.refs())
            .iter()
            .any(|name| name.starts_with("refs/secret")),
        "a named cell must not see the withdrawn ref reappear"
    );
    // And the twin, so the equality above is not vacuous on an empty set: the
    // narrowing really did happen and really did keep the permitted ref.
    assert_eq!(names(named.refs()), vec!["refs/heads/main".to_owned()]);
}

#[test]
fn two_cells_serving_the_same_head_are_distinguishable_in_the_answer() {
    // The deployment case the bead is about, at the wire boundary: two cells,
    // one authority, identical bytes -- and now telling them apart is possible.
    let first = advertise_under_read_label_served_by(
        &served(),
        &current_policy(),
        ReadLabel::current(),
        ServingCell::identified(Hint::new(
            CellId::from_bytes([0x01; 16]),
            HintSource::LocalProjection,
        )),
    );
    let second = advertise_under_read_label_served_by(
        &served(),
        &current_policy(),
        ReadLabel::current(),
        ServingCell::identified(Hint::new(
            CellId::from_bytes([0x02; 16]),
            HintSource::LocalProjection,
        )),
    );

    assert_eq!(
        names(first.refs()),
        names(second.refs()),
        "one authority, so the answers agree"
    );
    assert_ne!(
        first.served_by(),
        second.served_by(),
        "and the provenance does not, which is the whole point of 1egm"
    );
}
