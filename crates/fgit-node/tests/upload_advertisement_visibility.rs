#![forbid(unsafe_code)]
//! Fetch-advertisement visibility filtering (`frankengit-jkbo`, acceptance line 3).
//!
//! The receive path got this on `frankengit-eeb8`; the fetch path had no
//! visibility filtering at all until now. The property is the same one — a ref
//! hidden from a principal never reaches that principal's advertisement — but
//! the fetch view has two decisions the receive view does not, and both were
//! computed over the *unfiltered* ref map:
//!
//! * `HEAD` resolution, which can advertise a hidden ref's object id or refuse
//!   in a way that names the target; and
//! * the emptiness test that distinguishes "unborn" from "target missing",
//!   which is what makes the refusal reachable at all.
//!
//! That second one is why the obvious fix is not enough, and it is the reason
//! these tests assert *indistinguishability* rather than *absence*: suppressing
//! a refusal's message still leaves the two cases differing in whether a refusal
//! happened. Credit to `BoldIbis` for the observation and for the test shape.

use std::collections::BTreeMap;

use fgit_admission::AdmissionSnapshot;
use fgit_node::AdmissionUploadPackRepository;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{UploadPackRepository, WireLimits};

fn oid(nibble: char) -> GitOid {
    GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        &std::iter::repeat_n(nibble, 40).collect::<String>(),
    )
    .expect("a fixed 40-nibble SHA-1 object id")
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

/// A snapshot with the given refs, hide rules, and `HEAD` symref target.
fn snapshot(
    names: &[(&[u8], char)],
    rules: &[&[u8]],
    head_target: Option<&[u8]>,
) -> AdmissionSnapshot {
    let mut refs = BTreeMap::new();
    for (name, nibble) in names {
        refs.insert(
            RefName::try_new(name).expect("a fixed valid ref name"),
            oid(*nibble),
        );
    }
    AdmissionSnapshot {
        refs,
        head_target: head_target
            .map(|target| RefName::try_new(target).expect("a fixed valid ref name")),
        hidden_refs: hiding(rules),
        ..AdmissionSnapshot::default()
    }
}

fn advertised(snapshot: &AdmissionSnapshot, limits: &WireLimits) -> Vec<Vec<u8>> {
    AdmissionUploadPackRepository::from_snapshot(snapshot, GitHashAlgorithm::Sha1, limits)
        .expect("a bounded SHA-1 snapshot becomes an upload-pack view")
        .advertised_refs()
        .iter()
        .map(|reference| reference.name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// The property, and its permitted twin
// ---------------------------------------------------------------------------

#[test]
fn a_hidden_ref_is_absent_from_the_fetch_advertisement() {
    let names = advertised(
        &snapshot(
            &[(b"refs/heads/main", '1'), (b"refs/private/secret", '2')],
            &[b"refs/private"],
            Some(b"refs/heads/main"),
        ),
        &WireLimits::default(),
    );

    assert_eq!(
        names,
        vec![b"HEAD".to_vec(), b"refs/heads/main".to_vec()],
        "a hidden ref must not appear in the advertisement a principal receives"
    );
}

#[test]
fn the_permitted_twin_an_empty_policy_advertises_every_canonical_ref() {
    // Without this the assertion above is satisfied by a view that advertises
    // nothing at all.
    let names = advertised(
        &snapshot(
            &[(b"refs/heads/main", '1'), (b"refs/private/secret", '2')],
            &[],
            Some(b"refs/heads/main"),
        ),
        &WireLimits::default(),
    );

    assert_eq!(
        names,
        vec![
            b"HEAD".to_vec(),
            b"refs/heads/main".to_vec(),
            b"refs/private/secret".to_vec(),
        ],
        "an empty policy hides nothing, so every canonical ref is advertised"
    );
}

// ---------------------------------------------------------------------------
// Indistinguishability, which is stronger than absence
// ---------------------------------------------------------------------------

#[test]
fn a_repository_of_only_hidden_refs_is_byte_identical_to_an_unborn_one() {
    // THE INDISTINGUISHABILITY TEST, and the reason it is not two separate
    // "produces no error" assertions: those pass even when the two paths differ
    // in some other observable, which is exactly what happens if the refusal is
    // silenced without moving the emptiness test onto the visible set.
    //
    // Left: every ref exists but is hidden from this principal, and HEAD points
    // at one of them. Right: the repository genuinely has no refs and HEAD is
    // unborn. These must be the same answer, byte for byte.
    let all_hidden = advertised(
        &snapshot(
            &[(b"refs/private/secret", '2')],
            &[b"refs/private"],
            Some(b"refs/private/secret"),
        ),
        &WireLimits::default(),
    );
    let genuinely_unborn = advertised(
        &snapshot(&[], &[], Some(b"refs/heads/main")),
        &WireLimits::default(),
    );

    assert_eq!(
        all_hidden, genuinely_unborn,
        "a repository whose refs are all hidden must be indistinguishable from \
         an unborn one; if these differ, the difference IS the oracle"
    );
    assert!(
        all_hidden.is_empty(),
        "and the shared answer must be the empty advertisement, not some third thing"
    );
}

#[test]
fn a_hidden_head_target_is_not_advertised_and_is_not_refused() {
    // Stated separately from the pair above because the two failure modes are
    // different and only one of them is a refusal. Advertising HEAD here would
    // disclose the hidden ref's OBJECT ID, which is worse than disclosing that
    // it exists; refusing would name the target outright.
    let view = AdmissionUploadPackRepository::from_snapshot(
        &snapshot(
            &[(b"refs/heads/main", '1'), (b"refs/private/secret", '2')],
            &[b"refs/private"],
            Some(b"refs/private/secret"),
        ),
        GitHashAlgorithm::Sha1,
        &WireLimits::default(),
    )
    .expect("a hidden HEAD target must not refuse: the refusal would name it");

    let names: Vec<Vec<u8>> = view
        .advertised_refs()
        .iter()
        .map(|reference| reference.name.clone())
        .collect();
    assert_eq!(
        names,
        vec![b"refs/heads/main".to_vec()],
        "HEAD must be absent, and the visible ref must still be served"
    );
}

// ---------------------------------------------------------------------------
// The bound is decided over the visible set
// ---------------------------------------------------------------------------

#[test]
fn hidden_refs_do_not_consume_the_advertisement_bound() {
    // The count site. Three refs, two hidden, a limit of two: the principal sees
    // one ref plus HEAD, so this is admissible. An implementation that counts
    // over the raw map sees three plus HEAD and refuses — telling the principal
    // that refs it cannot see exist.
    let names = advertised(
        &snapshot(
            &[
                (b"refs/heads/main", '1'),
                (b"refs/private/a", '2'),
                (b"refs/private/b", '3'),
            ],
            &[b"refs/private"],
            Some(b"refs/heads/main"),
        ),
        &WireLimits {
            max_advertised_refs: 2,
            ..WireLimits::default()
        },
    );

    assert_eq!(
        names,
        vec![b"HEAD".to_vec(), b"refs/heads/main".to_vec()],
        "hidden refs must not consume a bound the principal cannot observe"
    );
}

#[test]
fn the_bound_still_refuses_when_the_visible_set_exceeds_it() {
    // The permitted twin of the bound test: the bound must remain a bound.
    let refusal = AdmissionUploadPackRepository::from_snapshot(
        &snapshot(
            &[
                (b"refs/heads/main", '1'),
                (b"refs/heads/other", '2'),
                (b"refs/heads/third", '3'),
            ],
            &[],
            Some(b"refs/heads/main"),
        ),
        GitHashAlgorithm::Sha1,
        &WireLimits {
            max_advertised_refs: 2,
            ..WireLimits::default()
        },
    )
    .expect_err("four advertised entries exceed a bound of two");

    assert!(
        format!("{refusal}").contains("advertised"),
        "the refusal must name the advertisement bound it enforced, got {refusal}"
    );
}
