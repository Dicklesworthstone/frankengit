#![forbid(unsafe_code)]

//! frankengit-xqhp: `AGENT_PROTOCOL.md` §4.3 — a workspace never silently
//! floats, and evidence checked before a refresh does not vouch for the state
//! after it.
//!
//! The central property is the last clause of §4.3: *"The evidence record
//! distinguishes checks performed before and after refresh."* Everything here
//! drives that distinction through the publication policy, because a
//! distinction the policy does not act on is decoration.

use fgit_agent::{
    EccPolicy, EccRefusal, EvidenceCarryingChange, EvidenceClass, EvidenceRecordRef, PartyFacts,
    RefreshReceipt, RefreshRelation, RefreshSide, RequirementDisposition, VerifierAttestation,
};

const fn facts(base: u128) -> PartyFacts {
    PartyFacts {
        workspace: Some(base),
        credentials: Some(base + 1),
        model_harness: Some(base + 2),
        context: Some(base + 3),
        oracle: Some(base + 4),
        sponsor: Some(base + 5),
        human: Some(base + 6),
    }
}

fn change(
    evidence: Vec<EvidenceRecordRef>,
    refreshed: Option<RefreshReceipt>,
) -> EvidenceCarryingChange {
    EvidenceCarryingChange {
        intent_run: 0x77,
        producer: facts(0x10),
        evidence,
        requirement_dispositions: vec![Some(RequirementDisposition::SatisfiedWithEvidence)],
        non_claims: vec![],
        verifiers: vec![VerifierAttestation {
            verifier: 0x96,
            facts: facts(0x20),
            upheld: true,
        }],
        refreshed_authority: refreshed,
    }
}

const fn record(class: EvidenceClass, side: Option<RefreshSide>) -> EvidenceRecordRef {
    EvidenceRecordRef {
        class,
        artifact: 0xd1,
        refresh_side: side,
    }
}

const fn receipt(relation: RefreshRelation, from_base: u128, to_base: u128) -> RefreshReceipt {
    RefreshReceipt {
        relation,
        from_base,
        to_base,
    }
}

fn requires_executed() -> EccPolicy {
    EccPolicy {
        required_classes: vec![EvidenceClass::Executed],
        ..EccPolicy::default()
    }
}

/// `ALL` must name every relation §4.3 lists.
///
/// Pinned against the specification rather than against the enum, and kept in
/// the same file as the tests that iterate it: a loop driven from `ALL` covers
/// a new relation automatically and silently *stops* covering a deleted one.
#[test]
fn all_names_every_relation_the_spec_lists() {
    assert_eq!(
        RefreshRelation::ALL.len(),
        5,
        "AGENT_PROTOCOL.md §4.3 lists five relations: FastForwarded, \
         RebasedByIntentReplay, RebasedByStructuredPatch, MergedByDeclaredProof, \
         ConflictRefused",
    );

    let labels: std::collections::BTreeSet<&str> =
        RefreshRelation::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(labels.len(), 5, "relation labels must not collide");

    let codes: std::collections::BTreeSet<u16> = RefreshRelation::ALL
        .iter()
        .map(|r| r.code_point())
        .collect();
    assert_eq!(codes.len(), 5, "relation code points must not collide");

    for relation in RefreshRelation::ALL {
        assert_eq!(
            RefreshRelation::from_code_point(relation.code_point()),
            Some(*relation),
            "{relation} must round-trip through its code point",
        );
    }
    assert_eq!(RefreshRelation::from_code_point(0), None);
    assert_eq!(RefreshRelation::from_code_point(6), None);
}

/// Exactly one of the five means the workspace did NOT advance.
///
/// Driven from `ALL` so a sixth relation forces a decision here rather than
/// defaulting into whichever arm the author happened to write last.
#[test]
fn conflict_refused_is_the_only_relation_that_does_not_advance() {
    let advancing: Vec<RefreshRelation> = RefreshRelation::ALL
        .iter()
        .copied()
        .filter(|relation| relation.advanced_the_workspace())
        .collect();

    assert_eq!(
        advancing,
        vec![
            RefreshRelation::FastForwarded,
            RefreshRelation::RebasedByIntentReplay,
            RefreshRelation::RebasedByStructuredPatch,
            RefreshRelation::MergedByDeclaredProof,
        ],
    );
    assert!(!RefreshRelation::ConflictRefused.advanced_the_workspace());
}

/// A policy that requires a receipt refuses a bundle without one.
#[test]
fn a_policy_requiring_a_refresh_receipt_refuses_a_bundle_without_one() {
    let policy = EccPolicy {
        requires_refreshed_authority: true,
        ..EccPolicy::default()
    };

    assert_eq!(
        change(vec![], None).evaluate(&policy),
        Err(EccRefusal::MissingRefreshReceipt)
    );

    // Permitted twin: a bundle carrying one is accepted at the same shape.
    let refreshed = change(
        vec![],
        Some(receipt(RefreshRelation::FastForwarded, 0xba5e, 0xba5f)),
    );
    assert!(refreshed.evaluate(&policy).is_ok());
}

/// `ConflictRefused` is a valid receipt but not a completed refresh.
///
/// The two policy switches are separate on purpose: a policy that wants the
/// refresh *recorded* is satisfied by a refusal, and one that needs the
/// workspace actually on the new base is not. If a single flag covered both,
/// one of those two policies would be unexpressible.
#[test]
fn a_refused_conflict_satisfies_recording_but_not_completion() {
    let refused = change(
        vec![],
        Some(receipt(RefreshRelation::ConflictRefused, 0xba5e, 0xba5f)),
    );

    // Recorded: accepted.
    assert!(
        refused
            .evaluate(&EccPolicy {
                requires_refreshed_authority: true,
                ..EccPolicy::default()
            })
            .is_ok(),
    );

    // Completed: refused, and the relation is named so the reader learns how.
    let demands_completion = EccPolicy {
        requires_refreshed_authority: true,
        requires_completed_refresh: true,
        ..EccPolicy::default()
    };
    assert_eq!(
        refused.evaluate(&demands_completion),
        Err(EccRefusal::RefreshDidNotComplete {
            relation: RefreshRelation::ConflictRefused
        })
    );

    // Permitted twin: each of the other four satisfies the same policy, so the
    // refusal is about the outcome and not about requiring completion at all.
    for relation in RefreshRelation::ALL
        .iter()
        .filter(|relation| relation.advanced_the_workspace())
    {
        let advanced = change(vec![], Some(receipt(*relation, 0xba5e, 0xba5f)));
        assert!(
            advanced.evaluate(&demands_completion).is_ok(),
            "{relation} completed the refresh and must be accepted",
        );
    }
}

/// §4.3's final clause: a pre-refresh check does not cover the post-refresh
/// state, and an UNSTATED side fails closed alongside it.
///
/// The unstated case is the one worth having. A record that never said when it
/// was checked is the easiest thing in the world to treat as current, and doing
/// so is how absent evidence becomes the permissive answer — the same defect
/// 9pdo fixed for independence dimensions, in a different field.
#[test]
fn evidence_checked_before_a_refresh_does_not_cover_the_state_after_it() {
    let moved = Some(receipt(
        RefreshRelation::RebasedByIntentReplay,
        0xba5e,
        0xba5f,
    ));

    for stale_side in [None, Some(RefreshSide::BeforeRefresh)] {
        let change = change(vec![record(EvidenceClass::Executed, stale_side)], moved);
        assert_eq!(
            change.evaluate(&requires_executed()),
            Err(EccRefusal::EvidenceNotRevalidatedAfterRefresh {
                required: EvidenceClass::Executed
            }),
            "side {stale_side:?} must not vouch for the post-refresh state",
        );
    }

    // Permitted twin: the same bundle with the check re-run after the refresh.
    let revalidated = change(
        vec![record(
            EvidenceClass::Executed,
            Some(RefreshSide::AfterRefresh),
        )],
        moved,
    );
    assert!(revalidated.evaluate(&requires_executed()).is_ok());

    // And a bundle carrying BOTH is fine — the stale record is not poison, it
    // simply does not discharge the requirement on its own.
    let both = change(
        vec![
            record(EvidenceClass::Executed, Some(RefreshSide::BeforeRefresh)),
            record(EvidenceClass::Executed, Some(RefreshSide::AfterRefresh)),
        ],
        moved,
    );
    assert!(both.evaluate(&requires_executed()).is_ok());
}

/// Re-validation is owed only when the basis actually moved.
///
/// Without this the rule would be over-strict, and over-strictness here has a
/// specific cost: it would train callers to stamp `AfterRefresh` on everything
/// to get past a demand that was never justified, which destroys the value of
/// the field. A refresh whose two bases are equal changed nothing.
#[test]
fn a_refresh_that_did_not_move_the_basis_owes_no_revalidation() {
    let stale = || {
        vec![record(
            EvidenceClass::Executed,
            Some(RefreshSide::BeforeRefresh),
        )]
    };

    let unmoved = Some(receipt(RefreshRelation::FastForwarded, 0xba5e, 0xba5e));
    assert!(
        change(stale(), unmoved)
            .evaluate(&requires_executed())
            .is_ok()
    );

    // The twin that shows the check is live: the ONLY difference is one byte of
    // the target basis, and the very same bundle is then refused.
    let moved = Some(receipt(RefreshRelation::FastForwarded, 0xba5e, 0xba5f));
    assert_eq!(
        change(stale(), moved).evaluate(&requires_executed()),
        Err(EccRefusal::EvidenceNotRevalidatedAfterRefresh {
            required: EvidenceClass::Executed
        })
    );
}

/// With no refresh at all, the side is simply irrelevant.
#[test]
fn without_a_refresh_the_side_does_not_matter() {
    for side in [
        None,
        Some(RefreshSide::BeforeRefresh),
        Some(RefreshSide::AfterRefresh),
    ] {
        let change = change(vec![record(EvidenceClass::Executed, side)], None);
        assert!(
            change.evaluate(&requires_executed()).is_ok(),
            "side {side:?} must be accepted when nothing was refreshed",
        );
    }
}

/// The receipt binds both bases, so a reader can check where the refresh landed.
#[test]
fn a_receipt_reports_whether_it_moved_and_whether_it_advanced() {
    let moved = receipt(RefreshRelation::MergedByDeclaredProof, 0xba5e, 0xba5f);
    assert!(moved.changed_basis());
    assert!(moved.advanced());

    let unmoved = receipt(RefreshRelation::FastForwarded, 0xba5e, 0xba5e);
    assert!(!unmoved.changed_basis());
    assert!(unmoved.advanced());

    // A refused conflict still records the target it would have moved to, so
    // "did not advance" and "no target recorded" stay distinguishable.
    let refused = receipt(RefreshRelation::ConflictRefused, 0xba5e, 0xba5f);
    assert!(!refused.advanced());
    assert!(refused.changed_basis());
}

/// Both sides are structurally distinct and round-trip through their codes.
#[test]
fn refresh_sides_are_distinct_and_round_trip() {
    assert_eq!(RefreshSide::ALL.len(), 2);
    for side in RefreshSide::ALL {
        assert_eq!(RefreshSide::from_code_point(side.code_point()), Some(*side));
    }
    assert_ne!(
        RefreshSide::BeforeRefresh.as_str(),
        RefreshSide::AfterRefresh.as_str()
    );
    assert_eq!(RefreshSide::from_code_point(0), None);
    assert_eq!(RefreshSide::from_code_point(3), None);
}
