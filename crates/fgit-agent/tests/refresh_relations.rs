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
    EccPolicy, EccRefusal, EvidenceCarryingChange, EvidenceClass, EvidenceRecordRef,
    IndependenceDimension, PartyFacts, RefreshReceipt, RefreshRelation, RefreshSide,
    RequirementDisposition, VerifierAttestation,
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

/// The documented check order, pinned with a bundle that is wrong FOUR ways.
///
/// `evaluate`'s doc comment promises a fixed sequence — dispositions, then the
/// refresh gate, then evidence classes, then verifiers — "so a bundle wrong in
/// several ways reports the same refusal on every run". That is a determinism
/// guarantee, and until this test it was a sentence nothing checked.
///
/// Every other case in the crate is a SINGLE-FAULT probe: it makes one thing
/// wrong and asserts one refusal. A complete single-fault corpus is
/// structurally blind to a stage swap, because moving a stage cannot change
/// which refusal fires when only one stage can fire at all. The faults have to
/// overlap before the order becomes observable.
///
/// So this peels the bundle one fault at a time and asserts the refusal changes
/// in the documented sequence. Each step also proves the *previous* stage was
/// genuinely masking the next one, which is what makes it an ordering test
/// rather than four more single-fault assertions.
#[test]
fn a_bundle_wrong_several_ways_reports_the_stages_in_the_documented_order() {
    // Every field listed explicitly, with no `..default()`. Clippy pointed out
    // the spread was dead, and the exhaustive form is the better one to keep:
    // adding a field to `EccPolicy` will stop this test compiling until someone
    // decides where the new stage belongs in the order. A `..default()` would
    // have silently absorbed it and left the sequence below quietly incomplete
    // — the same way an `ALL`-driven loop silently shrinks.
    let policy = EccPolicy {
        required_classes: vec![EvidenceClass::Executed],
        required_independence: vec![IndependenceDimension::Oracle],
        requires_verifier: true,
        requires_refreshed_authority: true,
        requires_completed_refresh: true,
    };

    // Wrong four ways at once: a requirement with no disposition, no refresh
    // receipt, no Executed evidence, and no verifier.
    let mut change = change(vec![], None);
    change.requirement_dispositions = vec![None];
    change.verifiers = vec![];

    // 1. Dispositions first.
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::RequirementWithoutDisposition { requirement: 0 }),
        "the disposition check must run before everything else",
    );

    // 2. Fix only that, and the refresh gate is next — NOT the evidence check,
    //    even though the bundle has no Executed record either.
    change.requirement_dispositions = vec![Some(RequirementDisposition::SatisfiedWithEvidence)];
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::MissingRefreshReceipt),
        "the refresh gate must run before the evidence loop",
    );

    // 3. Supply a receipt that did not complete. Still the refresh gate, and
    //    still ahead of the missing evidence class.
    change.refreshed_authority = Some(receipt(RefreshRelation::ConflictRefused, 0xba5e, 0xba5f));
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::RefreshDidNotComplete {
            relation: RefreshRelation::ConflictRefused
        }),
        "completion is decided at the refresh gate, before evidence",
    );

    // 4. Let the refresh succeed and move the basis. Evidence is next.
    change.refreshed_authority = Some(receipt(
        RefreshRelation::RebasedByIntentReplay,
        0xba5e,
        0xba5f,
    ));
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::MissingEvidenceClass {
            required: EvidenceClass::Executed
        }),
        "the evidence loop must run before the verifier checks",
    );

    // 5. Add the class but only checked BEFORE the refresh — still the evidence
    //    stage, on its re-validation rule, and still ahead of the verifiers.
    change.evidence = vec![record(
        EvidenceClass::Executed,
        Some(RefreshSide::BeforeRefresh),
    )];
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::EvidenceNotRevalidatedAfterRefresh {
            required: EvidenceClass::Executed
        }),
        "re-validation is part of the evidence stage, not a later one",
    );

    // 6. Re-check it after the refresh, and only now do the verifiers speak.
    change.evidence = vec![record(
        EvidenceClass::Executed,
        Some(RefreshSide::AfterRefresh),
    )];
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::NoVerifierAttestation),
        "the verifier checks run last",
    );

    // 7. Permitted twin. With every fault repaired the same policy accepts, so
    //    the sequence above is six stages masking each other rather than a
    //    bundle that could never pass at all.
    change.verifiers = vec![VerifierAttestation {
        verifier: 0x96,
        facts: facts(0x20),
        upheld: true,
    }];
    let classifications = change
        .evaluate(&policy)
        .expect("every fault repaired, the bundle must publish");
    assert_eq!(classifications.len(), 1);
    assert!(classifications[0].is_independent_on(IndependenceDimension::Oracle));
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
