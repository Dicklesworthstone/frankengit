//! Section 33.4's forbidden-decision negatives, with their permitted twins.
//!
//! A refusal test on its own proves nothing: a `resolve` that refused
//! everything would pass every negative case here and be useless. So each
//! forbidden target is paired against permitted targets that must still
//! resolve, and the exhaustiveness tests pin both closed sets so a sixth
//! forbidden target cannot be added without a case.

use fgit_statistics::authority::{
    AdmissibleShape, AdvisoryDecision, DecisionRefusal, EffectClass, ForbiddenTarget,
    ProposedTarget, resolve,
};

// -------------------------------------------------- the structural half

#[test]
fn no_advisory_decision_affects_canonical_state() {
    // The primary enforcement, stated as a test so it is visible rather than
    // merely true. `AdvisoryDecision` has no variant that could reach
    // `CanonicalStateAffecting`; this walks every variant and proves it.
    for decision in AdvisoryDecision::ALL {
        assert_ne!(
            decision.effect_class(),
            EffectClass::CanonicalStateAffecting,
            "{decision:?} classifies as canonical-state-affecting, which no permitted decision may \
             ever be: section 33 forbids adaptive control over canonical state"
        );
    }

    // The absence half. Without it the loop above is satisfied by an
    // `effect_class` that returns one constant, which would prove nothing about
    // the classification and would hide a genuine misclassification later.
    let classes: Vec<EffectClass> = AdvisoryDecision::ALL
        .iter()
        .map(|decision| decision.effect_class())
        .collect();
    assert!(
        classes.contains(&EffectClass::AnswerPreservingPhysical),
        "no decision classifies as answer-preserving, so effect_class is not discriminating"
    );
    assert!(
        classes.contains(&EffectClass::AnswerAffectingExecution),
        "no decision classifies as answer-affecting-execution, so effect_class is not \
         discriminating"
    );
}

#[test]
fn the_permitted_decision_set_is_closed_at_four() {
    // Pins the set. A fifth variant added without review would change what a
    // statistical mechanism is allowed to decide, which is a constitutional
    // change and not a refactor.
    assert_eq!(
        AdvisoryDecision::ALL.len(),
        4,
        "the permitted decision set grew; adding a decision a controller may make is a \
         constitutional question, not a convenience"
    );
    assert_eq!(ProposedTarget::PERMITTED.len(), AdvisoryDecision::ALL.len());
}

// -------------------------------------------------- the refusal half

#[test]
fn every_forbidden_target_is_refused_by_name() {
    // One case per section 33.4 target. Named individually rather than as a set
    // so a `resolve` that refused only three of the five cannot pass.
    for target in ForbiddenTarget::ALL {
        let outcome = resolve(ProposedTarget::Forbidden(target));
        assert_eq!(
            outcome,
            Err(DecisionRefusal::ForbiddenTarget { target }),
            "{target:?} must be refused: a statistical mechanism with authority over it can make \
             the system unfalsifiable in a way no downstream check recovers from"
        );

        // The reason travels with the refusal, so a caller's own evidence
        // records why rather than only that.
        let refusal = outcome.expect_err("refused");
        assert!(
            !refusal.reason().is_empty(),
            "{target:?} refused without a reason"
        );
        assert_eq!(refusal.reason(), target.reason());
    }
}

#[test]
fn the_forbidden_set_is_exhaustive_at_five() {
    assert_eq!(
        ForbiddenTarget::ALL.len(),
        5,
        "section 33.4 names identity, authorization, retention, deletion and ordering; a target \
         missing from ALL would never be walked by the refusal test above"
    );

    // Every reason is distinct: a copy-pasted reason would make two refusals
    // indistinguishable in an evidence record.
    let mut reasons: Vec<&str> = ForbiddenTarget::ALL
        .iter()
        .map(|target| target.reason())
        .collect();
    reasons.sort_unstable();
    let before = reasons.len();
    reasons.dedup();
    assert_eq!(
        before,
        reasons.len(),
        "two forbidden targets share a reason"
    );
}

#[test]
fn every_permitted_target_still_resolves() {
    // The permitted twin for the whole refusal half. Without this, a `resolve`
    // that returned Err unconditionally would satisfy every test above.
    let expected = [
        (ProposedTarget::RetryBackoff, AdmissibleShape::RetryBackoff),
        (ProposedTarget::BatchSize, AdmissibleShape::BatchSize),
        (ProposedTarget::ProbeRate, AdmissibleShape::ProbeRate),
        (
            ProposedTarget::PlanPreference,
            AdmissibleShape::PlanPreference,
        ),
    ];
    for (target, shape) in expected {
        assert_eq!(
            resolve(target),
            Ok(shape),
            "{target:?} is permitted and must resolve, or the refusals above are a blanket denial"
        );
    }

    // And every permitted target listed in PERMITTED is covered by the table.
    for target in ProposedTarget::PERMITTED {
        assert!(
            expected.iter().any(|(listed, _)| *listed == target),
            "{target:?} is in PERMITTED but has no case here"
        );
        assert!(resolve(target).is_ok());
    }
}

#[test]
fn resolving_a_permitted_target_does_not_produce_a_decision() {
    // A subtle one worth pinning. `resolve` returns the *shape* a controller may
    // produce, not a decision. If it returned a constructed AdvisoryDecision,
    // the authority boundary would be handing out values that no mechanism
    // computed -- a default dressed as an adaptive choice, which is exactly the
    // silent-fallback shape section 3.1 forbids.
    let shape = resolve(ProposedTarget::RetryBackoff).expect("permitted");
    assert_eq!(shape, AdmissibleShape::RetryBackoff);

    // The value still has to come from somewhere else; the shapes carry none.
    let decision = AdvisoryDecision::RetryBackoff { micros: 2_500 };
    assert_eq!(
        decision.effect_class(),
        EffectClass::AnswerAffectingExecution
    );
}
