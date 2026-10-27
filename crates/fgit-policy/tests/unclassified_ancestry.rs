//! Partial ref facts must never become a claimed fast-forward. These tests run
//! the actual compiler, canonical snapshot decoder and policy evaluators.

use fgit_codec::{DecodeLimits, harness::principal_snapshot_id};
use fgit_policy::{
    AuthenticationStrength, Decision, PolicyEvalRefusal, PolicyInputRoot, PolicyInstant,
    PolicySnapshot, PrincipalFacts, PrincipalKind, ProtectedRefRule, ProtectionBits, RefPattern,
    RefUpdateFact, RefUpdateKind, compile_and_seal, evaluate, evaluate_protected_ref, render_trace,
};
use fgit_types::{GitOid, GitOidSha1, PrincipalId, RefName};

fn input(kind: RefUpdateKind, force: bool) -> PolicyInputRoot {
    let previous =
        (kind != RefUpdateKind::Create).then_some(GitOid::Sha1(GitOidSha1::from_bytes([1; 20])));
    let next =
        (kind != RefUpdateKind::Delete).then_some(GitOid::Sha1(GitOidSha1::from_bytes([2; 20])));
    PolicyInputRoot::try_new(
        PrincipalFacts::try_new(
            PrincipalId::from_bytes([7; 16]),
            principal_snapshot_id(),
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        )
        .unwrap(),
        vec![
            RefUpdateFact::try_new(
                RefName::try_new(b"refs/heads/main").unwrap(),
                previous,
                next,
                kind,
                force,
            )
            .unwrap(),
        ],
        &[],
        &[],
        PolicyInstant::from_seconds(17),
    )
    .unwrap()
}

#[test]
fn unknown_ancestry_cannot_satisfy_positive_negated_set_or_unreached_graph_conditions() {
    for predicate in [
        "ref.update == fast_forward",
        "not ref.update == fast_forward",
        "ref.update in { fast_forward, non_fast_forward }",
        "not ref.update in { fast_forward, non_fast_forward }",
        "ref.name matches \"refs/heads/other\" and ref.update == non_fast_forward",
    ] {
        let policy = compile_and_seal(&format!(
            "policy ancestry {{ rule gate {{ when {predicate} then allow }} default allow }}"
        ))
        .unwrap();
        for force in [false, true] {
            assert!(
                matches!(
                    evaluate(&policy, &input(RefUpdateKind::UnclassifiedUpdate, force)),
                    Err(PolicyEvalRefusal::AncestryUnavailable { .. })
                ),
                "{predicate}; force={force}"
            );
            assert!(
                evaluate(&policy, &input(RefUpdateKind::FastForward, force)).is_ok(),
                "verified twin: {predicate}"
            );
        }
    }
}

#[test]
fn deletion_only_policy_uses_unknown_update_honestly_and_still_denies_deletion() {
    let policy = compile_and_seal("policy deletion { rule protect { when ref.update == delete then deny \"protected\" } default allow }").unwrap();
    let result = evaluate(&policy, &input(RefUpdateKind::UnclassifiedUpdate, false)).unwrap();
    assert_eq!(result.decision(), Decision::Allow);
    let trace = render_trace(&result);
    assert!(trace.contains("update_unclassified"));
    assert!(!trace.contains("fast_forward"));
    assert_eq!(
        evaluate(&policy, &input(RefUpdateKind::Delete, false))
            .unwrap()
            .decision(),
        Decision::Deny
    );
}

#[test]
fn protected_ref_fast_forward_requirement_refuses_unknown_ancestry_and_accepts_verified_twin() {
    let mut rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    rule.flags = ProtectionBits::empty().with(ProtectionBits::REQUIRE_FAST_FORWARD);
    rule.min_authentication = None;
    rule.reviews = None;
    rule.checks = None;
    rule.max_commit_bytes = None;
    rule.durability = None;
    let name = RefName::try_new(b"refs/heads/main").unwrap();
    for force in [false, true] {
        let mut selected = rule.clone();
        if force {
            selected.flags = selected.flags.with(ProtectionBits::ALLOW_FORCE_PUSH);
        }
        let unknown = evaluate_protected_ref(
            &[selected.clone()],
            &input(RefUpdateKind::UnclassifiedUpdate, force),
            &name,
        );
        assert_eq!(unknown.decision, Decision::Deny);
        assert!(unknown.verdicts.iter().any(|verdict| matches!(
            verdict,
            fgit_policy::RequirementVerdict::Failed {
                check_name: "fast_forward_only",
                ..
            }
        )));
        let verified = evaluate_protected_ref(
            &[selected],
            &input(RefUpdateKind::FastForward, force),
            &name,
        );
        assert_eq!(verified.decision, Decision::Allow);
    }
}

#[test]
fn new_kind_preserves_old_code_points_and_round_trips_as_explicit_unknown() {
    for (kind, code) in [
        (RefUpdateKind::Create, 1),
        (RefUpdateKind::FastForward, 2),
        (RefUpdateKind::NonFastForward, 3),
        (RefUpdateKind::Delete, 4),
        (RefUpdateKind::UnclassifiedUpdate, 5),
    ] {
        assert_eq!(kind.code_point(), code);
        assert_eq!(RefUpdateKind::from_code_point(code), Some(kind));
    }
    let snapshot = compile_and_seal("policy explicit_unknown { rule need_facts { when ref.update == update_unclassified then deny \"ancestry is required\" } default allow }").unwrap();
    let decoded =
        PolicySnapshot::decode(&snapshot.encode().unwrap(), DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(
        evaluate(&decoded, &input(RefUpdateKind::UnclassifiedUpdate, false))
            .unwrap()
            .decision(),
        Decision::Deny
    );
    assert_eq!(
        evaluate(&decoded, &input(RefUpdateKind::FastForward, false))
            .unwrap()
            .decision(),
        Decision::Allow
    );
}

#[test]
fn unknown_update_requires_both_native_endpoints() {
    let name = RefName::try_new(b"refs/heads/main").unwrap();
    let oid = GitOid::Sha1(GitOidSha1::from_bytes([1; 20]));
    assert!(
        RefUpdateFact::try_new(
            name.clone(),
            None,
            Some(oid),
            RefUpdateKind::UnclassifiedUpdate,
            false
        )
        .is_err()
    );
    assert!(
        RefUpdateFact::try_new(
            name.clone(),
            Some(oid),
            None,
            RefUpdateKind::UnclassifiedUpdate,
            false
        )
        .is_err()
    );
    RefUpdateFact::try_new(
        name,
        Some(oid),
        Some(oid),
        RefUpdateKind::UnclassifiedUpdate,
        false,
    )
    .unwrap();
}
