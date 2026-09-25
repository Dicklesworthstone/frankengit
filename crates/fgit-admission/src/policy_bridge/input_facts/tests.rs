#![forbid(unsafe_code)]

use super::*;
use crate::policy_bridge::{
    InMemoryPolicySnapshots, SubjectCodeMap, build_input_root, default_principal_snapshot_id,
    evaluate_effects_protection, evaluate_protection, evaluate_receive_pack_protection,
};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_policy::program::{Compare, TextLiteral};
use fgit_policy::{AuthenticationStrength, PolicyInstant, PrincipalFacts, PrincipalKind};
use fgit_reference::effect::RefEffect;
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefName};
use std::collections::BTreeMap;

fn check(predicate: &Predicate, force_known: bool) -> Result<(), FactCheckRefusal> {
    let mut remaining = 1_024;
    check_predicate(predicate, force_known, 0, &mut remaining)
}

fn missing(fact: MissingAdmissionFact) -> Result<(), FactCheckRefusal> {
    Err(FactCheckRefusal::Missing(fact))
}

#[test]
fn every_actor_selector_is_unavailable_even_under_negation() {
    for selector in [Selector::ActorId, Selector::ActorSnapshot] {
        for predicate in [
            Predicate::TextEquals {
                selector,
                value: TextLiteral::new("claimed"),
            },
            Predicate::TextIn {
                selector,
                values: vec![TextLiteral::new("claimed")],
            },
        ] {
            assert_eq!(
                check(&predicate, true),
                missing(MissingAdmissionFact::AuthenticatedPrincipal)
            );
            assert_eq!(
                check(&Predicate::Not(Box::new(predicate)), true),
                missing(MissingAdmissionFact::AuthenticatedPrincipal)
            );
        }
    }
    for kind in PrincipalKind::ALL {
        for predicate in [
            Predicate::PrincipalKindEquals(kind),
            Predicate::PrincipalKindIn(vec![kind]),
        ] {
            assert_eq!(
                check(&predicate, true),
                missing(MissingAdmissionFact::AuthenticatedPrincipal)
            );
        }
    }
    for strength in AuthenticationStrength::ALL {
        let predicate = Predicate::AuthenticationCompare {
            operator: Compare::GreaterOrEqual,
            value: strength,
        };
        assert_eq!(
            check(&predicate, true),
            missing(MissingAdmissionFact::AuthenticatedPrincipal)
        );
    }
    for selector in [Selector::ActorTeams, Selector::ActorCapabilities] {
        let predicate = Predicate::LabelContains {
            selector,
            label: fgit_policy::LabelName::try_new(b"maintainer").unwrap(),
        };
        assert_eq!(
            check(&predicate, true),
            missing(MissingAdmissionFact::AuthenticatedPrincipal)
        );
    }
    let reference = Predicate::TextEquals {
        selector: Selector::RefName,
        value: TextLiteral::new("refs/heads/main"),
    };
    assert_eq!(check(&reference, true), Ok(()));
}

#[test]
fn short_circuit_and_negation_cannot_turn_missing_facts_into_permission() {
    let evidence =
        Predicate::EvidenceAccepted(fgit_policy::EvidenceKind::try_new(b"review").unwrap());
    for predicate in [
        evidence.clone(),
        Predicate::Not(Box::new(evidence.clone())),
        Predicate::Any(vec![Predicate::Always, evidence.clone()]),
        Predicate::All(vec![Predicate::Never, evidence]),
    ] {
        assert_eq!(
            check(&predicate, true),
            missing(MissingAdmissionFact::Evidence)
        );
    }
    let aggregate = Predicate::AggregateCompare {
        name: fgit_policy::AggregateName::try_new(b"findings").unwrap(),
        operator: Compare::Equal,
        value: 0,
    };
    assert_eq!(
        check(&aggregate, true),
        missing(MissingAdmissionFact::Aggregates)
    );
    assert_eq!(check(&Predicate::Not(Box::new(Predicate::Never)), true), Ok(()));
}

#[test]
fn ancestry_is_not_the_force_flag_and_effects_have_no_force_intent() {
    for kind in RefUpdateKind::ALL {
        for predicate in [
            Predicate::UpdateKindEquals(kind),
            Predicate::UpdateKindIn(vec![kind]),
        ] {
            let expected = match kind {
                RefUpdateKind::Create | RefUpdateKind::Delete => Ok(()),
                RefUpdateKind::FastForward | RefUpdateKind::NonFastForward => {
                    missing(MissingAdmissionFact::VerifiedAncestry)
                }
            };
            assert_eq!(check(&predicate, true), expected);
            assert_eq!(check(&predicate, false), expected);
        }
    }
    assert_eq!(check(&Predicate::ForceRequested, true), Ok(()));
    assert_eq!(
        check(&Predicate::ForceRequested, false),
        missing(MissingAdmissionFact::ForceIntent)
    );
}

#[test]
fn structural_budgets_have_exact_permitted_twins() {
    let mut predicate = Predicate::Always;
    for _ in 0..MAX_PREDICATE_DEPTH {
        predicate = Predicate::Not(Box::new(predicate));
    }
    assert_eq!(check(&predicate, true), Ok(()));
    predicate = Predicate::Not(Box::new(predicate));
    assert_eq!(check(&predicate, true), Err(FactCheckRefusal::TooComplex));
    let wide = Predicate::All(vec![Predicate::Always; 8]);
    let mut exact = 9;
    assert_eq!(check_predicate(&wide, true, 0, &mut exact), Ok(()));
    assert_eq!(exact, 0);
    let mut insufficient = 8;
    assert_eq!(
        check_predicate(&wide, true, 0, &mut insufficient),
        Err(FactCheckRefusal::TooComplex)
    );
}

#[test]
fn legacy_adapters_refuse_fabricated_mfa_but_complete_facts_evaluate_normally() {
    let snapshot = fgit_policy::compile_and_seal(
        "policy mfa { rule require_mfa { when actor.authentication >= multi_factor then allow } default deny \"MFA required\" }",
    )
    .unwrap();
    let mut source = InMemoryPolicySnapshots::new();
    let id = source.pin(snapshot);
    let name = RefName::try_new(b"refs/heads/topic").unwrap();
    let principal_id = PrincipalId::from_bytes([7; 16]);
    let principal_snapshot = default_principal_snapshot_id();
    let instant = PolicyInstant::from_seconds(100);
    for (old, new) in [
        (
            GitOid::Sha1(GitOidSha1::from_bytes([1; 20])),
            GitOid::Sha1(GitOidSha1::from_bytes([2; 20])),
        ),
        (
            GitOid::Sha256(GitOidSha256::from_bytes([1; 32])),
            GitOid::Sha256(GitOidSha256::from_bytes([2; 32])),
        ),
    ] {
        let refs = BTreeMap::from([(name.clone(), old)]);
        let command = RefCommand {
            name: name.clone(),
            expected_old: ExpectedOld::Exactly(old),
            proposed_new: ProposedNew::Update(new),
            force: false,
        };
        let expected = PolicySourceRefusal::MissingAdmissionFacts {
            id: id.to_string(),
            fact: MissingAdmissionFact::AuthenticatedPrincipal,
        };
        assert_eq!(
            evaluate_receive_pack_protection(
                &source,
                &id,
                &SubjectCodeMap::default(),
                principal_id,
                principal_snapshot,
                &refs,
                std::slice::from_ref(&command),
                instant,
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(
            evaluate_effects_protection(
                &source,
                &id,
                &SubjectCodeMap::default(),
                principal_id,
                principal_snapshot,
                &refs,
                &BTreeMap::from([(name.clone(), RefEffect::Set(new))]),
                instant,
            )
            .unwrap_err(),
            expected
        );

        let update = fgit_policy::RefUpdateFact::try_new(
            name.clone(),
            Some(old),
            Some(new),
            RefUpdateKind::FastForward,
            false,
        )
        .unwrap();
        for authentication in AuthenticationStrength::ALL {
            let principal = PrincipalFacts::try_new(
                principal_id,
                principal_snapshot,
                PrincipalKind::Machine,
                authentication,
                &[],
                &[],
            )
            .unwrap();
            let input = fgit_policy::PolicyInputRoot::try_new(
                principal,
                vec![update.clone()],
                &[],
                &[],
                instant,
            )
            .unwrap();
            let first =
                evaluate_protection(&source, &id, &SubjectCodeMap::default(), &input).unwrap();
            assert_eq!(
                first.refusal.is_none(),
                authentication >= AuthenticationStrength::MultiFactor
            );
            assert_eq!(first.snapshot_id, id);
            assert_eq!(
                first,
                evaluate_protection(&source, &id, &SubjectCodeMap::default(), &input).unwrap()
            );
        }
        let legacy =
            build_input_root(principal_id, principal_snapshot, vec![update], instant).unwrap();
        assert_eq!(
            legacy.principal().authentication(),
            AuthenticationStrength::None
        );
    }
}

#[test]
fn existing_reference_only_policies_keep_allow_and_deny_results() {
    let principal = PrincipalId::from_bytes([7; 16]);
    let old = GitOid::Sha1(GitOidSha1::from_bytes([1; 20]));
    let protected = RefName::try_new(b"refs/heads/main").unwrap();
    let topic = RefName::try_new(b"refs/heads/topic").unwrap();
    let refs = BTreeMap::from([(protected.clone(), old), (topic.clone(), old)]);
    let mut source = InMemoryPolicySnapshots::new();
    let id = source.pin(
        crate::policy_bridge::compile_branch_protection_policy("refs/heads/main").unwrap(),
    );
    for name in [&protected, &topic] {
        let command = RefCommand {
            name: name.clone(),
            expected_old: ExpectedOld::Exactly(old),
            proposed_new: ProposedNew::Delete,
            force: false,
        };
        let verdict = evaluate_receive_pack_protection(
            &source,
            &id,
            &SubjectCodeMap::default(),
            principal,
            default_principal_snapshot_id(),
            &refs,
            &[command],
            PolicyInstant::from_seconds(100),
        )
        .unwrap();
        assert_eq!(verdict.refusal.is_some(), name == &protected);
        assert_eq!(verdict.snapshot_id, id);
    }
}
