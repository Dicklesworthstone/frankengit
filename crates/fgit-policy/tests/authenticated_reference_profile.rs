#![forbid(unsafe_code)]
//! Restricted authentication facts use the real compiler and shared evaluator.

use fgit_policy::{
    AuthenticationStrength, Decision, PolicyInputRefusal, RefUpdateFact, RefUpdateKind,
    compile_and_seal,
    reference_profile::{
        self, AuthenticatedReferenceInput, ReferencePolicyProfile, ReferencePolicyRefusal,
        evaluate_authenticated,
    },
    render_trace,
};
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefName};

fn update(sha256: bool, name: &[u8]) -> RefUpdateFact {
    let oid = if sha256 {
        GitOid::Sha256(GitOidSha256::from_bytes([1; 32]))
    } else {
        GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))
    };
    RefUpdateFact::try_new(
        RefName::try_new(name).unwrap(),
        None,
        Some(oid),
        RefUpdateKind::Create,
        false,
    )
    .unwrap()
}

#[test]
fn authenticated_actor_and_strength_have_permit_refusal_and_replay_twins() {
    let policy = compile_and_seal("policy releases { rule credential { when ref.name matches \"refs/tags/**\" and not (actor.id == \"33333333333333333333333333333333\" and actor.authentication >= single_factor) then deny \"authenticated publisher required\" } default allow }").unwrap();
    assert_eq!(
        reference_profile::classify(&policy).unwrap(),
        ReferencePolicyProfile::ReferenceAuthenticationV1,
    );
    assert_eq!(
        reference_profile::classify(&policy).unwrap().name(),
        "reference_authentication_v1",
    );
    for old in [
        ReferencePolicyProfile::ReferenceFactsV1,
        ReferencePolicyProfile::ReferenceActorIdV1,
    ] {
        assert_eq!(
            reference_profile::validate_for(old, &policy),
            Err(ReferencePolicyRefusal::UnsupportedFacts),
        );
    }
    for sha256 in [false, true] {
        for (actor, strength, target, expected) in [
            (
                0x33,
                AuthenticationStrength::SingleFactor,
                b"refs/tags/v1".as_slice(),
                Decision::Allow,
            ),
            (
                0x33,
                AuthenticationStrength::None,
                b"refs/tags/v1".as_slice(),
                Decision::Deny,
            ),
            (
                0x44,
                AuthenticationStrength::SingleFactor,
                b"refs/tags/v1".as_slice(),
                Decision::Deny,
            ),
            (
                0x33,
                AuthenticationStrength::None,
                b"refs/heads/raw-\xff".as_slice(),
                Decision::Allow,
            ),
        ] {
            let input = AuthenticatedReferenceInput::try_new(
                PrincipalId::from_bytes([actor; 16]),
                strength,
                vec![update(sha256, target)],
            )
            .unwrap();
            let first = evaluate_authenticated(&policy, &input).unwrap();
            let second = evaluate_authenticated(&policy, &input).unwrap();
            assert_eq!(first.decision(), expected);
            assert_eq!(first, second);
            assert_eq!(render_trace(&first), render_trace(&second));
        }
    }
}

#[test]
fn explicit_none_is_a_fact_but_single_factor_never_means_mfa() {
    for (predicate, none, single) in [
        (
            "actor.authentication == none",
            Decision::Allow,
            Decision::Deny,
        ),
        (
            "not actor.authentication >= single_factor",
            Decision::Allow,
            Decision::Deny,
        ),
        (
            "actor.authentication >= multi_factor",
            Decision::Deny,
            Decision::Deny,
        ),
        (
            "actor.authentication == hardware_backed",
            Decision::Deny,
            Decision::Deny,
        ),
    ] {
        let policy = compile_and_seal(&format!("policy p {{ rule r {{ when {predicate} then allow }} default deny \"credential requirement\" }}")).unwrap();
        for (strength, expected) in [
            (AuthenticationStrength::None, none),
            (AuthenticationStrength::SingleFactor, single),
        ] {
            let input = AuthenticatedReferenceInput::try_new(
                PrincipalId::from_bytes([0x33; 16]),
                strength,
                vec![update(false, b"refs/heads/main")],
            )
            .unwrap();
            assert_eq!(
                evaluate_authenticated(&policy, &input).unwrap().decision(),
                expected
            );
        }
    }
}

#[test]
fn unavailable_facts_are_refused_in_negated_unreachable_and_empty_subject_programs() {
    for (declaration, predicate) in [
        ("", "actor.kind == human"),
        ("", "actor.snapshot == \"unavailable\""),
        ("", "actor.teams contains release"),
        ("", "actor.capabilities contains release"),
        ("", "ref.force_requested"),
        ("", "ref.update == fast_forward"),
        ("", "ref.update == non_fast_forward"),
        ("aggregate incidents", "aggregate.incidents == 0"),
        ("evidence review { issuer forge.review }", "evidence review"),
    ] {
        for condition in [
            predicate.to_owned(),
            format!("not ({predicate})"),
            format!("actor.id == \"unreachable\" and ({predicate})"),
        ] {
            let policy = compile_and_seal(&format!("policy p {{ {declaration} rule r {{ when {condition} then allow }} default allow }}")).unwrap();
            for updates in [Vec::new(), vec![update(false, b"refs/heads/main")]] {
                let input = AuthenticatedReferenceInput::try_new(
                    PrincipalId::from_bytes([0x33; 16]),
                    AuthenticationStrength::SingleFactor,
                    updates,
                )
                .unwrap();
                assert_eq!(
                    evaluate_authenticated(&policy, &input),
                    Err(ReferencePolicyRefusal::UnsupportedFacts),
                    "{condition}",
                );
            }
        }
    }
}

#[test]
fn restricted_input_preserves_subject_and_evaluation_bounds() {
    let subject = update(false, b"refs/heads/main");
    let old = subject.next().copied().unwrap();
    let new = GitOid::Sha1(GitOidSha1::from_bytes([2; 20]));
    for kind in [RefUpdateKind::FastForward, RefUpdateKind::NonFastForward] {
        let classified =
            RefUpdateFact::try_new(subject.name().clone(), Some(old), Some(new), kind, false)
                .unwrap();
        assert!(matches!(
            AuthenticatedReferenceInput::try_new(
                PrincipalId::from_bytes([0x33; 16]),
                AuthenticationStrength::SingleFactor,
                vec![classified],
            ),
            Err(PolicyInputRefusal::ReferenceUpdateKindUnsupported { .. }),
        ));
    }
    let structural = RefUpdateFact::try_new(
        subject.name().clone(),
        Some(old),
        Some(new),
        RefUpdateKind::UnclassifiedUpdate,
        false,
    )
    .unwrap();
    let structural = AuthenticatedReferenceInput::try_new(
        PrincipalId::from_bytes([0x33; 16]),
        AuthenticationStrength::SingleFactor,
        vec![structural],
    )
    .unwrap();
    let deny_updates = compile_and_seal("policy p { rule r { when ref.update == update_unclassified then deny \"updates disabled\" } default allow }").unwrap();
    assert_eq!(
        evaluate_authenticated(&deny_updates, &structural)
            .unwrap()
            .decision(),
        Decision::Deny
    );
    assert!(matches!(
        AuthenticatedReferenceInput::try_new(
            PrincipalId::from_bytes([0x33; 16]),
            AuthenticationStrength::SingleFactor,
            vec![subject.clone(), subject.clone()],
        ),
        Err(PolicyInputRefusal::DuplicateSubject { .. }),
    ));
    assert!(matches!(
        AuthenticatedReferenceInput::try_new(
            PrincipalId::from_bytes([0x33; 16]),
            AuthenticationStrength::SingleFactor,
            vec![subject; fgit_policy::basis::MAX_SUBJECTS + 1],
        ),
        Err(PolicyInputRefusal::CountExceeded {
            field: "updates",
            ..
        }),
    ));
    let policy = compile_and_seal("policy p { rule r { when actor.authentication >= single_factor then allow } default deny \"credential\" }").unwrap();
    let long = RefName::try_new(&[b"refs/heads/".as_slice(), &vec![b'a'; 1000]].concat()).unwrap();
    assert_eq!(
        reference_profile::validate_evaluation_for(
            ReferencePolicyProfile::ReferenceAuthenticationV1,
            &policy,
            std::iter::repeat_n(&long, 1024),
        ),
        Err(ReferencePolicyRefusal::ResourceLimit),
    );
}
