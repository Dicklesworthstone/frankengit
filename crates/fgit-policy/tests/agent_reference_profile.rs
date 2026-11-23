#![forbid(unsafe_code)]
//! Authenticated agent kinds are a separately activated closed factual profile.

use fgit_policy::{
    AuthenticationStrength, Decision, PolicyInputRefusal, RefUpdateFact, RefUpdateKind,
    compile_and_seal,
    reference_profile::{
        self, AgentReferenceInput, AuthenticatedReferenceInput, ReferencePolicyProfile,
        ReferencePolicyRefusal, evaluate_agent, evaluate_authenticated,
    },
    render_trace,
};
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefName};

fn update(sha256: bool) -> RefUpdateFact {
    let oid = if sha256 {
        GitOid::Sha256(GitOidSha256::from_bytes([1; 32]))
    } else {
        GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))
    };
    RefUpdateFact::try_new(
        RefName::try_new(b"refs/heads/agent-\xff").unwrap(),
        None,
        Some(oid),
        RefUpdateKind::Create,
        false,
    )
    .unwrap()
}

#[test]
fn authenticated_agent_kind_and_strength_are_deterministic_and_bounded() {
    for (predicate, expected) in [
        ("actor.kind == agent", Decision::Allow),
        ("actor.kind in {human, agent}", Decision::Allow),
        ("not actor.kind == human", Decision::Allow),
        ("actor.kind == human", Decision::Deny),
        ("actor.kind in {machine, service}", Decision::Deny),
        (
            "actor.kind == agent and actor.authentication == single_factor and actor.id == \"33333333333333333333333333333333\" and ref.name matches \"refs/heads/**\"",
            Decision::Allow,
        ),
        (
            "actor.kind == agent and actor.authentication >= multi_factor",
            Decision::Deny,
        ),
        (
            "actor.kind == agent and actor.authentication == hardware_backed",
            Decision::Deny,
        ),
    ] {
        let policy = compile_and_seal(&format!("policy p {{ rule r {{ when {predicate} then allow }} default deny \"agent credential required\" }}")).unwrap();
        assert_eq!(
            reference_profile::classify(&policy).unwrap(),
            ReferencePolicyProfile::ReferencePrincipalKindV1,
        );
        assert_eq!(
            reference_profile::classify(&policy).unwrap().name(),
            "reference_principal_kind_v1",
        );
        for sha256 in [false, true] {
            let input = AgentReferenceInput::try_new(
                PrincipalId::from_bytes([0x33; 16]),
                vec![update(sha256)],
            )
            .unwrap();
            let first = evaluate_agent(&policy, &input).unwrap();
            let second = evaluate_agent(&policy, &input).unwrap();
            assert_eq!(first.decision(), expected, "{predicate}");
            assert_eq!(first, second);
            assert_eq!(render_trace(&first), render_trace(&second));
            assert_eq!(first.subjects()[0].name(), b"refs/heads/agent-\xff");
        }
    }
}

#[test]
fn historical_profiles_do_not_acquire_agent_kind_semantics() {
    for predicate in [
        "actor.kind == agent",
        "not actor.kind == human",
        "actor.id == \"unreachable\" and actor.kind == agent",
    ] {
        let policy = compile_and_seal(&format!(
            "policy p {{ rule r {{ when {predicate} then allow }} default allow }}"
        ))
        .unwrap();
        for profile in [
            ReferencePolicyProfile::ReferenceFactsV1,
            ReferencePolicyProfile::ReferenceActorIdV1,
            ReferencePolicyProfile::ReferenceAuthenticationV1,
        ] {
            assert_eq!(
                reference_profile::validate_for(profile, &policy),
                Err(ReferencePolicyRefusal::UnsupportedFacts),
            );
        }
        for updates in [Vec::new(), vec![update(false)]] {
            let input = AuthenticatedReferenceInput::try_new(
                PrincipalId::from_bytes([0x33; 16]),
                AuthenticationStrength::SingleFactor,
                updates,
            )
            .unwrap();
            assert_eq!(
                evaluate_authenticated(&policy, &input),
                Err(ReferencePolicyRefusal::UnsupportedFacts),
            );
        }
    }
}

#[test]
fn agent_kind_does_not_supply_membership_time_ancestry_or_evidence() {
    for (declaration, predicate) in [
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
            format!("actor.kind == human and ({predicate})"),
        ] {
            let policy = compile_and_seal(&format!("policy p {{ {declaration} rule r {{ when {condition} then allow }} default allow }}")).unwrap();
            for updates in [Vec::new(), vec![update(false)]] {
                let input =
                    AgentReferenceInput::try_new(PrincipalId::from_bytes([0x33; 16]), updates)
                        .unwrap();
                assert_eq!(
                    evaluate_agent(&policy, &input),
                    Err(ReferencePolicyRefusal::UnsupportedFacts),
                    "{condition}",
                );
            }
        }
    }
}

#[test]
fn agent_input_retains_structural_subject_and_trace_limits() {
    let subject = update(false);
    assert!(matches!(
        AgentReferenceInput::try_new(
            PrincipalId::from_bytes([0x33; 16]),
            vec![subject.clone(), subject.clone()],
        ),
        Err(PolicyInputRefusal::DuplicateSubject { .. }),
    ));
    for kind in [RefUpdateKind::FastForward, RefUpdateKind::NonFastForward] {
        let classified = RefUpdateFact::try_new(
            subject.name().clone(),
            subject.next().copied(),
            Some(GitOid::Sha1(GitOidSha1::from_bytes([2; 20]))),
            kind,
            false,
        )
        .unwrap();
        assert!(matches!(
            AgentReferenceInput::try_new(PrincipalId::from_bytes([0x33; 16]), vec![classified],),
            Err(PolicyInputRefusal::ReferenceUpdateKindUnsupported { .. }),
        ));
    }
    let policy = compile_and_seal("policy p { rule r { when actor.kind == agent then allow } default deny \"agent required\" }").unwrap();
    let long = RefName::try_new(&[b"refs/heads/".as_slice(), &vec![b'a'; 1000]].concat()).unwrap();
    assert_eq!(
        reference_profile::validate_evaluation_for(
            ReferencePolicyProfile::ReferencePrincipalKindV1,
            &policy,
            std::iter::repeat_n(&long, 1024),
        ),
        Err(ReferencePolicyRefusal::ResourceLimit),
    );
}
