//! Principal-ID policies observe only the sealed actor identifier. These tests
//! use the real compiler, profile checker, decoder and deterministic evaluator.
use fgit_codec::{DecodeLimits, harness::principal_snapshot_id};
use fgit_policy::{
    AuthenticationStrength, Decision, PolicyInputRoot, PolicyInstant, PolicySnapshot,
    PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind, compile_and_seal, evaluate,
    reference_profile::{self, ReferencePolicyProfile, ReferencePolicyRefusal},
    render_trace,
};
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefName};

fn input(principal: u8, sha256: bool, target: &[u8]) -> PolicyInputRoot {
    let oid = if sha256 {
        GitOid::Sha256(GitOidSha256::from_bytes([1; 32]))
    } else {
        GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))
    };
    PolicyInputRoot::try_new(
        PrincipalFacts::try_new(
            PrincipalId::from_bytes([principal; 16]),
            principal_snapshot_id(),
            PrincipalKind::Machine,
            AuthenticationStrength::None,
            &[],
            &[],
        )
        .unwrap(),
        vec![
            RefUpdateFact::try_new(
                RefName::try_new(target).unwrap(),
                None,
                Some(oid),
                RefUpdateKind::Create,
                false,
            )
            .unwrap(),
        ],
        &[],
        &[],
        PolicyInstant::from_seconds(0),
    )
    .unwrap()
}

#[test]
fn actor_profile_is_explicit_and_historical_ref_profile_stays_closed() {
    let old = compile_and_seal("policy old { default allow }").unwrap();
    let old_frame = old.encode().unwrap();
    assert_eq!(
        reference_profile::classify(&old).unwrap(),
        ReferencePolicyProfile::ReferenceFactsV1
    );
    assert_eq!(
        reference_profile::classify(&old).unwrap().name(),
        "reference_facts_v1"
    );
    assert_eq!(
        PolicySnapshot::decode(&old_frame, DecodeLimits::DEFAULT)
            .unwrap()
            .encode()
            .unwrap(),
        old_frame
    );

    let actor = compile_and_seal("policy release { rule publisher { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"publisher required\" }").unwrap();
    assert_eq!(
        reference_profile::validate(&actor),
        Err(ReferencePolicyRefusal::UnsupportedFacts)
    );
    assert_eq!(
        reference_profile::classify(&actor).unwrap(),
        ReferencePolicyProfile::ReferenceActorIdV1
    );
    assert_eq!(
        reference_profile::classify(&actor).unwrap().name(),
        "reference_actor_id_v1"
    );
    let frame = actor.encode().unwrap();
    let decoded = PolicySnapshot::decode(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded.id(), actor.id());
    assert_eq!(decoded.encode().unwrap(), frame);
}

#[test]
fn release_principal_allowlist_has_real_permit_and_refusal_twins() {
    for predicate in [
        "actor.id == \"33333333333333333333333333333333\"",
        "actor.id in { \"33333333333333333333333333333333\", \"44444444444444444444444444444444\" }",
        "actor.id matches \"3333*\"",
        "not actor.id == \"99999999999999999999999999999999\"",
    ] {
        let policy = compile_and_seal(&format!("policy releases {{ rule limited {{ when ref.name matches \"refs/tags/**\" and not ({predicate}) then deny \"release principal required\" }} default allow }}")).unwrap();
        let profile = reference_profile::classify(&policy).unwrap();
        for sha256 in [false, true] {
            for (principal, target, expected) in [
                (0x33, b"refs/tags/v1".as_slice(), Decision::Allow),
                (0x99, b"refs/tags/v1".as_slice(), Decision::Deny),
                (0x99, b"refs/heads/topic".as_slice(), Decision::Allow),
            ] {
                let facts = input(principal, sha256, target);
                reference_profile::validate_evaluation_for(
                    profile,
                    &policy,
                    facts.updates().iter().map(RefUpdateFact::name),
                )
                .unwrap();
                let first = evaluate(&policy, &facts).unwrap();
                let second = evaluate(&policy, &facts).unwrap();
                assert_eq!(first.decision(), expected, "{predicate}");
                assert_eq!(render_trace(&first), render_trace(&second));
            }
        }
    }
}

#[test]
fn actor_id_support_never_implies_authentication_membership_or_snapshot_facts() {
    for predicate in [
        "actor.authentication >= multi_factor",
        "actor.kind == human",
        "actor.snapshot == \"invented\"",
        "actor.teams contains release",
        "actor.capabilities contains release",
        "ref.force_requested",
        "ref.update == fast_forward",
    ] {
        for condition in [
            predicate.to_owned(),
            format!("not ({predicate})"),
            format!("actor.id == \"never\" and ({predicate})"),
        ] {
            let policy = compile_and_seal(&format!(
                "policy p {{ rule r {{ when {condition} then allow }} default allow }}"
            ))
            .unwrap();
            assert_eq!(
                reference_profile::classify(&policy),
                Err(ReferencePolicyRefusal::UnsupportedFacts),
                "{condition}"
            );
        }
    }
}

#[test]
fn actor_profile_retains_rule_and_evaluation_budgets() {
    let mut source = String::from("policy bounded { ");
    for index in 0..65 {
        source.push_str(&format!("rule r{index:02} {{ when actor.id == \"33333333333333333333333333333333\" then allow }} "));
    }
    source.push_str("default deny \"unknown actor\" }");
    let too_many = compile_and_seal(&source).unwrap();
    assert_eq!(
        reference_profile::classify(&too_many),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );

    let actor = compile_and_seal("policy p { rule r { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"unknown\" }").unwrap();
    let name = RefName::try_new(b"refs/heads/main").unwrap();
    let profile = reference_profile::classify(&actor).unwrap();
    assert_eq!(
        reference_profile::validate_evaluation_for(
            profile,
            &actor,
            std::iter::repeat_n(&name, 10_000)
        ),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );
    reference_profile::validate_evaluation_for(profile, &actor, [&name]).unwrap();
}
