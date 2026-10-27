use fgit_policy::{
    CompiledPolicy, CompiledRule, PolicyName, PolicySnapshot, PolicySnapshotBody, Predicate,
    RuleId, RuleOutcome, compile_and_seal,
    reference_profile::{self, ReferencePolicyRefusal},
};
use fgit_types::RefName;
use std::fmt::Write;

#[test]
fn structural_rules_and_default_only_policies_are_supported() {
    for source in [
        "policy p { default allow }",
        "policy p { default deny \"maintenance\" }",
        "policy p { rule releases { when ref.name matches \"refs/tags/**\" and ref.update == delete then deny \"immutable\" } default allow }",
        "policy p { rule creation { when ref.update in { create, delete, update_unclassified } then allow } default deny \"unsupported\" }",
    ] {
        let policy = compile_and_seal(source).unwrap();
        reference_profile::validate(&policy).unwrap();
        let decoded =
            PolicySnapshot::decode(&policy.encode().unwrap(), fgit_codec::DecodeLimits::DEFAULT)
                .unwrap();
        assert_eq!(decoded, policy);
        reference_profile::validate(&decoded).unwrap();
    }
}

#[test]
fn large_transport_policy_fits_canonical_activation_decoder_limits() {
    let mut source = String::from("policy transport { ");
    for index in 0..40 {
        write!(
            source,
            "rule r{index:02} {{ when ref.name == \"{}\" then deny \"retained\" }} ",
            "a".repeat(900)
        )
        .unwrap();
    }
    source.push_str("default allow }");
    assert!(source.len() > 16 * 1024);
    assert!(source.len() < fgit_policy::syntax::MAX_SOURCE_LEN);
    let snapshot = compile_and_seal(&source).unwrap();
    reference_profile::validate(&snapshot).unwrap();
    let frame = snapshot.encode().unwrap();
    assert!(frame.len() > 32 * 1024);
    assert!(frame.len() <= reference_profile::MAX_REFERENCE_POLICY_BYTES);

    // Match the bounded decoder used by forge activation and its HTTP/MCP
    // adapters without depending on the native node runtime in this test.
    let inherited = fgit_codec::DecodeLimits::DEFAULT;
    let limits = fgit_codec::DecodeLimits {
        frame_bytes: (reference_profile::MAX_REFERENCE_POLICY_BYTES as u64)
            .min(inherited.frame_bytes),
        byte_string_bytes: (reference_profile::MAX_REFERENCE_POLICY_BYTES as u64)
            .min(inherited.byte_string_bytes),
        elements: 4096.min(inherited.elements),
        depth: 32.min(inherited.depth.saturating_sub(1)),
    };
    let decoded = PolicySnapshot::decode(&frame, limits).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.id(), snapshot.id());
    assert_eq!(decoded.encode().unwrap(), frame);
    reference_profile::validate(&decoded).unwrap();
    assert!(
        PolicySnapshot::decode(
            &frame,
            fgit_codec::DecodeLimits {
                byte_string_bytes: 4096,
                ..limits
            },
        )
        .is_err(),
        "an explicitly narrower inherited payload bound must still refuse"
    );
}

#[test]
fn unavailable_facts_refuse_even_under_negation_or_short_circuit() {
    for condition in [
        "actor.authentication >= multi_factor",
        "actor.kind == human",
        "ref.update == fast_forward",
        "not ref.update == non_fast_forward",
        "ref.force_requested",
    ] {
        for expression in [
            condition.to_owned(),
            format!("ref.name == \"refs/heads/never\" and ({condition})"),
        ] {
            let source = format!(
                "policy p {{ rule gate {{ when {expression} then allow }} default allow }}"
            );
            let policy = compile_and_seal(&source).unwrap();
            assert_eq!(
                reference_profile::validate(&policy),
                Err(ReferencePolicyRefusal::UnsupportedFacts),
                "{source}"
            );
        }
    }
    reference_profile::validate(
        &compile_and_seal(
            "policy p { rule gate { when ref.update == delete then allow } default deny \"no\" }",
        )
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn rule_predicate_and_evaluation_work_are_bounded_before_engine_allocation() {
    fn program(predicate: Predicate, count: usize) -> PolicySnapshot {
        PolicySnapshot::seal(PolicySnapshotBody::new(CompiledPolicy::new(
            PolicyName::from_static("limits"),
            Vec::new(),
            Vec::new(),
            (0..count)
                .map(|i| {
                    CompiledRule::new(
                        RuleId::try_new(format!("r{i:04}").as_bytes()).unwrap(),
                        predicate.clone(),
                        RuleOutcome::Allow,
                    )
                })
                .collect(),
            RuleOutcome::Allow,
        )))
        .unwrap()
    }
    reference_profile::validate(&program(Predicate::Always, 64)).unwrap();
    assert_eq!(
        reference_profile::validate(&program(Predicate::Always, 65)),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );
    let nested = Predicate::All(
        (0..reference_profile::MAX_REFERENCE_POLICY_PREDICATES)
            .map(|i| Predicate::TextEquals {
                selector: fgit_policy::Selector::RefName,
                value: fgit_policy::TextLiteral::new(&format!("refs/heads/r{i:05}")),
            })
            .collect(),
    );
    assert_eq!(
        reference_profile::validate(&program(nested, 1)),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );
    let too_long = Predicate::TextEquals {
        selector: fgit_policy::Selector::RefName,
        value: fgit_policy::TextLiteral::new(
            &"a".repeat(fgit_policy::program::MAX_TEXT_LITERAL_LEN + 1),
        ),
    };
    assert_eq!(
        reference_profile::validate(&program(too_long, 1)),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );
    let policy = program(Predicate::Always, 64);
    let name = RefName::try_new(b"refs/heads/main").unwrap();
    reference_profile::validate_evaluation(&policy, std::iter::repeat_n(&name, 1)).unwrap();
    assert_eq!(
        reference_profile::validate_evaluation(&policy, std::iter::repeat_n(&name, 4096)),
        Err(ReferencePolicyRefusal::ResourceLimit)
    );
}
