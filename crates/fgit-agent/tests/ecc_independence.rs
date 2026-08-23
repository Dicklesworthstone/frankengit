#![forbid(unsafe_code)]

//! frankengit-fg030b: verifier independence is computed, and a publication
//! policy refuses a change that is missing the evidence it requires.
//!
//! The property under test is normative contract 25: *"verifier independence
//! class is enforced, not self-declared."* Every test here drives
//! [`classify_independence`] or [`EvidenceCarryingChange::evaluate`] from
//! recorded facts — none of them can assert an independence class, because the
//! API has nowhere to assert one.
//!
//! # Every dimension gets its own case
//!
//! The bead's acceptance asks for fixtures covering **each** of the seven
//! declared dimensions, not only workspace and credentials. A checker that
//! compared six fields and silently ignored the seventh would pass a
//! two-dimension test suite while leaving a real collusion path open, so the
//! per-dimension test below is driven from
//! [`IndependenceDimension::ALL`] rather than from a hand-written list — a new
//! dimension added to the enum is covered automatically instead of being
//! forgotten here.

use fgit_agent::{
    EccPolicy, EccRefusal, EvidenceCarryingChange, EvidenceClass, EvidenceRecordRef,
    IndependenceDimension, PartyFacts, RequirementDisposition, VerifierAttestation,
    classify_independence,
};

/// Facts sharing nothing with [`producer`].
const fn independent_facts() -> PartyFacts {
    PartyFacts {
        workspace: 0x20,
        credentials: 0x21,
        model_harness: 0x22,
        context: 0x23,
        oracle: 0x24,
        sponsor: 0x25,
        human: 0x26,
    }
}

const fn producer() -> PartyFacts {
    PartyFacts {
        workspace: 0x10,
        credentials: 0x11,
        model_harness: 0x12,
        context: 0x13,
        oracle: 0x14,
        sponsor: 0x15,
        human: 0x16,
    }
}

/// Copies the producer's identity on exactly one dimension.
const fn sharing_only(dimension: IndependenceDimension) -> PartyFacts {
    let mut facts = independent_facts();
    let shared = producer().on(dimension);
    match dimension {
        IndependenceDimension::Workspace => facts.workspace = shared,
        IndependenceDimension::Credentials => facts.credentials = shared,
        IndependenceDimension::ModelHarness => facts.model_harness = shared,
        IndependenceDimension::Context => facts.context = shared,
        IndependenceDimension::Oracle => facts.oracle = shared,
        IndependenceDimension::Sponsor => facts.sponsor = shared,
        IndependenceDimension::Human => facts.human = shared,
    }
    facts
}

const fn attestation(facts: PartyFacts) -> VerifierAttestation {
    VerifierAttestation {
        verifier: 0x99,
        facts,
        upheld: true,
    }
}

/// `ALL` must name every declared dimension, because every other test here
/// iterates it.
///
/// Without this, dropping a dimension from `ALL` would shrink the loop in
/// `sharing_any_single_dimension_is_detected_and_does_not_smear` from seven
/// cases to six and it would still pass — the suite would silently stop
/// covering the dimension that was removed. That is the failure the acceptance
/// warns about ("a checker that compares six fields and ignores the seventh"),
/// so the count is pinned against the normative contract rather than left to
/// the iteration.
#[test]
fn all_names_every_declared_independence_dimension() {
    assert_eq!(
        IndependenceDimension::ALL.len(),
        7,
        "NORMATIVE_PROTOCOL_CONTRACTS.md §28 classifies over seven dimensions: \
         workspace, credentials, model/harness, context, oracle, sponsor, human",
    );

    let labels: std::collections::BTreeSet<&str> = IndependenceDimension::ALL
        .iter()
        .map(|dimension| dimension.as_str())
        .collect();
    assert_eq!(
        labels.len(),
        IndependenceDimension::ALL.len(),
        "two dimensions must not share a label, or a report cannot distinguish them",
    );

    // Sponsor specifically: AGENTS.md §9 lists six and omits it, so it is the
    // one most likely to be dropped by someone reading only that list.
    assert!(IndependenceDimension::ALL.contains(&IndependenceDimension::Sponsor));
}

/// The permitted twin: a verifier sharing nothing is fully independent.
///
/// Without it, a classifier that reported every dimension as shared would
/// satisfy all the refusal cases below.
#[test]
fn a_verifier_sharing_nothing_is_fully_independent() {
    let classification = classify_independence(&producer(), &attestation(independent_facts()));

    assert!(classification.is_fully_independent());
    assert_eq!(classification.shared, vec![]);
    for dimension in IndependenceDimension::ALL {
        assert!(
            classification.is_independent_on(*dimension),
            "{dimension} must be independent when nothing is shared",
        );
    }
}

/// Each of the seven dimensions is detected, and detected *alone*.
///
/// Driven from `ALL`, so an eighth dimension added to the enum is covered here
/// without anyone remembering to extend this test.
#[test]
fn sharing_any_single_dimension_is_detected_and_does_not_smear() {
    for dimension in IndependenceDimension::ALL {
        let classification =
            classify_independence(&producer(), &attestation(sharing_only(*dimension)));

        assert!(
            !classification.is_fully_independent(),
            "{dimension} shared must not classify as fully independent",
        );
        assert_eq!(
            classification.shared,
            vec![*dimension],
            "sharing {dimension} must report exactly that dimension",
        );
        assert!(
            !classification.is_independent_on(*dimension),
            "{dimension} must be reported as shared",
        );
        for other in IndependenceDimension::ALL
            .iter()
            .filter(|d| *d != dimension)
        {
            assert!(
                classification.is_independent_on(*other),
                "sharing {dimension} must not implicate {other}",
            );
        }
    }
}

/// The acceptance's named case: same workspace or credentials, automatically
/// non-independent, with no opportunity to claim otherwise.
#[test]
fn a_verifier_sharing_workspace_or_credentials_is_never_independent() {
    for dimension in [
        IndependenceDimension::Workspace,
        IndependenceDimension::Credentials,
    ] {
        let classification =
            classify_independence(&producer(), &attestation(sharing_only(dimension)));
        assert!(!classification.is_independent_on(dimension));
    }
}

fn change_with(evidence: Vec<EvidenceRecordRef>) -> EvidenceCarryingChange {
    EvidenceCarryingChange {
        intent_run: 0x01,
        producer: producer(),
        evidence,
        requirement_dispositions: vec![Some(RequirementDisposition::SatisfiedWithEvidence)],
        non_claims: vec![],
        verifiers: vec![attestation(independent_facts())],
    }
}

/// A policy requiring executed evidence refuses a change that has none.
#[test]
fn a_change_missing_a_required_evidence_class_is_refused_typed() {
    let change = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Observed,
        artifact: 0xa1,
    }]);
    let policy = EccPolicy {
        required_classes: vec![EvidenceClass::Executed],
        ..EccPolicy::default()
    };

    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::MissingEvidenceClass {
            required: EvidenceClass::Executed
        })
    );

    // Permitted twin: the same policy passes once the class is present.
    let satisfied = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact: 0xa2,
    }]);
    assert!(satisfied.evaluate(&policy).is_ok());
}

/// A policy may not name a class that records *absence* as a required class.
///
/// This is the fail-closed half of [`EvidenceClass::supports_a_claim`]. Without
/// it, a policy requiring `Omitted` would be discharged by a bundle carrying an
/// `Omitted` row — a note saying the evidence was skipped satisfying an evidence
/// requirement by presence alone. The remedy is to fix the policy, which is why
/// this is a distinct refusal from `MissingEvidenceClass`: gathering more
/// evidence never clears it.
#[test]
fn a_policy_requiring_a_class_that_records_absence_is_refused() {
    for required in [EvidenceClass::Omitted, EvidenceClass::Unresolved] {
        // The bundle carries exactly the row the policy asks for, so a
        // presence-only check would accept it.
        let change = change_with(vec![EvidenceRecordRef {
            class: required,
            artifact: 0xa5,
        }]);
        let policy = EccPolicy {
            required_classes: vec![required],
            ..EccPolicy::default()
        };

        assert_eq!(
            change.evaluate(&policy),
            Err(EccRefusal::UnsupportedEvidenceClass { required }),
            "{required} must not discharge an evidence requirement",
        );
    }

    // Guard ORDER, not just guard presence. When the policy names `Omitted`
    // and the bundle has no `Omitted` row, both guards would fire; only the
    // order decides which refusal the caller sees. Every case above supplies
    // the row, so all of them are blind to a swap. The policy is the defect
    // here — no amount of gathering clears it — so the coherence check must
    // run first and `MissingEvidenceClass` must not shadow it.
    let no_matching_row = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact: 0xa7,
    }]);
    assert_eq!(
        no_matching_row.evaluate(&EccPolicy {
            required_classes: vec![EvidenceClass::Omitted],
            ..EccPolicy::default()
        }),
        Err(EccRefusal::UnsupportedEvidenceClass {
            required: EvidenceClass::Omitted
        }),
        "the incoherent policy must be reported, not a missing row",
    );

    // Permitted twin: the four classes that do support a claim are accepted on
    // the same shape, so the refusal is about the class and not the shape.
    for required in [
        EvidenceClass::Observed,
        EvidenceClass::Executed,
        EvidenceClass::Inferred,
        EvidenceClass::Statistical,
    ] {
        let change = change_with(vec![EvidenceRecordRef {
            class: required,
            artifact: 0xa6,
        }]);
        let policy = EccPolicy {
            required_classes: vec![required],
            ..EccPolicy::default()
        };
        assert!(
            change.evaluate(&policy).is_ok(),
            "{required} supports a claim and must be accepted",
        );
    }
}

/// §10.2: a requirement with no disposition is a construction error, not an
/// empty row that disappears from a summary.
#[test]
fn a_requirement_without_a_disposition_is_refused() {
    let mut change = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact: 0xa3,
    }]);
    change.requirement_dispositions = vec![
        Some(RequirementDisposition::SatisfiedWithEvidence),
        None,
        Some(RequirementDisposition::NotApplicable),
    ];

    assert_eq!(
        change.evaluate(&EccPolicy::default()),
        Err(EccRefusal::RequirementWithoutDisposition { requirement: 1 })
    );
}

/// Policy can demand independence on a named dimension, and a shared one refuses.
#[test]
fn a_policy_requiring_independence_refuses_a_verifier_that_shares_that_dimension() {
    let mut change = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact: 0xa4,
    }]);
    change.verifiers = vec![attestation(sharing_only(IndependenceDimension::Oracle))];

    let policy = EccPolicy {
        required_independence: vec![IndependenceDimension::Oracle],
        requires_verifier: true,
        ..EccPolicy::default()
    };

    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::VerifierNotIndependent {
            verifier: 0x99,
            dimension: IndependenceDimension::Oracle,
        })
    );

    // Permitted twin: an independent verifier on that dimension is accepted.
    change.verifiers = vec![attestation(independent_facts())];
    assert!(change.evaluate(&policy).is_ok());
}

/// A policy requiring a verifier refuses a bundle carrying none.
#[test]
fn a_policy_requiring_a_verifier_refuses_a_bundle_with_none() {
    let mut change = change_with(vec![]);
    change.verifiers = vec![];
    let policy = EccPolicy {
        requires_verifier: true,
        ..EccPolicy::default()
    };

    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::NoVerifierAttestation)
    );
}

/// The evidence classes are structurally distinct, and the two that record the
/// *absence* of support are separated from the four that assert it.
#[test]
fn evidence_classes_are_structurally_distinct_and_split_support_from_absence() {
    let all = EvidenceClass::ALL;
    assert_eq!(all.len(), 6);

    let labels: std::collections::BTreeSet<&str> = all.iter().map(|c| c.as_str()).collect();
    assert_eq!(labels.len(), all.len(), "class labels must not collide");

    for class in all {
        let supports = class.supports_a_claim();
        let expected = !matches!(class, EvidenceClass::Omitted | EvidenceClass::Unresolved);
        assert_eq!(
            supports, expected,
            "{class} must not be counted as supporting a claim",
        );
    }
}
