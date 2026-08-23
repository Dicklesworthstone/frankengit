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
        workspace: Some(0x20),
        credentials: Some(0x21),
        model_harness: Some(0x22),
        context: Some(0x23),
        oracle: Some(0x24),
        sponsor: Some(0x25),
        human: Some(0x26),
    }
}

const fn producer() -> PartyFacts {
    PartyFacts {
        workspace: Some(0x10),
        credentials: Some(0x11),
        model_harness: Some(0x12),
        context: Some(0x13),
        oracle: Some(0x14),
        sponsor: Some(0x15),
        human: Some(0x16),
    }
}

/// Copies `independent_facts`, but leaves exactly one dimension unreported.
const fn unreported_only(dimension: IndependenceDimension) -> PartyFacts {
    let mut facts = independent_facts();
    match dimension {
        IndependenceDimension::Workspace => facts.workspace = None,
        IndependenceDimension::Credentials => facts.credentials = None,
        IndependenceDimension::ModelHarness => facts.model_harness = None,
        IndependenceDimension::Context => facts.context = None,
        IndependenceDimension::Oracle => facts.oracle = None,
        IndependenceDimension::Sponsor => facts.sponsor = None,
        IndependenceDimension::Human => facts.human = None,
    }
    facts
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
    assert_eq!(classification.unreported, vec![]);
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

/// frankengit-9pdo, the regression this fix exists for.
///
/// An UNREPORTED dimension must not classify as independent. Before the fix
/// `PartyFacts` held bare `u128`, so "nobody recorded this" was unrepresentable
/// and a caller who did not know a dimension had to invent a value — inventing
/// a distinct one bought independence on that dimension for free. Absent
/// evidence produced the strongest class.
///
/// Driven from `ALL`, and checked in BOTH directions, because the asymmetry is
/// the whole point: two parties that both default to the same sentinel compare
/// equal and were always treated as non-independent. The dangerous case is the
/// mixed one, where the other side DID report an identity — which is exactly
/// the case that used to return independent.
#[test]
fn an_unreported_dimension_is_never_independent_in_either_direction() {
    for dimension in IndependenceDimension::ALL {
        // Verifier silent, producer reported a different identity.
        let verifier_silent =
            classify_independence(&producer(), &attestation(unreported_only(*dimension)));
        assert!(
            !verifier_silent.is_independent_on(*dimension),
            "{dimension} unreported by the verifier must not be independent",
        );
        assert!(verifier_silent.is_unreported_on(*dimension));
        assert!(!verifier_silent.is_fully_independent());

        // Producer silent, verifier reported one.
        let producer_silent = classify_independence(
            &unreported_only(*dimension),
            &attestation(independent_facts()),
        );
        assert!(
            !producer_silent.is_independent_on(*dimension),
            "{dimension} unreported by the producer must not be independent",
        );
        assert!(producer_silent.is_unreported_on(*dimension));

        // It must not smear: the other six are still independent.
        for other in IndependenceDimension::ALL
            .iter()
            .filter(|d| *d != dimension)
        {
            assert!(
                verifier_silent.is_independent_on(*other),
                "{dimension} unreported must not implicate {other}",
            );
        }
    }

    // Permitted twin: the same shape with the dimension actually reported, and
    // differing, IS independent. Without it, a classifier that called
    // everything non-independent would satisfy every assertion above.
    let both_reported = classify_independence(&producer(), &attestation(independent_facts()));
    assert!(both_reported.is_fully_independent());
}

/// A missing identity and a shared identity are different findings.
///
/// Both defeat independence, so a checker could collapse them and still refuse
/// correctly — and a report would then be unable to tell "these two ran in the
/// same workspace" from "nobody wrote down either workspace". The first is a
/// collusion signal, the second is missing evidence, and they have different
/// remedies.
#[test]
fn sharing_and_not_reporting_are_recorded_separately() {
    let mut facts = sharing_only(IndependenceDimension::Workspace);
    facts.oracle = None;

    let classification = classify_independence(&producer(), &attestation(facts));

    assert_eq!(
        classification.shared,
        vec![IndependenceDimension::Workspace]
    );
    assert_eq!(
        classification.unreported,
        vec![IndependenceDimension::Oracle]
    );
    assert!(!classification.is_unreported_on(IndependenceDimension::Workspace));
    assert!(!classification.is_independent_on(IndependenceDimension::Oracle));
}

/// A party that reports nothing is independent of nobody.
#[test]
fn all_unreported_facts_are_independent_on_no_dimension() {
    let classification =
        classify_independence(&producer(), &attestation(PartyFacts::all_unreported()));

    assert!(!classification.is_fully_independent());
    assert_eq!(classification.shared, vec![]);
    assert_eq!(
        classification.unreported,
        IndependenceDimension::ALL.to_vec(),
        "every dimension must be reported as undecidable, not as shared",
    );
}

/// Policy path: an unreported dimension refuses, and with its OWN refusal.
///
/// Asserting the refusal by value rather than `is_err()` is the point — the
/// remedy differs. `VerifierNotIndependent` means "get a different verifier";
/// `IndependenceUnreported` means "record the identity". Swapping verifiers
/// would not answer this one.
#[test]
fn a_policy_requiring_independence_on_an_unreported_dimension_refuses_typed() {
    let mut change = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact: 0xa8,
        refresh_side: None,
    }]);
    change.verifiers = vec![attestation(unreported_only(IndependenceDimension::Oracle))];

    let policy = EccPolicy {
        required_independence: vec![IndependenceDimension::Oracle],
        requires_verifier: true,
        ..EccPolicy::default()
    };

    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::IndependenceUnreported {
            verifier: 0x99,
            dimension: IndependenceDimension::Oracle,
        })
    );

    // A verifier that SHARES the dimension still gets the other refusal, so the
    // two paths are distinguished rather than one having swallowed the other.
    change.verifiers = vec![attestation(sharing_only(IndependenceDimension::Oracle))];
    assert_eq!(
        change.evaluate(&policy),
        Err(EccRefusal::VerifierNotIndependent {
            verifier: 0x99,
            dimension: IndependenceDimension::Oracle,
        })
    );

    // Permitted twin: reported and differing is accepted.
    change.verifiers = vec![attestation(independent_facts())];
    assert!(change.evaluate(&policy).is_ok());
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
        refreshed_authority: None,
    }
}

/// A policy requiring executed evidence refuses a change that has none.
#[test]
fn a_change_missing_a_required_evidence_class_is_refused_typed() {
    let change = change_with(vec![EvidenceRecordRef {
        class: EvidenceClass::Observed,
        artifact: 0xa1,
        refresh_side: None,
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
        refresh_side: None,
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
            refresh_side: None,
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
        refresh_side: None,
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
            refresh_side: None,
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
        refresh_side: None,
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
        refresh_side: None,
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
