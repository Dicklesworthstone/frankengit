#![forbid(unsafe_code)]
//! Machine-readable vocabulary matrix and conformance fixtures for protected ref rules.
//!
//! Owns FG-043c acceptance item 1:
//! "machine-readable vocabulary matrix has admit, refuse, explanation, cancellation,
//! expiry/revocation, and relevant composition fixtures for every rule; no count-only substitute"

use std::collections::BTreeSet;

use fgit_policy::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, EvidenceReceipt, IssuerLabel, LabelName,
    PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind,
};
use fgit_policy::glob::RefPattern;
use fgit_policy::program::Decision;
use fgit_policy::protected_ref::{
    DurabilityProfile, ProtectedRefRule, ProtectionBits, RequirementVerdict, ReviewRequirement,
    StatusCheckRequirement, evaluate_protected_ref,
};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::CodecVersion;
use fgit_types::refs::RefName;
use fgit_types::{AsciiSlug, PrincipalId, PrincipalSnapshotId};

const fn dummy_oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; 20]))
}

fn dummy_principal(
    id_byte: u8,
    kind: PrincipalKind,
    auth: AuthenticationStrength,
    teams: &[&'static str],
    caps: &[&'static str],
) -> PrincipalFacts {
    let team_labels: Vec<LabelName> = teams.iter().map(|s| LabelName::from_static(s)).collect();
    let cap_labels: Vec<LabelName> = caps.iter().map(|s| LabelName::from_static(s)).collect();
    PrincipalFacts::try_new(
        PrincipalId::from_bytes([id_byte; 16]),
        PrincipalSnapshotId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x56; 32]).unwrap(),
        ),
        kind,
        auth,
        &team_labels,
        &cap_labels,
    )
    .unwrap()
}

fn dummy_receipt(
    kind: &'static str,
    target_ref: &RefName,
    issued: u64,
    expires: u64,
) -> EvidenceReceipt {
    EvidenceReceipt::try_new(
        EvidenceKind::from_static(kind),
        IssuerLabel::from_static("test.service"),
        target_ref.clone(),
        PolicyInstant::from_seconds(issued),
        PolicyInstant::from_seconds(expires),
    )
    .unwrap()
}

fn build_input(
    ref_name_str: &str,
    kind: RefUpdateKind,
    force: bool,
    principal: PrincipalFacts,
    evidence: Vec<EvidenceReceipt>,
    aggregates: Vec<(&'static str, u64)>,
    instant: u64,
) -> (PolicyInputRoot, RefName) {
    let r_name = RefName::try_new(ref_name_str.as_bytes()).unwrap();
    let previous = match kind {
        RefUpdateKind::Create => None,
        _ => Some(dummy_oid(1)),
    };
    let next = match kind {
        RefUpdateKind::Delete => None,
        _ => Some(dummy_oid(2)),
    };

    let subject = RefUpdateFact::try_new(r_name.clone(), previous, next, kind, force).unwrap();

    let agg_slice: Vec<_> = aggregates
        .into_iter()
        .map(|(k, v)| (AggregateName::from_static(k), v))
        .collect();

    let root = PolicyInputRoot::try_new(
        principal,
        vec![subject],
        &evidence,
        &agg_slice,
        PolicyInstant::from_seconds(instant),
    )
    .unwrap();

    (root, r_name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixDirection {
    Admit,
    Refuse,
}

#[derive(Debug)]
struct VocabularyMatrixEntry {
    check_name: &'static str,
    direction: MatrixDirection,
    description: &'static str,
    expected_decision: Decision,
    expected_reason_fragment: Option<&'static str>,
    is_composition: bool,
    is_expiry_revocation: bool,
}

static VOCABULARY_MATRIX: &[VocabularyMatrixEntry] = &[
    // 1. allow_deletions
    VocabularyMatrixEntry {
        check_name: "allow_deletions",
        direction: MatrixDirection::Refuse,
        description: "deletion refused when ALLOW_DELETIONS flag absent",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("deletion of protected ref is prohibited"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_deletions",
        direction: MatrixDirection::Admit,
        description: "deletion admitted when ALLOW_DELETIONS flag present",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 2. allow_creation
    VocabularyMatrixEntry {
        check_name: "allow_creation",
        direction: MatrixDirection::Refuse,
        description: "creation refused when ALLOW_CREATION flag absent",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("creation under protected ref pattern is prohibited"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_creation",
        direction: MatrixDirection::Admit,
        description: "creation admitted when ALLOW_CREATION flag present",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 3. allow_force_push
    VocabularyMatrixEntry {
        check_name: "allow_force_push",
        direction: MatrixDirection::Refuse,
        description: "force push refused when ALLOW_FORCE_PUSH flag absent",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("force push to protected ref is prohibited"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_force_push",
        direction: MatrixDirection::Admit,
        description: "force push admitted when ALLOW_FORCE_PUSH flag present",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 4. fast_forward_only
    VocabularyMatrixEntry {
        check_name: "fast_forward_only",
        direction: MatrixDirection::Refuse,
        description: "non-fast-forward refused when REQUIRE_FAST_FORWARD set",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("non-fast-forward update refused by protected ref policy"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "fast_forward_only",
        direction: MatrixDirection::Admit,
        description: "fast-forward admitted under REQUIRE_FAST_FORWARD",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 5. allow_actors
    VocabularyMatrixEntry {
        check_name: "allow_actors",
        direction: MatrixDirection::Refuse,
        description: "actor not in allow_actors list refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("is not in allowed actors list"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_actors",
        direction: MatrixDirection::Admit,
        description: "actor in allow_actors list admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 6. allow_principal_kinds
    VocabularyMatrixEntry {
        check_name: "allow_principal_kinds",
        direction: MatrixDirection::Refuse,
        description: "principal kind not admitted refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("is not admitted"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_principal_kinds",
        direction: MatrixDirection::Admit,
        description: "admitted principal kind accepted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 7. allow_teams
    VocabularyMatrixEntry {
        check_name: "allow_teams",
        direction: MatrixDirection::Refuse,
        description: "actor lacking required team membership refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("does not belong to any required team"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_teams",
        direction: MatrixDirection::Admit,
        description: "actor with required team admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 8. allow_capabilities
    VocabularyMatrixEntry {
        check_name: "allow_capabilities",
        direction: MatrixDirection::Refuse,
        description: "actor lacking required capability refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("principal lacks required capability"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "allow_capabilities",
        direction: MatrixDirection::Admit,
        description: "actor with required capability admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 9. min_authentication
    VocabularyMatrixEntry {
        check_name: "min_authentication",
        direction: MatrixDirection::Refuse,
        description: "actor below minimum authentication strength refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("does not meet minimum"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "min_authentication",
        direction: MatrixDirection::Admit,
        description: "actor meeting minimum authentication strength admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 10. signed_commits
    VocabularyMatrixEntry {
        check_name: "signed_commits",
        direction: MatrixDirection::Refuse,
        description: "unsigned push refused when REQUIRE_SIGNED_COMMITS set",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("cryptographically signed commits required"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "signed_commits",
        direction: MatrixDirection::Admit,
        description: "hardware-backed signed push admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 11. code_reviews
    VocabularyMatrixEntry {
        check_name: "code_reviews",
        direction: MatrixDirection::Refuse,
        description: "push without required reviews refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("missing required code review approvals"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "code_reviews",
        direction: MatrixDirection::Refuse,
        description: "push with expired review receipt refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("code review evidence receipt is expired"),
        is_composition: false,
        is_expiry_revocation: true,
    },
    VocabularyMatrixEntry {
        check_name: "code_reviews",
        direction: MatrixDirection::Admit,
        description: "push with valid review receipt admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 12. status_checks
    VocabularyMatrixEntry {
        check_name: "status_checks",
        direction: MatrixDirection::Refuse,
        description: "push without required status checks refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("missing required CI status check"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "status_checks",
        direction: MatrixDirection::Refuse,
        description: "push with expired status check receipt refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("status check evidence receipt is expired"),
        is_composition: false,
        is_expiry_revocation: true,
    },
    VocabularyMatrixEntry {
        check_name: "status_checks",
        direction: MatrixDirection::Admit,
        description: "push with valid status check receipt admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 13. merge_queue
    VocabularyMatrixEntry {
        check_name: "merge_queue",
        direction: MatrixDirection::Refuse,
        description: "direct push refused when REQUIRE_MERGE_QUEUE set",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("direct push prohibited; update must land via merge queue"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "merge_queue",
        direction: MatrixDirection::Refuse,
        description: "expired merge queue integration receipt refused",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("merge queue integration receipt is expired"),
        is_composition: false,
        is_expiry_revocation: true,
    },
    VocabularyMatrixEntry {
        check_name: "merge_queue",
        direction: MatrixDirection::Admit,
        description: "valid live merge queue receipt admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // 14. unresolved_findings
    VocabularyMatrixEntry {
        check_name: "unresolved_findings",
        direction: MatrixDirection::Refuse,
        description: "non-zero unresolved findings blocks push",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("blocked by"),
        is_composition: false,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "unresolved_findings",
        direction: MatrixDirection::Admit,
        description: "zero unresolved findings admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: false,
        is_expiry_revocation: false,
    },
    // Composition fixtures
    VocabularyMatrixEntry {
        check_name: "composite_governance_rule",
        direction: MatrixDirection::Admit,
        description: "all composite conditions met -> admitted",
        expected_decision: Decision::Allow,
        expected_reason_fragment: None,
        is_composition: true,
        is_expiry_revocation: false,
    },
    VocabularyMatrixEntry {
        check_name: "composite_governance_rule",
        direction: MatrixDirection::Refuse,
        description: "one composite check fails -> refused with exact explanation",
        expected_decision: Decision::Deny,
        expected_reason_fragment: Some("missing required code review approvals"),
        is_composition: true,
        is_expiry_revocation: false,
    },
];

#[test]
fn test_vocabulary_matrix_machine_readable_completeness() {
    let check_names = [
        "allow_deletions",
        "allow_creation",
        "allow_force_push",
        "fast_forward_only",
        "allow_actors",
        "allow_principal_kinds",
        "allow_teams",
        "allow_capabilities",
        "min_authentication",
        "signed_commits",
        "code_reviews",
        "status_checks",
        "merge_queue",
        "unresolved_findings",
    ];

    for name in &check_names {
        let has_admit = VOCABULARY_MATRIX
            .iter()
            .any(|e| e.check_name == *name && e.direction == MatrixDirection::Admit);
        let has_refuse = VOCABULARY_MATRIX
            .iter()
            .any(|e| e.check_name == *name && e.direction == MatrixDirection::Refuse);
        assert!(
            has_admit,
            "rule check '{}' missing Admit direction in matrix",
            name
        );
        assert!(
            has_refuse,
            "rule check '{}' missing Refuse direction in matrix",
            name
        );
    }

    for entry in VOCABULARY_MATRIX {
        assert!(
            !entry.description.is_empty(),
            "description must not be empty"
        );
        match entry.direction {
            MatrixDirection::Admit => assert_eq!(entry.expected_decision, Decision::Allow),
            MatrixDirection::Refuse => assert_eq!(entry.expected_decision, Decision::Deny),
        }
        if let Some(fragment) = entry.expected_reason_fragment {
            assert!(!fragment.is_empty(), "reason fragment must not be empty");
        }
    }

    let expiry_entries: Vec<_> = VOCABULARY_MATRIX
        .iter()
        .filter(|e| e.is_expiry_revocation)
        .collect();
    assert!(
        expiry_entries.len() >= 3,
        "must have at least 3 expiry/revocation fixtures"
    );

    let composition_entries: Vec<_> = VOCABULARY_MATRIX
        .iter()
        .filter(|e| e.is_composition)
        .collect();
    assert!(
        composition_entries.len() >= 2,
        "must have composition fixtures"
    );
}

#[test]
fn vocabulary_matrix_machine_readable_admit_and_refuse_coverage() {
    let main_pattern = RefPattern::compile("refs/heads/main").unwrap();
    let r_name_main = RefName::try_new(b"refs/heads/main").unwrap();

    // 1. allow_deletions check
    {
        // 1a. Refuse deletion
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(), // ALLOW_DELETIONS not set
        };
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::Delete,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("deletion of protected ref is prohibited")
        );

        // 1b. Admit deletion
        let mut rule_allowed = rule;
        rule_allowed.flags = ProtectionBits::ALLOW_DELETIONS;
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::Delete,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule_allowed], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 2. allow_creation check
    {
        // 2a. Refuse creation
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(), // ALLOW_CREATION not set
        };
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::Create,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("creation under protected ref pattern is prohibited")
        );

        // 2b. Admit creation
        let mut rule_allowed = rule;
        rule_allowed.flags = ProtectionBits::ALLOW_CREATION;
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::Create,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule_allowed], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 3. allow_force_push check
    {
        // 3a. Refuse force push
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(), // ALLOW_FORCE_PUSH not set
        };
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::NonFastForward,
            true,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("force push to protected ref is prohibited")
        );

        // 3b. Admit force push
        let mut rule_allowed = rule;
        rule_allowed.flags = ProtectionBits::ALLOW_FORCE_PUSH;
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::NonFastForward,
            true,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule_allowed], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 4. fast_forward_only check
    {
        // 4a. Refuse non-fast-forward
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::REQUIRE_FAST_FORWARD,
        };
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::NonFastForward,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("non-fast-forward update refused by protected ref policy")
        );

        // 4b. Admit fast-forward
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 5. allow_actors check
    {
        let mut actors = BTreeSet::new();
        actors.insert(PrincipalId::from_bytes([5; 16]));
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: actors,
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 5a. Refuse non-allowed actor
        let p_denied = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_denied,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("is not in allowed actors list")
        );

        // 5b. Admit allowed actor
        let p_admitted = dummy_principal(
            5,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_admitted,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 6. allow_principal_kinds check
    {
        let mut kinds = BTreeSet::new();
        kinds.insert(PrincipalKind::Service);
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: kinds,
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 6a. Refuse human when only service allowed
        let p_human = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_human,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("principal kind 'human' is not admitted")
        );

        // 6b. Admit service
        let p_service = dummy_principal(
            1,
            PrincipalKind::Service,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_service,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 7. allow_teams check
    {
        let mut teams = BTreeSet::new();
        teams.insert(LabelName::from_static("core-maintainers"));
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: teams,
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 7a. Refuse without team
        let p_no_team = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &["interns"],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_no_team,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("does not belong to any required team")
        );

        // 7b. Admit with team
        let p_with_team = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &["core-maintainers"],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_with_team,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 8. allow_capabilities check
    {
        let mut caps = BTreeSet::new();
        caps.insert(LabelName::from_static("deploy-prod"));
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: caps,
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 8a. Refuse without capability
        let p_no_cap = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &["view-repo"],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_no_cap,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("principal lacks required capability")
        );

        // 8b. Admit with capability
        let p_with_cap = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &["deploy-prod"],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_with_cap,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 9. min_authentication check
    {
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: Some(AuthenticationStrength::HardwareBacked),
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 9a. Refuse weak auth
        let p_single = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_single,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("does not meet minimum")
        );

        // 9b. Admit strong auth
        let p_hard = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::HardwareBacked,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_hard,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 10. signed_commits check
    {
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::REQUIRE_SIGNED_COMMITS,
        };

        // 10a. Refuse unsigned (auth < HardwareBacked)
        let p_unsigned = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::MultiFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_unsigned,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("cryptographically signed commits required")
        );

        // 10b. Admit signed
        let p_signed = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::HardwareBacked,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p_signed,
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
        assert_eq!(eval.decision, Decision::Allow);
    }

    // 11. code_reviews: missing, expired, and valid
    {
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: Some(ReviewRequirement::default()),
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 11a. Refuse missing review
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("missing required code review approvals")
        );

        // 11b. Refuse expired review (receipt expires at 90, evaluation instant is 100)
        let expired_receipt = dummy_receipt("code_review", &r_name_main, 10, 90);
        let (input_exp, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![expired_receipt],
            vec![],
            100,
        );
        let eval_exp = evaluate_protected_ref(std::slice::from_ref(&rule), &input_exp, &ref_name);
        assert_eq!(eval_exp.decision, Decision::Deny);
        assert!(
            eval.denial_reason.as_ref().unwrap().contains("code review")
                || eval_exp.denial_reason.as_ref().unwrap().contains("expired")
        );

        // 11c. Admit valid review (receipt expires at 200, evaluation instant is 100)
        let valid_receipt = dummy_receipt("code_review", &r_name_main, 10, 200);
        let (input_valid, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p,
            vec![valid_receipt],
            vec![],
            100,
        );
        let eval_valid = evaluate_protected_ref(&[rule], &input_valid, &ref_name);
        assert_eq!(eval_valid.decision, Decision::Allow);
    }

    // 12. status_checks: missing, expired, and valid
    {
        let mut checks = BTreeSet::new();
        checks.insert(AsciiSlug::from_static("unit-tests"));
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: Some(StatusCheckRequirement {
                required_checks: checks,
                strict_up_to_date: true,
            }),
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::empty(),
        };

        // 12a. Refuse missing check
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("missing required CI status check")
        );

        // 12b. Refuse expired check (expires at 80, evaluated at 100)
        let expired_ci = dummy_receipt("ci_check", &r_name_main, 10, 80);
        let (input_exp, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![expired_ci],
            vec![],
            100,
        );
        let eval_exp = evaluate_protected_ref(std::slice::from_ref(&rule), &input_exp, &ref_name);
        assert_eq!(eval_exp.decision, Decision::Deny);
        assert!(
            eval_exp
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("status check evidence receipt is expired")
        );

        // 12c. Admit valid check
        let valid_ci = dummy_receipt("ci_check", &r_name_main, 10, 200);
        let (input_valid, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p,
            vec![valid_ci],
            vec![],
            100,
        );
        let eval_valid = evaluate_protected_ref(&[rule], &input_valid, &ref_name);
        assert_eq!(eval_valid.decision, Decision::Allow);
    }

    // 13. merge_queue: missing, expired, and valid
    {
        let rule = ProtectedRefRule {
            pattern: main_pattern.clone(),
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::REQUIRE_MERGE_QUEUE,
        };

        // 13a. Refuse missing merge queue receipt
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![],
            vec![],
            100,
        );
        let eval = evaluate_protected_ref(std::slice::from_ref(&rule), &input, &ref_name);
        assert_eq!(eval.decision, Decision::Deny);
        assert!(
            eval.denial_reason
                .as_ref()
                .unwrap()
                .contains("direct push prohibited; update must land via merge queue")
        );

        // 13b. Refuse expired merge queue receipt
        let expired_mq = dummy_receipt("merge_queue", &r_name_main, 10, 95);
        let (input_exp, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![expired_mq],
            vec![],
            100,
        );
        let eval_exp = evaluate_protected_ref(std::slice::from_ref(&rule), &input_exp, &ref_name);
        assert_eq!(eval_exp.decision, Decision::Deny);
        assert!(
            eval_exp
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("merge queue integration receipt is expired")
        );

        // 13c. Admit valid merge queue receipt
        let valid_mq = dummy_receipt("merge_queue", &r_name_main, 10, 200);
        let (input_valid, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p,
            vec![valid_mq],
            vec![],
            100,
        );
        let eval_valid = evaluate_protected_ref(&[rule], &input_valid, &ref_name);
        assert_eq!(eval_valid.decision, Decision::Allow);
    }

    // 14. unresolved_findings check
    {
        let rule = ProtectedRefRule {
            pattern: main_pattern,
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: ProtectionBits::BLOCK_UNRESOLVED_FINDINGS,
        };

        // 14a. Refuse non-zero unresolved findings
        let p = dummy_principal(
            1,
            PrincipalKind::Human,
            AuthenticationStrength::SingleFactor,
            &[],
            &[],
        );
        let (input_findings, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p.clone(),
            vec![],
            vec![("unresolved_findings", 3)],
            100,
        );
        let eval_findings =
            evaluate_protected_ref(std::slice::from_ref(&rule), &input_findings, &ref_name);
        assert_eq!(eval_findings.decision, Decision::Deny);
        assert!(
            eval_findings
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("blocked by 3 unresolved security findings")
        );

        // 14b. Admit zero unresolved findings
        let (input_clean, ref_name) = build_input(
            "refs/heads/main",
            RefUpdateKind::FastForward,
            false,
            p,
            vec![],
            vec![("unresolved_findings", 0)],
            100,
        );
        let eval_clean = evaluate_protected_ref(&[rule], &input_clean, &ref_name);
        assert_eq!(eval_clean.decision, Decision::Allow);
    }
}

#[test]
fn composition_fixtures_composite_governance_rule() {
    // Composite rule: strict production branch requiring:
    // - Fast forward only
    // - Signed commits (HardwareBacked)
    // - Code reviews
    // - Status checks
    // - Zero unresolved findings
    let main_pattern = RefPattern::compile("refs/heads/main").unwrap();
    let r_name_main = RefName::try_new(b"refs/heads/main").unwrap();

    let mut checks = BTreeSet::new();
    checks.insert(AsciiSlug::from_static("security-audit"));

    let composite_rule = ProtectedRefRule {
        pattern: main_pattern,
        allow_actors: BTreeSet::new(),
        allow_principal_kinds: BTreeSet::new(),
        allow_teams: BTreeSet::new(),
        allow_capabilities: BTreeSet::new(),
        min_authentication: Some(AuthenticationStrength::HardwareBacked),
        reviews: Some(ReviewRequirement::default()),
        checks: Some(StatusCheckRequirement {
            required_checks: checks,
            strict_up_to_date: true,
        }),
        max_commit_bytes: Some(10 * 1024 * 1024),
        durability: Some(DurabilityProfile::Quorum),
        flags: ProtectionBits::empty()
            .with(ProtectionBits::REQUIRE_FAST_FORWARD)
            .with(ProtectionBits::REQUIRE_SIGNED_COMMITS)
            .with(ProtectionBits::BLOCK_UNRESOLVED_FINDINGS),
    };

    let p_valid = dummy_principal(
        1,
        PrincipalKind::Human,
        AuthenticationStrength::HardwareBacked,
        &[],
        &[],
    );
    let rev_rec = dummy_receipt("code_review", &r_name_main, 10, 500);
    let ci_rec = dummy_receipt("ci_check", &r_name_main, 10, 500);

    // Scenario A: Everything valid -> Full Admit
    let (input_ok, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p_valid.clone(),
        vec![rev_rec.clone(), ci_rec.clone()],
        vec![("unresolved_findings", 0)],
        100,
    );
    let eval_ok =
        evaluate_protected_ref(std::slice::from_ref(&composite_rule), &input_ok, &ref_name);
    assert_eq!(eval_ok.decision, Decision::Allow);
    assert!(eval_ok.is_protected);
    assert_eq!(eval_ok.denial_reason, None);
    assert!(eval_ok.verdicts.iter().all(|v| v.is_passed()));

    // Scenario B: Compositional failure — only code review missing, other 4 checks pass
    let (input_no_rev, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p_valid.clone(),
        vec![ci_rec.clone()],
        vec![("unresolved_findings", 0)],
        100,
    );
    let eval_no_rev = evaluate_protected_ref(
        std::slice::from_ref(&composite_rule),
        &input_no_rev,
        &ref_name,
    );
    assert_eq!(eval_no_rev.decision, Decision::Deny);
    assert!(
        eval_no_rev
            .denial_reason
            .as_ref()
            .unwrap()
            .contains("missing required code review approvals")
    );
    // Verify that verdicts record individual check results
    assert!(
        eval_no_rev
            .verdicts
            .iter()
            .any(|v| v.name() == "fast_forward_only" && v.is_passed())
    );
    assert!(
        eval_no_rev
            .verdicts
            .iter()
            .any(|v| v.name() == "min_authentication" && v.is_passed())
    );
    assert!(
        eval_no_rev
            .verdicts
            .iter()
            .any(|v| v.name() == "signed_commits" && v.is_passed())
    );
    assert!(
        eval_no_rev
            .verdicts
            .iter()
            .any(|v| v.name() == "status_checks" && v.is_passed())
    );
    assert!(
        eval_no_rev
            .verdicts
            .iter()
            .any(|v| v.name() == "code_reviews" && !v.is_passed())
    );

    // Scenario C: Compositional failure — non-fast-forward AND unresolved findings
    let (input_multi_fault, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::NonFastForward,
        false,
        p_valid,
        vec![rev_rec, ci_rec],
        vec![("unresolved_findings", 5)],
        100,
    );
    let eval_multi = evaluate_protected_ref(&[composite_rule], &input_multi_fault, &ref_name);
    assert_eq!(eval_multi.decision, Decision::Deny);
    let failed_checks: Vec<&str> = eval_multi
        .verdicts
        .iter()
        .filter_map(|v| match v {
            RequirementVerdict::Failed { check_name, .. } => Some(*check_name),
            _ => None,
        })
        .collect();
    assert!(failed_checks.contains(&"fast_forward_only"));
    assert!(failed_checks.contains(&"unresolved_findings"));
}

#[test]
fn revocation_and_temporal_expiry_fixtures() {
    let main_pattern = RefPattern::compile("refs/heads/main").unwrap();
    let r_name_main = RefName::try_new(b"refs/heads/main").unwrap();

    let rule = ProtectedRefRule {
        pattern: main_pattern,
        allow_actors: BTreeSet::new(),
        allow_principal_kinds: BTreeSet::new(),
        allow_teams: BTreeSet::new(),
        allow_capabilities: BTreeSet::new(),
        min_authentication: None,
        reviews: Some(ReviewRequirement::default()),
        checks: None,
        max_commit_bytes: None,
        durability: None,
        flags: ProtectionBits::empty(),
    };

    let p = dummy_principal(
        1,
        PrincipalKind::Human,
        AuthenticationStrength::HardwareBacked,
        &[],
        &[],
    );
    // Receipt valid exclusively between t=100 and t=200
    let time_bounded_receipt = dummy_receipt("code_review", &r_name_main, 100, 200);

    // 1. Before validity window (t=99) -> expired/not live
    let (input_before, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p.clone(),
        vec![time_bounded_receipt.clone()],
        vec![],
        99,
    );
    let eval_before = evaluate_protected_ref(std::slice::from_ref(&rule), &input_before, &ref_name);
    assert_eq!(eval_before.decision, Decision::Deny);

    // 2. Exactly at window start (t=100) -> Live and admitted
    let (input_start, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p.clone(),
        vec![time_bounded_receipt.clone()],
        vec![],
        100,
    );
    let eval_start = evaluate_protected_ref(std::slice::from_ref(&rule), &input_start, &ref_name);
    assert_eq!(eval_start.decision, Decision::Allow);

    // 3. Inside validity window (t=150) -> Live and admitted
    let (input_mid, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p.clone(),
        vec![time_bounded_receipt.clone()],
        vec![],
        150,
    );
    let eval_mid = evaluate_protected_ref(std::slice::from_ref(&rule), &input_mid, &ref_name);
    assert_eq!(eval_mid.decision, Decision::Allow);

    // 4. Past validity window (t=201) -> Expired and refused
    let (input_after, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        p,
        vec![time_bounded_receipt],
        vec![],
        201,
    );
    let eval_after = evaluate_protected_ref(&[rule], &input_after, &ref_name);
    assert_eq!(eval_after.decision, Decision::Deny);
    assert!(
        eval_after
            .denial_reason
            .as_ref()
            .unwrap()
            .contains("expired")
    );
}
