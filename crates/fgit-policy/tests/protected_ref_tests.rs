//! Unit and property tests for protected ref rule evaluation.

use std::collections::BTreeSet;

use fgit_policy::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, EvidenceReceipt, IssuerLabel,
    PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind,
};
use fgit_policy::glob::RefPattern;
use fgit_policy::program::Decision;
use fgit_policy::protected_ref::{
    ProtectedRefRule, StatusCheckRequirement, evaluate_protected_ref,
};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::CodecVersion;
use fgit_types::refs::RefName;
use fgit_types::{PrincipalId, PrincipalSnapshotId};

const fn dummy_oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; 20]))
}

fn dummy_receipt(
    kind: EvidenceKind,
    target_ref: &RefName,
    issued: u64,
    expires: u64,
) -> EvidenceReceipt {
    EvidenceReceipt::try_new(
        kind,
        IssuerLabel::from_static("test.service"),
        target_ref.clone(),
        PolicyInstant::from_seconds(issued),
        PolicyInstant::from_seconds(expires),
    )
    .unwrap()
}

fn dummy_principal(auth: AuthenticationStrength) -> PrincipalFacts {
    PrincipalFacts::try_new(
        PrincipalId::from_bytes([1; 16]),
        PrincipalSnapshotId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x56; 32]).unwrap(),
        ),
        PrincipalKind::Human,
        auth,
        &[],
        &[],
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

#[test]
fn unprotected_refs_are_allowed_by_default() {
    let rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    let principal = dummy_principal(AuthenticationStrength::SingleFactor);

    let (input, ref_name) = build_input(
        "refs/heads/feature",
        RefUpdateKind::FastForward,
        false,
        principal,
        vec![],
        vec![],
        100,
    );

    let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
    assert_eq!(eval.decision, Decision::Allow);
    assert!(!eval.is_protected);
}

#[test]
fn force_push_and_deletions_are_prohibited_on_protected_branch() {
    let rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked);

    // 1. Force push attempt
    let (input_force, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::NonFastForward,
        true,
        principal.clone(),
        vec![],
        vec![],
        100,
    );
    let eval_force = evaluate_protected_ref(std::slice::from_ref(&rule), &input_force, &ref_name);
    assert_eq!(eval_force.decision, Decision::Deny);
    assert!(eval_force.is_protected);
    assert!(
        eval_force
            .denial_reason
            .unwrap()
            .contains("force push to protected ref is prohibited")
    );

    // 2. Deletion attempt
    let (input_del, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::Delete,
        false,
        principal,
        vec![],
        vec![],
        100,
    );
    let eval_del = evaluate_protected_ref(&[rule], &input_del, &ref_name);
    assert_eq!(eval_del.decision, Decision::Deny);
    assert!(eval_del.is_protected);
    assert!(
        eval_del
            .denial_reason
            .unwrap()
            .contains("deletion of protected ref is prohibited")
    );
}

#[test]
fn non_fast_forward_is_refused_when_fast_forward_is_required() {
    let rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked);

    let (input, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::NonFastForward,
        false,
        principal,
        vec![],
        vec![],
        100,
    );
    let eval = evaluate_protected_ref(&[rule], &input, &ref_name);
    assert_eq!(eval.decision, Decision::Deny);
    assert!(
        eval.denial_reason
            .unwrap()
            .contains("non-fast-forward update refused")
    );
}

#[test]
fn code_reviews_and_ci_checks_are_enforced_with_receipts() {
    let mut rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    let mut checks = BTreeSet::new();
    checks.insert(fgit_types::AsciiSlug::from_static("build-and-test"));
    rule.checks = Some(StatusCheckRequirement {
        required_checks: checks,
        strict_up_to_date: true,
    });

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked);
    let r_name = RefName::try_new(b"refs/heads/main").unwrap();

    // Missing reviews & checks
    let (input_missing, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        principal.clone(),
        vec![],
        vec![],
        100,
    );
    let eval_missing =
        evaluate_protected_ref(std::slice::from_ref(&rule), &input_missing, &ref_name);
    assert_eq!(eval_missing.decision, Decision::Deny);

    // With valid reviews and CI receipts
    let review_receipt = dummy_receipt(EvidenceKind::from_static("code_review"), &r_name, 50, 200);
    let ci_receipt = dummy_receipt(EvidenceKind::from_static("ci_check"), &r_name, 50, 200);

    let (input_valid, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        principal,
        vec![review_receipt, ci_receipt],
        vec![],
        100,
    );
    let eval_valid = evaluate_protected_ref(&[rule], &input_valid, &ref_name);
    assert_eq!(eval_valid.decision, Decision::Allow);
}

#[test]
fn unresolved_findings_block_protected_ref_updates() {
    let rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked);
    let r_name = RefName::try_new(b"refs/heads/main").unwrap();

    let review_receipt = dummy_receipt(EvidenceKind::from_static("code_review"), &r_name, 50, 200);

    // 2 unresolved findings
    let (input_blocked, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        principal.clone(),
        vec![review_receipt.clone()],
        vec![("unresolved_findings", 2)],
        100,
    );
    let eval_blocked =
        evaluate_protected_ref(std::slice::from_ref(&rule), &input_blocked, &ref_name);
    assert_eq!(eval_blocked.decision, Decision::Deny);
    assert!(
        eval_blocked
            .denial_reason
            .unwrap()
            .contains("blocked by 2 unresolved security findings")
    );

    // 0 unresolved findings
    let (input_clean, ref_name) = build_input(
        "refs/heads/main",
        RefUpdateKind::FastForward,
        false,
        principal,
        vec![review_receipt],
        vec![("unresolved_findings", 0)],
        100,
    );
    let eval_clean = evaluate_protected_ref(&[rule], &input_clean, &ref_name);
    assert_eq!(eval_clean.decision, Decision::Allow);
}

#[test]
fn immutable_tags_refuse_updates_and_deletions() {
    let rule = ProtectedRefRule::immutable_tag(RefPattern::compile("refs/tags/**").unwrap());
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked);

    // 1. Tag deletion attempt
    let (input_del, ref_name) = build_input(
        "refs/tags/v1.0.0",
        RefUpdateKind::Delete,
        false,
        principal.clone(),
        vec![],
        vec![],
        100,
    );
    let eval_del = evaluate_protected_ref(std::slice::from_ref(&rule), &input_del, &ref_name);
    assert_eq!(eval_del.decision, Decision::Deny);

    // 2. Tag force update attempt
    let (input_force, ref_name) = build_input(
        "refs/tags/v1.0.0",
        RefUpdateKind::NonFastForward,
        true,
        principal.clone(),
        vec![],
        vec![],
        100,
    );
    let eval_force = evaluate_protected_ref(std::slice::from_ref(&rule), &input_force, &ref_name);
    assert_eq!(eval_force.decision, Decision::Deny);

    // 3. New tag creation
    let (input_create, ref_name) = build_input(
        "refs/tags/v1.0.0",
        RefUpdateKind::Create,
        false,
        principal,
        vec![],
        vec![],
        100,
    );
    let eval_create = evaluate_protected_ref(&[rule], &input_create, &ref_name);
    assert_eq!(eval_create.decision, Decision::Allow);
}
