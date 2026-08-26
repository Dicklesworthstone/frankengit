//! Unit, property, and planted negative tests for the break-glass override protocol.

use std::collections::BTreeSet;

use fgit_policy::basis::{
    AuthenticationStrength, PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind,
    RefUpdateFact, RefUpdateKind,
};
use fgit_policy::break_glass::{
    BreakGlassIntent, BreakGlassRefusal, MAX_BREAK_GLASS_DURATION_SECS, evaluate_break_glass,
};
use fgit_policy::glob::RefPattern;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::CodecVersion;
use fgit_types::refs::RefName;
use fgit_types::{PrincipalId, PrincipalSnapshotId};

const fn dummy_oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; 20]))
}

fn dummy_principal(auth: AuthenticationStrength, id_byte: u8) -> PrincipalFacts {
    PrincipalFacts::try_new(
        PrincipalId::from_bytes([id_byte; 16]),
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
    current_oid: GitOid,
    proposed_oid: GitOid,
    principal: PrincipalFacts,
    instant: u64,
) -> PolicyInputRoot {
    let r_name = RefName::try_new(ref_name_str.as_bytes()).unwrap();
    let subject = RefUpdateFact::try_new(
        r_name,
        Some(current_oid),
        Some(proposed_oid),
        RefUpdateKind::NonFastForward,
        true,
    )
    .unwrap();

    PolicyInputRoot::try_new(
        principal,
        vec![subject],
        &[],
        &[],
        PolicyInstant::from_seconds(instant),
    )
    .unwrap()
}

fn valid_intent() -> BreakGlassIntent {
    let mut approvers = BTreeSet::new();
    approvers.insert(PrincipalId::from_bytes([2; 16]));
    approvers.insert(PrincipalId::from_bytes([3; 16]));

    BreakGlassIntent::new(
        "Incident INC-4029: Rollback compromised binary".to_owned(),
        PrincipalId::from_bytes([1; 16]),
        RefPattern::compile("refs/heads/main").unwrap(),
        RefName::try_new(b"refs/heads/main").unwrap(),
        dummy_oid(1),
        dummy_oid(2),
        approvers,
        PolicyInstant::from_seconds(100),
        PolicyInstant::from_seconds(3700), // 1 hour duration
    )
}

#[test]
fn a_valid_break_glass_intent_evaluates_to_a_receipt() {
    let intent = valid_intent();
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);

    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500, // within [100, 3700]
    );

    let receipt = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .expect("valid break glass must evaluate successfully");

    assert_eq!(receipt.intent, intent);
    assert_eq!(receipt.evaluated_at, PolicyInstant::from_seconds(1500));
    assert_eq!(
        receipt.post_review_obligation_id.as_str(),
        "post-incident-review"
    );
}

#[test]
fn empty_or_overlong_reason_is_refused() {
    let mut intent = valid_intent();
    intent.reason = "   ".to_owned();

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500,
    );

    let refusal = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(refusal, BreakGlassRefusal::ReasonEmpty);
}

#[test]
fn expired_or_not_yet_active_intent_is_refused() {
    let intent = valid_intent();
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);

    // 1. Not yet active (current: 50, issued_at: 100)
    let input_early = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal.clone(),
        50,
    );
    let early_err = evaluate_break_glass(
        &intent,
        &input_early,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(early_err, BreakGlassRefusal::NotYetActive { .. }));

    // 2. Expired (current: 4000, expires_at: 3700)
    let input_late = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        4000,
    );
    let late_err = evaluate_break_glass(
        &intent,
        &input_late,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(late_err, BreakGlassRefusal::Expired { .. }));
}

#[test]
fn duration_exceeding_max_bound_is_refused() {
    let mut intent = valid_intent();
    intent.issued_at = PolicyInstant::from_seconds(0);
    intent.expires_at = PolicyInstant::from_seconds(MAX_BREAK_GLASS_DURATION_SECS + 1);

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        100,
    );

    let refusal = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(
        refusal,
        BreakGlassRefusal::DurationExceedsMax { .. }
    ));
}

#[test]
fn self_approval_is_strictly_forbidden() {
    let mut intent = valid_intent();
    // Actor attempts to add themselves (id 1) to approvers list
    intent.approvers.insert(PrincipalId::from_bytes([1; 16]));
    intent.audit_token = intent.compute_audit_token();

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500,
    );

    let refusal = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        BreakGlassRefusal::SelfApprovalForbidden {
            actor: PrincipalId::from_bytes([1; 16])
        }
    );
}

#[test]
fn insufficient_threshold_approvals_is_refused() {
    let mut intent = valid_intent();
    intent.approvers.clear();
    intent.approvers.insert(PrincipalId::from_bytes([2; 16])); // only 1 approver
    intent.audit_token = intent.compute_audit_token();

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500,
    );

    let refusal = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        BreakGlassRefusal::InsufficientApprovals {
            actual: 1,
            required: 2
        }
    );
}

#[test]
fn scope_and_displaced_state_mismatches_are_refused() {
    let intent = valid_intent();
    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);

    // 1. Displaced state mismatch (current tip is dummy_oid(3), expected dummy_oid(1))
    let input_displaced = build_input(
        "refs/heads/main",
        dummy_oid(3),
        dummy_oid(2),
        principal.clone(),
        1500,
    );
    let disp_err = evaluate_break_glass(
        &intent,
        &input_displaced,
        &dummy_oid(3),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        disp_err,
        BreakGlassRefusal::DisplacedStateMismatch {
            actual: dummy_oid(3),
            expected: dummy_oid(1),
        }
    );

    // 2. Scope mismatch (intent target ref changed outside scope pattern)
    let mut bad_scope_intent = intent;
    bad_scope_intent.target_ref = RefName::try_new(b"refs/heads/other-branch").unwrap();
    bad_scope_intent.audit_token = bad_scope_intent.compute_audit_token();
    let input_scope = build_input(
        "refs/heads/other-branch",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500,
    );
    let scope_err = evaluate_break_glass(
        &bad_scope_intent,
        &input_scope,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(scope_err, BreakGlassRefusal::ScopeMismatch { .. }));
}

#[test]
fn mismatched_audit_token_is_refused() {
    let mut intent = valid_intent();
    let original_token = intent.audit_token;
    intent.audit_token = dummy_oid(99);

    let principal = dummy_principal(AuthenticationStrength::HardwareBacked, 1);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(1),
        dummy_oid(2),
        principal,
        1500,
    );

    let err = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(1),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        BreakGlassRefusal::AuditTokenMismatch {
            actual: dummy_oid(99),
            expected: original_token,
        }
    );
}
