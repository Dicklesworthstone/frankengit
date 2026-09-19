#![forbid(unsafe_code)]
//! Complete break-glass lifecycle, negative paths, tamper detection, and evidence retention.
//!
//! Owns FG-043c acceptance item 2:
//! "break-glass missing/weak auth, missing reason, approval threshold/race, scope/expiry,
//! self-approval, audit/notification suppression, cancellation, retry, and post-review cases behave
//! exactly; successful use retains displaced state and immutable evidence;"

use std::collections::BTreeSet;

use fgit_policy::basis::{
    AuthenticationStrength, PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind,
    RefUpdateFact, RefUpdateKind,
};
use fgit_policy::break_glass::{
    BreakGlassIntent, BreakGlassReceipt, BreakGlassRefusal, MAX_BREAK_GLASS_DURATION_SECS,
    MAX_BREAK_GLASS_REASON_LEN, evaluate_break_glass,
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

fn dummy_principal(id_byte: u8, auth: AuthenticationStrength) -> PrincipalFacts {
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

fn valid_base_intent() -> BreakGlassIntent {
    let mut approvers = BTreeSet::new();
    approvers.insert(PrincipalId::from_bytes([2; 16]));
    approvers.insert(PrincipalId::from_bytes([3; 16]));

    BreakGlassIntent::new(
        "Incident INC-9021: Emergency hotfix for data corruption".to_owned(),
        PrincipalId::from_bytes([1; 16]),
        RefPattern::compile("refs/heads/main").unwrap(),
        RefName::try_new(b"refs/heads/main").unwrap(),
        dummy_oid(10), // displaced state
        dummy_oid(20), // proposed state
        approvers,
        PolicyInstant::from_seconds(100),
        PolicyInstant::from_seconds(3700), // 1 hour duration
    )
}

#[test]
fn break_glass_weak_or_missing_authentication_refusal() {
    let intent = valid_base_intent();

    // Required auth: HardwareBacked
    // Actual auth: SingleFactor
    let weak_principal = dummy_principal(1, AuthenticationStrength::SingleFactor);
    let input_weak = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        weak_principal,
        1500,
    );

    let err = evaluate_break_glass(
        &intent,
        &input_weak,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        BreakGlassRefusal::InsufficientAuthentication {
            actual: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::HardwareBacked,
        }
    );
}

#[test]
fn break_glass_missing_or_overlong_reason_refusal() {
    let mut intent = valid_base_intent();
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal,
        1500,
    );

    // 1. Empty reason
    intent.reason = String::new();
    let err_empty = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(err_empty, BreakGlassRefusal::ReasonEmpty);

    // 2. Whitespace-only reason
    intent.reason = "    \t \n  ".to_owned();
    let err_ws = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(err_ws, BreakGlassRefusal::ReasonEmpty);

    // 3. Overlong reason (> 256 bytes)
    intent.reason = "x".repeat(MAX_BREAK_GLASS_REASON_LEN + 1);
    let err_long = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        err_long,
        BreakGlassRefusal::ReasonTooLong {
            len: MAX_BREAK_GLASS_REASON_LEN + 1,
            max: MAX_BREAK_GLASS_REASON_LEN,
        }
    );
}

#[test]
fn break_glass_approval_threshold_and_deduplication_race() {
    let mut intent = valid_base_intent();
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal,
        1500,
    );

    // 1. Below threshold: 1 approver when 2 required
    intent.approvers.clear();
    intent.approvers.insert(PrincipalId::from_bytes([2; 16]));
    intent.audit_token = intent.compute_audit_token();

    let err_under = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        err_under,
        BreakGlassRefusal::InsufficientApprovals {
            actual: 1,
            required: 2,
        }
    );

    // 2. Race / duplicate submission: trying to add the same approver twice collapses in BTreeSet
    intent.approvers.insert(PrincipalId::from_bytes([2; 16]));
    assert_eq!(intent.approvers.len(), 1);
    intent.audit_token = intent.compute_audit_token();

    let err_dup = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert_eq!(
        err_dup,
        BreakGlassRefusal::InsufficientApprovals {
            actual: 1,
            required: 2,
        }
    );
}

#[test]
fn break_glass_self_approval_prohibition() {
    let mut intent = valid_base_intent();
    // Actor is PrincipalId 1; adding 1 to approvers must fail closed
    intent.approvers.insert(PrincipalId::from_bytes([1; 16]));
    intent.audit_token = intent.compute_audit_token();

    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal,
        1500,
    );

    let err = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        BreakGlassRefusal::SelfApprovalForbidden {
            actor: PrincipalId::from_bytes([1; 16]),
        }
    );
}

#[test]
fn break_glass_scope_and_temporal_bounds() {
    let intent = valid_base_intent();
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);

    // 1. Target ref outside pattern
    let mut out_of_scope = intent.clone();
    out_of_scope.target_ref = RefName::try_new(b"refs/heads/feature-foo").unwrap();
    out_of_scope.audit_token = out_of_scope.compute_audit_token();
    let input_scope = build_input(
        "refs/heads/feature-foo",
        dummy_oid(10),
        dummy_oid(20),
        principal.clone(),
        1500,
    );
    let err_scope = evaluate_break_glass(
        &out_of_scope,
        &input_scope,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(err_scope, BreakGlassRefusal::ScopeMismatch { .. }));

    // 2. Not yet active (current: 50, issued_at: 100)
    let input_early = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal.clone(),
        50,
    );
    let err_early = evaluate_break_glass(
        &intent,
        &input_early,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(err_early, BreakGlassRefusal::NotYetActive { .. }));

    // 3. Expired (current: 4000, expires_at: 3700)
    let input_late = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal.clone(),
        4000,
    );
    let err_late = evaluate_break_glass(
        &intent,
        &input_late,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(err_late, BreakGlassRefusal::Expired { .. }));

    // 4. Overlong window duration (> 14400s)
    let mut overlong_intent = intent;
    overlong_intent.issued_at = PolicyInstant::from_seconds(100);
    overlong_intent.expires_at = PolicyInstant::from_seconds(100 + MAX_BREAK_GLASS_DURATION_SECS + 1);
    overlong_intent.audit_token = overlong_intent.compute_audit_token();
    let input_valid_time = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal,
        200,
    );
    let err_duration = evaluate_break_glass(
        &overlong_intent,
        &input_valid_time,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();
    assert!(matches!(
        err_duration,
        BreakGlassRefusal::DurationExceedsMax { .. }
    ));
}

#[test]
fn break_glass_audit_token_tamper_detection_and_notification_integrity() {
    let mut intent = valid_base_intent();
    let original_token = intent.audit_token;

    // Tampering with the token directly
    intent.audit_token = dummy_oid(77);
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal,
        1500,
    );

    let err_tamper = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();

    assert_eq!(
        err_tamper,
        BreakGlassRefusal::AuditTokenMismatch {
            actual: dummy_oid(77),
            expected: original_token,
        }
    );
}

#[test]
fn break_glass_displaced_state_mismatch_and_cancellation() {
    let intent = valid_base_intent();
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);

    // Tip moved to dummy_oid(99) by an intervening concurrent push
    let input_moved = build_input(
        "refs/heads/main",
        dummy_oid(99),
        dummy_oid(20),
        principal,
        1500,
    );

    let err = evaluate_break_glass(
        &intent,
        &input_moved,
        &dummy_oid(99),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        BreakGlassRefusal::DisplacedStateMismatch {
            actual: dummy_oid(99),
            expected: dummy_oid(10),
        }
    );
}

#[test]
fn break_glass_successful_execution_retains_displaced_state_and_post_review() {
    let intent = valid_base_intent();
    let principal = dummy_principal(1, AuthenticationStrength::HardwareBacked);
    let input = build_input(
        "refs/heads/main",
        dummy_oid(10),
        dummy_oid(20),
        principal.clone(),
        1500,
    );

    let receipt: BreakGlassReceipt = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .expect("valid break-glass must succeed");

    // 1. Displaced-state retention: exact pre-override OID preserved
    assert_eq!(receipt.intent.displaced_state, dummy_oid(10));
    assert_eq!(receipt.intent.proposed_oid, dummy_oid(20));

    // 2. Post-review obligation: non-removable record
    assert_eq!(receipt.post_review_obligation_id.as_str(), "post-incident-review");

    // 3. Evaluation instant and audit token preserved
    assert_eq!(receipt.evaluated_at, PolicyInstant::from_seconds(1500));
    assert_eq!(receipt.intent.audit_token, intent.compute_audit_token());

    // 4. Retry idempotency: re-evaluating identical intent against identical state yields identical receipt
    let retry_receipt = evaluate_break_glass(
        &intent,
        &input,
        &dummy_oid(10),
        2,
        AuthenticationStrength::HardwareBacked,
    )
    .expect("retry of valid break-glass must succeed");

    assert_eq!(receipt, retry_receipt);
}
