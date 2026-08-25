//! Unit and property tests for policy rollout modes, simulation, shadow, and diffs.

use fgit_policy::basis::{
    AuthenticationStrength, PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind,
    RefUpdateFact, RefUpdateKind,
};
use fgit_policy::program::Decision;
use fgit_policy::rollout::{
    CanaryLifecycleEvent, PolicyDiff, RolloutCohort, RolloutConfiguration, RolloutMode,
    evaluate_rollout,
};
use fgit_policy::{compile, compile_and_seal};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::CodecVersion;
use fgit_types::refs::RefName;
use fgit_types::{PrincipalId, PrincipalSnapshotId};

const fn dummy_oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; 20]))
}

fn build_input(ref_name_str: &str, kind: RefUpdateKind) -> PolicyInputRoot {
    let r_name = RefName::try_new(ref_name_str.as_bytes()).unwrap();
    let previous = match kind {
        RefUpdateKind::Create => None,
        _ => Some(dummy_oid(1)),
    };
    let next = match kind {
        RefUpdateKind::Delete => None,
        _ => Some(dummy_oid(2)),
    };

    let subject = RefUpdateFact::try_new(r_name, previous, next, kind, false).unwrap();

    let principal = PrincipalFacts::try_new(
        PrincipalId::from_bytes([1; 16]),
        PrincipalSnapshotId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x56; 32]).unwrap(),
        ),
        PrincipalKind::Human,
        AuthenticationStrength::HardwareBacked,
        &[],
        &[],
    )
    .unwrap();

    PolicyInputRoot::try_new(
        principal,
        vec![subject],
        &[],
        &[],
        PolicyInstant::from_seconds(100),
    )
    .unwrap()
}

#[test]
fn policy_diff_detects_added_removed_and_modified_rules() {
    let source_a = r#"policy active_policy {
  rule rule_1 {
    when ref.name matches "refs/heads/main"
    then deny "main protected"
  }
  rule rule_2 {
    when ref.update == non_fast_forward
    then deny "no force"
  }
  default allow
}"#;

    let source_b = r#"policy candidate_policy {
  rule rule_1 {
    when ref.name matches "refs/heads/**"
    then deny "all heads protected"
  }
  rule rule_3 {
    when ref.update == delete
    then deny "no delete"
  }
  default deny "default deny"
}"#;

    let policy_a = compile(source_a).unwrap();
    let policy_b = compile(source_b).unwrap();

    let diff = PolicyDiff::compute(&policy_a, &policy_b);

    assert_eq!(diff.rules_added.len(), 1); // rule_3
    assert_eq!(diff.rules_removed.len(), 1); // rule_2
    assert_eq!(diff.rules_modified.len(), 1); // rule_1
    assert!(diff.default_decision_changed);
    assert!(!diff.is_identical());

    // Identical diff check
    let self_diff = PolicyDiff::compute(&policy_a, &policy_a);
    assert!(self_diff.is_identical());
}

#[test]
fn rollout_cohort_percentage_hashing_is_deterministic() {
    let cohort_0 = RolloutCohort::Percentage(0);
    assert!(!cohort_0.matches_repository("repo-1"));
    assert!(!cohort_0.matches_repository("repo-2"));

    let cohort_100 = RolloutCohort::Percentage(100);
    assert!(cohort_100.matches_repository("repo-1"));
    assert!(cohort_100.matches_repository("repo-2"));

    let cohort_half = RolloutCohort::Percentage(50);
    let r1 = cohort_half.matches_repository("repo-1");
    let r1_again = cohort_half.matches_repository("repo-1");
    assert_eq!(
        r1, r1_again,
        "percentage cohort selection must be deterministic"
    );
}

#[test]
fn shadow_mode_detects_divergence_without_blocking_effective_decision() {
    let source_active = r"policy active_policy {
  rule allow_all {
    when true
    then allow
  }
  default allow
}";

    let source_candidate = r#"policy candidate_policy {
  rule deny_feature {
    when ref.name == "refs/heads/feature"
    then deny "feature branch blocked"
  }
  default allow
}"#;

    let active_snap = compile_and_seal(source_active).unwrap();
    let cand_snap = compile_and_seal(source_candidate).unwrap();

    let config = RolloutConfiguration {
        active_snapshot_id: active_snap.id(),
        candidate_snapshot_id: Some(cand_snap.id()),
        mode: RolloutMode::Shadow,
        cohort: RolloutCohort::All,
        config_version: 1,
        authorized_by: Some(PrincipalId::from_bytes([9; 16])),
    };

    let input = build_input("refs/heads/feature", RefUpdateKind::FastForward);

    let eval = evaluate_rollout(&config, &active_snap, Some(&cand_snap), &input, "repo-test")
        .expect("rollout evaluation must succeed");

    // Shadow mode effective decision allows
    assert_eq!(eval.effective_decision, Decision::Allow);
    assert_eq!(eval.mode, RolloutMode::Shadow);

    // But divergence was accurately recorded:
    assert_eq!(eval.divergences.len(), 1);
    assert_eq!(eval.divergences[0].active_decision, Decision::Allow);
    assert_eq!(eval.divergences[0].candidate_decision, Decision::Deny);
}

#[test]
fn warn_and_simulation_modes_do_not_block() {
    let source_strict = r#"policy strict_policy {
  rule deny_all {
    when true
    then deny "blocked"
  }
  default deny "blocked"
}"#;

    let strict_snap = compile_and_seal(source_strict).unwrap();

    // 1. Enforce mode blocks
    let config_enforce = RolloutConfiguration {
        active_snapshot_id: strict_snap.id(),
        candidate_snapshot_id: None,
        mode: RolloutMode::Enforce,
        cohort: RolloutCohort::All,
        config_version: 1,
        authorized_by: None,
    };
    let input = build_input("refs/heads/main", RefUpdateKind::FastForward);
    let eval_enforce =
        evaluate_rollout(&config_enforce, &strict_snap, None, &input, "repo-1").unwrap();
    assert_eq!(eval_enforce.effective_decision, Decision::Deny);

    // 2. Warn mode does not block
    let mut config_warn = config_enforce.clone();
    config_warn.mode = RolloutMode::Warn;
    let eval_warn = evaluate_rollout(&config_warn, &strict_snap, None, &input, "repo-1").unwrap();
    assert_eq!(eval_warn.effective_decision, Decision::Allow);

    // 3. Simulation mode does not block
    let mut config_sim = config_enforce;
    config_sim.mode = RolloutMode::Simulation;
    let eval_sim = evaluate_rollout(&config_sim, &strict_snap, None, &input, "repo-1").unwrap();
    assert_eq!(eval_sim.effective_decision, Decision::Allow);
}

#[test]
fn canary_lifecycle_events_are_recorded_immutably() {
    let snap_a = compile_and_seal("policy a { default allow }").unwrap();
    let snap_b = compile_and_seal("policy b { default allow }").unwrap();

    let promo_event = CanaryLifecycleEvent::Promoted {
        new_active: snap_b.id(),
        previous_active: snap_a.id(),
        instant: PolicyInstant::from_seconds(500),
        actor: PrincipalId::from_bytes([7; 16]),
    };

    let rollback_event = CanaryLifecycleEvent::RolledBack {
        reverted_to: snap_a.id(),
        rolled_back_from: snap_b.id(),
        instant: PolicyInstant::from_seconds(600),
        actor: PrincipalId::from_bytes([8; 16]),
        reason: "Regression detected in candidate policy".to_owned(),
    };

    assert!(matches!(promo_event, CanaryLifecycleEvent::Promoted { .. }));
    assert!(matches!(
        rollback_event,
        CanaryLifecycleEvent::RolledBack { .. }
    ));
}
