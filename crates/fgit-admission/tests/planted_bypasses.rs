#![forbid(unsafe_code)]
//! Tests proving planted inline-bypass defects in receive-pack and merge protection are caught.
//!
//! Owns FG-043c acceptance item 5:
//! "receive-pack and merge planted inline-bypass defects are caught;
//!  replay of an old decision retains its original policy snapshot/reason after policy changes"

use std::collections::BTreeMap;

use fgit_admission::CanonicalRefState;
use fgit_admission::policy_bridge::{
    InMemoryPolicySnapshots, MissingAdmissionFact, PolicySourceRefusal, SubjectCodeMap,
    compile_branch_protection_policy,
    compile_protected_branch_rules, default_principal_snapshot_id, evaluate_effects_protection,
    evaluate_protection, evaluate_receive_pack_protection,
};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_reference::effect::RefEffect;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode};

fn oid(byte: u8) -> GitOid {
    let hex = format!("{:02x}", byte).repeat(20);
    GitOid::from_hex(GitHashAlgorithm::Sha1, &hex).expect("valid oid hex")
}

const fn sample_principal_id() -> PrincipalId {
    PrincipalId::from_bytes([9; 16])
}

#[test]
fn planted_bypass_receive_pack_force_push_on_protected_ref_is_caught() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy = fgit_policy::compile_and_seal(
        r#"policy protect_main_force {
    rule deny_force {
        when ref.name matches "refs/heads/main" and ref.force_requested
        then deny "force update is prohibited on protected branch"
    }
    default allow
}"#,
    )
    .expect("compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));

    // Adversary plants a force update command on refs/heads/main
    let force_cmd = RefCommand {
        name: main_ref,
        expected_old: ExpectedOld::Exactly(oid(10)),
        proposed_new: ProposedNew::Update(oid(20)),
        force: true,
    };

    let verdict = evaluate_receive_pack_protection(
        &source,
        &id,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &[force_cmd],
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("receive pack evaluation succeeds");

    assert_eq!(
        verdict.refusal,
        Some(RefusalCode::ForceNotPermitted),
        "planted bypass defect: force push to protected ref was not caught!"
    );
    assert_eq!(verdict.snapshot_id, id);
}

#[test]
fn planted_bypass_receive_pack_non_fast_forward_on_protected_ref_is_caught() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy = fgit_policy::compile_and_seal(
        r#"policy protect_main_ff {
    rule deny_non_ff {
        when ref.name matches "refs/heads/main" and ref.update == non_fast_forward
        then deny "non_fast_forward update is prohibited on protected branch"
    }
    default allow
}"#,
    )
    .expect("compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));

    // A force request is not an ancestry witness. Either force value must
    // fail closed in the reference-only adapter, not synthesize a graph fact.
    for force in [false, true] {
        let command = RefCommand {
            name: main_ref.clone(),
            expected_old: ExpectedOld::Exactly(oid(10)),
            proposed_new: ProposedNew::Update(oid(20)),
            force,
        };
        assert_eq!(
            evaluate_receive_pack_protection(
                &source,
                &id,
                &SubjectCodeMap::default(),
                sample_principal_id(),
                default_principal_snapshot_id(),
                &refs,
                &[command],
                fgit_policy::PolicyInstant::from_seconds(100),
            )
            .unwrap_err(),
            PolicySourceRefusal::MissingAdmissionFacts {
                id: id.to_string(),
                fact: MissingAdmissionFact::VerifiedAncestry,
            }
        );
    }

    // Model explicit ancestry facts, independently of the force flag. This is
    // evaluator coverage, not a graph-validation or live receive campaign.
    for kind in [
        fgit_policy::RefUpdateKind::FastForward,
        fgit_policy::RefUpdateKind::NonFastForward,
    ] {
        let update = fgit_policy::RefUpdateFact::try_new(
            main_ref.clone(),
            Some(oid(10)),
            Some(oid(20)),
            kind,
            false,
        )
        .unwrap();
        let principal = fgit_policy::PrincipalFacts::try_new(
            sample_principal_id(),
            default_principal_snapshot_id(),
            fgit_policy::PrincipalKind::Machine,
            fgit_policy::AuthenticationStrength::SingleFactor,
            &[],
            &[],
        )
        .unwrap();
        let input = fgit_policy::PolicyInputRoot::try_new(
            principal,
            vec![update],
            &[],
            &[],
            fgit_policy::PolicyInstant::from_seconds(100),
        )
        .unwrap();
        let verdict = evaluate_protection(&source, &id, &SubjectCodeMap::default(), &input)
            .expect("complete-input evaluation succeeds");
        assert_eq!(
            verdict.refusal,
            if kind == fgit_policy::RefUpdateKind::NonFastForward {
                Some(RefusalCode::NonFastForwardRefused)
            } else {
                None
            }
        );
        assert_eq!(verdict.snapshot_id, id);
    }
}

#[test]
fn planted_bypass_receive_pack_deletion_on_protected_ref_is_caught() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy = compile_branch_protection_policy("refs/heads/main").expect("compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));

    // Adversary plants a delete command on refs/heads/main
    let delete_cmd = RefCommand {
        name: main_ref,
        expected_old: ExpectedOld::Exactly(oid(10)),
        proposed_new: ProposedNew::Delete,
        force: false,
    };

    let verdict = evaluate_receive_pack_protection(
        &source,
        &id,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &[delete_cmd],
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("receive pack evaluation succeeds");

    assert_eq!(
        verdict.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied),
        "planted bypass defect: deletion of protected ref was not caught!"
    );
    assert_eq!(verdict.snapshot_id, id);
}

#[test]
fn planted_bypass_canonical_ref_state_apply_force_update_is_refused() {
    let main_ref = RefName::try_new(b"refs/heads/main").expect("valid ref name");
    let mut initial_refs = BTreeMap::new();
    initial_refs.insert(main_ref.clone(), oid(10));

    let state = CanonicalRefState::new_with_head_target(initial_refs, main_ref.clone())
        .expect("valid initial ref state");

    // Planted bypass attempt: apply a RefEffect::Delete to HEAD target
    let mut effects = BTreeMap::new();
    effects.insert(main_ref, RefEffect::Delete);

    let outcome = state.apply(&effects);
    assert_eq!(
        outcome,
        Err(RefusalCode::ProtectedRefTransitionDenied),
        "planted bypass defect: CanonicalRefState::apply admitted deletion of protected HEAD target!"
    );
}

#[test]
fn planted_bypass_effects_protection_catches_unadmitted_updates() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy = compile_protected_branch_rules(["main"]).expect("compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let feature_ref = RefName::try_new(b"refs/heads/feature").unwrap();

    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));
    refs.insert(feature_ref.clone(), oid(20));

    // 1. Delete on protected main -> refused
    let mut del_effects = BTreeMap::new();
    del_effects.insert(main_ref, RefEffect::Delete);
    let eval_del = evaluate_effects_protection(
        &source,
        &id,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &del_effects,
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("eval succeeds");
    assert_eq!(
        eval_del.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied),
        "delete on protected main must be refused"
    );

    // 2. Update on feature branch -> admitted (unprotected)
    let mut feat_effects = BTreeMap::new();
    feat_effects.insert(feature_ref, RefEffect::Set(oid(21)));
    let eval_feat = evaluate_effects_protection(
        &source,
        &id,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &feat_effects,
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("eval succeeds");
    assert_eq!(
        eval_feat.refusal, None,
        "update on feature branch must be admitted"
    );
}

#[test]
fn planted_bypass_historical_snapshot_replay_invariance() {
    let mut source = InMemoryPolicySnapshots::new();

    // Snapshot A: allows updates to feature branch
    let policy_a = compile_branch_protection_policy("refs/heads/main").expect("compiles");
    let id_a = source.pin(policy_a);

    // Snapshot B: stricter policy denying all updates
    let policy_b = fgit_policy::compile_and_seal(
        r#"policy strict_deny_all {
  rule deny_all {
    when true
    then deny "all updates denied"
  }
  default deny "deny by default"
}"#,
    )
    .expect("compiles");
    let id_b = source.pin(policy_b);
    assert_ne!(id_a, id_b);

    let topic_ref = RefName::try_new(b"refs/heads/topic").unwrap();
    let mut refs = BTreeMap::new();
    refs.insert(topic_ref.clone(), oid(20));

    let update_cmd = RefCommand {
        name: topic_ref,
        expected_old: ExpectedOld::Exactly(oid(20)),
        proposed_new: ProposedNew::Update(oid(21)),
        force: false,
    };

    // Decision at time of transaction: evaluated under Snapshot A -> admitted!
    let historical_verdict = evaluate_receive_pack_protection(
        &source,
        &id_a,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        std::slice::from_ref(&update_cmd),
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("eval succeeds");
    assert_eq!(historical_verdict.refusal, None);
    assert_eq!(historical_verdict.snapshot_id, id_a);

    // Later: Policy B is current. Replaying historical decision against its pinned Snapshot A
    // must evaluate identically to the original decision, NOT to the new Policy B decision!
    let replay_verdict = evaluate_receive_pack_protection(
        &source,
        &id_a,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        std::slice::from_ref(&update_cmd),
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("replay eval succeeds");
    assert_eq!(
        replay_verdict, historical_verdict,
        "historical replay must be identical against pinned snapshot"
    );

    // Contrast: evaluating the same command under current Snapshot B produces denial
    let current_verdict = evaluate_receive_pack_protection(
        &source,
        &id_b,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &[update_cmd],
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("current eval succeeds");
    assert!(
        current_verdict.refusal.is_some(),
        "under strict Policy B the update is denied"
    );
    assert_eq!(current_verdict.snapshot_id, id_b);
}

#[test]
fn planted_bypass_merge_protection_direct_push_violation_is_caught() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy = compile_protected_branch_rules(["main"]).expect("compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));

    // Adversary attempts direct push/merge update to protected main
    let mut direct_merge_effects = BTreeMap::new();
    direct_merge_effects.insert(main_ref, RefEffect::Set(oid(12)));

    let verdict = evaluate_effects_protection(
        &source,
        &id,
        &SubjectCodeMap::default(),
        sample_principal_id(),
        default_principal_snapshot_id(),
        &refs,
        &direct_merge_effects,
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .expect("eval succeeds");

    assert_eq!(
        verdict.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied),
        "planted bypass defect: direct merge push violation on protected branch was not caught!"
    );
    assert_eq!(verdict.snapshot_id, id);
}
