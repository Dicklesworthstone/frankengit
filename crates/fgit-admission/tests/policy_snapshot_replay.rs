#![forbid(unsafe_code)]
//! FG-043r Retroactivity Replay Drill & Policy Bridge Tests.
//!
//! Acceptance criteria verified:
//! 1. Protection evaluation goes through fg043 PolicySnapshot (exact snapshot
//!    identity bound into verdict/decision), inline checks removed.
//! 2. A replay drill proves an old decision re-evaluates identically against its
//!    pinned snapshot after a later policy change (retroactivity negative).
//! 3. PolicySnapshotSource miss and substitution attempts fail closed with typed
//!    refusals without ambient fallback.

use std::collections::BTreeMap;

use fgit_admission::policy_bridge::persisted::{
    PolicyFrame, PolicyStageDisposition, PolicyStoreError, PolicyStoreLimits,
    evaluate_stored_policy, read_policy, stage_policy,
};
use fgit_admission::policy_bridge::{
    AuthorityPolicySource, InMemoryPolicySnapshots, PolicySnapshotSource, PolicySourceRefusal,
    SubjectCodeMap, compile_branch_protection_policy, compile_protected_branch_rules,
    evaluate_effects_protection, evaluate_protection, evaluate_receive_pack_protection,
};
use fgit_authority::{AuthorityStore, MemoryAuthorityStore, RefCommand, StoreInstanceId};
use fgit_policy::{
    AuthenticationStrength, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact,
    RefUpdateKind,
};
use fgit_reference::effect::RefEffect;
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, InternalObjectId, PrincipalId,
    PrincipalSnapshotId, RefName, RefusalCode,
};

/// Always-live cancellation probe for the policy store calls below.
const LIVE: fn() -> Result<(), RefusalCode> = || Ok(());

fn oid(byte: u8) -> GitOid {
    let hex = format!("{:02x}", byte).repeat(20);
    GitOid::from_hex(GitHashAlgorithm::Sha1, &hex).expect("valid oid hex")
}

const fn sample_principal_id() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}

fn sample_principal_snapshot_id() -> PrincipalSnapshotId {
    let digest = fgit_codec::harness::digest_of(42);
    PrincipalSnapshotId::from_internal_object_id(InternalObjectId::new(
        digest.algorithm(),
        PrincipalSnapshotId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        *digest.bytes(),
    ))
    .expect("valid principal snapshot id")
}

fn sample_input_root(
    ref_name: &[u8],
    kind: RefUpdateKind,
    force: bool,
) -> fgit_policy::PolicyInputRoot {
    let name = RefName::try_new(ref_name).expect("valid ref name");
    let (prev, next) = match kind {
        RefUpdateKind::Create => (None, Some(oid(1))),
        RefUpdateKind::Delete => (Some(oid(1)), None),
        RefUpdateKind::FastForward | RefUpdateKind::NonFastForward => (Some(oid(1)), Some(oid(2))),
    };
    let update = RefUpdateFact::try_new(name, prev, next, kind, force).expect("valid update fact");
    let principal = PrincipalFacts::try_new(
        sample_principal_id(),
        sample_principal_snapshot_id(),
        PrincipalKind::Human,
        AuthenticationStrength::MultiFactor,
        &[],
        &[],
    )
    .expect("valid principal facts");
    fgit_policy::PolicyInputRoot::try_new(
        principal,
        vec![update],
        &[],
        &[],
        PolicyInstant::from_seconds(100),
    )
    .expect("valid input root")
}

#[test]
fn in_memory_retroactivity_replay_drill() {
    // 1. Compile policy P1 (permissive baseline: protect tags from deletion, allow branches).
    let policy_p1 = fgit_policy::compile_and_seal(
        "policy repo_policy_p1 {\n    rule protect_tags {\n        when ref.name matches \"refs/tags/*\" and ref.update == delete\n        then deny \"tags cannot be deleted\"\n    }\n    default allow\n}",
    )
    .expect("policy P1 compiles");
    let p1_id = policy_p1.id();

    let mut source = InMemoryPolicySnapshots::new();
    let pinned_p1 = source.pin(policy_p1);
    assert_eq!(pinned_p1, p1_id);

    // 2. Formulate an update to refs/heads/main (create or fast-forward).
    let input_main = sample_input_root(b"refs/heads/main", RefUpdateKind::FastForward, false);
    let codes = SubjectCodeMap::default();

    // 3. Record decision D1 under policy P1.
    let verdict_d1 = evaluate_protection(&source, &p1_id, &codes, &input_main)
        .expect("evaluation under P1 succeeds");
    assert_eq!(verdict_d1.snapshot_id, p1_id);
    assert_eq!(
        verdict_d1.refusal, None,
        "policy P1 must allow fast-forward on main"
    );
    let trace_d1 = verdict_d1.trace;
    assert!(!trace_d1.is_empty(), "trace must record rule evaluation");

    // 4. Compile policy P2 (tightened later: prohibit direct pushes to main).
    let policy_p2 = fgit_policy::compile_and_seal(
        "policy repo_policy_p2 {\n    rule protect_main {\n        when ref.name matches \"refs/heads/main\"\n        then deny \"direct push to main denied\"\n    }\n    default allow\n}",
    )
    .expect("policy P2 compiles");
    let p2_id = policy_p2.id();
    assert_ne!(
        p1_id, p2_id,
        "policy P1 and P2 must have distinct identities"
    );

    let pinned_p2 = source.pin(policy_p2);
    assert_eq!(pinned_p2, p2_id);

    // 5. RETROACTIVITY REPLAY DRILL:
    // (a) Re-evaluate the identical input against P1's pinned snapshot ID.
    let replay_p1 = evaluate_protection(&source, &p1_id, &codes, &input_main)
        .expect("re-evaluation under P1 succeeds");
    assert_eq!(
        replay_p1.snapshot_id, p1_id,
        "replay must bind the exact predecessor snapshot"
    );
    assert_eq!(
        replay_p1.refusal, None,
        "replay under P1 must yield identical Allow outcome"
    );
    assert_eq!(
        replay_p1.trace, trace_d1,
        "replay under P1 must produce byte-identical rule-visit trace (retroactivity negative)"
    );

    // (b) Evaluate the same input against P2's new snapshot ID.
    let eval_p2 = evaluate_protection(&source, &p2_id, &codes, &input_main)
        .expect("evaluation under P2 succeeds");
    assert_eq!(eval_p2.snapshot_id, p2_id);
    assert_eq!(
        eval_p2.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied),
        "evaluation under tightened policy P2 must refuse"
    );
    assert_ne!(
        eval_p2.trace, trace_d1,
        "tightened policy trace must differ from historical trace"
    );
}

#[test]
fn persisted_authority_storage_retroactivity_replay() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(9901));
    let limits = PolicyStoreLimits::default();

    // 1. Stage policy P1 (allow all).
    let frame_p1 = PolicyFrame::compile("policy p1_open {\n    default allow\n}", limits, &LIVE)
        .expect("P1 compiles into frame");
    let p1_id = frame_p1.id();
    let receipt_p1 = stage_policy(&store, &frame_p1, &LIVE).expect("stage P1 succeeds");
    assert_eq!(receipt_p1.id, p1_id);
    assert_eq!(receipt_p1.disposition, PolicyStageDisposition::Created);

    let input = sample_input_root(b"refs/heads/feature", RefUpdateKind::Create, false);
    let codes = SubjectCodeMap::default();

    // 2. Evaluate under P1 on authority store.
    let verdict_p1 = evaluate_stored_policy(&store, p1_id, &input, &codes, limits, &LIVE)
        .expect("stored P1 evaluation succeeds");
    assert_eq!(verdict_p1.snapshot_id, p1_id);
    assert_eq!(verdict_p1.refusal, None);
    let trace_p1 = verdict_p1.trace;

    // 3. Stage policy P2 (tightened: deny creations).
    let frame_p2 = PolicyFrame::compile(
        "policy p2_strict {\n    rule no_create {\n        when ref.update == create\n        then deny \"creations prohibited\"\n    }\n    default allow\n}",
        limits,
        &LIVE,
    )
    .expect("P2 compiles into frame");
    let p2_id = frame_p2.id();
    assert_ne!(p1_id, p2_id);
    stage_policy(&store, &frame_p2, &LIVE).expect("stage P2 succeeds");

    // 4. Replay historical decision against P1 in authority store:
    let replay_p1 = evaluate_stored_policy(&store, p1_id, &input, &codes, limits, &LIVE)
        .expect("stored P1 replay succeeds");
    assert_eq!(replay_p1.snapshot_id, p1_id);
    assert_eq!(replay_p1.refusal, None);
    assert_eq!(
        replay_p1.trace, trace_p1,
        "persisted store replay must be byte-identical"
    );

    // 5. Evaluate same input under P2 in authority store:
    let eval_p2 = evaluate_stored_policy(&store, p2_id, &input, &codes, limits, &LIVE)
        .expect("stored P2 evaluation succeeds");
    assert_eq!(eval_p2.snapshot_id, p2_id);
    assert_eq!(
        eval_p2.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied)
    );
    assert_ne!(eval_p2.trace, trace_p1);

    // 6. Verify AuthorityPolicySource adapter:
    let auth_source = AuthorityPolicySource::new(&store);
    let snapshot_from_adapter = auth_source
        .snapshot_by_id(&p1_id)
        .expect("adapter reads P1");
    assert_eq!(snapshot_from_adapter.id(), p1_id);

    let verdict_via_adapter =
        evaluate_protection(&auth_source, &p1_id, &codes, &input).expect("adapter evaluation");
    assert_eq!(verdict_via_adapter.snapshot_id, p1_id);
    assert_eq!(verdict_via_adapter.refusal, None);
    assert_eq!(verdict_via_adapter.trace, trace_p1);
}

#[test]
fn toctou_and_substitution_fail_closed() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(9902));
    let limits = PolicyStoreLimits::default();

    let frame_p1 = PolicyFrame::compile("policy p1 { default allow }", limits, &LIVE).unwrap();
    let frame_p2 =
        PolicyFrame::compile("policy p2 { default deny \"deny\" }", limits, &LIVE).unwrap();

    let p1_id = frame_p1.id();
    let p2_id = frame_p2.id();

    // Plant P2's bytes under P1's immutable body key
    let key_p1 = fgit_authority::body_key_for_id(p1_id.as_internal_object_id()).unwrap();
    store.put_if_absent(&key_p1, frame_p2.bytes()).unwrap();

    // Reading P1 must fail with IdentityMismatch
    let read_err = read_policy(&store, p1_id, limits, &LIVE).unwrap_err();
    assert!(
        matches!(
            read_err,
            PolicyStoreError::IdentityMismatch { requested, observed }
                if *requested == p1_id && *observed == p2_id
        ),
        "substitution must fail closed with IdentityMismatch"
    );

    // Evaluation through AuthorityPolicySource must likewise fail closed
    let auth_source = AuthorityPolicySource::new(&store);
    let input = sample_input_root(b"refs/heads/main", RefUpdateKind::FastForward, false);
    let codes = SubjectCodeMap::default();

    let eval_err = evaluate_protection(&auth_source, &p1_id, &codes, &input).unwrap_err();
    assert!(
        matches!(
            eval_err,
            PolicySourceRefusal::IdentityMismatch { requested, observed }
                if *requested == p1_id && *observed == p2_id
        ),
        "adapter must fail closed on substituted identity"
    );

    // Unknown snapshot ID must fail closed with UnknownSnapshot
    let unknown_id = p2_id;
    let eval_unknown = evaluate_protection(&auth_source, &unknown_id, &codes, &input).unwrap_err();
    assert!(
        matches!(eval_unknown, PolicySourceRefusal::UnknownSnapshot { .. }),
        "unknown snapshot must fail closed"
    );
}

#[test]
fn receive_pack_and_effects_protection_bridge() {
    let mut source = InMemoryPolicySnapshots::new();
    let policy =
        compile_branch_protection_policy("refs/heads/main").expect("branch protection compiles");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let topic_ref = RefName::try_new(b"refs/heads/topic").unwrap();

    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(10));
    refs.insert(topic_ref.clone(), oid(20));

    let principal_id = sample_principal_id();
    let snapshot_id = sample_principal_snapshot_id();
    let codes = SubjectCodeMap::default();

    // 1. Receive-pack command to delete main -> refused!
    let delete_main_cmd = RefCommand {
        name: main_ref.clone(),
        expected_old: fgit_authority::ExpectedOld::Exactly(oid(10)),
        proposed_new: fgit_authority::ProposedNew::Delete,
        force: false,
    };
    let verdict_del = evaluate_receive_pack_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &[delete_main_cmd],
        PolicyInstant::from_seconds(0),
    )
    .expect("receive pack evaluation succeeds");
    assert_eq!(
        verdict_del.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied),
        "deleting main must be refused by policy"
    );
    assert_eq!(verdict_del.snapshot_id, id);

    // 2. Receive-pack command to update topic -> allowed!
    let update_topic_cmd = RefCommand {
        name: topic_ref,
        expected_old: fgit_authority::ExpectedOld::Exactly(oid(20)),
        proposed_new: fgit_authority::ProposedNew::Update(oid(21)),
        force: false,
    };
    let verdict_upd = evaluate_receive_pack_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &[update_topic_cmd],
        PolicyInstant::from_seconds(0),
    )
    .expect("receive pack evaluation succeeds");
    assert_eq!(
        verdict_upd.refusal, None,
        "updating non-protected topic must be allowed"
    );

    // 3. Effects protection on RefEffect::Delete of main -> refused!
    let mut effects = BTreeMap::new();
    effects.insert(main_ref.clone(), RefEffect::Delete);

    let verdict_effects = evaluate_effects_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &effects,
        PolicyInstant::from_seconds(0),
    )
    .expect("effects evaluation succeeds");
    assert_eq!(
        verdict_effects.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied)
    );

    // 4. Effects protection on RefEffect::Set -> allowed!
    let mut effects_set = BTreeMap::new();
    effects_set.insert(main_ref, RefEffect::Set(oid(11)));

    let verdict_set = evaluate_effects_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &effects_set,
        PolicyInstant::from_seconds(0),
    )
    .expect("effects evaluation succeeds");
    assert_eq!(verdict_set.refusal, None);
}

#[test]
fn multiple_protected_branch_rules_evaluation() {
    let mut source = InMemoryPolicySnapshots::new();
    let branches = ["main", "release", "stable"];
    let policy = compile_protected_branch_rules(branches).expect("multiple branch rules compile");
    let id = source.pin(policy);

    let main_ref = RefName::try_new(b"refs/heads/main").unwrap();
    let dev_ref = RefName::try_new(b"refs/heads/dev").unwrap();

    let mut refs = BTreeMap::new();
    refs.insert(main_ref.clone(), oid(1));
    refs.insert(dev_ref.clone(), oid(2));

    let principal_id = sample_principal_id();
    let snapshot_id = sample_principal_snapshot_id();
    let codes = SubjectCodeMap::default();

    // Push to main -> refused
    let mut effects_main = BTreeMap::new();
    effects_main.insert(main_ref, RefEffect::Set(oid(3)));

    let v_main = evaluate_effects_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &effects_main,
        PolicyInstant::from_seconds(0),
    )
    .unwrap();
    assert_eq!(
        v_main.refusal,
        Some(RefusalCode::ProtectedRefTransitionDenied)
    );

    // Push to dev -> allowed
    let mut effects_dev = BTreeMap::new();
    effects_dev.insert(dev_ref, RefEffect::Set(oid(4)));

    let v_dev = evaluate_effects_protection(
        &source,
        &id,
        &codes,
        principal_id,
        snapshot_id,
        &refs,
        &effects_dev,
        PolicyInstant::from_seconds(0),
    )
    .unwrap();
    assert_eq!(v_dev.refusal, None);
}
