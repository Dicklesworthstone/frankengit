//! Real embedded-node composition, not a planner-only oracle. The imported
//! source moves `text` to `moved`; the target independently edits its content.
use super::*;
use super::tests::{fixture, fixture_with_rename, metadata};
use fgit_admission::AdmissionLimits;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, PrincipalId};

fn references() -> (RefName, RefName) {
    (RefName::try_new(b"refs/heads/main").unwrap(), RefName::try_new(b"refs/heads/topic").unwrap())
}
fn prepare(node: &OneNode, profile: MergeProfile) -> PreparedMergeBundle {
    let request = node.request_context();
    let (target, incoming) = references();
    node.runtime().block_on(node.prepare_merge_bundle_with_profile_in(
        &request, &target, &incoming, &RefVisibility::new(), &metadata(),
        PreparationLimits::default(), profile,
    )).unwrap()
}
fn principal() -> PrincipalId { PrincipalId::from_bytes([0x73; 16]) }
fn session(key: &[u8]) -> crate::LoopbackReceiveSession {
    crate::LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn open_subject(node: &OneNode, target_tip: GitOid, source_tip: GitOid) -> (ReviewSubject, PullRequestCommand) {
    let (target_ref, source_ref) = references();
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: source_ref.clone(), target_ref: target_ref.clone(), source_tip, target_tip,
            title: "Move and independent edit".into(), body: String::new(),
        },
    };
    let request = node.request_context();
    let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(
        &request, &session(b"rename-pr-open"), &command, AdmissionLimits::default(),
    )).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        policy_epoch: selected.basis().body().policy_epoch,
        source_ref, target_ref, source_tip, target_tip,
    };
    (subject, command)
}

#[test]
fn explicit_path_profile_preserves_existing_artifact_bytes_and_conflicts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conflict in [false, true] {
            let (_scratch, node, _, _) = fixture(format, conflict);
            let (target, incoming) = references();
            let request = node.request_context();
            let original = node.runtime().block_on(node.prepare_merge_bundle_in(
                &request, &target, &incoming, &RefVisibility::new(), &metadata(), PreparationLimits::default(),
            )).unwrap();
            let explicit = prepare(&node, MergeProfile::PathMergeV1);
            assert_eq!(original.source_head, explicit.source_head);
            assert_eq!(original.outcome, explicit.outcome);
            assert_eq!(original.bundle, explicit.bundle);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn rename_profile_produces_verified_read_only_candidates_without_losing_edits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture_with_rename(format, false, true);
        let legacy = prepare(&node, MergeProfile::PathMergeV1);
        assert!(matches!(legacy.outcome, MergePreparation::Conflicted { .. }));
        assert!(legacy.bundle.is_none());
        let renamed = prepare(&node, MergeProfile::ExactRenamesV1);
        let repeated = prepare(&node, MergeProfile::ExactRenamesV1);
        assert_eq!(renamed.source_head, legacy.source_head);
        assert_eq!(renamed.outcome, repeated.outcome);
        assert_eq!(renamed.bundle, repeated.bundle);
        let MergePreparation::Clean(plan) = renamed.outcome else { panic!("rename must be clean"); };
        assert_eq!((plan.target, plan.source), (target, incoming));
        assert!(node.read_git_object(plan.commit).is_err(), "preparation staged its candidate");
        for object in &plan.objects {
            assert_eq!(git_object_id(format, object.kind, &object.body), object.id);
        }
        let root = plan.objects.iter().find(|object| object.id == plan.tree).unwrap();
        let limits = ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() };
        let ParsedObject::Tree(entries) = parse_object_body(
            ObjectType::Tree, &root.body, AcceptanceProfile::StrictCreate, &limits,
        ).unwrap() else { panic!("tree required"); };
        assert_eq!(entries.iter().map(|entry| entry.name.as_slice()).collect::<Vec<_>>(), [b"keep".as_slice(), b"moved".as_slice()]);
        let edited = git_object_id(format, ObjectType::Blob, b"A\nb\nc\nd\ne\n");
        assert_eq!(entries[1].object_id, edited.as_bytes());
        assert_eq!(node.read_git_object(edited).unwrap().payload(), b"A\nb\nc\nd\ne\n");
        let commit = plan.objects.iter().find(|object| object.id == plan.commit).unwrap();
        assert!(commit.body.starts_with(format!("tree {}\nparent {target}\nparent {incoming}\n", plan.tree).as_bytes()));
        let bundle = renamed.bundle.unwrap();
        let boundary = bundle.windows(4).position(|part| part == b"PACK").unwrap();
        let pack = fgit_pack::read_verified_pack(
            &bundle[boundary..], format, &PackLimits::default(), &mut || true, &fgit_pack::NativeChecksumVerifier,
        ).unwrap();
        assert_eq!(pack.entries().len(), plan.objects.len());
        let request = node.request_context();
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis().id(), renamed.source_head);
        node.shutdown().unwrap();
    }
}

#[test]
fn renamed_bundle_publishes_through_existing_authority_and_exact_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture_with_rename(format, false, true);
        let artifact = prepare(&node, MergeProfile::ExactRenamesV1);
        let MergePreparation::Clean(plan) = artifact.outcome else { panic!("clean merge"); };
        let (target_ref, source_ref) = references();
        let merge = NativeMerge {
            source_ref, source_tip: incoming, target_ref: target_ref.clone(), target_tip_before: target,
            base_tip: plan.base, merge_commit: plan.commit,
        };
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let bundle = artifact.bundle.unwrap();
        let result = node.runtime().block_on(node.apply_merge_bundle_durable_in(
            &request, principal(), b"exact-rename-reviewed", PullRequestNumber::FIRST,
            ExpectedVersion::NewStream, &merge, &bundle,
        )).unwrap();
        assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }));
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&target_ref], plan.commit);
        assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_ne!(after.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(node.runtime().block_on(node.apply_merge_bundle_durable_in(
            &request, principal(), b"exact-rename-reviewed", PullRequestNumber::FIRST,
            ExpectedVersion::NewStream, &merge, &bundle,
        )).unwrap(), result);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), after.basis());
        assert_eq!(node.read_git_object(plan.tree).unwrap().payload(), plan.objects.iter().find(|object| object.id == plan.tree).unwrap().body);
        node.shutdown().unwrap();
    }
}

#[test]
fn pr_profile_requires_the_same_open_subject_and_cannot_refresh_stale_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture_with_rename(format, false, true);
        let (subject, mut command) = open_subject(&node, target, incoming);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let artifact = node.runtime().block_on(node.prepare_pull_request_bundle_with_profile_in(
            &request, &subject, &RefVisibility::new(), &metadata(), PreparationLimits::default(), MergeProfile::ExactRenamesV1,
        )).unwrap();
        assert_eq!(artifact.source_head, before.basis().id());
        assert_eq!(artifact.subject, subject);
        assert!(matches!(artifact.outcome, MergePreparation::Clean(_)));
        assert!(artifact.bundle.is_some());
        let mut stale = subject.clone();
        stale.pull_request_version = subject.pull_request_version.next().unwrap();
        assert!(matches!(node.runtime().block_on(node.prepare_pull_request_bundle_with_profile_in(
            &request, &stale, &RefVisibility::new(), &metadata(), PreparationLimits::default(), MergeProfile::ExactRenamesV1,
        )), Err(NodeWorkspaceRefusal::StaleWorkspaceBase)));
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        command.action = PullRequestAction::Close;
        command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        let (_, closed) = node.runtime().block_on(node.admit_pull_request_durable_in(
            &request, &session(b"rename-pr-close"), &command, AdmissionLimits::default(),
        )).unwrap();
        assert!(matches!(closed.outcome, DecisionOutcome::Committed { .. }));
        let closed_head = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert!(matches!(node.runtime().block_on(node.prepare_pull_request_bundle_with_profile_in(
            &request, &subject, &RefVisibility::new(), &metadata(), PreparationLimits::default(), MergeProfile::ExactRenamesV1,
        )), Err(NodeWorkspaceRefusal::StaleWorkspaceBase)));
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), closed_head.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn explicit_renames_do_not_bypass_visibility_resource_or_cancellation_gates() {
    let (_scratch, node, _, _) = fixture_with_rename(GitHashAlgorithm::Sha1, false, true);
    let (target, incoming) = references();
    let request = node.request_context();
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let mut hidden = RefVisibility::new();
    hidden.push_rule(incoming.as_bytes(), &fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.prepare_merge_bundle_with_profile_in(
        &request, &target, &incoming, &hidden, &metadata(), PreparationLimits::default(), MergeProfile::ExactRenamesV1,
    )), Err(NodeWorkspaceRefusal::RefUnavailable)));
    let limits = PreparationLimits { max_tree_entries: 1, ..PreparationLimits::default() };
    assert!(matches!(node.runtime().block_on(node.prepare_merge_bundle_with_profile_in(
        &request, &target, &incoming, &RefVisibility::new(), &metadata(), limits, MergeProfile::ExactRenamesV1,
    )), Err(NodeWorkspaceRefusal::MergePreparation(_))));
    let cancelled = node.request_context();
    cancelled.cancel();
    assert!(node.runtime().block_on(node.prepare_merge_bundle_with_profile_in(
        &cancelled, &target, &incoming, &RefVisibility::new(), &metadata(), PreparationLimits::default(), MergeProfile::ExactRenamesV1,
    )).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}
