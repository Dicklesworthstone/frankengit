//! Native filesystem and authority coverage for omitted admitted blob reuse.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryId, TenantId};
use std::fs;
use std::path::PathBuf;

const METADATA_BYTES: usize = 64 * 1024;
const BLOB_BYTES: usize = 256 * 1024 + 17;

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x73; 16])
}

fn reopen(node: OneNode, format: GitHashAlgorithm, maximum_blob: Option<usize>) -> OneNode {
    let root = node.storage_root().to_owned();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.shutdown().unwrap();
    let mut config = crate::NodeConfig::new(
        root,
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2)
    .with_max_object_bytes(METADATA_BYTES as u64);
    if let Some(maximum) = maximum_blob {
        config = config.with_selected_pack_blob_limit(maximum);
    }
    let mut node = OneNode::open_existing(config).unwrap();
    node.bring_into_service(generation).unwrap();
    node
}

fn open_pr(node: &OneNode, target: GitOid, incoming: GitOid) -> ReviewSubject {
    let request = node.request_context();
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: incoming,
            target_tip: target,
            title: "Small change with an unchanged large blob".into(),
            body: String::new(),
        },
    };
    let session = crate::LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(b"large-frontier-pr".to_vec()).unwrap(),
    );
    let result = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let current = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    ReviewSubject {
        pull_request: command.number,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: command.data.source_ref,
        target_ref: command.data.target_ref,
        source_tip: incoming,
        target_tip: target,
        policy_epoch: current.basis().body().policy_epoch,
    }
}

fn prepare(
    node: &OneNode,
    subject: &ReviewSubject,
    style: MergeCommitStyle,
) -> (CandidateBinding, Vec<u8>) {
    let request = node.request_context();
    let prepared = node
        .runtime()
        .block_on(node.prepare_pull_request_bundle_with_options_in(
            &request,
            subject,
            &RefVisibility::new(),
            &tests::metadata(),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
            style,
        ))
        .unwrap();
    assert_eq!(&prepared.subject, subject);
    let MergePreparation::Clean(plan) = prepared.outcome else {
        panic!("clean candidate");
    };
    assert!(
        plan.objects
            .iter()
            .all(|object| object.body.len() < METADATA_BYTES)
    );
    assert!(node.read_git_object(plan.commit).is_err());
    (
        CandidateBinding {
            merge_base: plan.base,
            commit: plan.commit,
        },
        prepared.bundle.unwrap(),
    )
}

fn inspect(node: &OneNode, subject: &ReviewSubject, candidate: CandidateBinding, input: &[u8]) {
    let request = node.request_context();
    let inspected = node
        .runtime()
        .block_on(node.inspect_pull_request_bundle_in(
            &request,
            subject,
            candidate,
            input,
            &RefVisibility::new(),
            &ReviewOptions {
                mode: ComparisonMode::Direct,
                ..Default::default()
            },
        ))
        .unwrap();
    assert_eq!(inspected.review.comparison.entries.len(), 1);
    assert_eq!(inspected.review.comparison.entries[0].path, b"text");
}

fn assert_staging_empty(node: &OneNode) {
    assert_eq!(
        fs::read_dir(node.storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
}

fn stored(node: &OneNode, id: GitOid) -> PathBuf {
    let mut directories = vec![node.storage_root().join("objects")];
    let name = id.to_string();
    while let Some(directory) = directories.pop() {
        for item in fs::read_dir(directory).unwrap() {
            let item = item.unwrap();
            if item.file_type().unwrap().is_dir() {
                directories.push(item.path());
            } else if item.file_name() == name.as_str() {
                return item.path();
            }
        }
    }
    panic!("missing fixture object {id}")
}

fn end_to_end(format: GitHashAlgorithm, style: MergeCommitStyle, blob_bytes: usize) {
    let payload = vec![b'k'; blob_bytes];
    let inherited = git_object_id(format, ObjectType::Blob, &payload);
    let (_scratch, node, target, incoming) =
        tests::fixture_with_preserved(format, false, false, payload, 64 * 1024 * 1024);
    let node = reopen(node, format, Some(blob_bytes));
    // A body read cannot succeed under this configuration. Passing all three
    // operations below therefore requires the actual checked-envelope path.
    assert!(node.read_git_object(inherited).is_err());
    let subject = open_pr(&node, target, incoming);
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let (candidate, bundle) = prepare(&node, &subject, style);
    inspect(&node, &subject, candidate, &bundle);
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    assert_staging_empty(&node);
    let method = match style {
        MergeCommitStyle::TwoParent => crate::NativeMergeMethod::MergeCommit,
        MergeCommitStyle::Squash => crate::NativeMergeMethod::Squash,
    };
    let merge = candidate.merge(&subject);
    let outcome = node
        .runtime()
        .block_on(node.apply_merge_bundle_with_method_durable_in(
            &request,
            principal(),
            b"large-frontier-apply",
            subject.pull_request,
            ExpectedVersion::Exactly(subject.pull_request_version),
            &merge,
            &bundle,
            method,
        ))
        .unwrap();
    assert!(matches!(
        outcome.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let after = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(after.snapshot().refs[&subject.target_ref], candidate.commit);
    assert_ne!(
        after.basis().body().forge_position_root,
        before.basis().body().forge_position_root
    );
    assert_ne!(
        after.basis().body().outbox_root,
        before.basis().body().outbox_root
    );
    assert_staging_empty(&node);
    // An explicit content consumer must still verify the inherited bytes. The
    // merge itself does not claim to scrub them by observing an envelope.
    let mut stream = node
        .open_git_blob_stream(inherited, blob_bytes as u64)
        .unwrap();
    let mut chunk = [0; 64 * 1024];
    let mut total = 0;
    loop {
        let read = stream.read_tentative(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        assert!(chunk[..read].iter().all(|byte| *byte == b'k'));
        total += read;
    }
    assert_eq!(total, blob_bytes);
    assert!(stream.is_verified());
    drop(stream);
    let node = reopen(node, format, None);
    let request = node.request_context();
    let replay = node
        .runtime()
        .block_on(node.apply_merge_bundle_with_method_durable_in(
            &request,
            principal(),
            b"large-frontier-apply",
            subject.pull_request,
            ExpectedVersion::Exactly(subject.pull_request_version),
            &merge,
            &bundle,
            method,
        ))
        .unwrap();
    assert_eq!(
        replay, outcome,
        "terminal replay precedes the now-smaller intake policy"
    );
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        after.basis()
    );
    node.shutdown().unwrap();
}

#[test]
fn small_merge_and_squash_prepare_inspect_publish_and_replay_with_large_unchanged_blobs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for style in [MergeCommitStyle::TwoParent, MergeCommitStyle::Squash] {
            end_to_end(format, style, BLOB_BYTES);
        }
    }
}

#[test]
fn explicitly_allowed_native_blobs_above_thirty_two_mib_survive_the_complete_merge_path() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        end_to_end(format, MergeCommitStyle::TwoParent, 32 * 1024 * 1024 + 17);
    }
}

#[test]
fn hidden_missing_over_limit_and_cancelled_frontiers_never_publish_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = vec![b'k'; BLOB_BYTES];
        let inherited = git_object_id(format, ObjectType::Blob, &body);
        let (_scratch, node, target, incoming) =
            tests::fixture_with_preserved(format, false, false, body, 2 * 1024 * 1024);
        let node = reopen(node, format, Some(BLOB_BYTES));
        let subject = open_pr(&node, target, incoming);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let (candidate, bundle) = prepare(&node, &subject, MergeCommitStyle::TwoParent);
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(subject.source_ref.as_bytes(), &Default::default())
            .unwrap();
        assert!(
            node.runtime()
                .block_on(node.prepare_pull_request_bundle_in(
                    &request,
                    &subject,
                    &hidden,
                    &tests::metadata(),
                    PreparationLimits::default(),
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.inspect_pull_request_bundle_in(
                    &request,
                    &subject,
                    candidate,
                    &bundle,
                    &hidden,
                    &ReviewOptions {
                        mode: ComparisonMode::Direct,
                        ..Default::default()
                    },
                ))
                .is_err()
        );
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.prepare_pull_request_bundle_in(
                    &cancelled,
                    &subject,
                    &RefVisibility::new(),
                    &tests::metadata(),
                    PreparationLimits::default(),
                ))
                .is_err()
        );
        inspect(&node, &subject, candidate, &bundle);
        let path = stored(&node, inherited);
        let stored_bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(
            node.runtime()
                .block_on(node.prepare_pull_request_bundle_in(
                    &request,
                    &subject,
                    &RefVisibility::new(),
                    &tests::metadata(),
                    PreparationLimits::default(),
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.inspect_pull_request_bundle_in(
                    &request,
                    &subject,
                    candidate,
                    &bundle,
                    &RefVisibility::new(),
                    &ReviewOptions {
                        mode: ComparisonMode::Direct,
                        ..Default::default()
                    },
                ))
                .is_err()
        );
        let merge = candidate.merge(&subject);
        assert!(
            node.runtime()
                .block_on(node.apply_merge_bundle_durable_in(
                    &request,
                    principal(),
                    b"missing-frontier",
                    subject.pull_request,
                    ExpectedVersion::Exactly(subject.pull_request_version),
                    &merge,
                    &bundle,
                ))
                .is_err()
        );
        fs::write(&path, &stored_bytes).unwrap();
        inspect(&node, &subject, candidate, &bundle);
        assert!(node.read_git_object(candidate.commit).is_err());
        assert_staging_empty(&node);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        let node = reopen(node, format, Some(BLOB_BYTES - 1));
        let request = node.request_context();
        assert!(
            node.runtime()
                .block_on(node.prepare_pull_request_bundle_in(
                    &request,
                    &subject,
                    &RefVisibility::new(),
                    &tests::metadata(),
                    PreparationLimits::default(),
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.inspect_pull_request_bundle_in(
                    &request,
                    &subject,
                    candidate,
                    &bundle,
                    &RefVisibility::new(),
                    &ReviewOptions {
                        mode: ComparisonMode::Direct,
                        ..Default::default()
                    },
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.apply_merge_bundle_durable_in(
                    &request,
                    principal(),
                    b"bounded-frontier",
                    subject.pull_request,
                    ExpectedVersion::Exactly(subject.pull_request_version),
                    &merge,
                    &bundle,
                ))
                .is_err()
        );
        assert!(node.read_git_object(candidate.commit).is_err());
        assert_staging_empty(&node);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        node.shutdown().unwrap();
    }
}
