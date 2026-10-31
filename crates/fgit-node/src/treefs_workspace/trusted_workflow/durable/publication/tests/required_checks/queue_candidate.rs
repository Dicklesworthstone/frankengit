//! A real native two-parent queue candidate passes only after its own executed
//! workflow result is published canonically by the configured reporting actor.

use super::*;
use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_forge::QueueNumber;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_wire::visibility::RefVisibility;

fn land(
    node: &OneNode,
    command: &QueueCandidateLandingCommand,
    bundle: &[u8],
    key: &[u8],
) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.land_queue_head_bundle_durable_in(
            &node.request_context(),
            &session(key),
            command,
            bundle,
            Default::default(),
        ))
        .unwrap()
}

fn ci_bundle(original: &[u8], candidate: GitOid) -> Vec<u8> {
    let parsed =
        FullBundleInput::parse_incremental(original, FullBundleLimits::default(), &mut || true)
            .unwrap();
    assert_eq!(parsed.references().len(), 1);
    assert_eq!(*parsed.references()[0].target(), candidate);
    let mut bytes = match candidate.algorithm() {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    for prerequisite in parsed.prerequisites() {
        bytes.extend_from_slice(format!("-{prerequisite} canonical parent\n").as_bytes());
    }
    bytes.extend_from_slice(format!("{candidate} refs/heads/ci-candidate\n\n").as_bytes());
    bytes.extend_from_slice(parsed.pack_bytes());
    bytes
}

#[test]
fn two_parent_queue_candidate_requires_its_actual_canonical_workflow_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new();
        let (node, config, initial_run) = run_fixture(&temp, format, false);
        let old = initial_run.source_commit;
        let root = temp.0.join("source");
        let child = |message: &str| {
            loose(
                &root,
                format,
                GitObjectKind::Commit,
                "commit",
                format!(
                    "tree {}\nparent {old}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\n{message}\n",
                    initial_run.source_tree,
                )
                .as_bytes(),
            )
        };
        let target = child("independent target advance");
        let source = child("independent queued source");
        fs::remove_file(root.join("refs/heads/main")).unwrap();
        fs::write(root.join("refs/heads/advance"), format!("{source}\n")).unwrap();
        fs::write(
            root.join("refs/heads/target-advance"),
            format!("{target}\n"),
        )
        .unwrap();
        fs::write(root.join("HEAD"), b"ref: refs/heads/advance\n").unwrap();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &root,
                publisher(),
                b"queue-candidate-inputs",
            ))
            .unwrap();
        for result in imported.commands {
            assert_committed(&result.terminal);
        }
        assert_committed(&update(
            &node,
            source_ref(),
            ExpectedOld::Exactly(old),
            ProposedNew::Update(target),
            b"queue-target-advance",
        ));
        assert_committed(&update(
            &node,
            branch("ci-candidate"),
            ExpectedOld::Absent,
            ProposedNew::Update(old),
            b"queue-ci-old",
        ));
        let mut journal = initial_run.open_check_journal(None, &|| true).unwrap();
        let (batch, index, evidence) = completed(&mut journal);
        let old_green = OneNode::workflow_check_record_from_batch(
            branch("ci-candidate"),
            &batch,
            index,
            &evidence,
            &|| true,
        )
        .unwrap();
        observe(&node, &old_green, publisher(), b"queue-older-green");
        let pull = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: branch("advance"),
                source_tip: source,
                target_ref: source_ref(),
                target_tip: target,
                title: "Checked divergent queue candidate".into(),
                body: String::new(),
            },
        };
        let (_, opened) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(b"queue-candidate-pr"),
                &pull,
                Default::default(),
            ))
            .unwrap();
        assert_committed(&opened);
        let (_, queued) = node
            .runtime()
            .block_on(node.admit_queue_durable_in(
                &node.request_context(),
                &session(b"queue-candidate-enqueue"),
                &QueueCommand {
                    number: QueueNumber::FIRST,
                    expected_version: ExpectedVersion::NewStream,
                    target_ref: source_ref(),
                    action: QueueCommandAction::Enqueue {
                        pull_request: pull.number,
                        expected_pull_request_version: AggregateVersion::FIRST,
                        source_ref: pull.data.source_ref.clone(),
                        head_tip: source,
                        expected_target_tip: target,
                        priority: 0,
                    },
                },
                Default::default(),
            ))
            .unwrap();
        assert_committed(&queued);
        let required = RequiredWorkflowCheck {
            source_ref: branch("ci-candidate"),
            publisher: publisher(),
            graph_root: old_green.graph_root,
            job: old_green.job,
        };
        let policy = install_with_queue_requirement(
            &node,
            &required,
            b"queue-candidate-required-check",
            true,
        );
        let selected = ReviewSubject {
            pull_request: pull.number,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: pull.data.source_ref.clone(),
            target_ref: source_ref(),
            source_tip: source,
            target_tip: target,
            policy_epoch: policy.expected_epoch.next().unwrap(),
        };
        let prepared = node
            .runtime()
            .block_on(node.prepare_queue_head_bundle_in(
                &node.request_context(),
                QueueNumber::FIRST,
                AggregateVersion::FIRST,
                &selected,
                &RefVisibility::new(),
                &MergeMetadata {
                    author: "Queue <queue@example.invalid>".into(),
                    committer: "Queue <queue@example.invalid>".into(),
                    timestamp: 3,
                    message: b"Checked queue integration\n".to_vec(),
                },
                PreparationLimits::default(),
            ))
            .unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("divergent histories with unchanged workflow should merge cleanly");
        };
        assert_eq!(plan.base, old);
        let original_bundle = prepared.bundle.unwrap();
        let command = QueueCandidateLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::FIRST,
            expected_policy_epoch: selected.policy_epoch,
            pull_request: pull.number,
            expected_pull_request_version: AggregateVersion::FIRST,
            merge: CandidateBinding {
                merge_base: plan.base,
                commit: plan.commit,
            }
            .merge(&selected),
        };
        let before = materialize(&node);
        let older_refusal = land(
            &node,
            &command,
            &original_bundle,
            b"queue-old-candidate-check",
        );
        assert_denied(&older_refusal.1);
        assert_eq!(materialize(&node).snapshot().refs, before.snapshot().refs);
        assert!(node.read_git_object(plan.commit).is_err());

        // Admit the candidate on an explicitly leased reporting branch, then
        // execute repository-owned bytes and publish the verified result. This
        // separate CI ref does not change the protected target or queue state.
        let imported = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(b"queue-candidate-ci-import"),
                &ci_bundle(&original_bundle, plan.commit),
                &[(branch("ci-candidate"), Some(old))],
                Default::default(),
            ))
            .unwrap();
        for result in imported.commands {
            assert_committed(&result.terminal);
        }
        assert_eq!(materialize(&node).snapshot().refs[&source_ref()], target);
        let passed = execute(&node, &temp, plan.commit, 2, 8192);
        assert_eq!(passed.source_commit, plan.commit);
        assert_eq!(passed.graph_root, required.graph_root);
        assert_eq!(passed.job, required.job);
        assert_eq!(passed.conclusion, WorkflowCheckConclusion::Success);
        let local_refusal = land(
            &node,
            &command,
            &original_bundle,
            b"queue-local-only-candidate-check",
        );
        assert_denied(&local_refusal.1);
        observe(
            &node,
            &passed,
            publisher(),
            b"queue-candidate-verified-green",
        );
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap();
        serve(&mut reopened);
        let before = materialize(&reopened);
        let original = land(
            &reopened,
            &command,
            &original_bundle,
            b"queue-checked-two-parent-land",
        );
        assert_committed(&original.1);
        let mut expected = before.snapshot().refs.clone();
        expected.insert(source_ref(), plan.commit);
        assert_eq!(materialize(&reopened).snapshot().refs, expected);
        let queue = reopened
            .runtime()
            .block_on(reopened.read_queue_in(
                &reopened.request_context(),
                &RefVisibility::new(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.version, AggregateVersion::try_new(3).unwrap());
        assert!(queue.active_batch.is_none());
        assert_eq!(
            land(&reopened, &command, b"", b"queue-checked-two-parent-land"),
            original
        );
        assert_eq!(
            land(&reopened, &command, b"", b"queue-old-candidate-check"),
            older_refusal
        );
        assert_eq!(
            land(
                &reopened,
                &command,
                b"",
                b"queue-local-only-candidate-check"
            ),
            local_refusal
        );
        reopened.shutdown().unwrap();
    }
}
