//! Actual native execution, canonical checks and protected publication. Both
//! object formats exercise fast-forward and a distinct two-parent candidate.
use super::*;
use fgit_admission::ProjectionFailure;
use fgit_admission::merge::native::NativeMergeIntent;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{
    ProtectedBranch, ProtectionCommand, RequiredWorkflowCheck, ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};

mod queue_candidate;
mod queue_landing;

fn branch(name: &str) -> RefName {
    RefName::try_new(format!("refs/heads/{name}").as_bytes()).unwrap()
}
fn assert_committed(result: &TerminalOutcome) {
    assert!(
        matches!(result.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
}
fn assert_denied(result: &TerminalOutcome) {
    assert!(
        matches!(
            result.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ),
        "{result:?}"
    );
}
fn update(
    node: &OneNode,
    name: RefName,
    old: ExpectedOld,
    new: ProposedNew,
    key: &[u8],
) -> TerminalOutcome {
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session(key),
            &[RefCommand {
                name,
                expected_old: old,
                proposed_new: new,
                force: false,
            }],
            Default::default(),
        ))
        .unwrap();
    assert_eq!(result.commands.len(), 1);
    result.commands[0].terminal
}
fn install(node: &OneNode, required: &RequiredWorkflowCheck, key: &[u8]) -> ProtectionCommand {
    install_with_queue_requirement(node, required, key, false)
}
fn install_with_queue_requirement(
    node: &OneNode,
    required: &RequiredWorkflowCheck,
    key: &[u8],
    require_merge_queue: bool,
) -> ProtectionCommand {
    let selected = node
        .runtime()
        .block_on(node.read_review_protection_in(&node.request_context()))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: selected
            .version()
            .map(ExpectedVersion::Exactly)
            .unwrap_or(ExpectedVersion::NewStream),
        expected_epoch: selected.policy_epoch,
        protection: ReviewProtection {
            ref_policy: None,
            administrators: vec![publisher()],
            branches: ["main", "release"]
                .into_iter()
                .map(|name| ProtectedBranch {
                    require_merge_queue,
                    required_approvals: 0,
                    name: branch(name),
                    reviewers: Vec::new(),
                    required_checks: vec![required.clone()],
                })
                .collect(),
        },
    };
    let (_, result) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert_committed(&result);
    command
}
fn observe(node: &OneNode, record: &WorkflowCheckRecord, actor: PrincipalId, key: &[u8]) {
    let session =
        LoopbackReceiveSession::authenticated(actor, IdempotencyKey::new(key.to_vec()).unwrap());
    let (_, result) = node
        .runtime()
        .block_on(node.admit_trusted_workflow_check_in(
            &node.request_context(),
            &session,
            record,
            Default::default(),
        ))
        .unwrap();
    assert_committed(&result);
}
fn execute(
    node: &OneNode,
    temp: &Temp,
    tip: GitOid,
    nonce: u8,
    output_limit: usize,
) -> WorkflowCheckRecord {
    let run = node
        .runtime()
        .block_on(node.run_trusted_workflow_in(
            &node.request_context(),
            &branch("ci-candidate"),
            b"workflow.yml",
            [nonce; 16],
            &temp.0,
            &[b"workflow.yml".to_vec()],
            (None, Some(tip)),
            WorkflowLimits {
                stream_bytes: output_limit.min(4096),
                total_output_bytes: output_limit,
                ..Default::default()
            },
        ))
        .unwrap();
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    let (batch, index, evidence) = completed(&mut journal);
    OneNode::workflow_check_record_from_batch(
        branch("ci-candidate"),
        &batch,
        index,
        &evidence,
        &|| true,
    )
    .unwrap()
}
fn merge(node: &OneNode, intent: &NativeMergeIntent, key: &[u8]) -> TerminalOutcome {
    node.runtime()
        .block_on(node.admit_native_merge_durable_in(
            &node.request_context(),
            &session(key),
            intent,
            Default::default(),
            Default::default(),
        ))
        .unwrap()
}

#[test]
fn configured_checks_bind_exact_candidates_and_latest_publisher_results_on_every_path() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fast_forward in [true, false] {
            let temp = Temp::new();
            let (node, config, initial_run) = run_fixture(&temp, format, false);
            let root = temp.0.join("source");
            let old = initial_run.source_commit;
            let source = loose(&root, format, GitObjectKind::Commit, "commit", format!(
                "tree {}\nparent {old}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nsource child\n",
                initial_run.source_tree,
            ).as_bytes());
            let candidate = if fast_forward {
                source
            } else {
                loose(&root, format, GitObjectKind::Commit, "commit", format!(
                    "tree {}\nparent {old}\nparent {source}\nauthor Fixture <fixture@example.invalid> 3 +0000\ncommitter Fixture <fixture@example.invalid> 3 +0000\n\nprepared merge\n",
                    initial_run.source_tree,
                ).as_bytes())
            };
            fs::remove_file(root.join("refs/heads/main")).unwrap();
            fs::write(root.join("refs/heads/advance"), format!("{source}\n")).unwrap();
            fs::write(root.join("refs/heads/prepared"), format!("{candidate}\n")).unwrap();
            fs::write(root.join("HEAD"), "ref: refs/heads/advance\n").unwrap();
            let imported = node
                .runtime()
                .block_on(node.import_loose_git_directory_durable_in(
                    &node.request_context(),
                    &root,
                    publisher(),
                    b"required-check-candidates",
                ))
                .unwrap();
            assert!(!imported.commands.is_empty());
            for command in &imported.commands {
                assert_committed(&command.terminal);
            }
            assert_committed(&update(
                &node,
                branch("ci-candidate"),
                ExpectedOld::Absent,
                ProposedNew::Update(source),
                b"ci-source",
            ));
            let pr = PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                action: PullRequestAction::Open,
                data: PullRequestData {
                    source_ref: branch("advance"),
                    source_tip: source,
                    target_ref: source_ref(),
                    target_tip: old,
                    title: "Gate the exact candidate".into(),
                    body: "Explicit trusted publisher policy".into(),
                },
            };
            let (_, opened) = node
                .runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &node.request_context(),
                    &session(b"check-pr"),
                    &pr,
                    Default::default(),
                ))
                .unwrap();
            assert_committed(&opened);
            let intent = if fast_forward {
                NativeMergeIntent::fast_forward_only(
                    PullRequestNumber::FIRST,
                    AggregateVersion::FIRST,
                    branch("advance"),
                    source,
                    source_ref(),
                    old,
                )
                .unwrap()
            } else {
                NativeMergeIntent::new(
                    PullRequestNumber::FIRST,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    NativeMerge {
                        source_ref: branch("advance"),
                        source_tip: source,
                        base_tip: old,
                        target_ref: source_ref(),
                        target_tip_before: old,
                        merge_commit: candidate,
                    },
                )
                .unwrap()
            };
            let source_record = execute(&node, &temp, source, 2, 8192);
            assert_eq!(source_record.conclusion, WorkflowCheckConclusion::Success);
            let required = RequiredWorkflowCheck {
                source_ref: branch("ci-candidate"),
                publisher: publisher(),
                graph_root: source_record.graph_root,
                job: source_record.job.clone(),
            };
            install(&node, &required, b"install-checks");
            let missing = merge(&node, &intent, b"missing-check");
            assert_denied(&missing);
            let other_publisher = PrincipalId::from_bytes([0x99; 16]);
            observe(&node, &source_record, other_publisher, b"untrusted-success");
            assert_denied(&merge(&node, &intent, b"wrong-publisher"));
            observe(&node, &source_record, publisher(), b"source-success");
            if !fast_forward {
                // Source success is not a success for a different merge commit.
                assert_denied(&merge(&node, &intent, b"source-is-not-candidate"));
                assert_committed(&update(
                    &node,
                    branch("ci-candidate"),
                    ExpectedOld::Exactly(source),
                    ProposedNew::Update(candidate),
                    b"select-prepared-candidate",
                ));
                let candidate_record = execute(&node, &temp, candidate, 3, 8192);
                assert_eq!(candidate_record.graph_root, required.graph_root);
                observe(&node, &candidate_record, publisher(), b"candidate-success");
            }
            assert_committed(&update(
                &node,
                branch("other"),
                ExpectedOld::Absent,
                ProposedNew::Update(candidate),
                b"other-same-candidate",
            ));
            for field in 0..4 {
                let mut wrong = required.clone();
                match field {
                    0 => wrong.publisher = PrincipalId::from_bytes([0x88; 16]),
                    1 => wrong.graph_root[0] ^= 1,
                    2 => wrong.job.push_str("-different"),
                    _ => wrong.source_ref = branch("other"),
                }
                install(&node, &wrong, format!("wrong-selector-{field}").as_bytes());
                assert_denied(&merge(
                    &node,
                    &intent,
                    format!("deny-selector-{field}").as_bytes(),
                ));
            }
            let installed = install(&node, &required, b"restore-checks");
            // An older full-policy replacement cannot remove a newly installed check.
            let stale_clear = ProtectionCommand {
                protection: ReviewProtection {
                    ref_policy: None,
                    administrators: vec![publisher()],
                    branches: Vec::new(),
                },
                ..installed
            };
            let (_, stale) = node
                .runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &node.request_context(),
                    &session(b"stale-clear"),
                    &stale_clear,
                    Default::default(),
                ))
                .unwrap();
            assert!(matches!(
                stale.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::EvidenceStale,
                    ..
                }
            ));
            assert_denied(&update(
                &node,
                branch("release"),
                ExpectedOld::Absent,
                ProposedNew::Update(old),
                b"wrong-new-commit",
            ));
            // The PR source remains current; only the policy's CI source disappears.
            assert_committed(&update(
                &node,
                branch("ci-candidate"),
                ExpectedOld::Exactly(candidate),
                ProposedNew::Delete,
                b"delete-ci-source",
            ));
            assert_denied(&merge(&node, &intent, b"stale-ci-source"));
            assert_committed(&update(
                &node,
                branch("ci-candidate"),
                ExpectedOld::Absent,
                ProposedNew::Update(candidate),
                b"restore-ci-source",
            ));
            let failed = execute(&node, &temp, candidate, 4, 2);
            assert_eq!(failed.graph_root, required.graph_root);
            assert_eq!(failed.job, required.job);
            assert_eq!(failed.conclusion, WorkflowCheckConclusion::Failure);
            observe(&node, &failed, publisher(), b"latest-failure");
            let refused = merge(&node, &intent, b"failed-candidate");
            assert_denied(&refused);
            assert_denied(&update(
                &node,
                branch("release"),
                ExpectedOld::Absent,
                ProposedNew::Update(candidate),
                b"failed-direct-update",
            ));
            let retry = execute(&node, &temp, candidate, 5, 8192);
            assert_eq!(retry.graph_root, required.graph_root);
            assert_eq!(retry.conclusion, WorkflowCheckConclusion::Success);
            observe(&node, &retry, publisher(), b"latest-success");
            // A later failure from an unconfigured publisher cannot supersede it.
            observe(&node, &failed, other_publisher, b"untrusted-later-failure");
            assert_eq!(merge(&node, &intent, b"missing-check"), missing);
            assert_eq!(merge(&node, &intent, b"failed-candidate"), refused);
            let selected = materialize(&node);
            let request = node.request_context();
            assert_eq!(
                node.runtime().block_on(
                    fgit_admission::merge::native::protection::enforce_merge_at(
                        &node.authority,
                        request.authority(),
                        selected.basis(),
                        &selected.snapshot().refs,
                        &intent,
                        publisher(),
                        &|| true,
                    ),
                ),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::CancellationInProgress
                ))
            );
            let direct = update(
                &node,
                branch("release"),
                ExpectedOld::Absent,
                ProposedNew::Update(candidate),
                b"successful-direct-update",
            );
            assert_committed(&direct);
            assert_eq!(
                update(
                    &node,
                    branch("release"),
                    ExpectedOld::Absent,
                    ProposedNew::Update(candidate),
                    b"successful-direct-update"
                ),
                direct
            );
            assert_denied(&update(
                &node,
                branch("release"),
                ExpectedOld::Exactly(candidate),
                ProposedNew::Delete,
                b"protected-delete",
            ));
            let merged = merge(&node, &intent, b"successful-merge");
            assert_committed(&merged);
            assert_eq!(
                materialize(&node).snapshot().refs.get(&source_ref()),
                Some(&candidate)
            );
            node.shutdown().unwrap();
            let mut reopened = OneNode::open_existing(config).unwrap();
            serve(&mut reopened);
            let selected = reopened
                .runtime()
                .block_on(reopened.read_review_protection_in(&reopened.request_context()))
                .unwrap();
            assert_eq!(
                selected.protection().unwrap().branches[0].required_checks,
                vec![required]
            );
            assert_eq!(merge(&reopened, &intent, b"successful-merge"), merged);
            assert_eq!(merge(&reopened, &intent, b"failed-candidate"), refused);
            reopened.shutdown().unwrap();
        }
    }
}
