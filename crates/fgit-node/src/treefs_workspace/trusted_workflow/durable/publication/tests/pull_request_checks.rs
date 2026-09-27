//! Actual trusted execution, canonical publication, PR reads and file reopen.
//! These use the existing production fixture; journals never supply PR truth.
use super::*;
use crate::{PullRequestChecksPage, PullRequestChecksReadRefusal};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::visibility::RefVisibility;

fn target_ref() -> RefName {
    RefName::try_new(b"refs/heads/target").unwrap()
}

fn update_branch(node: &OneNode, name: RefName, old: ExpectedOld, new: ProposedNew, key: &[u8]) {
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
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })),
        "branch fixture must commit: {:?}",
        result.commands
    );
}

fn apply_pr(node: &OneNode, command: &PullRequestCommand, key: &[u8]) {
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(key),
            command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}

fn open_pr(node: &OneNode, tip: GitOid) -> PullRequestCommand {
    update_branch(
        node,
        target_ref(),
        ExpectedOld::Absent,
        ProposedNew::Update(tip),
        b"checks-target",
    );
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: source_ref(),
            target_ref: target_ref(),
            source_tip: tip,
            target_tip: tip,
            title: "Verify the actual workflow observation".into(),
            body: "A check reports its publisher's observation; it grants no merge authority."
                .into(),
        },
    };
    apply_pr(node, &command, b"checks-open-pr");
    command
}

fn publish_as(node: &OneNode, record: &WorkflowCheckRecord, principal: PrincipalId, key: &[u8]) {
    let authenticated = LoopbackReceiveSession::authenticated(
        principal,
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    let (_, result) = node
        .runtime()
        .block_on(node.admit_trusted_workflow_check_in(
            &node.request_context(),
            &authenticated,
            record,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(result.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
}

fn check_id(record: &WorkflowCheckRecord, publisher: PrincipalId) -> WorkflowCheckId {
    let event = record
        .proposed_event(publisher, record.source_commit.algorithm())
        .unwrap();
    let fgit_forge::AggregateId::WorkflowCheck(id) = event.aggregate else {
        panic!("workflow fixture must identify a check")
    };
    id
}

fn page(
    node: &OneNode,
    after: Option<WorkflowCheckId>,
    limit: u16,
    head: Option<RepositoryAuthorityHeadId>,
) -> PullRequestChecksPage {
    node.runtime()
        .block_on(node.read_pull_request_checks_in(
            &node.request_context(),
            &RefVisibility::new(),
            PullRequestNumber::FIRST,
            after,
            limit,
            head,
        ))
        .unwrap()
        .unwrap()
}

#[test]
fn canonical_check_pages_preserve_publishers_order_visibility_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new();
        let (node, config, run) = run_fixture(&temp, format, false);
        let command = open_pr(&node, run.source_commit);
        let empty = page(&node, None, 10, None);
        assert!(empty.source_current);
        assert!(empty.checks.is_empty());
        assert_eq!(empty.next_after, None);
        let record = submitted_record(&run);
        let first_publication = publish(&node, &record, b"checks-publisher-one");
        assert!(matches!(
            first_publication.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let second_publisher = PrincipalId::from_bytes([0x44; 16]);
        publish_as(&node, &record, second_publisher, b"checks-publisher-two");
        // Same native commit, different reporting branch: it must not appear
        // on a PR whose source branch is main.
        let mut other_branch = record.clone();
        other_branch.source_ref = target_ref();
        publish_as(
            &node,
            &other_branch,
            PrincipalId::from_bytes([0x74; 16]),
            b"checks-other-branch",
        );
        let selected = page(&node, None, 100, None);
        assert_eq!(selected.number, command.number);
        assert_eq!(selected.pull_request_version, AggregateVersion::FIRST);
        assert_eq!(selected.source_ref, command.data.source_ref);
        assert_eq!(selected.target_ref, command.data.target_ref);
        assert_eq!(selected.source_tip, run.source_commit);
        assert_eq!(selected.target_tip, run.source_commit);
        assert!(selected.source_current);
        let mut ids = vec![
            check_id(&record, publisher()),
            check_id(&record, second_publisher),
        ];
        ids.sort_unstable();
        assert_eq!(
            selected
                .checks
                .iter()
                .map(|check| check.id)
                .collect::<Vec<_>>(),
            ids
        );
        for check in &selected.checks {
            assert!([publisher(), second_publisher].contains(&check.publisher));
            assert_eq!(check.run_id, record.run_id);
            assert_eq!(check.attempt_id, record.attempt_id);
            assert_eq!(check.graph_root, record.graph_root);
            assert_eq!(check.job, record.job);
            assert_eq!(check.conclusion, WorkflowCheckConclusion::ActionRequired);
            assert_eq!(
                check.evidence_sha256,
                fgit_crypto::sha256_digest(&record.evidence)
            );
            assert_eq!(check.evidence_bytes, record.evidence.len() as u64);
        }
        assert_eq!(
            page(&node, None, 100, None),
            selected,
            "repeated reads are deterministic"
        );
        let first = page(&node, None, 1, Some(selected.source_head));
        assert_eq!(first.next_after, Some(ids[0]));
        publish_as(
            &node,
            &record,
            PrincipalId::from_bytes([0x45; 16]),
            b"checks-after-pin",
        );
        let second = page(&node, first.next_after, 1, Some(first.source_head));
        assert_eq!(second.source_head, first.source_head);
        assert_eq!(second.next_after, None);
        let mut walked = first.checks;
        walked.extend(second.checks);
        assert_eq!(walked, selected.checks);
        assert_eq!(page(&node, None, 100, None).checks.len(), 3);

        for hidden in [source_ref(), target_ref()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            let result = node
                .runtime()
                .block_on(node.read_pull_request_checks_in(
                    &node.request_context(),
                    &visibility,
                    command.number,
                    None,
                    100,
                    Some(selected.source_head),
                ))
                .unwrap();
            assert_eq!(
                result, None,
                "neither hidden branch may disclose PR or check identities"
            );
        }
        assert_eq!(page(&node, None, 100, Some(selected.source_head)), selected);
        assert!(
            node.runtime()
                .block_on(node.read_pull_request_checks_in(
                    &node.request_context(),
                    &RefVisibility::new(),
                    PullRequestNumber::try_new(99).unwrap(),
                    None,
                    100,
                    None,
                ))
                .unwrap()
                .is_none()
        );
        for limit in [0, 101] {
            assert!(matches!(
                node.runtime().block_on(node.read_pull_request_checks_in(
                    &node.request_context(),
                    &RefVisibility::new(),
                    command.number,
                    None,
                    limit,
                    None,
                )),
                Err(PullRequestChecksReadRefusal::InvalidLimit)
            ));
        }
        assert!(matches!(
            node.runtime().block_on(node.read_pull_request_checks_in(
                &node.request_context(),
                &RefVisibility::new(),
                command.number,
                Some(ids[0]),
                1,
                None,
            )),
            Err(PullRequestChecksReadRefusal::UnpinnedContinuation)
        ));
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        let error = node
            .runtime()
            .block_on(node.read_pull_request_checks_in(
                &cancelled,
                &RefVisibility::new(),
                command.number,
                None,
                100,
                None,
            ))
            .unwrap_err();
        assert!(
            !error.is_snapshot_unavailable(),
            "cancellation cannot become an expired token"
        );

        let current = page(&node, None, 100, None);
        let before = materialize(&node).basis().id();
        assert_eq!(page(&node, None, 100, Some(selected.source_head)), selected);
        assert_eq!(
            materialize(&node).basis().id(),
            before,
            "reads do not publish"
        );
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap();
        serve(&mut reopened);
        assert_eq!(page(&reopened, None, 100, None), current);
        assert_eq!(
            page(&reopened, None, 100, Some(selected.source_head)),
            selected
        );
        assert_eq!(
            publish(&reopened, &record, b"checks-publisher-one"),
            first_publication
        );
        assert_eq!(
            page(&reopened, None, 100, None),
            current,
            "retry must not add a second check"
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn source_movement_suppresses_stale_checks_until_matching_new_execution_is_published() {
    let temp = Temp::new();
    let (node, config, run) = run_fixture(&temp, GitHashAlgorithm::Sha256, false);
    let mut command = open_pr(&node, run.source_commit);
    let old_record = submitted_record(&run);
    assert!(matches!(
        publish(&node, &old_record, b"checks-old-source").1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let old_page = page(&node, None, 100, None);
    assert_eq!(old_page.checks.len(), 1);
    let root = temp.0.join("source");
    let body = format!(
        "tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nnew checked source\n",
        run.source_tree, run.source_commit,
    );
    let next = loose(
        &root,
        GitHashAlgorithm::Sha256,
        GitObjectKind::Commit,
        "commit",
        body.as_bytes(),
    );
    fs::remove_file(root.join("refs/heads/main")).unwrap();
    fs::write(root.join("refs/heads/advance"), format!("{next}\n")).unwrap();
    fs::write(root.join("HEAD"), "ref: refs/heads/advance\n").unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &root,
            publisher(),
            b"checks-import-next-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    update_branch(
        &node,
        source_ref(),
        ExpectedOld::Exactly(run.source_commit),
        ProposedNew::Update(next),
        b"checks-advance-main",
    );
    let stale = page(&node, None, 100, None);
    assert!(!stale.source_current);
    assert_eq!(
        stale.source_tip, run.source_commit,
        "do not silently update PR metadata"
    );
    assert!(stale.checks.is_empty());
    assert_eq!(stale.next_after, None);
    assert_eq!(page(&node, None, 100, Some(old_page.source_head)), old_page);

    command.action = PullRequestAction::Update;
    command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    command.data.source_tip = next;
    apply_pr(&node, &command, b"checks-refresh-pr");
    let refreshed = page(&node, None, 100, None);
    assert!(refreshed.source_current);
    assert_eq!(refreshed.source_tip, next);
    assert!(
        refreshed.checks.is_empty(),
        "old source evidence cannot apply to a refreshed PR"
    );
    let next_run = node
        .runtime()
        .block_on(node.run_trusted_workflow_in(
            &node.request_context(),
            &source_ref(),
            b"workflow.yml",
            [2; 16],
            &temp.0,
            &[b"workflow.yml".to_vec()],
            (None, Some(next)),
            WorkflowLimits {
                total_output_bytes: 8192,
                ..Default::default()
            },
        ))
        .unwrap();
    assert!(next_run.succeeded());
    let new_record = submitted_record(&next_run);
    assert_ne!(new_record.run_id, old_record.run_id);
    assert!(matches!(
        publish(&node, &new_record, b"checks-new-source").1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let current = page(&node, None, 100, None);
    assert_eq!(current.source_tip, next);
    assert_eq!(current.checks.len(), 1);
    assert_eq!(current.checks[0].id, check_id(&new_record, publisher()));
    assert_eq!(
        current.checks[0].conclusion,
        WorkflowCheckConclusion::ActionRequired
    );
    assert_eq!(page(&node, None, 100, Some(old_page.source_head)), old_page);
    update_branch(
        &node,
        source_ref(),
        ExpectedOld::Exactly(next),
        ProposedNew::Delete,
        b"checks-delete-source",
    );
    let deleted = page(&node, None, 100, None);
    assert!(!deleted.source_current);
    assert!(deleted.checks.is_empty());
    assert_eq!(page(&node, None, 100, Some(current.source_head)), current);
    node.shutdown().unwrap();
    let mut reopened = OneNode::open_existing(config).unwrap();
    serve(&mut reopened);
    assert_eq!(page(&reopened, None, 100, None), deleted);
    assert_eq!(
        page(&reopened, None, 100, Some(current.source_head)),
        current
    );
    assert_eq!(
        page(&reopened, None, 100, Some(old_page.source_head)),
        old_page
    );
    reopened.shutdown().unwrap();
}

#[test]
fn an_actual_failed_execution_remains_a_failure_on_the_pr() {
    let temp = Temp::new();
    let (node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha1, true);
    open_pr(&node, run.source_commit);
    let record = submitted_record(&run);
    assert!(matches!(
        publish(&node, &record, b"checks-real-failure").1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let checks = page(&node, None, 100, None);
    assert!(checks.source_current);
    assert_eq!(checks.checks.len(), 1);
    assert_eq!(
        checks.checks[0].conclusion,
        WorkflowCheckConclusion::Failure
    );
    assert_eq!(checks.checks[0].publisher, publisher());
    node.shutdown().unwrap();
}
