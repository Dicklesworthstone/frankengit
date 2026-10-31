//! A real executed job unlocks queued publication only after its exact-candidate
//! evidence is committed by the configured publisher. Local runner success and
//! an older candidate's canonical green result remain insufficient.
use super::*;
use fgit_admission::merge::native::queue::QueueLandingCommand;
use fgit_forge::QueueNumber;
use fgit_forge::merge_queue::{MergeQueueSnapshot, QueueCommand, QueueCommandAction};
use fgit_wire::visibility::RefVisibility;

fn queue(node: &OneNode) -> MergeQueueSnapshot {
    node.runtime()
        .block_on(node.read_queue_in(
            &node.request_context(),
            &RefVisibility::new(),
            QueueNumber::FIRST,
            None,
        ))
        .unwrap()
        .queue
        .unwrap()
}

fn land(node: &OneNode, command: &QueueLandingCommand, key: &[u8]) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.land_queue_head_durable_in(
            &node.request_context(),
            &session(key),
            command,
            Default::default(),
        ))
        .unwrap()
}

#[test]
fn queue_landing_accepts_persisted_success_from_actual_exact_candidate_execution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new();
        let (node, config, initial_run) = run_fixture(&temp, format, false);
        let old = initial_run.source_commit;
        let root = temp.0.join("source");
        let source = loose(
            &root,
            format,
            GitObjectKind::Commit,
            "commit",
            format!(
                "tree {}\nparent {old}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nqueue candidate\n",
                initial_run.source_tree,
            ).as_bytes(),
        );
        fs::remove_file(root.join("refs/heads/main")).unwrap();
        fs::write(root.join("refs/heads/advance"), format!("{source}\n")).unwrap();
        fs::write(root.join("HEAD"), "ref: refs/heads/advance\n").unwrap();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &root,
                publisher(),
                b"queue-check-candidate",
            ))
            .unwrap();
        assert!(!imported.commands.is_empty());
        for command in &imported.commands {
            assert_committed(&command.terminal);
        }

        // Publish an actual green result for the old commit through the same
        // configured reporting branch, publisher, graph and job. Once the CI
        // branch advances, that canonical observation cannot bless its child.
        assert_committed(&update(
            &node,
            branch("ci-candidate"),
            ExpectedOld::Absent,
            ProposedNew::Update(old),
            b"queue-ci-old",
        ));
        let mut journal = initial_run.open_check_journal(None, &|| true).unwrap();
        let (batch, index, evidence) = completed(&mut journal);
        let older = OneNode::workflow_check_record_from_batch(
            branch("ci-candidate"),
            &batch,
            index,
            &evidence,
            &|| true,
        )
        .unwrap();
        assert_eq!(older.conclusion, WorkflowCheckConclusion::Success);
        observe(&node, &older, publisher(), b"queue-old-canonical-success");
        assert_committed(&update(
            &node,
            branch("ci-candidate"),
            ExpectedOld::Exactly(old),
            ProposedNew::Update(source),
            b"queue-ci-candidate",
        ));
        let pull = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: branch("advance"),
                source_tip: source,
                target_ref: source_ref(),
                target_tip: old,
                title: "Land the checked queue head".into(),
                body: "Require verified exact-candidate workflow evidence".into(),
            },
        };
        let (_, opened) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(b"queue-check-pr"),
                &pull,
                Default::default(),
            ))
            .unwrap();
        assert_committed(&opened);
        let command = QueueCommand {
            number: QueueNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            target_ref: pull.data.target_ref.clone(),
            action: QueueCommandAction::Enqueue {
                pull_request: pull.number,
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: pull.data.source_ref.clone(),
                head_tip: source,
                expected_target_tip: old,
                priority: 0,
            },
        };
        let (_, queued) = node
            .runtime()
            .block_on(node.admit_queue_durable_in(
                &node.request_context(),
                &session(b"queue-check-enqueue"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert_committed(&queued);
        let required = RequiredWorkflowCheck {
            source_ref: branch("ci-candidate"),
            publisher: publisher(),
            graph_root: older.graph_root,
            job: older.job.clone(),
        };
        let installed = install(&node, &required, b"queue-required-check");
        let landing = QueueLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::FIRST,
            expected_policy_epoch: installed.expected_epoch.next().unwrap(),
            pull_request: pull.number,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: pull.data.source_ref.clone(),
            head_tip: source,
            target_ref: pull.data.target_ref.clone(),
            expected_target_tip: old,
        };
        let before = materialize(&node);
        let queued = queue(&node);
        let wrong_candidate = land(&node, &landing, b"queue-old-check-refusal");
        assert_denied(&wrong_candidate.1);
        assert_eq!(queue(&node), queued);
        assert_eq!(materialize(&node).snapshot().refs, before.snapshot().refs);

        let passed = execute(&node, &temp, source, 2, 8192);
        assert_eq!(passed.source_commit, source);
        assert_eq!(passed.source_ref, required.source_ref);
        assert_eq!(passed.graph_root, required.graph_root);
        assert_eq!(passed.job, required.job);
        assert_eq!(passed.conclusion, WorkflowCheckConclusion::Success);
        let local_only = land(&node, &landing, b"queue-unpublished-check-refusal");
        assert_denied(&local_only.1);
        assert_eq!(queue(&node), queued);
        assert_eq!(materialize(&node).snapshot().refs, before.snapshot().refs);
        observe(
            &node,
            &passed,
            publisher(),
            b"queue-exact-canonical-success",
        );

        // Reopening discards all in-process runner state. The landing gate
        // must find the selected observation in authenticated durable history.
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap();
        serve(&mut reopened);
        let before_landing = materialize(&reopened);
        let landed = land(&reopened, &landing, b"queue-checked-land");
        assert_committed(&landed.1);
        let mut expected_refs = before_landing.snapshot().refs.clone();
        expected_refs.insert(source_ref(), source);
        assert_eq!(materialize(&reopened).snapshot().refs, expected_refs);
        let after = queue(&reopened);
        assert_eq!(after.version, AggregateVersion::try_new(3).unwrap());
        assert!(after.is_empty());
        assert!(after.active_batch.is_none());
        assert_eq!(land(&reopened, &landing, b"queue-checked-land"), landed);
        assert_eq!(
            land(&reopened, &landing, b"queue-old-check-refusal"),
            wrong_candidate
        );
        assert_eq!(
            land(&reopened, &landing, b"queue-unpublished-check-refusal"),
            local_only
        );
        reopened.shutdown().unwrap();
    }
}
