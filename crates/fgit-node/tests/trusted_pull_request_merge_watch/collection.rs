//! Real discovery, per-PR merged-tree execution and retained member recovery.
use super::*;
use fgit_node::workflow_watch::{
    WorkflowWatchConfig, WorkflowWatchControl, WorkflowWatchReceipt, run_service_with_ready,
};
use std::cell::Cell;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn template(style: MergeCommitStyle) -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        RefName::try_new(b"refs/heads/ci-auto").unwrap(),
        OWNER,
        metadata(),
        MergeProfile::PathMergeV1,
        style,
    )
    .unwrap()
}
fn source_config(f: &Fixture) -> WorkflowWatchConfig {
    WorkflowWatchConfig::try_new(
        f.source.algorithm(),
        target_ref(),
        b"ci".to_vec(),
        f.parent(),
        read_inputs(),
        Duration::from_millis(20),
    )
    .unwrap()
    .with_pull_requests(4)
    .unwrap()
    .with_publisher(OWNER)
}
fn watch_config(f: &Fixture, style: MergeCommitStyle) -> WorkflowWatchConfig {
    source_config(f)
        .with_pull_request_merge_candidates(template(style))
        .unwrap()
}
fn candidate_ref(number: u64) -> RefName {
    RefName::try_new(format!("refs/heads/ci-auto/pr-{number}").as_bytes()).unwrap()
}
fn open_member(f: &Fixture, number: u64, source: RefName, target: RefName) {
    let command = PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: source,
            target_ref: target,
            source_tip: f.source,
            target_tip: f.target,
            title: format!("Merged-tree collection PR {number}"),
            body: String::new(),
        },
    };
    let n = f.node();
    let (_, result) = n
        .runtime()
        .block_on(n.admit_pull_request_durable_in(
            &n.request_context(),
            &session(format!("collection-open-{number}").as_bytes()),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(result.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
}
fn reported(f: &Fixture) -> usize {
    event_directories(f)
        .iter()
        .filter(|path| path.join("reported").is_file())
        .count()
}
fn executed(f: &Fixture) -> String {
    fs::read_to_string(f.root.join("executed")).unwrap_or_default()
}
fn stop_at_readiness(f: &Fixture, config: WorkflowWatchConfig) -> WorkflowWatchReceipt {
    let control = WorkflowWatchControl::default();
    run_service_with_ready(f.config.clone(), config, control.clone(), || {
        control.request_stop();
        Ok(())
    })
    .unwrap()
}
fn refuse_before_readiness(f: &Fixture, config: WorkflowWatchConfig) -> String {
    let ready = Cell::new(false);
    let control = WorkflowWatchControl::default();
    let result = run_service_with_ready(f.config.clone(), config, control.clone(), || {
        ready.set(true);
        control.request_stop();
        Ok(())
    });
    assert!(
        !ready.get(),
        "invalid collection reached readiness: {result:?}"
    );
    result.unwrap_err().to_string()
}
struct Running {
    control: WorkflowWatchControl,
    task: Option<asupersync::runtime::BlockingTaskHandle>,
    result: mpsc::Receiver<Result<WorkflowWatchReceipt, String>>,
}
impl Running {
    fn start(f: &Fixture, config: WorkflowWatchConfig) -> Self {
        let control = WorkflowWatchControl::default();
        let owned = control.clone();
        let node = f
            .config
            .clone()
            .with_expected_repository_incarnation(f.node().repository_incarnation_id());
        let (ready_send, ready) = mpsc::sync_channel(1);
        let (send, result) = mpsc::sync_channel(1);
        let task = f
            .node()
            .runtime()
            .submit_blocking(move || {
                let outcome = run_service_with_ready(node, config, owned, || {
                    ready_send.send(()).map_err(std::io::Error::other)
                })
                .map_err(|error| error.to_string());
                let _ = send.send(outcome);
            })
            .unwrap();
        let running = Self {
            control,
            task: Some(task),
            result,
        };
        ready.recv_timeout(Duration::from_secs(20)).unwrap();
        running
    }
    fn wait_for_reports(&self, f: &Fixture, count: usize) {
        let start = Instant::now();
        while reported(f) < count {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "merged-tree service did not report {count} PRs; executed={:?}",
                executed(f)
            );
            assert!(
                matches!(self.result.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "service stopped before reporting"
            );
            f.node().runtime().wait_for(Duration::from_millis(10));
        }
    }
    fn stop(mut self) -> WorkflowWatchReceipt {
        self.control.request_stop();
        assert!(
            self.task
                .as_ref()
                .unwrap()
                .wait_timeout(Duration::from_secs(20)),
            "collection did not drain"
        );
        drop(self.task.take());
        self.result
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.control.request_stop();
        if let Some(task) = self.task.take() {
            task.wait();
        }
    }
}

#[test]
fn discovered_prs_test_real_combined_trees_on_distinct_refs_and_restart_without_reexecution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for style in [MergeCommitStyle::TwoParent, MergeCommitStyle::Squash] {
            let mut f = Fixture::new(format, WORKFLOW);
            install_workflows(&mut f, false, false);
            open_member(&f, 1, source_ref(), target_ref());
            open_member(&f, 9, source_ref(), target_ref());
            let n = f.node();
            let prepared = n
                .runtime()
                .block_on(n.prepare_merge_bundle_with_options_in(
                    &n.request_context(),
                    &target_ref(),
                    &source_ref(),
                    &Default::default(),
                    &metadata(),
                    Default::default(),
                    MergeProfile::PathMergeV1,
                    style,
                ))
                .unwrap();
            let MergePreparation::Clean(expected) = prepared.outcome else {
                panic!("clean candidate");
            };
            assert_ne!(expected.commit, f.source);
            let config = watch_config(&f, style);
            let running = Running::start(&f, config.clone());
            running.wait_for_reports(&f, 2);
            let receipt = running.stop();
            assert_eq!(receipt.dispatched, 2);
            assert_eq!(receipt.checks_committed, 2);
            assert!(!receipt.non_green, "{receipt:?}");
            assert!(!receipt.requires_reconciliation);
            assert!(!receipt.publication_pending);
            assert_eq!(
                executed(&f),
                "xx",
                "each job verified both target-only and source-only content"
            );
            let state = f
                .node()
                .runtime()
                .block_on(f.node().materialize_admission())
                .unwrap();
            assert_eq!(state.snapshot().refs[&source_ref()], f.source);
            assert_eq!(state.snapshot().refs[&target_ref()], f.target);
            assert_eq!(state.snapshot().refs[&candidate_ref(1)], expected.commit);
            assert_eq!(state.snapshot().refs[&candidate_ref(9)], expected.commit);
            assert!(
                !state
                    .snapshot()
                    .refs
                    .contains_key(template(style).reference())
            );
            for event in event_directories(&f) {
                let text = fs::read_to_string(event.join("event.json")).unwrap();
                assert!(text.contains(&format!("\"commit\":\"{}\"", expected.commit)));
                assert!(text.contains("\"synthetic_merge\":true"));
            }
            f.reopen();
            let recovered = stop_at_readiness(&f, config.clone());
            assert_eq!(recovered.dispatched, 0);
            assert_eq!(recovered.checks_committed, 0);
            assert_eq!(executed(&f), "xx");
            assert!(refuse_before_readiness(&f, source_config(&f)).contains("inventory"));
            let changed = source_config(&f)
                .with_pull_request_merge_candidates(
                    PullRequestMergeWatchConfig::try_new(
                        RefName::try_new(b"refs/heads/other-ci").unwrap(),
                        OWNER,
                        metadata(),
                        MergeProfile::PathMergeV1,
                        style,
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(refuse_before_readiness(&f, changed).contains("inventory"));
            assert_eq!(executed(&f), "xx");
        }
    }
}

#[test]
fn readiness_failure_cannot_publish_a_member_candidate_or_start_scripts() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    install_workflows(&mut f, false, false);
    open_member(&f, 1, source_ref(), target_ref());
    let config = watch_config(&f, MergeCommitStyle::TwoParent);
    let before = generation(f.node());
    assert!(
        run_service_with_ready(
            f.config.clone(),
            config.clone(),
            WorkflowWatchControl::default(),
            || { Err(std::io::Error::other("injected readiness-output failure")) }
        )
        .is_err()
    );
    assert_eq!(generation(f.node()), before);
    assert!(executed(&f).is_empty());
    assert!(event_directories(&f).is_empty());
    let running = Running::start(&f, config);
    running.wait_for_reports(&f, 1);
    assert_eq!(running.stop().dispatched, 1);
}

#[test]
fn an_unrelated_visible_pr_in_the_ci_namespace_refuses_before_membership_or_publication() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    install_workflows(&mut f, false, false);
    open_member(&f, 1, source_ref(), target_ref());
    let unrelated_target = RefName::try_new(b"refs/heads/unrelated-target").unwrap();
    set_branch(&f, candidate_ref(1), None, f.source, b"other-pr-source");
    set_branch(
        &f,
        unrelated_target.clone(),
        None,
        f.target,
        b"other-pr-target",
    );
    open_member(&f, 9, candidate_ref(1), unrelated_target);
    let before = generation(f.node());
    let message = refuse_before_readiness(&f, watch_config(&f, MergeCommitStyle::TwoParent));
    assert!(message.contains("namespace"), "{message}");
    assert_eq!(generation(f.node()), before);
    assert!(event_directories(&f).is_empty());
    assert!(executed(&f).is_empty());
}

#[test]
fn damaged_original_candidate_custody_blocks_later_discovered_prs() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    install_workflows(&mut f, false, false);
    open_member(&f, 1, source_ref(), target_ref());
    let config = watch_config(&f, MergeCommitStyle::TwoParent);
    let running = Running::start(&f, config.clone());
    running.wait_for_reports(&f, 1);
    assert_eq!(running.stop().dispatched, 1);
    let event = event_directories(&f).pop().unwrap();
    fs::remove_file(event.join("settled")).unwrap();
    fs::write(event.join("check-sources"), b"corrupt retained handoff").unwrap();
    open_member(&f, 9, source_ref(), target_ref());
    f.reopen();
    assert!(refuse_before_readiness(&f, config).contains("custody"));
    assert_eq!(executed(&f), "x");
    let state = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    assert!(!state.snapshot().refs.contains_key(&candidate_ref(9)));
}
