//! Automatic collection uses real canonical PRs, the native supervisor and
//! original per-PR event custody. No scheduler or execution backend is mocked.
use super::*;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_node::workflow_watch::{
    WorkflowWatchConfig, WorkflowWatchControl, WorkflowWatchReceipt, run_service_with_ready,
};
use std::cell::Cell;
use std::sync::mpsc;
use std::time::Instant;

fn target() -> RefName {
    RefName::try_new(b"refs/heads/base").unwrap()
}
fn topic(number: u64) -> RefName {
    RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap()
}
fn setup(format: GitHashAlgorithm, tail: &str) -> Fixture {
    let f = Fixture::new(format, "pull_request", tail);
    f.update_ref(target(), ExpectedOld::Absent, f.tip, b"collection-base");
    f
}
fn data(f: &Fixture, number: u64) -> PullRequestData {
    PullRequestData {
        source_ref: topic(number),
        target_ref: target(),
        source_tip: f.tip,
        target_tip: f.tip,
        title: format!("collection member {number}"),
        body: String::new(),
    }
}
fn transition(f: &Fixture, number: u64, previous: u64, action: PullRequestAction) {
    let command = PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: if previous == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(previous).unwrap())
        },
        action,
        data: data(f, number),
    };
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(format!("collection-pr-{number}-{previous}-{action:?}").into_bytes())
            .unwrap(),
    );
    let n = f.node();
    let (_, result) = n
        .runtime()
        .block_on(n.admit_pull_request_durable_in(
            &n.command_request_context(None),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(result.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
}
fn open(f: &Fixture, number: u64) {
    f.update_ref(
        topic(number),
        ExpectedOld::Absent,
        f.tip,
        format!("collection-source-{number}").as_bytes(),
    );
    transition(f, number, 0, PullRequestAction::Open);
}
fn config(f: &Fixture, maximum: usize) -> WorkflowWatchConfig {
    WorkflowWatchConfig::try_new(
        f.tip.algorithm(),
        target(),
        b"ci".to_vec(),
        f.parent(),
        vec![b"ci".to_vec()],
        Duration::from_millis(20),
    )
    .unwrap()
    .with_pull_requests(maximum)
    .unwrap()
    .with_publisher(PrincipalId::from_bytes([0xb3; 16]))
}
fn initialize(f: &Fixture, watch: WorkflowWatchConfig) -> WorkflowWatchReceipt {
    let control = WorkflowWatchControl::default();
    run_service_with_ready(f.config.clone(), watch, control.clone(), || {
        control.request_stop();
        Ok(())
    })
    .unwrap()
}
fn refused_before_ready(f: &Fixture, watch: WorkflowWatchConfig) -> String {
    let ready = Cell::new(false);
    let control = WorkflowWatchControl::default();
    let result = run_service_with_ready(f.config.clone(), watch, control.clone(), || {
        ready.set(true);
        // If readiness is wrongly reached, end the controller cleanly so the
        // assertion fails independently of its panic-catching callback API.
        control.request_stop();
        Ok(())
    });
    assert!(
        !ready.get(),
        "unsafe collection reached readiness: {result:?}"
    );
    result.unwrap_err().to_string()
}
fn events(f: &Fixture) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for root in fs::read_dir(f.parent()).unwrap().map(Result::unwrap) {
        if !root.file_name().to_string_lossy().starts_with("watch-") {
            continue;
        }
        for entry in fs::read_dir(root.path()).unwrap().map(Result::unwrap) {
            if entry.file_name().to_string_lossy().starts_with("event-") {
                result.push(entry.path());
            }
        }
    }
    result.sort();
    result
}
fn reported(f: &Fixture) -> usize {
    events(f)
        .iter()
        .filter(|path| path.join("reported").is_file())
        .count()
}
fn inventory(f: &Fixture) -> Vec<u8> {
    let root = fs::read_dir(f.parent())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("pull-requests-")
        })
        .unwrap()
        .path();
    fs::read(root.join("inventory")).unwrap()
}
fn wait_for(f: &Fixture, test: impl Fn() -> bool) {
    let start = Instant::now();
    while !test() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "collection observation did not arrive; effects={}",
            f.count()
        );
        f.node().runtime().wait_for(Duration::from_millis(10));
    }
}
fn poll_original(f: &Fixture, number: u64) -> PathBuf {
    let n = f.node();
    let poll = n
        .runtime()
        .block_on(n.poll_trusted_pull_request_workflows_in(
            &n.command_request_context(None),
            &topic(number),
            number,
            b"ci",
            &f.parent(),
            &[b"ci".to_vec()],
            WorkflowLimits::default(),
            None,
        ))
        .unwrap();
    assert!(poll.execution_settled());
    assert!(poll.dispatch().unwrap().succeeded());
    poll.dispatch()
        .unwrap()
        .run_directory
        .parent()
        .unwrap()
        .to_path_buf()
}

struct Running {
    control: WorkflowWatchControl,
    task: Option<asupersync::runtime::BlockingTaskHandle>,
    result: mpsc::Receiver<Result<WorkflowWatchReceipt, String>>,
}
impl Running {
    fn start(f: &Fixture, watch: WorkflowWatchConfig) -> Self {
        let control = WorkflowWatchControl::default();
        let owned = control.clone();
        let node_config = f
            .config
            .clone()
            .with_expected_repository_incarnation(f.node().repository_incarnation_id());
        let (ready_send, ready) = mpsc::sync_channel(1);
        let (send, result) = mpsc::sync_channel(1);
        let task = f
            .node()
            .runtime()
            .submit_blocking(move || {
                let result = run_service_with_ready(node_config, watch, owned, || {
                    ready_send.send(()).map_err(std::io::Error::other)
                })
                .map_err(|error| error.to_string());
                let _ = send.send(result);
            })
            .unwrap();
        let running = Self {
            control,
            task: Some(task),
            result,
        };
        ready.recv_timeout(Duration::from_secs(15)).unwrap();
        running
    }
    fn stop(mut self) -> WorkflowWatchReceipt {
        self.control.request_stop();
        assert!(
            self.task
                .as_ref()
                .unwrap()
                .wait_timeout(Duration::from_secs(15)),
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
fn discovers_initial_and_later_prs_without_replaying_completed_members_on_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = setup(format, "true");
        open(&f, 2);
        open(&f, 9);
        let watch = config(&f, 4);
        let running = Running::start(&f, watch.clone());
        wait_for(&f, || reported(&f) == 2);
        assert_eq!(f.count(), "xx");
        open(&f, 14);
        wait_for(&f, || reported(&f) == 3);
        let receipt = running.stop();
        assert_eq!(receipt.dispatched, 3);
        assert_eq!(receipt.checks_committed, 3);
        assert!(receipt.node_closed);
        assert!(!receipt.publication_pending);
        assert!(!receipt.requires_reconciliation);
        let original = inventory(&f);
        f.reopen();
        let recovered = initialize(&f, watch);
        assert_eq!(recovered.dispatched, 0);
        assert_eq!(recovered.checks_committed, 0);
        assert_eq!(inventory(&f), original);
        assert_eq!(f.count(), "xxx");
    }
}

#[test]
fn closed_members_keep_their_custody_while_other_members_and_reopened_prs_progress() {
    let f = setup(GitHashAlgorithm::Sha256, "true");
    open(&f, 2);
    open(&f, 9);
    let watch = config(&f, 3);
    let running = Running::start(&f, watch.clone());
    wait_for(&f, || reported(&f) == 2);
    transition(&f, 2, 1, PullRequestAction::Close);
    transition(&f, 9, 1, PullRequestAction::Update);
    wait_for(&f, || reported(&f) == 3);
    assert_eq!(f.count(), "xxx");
    transition(&f, 2, 2, PullRequestAction::Reopen);
    wait_for(&f, || reported(&f) == 4);
    assert_eq!(running.stop().dispatched, 4);
    assert_eq!(f.count(), "xxxx");
    assert_eq!(initialize(&f, watch).dispatched, 0);
}

#[test]
fn capacity_refuses_the_complete_addition_set_and_retains_closed_members() {
    let f = setup(GitHashAlgorithm::Sha1, "true");
    open(&f, 2);
    let watch = config(&f, 2);
    initialize(&f, watch.clone());
    let before = inventory(&f);
    open(&f, 9);
    open(&f, 14);
    assert!(refused_before_ready(&f, watch).contains("member bound"));
    assert_eq!(
        inventory(&f),
        before,
        "a valid prefix was incorrectly admitted"
    );
    assert_eq!(f.count(), "");
    let running = Running::start(&f, config(&f, 3));
    wait_for(&f, || reported(&f) == 3);
    assert_eq!(running.stop().dispatched, 3);
    transition(&f, 2, 1, PullRequestAction::Close);
    transition(&f, 9, 1, PullRequestAction::Close);
    transition(&f, 14, 1, PullRequestAction::Close);
    let before = inventory(&f);
    assert!(refused_before_ready(&f, config(&f, 2)).contains("retained member limit"));
    assert_eq!(inventory(&f), before);
    assert_eq!(initialize(&f, config(&f, 4)).dispatched, 0);
    assert_eq!(f.count(), "xxx");
}

#[test]
fn cold_start_reconciles_original_closed_member_before_readiness_without_execution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = setup(format, "true");
        open(&f, 2);
        open(&f, 9);
        let watch = config(&f, 3);
        initialize(&f, watch.clone());
        let original = poll_original(&f, 2);
        let handoff = fs::read(original.join("check-sources")).unwrap();
        transition(&f, 2, 1, PullRequestAction::Close);
        f.reopen();
        let control = WorkflowWatchControl::default();
        let receipt =
            run_service_with_ready(f.config.clone(), watch.clone(), control.clone(), || {
                assert!(
                    original.join("reported").is_file(),
                    "closed member was skipped at readiness"
                );
                assert_eq!(f.count(), "x");
                control.request_stop();
                Ok(())
            })
            .unwrap();
        assert_eq!(receipt.checks_committed, 1);
        assert_eq!(receipt.checks_refused, 0);
        assert!(!receipt.non_green);
        assert_eq!(receipt.dispatched, 0);
        assert_eq!(fs::read(original.join("check-sources")).unwrap(), handoff);
        assert_eq!(initialize(&f, watch).checks_committed, 0);
        assert_eq!(f.count(), "x");
    }
}

#[test]
fn unresolved_old_member_blocks_all_new_execution_and_membership() {
    let mut f = setup(GitHashAlgorithm::Sha256, "true");
    open(&f, 2);
    let watch = config(&f, 3);
    initialize(&f, watch.clone());
    let original = poll_original(&f, 2);
    transition(&f, 2, 1, PullRequestAction::Close);
    let bytes = fs::read(original.join("check-sources")).unwrap();
    fs::remove_file(original.join("settled")).unwrap();
    let mut corrupt = bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(original.join("check-sources"), corrupt).unwrap();
    let before = inventory(&f);
    open(&f, 9);
    f.reopen();
    assert!(refused_before_ready(&f, watch.clone()).contains("custody"));
    assert_eq!(inventory(&f), before);
    assert_eq!(f.count(), "x");
    // Restoring the exact original proof allows native recovery; canonical
    // checks or current PR discovery were never substitutes for that proof.
    fs::write(original.join("check-sources"), bytes).unwrap();
    let running = Running::start(&f, watch);
    wait_for(&f, || reported(&f) == 2);
    assert_eq!(running.stop().dispatched, 1);
    assert_eq!(f.count(), "xx");
}

#[test]
fn missing_initialized_custody_is_not_recreated_and_empty_binding_is_permanent() {
    let f = setup(GitHashAlgorithm::Sha1, "true");
    let watch = config(&f, 2);
    initialize(&f, watch.clone());
    let before = inventory(&f);
    assert!(
        refused_before_ready(
            &f,
            watch
                .clone()
                .with_publisher(PrincipalId::from_bytes([99; 16]))
        )
        .contains("publisher or execution configuration differs")
    );
    assert_eq!(inventory(&f), before);
    open(&f, 2);
    initialize(&f, watch.clone());
    let child = fs::read_dir(f.parent())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("watch-"))
        .unwrap()
        .path();
    fs::remove_dir_all(&child).unwrap();
    assert!(refused_before_ready(&f, watch).contains("custody"));
    assert!(!child.exists());
    assert_eq!(f.count(), "");
}

#[test]
fn fixed_pr_service_and_collection_share_the_same_member_owner() {
    let f = setup(GitHashAlgorithm::Sha256, "true");
    open(&f, 2);
    open(&f, 9);
    let fixed = WorkflowWatchConfig::try_new(
        f.tip.algorithm(),
        topic(2),
        b"ci".to_vec(),
        f.parent(),
        vec![b"ci".to_vec()],
        Duration::from_millis(20),
    )
    .unwrap()
    .with_pull_request(2)
    .unwrap()
    .with_publisher(PrincipalId::from_bytes([0xb3; 16]));
    let running = Running::start(&f, fixed);
    wait_for(&f, || reported(&f) == 1);
    let error = refused_before_ready(&f, config(&f, 3));
    assert!(
        error.to_string().contains("another workflow watcher"),
        "{error}"
    );
    running.stop();
    assert_eq!(f.count(), "x");
    let running = Running::start(&f, config(&f, 3));
    wait_for(&f, || reported(&f) == 2);
    assert_eq!(running.stop().dispatched, 1);
    assert_eq!(f.count(), "xx");
}

#[test]
fn collection_stop_drains_active_member_and_never_admits_a_second_child() {
    let f = setup(GitHashAlgorithm::Sha1, "sleep 30 & wait");
    open(&f, 2);
    open(&f, 9);
    let watch = config(&f, 2);
    let running = Running::start(&f, watch.clone());
    wait_for(&f, || f.count() == "x");
    let receipt = running.stop();
    assert!(receipt.node_closed);
    assert!(receipt.interrupted);
    assert!(receipt.non_green);
    assert!(!receipt.requires_reconciliation);
    assert_eq!(receipt.dispatched, 1);
    assert_eq!(f.count(), "x");
    let recovered = initialize(&f, watch);
    assert_eq!(recovered.dispatched, 0);
    assert!(!recovered.requires_reconciliation);
    assert_eq!(f.count(), "x");
}
