//! The actual owned native controller, using the same canonical repository and
//! real process fixture as the existing ref-watch integration tests.
use super::*;
use fgit_node::workflow_watch::{
    WorkflowWatchConfig, WorkflowWatchControl, WorkflowWatchReceipt, run_service_with_ready,
};
use std::sync::mpsc;
use std::time::Instant;

fn config(f: &Fixture) -> WorkflowWatchConfig {
    WorkflowWatchConfig::try_new(
        f.tip.algorithm(),
        reference(),
        b"ci".to_vec(),
        f.parent(),
        vec![b"ci".to_vec()],
        Duration::from_millis(20),
    )
    .unwrap()
}

fn reported(f: &Fixture) -> usize {
    fs::read_dir(f.parent())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("watch-"))
        .flat_map(|entry| fs::read_dir(entry.path()).unwrap().filter_map(Result::ok))
        .filter(|entry| entry.path().join("reported").is_file())
        .count()
}

fn wait_for(f: &Fixture, test: impl Fn() -> bool) {
    let start = Instant::now();
    while !test() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "workflow observation did not arrive"
        );
        f.node().runtime().wait_for(Duration::from_millis(10));
    }
}

struct Running {
    control: WorkflowWatchControl,
    task: Option<asupersync::runtime::BlockingTaskHandle>,
    result: mpsc::Receiver<Result<WorkflowWatchReceipt, String>>,
}
impl Running {
    fn start(f: &Fixture, config: WorkflowWatchConfig) -> Self {
        let control = WorkflowWatchControl::default();
        let child_control = control.clone();
        let node_config = f
            .config
            .clone()
            .with_expected_repository_incarnation(f.node().repository_incarnation_id());
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (sender, result) = mpsc::sync_channel(1);
        let task = f
            .node()
            .runtime()
            .submit_blocking(move || {
                let outcome = run_service_with_ready(node_config, config, child_control, || {
                    ready_sender.send(()).map_err(std::io::Error::other)
                })
                .map_err(|error| error.to_string());
                let _ = sender.send(outcome);
            })
            .unwrap();
        let running = Self {
            control,
            task: Some(task),
            result,
        };
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        running
    }
    fn stop(mut self) -> WorkflowWatchReceipt {
        self.control.request_stop();
        assert!(
            self.task
                .as_ref()
                .unwrap()
                .wait_timeout(Duration::from_secs(10)),
            "workflow service did not drain"
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
fn pending_original_checks_reconcile_before_readiness_without_reexecution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, "push", "true");
        assert!(poll!(f).unwrap().dispatch().unwrap().succeeded());
        assert_eq!(reported(&f), 0);
        let watch = config(&f).with_publisher(PrincipalId::from_bytes([0xb3; 16]));
        let control = WorkflowWatchControl::default();
        let receipt =
            run_service_with_ready(f.config.clone(), watch.clone(), control.clone(), || {
                assert_eq!(
                    reported(&f),
                    1,
                    "readiness preceded pending check settlement"
                );
                control.request_stop();
                Ok(())
            })
            .unwrap();
        assert_eq!(receipt.checks_committed, 1);
        assert_eq!(receipt.polls, 0);
        assert!(!receipt.publication_pending);
        assert_eq!(f.count(), "x");
        let control = WorkflowWatchControl::default();
        let repeat =
            run_service_with_ready(f.config.clone(), watch.clone(), control.clone(), || {
                control.request_stop();
                Ok(())
            })
            .unwrap();
        assert_eq!(repeat.checks_committed, 0);
        assert!(!repeat.publication_pending);
        assert_eq!(f.count(), "x");
        let error = run_service_with_ready(
            f.config.clone(),
            watch.with_publisher(PrincipalId::from_bytes([9; 16])),
            WorkflowWatchControl::default(),
            || panic!("replacement publisher must not report ready"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("publisher differs"));
        assert_eq!(f.count(), "x");
    }
}

#[test]
fn readiness_failure_and_preexisting_stop_never_execute_a_script() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let error = run_service_with_ready(
        f.config.clone(),
        config(&f),
        WorkflowWatchControl::default(),
        || Err(std::io::Error::other("readiness sink disconnected")),
    )
    .unwrap_err();
    assert!(error.to_string().contains("readiness sink disconnected"));
    assert_eq!(f.count(), "");
    let control = WorkflowWatchControl::default();
    control.request_stop();
    assert!(
        run_service_with_ready(f.config.clone(), config(&f), control, || panic!("stopped"))
            .unwrap_err()
            .to_string()
            .contains("stopped before readiness")
    );
    assert_eq!(f.count(), "");
    // The failed readiness released its service lock after native node shutdown.
    let control = WorkflowWatchControl::default();
    let receipt = run_service_with_ready(f.config.clone(), config(&f), control.clone(), || {
        control.request_stop();
        Ok(())
    })
    .unwrap();
    assert_eq!(receipt.polls, 0);
    assert!(poll!(f).unwrap().dispatch().unwrap().succeeded());
    let error = run_service_with_ready(
        f.config.clone(),
        config(&f).with_publisher(PrincipalId::from_bytes([0xb3; 16])),
        WorkflowWatchControl::default(),
        || Err(std::io::Error::other("ready output lost after recovery")),
    )
    .unwrap_err();
    let observed = error
        .receipt()
        .expect("later failure must retain original counts");
    assert_eq!(observed.checks_committed, 1);
    assert!(observed.node_closed);
    assert!(observed.service_failed);
    assert_eq!(f.count(), "x");
}

#[test]
fn service_outlives_an_attempt_budget_and_publishes_each_new_event_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, "push", "true");
        let watch = config(&f)
            .with_publisher(PrincipalId::from_bytes([0xb3; 16]))
            .with_attempt_timeout(Duration::from_secs(2))
            .unwrap();
        let running = Running::start(&f, watch);
        wait_for(&f, || reported(&f) == 1);
        assert_eq!(f.count(), "x");
        f.node().runtime().wait_for(Duration::from_millis(2200));
        f.advance();
        wait_for(&f, || reported(&f) == 2);
        assert_eq!(f.count(), "xx");
        let receipt = running.stop();
        assert_eq!(receipt.dispatched, 2);
        assert_eq!(receipt.checks_committed, 2);
        assert!(!receipt.non_green);
        assert!(!receipt.requires_reconciliation);
        assert!(!receipt.publication_pending);
        let replay = poll!(f).unwrap();
        assert_eq!(replay.state(), "previously_settled");
        assert_eq!(f.count(), "xx");
    }
}

#[test]
fn requested_stop_drains_an_active_process_and_retains_interrupted_event_custody() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha256,
        "push",
        "sleep 30; printf escaped >> ../after",
    );
    let running = Running::start(
        &f,
        config(&f).with_publisher(PrincipalId::from_bytes([0xb3; 16])),
    );
    wait_for(&f, || f.count() == "x");
    let receipt = running.stop();
    assert!(receipt.interrupted);
    assert!(receipt.non_green);
    assert!(receipt.requires_reconciliation);
    assert!(receipt.publication_pending);
    let error = run_service_with_ready(
        f.config.clone(),
        config(&f),
        WorkflowWatchControl::default(),
        || panic!("unresolved execution must stop before readiness"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("unresolved"));
    assert_eq!(f.count(), "x");
    assert_eq!(poll!(f).unwrap().state(), "blocked_unresolved");
}

#[test]
fn competing_service_owner_refuses_while_settled_job_failure_remains_a_check() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "exit 7");
    let watch = config(&f).with_publisher(PrincipalId::from_bytes([0xb3; 16]));
    let running = Running::start(&f, watch.clone());
    wait_for(&f, || reported(&f) == 1);
    let error = run_service_with_ready(
        f.config.clone(),
        watch,
        WorkflowWatchControl::default(),
        || panic!("competing service must never become ready"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("another workflow watcher"));
    let receipt = running.stop();
    assert!(receipt.non_green);
    assert!(!receipt.requires_reconciliation);
    assert_eq!(receipt.checks_committed, 1);
    assert_eq!(f.count(), "x");
}

#[test]
fn malformed_scope_refuses_before_custody_or_script_creation() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let make = |reference, directory, parent, inputs, interval| {
        WorkflowWatchConfig::try_new(
            f.tip.algorithm(),
            reference,
            directory,
            parent,
            inputs,
            interval,
        )
    };
    assert!(
        make(
            RefName::try_new(b"refs/tags/v1").unwrap(),
            b"ci".to_vec(),
            f.parent(),
            vec![b"ci".to_vec()],
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        make(
            reference(),
            b"../ci".to_vec(),
            f.parent(),
            vec![b"ci".to_vec()],
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        make(
            reference(),
            b"ci".to_vec(),
            PathBuf::from("relative"),
            vec![b"ci".to_vec()],
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        make(
            reference(),
            b"ci".to_vec(),
            f.parent(),
            vec![b"src".to_vec()],
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        make(
            reference(),
            b"ci".to_vec(),
            f.parent(),
            vec![b"ci".to_vec(), b"ci".to_vec()],
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(config(&f).with_attempt_timeout(Duration::ZERO).is_err());
    assert!(
        config(&f)
            .with_attempt_timeout(Duration::from_secs(3601))
            .is_err()
    );
    assert!(config(&f).with_pull_request(0).is_err());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert_eq!(f.count(), "");
}

#[test]
fn listener_stop_and_control_failure_interrupt_startup_before_any_script() {
    use std::cell::RefCell;
    use std::net::TcpListener;
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let credentials = f.root.join("http-credentials");
    fs::write(
        &credentials,
        format!(
            "frankengit-http-credentials-v1 {} {} {}\n",
            f.node().tenant_id(),
            f.node().repository_id(),
            f.node().repository_incarnation_id(),
        ),
    )
    .unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).unwrap();
    for fail_control in [false, true] {
        let observed = RefCell::new(None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let result = f
            .node()
            .serve_repository_http_with_workflow_service_until_stopped(
                &listener,
                1,
                &credentials,
                false,
                false,
                false,
                false,
                false,
                config(&f),
                None,
                &|| {
                    if fail_control {
                        Err(std::io::Error::other("startup stop control failed"))
                    } else {
                        Ok(true)
                    }
                },
                &|| panic!("stopped startup must not announce HTTP readiness"),
                &|receipt| {
                    *observed.borrow_mut() = Some(receipt.clone());
                    Ok(())
                },
            );
        if fail_control {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("startup stop control failed")
            );
        } else {
            assert_eq!(result.unwrap().accepted_sessions(), 0);
        }
        let observed = observed
            .into_inner()
            .expect("native startup drain must be observed");
        assert!(observed.node_closed);
        assert!(!observed.service_failed);
        assert_eq!(observed.dispatched, 0);
        assert_eq!(f.count(), "");
    }
}

#[test]
fn a_live_service_refuses_replaced_watch_custody_without_recreating_it() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let mut running = Running::start(
        &f,
        config(&f).with_publisher(PrincipalId::from_bytes([0xb3; 16])),
    );
    wait_for(&f, || reported(&f) == 1);
    let original = fs::read_dir(f.parent())
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("watch-"))
        .unwrap()
        .path();
    fs::rename(&original, f.root.join("retained-original-watch")).unwrap();
    let error = running
        .result
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap_err();
    assert!(error.contains("custody"), "{error}");
    running.control.request_stop();
    assert!(
        running
            .task
            .as_ref()
            .unwrap()
            .wait_timeout(Duration::from_secs(10))
    );
    drop(running.task.take());
    assert!(
        !original.exists(),
        "the service silently recreated lost replay custody"
    );
    assert_eq!(f.count(), "x");
}
