#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Prestart recovery from real native preparation and ordinary CI admission.
//! No executed attempt is rewound or given another execution identity.
#[path = "trusted_merge_watch_recovery/support.rs"]
mod support;
use support::*;

use fgit_authority::key_recovery::RequestRecovery;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_forge::preparation::{MergeCommitStyle, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::TrustedWorkflowArtifactConfig;
use fgit_node::workflow_watch::{
    PullRequestMergeWatchConfig, WorkflowWatchControl, WorkflowWatchReceipt, run_service_with_ready,
};
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PolicyEpoch};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::mpsc,
    time::{Duration, Instant},
};

fn assert_resumed(pending: &Pending, observation: Poll) {
    assert_eq!(observation.state, "resumed", "{}", observation.json);
    assert!(observation.dispatched);
    assert!(observation.settled);
    assert_eq!(fs::read(pending.f.root.join("executed")).unwrap(), b"x");
    assert!(pending.directory.join("execution-started").is_file());
    assert!(pending.directory.join("settled").is_file());
    let publication =
        json(&fs::read(pending.directory.join("candidate-publication.json")).unwrap());
    assert_eq!(
        text_field(&publication, "candidate"),
        pending.candidate.to_string()
    );
    assert_eq!(
        unhex(text_field(&publication, "publication_key")),
        pending.key
    );
    pending.assert_original_records();
    pending.assert_ci(Some(pending.candidate));
}

#[test]
fn retained_prepublication_intent_executes_once_under_original_key_and_absent_lease() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::PullRequest, Mode::Queue] {
            let mut pending = Pending::new(format, mode, false);
            assert!(matches!(pending.outcome(), RequestRecovery::KeyNotObserved));
            pending.activate();
            let before = generation(pending.f.node());
            let report = publish(&pending.f, mode);
            assert!(report.error.is_none(), "{:?}", report.error);
            assert_eq!((report.pending, report.committed), (1, 0));
            assert!(report.lines.is_empty());
            assert!(report.json.contains("\"pending_execution\":1"));
            assert!(report.json.contains("\"execution_retried\":false"));
            assert!(report.json.contains("\"refs_changed\":false"));
            assert_eq!(generation(pending.f.node()), before);
            pending.assert_unstarted();
            pending.f.reopen();
            assert_resumed(&pending, pending.poll().unwrap());
            assert_eq!(
                generation(pending.f.node()),
                before + 1,
                "one original CI publication"
            );
            let outcome = pending.outcome();
            let terminal = outcome.terminal().unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            pending.f.reopen();
            let repeated = pending.poll().unwrap();
            assert_eq!(repeated.state, "previously_settled");
            assert!(!repeated.dispatched);
            assert_eq!(pending.outcome(), outcome);
            assert_eq!(generation(pending.f.node()), before + 1);
            let reported = publish(&pending.f, mode);
            assert!(reported.error.is_none(), "{:?}", reported.error);
            assert_eq!((reported.pending, reported.committed), (0, 1));
            assert!(
                reported.lines[0].contains(&format!("\"source_commit\":\"{}\"", pending.candidate))
            );
            let after = generation(pending.f.node());
            let repeated = publish(&pending.f, mode);
            assert!(repeated.error.is_none());
            assert_eq!(
                (repeated.pending, repeated.committed, repeated.previous),
                (0, 0, 1)
            );
            assert_eq!(generation(pending.f.node()), after);
            assert_eq!(fs::read(pending.f.root.join("executed")).unwrap(), b"x");
        }
    }
}

#[test]
fn committed_ci_with_lost_reply_and_cancelled_restart_uses_the_original_transaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::PullRequest, Mode::Queue] {
            let mut pending = Pending::new(format, mode, true);
            pending.activate();
            let (transaction, outcome) = pending.admit_original();
            assert!(matches!(outcome, DecisionOutcome::Committed { .. }));
            let original = pending.outcome();
            assert_eq!(
                match &original {
                    RequestRecovery::Recovered(row) => row.tx_id().to_string(),
                    _ => panic!("original decision missing"),
                },
                transaction
            );
            assert!(
                !pending
                    .directory
                    .join("candidate-publication.json")
                    .exists()
            );
            pending.assert_unstarted();
            pending.f.reopen();
            let before = generation(pending.f.node());
            // Cancel a resumed poll before its first invocation. The original
            // CI decision has already committed and must survive cancellation.
            let node = pending.f.node();
            let request = node.request_context();
            request.cancel();
            let stopped = node
                .runtime()
                .block_on(async {
                    match mode {
                        Mode::PullRequest => {
                            node.poll_trusted_pull_request_merge_workflows_in(
                                &request,
                                &source_ref(),
                                1,
                                b"ci",
                                &pending.f.parent(),
                                &inputs(),
                                Default::default(),
                                None,
                                &config(),
                            )
                            .await
                        }
                        Mode::Queue => {
                            node.poll_trusted_queue_head_merge_workflows_in(
                                &request,
                                &target_ref(),
                                1,
                                b"ci",
                                &pending.f.parent(),
                                &inputs(),
                                Default::default(),
                                None,
                                &config(),
                            )
                            .await
                        }
                    }
                })
                .unwrap();
            assert!(stopped.stopped_before_reservation());
            pending.assert_unstarted();
            assert_eq!(generation(node), before);
            let report = publish(&pending.f, mode);
            assert!(report.error.is_none(), "{:?}", report.error);
            assert_eq!((report.pending, report.committed), (1, 0));
            assert_resumed(&pending, pending.poll().unwrap());
            assert_eq!(
                generation(pending.f.node()),
                before,
                "historical CI result was published twice"
            );
            assert_eq!(pending.outcome(), original);
            let receipt =
                json(&fs::read(pending.directory.join("candidate-publication.json")).unwrap());
            assert_eq!(text_field(&receipt, "transaction_id"), transaction);
            assert_eq!(pending.admit_original().0, transaction);
            assert_eq!(generation(pending.f.node()), before);
            pending.f.reopen();
            assert_eq!(pending.poll().unwrap().state, "previously_settled");
            assert_eq!(fs::read(pending.f.root.join("executed")).unwrap(), b"x");
            pending.assert_original_records();
        }
    }
}

struct Running {
    control: WorkflowWatchControl,
    task: Option<asupersync::runtime::BlockingTaskHandle>,
    result: mpsc::Receiver<Result<WorkflowWatchReceipt, String>>,
    release: mpsc::SyncSender<()>,
}
impl Running {
    fn held_at_readiness(pending: &Pending) -> Self {
        let control = WorkflowWatchControl::default();
        let child_control = control.clone();
        let config = pending.f.config.clone();
        let watch = pending.watch();
        let (announced, ready) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let (sent, result) = mpsc::sync_channel(1);
        let task = pending
            .f
            .node()
            .runtime()
            .submit_blocking(move || {
                let outcome = run_service_with_ready(config, watch, child_control, || {
                    announced.send(()).map_err(std::io::Error::other)?;
                    released
                        .recv_timeout(Duration::from_secs(10))
                        .map_err(std::io::Error::other)
                })
                .map_err(|error| error.to_string());
                let _ = sent.send(outcome);
            })
            .unwrap();
        let running = Self {
            control,
            task: Some(task),
            result,
            release,
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
            "service did not drain"
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
        let _ = self.release.try_send(());
        if let Some(task) = self.task.take() {
            task.wait();
        }
    }
}

#[test]
fn service_defers_all_publication_and_execution_until_successful_readiness() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::PullRequest, Mode::Queue] {
            let pending = Pending::new(format, mode, false);
            let before = generation(pending.f.node());
            for reporting in [false, true] {
                let failed = run_service_with_ready(
                    pending.f.config.clone(),
                    pending.watch_with_reporting(reporting),
                    WorkflowWatchControl::default(),
                    || {
                        pending.assert_unstarted();
                        pending.assert_ci(None);
                        assert_eq!(generation(pending.f.node()), before);
                        Err(std::io::Error::other("listener readiness rejected"))
                    },
                )
                .unwrap_err();
                let receipt = failed.receipt().unwrap();
                assert_eq!(receipt.pending_execution, 1);
                assert_eq!(receipt.polls, 0);
                assert_eq!(receipt.checks_committed, 0);
                assert!(receipt.node_closed);
                assert!(receipt.to_json().contains("\"pending_execution\":1"));
            }
            let stop = WorkflowWatchControl::default();
            stop.request_stop();
            assert!(
                run_service_with_ready(pending.f.config.clone(), pending.watch(), stop, || panic!(
                    "stopped controller announced ready"
                ))
                .is_err()
            );
            pending.assert_unstarted();
            assert_eq!(generation(pending.f.node()), before);
            let running = Running::held_at_readiness(&pending);
            pending.assert_unstarted();
            pending.assert_ci(None);
            assert_eq!(generation(pending.f.node()), before);
            running.release.send(()).unwrap();
            let started = Instant::now();
            while !pending.directory.join("reported").is_file() {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "service did not finish original candidate"
                );
                pending
                    .f
                    .node()
                    .runtime()
                    .wait_for(Duration::from_millis(10));
            }
            let receipt = running.stop();
            assert_eq!(receipt.pending_execution, 0);
            assert_eq!(receipt.dispatched, 1);
            assert_eq!(receipt.checks_committed, 1);
            assert!(!receipt.requires_reconciliation);
            assert_eq!(fs::read(pending.f.root.join("executed")).unwrap(), b"x");
            pending.assert_original_records();
            pending.assert_ci(Some(pending.candidate));
            let original = pending.outcome();
            let stopped = WorkflowWatchControl::default();
            let again = run_service_with_ready(
                pending.f.config.clone(),
                pending.watch(),
                stopped.clone(),
                || {
                    stopped.request_stop();
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                (
                    again.pending_execution,
                    again.dispatched,
                    again.checks_committed
                ),
                (0, 0, 0)
            );
            assert_eq!(pending.outcome(), original);
            assert_eq!(fs::read(pending.f.root.join("executed")).unwrap(), b"x");
        }
    }
}

#[test]
fn changed_execution_configuration_never_reinterprets_the_original_intent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::PullRequest, Mode::Queue] {
            let mut pending = Pending::new(format, mode, false);
            pending.activate();
            let before = generation(pending.f.node());
            let original = WorkflowLimits::default();
            for limits in [
                WorkflowLimits {
                    step_timeout: Duration::from_secs(30),
                    ..original
                },
                WorkflowLimits {
                    run_timeout: Duration::from_secs(300),
                    ..original
                },
                WorkflowLimits {
                    stream_bytes: original.stream_bytes / 2,
                    ..original
                },
                WorkflowLimits {
                    total_output_bytes: original.total_output_bytes / 2,
                    ..original
                },
            ] {
                assert!(poll(&pending.f, mode, &config(), &inputs(), limits, None).is_err());
            }
            assert!(
                poll(
                    &pending.f,
                    mode,
                    &config(),
                    &[b"ci".to_vec()],
                    original,
                    None
                )
                .is_err()
            );
            let artifacts = TrustedWorkflowArtifactConfig::new_with_logs(
                pending.f.root.join("different-artifacts"),
                Vec::new(),
                1024,
                4096,
            )
            .unwrap();
            assert!(
                poll(
                    &pending.f,
                    mode,
                    &config(),
                    &inputs(),
                    original,
                    Some(&artifacts)
                )
                .is_err()
            );
            let mut changed = metadata();
            changed.timestamp += 1;
            let changed = PullRequestMergeWatchConfig::try_new(
                ci_ref(),
                OWNER,
                changed,
                MergeProfile::PathMergeV1,
                MergeCommitStyle::TwoParent,
            )
            .unwrap();
            assert!(poll(&pending.f, mode, &changed, &inputs(), original, None).is_err());
            pending.assert_unstarted();
            pending.assert_ci(None);
            pending.assert_original_records();
            assert_eq!(generation(pending.f.node()), before);
            assert_resumed(&pending, pending.poll().unwrap());
        }
    }
}

fn assert_blocked(pending: &Pending, classifier_must_refuse: bool) {
    let before = generation(pending.f.node());
    if let Ok(observed) = pending.poll() {
        assert_eq!(observed.state, "blocked_unresolved", "{}", observed.json);
        assert!(!observed.dispatched);
        assert!(!observed.settled);
    }
    let report = publish(&pending.f, pending.mode);
    if classifier_must_refuse {
        assert!(report.error.is_some());
    } else {
        // A synchronous custody classifier cannot turn historical local
        // metadata into a current canonical PR/queue/outcome observation.
        assert!(report.error.is_some() || report.pending == 1);
    }
    assert_eq!(report.committed, 0);
    assert!(report.lines.is_empty());
    assert!(!pending.f.root.join("executed").exists());
    assert!(!pending.directory.join("settled").exists());
    assert_eq!(generation(pending.f.node()), before);
}

#[derive(Clone, Copy, Debug)]
enum Stale {
    Source,
    Target,
    PullRequest,
    Queue,
    Policy,
    Ci,
}
#[test]
fn stale_canonical_subject_or_ci_lease_cannot_execute_or_replace_a_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for stale in [
            Stale::Source,
            Stale::Target,
            Stale::PullRequest,
            Stale::Queue,
            Stale::Policy,
            Stale::Ci,
        ] {
            let mut pending = Pending::new(format, Mode::Queue, true);
            pending.activate();
            let (_, outcome) = pending.admit_original();
            assert!(matches!(outcome, DecisionOutcome::Committed { .. }));
            let original = pending.outcome();
            let f = &pending.f;
            match stale {
                Stale::Source => branch(f, source_ref(), Some(f.source), f.target, b"moved-source"),
                Stale::Target => branch(f, target_ref(), Some(f.target), f.source, b"moved-target"),
                Stale::PullRequest => pull(
                    f,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    b"changed-pr",
                ),
                Stale::Queue => queue(
                    f,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    QueueCommandAction::Reorder {
                        order: vec![PullRequestNumber::FIRST],
                    },
                    b"changed-queue",
                ),
                Stale::Policy => {
                    let policy = ProtectionCommand {
                        expected_version: ExpectedVersion::NewStream,
                        expected_epoch: PolicyEpoch::FIRST,
                        protection: ReviewProtection {
                            administrators: vec![OWNER],
                            ref_policy: None,
                            branches: vec![ProtectedBranch {
                                name: target_ref(),
                                reviewers: Vec::new(),
                                required_approvals: 0,
                                required_candidate_checks: Vec::new(),
                                require_merge_queue: true,
                                required_checks: Vec::new(),
                            }],
                        },
                    };
                    let (_, outcome) = f
                        .node()
                        .runtime()
                        .block_on(f.node().admit_review_protection_durable_in(
                            &f.node().request_context(),
                            &session(b"changed-policy"),
                            &policy,
                            Default::default(),
                        ))
                        .unwrap();
                    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
                }
                Stale::Ci => branch(
                    f,
                    ci_ref(),
                    Some(pending.candidate),
                    f.source,
                    b"independent-ci-owner",
                ),
            }
            pending.f.reopen();
            assert_blocked(&pending, false);
            assert_eq!(pending.outcome(), original, "{stale:?}");
            pending.assert_original_records();
            pending.assert_unstarted();
        }
    }
}

#[test]
fn original_terminal_refusal_is_not_replaced_when_the_ci_lease_later_matches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::PullRequest, Mode::Queue] {
            let mut pending = Pending::new(format, mode, true);
            pending.activate();
            branch(
                &pending.f,
                ci_ref(),
                pending.old,
                pending.f.target,
                b"conflicting-ci-owner",
            );
            let (transaction, outcome) = pending.admit_original();
            assert!(matches!(outcome, DecisionOutcome::Refused { .. }));
            let refused = pending.outcome();
            branch(
                &pending.f,
                ci_ref(),
                Some(pending.f.target),
                pending.old.unwrap(),
                b"restore-original-ci-lease",
            );
            pending.f.reopen();
            assert_blocked(&pending, true);
            assert_eq!(pending.outcome(), refused);
            assert_eq!(pending.admit_original().0, transaction);
            pending.assert_ci(pending.old);
            pending.assert_original_records();
            pending.assert_unstarted();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    Legacy,
    Truncated,
    Altered,
    Permissions,
    Candidate,
    Event,
    Started,
    Dispatch,
    Reply,
}
#[test]
fn missing_changed_or_already_started_custody_never_grants_first_execution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for damage in [
            Damage::Legacy,
            Damage::Truncated,
            Damage::Altered,
            Damage::Permissions,
            Damage::Candidate,
            Damage::Event,
            Damage::Started,
            Damage::Dispatch,
            Damage::Reply,
        ] {
            let mut pending = Pending::new(format, Mode::Queue, false);
            pending.activate();
            let intent = pending.directory.join("prestart-intent");
            match damage {
                Damage::Legacy => fs::remove_file(intent).unwrap(),
                Damage::Truncated | Damage::Altered => {
                    let mut bytes = fs::read(&intent).unwrap();
                    if matches!(damage, Damage::Truncated) {
                        bytes.pop();
                    } else {
                        let index = bytes.len() / 2;
                        bytes[index] ^= 1;
                    }
                    fs::write(intent, bytes).unwrap();
                }
                Damage::Permissions => {
                    fs::set_permissions(intent, fs::Permissions::from_mode(0o640)).unwrap()
                }
                Damage::Candidate => {
                    let mut bytes = pending.bundle.clone();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(pending.directory.join("candidate.bundle"), bytes).unwrap();
                }
                Damage::Event => fs::write(pending.directory.join("event.json"), b"{").unwrap(),
                Damage::Started => {
                    use std::os::unix::fs::OpenOptionsExt;
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pending.directory.join("execution-started"))
                        .unwrap();
                }
                Damage::Dispatch => {
                    let document = json(&pending.event);
                    let path = pending
                        .directory
                        .join(format!("dispatch-{}", text_field(&document, "dispatch_id")));
                    fs::create_dir(&path).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                Damage::Reply => {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pending.directory.join("candidate-publication.json"))
                        .unwrap()
                        .write_all(b"{")
                        .unwrap();
                }
            }
            pending.f.reopen();
            assert_blocked(&pending, true);
            assert!(
                matches!(pending.outcome(), RequestRecovery::KeyNotObserved),
                "{damage:?}"
            );
            pending.assert_ci(None);
        }
    }
}
