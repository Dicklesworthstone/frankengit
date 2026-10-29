use super::*;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};

fn target() -> RefName {
    RefName::try_new(b"refs/heads/base").unwrap()
}
fn data(f: &Fixture) -> PullRequestData {
    PullRequestData {
        source_ref: reference(),
        target_ref: target(),
        source_tip: f.tip,
        target_tip: f.tip,
        title: "native watched PR".into(),
        body: "text, not instructions".into(),
    }
}
fn transition(
    f: &Fixture,
    number: u64,
    previous: u64,
    action: PullRequestAction,
    data: &PullRequestData,
) {
    let n = f.node();
    let command = PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: if previous == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(previous).unwrap())
        },
        action,
        data: data.clone(),
    };
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(format!("pr-{number}-{previous}-{action:?}").into_bytes()).unwrap(),
    );
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
fn setup(fmt: GitHashAlgorithm, tail: &str) -> (Fixture, PullRequestData) {
    let f = Fixture::new(fmt, "pull_request", tail);
    f.update_ref(target(), ExpectedOld::Absent, f.tip, b"base-ref");
    let data = data(&f);
    (f, data)
}
macro_rules! pr_poll {
    ($f:expr,$number:expr) => {{
        let n = $f.node();
        n.runtime()
            .block_on(n.poll_trusted_pull_request_workflows_in(
                &n.command_request_context(None),
                &reference(),
                $number,
                b"ci",
                &$f.parent(),
                &[b"ci".to_vec()],
                Default::default(),
                None,
            ))
    }};
}
macro_rules! pr_report {
    ($f:expr,$number:expr,$observe:expr) => {{
        let n = $f.node();
        n.runtime()
            .block_on(n.publish_trusted_pull_request_workflow_checks_in(
                &n.command_request_context(None),
                &reference(),
                $number,
                b"ci",
                &$f.parent(),
                PrincipalId::from_bytes([0xb3; 16]),
                $observe,
            ))
    }};
}

#[test]
fn open_pr_and_current_source_target_changes_run_once_without_metadata_refresh() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, original) = setup(fmt, "true");
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "pull_request_unavailable");
        transition(&f, 7, 0, PullRequestAction::Open, &original);
        let first = pr_poll!(f, 7).unwrap();
        assert!(first.dispatch().unwrap().succeeded());
        assert!(
            first
                .to_json()
                .contains("latest-canonical-pull-request-head-v1")
        );
        assert!(first.to_json().contains("\"synthetic_merge\":false"));
        assert_eq!(f.count(), "x");
        f.reopen();
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "previously_settled");
        f.update_ref(
            RefName::try_new(b"refs/heads/other").unwrap(),
            ExpectedOld::Absent,
            f.tip,
            b"other",
        );
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "x");
        f.advance();
        let advanced = pr_poll!(f, 7).unwrap();
        assert_eq!(
            advanced.dispatch().unwrap().runs()[0].executed_commit(),
            f.tip
        );
        assert!(advanced.to_json().contains(&format!(
            "\"recorded_source_commit\":\"{}\"",
            original.source_tip
        )));
        assert_eq!(f.count(), "xx");
        f.update_ref(
            target(),
            ExpectedOld::Exactly(original.target_tip),
            f.tip,
            b"advance-base",
        );
        let target_change = pr_poll!(f, 7).unwrap();
        assert!(target_change.dispatch().unwrap().succeeded());
        assert_eq!(f.count(), "xxx");
        f.reopen();
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "xxx");
    }
}

#[test]
fn close_suppresses_execution_and_reopen_same_commit_has_a_new_versioned_identity() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, data) = setup(fmt, "true");
        transition(&f, 7, 0, PullRequestAction::Open, &data);
        assert!(pr_poll!(f, 7).unwrap().dispatch().unwrap().succeeded());
        transition(&f, 7, 1, PullRequestAction::Close, &data);
        f.reopen();
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "pull_request_unavailable");
        assert_eq!(f.count(), "x");
        transition(&f, 7, 2, PullRequestAction::Reopen, &data);
        let reopened = pr_poll!(f, 7).unwrap();
        assert!(reopened.dispatch().unwrap().succeeded());
        assert!(reopened.to_json().contains("\"version\":\"3\""));
        assert_eq!(f.count(), "xx");
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "previously_settled");
    }
}

#[test]
fn pr_number_and_trigger_namespaces_do_not_borrow_another_event_or_run() {
    let (f, data) = setup(GitHashAlgorithm::Sha256, "true");
    transition(&f, 7, 0, PullRequestAction::Open, &data);
    assert_eq!(pr_poll!(f, 6).unwrap().state(), "pull_request_unavailable");
    assert!(poll!(f).unwrap().dispatch().unwrap().runs().is_empty());
    assert!(pr_poll!(f, 7).unwrap().dispatch().unwrap().succeeded());
    transition(&f, 8, 0, PullRequestAction::Open, &data);
    assert!(pr_poll!(f, 8).unwrap().dispatch().unwrap().succeeded());
    assert_eq!(f.count(), "xx");
    let n = f.node();
    let mismatched = n
        .runtime()
        .block_on(n.poll_trusted_pull_request_workflows_in(
            &n.command_request_context(None),
            &target(),
            7,
            b"ci",
            &f.parent(),
            &[b"ci".to_vec()],
            Default::default(),
            None,
        ))
        .unwrap();
    assert_eq!(mismatched.state(), "pull_request_unavailable");
    assert_eq!(f.count(), "xx");
}

#[test]
fn pr_check_publication_reuses_original_decisions_after_receipt_loss_and_close() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, data) = setup(
            fmt,
            "true\n  second:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true",
        );
        transition(&f, 7, 0, PullRequestAction::Open, &data);
        pr_poll!(f, 7).unwrap();
        let mut first = String::new();
        let interrupted = pr_report!(f, 7, |line: &str| {
            if line.contains("workflow_check_set_decision") {
                first = line.into();
                return Err("lost receipt".into());
            }
            Ok(())
        });
        assert_eq!(interrupted.committed, 1);
        assert!(interrupted.error.is_some());
        transition(&f, 7, 1, PullRequestAction::Close, &data);
        f.reopen();
        let mut receipts = Vec::new();
        let recovered = pr_report!(f, 7, |line: &str| {
            receipts.push(line.to_owned());
            Ok(())
        });
        assert!(recovered.error.is_none(), "{recovered:?}");
        assert_eq!(recovered.committed, 2);
        assert!(receipts.contains(&first));
        assert_eq!(f.count(), "x");
        let repeat = pr_report!(f, 7, |_: &str| panic!("already reported"));
        assert_eq!(repeat.previously_reported, 1);
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "pull_request_unavailable");
    }
}

#[test]
fn unresolved_pr_custody_blocks_reopened_events_and_never_becomes_a_check() {
    let (mut f, data) = setup(GitHashAlgorithm::Sha1, "sleep 30");
    transition(&f, 7, 0, PullRequestAction::Open, &data);
    let n = f.node();
    let run = n
        .runtime()
        .block_on(n.poll_trusted_pull_request_workflows_in(
            &n.command_request_context(None),
            &reference(),
            7,
            b"ci",
            &f.parent(),
            &[b"ci".to_vec()],
            WorkflowLimits {
                step_timeout: Duration::from_millis(100),
                run_timeout: Duration::from_secs(3),
                ..Default::default()
            },
            None,
        ))
        .unwrap();
    assert!(run.requires_reconciliation());
    assert_eq!(f.count(), "x");
    transition(&f, 7, 1, PullRequestAction::Close, &data);
    transition(&f, 7, 2, PullRequestAction::Reopen, &data);
    f.reopen();
    assert_eq!(pr_poll!(f, 7).unwrap().state(), "blocked_unresolved");
    assert!(
        pr_report!(f, 7, |_: &str| panic!("unresolved"))
            .error
            .is_some()
    );
    assert_eq!(f.count(), "x");
}

#[test]
fn invalid_number_and_cancelled_selection_create_no_execution_claim() {
    let (f, data) = setup(GitHashAlgorithm::Sha1, "true");
    transition(&f, 7, 0, PullRequestAction::Open, &data);
    assert!(pr_poll!(f, 0).is_err());
    assert!(
        pr_report!(f, 0, |_: &str| panic!("invalid"))
            .error
            .is_some()
    );
    let n = f.node();
    let request = n.command_request_context(None);
    request.cancel();
    // A cancellation observed before event reservation is a typed stop, not a
    // failure (74e832cc); it still creates no execution claim.
    let stopped = n
        .runtime()
        .block_on(n.poll_trusted_pull_request_workflows_in(
            &request,
            &reference(),
            7,
            b"ci",
            &f.parent(),
            &[b"ci".to_vec()],
            Default::default(),
            None,
        ))
        .unwrap();
    assert!(stopped.stopped_before_reservation());
    assert!(!stopped.execution_settled());
    assert!(stopped.dispatch().is_none());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert_eq!(f.count(), "");
    assert!(pr_poll!(f, 7).unwrap().dispatch().unwrap().succeeded());
}

#[test]
fn canonically_merged_pr_cannot_launch_another_head_workflow() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, mut data) = setup(fmt, "true");
        let base = f.tip;
        f.advance();
        data.source_tip = f.tip;
        transition(&f, 7, 0, PullRequestAction::Open, &data);
        assert!(pr_poll!(f, 7).unwrap().dispatch().unwrap().succeeded());
        let n = f.node();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xb3; 16]),
            IdempotencyKey::new(b"merge-watched-pr".to_vec()).unwrap(),
        );
        let (_, result) = n
            .runtime()
            .block_on(n.fast_forward_pull_request_durable_in(
                &n.command_request_context(None),
                &session,
                PullRequestNumber::try_new(7).unwrap(),
                AggregateVersion::FIRST,
                &reference(),
                f.tip,
                &target(),
                base,
                Default::default(),
                Default::default(),
            ))
            .unwrap();
        assert!(
            matches!(result.outcome, DecisionOutcome::Committed { .. }),
            "{result:?}"
        );
        f.reopen();
        assert_eq!(pr_poll!(f, 7).unwrap().state(), "pull_request_unavailable");
        assert_eq!(f.count(), "x");
    }
}
