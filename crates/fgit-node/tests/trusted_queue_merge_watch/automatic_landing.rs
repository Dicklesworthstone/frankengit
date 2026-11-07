//! Real candidate CI, canonical checks, atomic landing and durable original-outcome recovery.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::queue::QueueAction;
use fgit_forge::merge_queue::{DequeueReason, MergeQueueSnapshot};
use fgit_node::workflow_watch::{
    TrustedQueueLanding, WorkflowWatchConfig, WorkflowWatchControl, run_service_with_ready,
};
use fgit_types::{PrincipalId, RepositoryAuthorityHeadId};
use std::time::Duration;

fn automatic(
    f: &Fixture,
    merge: &PullRequestMergeWatchConfig,
    principal: PrincipalId,
    observe: impl FnMut(&str) -> Result<(), String>,
) -> TrustedQueueLanding {
    let node = f.node();
    node.runtime()
        .block_on(node.land_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            OWNER,
            merge,
            principal,
            observe,
        ))
}

fn publish_checks(f: &Fixture, merge: &PullRequestMergeWatchConfig) -> usize {
    let node = f.node();
    let report = node
        .runtime()
        .block_on(node.publish_trusted_queue_head_merge_workflow_checks_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            OWNER,
            merge,
            |_| Ok(()),
        ));
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(!report.request_stopped);
    assert_eq!(report.refused, 0);
    report.committed
}

fn candidate(format: GitHashAlgorithm, observed: &str) -> GitOid {
    let candidate = observed.split_once("\"merge_candidate\":").unwrap().1;
    GitOid::from_hex(format, json_string(candidate, "commit")).unwrap()
}

fn position(f: &Fixture) -> (RepositoryAuthorityHeadId, u64, u64) {
    let state = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    (
        state.basis().id(),
        state
            .basis()
            .body()
            .latest_repository_sequence
            .unwrap()
            .get(),
        state.basis().body().latest_decision_sequence.unwrap().get(),
    )
}

fn queue(f: &Fixture) -> MergeQueueSnapshot {
    f.node()
        .runtime()
        .block_on(f.node().read_queue_in(
            &f.node().request_context(),
            &Default::default(),
            QueueNumber::FIRST,
            None,
        ))
        .unwrap()
        .queue
        .unwrap()
}

fn no_landing_attempts(f: &Fixture) {
    let events = event_directories(f);
    assert!(!events.is_empty());
    for event in events {
        assert!(
            !event.join("landing-attempts").exists(),
            "waiting must not reserve a target-publication attempt: {}",
            event.display()
        );
    }
}

fn require_candidate_check(f: &Fixture, observed: &str) {
    let node = f.node();
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session(b"automatic-queue-required-check"),
            &ProtectionCommand {
                expected_version: ExpectedVersion::NewStream,
                expected_epoch: PolicyEpoch::FIRST,
                protection: ReviewProtection {
                    administrators: vec![OWNER],
                    ref_policy: None,
                    branches: vec![ProtectedBranch {
                        path_reviews: Vec::new(),
                        name: target_ref(),
                        reviewers: Vec::new(),
                        required_approvals: 0,
                        required_candidate_checks: Vec::new(),
                        require_merge_queue: true,
                        required_checks: vec![RequiredWorkflowCheck {
                            source_ref: ci_ref(),
                            publisher: OWNER,
                            graph_root: hex32(json_string(observed, "graph_sha256")),
                            job: "check".into(),
                        }],
                    }],
                },
            },
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

/// Inspect the actual durable batch and PR projection, not just the controller's counters.
fn assert_atomic_landing(
    f: &Fixture,
    second: GitOid,
    selected: u64,
    candidate: GitOid,
    queue_version: u64,
    before: (RepositoryAuthorityHeadId, u64, u64),
) -> String {
    let node = f.node();
    let state = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(state.snapshot().refs[&target_ref()], candidate);
    assert_eq!(state.snapshot().refs[&source_ref()], f.source);
    assert_eq!(state.snapshot().refs[&second_ref()], second);
    let (_, repository_sequence, decision_sequence) = position(f);
    assert_eq!(repository_sequence, before.1 + 1);
    assert_eq!(decision_sequence, before.2 + 1);
    let remaining = if selected == 2 { 1 } else { 2 };
    let queue = queue(f);
    assert_eq!(queue.version, version(queue_version + 2));
    assert_eq!(queue.deterministic_order(), vec![pull_number(remaining)]);
    assert!(queue.active_batch.is_none());

    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&node.request_context()))
        .unwrap();
    let last = history.last().unwrap();
    assert_eq!(last.batch.decisions.len(), 1);
    assert_eq!(last.batch.committed_rcrs.len(), 1);
    assert_eq!(last.forge_events.len(), 3);
    let events = &last.forge_events;
    let ForgeEventPayload::MergeQueueChangedNative(formed) = &events[0].payload else {
        panic!("landing must form the exact queue batch");
    };
    let QueueAction::BatchFormed { batch_id, entries } = &formed.action else {
        panic!("landing must form the exact queue batch");
    };
    assert_eq!(events[0].version, version(queue_version + 1));
    assert_eq!(entries, &[pull_number(selected)]);
    let ForgeEventPayload::MergeCommittedNative(merge) = &events[1].payload else {
        panic!("landing must merge the selected PR in the same record");
    };
    assert_eq!(events[1].version, version(2));
    assert_eq!(merge.target_ref, target_ref());
    assert_eq!(merge.target_tip_before, f.target);
    assert_eq!(merge.merge_commit, candidate);
    assert_eq!(
        merge.source_ref,
        if selected == 2 {
            second_ref()
        } else {
            source_ref()
        }
    );
    assert_eq!(
        merge.source_tip,
        if selected == 2 { second } else { f.source }
    );
    let ForgeEventPayload::MergeQueueChangedNative(landed) = &events[2].payload else {
        panic!("landing must retire the same queue batch");
    };
    assert_eq!(events[2].version, version(queue_version + 2));
    assert_eq!(
        landed.action,
        QueueAction::BatchLanded {
            batch_id: *batch_id,
            entries: vec![pull_number(selected)],
            target_tip: candidate,
        }
    );
    let record = &last.batch.committed_rcrs[0];
    assert_eq!(record.resulting_ref_root, state.basis().body().ref_root);
    assert_eq!(
        record.resulting_forge_position_root,
        state.basis().body().forge_position_root
    );
    let page = node
        .runtime()
        .block_on(node.read_pull_requests_in(
            &node.request_context(),
            &Default::default(),
            0,
            100,
            None,
        ))
        .unwrap();
    let merged = page
        .pull_requests
        .iter()
        .find(|row| row.number == pull_number(selected))
        .unwrap();
    assert_eq!(merged.event, events[1]);
    let untouched = page
        .pull_requests
        .iter()
        .find(|row| row.number == pull_number(remaining))
        .unwrap();
    assert_eq!(untouched.event.version, AggregateVersion::FIRST);
    assert!(matches!(
        untouched.event.payload,
        ForgeEventPayload::PullRequestChangedNative(_)
    ));
    record.tx_id.to_string()
}

#[test]
fn successful_candidate_waits_for_canonical_checks_then_lands_one_atomic_record() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let merge = config();
        let initial = poll(&f, &merge).unwrap();
        require_candidate_check(&f, &initial);
        let observed = poll(&f, &merge).unwrap();
        assert!(observed.contains("\"succeeded\":true"), "{observed}");
        let tested = candidate(format, &observed);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        let before = position(&f);
        let before_queue = queue(&f);

        let waiting = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(waiting.error.is_none(), "{waiting:?}");
        assert_eq!(waiting.waiting, 1);
        assert_eq!(waiting.committed, 0);
        assert_eq!(waiting.refused, 0);
        assert_eq!(position(&f), before);
        assert_eq!(queue(&f), before_queue);
        assert_pr_refs(&f, second);
        no_landing_attempts(&f);

        assert_eq!(publish_checks(&f, &merge), 2);
        let before_landing = position(&f);
        let mut decisions = Vec::new();
        let landed = automatic(&f, &merge, OWNER, |row| {
            if row.contains("\"type\":\"workflow_queue_landing_decision\"") {
                decisions.push(row.to_owned());
            }
            Ok(())
        });
        assert!(landed.error.is_none(), "{landed:?}");
        assert_eq!(landed.committed, 1);
        assert_eq!(landed.refused, 0);
        assert_eq!(decisions.len(), 1);
        let tx = assert_atomic_landing(&f, second, 2, tested, 2, before_landing);
        assert_eq!(json_string(&decisions[0], "transaction_id"), tx);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");

        let final_position = position(&f);
        f.reopen();
        let retry = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(retry.error.is_none(), "{retry:?}");
        assert_eq!(retry.previously_decided, 1);
        assert_eq!(retry.committed, 0);
        assert_eq!(retry.refused, 0);
        assert_eq!(position(&f), final_position);
        assert!(
            poll(&f, &merge)
                .unwrap()
                .contains("\"state\":\"queue_head_stale\"")
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
    }
}

#[test]
fn lost_terminal_observer_recovers_original_outcome_without_bundle_or_current_queue_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let merge = config();
        let observed = poll(&f, &merge).unwrap();
        let tested = candidate(format, &observed);
        assert_eq!(publish_checks(&f, &merge), 1);
        let before = position(&f);
        let mut lost_decision = None;
        let lost = automatic(&f, &merge, OWNER, |row| {
            if row.contains("\"type\":\"workflow_queue_landing_decision\"") {
                lost_decision = Some(row.to_owned());
                Err("test consumer lost the terminal response".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(lost.committed, 1);
        assert!(
            lost.error
                .as_deref()
                .unwrap()
                .contains("lost the terminal response")
        );
        let lost_decision = lost_decision.unwrap();
        let tx = assert_atomic_landing(&f, second, 2, tested, 2, before);
        assert_eq!(json_string(&lost_decision, "transaction_id"), tx);

        change_queue(
            &f,
            4,
            QueueCommandAction::Dequeue {
                pull_request: pull_number(1),
                reason: DequeueReason::Withdrawn,
            },
            b"withdraw-after-lost-automatic-landing",
        );
        assert!(queue(&f).entries.is_empty());
        let events = event_directories(&f);
        assert_eq!(events.len(), 1);
        fs::remove_file(events[0].join("landing.bundle")).unwrap();
        let final_position = position(&f);
        f.reopen();

        let changed = automatic(&f, &merge, PrincipalId::from_bytes([0x7f; 16]), |_| Ok(()));
        assert!(
            changed.error.is_some(),
            "changed authority must not adopt custody"
        );
        assert_eq!(changed.committed, 0);
        assert_eq!(position(&f), final_position);

        let mut recovered_decisions = Vec::new();
        let recovered = automatic(&f, &merge, OWNER, |row| {
            if row.contains("\"type\":\"workflow_queue_landing_decision\"") {
                recovered_decisions.push(row.to_owned());
            }
            Ok(())
        });
        assert!(recovered.error.is_none(), "{recovered:?}");
        assert_eq!(recovered.committed, 1);
        assert_eq!(recovered.refused, 0);
        assert_eq!(recovered_decisions, vec![lost_decision]);
        assert_eq!(position(&f), final_position);
        assert!(queue(&f).entries.is_empty());
        assert!(!events[0].join("landing.bundle").exists());
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        let again = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(again.error.is_none(), "{again:?}");
        assert_eq!(again.previously_decided, 1);
        assert_eq!(again.committed, 0);
        assert_eq!(position(&f), final_position);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}

#[test]
fn queue_reorder_after_ci_cannot_land_the_former_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (f, second) = queued_fixture(format, false, false);
        let merge = config();
        let first = poll(&f, &merge).unwrap();
        let first_candidate = candidate(format, &first);
        assert_eq!(publish_checks(&f, &merge), 1);
        change_queue(
            &f,
            2,
            QueueCommandAction::Reorder {
                order: vec![pull_number(1), pull_number(2)],
            },
            b"reorder-before-automatic-landing",
        );
        let before = position(&f);
        let reordered = queue(&f);
        let waiting = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(waiting.error.is_none(), "{waiting:?}");
        assert_eq!(waiting.committed, 0);
        assert_eq!(waiting.refused, 0);
        assert!(waiting.waiting + waiting.stale > 0);
        assert_eq!(position(&f), before);
        assert_eq!(queue(&f), reordered);
        assert_pr_refs(&f, second);
        no_landing_attempts(&f);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");

        let current = poll(&f, &merge).unwrap();
        let current_candidate = candidate(format, &current);
        assert_ne!(current_candidate, first_candidate);
        assert!(current.contains("\"pull_request\":\"1\""));
        assert_eq!(publish_checks(&f, &merge), 1);
        let before = position(&f);
        let landed = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(landed.error.is_none(), "{landed:?}");
        assert_eq!(landed.committed, 1);
        assert_eq!(landed.refused, 0);
        assert_atomic_landing(&f, second, 1, current_candidate, 3, before);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
    }
}

#[test]
fn canonically_reported_failed_ci_never_becomes_a_landable_candidate_or_automatic_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let merge = config();
        // The real shell step reaches its append and fails against a directory.
        // No check journal, outcome or source workflow is fabricated.
        fs::create_dir(f.root.join("executed")).unwrap();
        let observed = poll(&f, &merge).unwrap();
        assert!(observed.contains("\"succeeded\":false"), "{observed}");
        assert_eq!(publish_checks(&f, &merge), 1);
        let before = position(&f);
        let waiting = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(waiting.error.is_none(), "{waiting:?}");
        assert_eq!(waiting.waiting, 1);
        assert_eq!(waiting.committed, 0);
        assert_eq!(waiting.refused, 0);
        assert_eq!(position(&f), before);
        assert_pr_refs(&f, second);
        no_landing_attempts(&f);

        fs::remove_dir(f.root.join("executed")).unwrap();
        f.reopen();
        let again = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(again.error.is_none(), "{again:?}");
        assert_eq!(again.waiting, 1);
        assert_eq!(again.committed, 0);
        assert_eq!(position(&f), before);
        assert!(
            poll(&f, &merge)
                .unwrap()
                .contains("\"state\":\"previously_settled\"")
        );
        assert!(!f.root.join("executed").exists());
        no_landing_attempts(&f);
    }
}

#[test]
fn unresolved_prior_execution_blocks_landing_after_reorder_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, true);
        let merge = config();
        assert!(matches!(
            poll(&f, &merge),
            Err(TrustedWorkflowFailure::Journal { .. })
        ));
        change_queue(
            &f,
            2,
            QueueCommandAction::Reorder {
                order: vec![pull_number(1), pull_number(2)],
            },
            b"reorder-unresolved-automatic-landing",
        );
        let before = position(&f);
        f.reopen();
        let blocked = automatic(&f, &merge, OWNER, |_| Ok(()));
        assert!(blocked.error.is_some(), "{blocked:?}");
        assert_eq!(blocked.committed, 0);
        assert_eq!(blocked.refused, 0);
        assert_eq!(position(&f), before);
        assert_pr_refs(&f, second);
        assert!(!f.root.join("executed").exists());
        no_landing_attempts(&f);
    }
}

#[test]
fn failed_service_readiness_cannot_land_a_fully_checked_queue_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let merge = config();
        assert!(poll(&f, &merge).unwrap().contains("\"succeeded\":true"));
        assert_eq!(publish_checks(&f, &merge), 1);
        let before = position(&f);
        let service = WorkflowWatchConfig::try_new(
            format,
            target_ref(),
            b"ci".to_vec(),
            f.parent(),
            read_inputs(),
            Duration::from_millis(10),
        )
        .unwrap()
        .with_merge_queue(1)
        .unwrap()
        .with_merge_candidate(merge.clone())
        .unwrap()
        .with_publisher(OWNER)
        .with_landing_principal(OWNER);
        f.node.take().unwrap().shutdown().unwrap();
        let ready = std::cell::Cell::new(false);
        let error = run_service_with_ready(
            f.config.clone(),
            service,
            WorkflowWatchControl::default(),
            || {
                ready.set(true);
                Err(std::io::Error::other("test readiness output unavailable"))
            },
        )
        .unwrap_err();
        assert!(ready.get());
        let receipt = error.receipt().unwrap();
        assert!(receipt.node_closed);
        assert_eq!(receipt.landings_committed, 0);
        assert_eq!(receipt.landings_refused, 0);
        assert_eq!(receipt.dispatched, 0);
        f.reopen();
        assert_eq!(position(&f), before);
        assert_pr_refs(&f, second);
        no_landing_attempts(&f);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}
